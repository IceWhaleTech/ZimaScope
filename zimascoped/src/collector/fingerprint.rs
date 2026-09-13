//! Data-driven protocol fingerprints.
//!
//! The matcher is a tiny rule engine over the bounded first-payload sample.
//! The default library ships inside the binary as JSON; a deployment can
//! replace it through `PUT /v1/fingerprints` without rebuilding anything.
//! Only structural checks that cannot be expressed as byte predicates (DNS
//! question parsing) stay as builtins.

use std::{
    fmt,
    path::Path,
    sync::{Arc, RwLock},
};

use serde::{Deserialize, Serialize};

/// The embedded default library, validated by unit tests at build time.
pub const DEFAULT_LIBRARY: &str = include_str!("fingerprints.json");

/// Maximum accepted payload offset in any predicate.
const MAX_OFFSET: usize = 4096;
const MAX_RULES: usize = 512;
const MAX_PREDICATES_PER_RULE: usize = 16;
const MAX_SERVICE_NAME: usize = 32;

/// Shared, hot-swappable library handle used by the collector and the API.
pub type SharedFingerprints = Arc<RwLock<FingerprintLibrary>>;

/// Creates a shared handle around the embedded default library.
pub fn shared_default() -> SharedFingerprints {
    Arc::new(RwLock::new(FingerprintLibrary::default_library()))
}

/// Validation or parse failure with a human-readable reason.
#[derive(Debug)]
pub struct FingerprintError(String);

impl fmt::Display for FingerprintError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for FingerprintError {}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct LibraryDocument {
    #[serde(default = "default_version")]
    version: u32,
    rules: Vec<RuleSpec>,
}

fn default_version() -> u32 {
    1
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct RuleSpec {
    service: String,
    #[serde(rename = "match")]
    predicates: Vec<PredicateSpec>,
}

/// One predicate; the rule matches when every predicate matches (AND).
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "op", rename_all = "snake_case")]
enum PredicateSpec {
    MinLen {
        value: usize,
    },
    PrefixText {
        value: String,
    },
    PrefixTextAny {
        values: Vec<String>,
    },
    /// Exact byte sequence at an offset, hex-encoded (`"16 03"` or `"1603"`).
    Bytes {
        #[serde(default)]
        offset: usize,
        hex: String,
    },
    Byte {
        offset: usize,
        #[serde(default)]
        mask: Option<u8>,
        compare: Compare,
    },
    Int {
        offset: usize,
        size: u8,
        #[serde(default)]
        endian: Endian,
        compare: Compare,
    },
    /// Structural validators that byte predicates cannot express.
    Builtin {
        name: Builtin,
    },
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
enum Endian {
    #[default]
    Be,
    Le,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
struct Compare {
    eq: Option<u64>,
    ne: Option<u64>,
    lt: Option<u64>,
    lte: Option<u64>,
    gt: Option<u64>,
    gte: Option<u64>,
    #[serde(rename = "in")]
    r#in: Option<Vec<u64>>,
}

impl Compare {
    fn validate(&self) -> Result<(), FingerprintError> {
        if self.eq.is_none()
            && self.ne.is_none()
            && self.lt.is_none()
            && self.lte.is_none()
            && self.gt.is_none()
            && self.gte.is_none()
            && self.r#in.is_none()
        {
            return Err(FingerprintError("compare block is empty".into()));
        }
        Ok(())
    }

    fn matches(&self, value: u64) -> bool {
        if let Some(eq) = self.eq {
            if value != eq {
                return false;
            }
        }
        if let Some(ne) = self.ne {
            if value == ne {
                return false;
            }
        }
        if let Some(lt) = self.lt {
            if value >= lt {
                return false;
            }
        }
        if let Some(lte) = self.lte {
            if value > lte {
                return false;
            }
        }
        if let Some(gt) = self.gt {
            if value <= gt {
                return false;
            }
        }
        if let Some(gte) = self.gte {
            if value < gte {
                return false;
            }
        }
        if let Some(choices) = &self.r#in {
            if !choices.contains(&value) {
                return false;
            }
        }
        true
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum Builtin {
    /// DNS message whose question section parses cleanly.
    DnsQuery,
}

#[derive(Clone, Debug)]
enum Predicate {
    MinLen(usize),
    PrefixText(Vec<u8>),
    PrefixTextAny(Vec<Vec<u8>>),
    Bytes {
        offset: usize,
        bytes: Vec<u8>,
    },
    Byte {
        offset: usize,
        mask: Option<u8>,
        compare: Compare,
    },
    Int {
        offset: usize,
        size: u8,
        endian: Endian,
        compare: Compare,
    },
    Builtin(Builtin),
}

impl Predicate {
    fn matches(&self, payload: &[u8]) -> bool {
        match self {
            Self::MinLen(minimum) => payload.len() >= *minimum,
            Self::PrefixText(prefix) => payload.starts_with(prefix),
            Self::PrefixTextAny(prefixes) => {
                prefixes.iter().any(|prefix| payload.starts_with(prefix))
            }
            Self::Bytes { offset, bytes } => payload
                .get(*offset..offset + bytes.len())
                .is_some_and(|window| window == bytes.as_slice()),
            Self::Byte {
                offset,
                mask,
                compare,
            } => payload.get(*offset).is_some_and(|byte| {
                let value = mask.map_or(u64::from(*byte), |mask| u64::from(byte & mask));
                compare.matches(value)
            }),
            Self::Int {
                offset,
                size,
                endian,
                compare,
            } => read_int(payload, *offset, *size, *endian)
                .is_some_and(|value| compare.matches(value)),
            Self::Builtin(Builtin::DnsQuery) => is_dns_query(payload),
        }
    }
}

#[derive(Clone, Debug)]
struct CompiledRule {
    service: Box<str>,
    predicates: Vec<Predicate>,
}

impl CompiledRule {
    fn matches(&self, payload: &[u8]) -> bool {
        self.predicates
            .iter()
            .all(|predicate| predicate.matches(payload))
    }
}

/// A validated, compiled fingerprint library.
#[derive(Debug)]
pub struct FingerprintLibrary {
    rules: Vec<CompiledRule>,
    raw: String,
    custom: bool,
}

impl FingerprintLibrary {
    /// The embedded default library. Panics only if the shipped file is
    /// invalid, which unit tests prevent.
    pub fn default_library() -> Self {
        let mut library =
            Self::from_json(DEFAULT_LIBRARY).expect("embedded fingerprint library is valid");
        library.custom = false;
        library
    }

    /// Parses and validates a library document.
    pub fn from_json(raw: &str) -> Result<Self, FingerprintError> {
        let document: LibraryDocument = serde_json::from_str(raw)
            .map_err(|error| FingerprintError(format!("invalid fingerprint JSON: {error}")))?;
        if document.rules.is_empty() {
            return Err(FingerprintError("library has no rules".into()));
        }
        if document.rules.len() > MAX_RULES {
            return Err(FingerprintError(format!(
                "library has {} rules; the maximum is {MAX_RULES}",
                document.rules.len()
            )));
        }
        let mut rules = Vec::with_capacity(document.rules.len());
        for (index, spec) in document.rules.into_iter().enumerate() {
            rules.push(compile_rule(index, spec)?);
        }
        Ok(Self {
            rules,
            raw: raw.to_owned(),
            custom: true,
        })
    }

    /// Loads a custom library from disk, keeping the default when absent.
    pub fn load_or_default(path: &Path) -> Self {
        match std::fs::read_to_string(path) {
            Ok(raw) => match Self::from_json(&raw) {
                Ok(library) => library,
                Err(error) => {
                    eprintln!(
                        "zimascoped: ignoring invalid fingerprints at {}: {error}",
                        path.display()
                    );
                    Self::default_library()
                }
            },
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Self::default_library(),
            Err(error) => {
                eprintln!(
                    "zimascoped: cannot read fingerprints at {}: {error}",
                    path.display()
                );
                Self::default_library()
            }
        }
    }

    /// Returns the first matching service name.
    pub fn classify(&self, payload: &[u8]) -> Option<&str> {
        self.rules
            .iter()
            .find(|rule| rule.matches(payload))
            .map(|rule| rule.service.as_ref())
    }

    /// The JSON document backing this library.
    pub fn raw(&self) -> &str {
        &self.raw
    }

    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Whether this library came from an upload or a file rather than the
    /// embedded default.
    pub fn is_custom(&self) -> bool {
        self.custom
    }

    /// Sorted unique service names this library can classify.
    pub fn services(&self) -> Vec<String> {
        let mut names: Vec<String> = self
            .rules
            .iter()
            .map(|rule| rule.service.to_string())
            .collect();
        names.sort();
        names.dedup();
        names
    }
}

fn compile_rule(index: usize, spec: RuleSpec) -> Result<CompiledRule, FingerprintError> {
    let service = spec.service.trim().to_owned();
    if service.is_empty() {
        return Err(FingerprintError(format!(
            "rule {index}: empty service name"
        )));
    }
    if service.len() > MAX_SERVICE_NAME {
        return Err(FingerprintError(format!(
            "rule {index}: service name is longer than {MAX_SERVICE_NAME} characters"
        )));
    }
    if spec.predicates.is_empty() {
        return Err(FingerprintError(format!(
            "rule {index} ({service}): no match predicates"
        )));
    }
    if spec.predicates.len() > MAX_PREDICATES_PER_RULE {
        return Err(FingerprintError(format!(
            "rule {index} ({service}): more than {MAX_PREDICATES_PER_RULE} predicates"
        )));
    }
    let predicates = spec
        .predicates
        .into_iter()
        .map(|predicate| compile_predicate(index, &service, predicate))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(CompiledRule {
        service: service.into_boxed_str(),
        predicates,
    })
}

fn compile_predicate(
    index: usize,
    service: &str,
    spec: PredicateSpec,
) -> Result<Predicate, FingerprintError> {
    let context = format!("rule {index} ({service})");
    match spec {
        PredicateSpec::MinLen { value } => {
            if value == 0 || value > MAX_OFFSET {
                return Err(FingerprintError(format!(
                    "{context}: min_len must be between 1 and {MAX_OFFSET}"
                )));
            }
            Ok(Predicate::MinLen(value))
        }
        PredicateSpec::PrefixText { value } => {
            check_text(&context, &value)?;
            Ok(Predicate::PrefixText(value.into_bytes()))
        }
        PredicateSpec::PrefixTextAny { values } => {
            if values.is_empty() {
                return Err(FingerprintError(format!(
                    "{context}: prefix_text_any is empty"
                )));
            }
            for value in &values {
                check_text(&context, value)?;
            }
            Ok(Predicate::PrefixTextAny(
                values.into_iter().map(String::into_bytes).collect(),
            ))
        }
        PredicateSpec::Bytes { offset, hex } => {
            check_offset(&context, offset)?;
            let bytes = parse_hex(&context, &hex)?;
            if bytes.is_empty() || bytes.len() > 64 {
                return Err(FingerprintError(format!(
                    "{context}: bytes must decode to 1..=64 bytes"
                )));
            }
            Ok(Predicate::Bytes { offset, bytes })
        }
        PredicateSpec::Byte {
            offset,
            mask,
            compare,
        } => {
            check_offset(&context, offset)?;
            compare
                .validate()
                .map_err(|error| FingerprintError(format!("{context}: {error}")))?;
            Ok(Predicate::Byte {
                offset,
                mask,
                compare,
            })
        }
        PredicateSpec::Int {
            offset,
            size,
            endian,
            compare,
        } => {
            check_offset(&context, offset)?;
            if !(1..=4).contains(&size) {
                return Err(FingerprintError(format!(
                    "{context}: int size must be 1, 2, 3 or 4"
                )));
            }
            compare
                .validate()
                .map_err(|error| FingerprintError(format!("{context}: {error}")))?;
            Ok(Predicate::Int {
                offset,
                size,
                endian,
                compare,
            })
        }
        PredicateSpec::Builtin { name } => Ok(Predicate::Builtin(name)),
    }
}

fn check_offset(context: &str, offset: usize) -> Result<(), FingerprintError> {
    if offset > MAX_OFFSET {
        return Err(FingerprintError(format!(
            "{context}: offset exceeds {MAX_OFFSET}"
        )));
    }
    Ok(())
}

fn check_text(context: &str, value: &str) -> Result<(), FingerprintError> {
    if value.is_empty() || value.len() > 64 {
        return Err(FingerprintError(format!(
            "{context}: text values must be 1..=64 bytes"
        )));
    }
    Ok(())
}

fn parse_hex(context: &str, value: &str) -> Result<Vec<u8>, FingerprintError> {
    let compact: String = value.chars().filter(|char| !char.is_whitespace()).collect();
    if !compact.len().is_multiple_of(2) {
        return Err(FingerprintError(format!(
            "{context}: hex value has an odd number of digits"
        )));
    }
    let mut bytes = Vec::with_capacity(compact.len() / 2);
    let chars: Vec<char> = compact.chars().collect();
    for pair in chars.chunks(2) {
        let text: String = pair.iter().collect();
        let byte = u8::from_str_radix(&text, 16)
            .map_err(|_| FingerprintError(format!("{context}: invalid hex {text:?}")))?;
        bytes.push(byte);
    }
    Ok(bytes)
}

fn read_int(payload: &[u8], offset: usize, size: u8, endian: Endian) -> Option<u64> {
    let size = usize::from(size);
    let window = payload.get(offset..offset + size)?;
    let mut value = 0u64;
    match endian {
        Endian::Be => {
            for byte in window {
                value = (value << 8) | u64::from(*byte);
            }
        }
        Endian::Le => {
            for (shift, byte) in window.iter().enumerate() {
                value |= u64::from(*byte) << (8 * shift);
            }
        }
    }
    Some(value)
}

/// DNS message with a structurally valid question section.
fn is_dns_query(payload: &[u8]) -> bool {
    if payload.len() < 13 {
        return false;
    }
    let flags = u16::from_be_bytes([payload[2], payload[3]]);
    if flags & 0x7800 != 0 {
        // OPCODE must be QUERY (0).
        return false;
    }
    let questions = u16::from_be_bytes([payload[4], payload[5]]);
    if questions == 0 || questions > 4 {
        return false;
    }
    let mut position = 12usize;
    let mut labels = 0usize;
    loop {
        let Some(&length) = payload.get(position) else {
            return false;
        };
        position += 1;
        if length == 0 {
            break;
        }
        if length > 63 {
            return false;
        }
        position += length as usize;
        labels += 1;
        if labels > 20 || position > payload.len() {
            return false;
        }
    }
    if position + 4 > payload.len() {
        return false;
    }
    let class = u16::from_be_bytes([payload[position + 2], payload[position + 3]]);
    matches!(class, 1 | 255)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn library() -> FingerprintLibrary {
        FingerprintLibrary::default_library()
    }

    #[test]
    fn default_library_classifies_known_protocols() {
        let library = library();

        assert_eq!(library.classify(b"SSH-2.0-OpenSSH_9.6\r\n"), Some("SSH"));
        assert_eq!(
            library.classify(&[0x16, 0x03, 0x01, 0x02, 0x00]),
            Some("TLS")
        );
        assert_eq!(
            library.classify(b"GET /index.html HTTP/1.1\r\n"),
            Some("HTTP")
        );
        assert_eq!(library.classify(b"HTTP/1.1 200 OK\r\n"), Some("HTTP"));
        assert_eq!(
            library.classify(&[0x4a, 0x00, 0x00, 0x00, 0x0a, b'8']),
            Some("MySQL")
        );
        assert_eq!(
            library.classify(&[0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f]),
            Some("PostgreSQL")
        );
        assert_eq!(library.classify(b"*2\r\n$4\r\nPING\r\n"), Some("Redis"));
        assert_eq!(library.classify(b"+PONG\r\n"), Some("Redis"));
        assert_eq!(
            library.classify(&[0x03, 0x00, 0x00, 0x13, 0x0e, 0xe0]),
            Some("RDP")
        );
        assert_eq!(
            library.classify(&[0xc3, 0x00, 0x00, 0x00, 0x01, 0x08, 0x00]),
            Some("QUIC")
        );
        assert_eq!(
            library.classify(&[0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
            Some("WireGuard")
        );

        let mut mongo = vec![0u8; 32];
        mongo[0] = 32;
        mongo[12] = 0xdd;
        mongo[13] = 0x07;
        assert_eq!(library.classify(&mongo), Some("MongoDB"));

        let dns_query = [
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'e',
            b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00,
            0x01,
        ];
        assert_eq!(library.classify(&dns_query), Some("DNS"));
    }

    #[test]
    fn unknown_payloads_stay_unlabelled() {
        let library = library();
        assert!(library.classify(&[]).is_none());
        assert!(library.classify(&[0xde, 0xad, 0xbe, 0xef]).is_none());
        assert!(library.classify(b"SSH").is_none());
        assert!(
            library
                .classify(b"random bytes that are long enough")
                .is_none()
        );
    }

    #[test]
    fn custom_rules_extend_coverage_without_recompiling() {
        let custom = r#"{
            "rules": [
                { "service": "SOCKS5", "match": [
                    { "op": "min_len", "value": 3 },
                    { "op": "byte", "offset": 0, "compare": { "eq": 5 } },
                    { "op": "byte", "offset": 1, "compare": { "gte": 1, "lte": 8 } }
                ]}
            ]
        }"#;
        let library = FingerprintLibrary::from_json(custom).expect("valid custom library");
        assert_eq!(library.classify(&[0x05, 0x01, 0x00]), Some("SOCKS5"));
        assert!(library.classify(&[0x16, 0x03, 0x01]).is_none());
        assert!(library.is_custom());
    }

    #[test]
    fn invalid_libraries_are_rejected() {
        assert!(FingerprintLibrary::from_json("{}").is_err());
        assert!(FingerprintLibrary::from_json(r#"{"rules":[]}"#).is_err());
        assert!(
            FingerprintLibrary::from_json(
                r#"{"rules":[{"service":"","match":[{"op":"min_len","value":1}]}]}"#
            )
            .is_err()
        );
        assert!(
            FingerprintLibrary::from_json(
                r#"{"rules":[{"service":"X","match":[{"op":"byte","offset":0,"compare":{}}]}]}"#
            )
            .is_err()
        );
        assert!(
            FingerprintLibrary::from_json(
                r#"{"rules":[{"service":"X","match":[{"op":"int","offset":0,"size":9,"compare":{"eq":1}}]}]}"#
            )
            .is_err()
        );
        assert!(
            FingerprintLibrary::from_json(
                r#"{"rules":[{"service":"X","match":[{"op":"bytes","hex":"zz"}]}]}"#
            )
            .is_err()
        );
    }
}
