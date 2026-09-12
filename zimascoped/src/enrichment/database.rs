//! Local GeoIP/ASN enrichment backed by standard MaxMind DB files.

use std::{fs, net::IpAddr, path::Path, sync::Arc};

use anyhow::{Context, Result, bail};
use maxminddb::{Reader, path};

/// Enrichment fields collected from one or more MMDB records.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct GeoRecord {
    pub country: Option<Box<str>>,
    pub region: Option<Box<str>>,
    pub city_approximate: Option<Box<str>>,
    pub asn: Option<u32>,
    pub organization: Option<Box<str>>,
}

/// An immutable snapshot of one MMDB file or a directory of MMDB files.
#[derive(Clone, Debug)]
pub struct GeoIpDatabase {
    version: Box<str>,
    index_nodes: usize,
    readers: Vec<Arc<Reader<Vec<u8>>>>,
}

impl GeoIpDatabase {
    /// Loads one `.mmdb` file, or every `.mmdb` file in a directory.
    pub fn load(path: &Path) -> Result<Self> {
        let paths = if path.is_dir() {
            let mut paths = Vec::new();
            for entry in fs::read_dir(path)
                .with_context(|| format!("read GeoIP database directory {}", path.display()))?
            {
                let candidate = entry.context("read GeoIP database directory entry")?.path();
                if candidate
                    .extension()
                    .is_some_and(|extension| extension.eq_ignore_ascii_case("mmdb"))
                {
                    paths.push(candidate);
                }
            }
            paths.sort();
            paths
        } else {
            vec![path.to_owned()]
        };

        if paths.is_empty() {
            bail!("no .mmdb files found in {}", path.display());
        }

        let readers = paths
            .iter()
            .map(|path| {
                Reader::open_readfile(path)
                    .with_context(|| format!("open MMDB database {}", path.display()))
            })
            .collect::<Result<Vec<_>>>()?;
        Self::from_readers(readers)
    }

    fn from_readers(readers: Vec<Reader<Vec<u8>>>) -> Result<Self> {
        if readers.is_empty() {
            bail!("at least one MMDB database is required");
        }

        let version = readers
            .iter()
            .map(|reader| {
                let metadata = reader.metadata();
                format!("{}@{}", metadata.database_type, metadata.build_epoch)
            })
            .collect::<Vec<_>>()
            .join(",");
        let index_nodes = readers
            .iter()
            .map(|reader| reader.metadata().node_count as usize)
            .sum();

        Ok(Self {
            version: version.into(),
            index_nodes,
            readers: readers.into_iter().map(Arc::new).collect(),
        })
    }

    #[cfg(test)]
    pub(crate) fn from_bytes(bytes: Vec<u8>) -> Result<Self> {
        Self::from_readers(vec![
            Reader::from_source(bytes).context("parse MMDB database")?,
        ])
    }

    pub fn version(&self) -> &str {
        &self.version
    }

    pub fn is_empty(&self) -> bool {
        self.index_nodes == 0
    }

    pub fn index_node_count(&self) -> usize {
        self.index_nodes
    }

    /// Looks up and merges available location and ASN fields.
    pub fn lookup(&self, address: IpAddr) -> Result<Option<GeoRecord>> {
        let mut record = GeoRecord::default();
        let mut found = false;

        for reader in &self.readers {
            if address.is_ipv6() && reader.metadata().ip_version == 4 {
                continue;
            }
            let result = reader.lookup(address).context("look up address in MMDB")?;
            if !result.has_data() {
                continue;
            }
            found = true;

            set_once(
                &mut record.country,
                result.decode_path::<String>(&path!["country", "iso_code"])?,
            );
            set_once(
                &mut record.region,
                result
                    .decode_path::<String>(&path!["subdivisions", 0, "names", "en"])?
                    .or(result.decode_path::<String>(&path!["subdivisions", 0, "iso_code"])?),
            );
            set_once(
                &mut record.city_approximate,
                result.decode_path::<String>(&path!["city", "names", "en"])?,
            );
            record.asn = record
                .asn
                .or(result.decode_path::<u32>(&path!["autonomous_system_number"])?)
                .or(result.decode_path::<u32>(&path!["traits", "autonomous_system_number"])?);
            set_once(
                &mut record.organization,
                result
                    .decode_path::<String>(&path!["autonomous_system_organization"])?
                    .or(result.decode_path::<String>(&path![
                        "traits",
                        "autonomous_system_organization"
                    ])?)
                    .or(result.decode_path::<String>(&path!["organization"])?),
            );
        }

        Ok(found.then_some(record))
    }
}

fn set_once(target: &mut Option<Box<str>>, value: Option<String>) {
    if target.is_none() {
        *target = value.map(String::into_boxed_str);
    }
}

#[cfg(test)]
pub(crate) fn test_database() -> GeoIpDatabase {
    use maxminddb_writer::{Database, paths::IpAddrWithMask};

    #[derive(serde::Serialize)]
    struct Names<'a> {
        en: &'a str,
    }

    #[derive(serde::Serialize)]
    struct Named<'a> {
        names: Names<'a>,
    }

    #[derive(serde::Serialize)]
    struct Country<'a> {
        iso_code: &'a str,
    }

    #[derive(serde::Serialize)]
    struct Record<'a> {
        country: Country<'a>,
        subdivisions: [Named<'a>; 1],
        city: Named<'a>,
        autonomous_system_number: u32,
        autonomous_system_organization: &'a str,
    }

    let mut database = Database::default();
    database.metadata.database_type = "ZimaScope-Test".into();
    database.metadata.binary_format_major_version = 2;
    database.metadata.binary_format_minor_version = 0;
    database.metadata.build_epoch = 1_788_739_200;
    let record = database
        .insert_value(Record {
            country: Country { iso_code: "US" },
            subdivisions: [Named {
                names: Names { en: "California" },
            }],
            city: Named {
                names: Names {
                    en: "Mountain View",
                },
            },
            autonomous_system_number: 15169,
            autonomous_system_organization: "Google LLC",
        })
        .expect("serialize test record");
    database.insert_node(
        "8.8.8.0/24"
            .parse::<IpAddrWithMask>()
            .expect("valid test network"),
        record,
    );
    let bytes = database.write_to(Vec::new()).expect("write test MMDB");
    GeoIpDatabase::from_bytes(bytes).expect("read test MMDB")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_standard_mmdb_fields() {
        let database = test_database();
        let record = database
            .lookup("8.8.8.8".parse().unwrap())
            .expect("lookup succeeds")
            .expect("known address");

        assert_eq!(database.version(), "ZimaScope-Test@1788739200");
        assert!(!database.is_empty());
        assert_eq!(record.country.as_deref(), Some("US"));
        assert_eq!(record.region.as_deref(), Some("California"));
        assert_eq!(record.city_approximate.as_deref(), Some("Mountain View"));
        assert_eq!(record.asn, Some(15169));
        assert_eq!(record.organization.as_deref(), Some("Google LLC"));
    }

    #[test]
    fn unknown_addresses_return_none() {
        assert!(
            test_database()
                .lookup("1.1.1.1".parse().unwrap())
                .expect("lookup succeeds")
                .is_none()
        );
    }

    #[test]
    fn missing_database_file_is_an_error() {
        assert!(GeoIpDatabase::load(Path::new("/nonexistent/zimascope.mmdb")).is_err());
    }
}
