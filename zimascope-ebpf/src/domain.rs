//! Bounded DNS, TLS SNI and HTTP Host extraction.
//!
//! These parsers are generic over [`PacketCursor`] so the exact code that runs
//! in the eBPF program is unit tested on the host. They never allocate and
//! never inspect more bytes than the caller's declared payload bounds. Raw
//! payload bytes are discarded after extraction; only the domain, the evidence
//! kind, the address and a TTL leave this module.

use zimascope_common::kernel_abi::DOMAIN_MAX_LEN;

use crate::parse::PacketCursor;

pub const DNS_PORT: u16 = 53;
pub const TLS_PORT: u16 = 443;
pub const HTTP_PORT: u16 = 80;

pub const MAX_DNS_ANSWERS: usize = 8;
pub const MAX_DNS_LABELS: usize = 16;
pub const MAX_TLS_EXTENSIONS: usize = 16;
pub const MAX_HTTP_SCAN: usize = 512;
pub const MAX_HTTP_HEADERS: usize = 16;
pub const MAX_HTTP_HOST_LEN: usize = 253;

/// One A record extracted from a DNS response.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DnsAnswer {
    pub ttl_secs: u32,
    pub address: [u8; 16],
}

#[inline(always)]
fn within(offset: usize, len: usize, end: usize) -> bool {
    offset.checked_add(len).is_some_and(|limit| limit <= end)
}

/// Extracts A records from a DNS response, pairing each one with the question
/// name and its TTL. Returns the number of answers emitted.
pub fn parse_dns_response<C, F>(
    cursor: &C,
    offset: usize,
    end: usize,
    domain_buffer: &mut [u8; DOMAIN_MAX_LEN],
    mut emit: F,
) -> usize
where
    C: PacketCursor + ?Sized,
    F: FnMut(&[u8; DOMAIN_MAX_LEN], usize, DnsAnswer),
{
    if !within(offset, 12, end) {
        return 0;
    }
    if cursor
        .read_u16_be(offset + 2)
        .is_none_or(|flags| flags & 0x8000 == 0)
    {
        return 0;
    }
    if cursor
        .read_u16_be(offset + 4)
        .is_none_or(|count| count == 0)
    {
        return 0;
    }
    let answers = match cursor.read_u16_be(offset + 6) {
        Some(count) if count > 0 => count as usize,
        _ => return 0,
    };

    let mut position = offset + 12;
    let Some(name_len) = read_question_name(cursor, &mut position, end, domain_buffer) else {
        return 0;
    };
    if name_len == 0 || !within(position, 4, end) {
        return 0;
    }
    position += 4;

    let answers = answers.min(MAX_DNS_ANSWERS);
    let mut emitted = 0usize;

    for _ in 0..MAX_DNS_ANSWERS {
        if emitted == answers {
            break;
        }
        if !skip_answer_name(cursor, &mut position, end) {
            break;
        }
        if !within(position, 10, end) {
            break;
        }

        let (Some(rtype), Some(class), Some(ttl), Some(rdlength)) = (
            cursor.read_u16_be(position),
            cursor.read_u16_be(position + 2),
            cursor.read_u32_be(position + 4),
            cursor.read_u16_be(position + 8),
        ) else {
            break;
        };
        position += 10;

        let rdlength = rdlength as usize;
        if !within(position, rdlength, end) {
            break;
        }

        if rtype == 1 && class == 1 && rdlength == 4 {
            let (Some(b0), Some(b1), Some(b2), Some(b3)) = (
                cursor.read_u8(position),
                cursor.read_u8(position + 1),
                cursor.read_u8(position + 2),
                cursor.read_u8(position + 3),
            ) else {
                break;
            };
            let mut address = [0u8; 16];
            address[12..].copy_from_slice(&[b0, b1, b2, b3]);
            emit(
                domain_buffer,
                name_len,
                DnsAnswer {
                    ttl_secs: ttl,
                    address,
                },
            );
            emitted += 1;
        }

        position += rdlength;
    }

    emitted
}

/// Reads a question name into `domain_buffer`, returning its length.
fn read_question_name<C: PacketCursor + ?Sized>(
    cursor: &C,
    position: &mut usize,
    end: usize,
    domain_buffer: &mut [u8; DOMAIN_MAX_LEN],
) -> Option<usize> {
    let mut length = 0usize;

    for _ in 0..MAX_DNS_LABELS {
        if !within(*position, 1, end) {
            return None;
        }
        let label_len = cursor.read_u8(*position)? as usize;
        *position += 1;

        if label_len == 0 {
            return Some(length);
        }
        if label_len & 0xC0 != 0 || label_len > 63 || !within(*position, label_len, end) {
            return None;
        }

        if length > 0 {
            if length + 1 >= DOMAIN_MAX_LEN {
                return None;
            }
            domain_buffer[length] = b'.';
            length += 1;
        }
        if length + label_len > DOMAIN_MAX_LEN {
            return None;
        }

        if !cursor.read_bytes(*position, &mut domain_buffer[length..length + label_len]) {
            return None;
        }
        length += label_len;
        *position += label_len;
    }

    None
}

/// Skips an answer owner name, which may be a compression pointer.
fn skip_answer_name<C: PacketCursor + ?Sized>(
    cursor: &C,
    position: &mut usize,
    end: usize,
) -> bool {
    for _ in 0..MAX_DNS_LABELS {
        if !within(*position, 1, end) {
            return false;
        }
        let Some(label_len) = cursor.read_u8(*position) else {
            return false;
        };
        *position += 1;

        if label_len == 0 {
            return true;
        }
        if label_len & 0xC0 == 0xC0 {
            if !within(*position, 1, end) {
                return false;
            }
            *position += 1;
            return true;
        }
        if label_len > 63 || !within(*position, label_len as usize, end) {
            return false;
        }
        *position += label_len as usize;
    }

    false
}

/// Extracts the server name from a TLS ClientHello, if the first payload bytes
/// contain one.
pub fn extract_tls_sni<C: PacketCursor + ?Sized>(
    cursor: &C,
    offset: usize,
    end: usize,
    domain_buffer: &mut [u8; DOMAIN_MAX_LEN],
) -> Option<usize> {
    if !within(offset, 5, end) || cursor.read_u8(offset)? != 0x16 {
        return None;
    }
    let record_len = cursor.read_u16_be(offset + 3)? as usize;
    let mut position = offset + 5;
    if !within(position, record_len, end) || !within(position, 4, end) {
        return None;
    }
    if cursor.read_u8(position)? != 0x01 {
        return None;
    }
    let handshake_len = ((cursor.read_u8(position + 1)? as usize) << 16)
        | ((cursor.read_u8(position + 2)? as usize) << 8)
        | cursor.read_u8(position + 3)? as usize;
    if handshake_len < 34 || !within(position + 4, handshake_len, end) {
        return None;
    }
    position += 4 + 2 + 32;

    let session_len = cursor.read_u8(position)? as usize;
    position += 1;
    if !within(position, session_len, end) {
        return None;
    }
    position += session_len;

    if !within(position, 2, end) {
        return None;
    }
    let cipher_len = cursor.read_u16_be(position)? as usize;
    position += 2;
    if !within(position, cipher_len, end) {
        return None;
    }
    position += cipher_len;

    if !within(position, 1, end) {
        return None;
    }
    let compression_len = cursor.read_u8(position)? as usize;
    position += 1;
    if !within(position, compression_len, end) {
        return None;
    }
    position += compression_len;

    if !within(position, 2, end) {
        return None;
    }
    let extensions_len = cursor.read_u16_be(position)? as usize;
    position += 2;
    if !within(position, extensions_len, end) {
        return None;
    }
    let extensions_end = position + extensions_len;

    for _ in 0..MAX_TLS_EXTENSIONS {
        if !within(position, 4, extensions_end) {
            break;
        }
        let extension_type = cursor.read_u16_be(position)?;
        let extension_len = cursor.read_u16_be(position + 2)? as usize;
        position += 4;
        if !within(position, extension_len, extensions_end) {
            return None;
        }

        if extension_type == 0 {
            if extension_len < 5 {
                return None;
            }
            let list_len = cursor.read_u16_be(position)? as usize;
            if list_len + 2 > extension_len {
                return None;
            }
            if cursor.read_u8(position + 2)? != 0 {
                return None;
            }
            let name_len = cursor.read_u16_be(position + 3)? as usize;
            if name_len == 0
                || name_len > DOMAIN_MAX_LEN
                || !within(position + 5, name_len, extensions_end)
            {
                return None;
            }
            if !cursor.read_bytes(position + 5, &mut domain_buffer[..name_len]) {
                return None;
            }
            return Some(name_len);
        }

        position += extension_len;
    }

    None
}

/// Extracts the `Host` header from a plaintext HTTP request, without the port.
pub fn extract_http_host<C: PacketCursor + ?Sized>(
    cursor: &C,
    offset: usize,
    end: usize,
    domain_buffer: &mut [u8; DOMAIN_MAX_LEN],
) -> Option<usize> {
    let scan_end = end.min(offset + MAX_HTTP_SCAN);

    if !is_http_request(cursor, offset, scan_end) {
        return None;
    }

    let mut position = find_crlf(cursor, offset, scan_end)? + 2;

    for _ in 0..MAX_HTTP_HEADERS {
        if !within(position, 2, scan_end) {
            return None;
        }
        if cursor.read_u8(position)? == b'\r' && cursor.read_u8(position + 1)? == b'\n' {
            return None;
        }

        if header_is_host(cursor, position, scan_end) {
            position += 5;
            for _ in 0..MAX_HTTP_SCAN {
                if position >= scan_end {
                    break;
                }
                let Some(byte) = cursor.read_u8(position) else {
                    break;
                };
                if byte != b' ' && byte != b'\t' {
                    break;
                }
                position += 1;
            }

            let value_start = position;
            let mut length = 0usize;
            for _ in 0..MAX_HTTP_SCAN {
                if position >= scan_end {
                    break;
                }
                let Some(byte) = cursor.read_u8(position) else {
                    break;
                };
                if byte == b'\r' || byte == b'\n' || byte == b':' {
                    break;
                }
                if length < MAX_HTTP_HOST_LEN {
                    domain_buffer[length] = byte;
                    length += 1;
                }
                position += 1;
            }

            while length > 0 && matches!(domain_buffer[length - 1], b' ' | b'\t') {
                length -= 1;
            }
            if position == value_start || length == 0 {
                return None;
            }
            return Some(length);
        }

        position = find_crlf(cursor, position, scan_end)? + 2;
    }

    None
}

fn is_http_request<C: PacketCursor + ?Sized>(cursor: &C, offset: usize, end: usize) -> bool {
    if !within(offset, 4, end) {
        return false;
    }
    let (Some(b0), Some(b1), Some(b2), Some(b3)) = (
        cursor.read_u8(offset),
        cursor.read_u8(offset + 1),
        cursor.read_u8(offset + 2),
        cursor.read_u8(offset + 3),
    ) else {
        return false;
    };

    matches!(
        (b0, b1, b2, b3),
        (b'G', b'E', b'T', b' ')
            | (b'P', b'O', b'S', b'T')
            | (b'H', b'E', b'A', b'D')
            | (b'P', b'U', b'T', b' ')
            | (b'D', b'E', b'L', b'E')
            | (b'O', b'P', b'T', b'I')
            | (b'P', b'A', b'T', b'C')
            | (b'C', b'O', b'N', b'N')
    )
}

fn header_is_host<C: PacketCursor + ?Sized>(cursor: &C, position: usize, end: usize) -> bool {
    if !within(position, 5, end) {
        return false;
    }
    let (Some(b0), Some(b1), Some(b2), Some(b3), Some(b4)) = (
        cursor.read_u8(position),
        cursor.read_u8(position + 1),
        cursor.read_u8(position + 2),
        cursor.read_u8(position + 3),
        cursor.read_u8(position + 4),
    ) else {
        return false;
    };

    matches!(
        (b0, b1, b2, b3, b4),
        (b'H' | b'h', b'O' | b'o', b'S' | b's', b'T' | b't', b':')
    )
}

fn find_crlf<C: PacketCursor + ?Sized>(
    cursor: &C,
    mut position: usize,
    end: usize,
) -> Option<usize> {
    for _ in 0..MAX_HTTP_SCAN {
        if !within(position, 2, end) {
            return None;
        }
        if cursor.read_u8(position)? == b'\r' && cursor.read_u8(position + 1)? == b'\n' {
            return Some(position);
        }
        position += 1;
    }
    None
}

#[cfg(test)]
mod tests {
    extern crate std;

    use std::vec::Vec;

    use super::*;

    fn dns_response(question: &str, answers: &[(u32, [u8; 4])]) -> Vec<u8> {
        let mut message = Vec::new();
        message.extend_from_slice(&0x1234u16.to_be_bytes());
        message.extend_from_slice(&0x8180u16.to_be_bytes());
        message.extend_from_slice(&1u16.to_be_bytes());
        message.extend_from_slice(&(answers.len() as u16).to_be_bytes());
        message.extend_from_slice(&0u16.to_be_bytes());
        message.extend_from_slice(&0u16.to_be_bytes());
        for label in question.split('.') {
            message.push(label.len() as u8);
            message.extend_from_slice(label.as_bytes());
        }
        message.push(0);
        message.extend_from_slice(&1u16.to_be_bytes());
        message.extend_from_slice(&1u16.to_be_bytes());
        for (ttl, address) in answers {
            message.push(0xC0);
            message.push(0x0C);
            message.extend_from_slice(&1u16.to_be_bytes());
            message.extend_from_slice(&1u16.to_be_bytes());
            message.extend_from_slice(&ttl.to_be_bytes());
            message.extend_from_slice(&4u16.to_be_bytes());
            message.extend_from_slice(address);
        }
        message
    }

    fn client_hello(sni: &str) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[0u8; 32]);
        body.push(0);
        body.extend_from_slice(&2u16.to_be_bytes());
        body.extend_from_slice(&[0x13, 0x01]);
        body.push(1);
        body.push(0);

        let entry_len = 1 + 2 + sni.len();
        let mut server_name = Vec::new();
        server_name.extend_from_slice(&(entry_len as u16).to_be_bytes());
        server_name.push(0);
        server_name.extend_from_slice(&(sni.len() as u16).to_be_bytes());
        server_name.extend_from_slice(sni.as_bytes());

        let mut extensions = Vec::new();
        extensions.extend_from_slice(&0u16.to_be_bytes());
        extensions.extend_from_slice(&(server_name.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&server_name);

        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);

        let mut handshake = Vec::new();
        handshake.push(0x01);
        handshake.extend_from_slice(&[
            (body.len() >> 16) as u8,
            (body.len() >> 8) as u8,
            body.len() as u8,
        ]);
        handshake.extend_from_slice(&body);

        let mut record = Vec::new();
        record.push(0x16);
        record.extend_from_slice(&[0x03, 0x01]);
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    fn collect_dns(message: &[u8]) -> Vec<(std::string::String, DnsAnswer)> {
        let mut buffer = [0u8; DOMAIN_MAX_LEN];
        let mut seen = Vec::new();
        parse_dns_response(
            message,
            0,
            message.len(),
            &mut buffer,
            |domain, len, answer| {
                seen.push((
                    std::string::String::from_utf8_lossy(&domain[..len]).into_owned(),
                    answer,
                ));
            },
        );
        seen
    }

    #[test]
    fn dns_response_yields_domain_address_and_ttl() {
        let message = dns_response("Example.COM", &[(300, [93, 184, 216, 34])]);
        let answers = collect_dns(&message);

        assert_eq!(answers.len(), 1);
        assert_eq!(answers[0].0, "Example.COM");
        assert_eq!(answers[0].1.ttl_secs, 300);
        assert_eq!(&answers[0].1.address[12..], &[93, 184, 216, 34]);
    }

    #[test]
    fn dns_response_supports_multiple_answers() {
        let message = dns_response(
            "cdn.example.com",
            &[
                (60, [192, 0, 2, 1]),
                (60, [192, 0, 2, 2]),
                (60, [192, 0, 2, 3]),
            ],
        );
        let answers = collect_dns(&message);

        assert_eq!(answers.len(), 3);
        assert_eq!(&answers[2].1.address[12..], &[192, 0, 2, 3]);
    }

    #[test]
    fn dns_request_is_not_an_answer() {
        let mut message = dns_response("example.com", &[(300, [192, 0, 2, 1])]);
        message[2] = 0x01;
        message[3] = 0x00;

        assert!(collect_dns(&message).is_empty());
    }

    #[test]
    fn truncated_dns_never_panics() {
        let message = dns_response("example.com", &[(300, [192, 0, 2, 1])]);
        let mut buffer = [0u8; DOMAIN_MAX_LEN];

        for len in 0..message.len() {
            parse_dns_response(&message[..len], 0, len, &mut buffer, |_, _, _| {
                panic!("no answer from a truncated message")
            });
        }
    }

    #[test]
    fn tls_client_hello_yields_sni() {
        let record = client_hello("cdn.example.com");
        let mut buffer = [0u8; DOMAIN_MAX_LEN];

        let len =
            extract_tls_sni(&record[..], 0, record.len(), &mut buffer).expect("sni is present");
        assert_eq!(&buffer[..len], b"cdn.example.com");
    }

    #[test]
    fn tls_non_handshake_is_ignored() {
        let mut record = client_hello("cdn.example.com");
        record[0] = 0x17;

        let mut buffer = [0u8; DOMAIN_MAX_LEN];
        assert_eq!(
            extract_tls_sni(&record[..], 0, record.len(), &mut buffer),
            None
        );
    }

    #[test]
    fn truncated_tls_never_panics() {
        let record = client_hello("cdn.example.com");
        let mut buffer = [0u8; DOMAIN_MAX_LEN];

        for len in 0..record.len() {
            let _ = extract_tls_sni(&record[..len], 0, len, &mut buffer);
        }
    }

    #[test]
    fn http_host_is_extracted_without_port() {
        let request = b"GET /index HTTP/1.1\r\nUser-Agent: test\r\nHost: Example.COM:8080\r\nAccept: */*\r\n\r\n";
        let mut buffer = [0u8; DOMAIN_MAX_LEN];

        let len = extract_http_host(&request[..], 0, request.len(), &mut buffer)
            .expect("host is present");
        assert_eq!(&buffer[..len], b"Example.COM");
    }

    #[test]
    fn http_post_is_supported() {
        let request = b"POST /api HTTP/1.0\r\nhost: api.example.com\r\n\r\n";
        let mut buffer = [0u8; DOMAIN_MAX_LEN];

        let len = extract_http_host(&request[..], 0, request.len(), &mut buffer)
            .expect("host is present");
        assert_eq!(&buffer[..len], b"api.example.com");
    }

    #[test]
    fn http_without_host_is_ignored() {
        let request = b"GET / HTTP/1.1\r\nUser-Agent: test\r\n\r\n";
        let mut buffer = [0u8; DOMAIN_MAX_LEN];

        assert_eq!(
            extract_http_host(&request[..], 0, request.len(), &mut buffer),
            None
        );
    }

    #[test]
    fn non_http_payload_is_ignored() {
        let payload = b"\x16\x03\x01\x00\x50binary";
        let mut buffer = [0u8; DOMAIN_MAX_LEN];

        assert_eq!(
            extract_http_host(&payload[..], 0, payload.len(), &mut buffer),
            None
        );
    }
}
