//! Minimal HTTP/1.1 client for the proxy control API.

use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpStream, ToSocketAddrs},
    time::Duration,
};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
const READ_TIMEOUT: Duration = Duration::from_secs(3);

pub(super) struct Target {
    pub(super) url: String,
    pub(super) secret: String,
}

/// Fetches `GET /connections` and returns the decoded response body.
pub(super) fn fetch_body(target: &Target) -> Result<Vec<u8>, String> {
    let (authority, path) = parse_url(&target.url)?;
    let mut addresses = authority
        .to_socket_addrs()
        .map_err(|error| format!("resolve {authority}: {error}"))?;
    let address: SocketAddr = addresses
        .next()
        .ok_or_else(|| format!("no address for {authority}"))?;
    let mut stream = TcpStream::connect_timeout(&address, CONNECT_TIMEOUT)
        .map_err(|error| format!("connect {address}: {error}"))?;
    stream
        .set_read_timeout(Some(READ_TIMEOUT))
        .and_then(|()| stream.set_write_timeout(Some(READ_TIMEOUT)))
        .map_err(|error| format!("configure socket: {error}"))?;

    let request = format!(
        "GET {path}/connections HTTP/1.1\r\nHost: {authority}\r\nAuthorization: Bearer {}\r\nConnection: close\r\n\r\n",
        target.secret
    );
    stream
        .write_all(request.as_bytes())
        .map_err(|error| format!("send request: {error}"))?;
    let mut raw = Vec::new();
    stream
        .read_to_end(&mut raw)
        .map_err(|error| format!("read response: {error}"))?;

    let (head, body) = split_response(&raw)?;
    let status = head.lines().next().unwrap_or_default();
    if !status.contains(" 200") {
        if status.contains(" 401") {
            return Err("controller rejected the secret (401 Unauthorized)".to_owned());
        }
        return Err(format!("controller returned {status}"));
    }
    decode_body(&head, body)
}

/// Splits an HTTP response into head text and body bytes; the body starts
/// after the `\r\n\r\n` terminator, not at it.
fn split_response(raw: &[u8]) -> Result<(String, &[u8]), String> {
    let separator = raw
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| "malformed HTTP response".to_owned())?;
    let head = String::from_utf8_lossy(&raw[..separator]).into_owned();
    Ok((head, &raw[separator + 4..]))
}

/// Decodes `Transfer-Encoding: chunked` bodies; the controller uses chunked
/// framing even for single JSON documents.
fn decode_body(head: &str, body: &[u8]) -> Result<Vec<u8>, String> {
    let chunked = head.lines().any(|line| {
        let lower = line.to_ascii_lowercase();
        lower.starts_with("transfer-encoding:") && lower.contains("chunked")
    });
    if !chunked {
        return Ok(body.to_vec());
    }

    let mut decoded = Vec::with_capacity(body.len());
    let mut position = 0usize;
    loop {
        let line_end = body[position..]
            .windows(2)
            .position(|window| window == b"\r\n")
            .map(|offset| position + offset)
            .ok_or_else(|| "malformed chunked response: missing size line".to_owned())?;
        let size_line = std::str::from_utf8(&body[position..line_end])
            .map_err(|_| "malformed chunked response: non-UTF-8 size".to_owned())?;
        let size = usize::from_str_radix(size_line.split(';').next().unwrap_or("").trim(), 16)
            .map_err(|_| "malformed chunked response: bad chunk size".to_owned())?;
        position = line_end + 2;
        if size == 0 {
            return Ok(decoded);
        }
        let end = position + size;
        if end > body.len() {
            return Err("malformed chunked response: truncated chunk".to_owned());
        }
        decoded.extend_from_slice(&body[position..end]);
        position = end;
        if body.get(position..position + 2) != Some(b"\r\n") {
            return Err("malformed chunked response: missing chunk terminator".to_owned());
        }
        position += 2;
    }
}

/// Parses `http://host:port[/prefix]` into authority and path.
fn parse_url(url: &str) -> Result<(String, String), String> {
    let rest = url
        .strip_prefix("http://")
        .ok_or_else(|| "only http:// controller URLs are supported".to_owned())?;
    let (authority, path) = match rest.split_once('/') {
        Some((authority, path)) => (authority, format!("/{path}")),
        None => (rest, String::new()),
    };
    if authority.is_empty() {
        return Err("controller URL has no host".to_owned());
    }
    Ok((authority.to_owned(), path))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_chunked_body() {
        let body = b"18\r\n{\"connections\":[],\"a\":1}\r\n0\r\n\r\n";
        let head = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked";
        assert_eq!(
            decode_body(head, body).expect("decode"),
            b"{\"connections\":[],\"a\":1}"
        );
    }

    #[test]
    fn splits_headers_from_chunked_body() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n12\r\n{\"connections\":[]}\r\n0\r\n\r\n";
        let (head, body) = split_response(raw).expect("split");
        assert_eq!(head.lines().next(), Some("HTTP/1.1 200 OK"));
        assert_eq!(
            decode_body(&head, body).expect("decode"),
            b"{\"connections\":[]}"
        );
    }

    #[test]
    fn decodes_split_chunks() {
        let body = b"5\r\n{\"a\":\r\n5\r\n1234}\r\n0\r\n\r\n";
        let head = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked";
        assert_eq!(decode_body(head, body).expect("decode"), b"{\"a\":1234}");
    }

    #[test]
    fn passes_through_plain_body() {
        let body = b"{\"connections\":[]}";
        let head = "HTTP/1.1 200 OK\r\nContent-Length: 18";
        assert_eq!(decode_body(head, body).expect("decode"), body);
    }

    #[test]
    fn rejects_truncated_chunks() {
        let body = b"20\r\nshort\r\n0\r\n\r\n";
        let head = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked";
        assert!(decode_body(head, body).is_err());
    }

    #[test]
    fn parses_controller_urls() {
        assert_eq!(
            parse_url("http://192.168.100.3:9090").expect("url"),
            ("192.168.100.3:9090".to_owned(), String::new())
        );
        assert_eq!(
            parse_url("http://192.168.100.3:9090/api").expect("url"),
            ("192.168.100.3:9090".to_owned(), "/api".to_owned())
        );
        assert!(parse_url("https://192.168.100.3:9090").is_err());
        assert!(parse_url("http://").is_err());
    }
}
