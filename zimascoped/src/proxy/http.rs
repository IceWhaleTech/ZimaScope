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

    let (status, chunked, body) = parse_response(&raw)?;
    if status != 200 {
        if status == 401 {
            return Err("controller rejected the secret (401 Unauthorized)".to_owned());
        }
        let status_line = raw.split(|byte| *byte == b'\n').next().unwrap_or_default();
        let status_line = String::from_utf8_lossy(status_line);
        return Err(format!("controller returned {}", status_line.trim_end()));
    }
    decode_body(chunked, body)
}

/// Parses the response head with `httparse`, returning the status code, whether
/// the body is chunked and the body bytes.
fn parse_response(raw: &[u8]) -> Result<(u16, bool, &[u8]), String> {
    let mut headers = [httparse::EMPTY_HEADER; 32];
    let mut response = httparse::Response::new(&mut headers);
    let head_len = match response.parse(raw) {
        Ok(httparse::Status::Complete(length)) => length,
        Ok(httparse::Status::Partial) => {
            return Err("malformed HTTP response: incomplete head".to_owned());
        }
        Err(error) => return Err(format!("malformed HTTP response: {error}")),
    };
    let status = response
        .code
        .ok_or_else(|| "malformed HTTP response: no status code".to_owned())?;
    let chunked = response.headers.iter().any(|header| {
        header.name.eq_ignore_ascii_case("transfer-encoding")
            && header
                .value
                .split(|byte| *byte == b',')
                .any(|token| token.trim_ascii().eq_ignore_ascii_case(b"chunked"))
    });
    Ok((status, chunked, &raw[head_len..]))
}

/// Decodes `Transfer-Encoding: chunked` bodies; the controller uses chunked
/// framing even for single JSON documents.
fn decode_body(chunked: bool, body: &[u8]) -> Result<Vec<u8>, String> {
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
        assert_eq!(
            decode_body(true, body).expect("decode"),
            b"{\"connections\":[],\"a\":1}"
        );
    }

    #[test]
    fn parses_status_headers_and_chunked_body() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n12\r\n{\"connections\":[]}\r\n0\r\n\r\n";
        let (status, chunked, body) = parse_response(raw).expect("parse");
        assert_eq!(status, 200);
        assert!(chunked);
        assert_eq!(
            decode_body(chunked, body).expect("decode"),
            b"{\"connections\":[]}"
        );
    }

    #[test]
    fn detects_chunked_case_insensitively() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, Chunked\r\n\r\n";
        let (_, chunked, _) = parse_response(raw).expect("parse");
        assert!(chunked);
    }

    #[test]
    fn reports_non_success_status() {
        let raw = b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
        let (status, chunked, _) = parse_response(raw).expect("parse");
        assert_eq!(status, 404);
        assert!(!chunked);
    }

    #[test]
    fn rejects_a_truncated_head() {
        assert!(parse_response(b"HTTP/1.1 200 OK\r\n").is_err());
    }

    #[test]
    fn decodes_split_chunks() {
        let body = b"5\r\n{\"a\":\r\n5\r\n1234}\r\n0\r\n\r\n";
        assert_eq!(decode_body(true, body).expect("decode"), b"{\"a\":1234}");
    }

    #[test]
    fn passes_through_plain_body() {
        let body = b"{\"connections\":[]}";
        assert_eq!(decode_body(false, body).expect("decode"), body);
    }

    #[test]
    fn rejects_truncated_chunks() {
        let body = b"20\r\nshort\r\n0\r\n\r\n";
        assert!(decode_body(true, body).is_err());
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
