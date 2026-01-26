use crate::http::error::Error;
use crate::http::header::HttpHeader;
use crate::http::method::HttpMethod;
use crate::http::version::HttpVersion;
use crate::http::Result;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

#[derive(Debug, Clone, PartialEq)]
pub struct HttpRequest {
    method: HttpMethod,
    uri: String,
    version: HttpVersion,
    headers: Vec<HttpHeader>,
}

impl HttpRequest {
    pub fn parse(data: &[u8]) -> Result<Self> {
        let text = core::str::from_utf8(data).map_err(|_| Error::InvalidHttpRequest)?;

        let mut lines = text.split("\r\n");

        let request_line = lines.next().ok_or(Error::InvalidHttpRequest)?;
        let (method, uri, version) = Self::parse_request_line(request_line)?;

        let mut headers = Vec::new();
        for line in lines {
            if line.is_empty() {
                break;
            }
            headers.push(Self::parse_header_line(line)?);
        }

        Ok(Self {
            method,
            uri,
            version,
            headers,
        })
    }

    fn parse_request_line(line: &str) -> Result<(HttpMethod, String, HttpVersion)> {
        let mut parts = line.split_whitespace();

        let method_str = parts.next().ok_or(Error::InvalidHttpRequest)?;
        let uri = parts.next().ok_or(Error::InvalidHttpRequest)?;
        let version_str = parts.next().ok_or(Error::InvalidHttpRequest)?;

        let method = HttpMethod::from_str(method_str)?;
        let version = HttpVersion::from_str(version_str)?;

        Ok((method, uri.to_string(), version))
    }

    fn parse_header_line(line: &str) -> Result<HttpHeader> {
        let colon_pos = line.find(':').ok_or(Error::InvalidHttpRequest)?;

        let name = line[..colon_pos].trim().to_string();
        let value = line[colon_pos + 1..].trim().to_string();

        Ok(HttpHeader::new(name, value))
    }

    pub fn method(&self) -> HttpMethod {
        self.method
    }

    pub fn uri(&self) -> &str {
        &self.uri
    }

    pub fn version(&self) -> HttpVersion {
        self.version
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|h| h.name_eq_ignore_case(name))
            .map(|h| h.value())
    }
}
