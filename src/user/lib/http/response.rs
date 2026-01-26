use crate::http::header::HttpHeader;
use crate::http::mime::mime_type_from_path;
use crate::http::status::HttpStatus;
use crate::http::version::HttpVersion;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

pub struct HttpResponse {
    version: HttpVersion,
    status: HttpStatus,
    headers: Vec<HttpHeader>,
    body: Vec<u8>,
}

impl HttpResponse {
    pub fn new(status: HttpStatus) -> Self {
        Self {
            version: HttpVersion::Http11,
            status,
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    pub fn add_header(&mut self, name: String, value: String) {
        self.headers.push(HttpHeader::new(name, value));
    }

    pub fn set_body(&mut self, body: Vec<u8>) {
        self.body = body;
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut result = Vec::new();

        let status_line = format!(
            "{} {} {}\r\n",
            self.version.as_str(),
            self.status.code(),
            self.status.message()
        );
        result.extend_from_slice(status_line.as_bytes());

        for header in &self.headers {
            let header_line = format!("{}: {}\r\n", header.name(), header.value());
            result.extend_from_slice(header_line.as_bytes());
        }

        result.extend_from_slice(b"\r\n");

        result.extend_from_slice(&self.body);

        result
    }

    pub fn from_file_content(path: &str, content: Vec<u8>) -> Self {
        let mut response = Self::new(HttpStatus::Ok);

        let mime_type = mime_type_from_path(path);
        response.add_header("Content-Type".to_string(), mime_type.to_string());
        response.add_header("Content-Length".to_string(), content.len().to_string());
        response.add_header("Connection".to_string(), "close".to_string());
        response.add_header("Server".to_string(), "octox-httpd/0.1".to_string());
        response.set_body(content);

        response
    }

    pub fn validate_path(uri: &str) -> core::result::Result<String, HttpStatus> {
        if uri.contains("..") {
            return Err(HttpStatus::Forbidden);
        }

        let path = uri.trim_start_matches('/');

        let path = if path.is_empty() {
            "index.html".to_string()
        } else {
            path.to_string()
        };

        Ok(path)
    }

    pub fn error(status: HttpStatus) -> Self {
        let mut response = Self::new(status);

        let html = format!(
            "<!DOCTYPE html>\n\
             <html>\n\
             <head><title>{} {}</title></head>\n\
             <body>\n\
             <h1>{} {}</h1>\n\
             <p>octox-httpd/0.1</p>\n\
             </body>\n\
             </html>\n",
            status.code(),
            status.message(),
            status.code(),
            status.message()
        );

        response.add_header("Content-Type".to_string(), "text/html".to_string());
        response.add_header("Content-Length".to_string(), html.len().to_string());
        response.add_header("Connection".to_string(), "close".to_string());
        response.add_header("Server".to_string(), "octox-httpd/0.1".to_string());

        response.set_body(html.into_bytes());

        response
    }
}
