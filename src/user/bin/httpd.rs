#![no_std]
extern crate alloc;

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use ulib::http::{HttpRequest, HttpResponse, HttpStatus};
use ulib::sys::{self, Error};
use ulib::{accept, close, env, fs, io, listen, print, println, recv, send, socket};

const DEFAULT_PORT: u16 = 8080;
const REQUEST_BUFFER_SIZE: usize = 8192;
const SEND_RETRY_TICKS: usize = 1;

struct Config {
    port: u16,
    doc_root: String,
}

impl Config {
    fn parse() -> Result<Self, String> {
        let mut args = env::args();
        let _prog = args.next();

        let mut port = DEFAULT_PORT;
        let mut doc_root: Option<String> = None;

        while let Some(arg) = args.next() {
            if let Ok(p) = arg.parse::<u16>() {
                port = p;
            } else {
                doc_root = Some(String::from(arg));
            }
        }

        let doc_root = doc_root.ok_or("document root is required".to_string())?;

        Ok(Config { port, doc_root })
    }
}

fn main() {
    let config = match Config::parse() {
        Ok(c) => c,
        Err(e) => {
            println!("[httpd] error: {}", e);
            println!("[httpd] usage: httpd [port] <document_root>");
            println!("[httpd]   port: listen port (default: 8080)");
            println!("[httpd]   document_root: path to serve files from");
            return;
        }
    };

    println!("[httpd] octox-httpd/0.1");
    println!("[httpd] document root: {}", config.doc_root);
    println!("[httpd] listening on port {}", config.port);

    if let Err(e) = run_server(config) {
        println!("[httpd] server error: {}", e);
    }
}

fn run_server(config: Config) -> Result<(), String> {
    let sock = socket().map_err(|e| format!("failed to create socket: {:?}", e))?;

    listen(sock, config.port).map_err(|e| format!("listen failed: {:?}", e))?;

    println!("[httpd] server started successfully");

    loop {
        match accept(sock) {
            Ok(conn_sock) => {
                if let Err(e) = handle_connection(conn_sock, &config.doc_root) {
                    println!("[httpd] connection error: {}", e);
                }
                let _ = close(conn_sock);
            }
            Err(e) => {
                println!("[httpd] accept failed: {:?}", e);
            }
        }
    }
}

fn handle_connection(sock: usize, doc_root: &str) -> Result<(), String> {
    let request_data = read_request(sock)?;

    let request = match HttpRequest::parse(&request_data) {
        Ok(req) => req,
        Err(_) => {
            let response = HttpResponse::error(HttpStatus::BadRequest);
            send_response(sock, &response)?;
            return Ok(());
        }
    };

    println!("[httpd] {} {}", request.method().as_str(), request.uri());

    let path = match HttpResponse::validate_path(request.uri()) {
        Ok(p) => p,
        Err(status) => {
            let response = HttpResponse::error(status);
            send_response(sock, &response)?;
            return Ok(());
        }
    };

    let full_path = build_full_path(doc_root, &path);

    match read_file(&full_path) {
        Ok(content) => {
            let response = HttpResponse::from_file_content(&path, content);
            send_response(sock, &response)?;
        }
        Err(FileError::NotFound) => {
            let response = HttpResponse::error(HttpStatus::NotFound);
            send_response(sock, &response)?;
        }
        Err(FileError::ReadError) => {
            let response = HttpResponse::error(HttpStatus::InternalServerError);
            send_response(sock, &response)?;
        }
    }

    Ok(())
}

fn read_request(sock: usize) -> Result<Vec<u8>, String> {
    let mut buffer = Vec::with_capacity(REQUEST_BUFFER_SIZE);
    let mut tmp = [0u8; 256];

    loop {
        match recv(sock, &mut tmp) {
            Ok(0) => {
                return Err("connection closed before complete request".to_string());
            }
            Ok(n) => {
                buffer.extend_from_slice(&tmp[..n]);

                if has_header_end(&buffer) {
                    break;
                }

                if buffer.len() >= REQUEST_BUFFER_SIZE {
                    return Err("request too large".to_string());
                }
            }
            Err(_) => {
                return Err("recv failed".to_string());
            }
        }
    }

    Ok(buffer)
}

fn has_header_end(data: &[u8]) -> bool {
    if data.len() < 4 {
        return false;
    }

    for window in data.windows(4) {
        if window == b"\r\n\r\n" {
            return true;
        }
    }

    false
}

fn send_response(sock: usize, response: &HttpResponse) -> Result<(), String> {
    let bytes = response.to_bytes();
    let total = bytes.len();
    let mut sent = 0;

    println!("[httpd] sending {} bytes", total);

    while sent < bytes.len() {
        match send(sock, &bytes[sent..]) {
            Ok(0) => {
                let _ = sys::sleep(SEND_RETRY_TICKS);
            }
            Ok(n) => {
                sent += n;
                println!("[httpd] sent {} bytes (total: {}/{})", n, sent, total);
            }
            Err(Error::BufferFull) | Err(Error::WouldBlock) => {
                let _ = sys::sleep(SEND_RETRY_TICKS);
            }
            Err(_) => {
                println!("[httpd] send failed at {}/{}", sent, total);
                return Err("send failed".to_string());
            }
        }
    }

    println!("[httpd] send complete");
    Ok(())
}

fn build_full_path(doc_root: &str, path: &str) -> String {
    if doc_root.ends_with('/') {
        format!("{}{}", doc_root, path)
    } else {
        format!("{}/{}", doc_root, path)
    }
}

enum FileError {
    NotFound,
    ReadError,
}

fn read_file(path: &str) -> Result<Vec<u8>, FileError> {
    let mut file = fs::File::open(path).map_err(|_| FileError::NotFound)?;

    let metadata = file.metadata().map_err(|_| FileError::ReadError)?;
    let file_size = metadata.len();

    let mut content = Vec::with_capacity(file_size);
    let mut buffer = [0u8; 512];

    loop {
        match io::Read::read(&mut file, &mut buffer) {
            Ok(0) => break,
            Ok(n) => content.extend_from_slice(&buffer[..n]),
            Err(_) => return Err(FileError::ReadError),
        }
    }

    Ok(content)
}
