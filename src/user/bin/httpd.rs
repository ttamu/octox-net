#![no_std]
extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use ulib::http::{HttpRequest, HttpResponse, HttpStatus};
use ulib::sys::{self, Error};
use ulib::{accept, close, fs, io, listen, print, println, recv, send, socket};
use args::{Args, Error as ArgsError};

const DEFAULT_PORT: u16 = 8080;
const REQUEST_BUFFER_SIZE: usize = 8192;
const SEND_RETRY_TICKS: usize = 1;

mod args {
    use alloc::string::String;
    use ulib::env;

    pub struct Args {
        pub port: u16,
        pub doc_root: String,
    }

    pub enum Error {
        MissingDocRoot,
    }

    impl Args {
        pub fn parse() -> Result<Self, Error> {
            let mut args = env::args();
            let _prog = args.next();

            let mut port = super::DEFAULT_PORT;
            let mut doc_root: Option<String> = None;

            while let Some(arg) = args.next() {
                if let Ok(p) = arg.parse::<u16>() {
                    port = p;
                } else {
                    doc_root = Some(String::from(arg));
                }
            }

            let doc_root = doc_root.ok_or(Error::MissingDocRoot)?;

            Ok(Args { port, doc_root })
        }
    }
}

enum FileError {
    NotFound,
    ReadError,
}

struct Server {
    port: u16,
    doc_root: String,
}

impl Server {
    fn new(port: u16, doc_root: String) -> Self {
        Self { port, doc_root }
    }

    fn run(&self) -> Result<(), String> {
        let sock = self.open_listener()?;

        println!("[httpd] server started successfully");

        loop {
            match accept(sock) {
                Ok(conn_sock) => {
                    if let Err(e) = self.handle_connection(conn_sock) {
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

    fn open_listener(&self) -> Result<usize, String> {
        let sock = socket().map_err(|e| alloc::format!("failed to create socket: {:?}", e))?;
        listen(sock, self.port).map_err(|e| alloc::format!("listen failed: {:?}", e))?;
        Ok(sock)
    }

    fn handle_connection(&self, sock: usize) -> Result<(), String> {
        let request_data = Self::read_request_headers(sock)?;
        let request = match Self::parse_request(&request_data) {
            Ok(req) => req,
            Err(status) => {
                Self::send_status(sock, status)?;
                return Ok(());
            }
        };

        println!("[httpd] {} {}", request.method().as_str(), request.uri());

        let path = match Self::validate_request_path(&request) {
            Ok(p) => p,
            Err(status) => {
                Self::send_status(sock, status)?;
                return Ok(());
            }
        };

        let full_path = self.build_full_path(&path);
        let response = match Self::read_file(&full_path) {
            Ok(content) => HttpResponse::from_file_content(&path, content),
            Err(err) => HttpResponse::error(Self::file_error_status(err)),
        };

        Self::send_response(sock, &response)
    }

    fn read_request_headers(sock: usize) -> Result<Vec<u8>, String> {
        let mut buffer = Vec::with_capacity(REQUEST_BUFFER_SIZE);
        let mut tmp = [0u8; 256];

        loop {
            match recv(sock, &mut tmp) {
                Ok(0) => {
                    return Err(String::from("connection closed before complete request"));
                }
                Ok(n) => {
                    buffer.extend_from_slice(&tmp[..n]);

                    if Self::has_header_end(&buffer) {
                        break;
                    }

                    if buffer.len() >= REQUEST_BUFFER_SIZE {
                        return Err(String::from("request too large"));
                    }
                }
                Err(_) => {
                    return Err(String::from("recv failed"));
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

    fn parse_request(data: &[u8]) -> Result<HttpRequest, HttpStatus> {
        HttpRequest::parse(data).map_err(|_| HttpStatus::BadRequest)
    }

    fn validate_request_path(request: &HttpRequest) -> Result<String, HttpStatus> {
        HttpResponse::validate_path(request.uri())
    }

    fn send_status(sock: usize, status: HttpStatus) -> Result<(), String> {
        let response = HttpResponse::error(status);
        Self::send_response(sock, &response)
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
                    return Err(String::from("send failed"));
                }
            }
        }

        println!("[httpd] send complete");
        Ok(())
    }

    fn build_full_path(&self, path: &str) -> String {
        if self.doc_root.ends_with('/') {
            alloc::format!("{}{}", self.doc_root, path)
        } else {
            alloc::format!("{}/{}", self.doc_root, path)
        }
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

    fn file_error_status(err: FileError) -> HttpStatus {
        match err {
            FileError::NotFound => HttpStatus::NotFound,
            FileError::ReadError => HttpStatus::InternalServerError,
        }
    }
}

fn print_usage() {
    println!("[httpd] usage: httpd [port] <document_root>");
    println!("[httpd]   port: listen port (default: 8080)");
    println!("[httpd]   document_root: path to serve files from");
}

fn main() {
    let args = match Args::parse() {
        Ok(args) => args,
        Err(ArgsError::MissingDocRoot) => {
            println!("[httpd] error: document root is required");
            print_usage();
            return;
        }
    };

    println!("[httpd] octox-httpd/0.1");
    println!("[httpd] document root: {}", args.doc_root);
    println!("[httpd] listening on port {}", args.port);

    let server = Server::new(args.port, args.doc_root);
    if let Err(e) = server.run() {
        println!("[httpd] server error: {}", e);
    }
}
