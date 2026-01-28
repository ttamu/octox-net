#![no_std]
extern crate alloc;

use alloc::string::String;
use ulib::io::{Read, Write};
use ulib::stdio::{stdin, stdout};
use ulib::{accept, close, connect, env, listen, print, println, recv, send, socket, sys};
use args::{Error, Mode};

const COLOR_RESET: &str = "\x1b[0m";
const COLOR_RED: &str = "\x1b[31m";
const COLOR_GREEN: &str = "\x1b[32m";
const COLOR_CYAN: &str = "\x1b[36m";
const IO_BUF_SIZE: usize = 1024;

mod args {
    use alloc::string::String;
    use alloc::vec::Vec;
    use ulib::env;

    pub enum Mode {
        Listen { port: u16 },
        Connect { addr: String, port: u16 },
    }

    pub enum Error {
        Usage,
        UnknownArg(&'static str),
        InvalidPort(&'static str),
    }

    pub fn parse() -> Result<Mode, Error> {
        let mut args = env::args();
        let _prog = args.next();

        let mut listen_mode = false;
        let mut positional: Vec<&'static str> = Vec::new();

        for arg in args {
            if arg == "-l" {
                listen_mode = true;
                continue;
            }
            if arg.starts_with('-') {
                return Err(Error::UnknownArg(arg));
            }
            positional.push(arg);
        }

        if listen_mode {
            if positional.len() != 1 {
                return Err(Error::Usage);
            }
            let port = parse_port(positional[0])?;
            return Ok(Mode::Listen { port });
        }

        if positional.len() != 2 {
            return Err(Error::Usage);
        }

        let addr = String::from(positional[0]);
        let port = parse_port(positional[1])?;

        Ok(Mode::Connect { addr, port })
    }

    fn parse_port(arg: &'static str) -> Result<u16, Error> {
        arg.parse::<u16>().map_err(|_| Error::InvalidPort(arg))
    }
}

struct Connection {
    sock: usize,
}

impl Connection {
    const CHILD_PROCESS: usize = 0;

    fn listen(port: u16) -> Result<Self, String> {
        let sock = socket().map_err(|e| alloc::format!("failed to create socket: {:?}", e))?;

        println!("[nc] listening on port {}", port);
        listen(sock, port).map_err(|e| alloc::format!("listen failed: {:?}", e))?;

        println!("[nc] waiting for connection...");
        let conn_sock = accept(sock).map_err(|e| alloc::format!("accept failed: {:?}", e))?;
        println!("{}[nc] connection accepted{}", COLOR_GREEN, COLOR_RESET);

        let _ = close(sock);

        Ok(Self { sock: conn_sock })
    }

    fn connect(addr: String, port: u16) -> Result<Self, String> {
        let sock = socket().map_err(|e| alloc::format!("failed to create socket: {:?}", e))?;

        println!("[nc] connecting to {}:{}", addr, port);
        let local_port = 40000 + (sys::getpid().unwrap_or(0) as u16 % 10000); // TODO: エフェメラルポート割り当てもちゃんとする

        connect(sock, &addr, port, local_port)
            .map_err(|e| alloc::format!("connect failed: {:?}", e))?;
        println!("{}[nc] connected{}", COLOR_GREEN, COLOR_RESET);

        Ok(Self { sock })
    }

    fn start(self) {
        let pid = match sys::fork() {
            Ok(pid) => pid,
            Err(e) => {
                println!("{}[nc] fork failed: {:?}{}", COLOR_RED, e, COLOR_RESET);
                let _ = close(self.sock);
                return;
            }
        };

        if pid == Self::CHILD_PROCESS {
            self.receive_loop();
        } else {
            self.send_loop(pid);
        }
    }

    fn receive_loop(&self) {
        let mut buf = [0u8; IO_BUF_SIZE];
        loop {
            match recv(self.sock, &mut buf) {
                Ok(0) => {
                    println!("{}[nc] connection closed{}", COLOR_GREEN, COLOR_RESET);
                    break;
                }
                Ok(n) => {
                    let mut out = stdout();
                    let _ = out.write(COLOR_CYAN.as_bytes());
                    let _ = out.write(&buf[..n]);
                    let _ = out.write(COLOR_RESET.as_bytes());
                }
                Err(_) => {
                    break;
                }
            }
        }
        sys::exit(0);
    }

    fn send_loop(&self, child_pid: usize) {
        let mut buf = [0u8; IO_BUF_SIZE];
        let mut input = stdin();

        loop {
            match input.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if let Err(_) = send(self.sock, &buf[..n]) {
                        break;
                    }
                }
                Err(_) => break,
            }
        }

        let _ = close(self.sock);
        let _ = sys::kill(child_pid);
        let mut status = 0;
        let _ = sys::wait(&mut status);
    }
}

fn print_usage() {
    println!("usage: nc -l <port>");
    println!("       nc <host> <port>");
}

fn main() {
    let mode = match args::parse() {
        Ok(mode) => mode,
        Err(Error::Usage) => {
            println!("{}error: invalid arguments{}", COLOR_RED, COLOR_RESET);
            print_usage();
            return;
        }
        Err(Error::UnknownArg(arg)) => {
            println!("{}error: unknown option: {}{}", COLOR_RED, arg, COLOR_RESET);
            print_usage();
            return;
        }
        Err(Error::InvalidPort(arg)) => {
            println!("{}error: invalid port: {}{}", COLOR_RED, arg, COLOR_RESET);
            print_usage();
            return;
        }
    };

    let conn = match mode {
        Mode::Listen { port } => Connection::listen(port),
        Mode::Connect { addr, port } => Connection::connect(addr, port),
    };

    match conn {
        Ok(connection) => connection.start(),
        Err(e) => println!("{}[nc] error: {}{}", COLOR_RED, e, COLOR_RESET),
    }
}
