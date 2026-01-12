#![no_std]
extern crate alloc;

use alloc::string::String;
use ulib::io::{Read, Write};
use ulib::stdio::{stdin, stdout};
use ulib::{
    env, print, println, sys, tcp_accept, tcp_close, tcp_connect, tcp_listen, tcp_recv, tcp_send,
    tcp_socket,
};

const COLOR_RESET: &str = "\x1b[0m";
const COLOR_RED: &str = "\x1b[31m";
const COLOR_GREEN: &str = "\x1b[32m";
const COLOR_CYAN: &str = "\x1b[36m";

fn main() {
    let mut args = env::args();
    let _prog = args.next();

    // Parse arguments
    let mut listen_mode = false;
    let mut addr = String::from("0.0.0.0");
    let mut port: u16 = 0;

    while let Some(arg) = args.next() {
        if arg == "-l" {
            listen_mode = true;
        } else {
            // Check if it's a port number
            if let Ok(p) = arg.parse::<u16>() {
                port = p;
            } else {
                // Otherwise treat as IP address (only if we don't have one yet, or overwrite default)
                // Note: strict check would be better, but simple parsing for now
                if arg.contains('.') {
                    addr = String::from(arg);
                }
            }
        }
    }

    if port == 0 {
        println!("Usage:");
        println!("  Client: nc <ip> <port>");
        println!("  Server: nc -l <port>");
        return;
    }

    let sock = match tcp_socket() {
        Ok(s) => s,
        Err(e) => {
            println!(
                "{}[nc] failed to create socket: {:?}{}",
                COLOR_RED, e, COLOR_RESET
            );
            return;
        }
    };

    if listen_mode {
        println!("[nc] listening on port {}", port);
        if let Err(e) = tcp_listen(sock, port) {
            println!("{}[nc] listen failed: {:?}{}", COLOR_RED, e, COLOR_RESET);
            return;
        }

        println!("[nc] waiting for connection...");
        let client_sock = match tcp_accept(sock) {
            Ok(s) => s,
            Err(e) => {
                println!("{}[nc] accept failed: {:?}{}", COLOR_RED, e, COLOR_RESET);
                return;
            }
        };
        println!("{}[nc] connection accepted{}", COLOR_GREEN, COLOR_RESET);

        // Use the accepted socket for communication
        // Close the listening socket as we only handle one connection in this simple nc
        let _ = tcp_close(sock);

        run_communication(client_sock);
    } else {
        println!("[nc] connecting to {}:{}", addr, port);
        // Use a random local port
        let local_port = 40000 + (sys::getpid().unwrap_or(0) as u16 % 10000);

        if let Err(e) = tcp_connect(sock, &addr, port, local_port) {
            println!("{}[nc] connect failed: {:?}{}", COLOR_RED, e, COLOR_RESET);
            return;
        }
        println!("{}[nc] connected{}", COLOR_GREEN, COLOR_RESET);

        run_communication(sock);
    }
}

fn run_communication(sock: usize) {
    let pid = match sys::fork() {
        Ok(pid) => pid,
        Err(e) => {
            println!("{}[nc] fork failed: {:?}{}", COLOR_RED, e, COLOR_RESET);
            let _ = tcp_close(sock);
            return;
        }
    };

    if pid == 0 {
        // Child process: Receive from socket and write to stdout
        let mut buf = [0u8; 1024];
        loop {
            match tcp_recv(sock, &mut buf) {
                Ok(0) => {
                    // Connection closed by peer
                    println!(
                        "{}[nc] connection closed{}",
                        COLOR_GREEN, COLOR_RESET
                    );
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
    } else {
        // Parent process: Read from stdin and send to socket
        let mut buf = [0u8; 1024];
        let mut input = stdin();

        loop {
            match input.read(&mut buf) {
                Ok(0) => break, // EOF
                Ok(n) => {
                    if let Err(_) = tcp_send(sock, &buf[..n]) {
                        break;
                    }
                }
                Err(_) => break,
            }
        }

        let _ = tcp_close(sock);
        let _ = sys::kill(pid);
        let mut status = 0;
        let _ = sys::wait(&mut status);
    }
}
