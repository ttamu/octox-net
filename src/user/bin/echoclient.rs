#![no_std]
extern crate alloc;

use ulib::{env, print, println, tcp_close, tcp_connect, tcp_recv, tcp_send, tcp_socket};

fn main() {
    let mut args = env::args();
    let _prog = args.next();

    let addr = args.next().unwrap_or("127.0.0.1");
    let port: u16 = args
        .next()
        .and_then(|s| s.parse().ok())
        .unwrap_or(7);
    let message = args.next().unwrap_or("Hello, TCP!");

    println!("[echo client] connecting to {}:{}", addr, port);

    let sock = match tcp_socket() {
        Ok(s) => s,
        Err(e) => {
            println!("[echo client] failed to create socket: {:?}", e);
            return;
        }
    };

    // Use a random local port (based on pid)
    let local_port = 40000 + (ulib::sys::getpid().unwrap_or(0) as u16 % 1000);

    if let Err(e) = tcp_connect(sock, addr, port, local_port) {
        println!("[echo client] connect failed: {:?}", e);
        return;
    }

    println!("[echo client] connected");

    let data = message.as_bytes();
    match tcp_send(sock, data) {
        Ok(n) => println!("[echo client] sent {} bytes: {}", n, message),
        Err(e) => {
            println!("[echo client] send failed: {:?}", e);
            let _ = tcp_close(sock);
            return;
        }
    }

    let mut buf = [0u8; 1024];
    match tcp_recv(sock, &mut buf) {
        Ok(n) => {
            if let Ok(s) = core::str::from_utf8(&buf[..n]) {
                println!("[echo client] received {} bytes: {}", n, s);
            } else {
                println!("[echo client] received {} bytes (binary)", n);
            }
        }
        Err(e) => {
            println!("[echo client] recv failed: {:?}", e);
        }
    }

    let _ = tcp_close(sock);
    println!("[echo client] connection closed");
}
