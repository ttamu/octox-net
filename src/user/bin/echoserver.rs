#![no_std]
extern crate alloc;

use ulib::{env, print, println, tcp_accept, tcp_close, tcp_listen, tcp_recv, tcp_send, tcp_socket};

fn main() {
    let mut args = env::args();
    let _prog = args.next();
    let port: u16 = args
        .next()
        .and_then(|s| s.parse().ok())
        .unwrap_or(7);

    println!("[echo server] starting on port {}", port);

    let listen_sock = match tcp_socket() {
        Ok(s) => s,
        Err(e) => {
            println!("[echo server] failed to create socket: {:?}", e);
            return;
        }
    };

    if let Err(e) = tcp_listen(listen_sock, port) {
        println!("[echo server] failed to listen: {:?}", e);
        return;
    }

    println!("[echo server] listening...");

    loop {
        let client_sock = match tcp_accept(listen_sock) {
            Ok(s) => s,
            Err(e) => {
                println!("[echo server] accept failed: {:?}", e);
                continue;
            }
        };

        println!("[echo server] accepted connection (socket {})", client_sock);

        let mut buf = [0u8; 1024];
        loop {
            match tcp_recv(client_sock, &mut buf) {
                Ok(0) => {
                    println!("[echo server] connection closed by peer");
                    break;
                }
                Ok(n) => {
                    println!("[echo server] received {} bytes", n);
                    if let Err(e) = tcp_send(client_sock, &buf[..n]) {
                        println!("[echo server] send failed: {:?}", e);
                        break;
                    }
                    println!("[echo server] echoed {} bytes", n);
                }
                Err(e) => {
                    println!("[echo server] recv failed: {:?}", e);
                    break;
                }
            }
        }

        let _ = tcp_close(client_sock);
        println!("[echo server] connection closed");
    }
}
