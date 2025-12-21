#![no_std]
extern crate alloc;

use ulib::sys::Error;
use ulib::{env, icmp_echo_request, icmp_recv_reply, print, println, sys};

fn main() {
    let mut args = env::args();
    let _prog = args.next();
    let Some(dst) = args.next() else {
        println!("usage: ping <ip address>");
        return;
    };

    let id = (sys::getpid().unwrap_or(0) & 0xFFFF) as u16;
    println!("PING {} ({}): 56 data bytes", dst, dst);

    for seq in 0..2 {
        let mut payload = [0u8; 56];
        for (i, b) in payload.iter_mut().enumerate() {
            *b = (0x20 + (i % 64)) as u8;
        }

        let start_us = sys::clocktime().unwrap_or(0) as u64;
        if let Err(e) = icmp_echo_request(dst, id, seq as u16, &payload) {
            println!("failed to send request: {:?}", e);
            continue;
        }

        let mut buf = [0u8; 256];
        match icmp_recv_reply(id, 3000, &mut buf) {
            Ok(n) => {
                let end_us = sys::clocktime().unwrap_or(0) as u64;
                let elapsed_us = end_us.saturating_sub(start_us);
                let elapsed_ms = elapsed_us / 1000;
                let rem_us = elapsed_us % 1000;
                println!(
                    "{} bytes from {}: icmp_seq={} ttl=64 time={}.{:03} ms",
                    n + 8,
                    dst,
                    seq,
                    elapsed_ms,
                    rem_us
                );
            }
            Err(Error::Timeout) => {
                println!("Request timeout for icmp_seq {}", seq);
            }
            Err(e) => {
                println!("recv error: {:?}", e);
            }
        }
        sys::sleep(50).ok();
    }
}
