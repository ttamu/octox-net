#![no_std]
extern crate alloc;

use ulib::sys::Error;
use ulib::{env, icmp_echo_request, icmp_recv_reply, print, println, sys};

const PAYLOAD_SIZE: usize = 56;
const ICMP_HEADER_LEN: usize = 8;
const REPLY_BUF_SIZE: usize = 256;
const DEFAULT_COUNT: u16 = 2;
const TIMEOUT_MS: u64 = 3000;
const INTERVAL_MS: usize = 10;

fn main() {
    let Some(dst) = parse_dst() else {
        print_usage();
        return;
    };

    let id = (sys::getpid().unwrap_or(0) & 0xFFFF) as u16;
    let payload = build_payload();
    println!("PING {} ({}): {} data bytes", dst, dst, PAYLOAD_SIZE);

    for seq in 0..DEFAULT_COUNT {
        if let Err(e) = ping_once(dst, id, seq, &payload) {
            println!("recv error: {:?}", e);
        }
        sys::sleep(INTERVAL_MS).ok();
    }
}

fn build_payload() -> [u8; PAYLOAD_SIZE] {
    let mut payload = [0u8; PAYLOAD_SIZE];
    for (i, b) in payload.iter_mut().enumerate() {
        *b = (0x20 + (i % 64)) as u8;
    }
    payload
}

fn clock_us() -> u64 {
    sys::clocktime().unwrap_or(0) as u64
}

fn print_reply(dst: &str, seq: u16, payload_len: usize, start_us: u64) {
    let end_us = clock_us();
    let elapsed_us = end_us.saturating_sub(start_us);
    let elapsed_ms = elapsed_us / 1000;
    let rem_us = elapsed_us % 1000;
    println!(
        "{} bytes from {}: icmp_seq={} ttl=64 time={}.{:03} ms",
        payload_len + ICMP_HEADER_LEN,
        dst,
        seq,
        elapsed_ms,
        rem_us
    );
}

fn print_usage() {
    println!("usage: ping <ip address>");
}

fn parse_dst() -> Option<&'static str> {
    let mut args = env::args();
    let _prog = args.next();
    args.next()
}

fn ping_once(dst: &str, id: u16, seq: u16, payload: &[u8]) -> Result<(), Error> {
    let start_us = clock_us();
    icmp_echo_request(dst, id, seq, payload)?;

    let mut buf = [0u8; REPLY_BUF_SIZE];
    match icmp_recv_reply(id, TIMEOUT_MS, &mut buf) {
        Ok(n) => {
            print_reply(dst, seq, n, start_us);
            Ok(())
        }
        Err(Error::Timeout) => {
            println!("Request timeout for icmp_seq {}", seq);
            Ok(())
        }
        Err(e) => Err(e),
    }
}
