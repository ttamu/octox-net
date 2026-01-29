#![no_std]
extern crate alloc;

use alloc::{vec, vec::Vec};
use ulib::sys::Error;
use ulib::{env, icmp_close, icmp_recvfrom, icmp_sendto, icmp_socket, print, println, sys};

const PAYLOAD_SIZE: usize = 56;
const ICMP_HEADER_LEN: usize = 8;
const ICMP_ECHO_REQUEST: u8 = 8;
const ICMP_ECHO_REPLY: u8 = 0;
const REPLY_BUF_SIZE: usize = 256;
const DEFAULT_COUNT: u16 = 2;
const TIMEOUT_MS: u64 = 3000;
const INTERVAL_MS: usize = 10;

fn main() {
    let Some(dst) = parse_dst() else {
        print_usage();
        return;
    };

    let sock = match icmp_socket() {
        Ok(sock) => sock,
        Err(e) => {
            println!("icmp socket error: {:?}", e);
            return;
        }
    };

    let id = (sys::getpid().unwrap_or(0) & 0xFFFF) as u16;
    let payload = build_payload();
    println!("PING {} ({}): {} data bytes", dst, dst, PAYLOAD_SIZE);

    for seq in 0..DEFAULT_COUNT {
        if let Err(e) = ping_once(sock, dst, id, seq, &payload) {
            println!("recv error: {:?}", e);
        }
        sys::sleep(INTERVAL_MS).ok();
    }

    let _ = icmp_close(sock);
}

fn build_payload() -> [u8; PAYLOAD_SIZE] {
    let mut payload = [0u8; PAYLOAD_SIZE];
    for (i, b) in payload.iter_mut().enumerate() {
        *b = (0x20 + (i % 64)) as u8;
    }
    payload
}

fn build_echo_request(id: u16, seq: u16, payload: &[u8]) -> Vec<u8> {
    let mut packet = vec![0u8; ICMP_HEADER_LEN + payload.len()];
    packet[0] = ICMP_ECHO_REQUEST;
    packet[1] = 0;
    packet[2] = 0;
    packet[3] = 0;
    packet[4..6].copy_from_slice(&id.to_be_bytes());
    packet[6..8].copy_from_slice(&seq.to_be_bytes());
    packet[ICMP_HEADER_LEN..].copy_from_slice(payload);
    packet
}

fn parse_echo_reply(buf: &[u8]) -> Option<(u16, u16, usize)> {
    if buf.len() < ICMP_HEADER_LEN {
        return None;
    }
    if buf[0] != ICMP_ECHO_REPLY {
        return None;
    }
    let id = u16::from_be_bytes([buf[4], buf[5]]);
    let seq = u16::from_be_bytes([buf[6], buf[7]]);
    Some((id, seq, buf.len() - ICMP_HEADER_LEN))
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

fn ping_once(sock: usize, dst: &str, id: u16, seq: u16, payload: &[u8]) -> Result<(), Error> {
    let start_us = clock_us();
    let packet = build_echo_request(id, seq, payload);
    icmp_sendto(sock, dst, &packet)?;

    let mut buf = [0u8; REPLY_BUF_SIZE];
    let mut src: u32 = 0;
    let timeout_us = TIMEOUT_MS.saturating_mul(1000);

    loop {
        match icmp_recvfrom(sock, &mut buf, &mut src) {
            Ok(n) => {
                if let Some((reply_id, reply_seq, payload_len)) = parse_echo_reply(&buf[..n]) {
                    if reply_id == id && reply_seq == seq {
                        print_reply(dst, seq, payload_len, start_us);
                        return Ok(());
                    }
                }
            }
            Err(Error::WouldBlock) => {
                if clock_us().saturating_sub(start_us) >= timeout_us {
                    println!("Request timeout for icmp_seq {}", seq);
                    return Ok(());
                }
                sys::sleep(1).ok();
            }
            Err(e) => return Err(e),
        }

        if clock_us().saturating_sub(start_us) >= timeout_us {
            println!("Request timeout for icmp_seq {}", seq);
            return Ok(());
        }
    }
}
