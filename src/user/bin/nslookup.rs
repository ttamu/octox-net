#![no_std]
extern crate alloc;

use ulib::{dns_resolve, env, print, println};

fn main() {
    let Some(domain) = parse_domain() else {
        print_usage();
        return;
    };

    println!("Resolving: {}", domain);

    let addr = match dns_resolve(domain) {
        Ok(a) => a,
        Err(e) => {
            println!("DNS resolution failed: {:?}", e);
            return;
        }
    };

    let (a, b, c, d) = split_ipv4(addr);

    println!("");
    println!("Name:    {}", domain);
    println!("Address: {}.{}.{}.{}", a, b, c, d);
}

fn parse_domain() -> Option<&'static str> {
    let mut args = env::args();
    let _prog = args.next();
    args.next()
}

fn print_usage() {
    println!("Usage: nslookup <domain>");
    println!("Examples:");
    println!("  nslookup example.com");
    println!("  nslookup google.com");
    println!("  nslookup github.com");
}

fn split_ipv4(addr: u32) -> (u8, u8, u8, u8) {
    (
        ((addr >> 24) & 0xFF) as u8,
        ((addr >> 16) & 0xFF) as u8,
        ((addr >> 8) & 0xFF) as u8,
        (addr & 0xFF) as u8,
    )
}
