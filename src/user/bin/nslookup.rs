#![no_std]
extern crate alloc;

use ulib::{dns_resolve, env, print, println};

fn main() {
    let mut args = env::args();
    let _prog = args.next();

    let Some(domain) = args.next() else {
        println!("Usage: nslookup <domain>");
        println!("Examples:");
        println!("  nslookup example.com");
        println!("  nslookup google.com");
        println!("  nslookup github.com");
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

    let a = (addr >> 24) & 0xFF;
    let b = (addr >> 16) & 0xFF;
    let c = (addr >> 8) & 0xFF;
    let d = addr & 0xFF;

    println!("");
    println!("Name:    {}", domain);
    println!("Address: {}.{}.{}.{}", a, b, c, d);
}
