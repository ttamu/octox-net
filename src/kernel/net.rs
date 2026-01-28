pub mod arp;
pub mod device;
pub mod dns;
pub mod driver;
pub mod ethernet;
pub mod icmp;
pub mod interface;
pub mod ip;
pub mod protocol;
pub mod route;
pub mod socket;
pub mod tcp;
pub mod trace;
pub mod udp;
pub mod util;

use crate::println;
use core::sync::atomic::{AtomicBool, Ordering};

static NET_POLL_PENDING: AtomicBool = AtomicBool::new(false);
static NET_POLL_RUNNING: AtomicBool = AtomicBool::new(false);

pub fn init() {
    println!("[kernel] Network stack init");

    ip::ip_init();

    driver::loopback::init().expect("loopback init failed");
    driver::loopback::setup_iface().expect("loopback setup failed");

    driver::virtio_net::init().expect("virtio-net init failed");
    driver::virtio_net::setup_iface().expect("virtio-net iface failed");

    println!("[kernel] Network stack initialized");
}

pub fn poll() {
    driver::virtio_net::poll_rx();
    let _ = tcp::poll();
}

pub fn request_poll() {
    NET_POLL_PENDING.store(true, Ordering::Release);
}

pub fn poll_if_pending() {
    if !NET_POLL_PENDING.load(Ordering::Acquire) {
        return;
    }

    if NET_POLL_RUNNING.swap(true, Ordering::AcqRel) {
        return;
    }

    loop {
        NET_POLL_PENDING.store(false, Ordering::Release);
        poll();
        if !NET_POLL_PENDING.load(Ordering::Acquire) {
            break;
        }
    }

    NET_POLL_RUNNING.store(false, Ordering::Release);
}
