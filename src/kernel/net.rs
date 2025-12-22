pub mod arp;
pub mod device;
pub mod driver;
pub mod ethernet;
pub mod icmp;
pub mod interface;
pub mod ip;
pub mod protocol;
pub mod route;
pub mod udp;
pub mod util;

pub fn init() {
    crate::println!("[kernel] Network stack init");

    ip::ip_init();

    driver::loopback::loopback_init().expect("loopback init failed");
    driver::loopback::loopback_setup().expect("loopback setup failed");

    driver::virtio_net::init().expect("virtio-net init failed");
    driver::virtio_net::setup_iface().expect("virtio-net iface failed");

    crate::println!("[kernel] Network stack initialized");
}
