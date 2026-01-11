//! TCP implementation for octox-net.
//!
//! This module provides a complete TCP/IP stack implementation following
//! RFC 793 and smoltcp design patterns.

pub mod manager;
pub mod socket;
pub mod storage;
pub mod wire;

// Re-export commonly used types
pub use manager::{socket_accept, socket_alloc, socket_free, socket_get, socket_get_mut, tcp_input, tcp_poll};
pub use socket::{IpEndpoint, State, TcpSocket};
pub use storage::{Assembler, RingBuffer};
pub use wire::{Control, Packet, Repr, SeqNumber};

/// Initialize TCP subsystem.
pub fn init() {
    crate::println!("[tcp] TCP stack initialized");
    crate::println!("[tcp] Socket pool: {} sockets, 8KB buffers", 32);
}
