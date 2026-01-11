//! TCP socket management and integration with IP layer.
//!
//! This module provides:
//! - Global socket pool with fixed allocation
//! - tcp_input() for packet reception from IP layer
//! - tcp_poll() for periodic processing and transmission

use super::socket::TcpSocket;
use super::wire::{Packet, Repr};
use crate::error::{Error, Result};
use crate::net::ip::{self, IpAddr};
use crate::spinlock::Mutex;
use alloc::{vec, vec::Vec};

const TCP_SOCKET_COUNT: usize = 32;
const SOCKET_BUFFER_SIZE: usize = 8192; // 8KB per socket per direction

// ========== Socket Pool ==========

struct SocketEntry {
    socket: Option<TcpSocket>,
    rx_storage: [u8; SOCKET_BUFFER_SIZE],
    tx_storage: [u8; SOCKET_BUFFER_SIZE],
}

impl SocketEntry {
    const fn new() -> Self {
        Self {
            socket: None,
            rx_storage: [0; SOCKET_BUFFER_SIZE],
            tx_storage: [0; SOCKET_BUFFER_SIZE],
        }
    }
}

static TCP_SOCKETS: Mutex<[SocketEntry; TCP_SOCKET_COUNT]> = Mutex::new(
    [const { SocketEntry::new() }; TCP_SOCKET_COUNT],
    "tcp_sockets",
);

// ========== Public API ==========

/// Allocate a TCP socket.
pub fn socket_alloc() -> Result<usize> {
    let mut sockets = TCP_SOCKETS.lock();

    for (i, entry) in sockets.iter_mut().enumerate() {
        if entry.socket.is_none() {
            // Create socket with borrowed storage
            // SAFETY: Storage is 'static because it's part of the global array
            let rx_buf: &'static mut [u8] =
                unsafe { core::mem::transmute(&mut entry.rx_storage[..]) };
            let tx_buf: &'static mut [u8] =
                unsafe { core::mem::transmute(&mut entry.tx_storage[..]) };

            entry.socket = Some(TcpSocket::new(rx_buf, tx_buf));
            return Ok(i);
        }
    }

    Err(Error::NoPcbAvailable)
}

/// Release a TCP socket.
pub fn socket_free(index: usize) -> Result<()> {
    let mut sockets = TCP_SOCKETS.lock();

    if index >= TCP_SOCKET_COUNT {
        return Err(Error::InvalidPcbIndex);
    }

    sockets[index].socket = None;
    Ok(())
}

/// Execute a closure with mutable access to a socket.
pub fn socket_get_mut<F, R>(index: usize, f: F) -> Result<R>
where
    F: FnOnce(&mut TcpSocket) -> R,
{
    let mut sockets = TCP_SOCKETS.lock();

    if index >= TCP_SOCKET_COUNT {
        return Err(Error::InvalidPcbIndex);
    }

    match &mut sockets[index].socket {
        Some(socket) => Ok(f(socket)),
        None => Err(Error::InvalidPcbState),
    }
}

/// Execute a closure with immutable access to a socket.
pub fn socket_get<F, R>(index: usize, f: F) -> Result<R>
where
    F: FnOnce(&TcpSocket) -> R,
{
    let sockets = TCP_SOCKETS.lock();

    if index >= TCP_SOCKET_COUNT {
        return Err(Error::InvalidPcbIndex);
    }

    match &sockets[index].socket {
        Some(socket) => Ok(f(socket)),
        None => Err(Error::InvalidPcbState),
    }
}

/// Accept a connection from a listening socket.
/// Returns the new socket index for the accepted connection.
pub fn socket_accept(listen_index: usize) -> Result<usize> {
    let mut sockets = TCP_SOCKETS.lock();

    if listen_index >= TCP_SOCKET_COUNT {
        return Err(Error::InvalidPcbIndex);
    }

    // Extract connection from listening socket
    let conn = match &mut sockets[listen_index].socket {
        Some(socket) => socket.accept_connection().ok_or(Error::WouldBlock)?,
        None => return Err(Error::InvalidPcbState),
    };

    // Find a free socket for the new connection
    for (i, entry) in sockets.iter_mut().enumerate() {
        if entry.socket.is_none() {
            // Create socket with borrowed storage
            let rx_buf: &'static mut [u8] =
                unsafe { core::mem::transmute(&mut entry.rx_storage[..]) };
            let tx_buf: &'static mut [u8] =
                unsafe { core::mem::transmute(&mut entry.tx_storage[..]) };

            let mut new_socket = TcpSocket::new(rx_buf, tx_buf);
            new_socket.apply_accepted(conn);
            entry.socket = Some(new_socket);
            return Ok(i);
        }
    }

    // No free socket available - put connection back (not ideal, but prevents loss)
    // In practice this should not happen if socket pool is sized correctly
    Err(Error::NoPcbAvailable)
}

// ========== Packet Processing ==========

/// TCP input handler (called from IP layer).
pub fn tcp_input(src_ip: IpAddr, dst_ip: IpAddr, data: &[u8]) -> Result<()> {
    // Parse TCP packet
    let packet = Packet::new_checked(data)?;
    let repr = Repr::parse(&packet, src_ip, dst_ip, true)?;

    crate::println!(
        "[tcp] recv: {}:{} -> {}:{} seq={} ack={:?} {} bytes {}",
        format_ip(src_ip),
        repr.src_port,
        format_ip(dst_ip),
        repr.dst_port,
        repr.seq_number,
        repr.ack_number,
        repr.payload.len(),
        format_control(&repr.control),
    );

    let timestamp_ms = get_time_ms();
    let mut response: Option<(IpAddr, IpAddr, Repr<'static>)> = None;

    // Find matching socket
    {
        let mut sockets = TCP_SOCKETS.lock();

        for entry in sockets.iter_mut() {
            if let Some(socket) = &mut entry.socket {
                if socket.matches(src_ip, repr.src_port, dst_ip, repr.dst_port) {
                    // Process segment
                    if let Some(reply) = socket.process(timestamp_ms, src_ip, dst_ip, &repr) {
                        response = Some((dst_ip, src_ip, reply));
                    }

                    drop(sockets); // Release lock before sending

                    // Send response if any
                    if let Some((src, dst, reply_repr)) = response {
                        send_segment(src, dst, &reply_repr)?;
                    }

                    return Ok(());
                }
            }
        }
    }

    // No matching socket - send RST
    crate::println!("[tcp] no matching socket, sending RST");
    let rst = rst_for_segment(&repr);
    send_segment(dst_ip, src_ip, &rst)?;

    Ok(())
}

/// Poll all TCP sockets for outgoing segments.
pub fn tcp_poll() -> Result<()> {
    let timestamp_ms = get_time_ms();
    let mut to_send: Vec<(IpAddr, IpAddr, Repr<'static>, Vec<u8>)> = Vec::new();

    // Collect all segments to send
    {
        let mut sockets = TCP_SOCKETS.lock();

        for entry in sockets.iter_mut() {
            if let Some(socket) = &mut entry.socket {
                if !socket.is_open() {
                    continue;
                }

                if let Some((repr, payload)) = socket.dispatch(timestamp_ms) {
                    let local = socket.local_endpoint();
                    let remote = socket.remote_endpoint();

                    if !local.is_unspecified() && !remote.is_unspecified() {
                        to_send.push((local.addr, remote.addr, repr, payload));
                    }
                }
            }
        }
    } // Release lock

    // Send all queued segments
    for (src_ip, dst_ip, repr, payload) in to_send {
        send_segment_with_payload(src_ip, dst_ip, &repr, &payload)?;
    }

    Ok(())
}

// ========== Helper Functions ==========

/// Send a TCP segment.
fn send_segment(src_ip: IpAddr, dst_ip: IpAddr, repr: &Repr) -> Result<()> {
    send_segment_with_payload(src_ip, dst_ip, repr, &[])
}

/// Send a TCP segment with payload.
fn send_segment_with_payload(
    src_ip: IpAddr,
    dst_ip: IpAddr,
    repr: &Repr,
    payload: &[u8],
) -> Result<()> {
    let total_len = repr.buffer_len() + payload.len();
    let mut buf = vec![0u8; total_len];

    // Create packet and emit repr
    let mut packet = Packet::new_unchecked(&mut buf[..repr.buffer_len()]);
    repr.emit(&mut packet, src_ip, dst_ip);

    // Copy payload if present
    if !payload.is_empty() {
        buf[repr.buffer_len()..].copy_from_slice(payload);

        // Recalculate checksum with payload
        let mut full_packet = Packet::new_unchecked(&mut buf[..]);
        full_packet.fill_checksum(src_ip, dst_ip);
    }

    crate::println!(
        "[tcp] send: {}:{} -> {}:{} seq={} ack={:?} {} bytes {}",
        format_ip(src_ip),
        repr.src_port,
        format_ip(dst_ip),
        repr.dst_port,
        repr.seq_number,
        repr.ack_number,
        payload.len(),
        format_control(&repr.control),
    );

    // Send via IP layer (protocol 6 = TCP)
    ip::output_route(dst_ip, 6, &buf)
}

/// Generate RST for an incoming segment.
fn rst_for_segment(repr: &Repr) -> Repr<'static> {
    use super::wire::Control;

    let (seq, ack) = if repr.ack_number.is_some() {
        (repr.ack_number.unwrap(), None)
    } else {
        (
            super::wire::SeqNumber::new(0),
            Some(repr.seq_number + repr.segment_len()),
        )
    };

    Repr {
        src_port: repr.dst_port,
        dst_port: repr.src_port,
        control: Control::Rst,
        seq_number: seq,
        ack_number: ack,
        window_len: 0,
        max_seg_size: None,
        window_scale: None,
        sack_permitted: false,
        payload: &[],
    }
}

/// Get current time in milliseconds.
fn get_time_ms() -> u64 {
    let ticks = crate::trap::TICKS.lock();
    (*ticks as u64) * (crate::param::TICK_MS as u64)
}

/// Format IP address for display.
fn format_ip(ip: IpAddr) -> alloc::string::String {
    let bytes = ip.0.to_be_bytes();
    alloc::format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3])
}

/// Format control flag for display.
fn format_control(control: &super::wire::Control) -> &'static str {
    use super::wire::Control;
    match control {
        Control::None => "",
        Control::Syn => "SYN",
        Control::Fin => "FIN",
        Control::Rst => "RST",
        Control::Psh => "PSH",
    }
}
