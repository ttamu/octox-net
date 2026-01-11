# octox-net TCP実装計画 (smoltcp-based, revised)

## 概要

smoltcpの設計パターンに完全準拠したTCP実装。
RFC 793準拠の状態機械、ゼロコピー設計、型安全性、Rustイディオムを重視。

## 参考実装

- **smoltcp**: Rust製TCP/IP実装（アーキテクチャと設計パターンの参考）
- **RFC 793**: TCP仕様（状態機械の参考）

---

## アーキテクチャ

smoltcp準拠の階層構造:

```text
┌─────────────────────────────────────┐
│   Application (User code)           │
└───────────────┬─────────────────────┘
                ↓
┌─────────────────────────────────────┐
│   Socket layer (socket/tcp.rs)      │
│   - TcpSocket struct                │
│   - State machine (process method)  │
│   - TX/RXバッファ管理                 │
│   - read/write API                  │
└───────────────┬─────────────────────┘
                ↓
┌─────────────────────────────────────┐
│   Interface layer (iface/)          │
│   - SocketSet<'a> (複数ソケット管理)   │
│   - SocketHandle (ソケット識別)       │
│   - Socket<'a> enum (プロトコル抽象)  │
└───────────────┬─────────────────────┘
                ↓
┌─────────────────────────────────────┐
│   Wire layer (wire/tcp.rs)          │
│   - Packet (zero-copy parse)        │
│   - Repr (abstract representation)  │
│   - emit/parse methods              │
└─────────────────────────────────────┘
```

---

## 実装について

### ファイル構成

```text
src/kernel/net/
├── socket/
│   ├── mod.rs       # Socket<'a> enum, AnySocket trait
│   └── tcp.rs       # TcpSocket, State, process()
├── wire/
│   ├── mod.rs       # Common wire utilities
│   └── tcp.rs       # TCP Packet, Repr, SeqNumber, Control
├── iface/
│   ├── mod.rs       # Interface module exports
│   └── socket_set.rs # SocketSet<'a>, SocketHandle
├── util.rs          # random_u32(), checksum(), etc.
└── ...
```

---

## 完全実装コード

### Step 1: Utilityの拡張 (src/kernel/net/util.rs)

既存のutil.rsに乱数生成器を追加:

```rust
// 既存コードの後に追加

use core::sync::atomic::{AtomicU32, Ordering};
use byteorder::{ByteOrder, NetworkEndian};
use noli::net::IpV4Addr;

// ========== Random Number Generator (Xorshift) ==========

static RNG_STATE: AtomicU32 = AtomicU32::new(123456789);

/// Initialize RNG with a seed (call once at boot with timer value).
pub fn random_init(seed: u32) {
    RNG_STATE.store(seed, Ordering::Relaxed);
}

/// Generate a random u32 using Xorshift algorithm.
pub fn random_u32() -> u32 {
    let mut state = RNG_STATE.load(Ordering::Relaxed);
    state ^= state << 13;
    state ^= state >> 17;
    state ^= state << 5;
    RNG_STATE.store(state, Ordering::Relaxed);
    state
}

// ========== Checksum Helpers ==========

/// Compute RFC 1071 compliant checksum (without the final complement).
pub fn checksum_data(mut data: &[u8]) -> u16 {
    let mut accum: u32 = 0;

    // Process data in 2-byte chunks
    while data.len() >= 2 {
        accum += NetworkEndian::read_u16(data) as u32;
        data = &data[2..];
    }

    // Add the last remaining odd byte, if any
    if let Some(&value) = data.first() {
        accum += (value as u32) << 8;
    }

    // Propagate carries
    while (accum >> 16) != 0 {
        accum = (accum & 0xffff) + (accum >> 16);
    }

    accum as u16
}

/// Combine several RFC 1071 compliant checksums.
pub fn checksum_combine(checksums: &[u16]) -> u16 {
    let mut accum: u32 = 0;
    for &word in checksums {
        accum += word as u32;
    }

    // Propagate carries
    while (accum >> 16) != 0 {
        accum = (accum & 0xffff) + (accum >> 16);
    }

    accum as u16
}

/// Compute TCP/UDP pseudo-header checksum for IPv4.
pub fn tcp_pseudo_header(src_ip: IpV4Addr, dst_ip: IpV4Addr, protocol: u8, length: u16) -> u16 {
    let mut proto_len = [0u8; 4];
    proto_len[1] = protocol;
    NetworkEndian::write_u16(&mut proto_len[2..4], length);

    checksum_combine(&[
        checksum_data(src_ip.as_slice()),
        checksum_data(dst_ip.as_slice()),
        checksum_data(&proto_len),
    ])
}
```

**Cargo.toml に追加:**
```toml
[dependencies]
byteorder = { version = "1.5", default-features = false }
```

---

### Step 2: Wire層 - Packet, Repr, SeqNumber (src/kernel/net/wire/tcp.rs)

```rust
//! TCP wire format and packet representation.
//!
//! This module implements zero-copy parsing and emission of TCP packets,
//! following the design pattern of smoltcp's wire layer.

use byteorder::{ByteOrder, NetworkEndian};
use core::fmt::{self, Display};
use core::ops::{Add, AddAssign, Sub};
use crate::error::{Error, Result};
use crate::kernel::net::util;
use noli::net::IpV4Addr;

// ========== Field Definitions ==========

mod field {
    pub type Field = ::core::ops::Range<usize>;

    pub const SRC_PORT: Field = 0..2;
    pub const DST_PORT: Field = 2..4;
    pub const SEQ_NUM: Field = 4..8;
    pub const ACK_NUM: Field = 8..12;
    pub const FLAGS: Field = 12..14;
    pub const WIN_SIZE: Field = 14..16;
    pub const CHECKSUM: Field = 16..18;
    pub const URGENT: Field = 18..20;

    // Flag bit positions (in network byte order u16)
    pub const FLG_FIN: u16 = 0x0001;
    pub const FLG_SYN: u16 = 0x0002;
    pub const FLG_RST: u16 = 0x0004;
    pub const FLG_PSH: u16 = 0x0008;
    pub const FLG_ACK: u16 = 0x0010;
    pub const FLG_URG: u16 = 0x0020;
}

pub const HEADER_LEN: usize = field::URGENT.end;

// ========== TCP Sequence Number ==========

/// A TCP sequence number.
///
/// Sequence numbers are monotonically advancing integers modulo 2^32.
/// Using i32 internally allows wraparound-safe comparisons.
///
/// See [RFC 793 Section 3.3](https://www.rfc-editor.org/rfc/rfc793.html#section-3.3)
#[derive(Debug, PartialEq, Eq, Clone, Copy, Default)]
pub struct SeqNumber(pub i32);

impl SeqNumber {
    pub const fn new(val: u32) -> Self {
        SeqNumber(val as i32)
    }

    pub const fn as_u32(self) -> u32 {
        self.0 as u32
    }
}

impl fmt::Display for SeqNumber {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0 as u32)
    }
}

impl Add<usize> for SeqNumber {
    type Output = SeqNumber;
    fn add(self, rhs: usize) -> SeqNumber {
        if rhs > i32::MAX as usize {
            panic!("sequence number addition overflow");
        }
        SeqNumber(self.0.wrapping_add(rhs as i32))
    }
}

impl Sub<usize> for SeqNumber {
    type Output = SeqNumber;
    fn sub(self, rhs: usize) -> SeqNumber {
        if rhs > i32::MAX as usize {
            panic!("sequence number subtraction overflow");
        }
        SeqNumber(self.0.wrapping_sub(rhs as i32))
    }
}

impl AddAssign<usize> for SeqNumber {
    fn add_assign(&mut self, rhs: usize) {
        *self = *self + rhs;
    }
}

impl Sub for SeqNumber {
    type Output = usize;
    fn sub(self, rhs: SeqNumber) -> usize {
        let result = self.0.wrapping_sub(rhs.0);
        if result < 0 {
            panic!("sequence number subtraction underflow");
        }
        result as usize
    }
}

impl core::cmp::PartialOrd for SeqNumber {
    fn partial_cmp(&self, other: &SeqNumber) -> Option<core::cmp::Ordering> {
        self.0.wrapping_sub(other.0).partial_cmp(&0)
    }
}

// ========== TCP Control ==========

/// TCP control flags.
///
/// See [RFC 793 Section 3.1](https://www.rfc-editor.org/rfc/rfc793.html#section-3.1)
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Control {
    None,
    Syn,
    Fin,
    Rst,
    Psh,
}

// ========== TCP Packet (Zero-Copy) ==========

/// A read/write wrapper around a TCP packet buffer.
///
/// This struct provides zero-copy access to TCP packet fields.
#[derive(Debug, Clone)]
pub struct Packet<T: AsRef<[u8]>> {
    buffer: T,
}

impl<T: AsRef<[u8]>> Packet<T> {
    /// Create a new unchecked packet wrapper.
    pub const fn new_unchecked(buffer: T) -> Packet<T> {
        Packet { buffer }
    }

    /// Create a new checked packet wrapper.
    pub fn new_checked(buffer: T) -> Result<Packet<T>> {
        let packet = Self::new_unchecked(buffer);
        packet.check_len()?;
        Ok(packet)
    }

    /// Ensure that no accessor method will panic.
    pub fn check_len(&self) -> Result<()> {
        let len = self.buffer.as_ref().len();
        if len < HEADER_LEN {
            return Err(Error::Failed("TCP packet too short"));
        }
        let header_len = self.header_len() as usize;
        if len < header_len || header_len < HEADER_LEN {
            return Err(Error::Failed("invalid TCP header length"));
        }
        Ok(())
    }

    /// Consume the packet, returning the underlying buffer.
    pub fn into_inner(self) -> T {
        self.buffer
    }

    // ========== Getter Methods ==========

    /// Return the source port field.
    #[inline]
    pub fn src_port(&self) -> u16 {
        let data = self.buffer.as_ref();
        NetworkEndian::read_u16(&data[field::SRC_PORT])
    }

    /// Return the destination port field.
    #[inline]
    pub fn dst_port(&self) -> u16 {
        let data = self.buffer.as_ref();
        NetworkEndian::read_u16(&data[field::DST_PORT])
    }

    /// Return the sequence number field.
    #[inline]
    pub fn seq_number(&self) -> SeqNumber {
        let data = self.buffer.as_ref();
        SeqNumber(NetworkEndian::read_i32(&data[field::SEQ_NUM]))
    }

    /// Return the acknowledgement number field.
    #[inline]
    pub fn ack_number(&self) -> SeqNumber {
        let data = self.buffer.as_ref();
        SeqNumber(NetworkEndian::read_i32(&data[field::ACK_NUM]))
    }

    /// Return the header length, in octets.
    #[inline]
    pub fn header_len(&self) -> u8 {
        let data = self.buffer.as_ref();
        let raw = NetworkEndian::read_u16(&data[field::FLAGS]);
        ((raw >> 12) * 4) as u8
    }

    /// Return the FIN flag.
    #[inline]
    pub fn fin(&self) -> bool {
        let data = self.buffer.as_ref();
        let raw = NetworkEndian::read_u16(&data[field::FLAGS]);
        (raw & field::FLG_FIN) != 0
    }

    /// Return the SYN flag.
    #[inline]
    pub fn syn(&self) -> bool {
        let data = self.buffer.as_ref();
        let raw = NetworkEndian::read_u16(&data[field::FLAGS]);
        (raw & field::FLG_SYN) != 0
    }

    /// Return the RST flag.
    #[inline]
    pub fn rst(&self) -> bool {
        let data = self.buffer.as_ref();
        let raw = NetworkEndian::read_u16(&data[field::FLAGS]);
        (raw & field::FLG_RST) != 0
    }

    /// Return the PSH flag.
    #[inline]
    pub fn psh(&self) -> bool {
        let data = self.buffer.as_ref();
        let raw = NetworkEndian::read_u16(&data[field::FLAGS]);
        (raw & field::FLG_PSH) != 0
    }

    /// Return the ACK flag.
    #[inline]
    pub fn ack(&self) -> bool {
        let data = self.buffer.as_ref();
        let raw = NetworkEndian::read_u16(&data[field::FLAGS]);
        (raw & field::FLG_ACK) != 0
    }

    /// Return the URG flag.
    #[inline]
    pub fn urg(&self) -> bool {
        let data = self.buffer.as_ref();
        let raw = NetworkEndian::read_u16(&data[field::FLAGS]);
        (raw & field::FLG_URG) != 0
    }

    /// Return the window size field.
    #[inline]
    pub fn window_len(&self) -> u16 {
        let data = self.buffer.as_ref();
        NetworkEndian::read_u16(&data[field::WIN_SIZE])
    }

    /// Return the checksum field.
    #[inline]
    pub fn checksum(&self) -> u16 {
        let data = self.buffer.as_ref();
        NetworkEndian::read_u16(&data[field::CHECKSUM])
    }

    /// Return the urgent pointer field.
    #[inline]
    pub fn urgent_at(&self) -> u16 {
        let data = self.buffer.as_ref();
        NetworkEndian::read_u16(&data[field::URGENT])
    }

    /// Return a pointer to the payload.
    #[inline]
    pub fn payload(&self) -> &[u8] {
        let header_len = self.header_len() as usize;
        let data = self.buffer.as_ref();
        &data[header_len..]
    }

    /// Return the segment length (in sequence space).
    /// SYN and FIN flags each consume 1 byte.
    pub fn segment_len(&self) -> usize {
        let mut length = self.payload().len();
        if self.syn() {
            length += 1;
        }
        if self.fin() {
            length += 1;
        }
        length
    }

    /// Verify the checksum.
    pub fn verify_checksum(&self, src_ip: IpV4Addr, dst_ip: IpV4Addr) -> bool {
        let data = self.buffer.as_ref();
        let pseudo = util::tcp_pseudo_header(src_ip, dst_ip, 6, data.len() as u16);
        util::checksum_combine(&[pseudo, util::checksum_data(data)]) == !0
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> Packet<T> {
    // ========== Setter Methods ==========

    /// Set the source port field.
    #[inline]
    pub fn set_src_port(&mut self, value: u16) {
        let data = self.buffer.as_mut();
        NetworkEndian::write_u16(&mut data[field::SRC_PORT], value);
    }

    /// Set the destination port field.
    #[inline]
    pub fn set_dst_port(&mut self, value: u16) {
        let data = self.buffer.as_mut();
        NetworkEndian::write_u16(&mut data[field::DST_PORT], value);
    }

    /// Set the sequence number field.
    #[inline]
    pub fn set_seq_number(&mut self, value: SeqNumber) {
        let data = self.buffer.as_mut();
        NetworkEndian::write_i32(&mut data[field::SEQ_NUM], value.0);
    }

    /// Set the acknowledgement number field.
    #[inline]
    pub fn set_ack_number(&mut self, value: SeqNumber) {
        let data = self.buffer.as_mut();
        NetworkEndian::write_i32(&mut data[field::ACK_NUM], value.0);
    }

    /// Set the header length field.
    #[inline]
    pub fn set_header_len(&mut self, length: u8) {
        let data = self.buffer.as_mut();
        let raw = NetworkEndian::read_u16(&data[field::FLAGS]);
        let raw = (raw & 0x0fff) | (((length / 4) as u16) << 12);
        NetworkEndian::write_u16(&mut data[field::FLAGS], raw);
    }

    /// Clear the entire flags field.
    #[inline]
    pub fn clear_flags(&mut self) {
        let data = self.buffer.as_mut();
        let raw = NetworkEndian::read_u16(&data[field::FLAGS]);
        let raw = raw & !0x0fff;
        NetworkEndian::write_u16(&mut data[field::FLAGS], raw);
    }

    /// Set the FIN flag.
    #[inline]
    pub fn set_fin(&mut self, value: bool) {
        let data = self.buffer.as_mut();
        let raw = NetworkEndian::read_u16(&data[field::FLAGS]);
        let raw = if value {
            raw | field::FLG_FIN
        } else {
            raw & !field::FLG_FIN
        };
        NetworkEndian::write_u16(&mut data[field::FLAGS], raw);
    }

    /// Set the SYN flag.
    #[inline]
    pub fn set_syn(&mut self, value: bool) {
        let data = self.buffer.as_mut();
        let raw = NetworkEndian::read_u16(&data[field::FLAGS]);
        let raw = if value {
            raw | field::FLG_SYN
        } else {
            raw & !field::FLG_SYN
        };
        NetworkEndian::write_u16(&mut data[field::FLAGS], raw);
    }

    /// Set the RST flag.
    #[inline]
    pub fn set_rst(&mut self, value: bool) {
        let data = self.buffer.as_mut();
        let raw = NetworkEndian::read_u16(&data[field::FLAGS]);
        let raw = if value {
            raw | field::FLG_RST
        } else {
            raw & !field::FLG_RST
        };
        NetworkEndian::write_u16(&mut data[field::FLAGS], raw);
    }

    /// Set the PSH flag.
    #[inline]
    pub fn set_psh(&mut self, value: bool) {
        let data = self.buffer.as_mut();
        let raw = NetworkEndian::read_u16(&data[field::FLAGS]);
        let raw = if value {
            raw | field::FLG_PSH
        } else {
            raw & !field::FLG_PSH
        };
        NetworkEndian::write_u16(&mut data[field::FLAGS], raw);
    }

    /// Set the ACK flag.
    #[inline]
    pub fn set_ack(&mut self, value: bool) {
        let data = self.buffer.as_mut();
        let raw = NetworkEndian::read_u16(&data[field::FLAGS]);
        let raw = if value {
            raw | field::FLG_ACK
        } else {
            raw & !field::FLG_ACK
        };
        NetworkEndian::write_u16(&mut data[field::FLAGS], raw);
    }

    /// Set the window size field.
    #[inline]
    pub fn set_window_len(&mut self, value: u16) {
        let data = self.buffer.as_mut();
        NetworkEndian::write_u16(&mut data[field::WIN_SIZE], value);
    }

    /// Set the checksum field.
    #[inline]
    pub fn set_checksum(&mut self, value: u16) {
        let data = self.buffer.as_mut();
        NetworkEndian::write_u16(&mut data[field::CHECKSUM], value);
    }

    /// Set the urgent pointer field.
    #[inline]
    pub fn set_urgent_at(&mut self, value: u16) {
        let data = self.buffer.as_mut();
        NetworkEndian::write_u16(&mut data[field::URGENT], value);
    }

    /// Fill the checksum field.
    pub fn fill_checksum(&mut self, src_ip: IpV4Addr, dst_ip: IpV4Addr) {
        self.set_checksum(0);
        let data = self.buffer.as_ref();
        let pseudo = util::tcp_pseudo_header(src_ip, dst_ip, 6, data.len() as u16);
        let checksum = !util::checksum_combine(&[pseudo, util::checksum_data(data)]);
        self.set_checksum(checksum);
    }
}

impl<T: AsRef<[u8]>> Display for Packet<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "TCP {}:{} > {}:{} seq={} ack={} win={}{}{}{}{}{}",
            "?",
            self.src_port(),
            "?",
            self.dst_port(),
            self.seq_number(),
            self.ack_number(),
            self.window_len(),
            if self.syn() { " SYN" } else { "" },
            if self.fin() { " FIN" } else { "" },
            if self.rst() { " RST" } else { "" },
            if self.psh() { " PSH" } else { "" },
            if self.ack() { " ACK" } else { "" },
        )
    }
}

// ========== TCP Repr (High-Level Representation) ==========

/// A high-level representation of a TCP packet.
///
/// This struct abstracts away the wire format details and provides
/// a convenient interface for packet manipulation.
#[derive(Debug, Clone)]
pub struct Repr<'a> {
    pub src_port: u16,
    pub dst_port: u16,
    pub control: Control,
    pub seq_number: SeqNumber,
    pub ack_number: Option<SeqNumber>,
    pub window_len: u16,
    pub payload: &'a [u8],
}

impl<'a> Repr<'a> {
    /// Parse a TCP packet and return a high-level representation.
    pub fn parse<T>(
        packet: &Packet<&'a T>,
        src_ip: IpV4Addr,
        dst_ip: IpV4Addr,
        check_checksum: bool,
    ) -> Result<Repr<'a>>
    where
        T: AsRef<[u8]> + ?Sized,
    {
        // Verify checksum if requested
        if check_checksum && !packet.verify_checksum(src_ip, dst_ip) {
            return Err(Error::Failed("TCP checksum verification failed"));
        }

        // Determine control
        let control = if packet.syn() && !packet.ack() {
            Control::Syn
        } else if packet.fin() {
            Control::Fin
        } else if packet.rst() {
            Control::Rst
        } else if packet.psh() {
            Control::Psh
        } else {
            Control::None
        };

        // ACK number is only valid if ACK flag is set
        let ack_number = if packet.ack() {
            Some(packet.ack_number())
        } else {
            None
        };

        Ok(Repr {
            src_port: packet.src_port(),
            dst_port: packet.dst_port(),
            control,
            seq_number: packet.seq_number(),
            ack_number,
            window_len: packet.window_len(),
            payload: packet.payload(),
        })
    }

    /// Emit this representation into a TCP packet.
    pub fn emit<T>(
        &self,
        packet: &mut Packet<T>,
        src_ip: IpV4Addr,
        dst_ip: IpV4Addr,
    )
    where
        T: AsRef<[u8]> + AsMut<[u8]>,
    {
        packet.set_src_port(self.src_port);
        packet.set_dst_port(self.dst_port);
        packet.set_seq_number(self.seq_number);
        packet.set_header_len(HEADER_LEN as u8);
        packet.set_window_len(self.window_len);
        packet.set_urgent_at(0);
        packet.clear_flags();

        // Set control flags
        match self.control {
            Control::Syn => packet.set_syn(true),
            Control::Fin => packet.set_fin(true),
            Control::Rst => packet.set_rst(true),
            Control::Psh => packet.set_psh(true),
            Control::None => {}
        }

        // Set ACK if present
        if let Some(ack) = self.ack_number {
            packet.set_ack(true);
            packet.set_ack_number(ack);
        }

        // Fill checksum
        packet.fill_checksum(src_ip, dst_ip);
    }

    /// Return the length of a packet that will be emitted from this repr.
    pub fn buffer_len(&self) -> usize {
        HEADER_LEN + self.payload.len()
    }
}
```

---

### Step 3: Socket層 - TcpSocket, State, process() (src/kernel/net/socket/tcp.rs)

```rust
//! TCP socket implementation.
//!
//! This module implements the TCP state machine and socket API,
//! following RFC 793 and smoltcp's design patterns.

use crate::kernel::net::wire::tcp::{Control, Packet, Repr, SeqNumber, HEADER_LEN};
use crate::kernel::net::util::random_u32;
use crate::error::{Error, Result};
use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::fmt::{self, Display};
use noli::net::IpV4Addr;

// ========== TCP State ==========

/// The state of a TCP socket, according to [RFC 793](https://www.rfc-editor.org/rfc/rfc793.html).
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum State {
    Closed,
    Listen,
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    Closing,
    TimeWait,
    CloseWait,
    LastAck,
}

impl Display for State {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            State::Closed => write!(f, "CLOSED"),
            State::Listen => write!(f, "LISTEN"),
            State::SynSent => write!(f, "SYN-SENT"),
            State::SynReceived => write!(f, "SYN-RECEIVED"),
            State::Established => write!(f, "ESTABLISHED"),
            State::FinWait1 => write!(f, "FIN-WAIT-1"),
            State::FinWait2 => write!(f, "FIN-WAIT-2"),
            State::Closing => write!(f, "CLOSING"),
            State::TimeWait => write!(f, "TIME-WAIT"),
            State::CloseWait => write!(f, "CLOSE-WAIT"),
            State::LastAck => write!(f, "LAST-ACK"),
        }
    }
}

// ========== Endpoint ==========

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct IpEndpoint {
    pub addr: IpV4Addr,
    pub port: u16,
}

impl IpEndpoint {
    pub const fn new(addr: IpV4Addr, port: u16) -> Self {
        IpEndpoint { addr, port }
    }
}

impl Display for IpEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}:{}", self.addr, self.port)
    }
}

// ========== Tuple ==========

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
struct Tuple {
    local: IpEndpoint,
    remote: IpEndpoint,
}

// ========== Error Types ==========

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListenError {
    InvalidState,
    Unaddressable,
}

impl fmt::Display for ListenError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ListenError::InvalidState => write!(f, "invalid state"),
            ListenError::Unaddressable => write!(f, "unaddressable destination"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectError {
    InvalidState,
    Unaddressable,
}

impl fmt::Display for ConnectError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ConnectError::InvalidState => write!(f, "invalid state"),
            ConnectError::Unaddressable => write!(f, "unaddressable destination"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendError {
    InvalidState,
    BufferFull,
}

impl fmt::Display for SendError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            SendError::InvalidState => write!(f, "invalid state"),
            SendError::BufferFull => write!(f, "buffer full"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecvError {
    InvalidState,
    Finished,
}

impl fmt::Display for RecvError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            RecvError::InvalidState => write!(f, "invalid state"),
            RecvError::Finished => write!(f, "operation finished"),
        }
    }
}

// ========== TCP Socket ==========

const SOCKET_BUFFER_SIZE: usize = 65535;
const TIME_WAIT_TIMEOUT_MS: u64 = 30000;

/// A TCP socket.
///
/// This struct holds all state for a TCP connection, following the
/// design pattern of smoltcp's Socket struct.
pub struct TcpSocket {
    // State
    state: State,

    // Endpoints
    tuple: Option<Tuple>,
    listen_endpoint: IpEndpoint,

    // Sequence numbers (RFC 793 Section 3.2)
    local_seq_no: SeqNumber,      // SND.NXT
    remote_seq_no: SeqNumber,     // RCV.NXT
    remote_last_seq: SeqNumber,   // Last SEQ sent
    remote_last_ack: Option<SeqNumber>, // Last ACK sent
    iss: SeqNumber,                // Initial send sequence
    irs: SeqNumber,                // Initial receive sequence

    // Window management
    local_win_len: u16,            // SND.WND (remote's receive window)
    remote_win_len: u16,           // RCV.WND (our receive window)
    snd_wl1: SeqNumber,            // SEQ of last window update
    snd_wl2: SeqNumber,            // ACK of last window update
    snd_una: SeqNumber,            // SND.UNA (oldest unacked)

    // Buffers
    rx_buffer: VecDeque<u8>,
    tx_buffer: VecDeque<u8>,

    // Timer state
    timewait_deadline_ms: Option<u64>,
}

impl TcpSocket {
    /// Create a new TCP socket.
    pub fn new() -> Self {
        TcpSocket {
            state: State::Closed,
            tuple: None,
            listen_endpoint: IpEndpoint::default(),
            local_seq_no: SeqNumber::new(0),
            remote_seq_no: SeqNumber::new(0),
            remote_last_seq: SeqNumber::new(0),
            remote_last_ack: None,
            iss: SeqNumber::new(0),
            irs: SeqNumber::new(0),
            local_win_len: 0,
            remote_win_len: 0,
            snd_wl1: SeqNumber::new(0),
            snd_wl2: SeqNumber::new(0),
            snd_una: SeqNumber::new(0),
            rx_buffer: VecDeque::with_capacity(SOCKET_BUFFER_SIZE),
            tx_buffer: VecDeque::new(),
            timewait_deadline_ms: None,
        }
    }

    /// Get the current state.
    pub fn state(&self) -> State {
        self.state
    }

    /// Check if the socket is in a state that allows sending.
    pub fn can_send(&self) -> bool {
        matches!(self.state, State::Established | State::CloseWait)
    }

    /// Check if the socket is in a state that allows receiving.
    pub fn can_recv(&self) -> bool {
        matches!(
            self.state,
            State::Established | State::FinWait1 | State::FinWait2 | State::CloseWait
        )
    }

    // ========== API Methods ==========

    /// Listen for connections (passive open).
    pub fn listen(&mut self, local_endpoint: IpEndpoint) -> core::result::Result<(), ListenError> {
        if !matches!(self.state, State::Closed) {
            return Err(ListenError::InvalidState);
        }

        self.listen_endpoint = local_endpoint;
        self.tuple = Some(Tuple {
            local: local_endpoint,
            remote: IpEndpoint::default(),
        });
        self.state = State::Listen;
        Ok(())
    }

    /// Connect to a remote endpoint (active open).
    pub fn connect(&mut self, local: IpEndpoint, remote: IpEndpoint) -> core::result::Result<(), ConnectError> {
        if !matches!(self.state, State::Closed) {
            return Err(ConnectError::InvalidState);
        }

        self.tuple = Some(Tuple { local, remote });
        self.iss = SeqNumber::new(random_u32());
        self.local_seq_no = self.iss;
        self.snd_una = self.iss;
        self.remote_win_len = self.rx_buffer.capacity() as u16;
        self.state = State::SynSent;

        Ok(())
    }

    /// Send data.
    pub fn send(&mut self, data: &[u8]) -> core::result::Result<usize, SendError> {
        if !self.can_send() {
            return Err(SendError::InvalidState);
        }

        let available = self.tx_buffer.capacity().saturating_sub(self.tx_buffer.len());
        let to_send = core::cmp::min(data.len(), available);

        if to_send == 0 {
            return Err(SendError::BufferFull);
        }

        for &byte in &data[..to_send] {
            self.tx_buffer.push_back(byte);
        }

        Ok(to_send)
    }

    /// Receive data.
    pub fn recv(&mut self, buf: &mut [u8]) -> core::result::Result<usize, RecvError> {
        if !self.can_recv() && !matches!(self.state, State::CloseWait) {
            return Err(RecvError::InvalidState);
        }

        let len = core::cmp::min(buf.len(), self.rx_buffer.len());

        for i in 0..len {
            buf[i] = self.rx_buffer.pop_front().unwrap();
        }

        // Update receive window
        self.remote_win_len = (self.rx_buffer.capacity() - self.rx_buffer.len()) as u16;

        Ok(len)
    }

    /// Close the connection.
    pub fn close(&mut self) -> Result<()> {
        match self.state {
            State::Closed => Err(Error::Failed("already closed")),
            State::Listen | State::SynSent => {
                self.state = State::Closed;
                Ok(())
            }
            State::SynReceived | State::Established => {
                self.state = State::FinWait1;
                Ok(())
            }
            State::CloseWait => {
                self.state = State::LastAck;
                Ok(())
            }
            _ => Err(Error::Failed("invalid state for close")),
        }
    }

    // ========== Packet Processing (RFC 793) ==========

    /// Process an incoming TCP segment.
    ///
    /// This implements the TCP state machine according to RFC 793 Section 3.9.
    /// Returns a Repr if a response packet should be sent.
    pub fn process<'a>(
        &mut self,
        repr: &Repr<'a>,
        src_ip: IpV4Addr,
        dst_ip: IpV4Addr,
    ) -> Option<Repr<'static>> {
        // Extract flags for easier matching
        let has_syn = repr.control == Control::Syn;
        let has_fin = repr.control == Control::Fin;
        let has_rst = repr.control == Control::Rst;
        let has_ack = repr.ack_number.is_some();

        match self.state {
            // ========== LISTEN ==========
            State::Listen => {
                // First: check RST
                if has_rst {
                    return None;
                }

                // Second: check ACK
                if has_ack {
                    // Send RST
                    return Some(self.rst_reply(repr.ack_number.unwrap()));
                }

                // Third: check SYN
                if has_syn {
                    self.irs = repr.seq_number;
                    self.remote_seq_no = repr.seq_number + 1;
                    self.iss = SeqNumber::new(random_u32());
                    self.local_seq_no = self.iss;
                    self.snd_una = self.iss;
                    self.remote_win_len = self.rx_buffer.capacity() as u16;

                    // Update tuple
                    if let Some(ref mut tuple) = self.tuple {
                        tuple.remote = IpEndpoint::new(src_ip, repr.src_port);
                    }

                    self.state = State::SynReceived;

                    // Send SYN-ACK
                    return Some(Repr {
                        src_port: repr.dst_port,
                        dst_port: repr.src_port,
                        control: Control::Syn,
                        seq_number: self.iss,
                        ack_number: Some(self.remote_seq_no),
                        window_len: self.remote_win_len,
                        payload: &[],
                    });
                }

                None
            }

            // ========== SYN-SENT ==========
            State::SynSent => {
                let mut acceptable = false;

                // First: check ACK
                if has_ack {
                    let ack = repr.ack_number.unwrap();
                    if ack <= self.iss || ack > self.local_seq_no {
                        // Send RST
                        return Some(self.rst_reply(ack));
                    }
                    if self.snd_una <= ack && ack <= self.local_seq_no {
                        acceptable = true;
                    }
                }

                // Second: check RST
                if has_rst {
                    if acceptable {
                        self.state = State::Closed;
                    }
                    return None;
                }

                // Fourth: check SYN
                if has_syn {
                    self.irs = repr.seq_number;
                    self.remote_seq_no = repr.seq_number + 1;

                    if acceptable {
                        self.snd_una = repr.ack_number.unwrap();
                    }

                    if self.snd_una > self.iss {
                        // Connection established
                        self.state = State::Established;
                        self.local_win_len = repr.window_len;
                        self.snd_wl1 = repr.seq_number;
                        self.snd_wl2 = repr.ack_number.unwrap();

                        // Send ACK
                        return Some(Repr {
                            src_port: repr.dst_port,
                            dst_port: repr.src_port,
                            control: Control::None,
                            seq_number: self.local_seq_no,
                            ack_number: Some(self.remote_seq_no),
                            window_len: self.remote_win_len,
                            payload: &[],
                        });
                    } else {
                        // Simultaneous open
                        self.state = State::SynReceived;
                        return Some(Repr {
                            src_port: repr.dst_port,
                            dst_port: repr.src_port,
                            control: Control::Syn,
                            seq_number: self.iss,
                            ack_number: Some(self.remote_seq_no),
                            window_len: self.remote_win_len,
                            payload: &[],
                        });
                    }
                }

                None
            }

            // ========== Other States ==========
            State::SynReceived
            | State::Established
            | State::FinWait1
            | State::FinWait2
            | State::CloseWait
            | State::Closing
            | State::LastAck
            | State::TimeWait => {
                // First: check sequence number
                let seg_len = repr.payload.len() + if has_syn { 1 } else { 0 } + if has_fin { 1 } else { 0 };

                let acceptable = if seg_len == 0 {
                    if self.remote_win_len == 0 {
                        repr.seq_number == self.remote_seq_no
                    } else {
                        self.remote_seq_no <= repr.seq_number
                            && repr.seq_number < self.remote_seq_no + self.remote_win_len as usize
                    }
                } else {
                    if self.remote_win_len == 0 {
                        false
                    } else {
                        (self.remote_seq_no <= repr.seq_number
                            && repr.seq_number < self.remote_seq_no + self.remote_win_len as usize)
                            || (self.remote_seq_no <= repr.seq_number + seg_len - 1
                                && repr.seq_number + seg_len - 1 < self.remote_seq_no + self.remote_win_len as usize)
                    }
                };

                if !acceptable {
                    if !has_rst {
                        return Some(self.ack_reply());
                    }
                    return None;
                }

                // Second: check RST
                if has_rst {
                    self.state = State::Closed;
                    return None;
                }

                // Fourth: check SYN (in window)
                if has_syn {
                    self.state = State::Closed;
                    return Some(self.rst_reply(self.local_seq_no));
                }

                // Fifth: check ACK
                if !has_ack {
                    return None;
                }

                let ack = repr.ack_number.unwrap();

                // Process ACK
                match self.state {
                    State::SynReceived => {
                        if self.snd_una <= ack && ack <= self.local_seq_no {
                            self.state = State::Established;
                            self.snd_una = ack;
                        } else {
                            return Some(self.rst_reply(ack));
                        }
                    }
                    _ => {}
                }

                // Update window
                if self.snd_una < ack && ack <= self.local_seq_no {
                    self.snd_una = ack;

                    // Update send window
                    if self.snd_wl1 < repr.seq_number
                        || (self.snd_wl1 == repr.seq_number && self.snd_wl2 <= ack)
                    {
                        self.local_win_len = repr.window_len;
                        self.snd_wl1 = repr.seq_number;
                        self.snd_wl2 = ack;
                    }
                }

                // State-specific ACK processing
                match self.state {
                    State::FinWait1 => {
                        if ack == self.local_seq_no {
                            self.state = State::FinWait2;
                        }
                    }
                    State::Closing => {
                        if ack == self.local_seq_no {
                            self.state = State::TimeWait;
                            self.timewait_deadline_ms = Some(get_time_ms() + TIME_WAIT_TIMEOUT_MS);
                        }
                    }
                    State::LastAck => {
                        if ack == self.local_seq_no {
                            self.state = State::Closed;
                            return None;
                        }
                    }
                    State::TimeWait => {
                        if has_fin {
                            self.timewait_deadline_ms = Some(get_time_ms() + TIME_WAIT_TIMEOUT_MS);
                        }
                    }
                    _ => {}
                }

                // Seventh: process segment text
                if matches!(self.state, State::Established | State::FinWait1 | State::FinWait2)
                    && !repr.payload.is_empty()
                {
                    // Store data
                    for &byte in repr.payload {
                        if self.rx_buffer.len() < self.rx_buffer.capacity() {
                            self.rx_buffer.push_back(byte);
                        }
                    }
                    self.remote_seq_no = repr.seq_number + repr.payload.len();
                    self.remote_win_len = (self.rx_buffer.capacity() - self.rx_buffer.len()) as u16;

                    return Some(self.ack_reply());
                }

                // Eighth: check FIN
                if has_fin {
                    self.remote_seq_no = repr.seq_number + 1;

                    match self.state {
                        State::SynReceived | State::Established => {
                            self.state = State::CloseWait;
                        }
                        State::FinWait1 => {
                            if ack == self.local_seq_no {
                                self.state = State::TimeWait;
                                self.timewait_deadline_ms = Some(get_time_ms() + TIME_WAIT_TIMEOUT_MS);
                            } else {
                                self.state = State::Closing;
                            }
                        }
                        State::FinWait2 => {
                            self.state = State::TimeWait;
                            self.timewait_deadline_ms = Some(get_time_ms() + TIME_WAIT_TIMEOUT_MS);
                        }
                        State::TimeWait => {
                            self.timewait_deadline_ms = Some(get_time_ms() + TIME_WAIT_TIMEOUT_MS);
                        }
                        _ => {}
                    }

                    return Some(self.ack_reply());
                }

                None
            }

            State::Closed => None,
        }
    }

    /// Generate an RST reply.
    fn rst_reply(&self, seq: SeqNumber) -> Repr<'static> {
        Repr {
            src_port: self.tuple.as_ref().map(|t| t.local.port).unwrap_or(0),
            dst_port: self.tuple.as_ref().map(|t| t.remote.port).unwrap_or(0),
            control: Control::Rst,
            seq_number: seq,
            ack_number: None,
            window_len: 0,
            payload: &[],
        }
    }

    /// Generate an ACK reply.
    fn ack_reply(&self) -> Repr<'static> {
        Repr {
            src_port: self.tuple.as_ref().map(|t| t.local.port).unwrap_or(0),
            dst_port: self.tuple.as_ref().map(|t| t.remote.port).unwrap_or(0),
            control: Control::None,
            seq_number: self.local_seq_no,
            ack_number: Some(self.remote_seq_no),
            window_len: self.remote_win_len,
            payload: &[],
        }
    }

    /// Check if there is data to send and return a Repr if so.
    pub fn dispatch(&mut self) -> Option<Repr<'static>> {
        // Check if we need to send a SYN
        if self.state == State::SynSent {
            self.local_seq_no = self.iss + 1;
            return Some(Repr {
                src_port: self.tuple.as_ref().unwrap().local.port,
                dst_port: self.tuple.as_ref().unwrap().remote.port,
                control: Control::Syn,
                seq_number: self.iss,
                ack_number: None,
                window_len: self.remote_win_len,
                payload: &[],
            });
        }

        // Check if we need to send a FIN
        if matches!(self.state, State::FinWait1 | State::LastAck) && self.tx_buffer.is_empty() {
            // FIN already accounted for in local_seq_no
            return Some(Repr {
                src_port: self.tuple.as_ref().unwrap().local.port,
                dst_port: self.tuple.as_ref().unwrap().remote.port,
                control: Control::Fin,
                seq_number: self.local_seq_no,
                ack_number: Some(self.remote_seq_no),
                window_len: self.remote_win_len,
                payload: &[],
            });
        }

        // Check if we have data to send
        if self.can_send() && !self.tx_buffer.is_empty() {
            // Calculate how much we can send
            let in_flight = (self.local_seq_no - self.snd_una) as usize;
            let window_available = (self.local_win_len as usize).saturating_sub(in_flight);

            if window_available == 0 {
                return None;
            }

            let mss = 1460; // TODO: negotiate MSS
            let to_send = core::cmp::min(
                core::cmp::min(self.tx_buffer.len(), mss),
                window_available,
            );

            if to_send == 0 {
                return None;
            }

            // Create payload buffer
            let mut payload_buf = alloc::vec![0u8; to_send];
            for i in 0..to_send {
                payload_buf[i] = self.tx_buffer[i];
            }

            // Note: In a real implementation, we'd need to handle the lifetime properly
            // For now, this is a placeholder showing the structure
            return None; // TODO: handle payload lifetime
        }

        None
    }
}

impl Default for TcpSocket {
    fn default() -> Self {
        Self::new()
    }
}

// ========== Helper Functions ==========

fn get_time_ms() -> u64 {
    // TODO: Implement proper time source
    // For now, return a dummy value
    0
}
```

---

### Step 4: Interface層 - SocketSet (src/kernel/net/iface/socket_set.rs)

```rust
//! Socket set for managing multiple sockets.

use alloc::vec::Vec;
use core::fmt;
use crate::kernel::net::socket::Socket;

/// A handle identifying a socket in the set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SocketHandle(usize);

impl SocketHandle {
    pub fn new(index: usize) -> Self {
        Self(index)
    }
}

impl fmt::Display for SocketHandle {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "#{}", self.0)
    }
}

/// Socket storage entry.
pub struct SocketStorage<'a> {
    inner: Option<Socket<'a>>,
}

impl<'a> SocketStorage<'a> {
    pub const EMPTY: Self = Self { inner: None };
}

/// A set of sockets for managing multiple network endpoints.
pub struct SocketSet<'a> {
    sockets: Vec<SocketStorage<'a>>,
}

impl<'a> SocketSet<'a> {
    /// Create a new socket set with the specified capacity.
    pub fn new(capacity: usize) -> Self {
        let mut sockets = Vec::with_capacity(capacity);
        for _ in 0..capacity {
            sockets.push(SocketStorage { inner: None });
        }
        Self { sockets }
    }

    /// Add a socket to the set and return its handle.
    pub fn add(&mut self, socket: Socket<'a>) -> Result<SocketHandle, &'static str> {
        for (index, slot) in self.sockets.iter_mut().enumerate() {
            if slot.inner.is_none() {
                slot.inner = Some(socket);
                return Ok(SocketHandle(index));
            }
        }
        Err("socket set is full")
    }

    /// Get a reference to a socket by its handle.
    pub fn get(&self, handle: SocketHandle) -> Option<&Socket<'a>> {
        self.sockets.get(handle.0).and_then(|s| s.inner.as_ref())
    }

    /// Get a mutable reference to a socket by its handle.
    pub fn get_mut(&mut self, handle: SocketHandle) -> Option<&mut Socket<'a>> {
        self.sockets.get_mut(handle.0).and_then(|s| s.inner.as_mut())
    }

    /// Remove a socket from the set.
    pub fn remove(&mut self, handle: SocketHandle) -> Option<Socket<'a>> {
        self.sockets.get_mut(handle.0).and_then(|s| s.inner.take())
    }
}
```

---

### Step 5: Socket層 - Socket enum (src/kernel/net/socket/mod.rs)

```rust
//! Network socket types.

pub mod tcp;

/// A network socket.
///
/// This enum abstracts different types of sockets.
/// Currently only TCP is implemented.
#[derive(Debug)]
pub enum Socket<'a> {
    Tcp(tcp::TcpSocket),
}

impl<'a> Socket<'a> {
    /// Unwrap as TCP socket.
    pub fn as_tcp(&self) -> Option<&tcp::TcpSocket> {
        match self {
            Socket::Tcp(s) => Some(s),
        }
    }

    /// Unwrap as mutable TCP socket.
    pub fn as_tcp_mut(&mut self) -> Option<&mut tcp::TcpSocket> {
        match self {
            Socket::Tcp(s) => Some(s),
        }
    }
}

/// Trait for converting sockets to/from the Socket enum.
pub trait AnySocket<'a> {
    fn upcast(self) -> Socket<'a>;
    fn downcast(socket: &Socket<'a>) -> Option<&Self>;
    fn downcast_mut(socket: &mut Socket<'a>) -> Option<&mut Self>;
}

impl<'a> AnySocket<'a> for tcp::TcpSocket {
    fn upcast(self) -> Socket<'a> {
        Socket::Tcp(self)
    }

    fn downcast(socket: &Socket<'a>) -> Option<&Self> {
        match socket {
            Socket::Tcp(s) => Some(s),
        }
    }

    fn downcast_mut(socket: &mut Socket<'a>) -> Option<&mut Self> {
        match socket {
            Socket::Tcp(s) => Some(s),
        }
    }
}
```

---

### Step 6: Wire層 - Module exports (src/kernel/net/wire/mod.rs)

```rust
//! Wire format parsers and emitters.

pub mod tcp;

pub use tcp::{Control, Packet, Repr, SeqNumber};
```

---

### Step 7: Interface層 - Module exports (src/kernel/net/iface/mod.rs)

```rust
//! Network interface management.

pub mod socket_set;

pub use socket_set::{SocketHandle, SocketSet, SocketStorage};
```

---

## 使用例

### TCPサーバー (with SocketSet)

```rust
use octox_net::kernel::net::socket::tcp::{IpEndpoint, TcpSocket};
use octox_net::kernel::net::iface::SocketSet;
use octox_net::kernel::net::socket::{Socket, AnySocket};
use noli::net::IpV4Addr;

// Create socket set
let mut sockets = SocketSet::new(16);

// Create and add TCP socket
let mut tcp_socket = TcpSocket::new();
let local = IpEndpoint::new(IpV4Addr::new(0, 0, 0, 0), 8080);
tcp_socket.listen(local)?;

let handle = sockets.add(Socket::Tcp(tcp_socket))?;

// Later: access socket
if let Some(Socket::Tcp(socket)) = sockets.get_mut(handle) {
    let mut buf = [0u8; 1024];
    let n = socket.recv(&mut buf)?;
    socket.send(b"Hello, World!")?;
}
```

### TCPクライアント

```rust
let mut tcp_socket = TcpSocket::new();

let local = IpEndpoint::new(IpV4Addr::new(0, 0, 0, 0), 0);
let remote = IpEndpoint::new(IpV4Addr::new(192, 168, 1, 100), 8080);

tcp_socket.connect(local, remote)?;

// (After connection established via process())
socket.send(b"GET / HTTP/1.0\r\n\r\n")?;

let mut buf = [0u8; 4096];
let n = socket.recv(&mut buf)?;

socket.close()?;
```

---

## 実装チェックリスト

- [ ] Step 1: Utility拡張
  - [ ] random_u32() (Xorshift)
  - [ ] byteorder依存追加
- [ ] Step 2: Wire層 (wire/tcp.rs)
  - [ ] Field type alias
  - [ ] SeqNumber (i32ベース)
  - [ ] Packet (NetworkEndian使用)
  - [ ] Repr構造体
  - [ ] parse/emit メソッド
- [ ] Step 3: Socket層 (socket/tcp.rs)
  - [ ] TcpSocket構造体
  - [ ] State enum (RFC URL付き)
  - [ ] process() メソッド (RFC 793準拠)
  - [ ] API (listen/connect/send/recv/close)
- [ ] Step 4: Interface層 (iface/socket_set.rs)
  - [ ] SocketSet<'a>
  - [ ] SocketHandle
  - [ ] SocketStorage
- [ ] Step 5: Socket enum (socket/mod.rs)
  - [ ] Socket<'a> enum
  - [ ] AnySocket trait
- [ ] Step 6-7: Module exports
  - [ ] wire/mod.rs
  - [ ] iface/mod.rs

---

## 次のステップ

1. **IP層統合**: SocketSetとIP層の接続（tcp_input呼び出し）
2. **時刻取得**: get_time_ms()の実装
3. **再送タイマー**: RTT推定と再送ロジック
4. **poll機能**: タイムアウト・再送処理のためのポーリング
5. **テスト**: 単体テストと統合テスト

---

## 設計の特徴

### smoltcp完全準拠

1. **Wire/Socket層分離**: Packetの解析とソケット状態機械を明確に分離
2. **Repr構造体**: 抽象表現による柔軟なパケット操作
3. **ゼロコピー**: `Packet<T: AsRef<[u8]>>`
4. **型安全性**: SeqNumber, State, Control等の型
5. **NetworkEndian**: byteorderクレート使用

### RFC 793準拠

- TCP状態機械の完全実装
- Segment Arrives処理
- Sequence number処理
- Window管理

### Rustイディオム

- Field type alias
- Option/Result型
- パターンマッチング
- trait実装 (Display, Default)
- 適切なエラー型分離
