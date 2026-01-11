//! TCP wire format and packet representation.
//!
//! This module implements zero-copy parsing and emission of TCP packets,
//! following RFC 793 and smoltcp's design patterns.

use crate::error::{Error, Result};
use crate::net::ip::IpAddr;
use crate::net::util::{self, read_i32, read_u16, write_i32, write_u16};
use core::cmp::Ordering;
use core::fmt;
use core::ops::{Add, AddAssign, Sub};

// ========== TCP Header Field Offsets ==========

mod field {
    pub type Field = core::ops::Range<usize>;

    pub const SRC_PORT: Field = 0..2;
    pub const DST_PORT: Field = 2..4;
    pub const SEQ_NUM: Field = 4..8;
    pub const ACK_NUM: Field = 8..12;
    pub const _FLAGS: Field = 12..14;
    pub const WIN_SIZE: Field = 14..16;
    pub const CHECKSUM: Field = 16..18;
    pub const URGENT: Field = 18..20;

    // Flag bit positions (in big-endian u16, lower byte)
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
/// Using i32 internally allows wraparound-safe comparisons per RFC 793.
///
/// See [RFC 793 Section 3.3](https://www.rfc-editor.org/rfc/rfc793.html#section-3.3)
#[derive(Debug, PartialEq, Eq, Clone, Copy, Default)]
pub struct SeqNumber(pub i32);

impl SeqNumber {
    /// Create a sequence number from a u32 value.
    pub const fn new(val: u32) -> Self {
        SeqNumber(val as i32)
    }

    /// Convert to u32.
    pub const fn as_u32(self) -> u32 {
        self.0 as u32
    }
}

impl fmt::Display for SeqNumber {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0 as u32)
    }
}

// Arithmetic operations with wraparound safety

impl Add<usize> for SeqNumber {
    type Output = SeqNumber;
    fn add(self, rhs: usize) -> SeqNumber {
        // Check for reasonable bounds
        debug_assert!(
            rhs <= i32::MAX as usize,
            "sequence number addition overflow"
        );
        SeqNumber(self.0.wrapping_add(rhs as i32))
    }
}

impl Sub<usize> for SeqNumber {
    type Output = SeqNumber;
    fn sub(self, rhs: usize) -> SeqNumber {
        debug_assert!(
            rhs <= i32::MAX as usize,
            "sequence number subtraction overflow"
        );
        SeqNumber(self.0.wrapping_sub(rhs as i32))
    }
}

impl AddAssign<usize> for SeqNumber {
    fn add_assign(&mut self, rhs: usize) {
        *self = *self + rhs;
    }
}

/// Subtraction between two sequence numbers gives the distance.
impl Sub for SeqNumber {
    type Output = usize;
    fn sub(self, rhs: SeqNumber) -> usize {
        let result = self.0.wrapping_sub(rhs.0);
        // In wraparound arithmetic, result can be negative if rhs > self
        // This is a valid case (e.g., when comparing wrapped sequences)
        // Return as usize (will be very large if negative, caller must handle)
        result as usize
    }
}

// Comparison using wraparound-safe arithmetic (RFC 793)

impl PartialOrd for SeqNumber {
    fn partial_cmp(&self, other: &SeqNumber) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for SeqNumber {
    fn cmp(&self, other: &Self) -> Ordering {
        // Wraparound-safe comparison: use signed subtraction
        let diff = self.0.wrapping_sub(other.0);
        diff.cmp(&0)
    }
}

// ========== TCP Control Flags ==========

/// TCP control flags.
///
/// Note: ACK is handled separately in Repr.ack_number field.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Control {
    None,
    Syn,
    Fin,
    Rst,
    Psh,
}

impl Control {
    /// Return how many sequence numbers this control consumes.
    pub fn len(&self) -> usize {
        match self {
            Control::Syn | Control::Fin => 1,
            _ => 0,
        }
    }
}

// ========== TCP Options ==========

/// TCP options that can appear in the header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpOption<'a> {
    EndOfOptions,
    NoOp,
    MaxSegmentSize(u16),
    WindowScale(u8),
    SackPermitted,
    Timestamp { tsval: u32, tsecr: u32 },
    Unknown { kind: u8, data: &'a [u8] },
}

impl<'a> TcpOption<'a> {
    /// Parse a single TCP option from the data.
    ///
    /// Returns (option, bytes_consumed) or error.
    pub fn parse(data: &'a [u8]) -> Result<(Self, usize)> {
        if data.is_empty() {
            return Err(Error::PacketTooShort);
        }

        let kind = data[0];
        match kind {
            0 => Ok((TcpOption::EndOfOptions, 1)),
            1 => Ok((TcpOption::NoOp, 1)),
            2 => {
                // MSS
                if data.len() < 4 {
                    return Err(Error::PacketTooShort);
                }
                if data[1] != 4 {
                    return Err(Error::InvalidLength);
                }
                let mss = u16::from_be_bytes([data[2], data[3]]);
                Ok((TcpOption::MaxSegmentSize(mss), 4))
            }
            3 => {
                // Window scale
                if data.len() < 3 {
                    return Err(Error::PacketTooShort);
                }
                if data[1] != 3 {
                    return Err(Error::InvalidLength);
                }
                Ok((TcpOption::WindowScale(data[2]), 3))
            }
            4 => {
                // SACK permitted
                if data.len() < 2 {
                    return Err(Error::PacketTooShort);
                }
                if data[1] != 2 {
                    return Err(Error::InvalidLength);
                }
                Ok((TcpOption::SackPermitted, 2))
            }
            8 => {
                // Timestamp
                if data.len() < 10 {
                    return Err(Error::PacketTooShort);
                }
                if data[1] != 10 {
                    return Err(Error::InvalidLength);
                }
                let tsval = u32::from_be_bytes([data[2], data[3], data[4], data[5]]);
                let tsecr = u32::from_be_bytes([data[6], data[7], data[8], data[9]]);
                Ok((TcpOption::Timestamp { tsval, tsecr }, 10))
            }
            _ => {
                // Unknown option
                if data.len() < 2 {
                    return Err(Error::PacketTooShort);
                }
                let len = data[1] as usize;
                if len < 2 || data.len() < len {
                    return Err(Error::InvalidLength);
                }
                Ok((
                    TcpOption::Unknown {
                        kind,
                        data: &data[2..len],
                    },
                    len,
                ))
            }
        }
    }

    /// Emit the option to a buffer, returning bytes written.
    pub fn emit(&self, buf: &mut [u8]) -> usize {
        match *self {
            TcpOption::EndOfOptions => {
                buf[0] = 0;
                1
            }
            TcpOption::NoOp => {
                buf[0] = 1;
                1
            }
            TcpOption::MaxSegmentSize(mss) => {
                buf[0] = 2;
                buf[1] = 4;
                buf[2..4].copy_from_slice(&mss.to_be_bytes());
                4
            }
            TcpOption::WindowScale(shift) => {
                buf[0] = 3;
                buf[1] = 3;
                buf[2] = shift;
                3
            }
            TcpOption::SackPermitted => {
                buf[0] = 4;
                buf[1] = 2;
                2
            }
            TcpOption::Timestamp { tsval, tsecr } => {
                buf[0] = 8;
                buf[1] = 10;
                buf[2..6].copy_from_slice(&tsval.to_be_bytes());
                buf[6..10].copy_from_slice(&tsecr.to_be_bytes());
                10
            }
            TcpOption::Unknown { kind, data } => {
                let len = 2 + data.len();
                buf[0] = kind;
                buf[1] = len as u8;
                buf[2..len].copy_from_slice(data);
                len
            }
        }
    }

    /// Return the length of this option when emitted.
    pub fn buffer_len(&self) -> usize {
        match *self {
            TcpOption::EndOfOptions | TcpOption::NoOp => 1,
            TcpOption::MaxSegmentSize(_) => 4,
            TcpOption::WindowScale(_) => 3,
            TcpOption::SackPermitted => 2,
            TcpOption::Timestamp { .. } => 10,
            TcpOption::Unknown { data, .. } => 2 + data.len(),
        }
    }
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
            return Err(Error::PacketTooShort);
        }
        let header_len = self.header_len() as usize;
        if len < header_len || header_len < HEADER_LEN {
            return Err(Error::InvalidHeaderLen);
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
        read_u16(&self.buffer.as_ref()[field::SRC_PORT])
    }

    /// Return the destination port field.
    #[inline]
    pub fn dst_port(&self) -> u16 {
        read_u16(&self.buffer.as_ref()[field::DST_PORT])
    }

    /// Return the sequence number field.
    #[inline]
    pub fn seq_number(&self) -> SeqNumber {
        SeqNumber(read_i32(&self.buffer.as_ref()[field::SEQ_NUM]))
    }

    /// Return the acknowledgement number field.
    #[inline]
    pub fn ack_number(&self) -> SeqNumber {
        SeqNumber(read_i32(&self.buffer.as_ref()[field::ACK_NUM]))
    }

    /// Return the header length, in octets.
    #[inline]
    pub fn header_len(&self) -> u8 {
        let data = self.buffer.as_ref();
        ((data[12] >> 4) * 4) as u8
    }

    /// Return the FIN flag.
    #[inline]
    pub fn fin(&self) -> bool {
        let data = self.buffer.as_ref();
        (data[13] & (field::FLG_FIN as u8)) != 0
    }

    /// Return the SYN flag.
    #[inline]
    pub fn syn(&self) -> bool {
        let data = self.buffer.as_ref();
        (data[13] & (field::FLG_SYN as u8)) != 0
    }

    /// Return the RST flag.
    #[inline]
    pub fn rst(&self) -> bool {
        let data = self.buffer.as_ref();
        (data[13] & (field::FLG_RST as u8)) != 0
    }

    /// Return the PSH flag.
    #[inline]
    pub fn psh(&self) -> bool {
        let data = self.buffer.as_ref();
        (data[13] & (field::FLG_PSH as u8)) != 0
    }

    /// Return the ACK flag.
    #[inline]
    pub fn ack(&self) -> bool {
        let data = self.buffer.as_ref();
        (data[13] & (field::FLG_ACK as u8)) != 0
    }

    /// Return the URG flag.
    #[inline]
    pub fn urg(&self) -> bool {
        let data = self.buffer.as_ref();
        (data[13] & (field::FLG_URG as u8)) != 0
    }

    /// Return the window size field.
    #[inline]
    pub fn window_len(&self) -> u16 {
        read_u16(&self.buffer.as_ref()[field::WIN_SIZE])
    }

    /// Return the checksum field.
    #[inline]
    pub fn checksum(&self) -> u16 {
        read_u16(&self.buffer.as_ref()[field::CHECKSUM])
    }

    /// Return the urgent pointer field.
    #[inline]
    pub fn urgent_at(&self) -> u16 {
        read_u16(&self.buffer.as_ref()[field::URGENT])
    }

    /// Return the options slice.
    #[inline]
    pub fn options(&self) -> &[u8] {
        let header_len = self.header_len() as usize;
        let data = self.buffer.as_ref();
        &data[HEADER_LEN..header_len]
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
    pub fn verify_checksum(&self, src_ip: IpAddr, dst_ip: IpAddr) -> bool {
        let data = self.buffer.as_ref();
        let pseudo = tcp_pseudo_header_checksum(src_ip, dst_ip, data.len() as u16);
        let tcp_sum = util::checksum(data);

        // Combine pseudo-header and TCP checksum
        let combined = checksum_combine(&[pseudo, tcp_sum]);
        combined == 0
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> Packet<T> {
    // ========== Setter Methods ==========

    /// Set the source port field.
    #[inline]
    pub fn set_src_port(&mut self, value: u16) {
        write_u16(&mut self.buffer.as_mut()[field::SRC_PORT], value);
    }

    /// Set the destination port field.
    #[inline]
    pub fn set_dst_port(&mut self, value: u16) {
        write_u16(&mut self.buffer.as_mut()[field::DST_PORT], value);
    }

    /// Set the sequence number field.
    #[inline]
    pub fn set_seq_number(&mut self, value: SeqNumber) {
        write_i32(&mut self.buffer.as_mut()[field::SEQ_NUM], value.0);
    }

    /// Set the acknowledgement number field.
    #[inline]
    pub fn set_ack_number(&mut self, value: SeqNumber) {
        write_i32(&mut self.buffer.as_mut()[field::ACK_NUM], value.0);
    }

    /// Set the header length field (in 32-bit words).
    #[inline]
    pub fn set_header_len(&mut self, length: u8) {
        let data = self.buffer.as_mut();
        data[12] = (data[12] & 0x0f) | ((length / 4) << 4);
    }

    /// Clear the entire flags field.
    #[inline]
    pub fn clear_flags(&mut self) {
        let data = self.buffer.as_mut();
        data[13] = 0;
    }

    /// Set the FIN flag.
    #[inline]
    pub fn set_fin(&mut self, value: bool) {
        let data = self.buffer.as_mut();
        if value {
            data[13] |= field::FLG_FIN as u8;
        } else {
            data[13] &= !(field::FLG_FIN as u8);
        }
    }

    /// Set the SYN flag.
    #[inline]
    pub fn set_syn(&mut self, value: bool) {
        let data = self.buffer.as_mut();
        if value {
            data[13] |= field::FLG_SYN as u8;
        } else {
            data[13] &= !(field::FLG_SYN as u8);
        }
    }

    /// Set the RST flag.
    #[inline]
    pub fn set_rst(&mut self, value: bool) {
        let data = self.buffer.as_mut();
        if value {
            data[13] |= field::FLG_RST as u8;
        } else {
            data[13] &= !(field::FLG_RST as u8);
        }
    }

    /// Set the PSH flag.
    #[inline]
    pub fn set_psh(&mut self, value: bool) {
        let data = self.buffer.as_mut();
        if value {
            data[13] |= field::FLG_PSH as u8;
        } else {
            data[13] &= !(field::FLG_PSH as u8);
        }
    }

    /// Set the ACK flag.
    #[inline]
    pub fn set_ack(&mut self, value: bool) {
        let data = self.buffer.as_mut();
        if value {
            data[13] |= field::FLG_ACK as u8;
        } else {
            data[13] &= !(field::FLG_ACK as u8);
        }
    }

    /// Set the window size field.
    #[inline]
    pub fn set_window_len(&mut self, value: u16) {
        write_u16(&mut self.buffer.as_mut()[field::WIN_SIZE], value);
    }

    /// Set the checksum field.
    #[inline]
    pub fn set_checksum(&mut self, value: u16) {
        write_u16(&mut self.buffer.as_mut()[field::CHECKSUM], value);
    }

    /// Set the urgent pointer field.
    #[inline]
    pub fn set_urgent_at(&mut self, value: u16) {
        write_u16(&mut self.buffer.as_mut()[field::URGENT], value);
    }

    /// Fill the checksum field.
    pub fn fill_checksum(&mut self, src_ip: IpAddr, dst_ip: IpAddr) {
        self.set_checksum(0);
        let data = self.buffer.as_ref();
        let pseudo = tcp_pseudo_header_checksum(src_ip, dst_ip, data.len() as u16);
        let tcp_sum = util::checksum(data);
        let checksum = !checksum_combine(&[pseudo, tcp_sum]);
        self.set_checksum(checksum);
    }
}

impl<T: AsRef<[u8]>> fmt::Display for Packet<T> {
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
    pub max_seg_size: Option<u16>,
    pub window_scale: Option<u8>,
    pub sack_permitted: bool,
    pub payload: &'a [u8],
}

impl<'a> Repr<'a> {
    /// Parse a TCP packet and return a high-level representation.
    pub fn parse<T>(
        packet: &'a Packet<&'a T>,
        _src_ip: IpAddr,
        _dst_ip: IpAddr,
        checksum_check: bool,
    ) -> Result<Repr<'a>>
    where
        T: AsRef<[u8]> + ?Sized,
    {
        // Verify checksum if requested
        if checksum_check && !packet.verify_checksum(_src_ip, _dst_ip) {
            return Err(Error::ChecksumError);
        }

        // Determine primary control flag
        let control = if packet.rst() {
            Control::Rst
        } else if packet.syn() {
            Control::Syn
        } else if packet.fin() {
            Control::Fin
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

        // Parse options
        let mut max_seg_size = None;
        let mut window_scale = None;
        let mut sack_permitted = false;

        let options_data = packet.options();
        let mut offset = 0;
        while offset < options_data.len() {
            match TcpOption::parse(&options_data[offset..]) {
                Ok((TcpOption::EndOfOptions, _)) => break,
                Ok((TcpOption::NoOp, len)) => offset += len,
                Ok((TcpOption::MaxSegmentSize(mss), len)) => {
                    max_seg_size = Some(mss);
                    offset += len;
                }
                Ok((TcpOption::WindowScale(shift), len)) => {
                    window_scale = Some(shift);
                    offset += len;
                }
                Ok((TcpOption::SackPermitted, len)) => {
                    sack_permitted = true;
                    offset += len;
                }
                Ok((_, len)) => offset += len, // Skip unknown options
                Err(_) => break,               // Malformed options
            }
        }

        Ok(Repr {
            src_port: packet.src_port(),
            dst_port: packet.dst_port(),
            control,
            seq_number: packet.seq_number(),
            ack_number,
            window_len: packet.window_len(),
            max_seg_size,
            window_scale,
            sack_permitted,
            payload: packet.payload(),
        })
    }

    /// Emit this representation into a TCP packet.
    pub fn emit<T>(&self, packet: &mut Packet<T>, src_ip: IpAddr, dst_ip: IpAddr)
    where
        T: AsRef<[u8]> + AsMut<[u8]>,
    {
        packet.set_src_port(self.src_port);
        packet.set_dst_port(self.dst_port);
        packet.set_seq_number(self.seq_number);
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

        // Calculate options length
        let mut options_len = 0;
        if self.max_seg_size.is_some() {
            options_len += 4;
        }
        if self.window_scale.is_some() {
            options_len += 3;
        }
        if self.sack_permitted {
            options_len += 2;
        }

        // Pad to 4-byte boundary
        let padded_options_len = (options_len + 3) & !3;
        let header_len = HEADER_LEN + padded_options_len;
        packet.set_header_len(header_len as u8);

        // Emit options
        if options_len > 0 {
            let buffer = packet.buffer.as_mut();
            let options_buf = &mut buffer[HEADER_LEN..header_len];
            let mut offset = 0;

            if let Some(mss) = self.max_seg_size {
                offset += TcpOption::MaxSegmentSize(mss).emit(&mut options_buf[offset..]);
            }
            if let Some(shift) = self.window_scale {
                offset += TcpOption::WindowScale(shift).emit(&mut options_buf[offset..]);
            }
            if self.sack_permitted {
                offset += TcpOption::SackPermitted.emit(&mut options_buf[offset..]);
            }

            // Pad with NOPs
            while offset < padded_options_len {
                options_buf[offset] = 1; // NOP
                offset += 1;
            }
        }

        // Copy payload
        if !self.payload.is_empty() {
            let buffer = packet.buffer.as_mut();
            let payload_start = header_len;
            buffer[payload_start..payload_start + self.payload.len()].copy_from_slice(self.payload);
        }

        // Fill checksum
        packet.fill_checksum(src_ip, dst_ip);
    }

    /// Return the length of a packet that will be emitted from this repr.
    pub fn buffer_len(&self) -> usize {
        let mut options_len = 0;
        if self.max_seg_size.is_some() {
            options_len += 4;
        }
        if self.window_scale.is_some() {
            options_len += 3;
        }
        if self.sack_permitted {
            options_len += 2;
        }
        let padded_options_len = (options_len + 3) & !3;
        HEADER_LEN + padded_options_len + self.payload.len()
    }

    /// Return segment length in sequence space.
    pub fn segment_len(&self) -> usize {
        self.payload.len() + self.control.len()
    }
}

// ========== Checksum Helpers ==========

/// Compute TCP pseudo-header checksum for IPv4.
fn tcp_pseudo_header_checksum(src_ip: IpAddr, dst_ip: IpAddr, tcp_len: u16) -> u16 {
    let src_bytes = src_ip.0.to_be_bytes();
    let dst_bytes = dst_ip.0.to_be_bytes();

    let mut sum: u32 = 0;

    // Source IP
    sum += u16::from_be_bytes([src_bytes[0], src_bytes[1]]) as u32;
    sum += u16::from_be_bytes([src_bytes[2], src_bytes[3]]) as u32;

    // Destination IP
    sum += u16::from_be_bytes([dst_bytes[0], dst_bytes[1]]) as u32;
    sum += u16::from_be_bytes([dst_bytes[2], dst_bytes[3]]) as u32;

    // Protocol (6 = TCP)
    sum += 6u32;

    // TCP length
    sum += tcp_len as u32;

    // Fold carries
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    sum as u16
}

/// Combine checksums.
fn checksum_combine(checksums: &[u16]) -> u16 {
    let mut sum: u32 = 0;
    for &word in checksums {
        sum += word as u32;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum as u16
}

// ========== Tests ==========

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_seq_number_arithmetic() {
        let a = SeqNumber::new(100);
        let b = SeqNumber::new(200);

        assert!(a < b);
        assert_eq!((b - a), 100);
        assert_eq!(a + 100, b);
    }

    #[test]
    fn test_seq_number_wraparound() {
        let a = SeqNumber::new(0xFFFF_FFFF);
        let b = SeqNumber::new(10);

        // b is after a despite lower numeric value
        assert!(a < b);
    }

    #[test]
    fn test_seq_number_add_assign() {
        let mut a = SeqNumber::new(100);
        a += 50;
        assert_eq!(a, SeqNumber::new(150));
    }

    #[test]
    fn test_packet_parse() {
        let data = [
            0x00, 0x50, // src port 80
            0x1F, 0x90, // dst port 8080
            0x00, 0x00, 0x00, 0x64, // seq 100
            0x00, 0x00, 0x00, 0xC8, // ack 200
            0x50, 0x12, // data offset 5 (20 bytes), flags SYN+ACK
            0x20, 0x00, // window 8192
            0x00, 0x00, // checksum (placeholder)
            0x00, 0x00, // urgent
        ];

        let packet = Packet::new_unchecked(&data);
        assert_eq!(packet.src_port(), 80);
        assert_eq!(packet.dst_port(), 8080);
        assert_eq!(packet.seq_number(), SeqNumber::new(100));
        assert_eq!(packet.ack_number(), SeqNumber::new(200));
        assert_eq!(packet.header_len(), 20);
        assert_eq!(packet.window_len(), 8192);
        assert!(packet.syn());
        assert!(packet.ack());
        assert!(!packet.fin());
        assert!(!packet.rst());
    }

    #[test]
    fn test_control_len() {
        assert_eq!(Control::None.len(), 0);
        assert_eq!(Control::Syn.len(), 1);
        assert_eq!(Control::Fin.len(), 1);
        assert_eq!(Control::Rst.len(), 0);
        assert_eq!(Control::Psh.len(), 0);
    }

    #[test]
    fn test_tcp_option_mss() {
        let data = [2, 4, 0x05, 0xB4]; // MSS = 1460
        let (opt, len) = TcpOption::parse(&data).unwrap();
        assert_eq!(opt, TcpOption::MaxSegmentSize(1460));
        assert_eq!(len, 4);

        let mut buf = [0u8; 4];
        let written = opt.emit(&mut buf);
        assert_eq!(written, 4);
        assert_eq!(buf, data);
    }
}
