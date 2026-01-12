//! TCP socket implementation.
//!
//! This module implements the TCP state machine and socket API,
//! following RFC 793 and smoltcp's design patterns.

use super::storage::{Assembler, RingBuffer};
use super::wire::{Control, Repr, SeqNumber};
use crate::error::{Error, Result};
use crate::net::ip::IpAddr;
use alloc::vec;
use alloc::vec::Vec;
use core::fmt;

// ========== TCP State ==========

/// The state of a TCP socket, according to [RFC 793](https://www.rfc-editor.org/rfc/rfc793.html).
/// [RFC 9293](https://datatracker.ietf.org/doc/html/rfc9293)
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

impl fmt::Display for State {
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
    pub addr: IpAddr,
    pub port: u16,
}

impl IpEndpoint {
    pub const fn new(addr: IpAddr, port: u16) -> Self {
        IpEndpoint { addr, port }
    }

    pub const fn unspecified() -> Self {
        IpEndpoint {
            addr: IpAddr(0),
            port: 0,
        }
    }

    pub fn is_unspecified(&self) -> bool {
        self.addr.0 == 0 && self.port == 0
    }
}

impl fmt::Display for IpEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let bytes = self.addr.0.to_be_bytes();
        write!(
            f,
            "{}.{}.{}.{}:{}",
            bytes[0], bytes[1], bytes[2], bytes[3], self.port
        )
    }
}

// ========== TCP Socket ==========

const DEFAULT_MSS: u16 = 1460; // Typical MSS for Ethernet
const TIME_WAIT_DURATION_MS: u64 = 30000; // 30 seconds (simplified from 2*MSL)

#[derive(Clone, Copy, Debug)]
pub struct Tuple {
    pub local: IpEndpoint,
    pub remote: IpEndpoint,
}

/// Connection state extracted during accept.
#[derive(Debug)]
pub(crate) struct AcceptedConnection {
    pub tuple: Tuple,
    pub snd_una: SeqNumber,
    pub snd_nxt: SeqNumber,
    pub snd_wnd: u16,
    pub snd_wl1: SeqNumber,
    pub snd_wl2: SeqNumber,
    pub iss: SeqNumber,
    pub rcv_nxt: SeqNumber,
    pub rcv_wnd: u16,
    pub irs: SeqNumber,
    pub remote_mss: u16,
    pub state: State,
}

/// A TCP socket.
///
/// This struct holds all state for a TCP connection, following RFC 793.
pub struct TcpSocket {
    state: State,
    tuple: Option<Tuple>,
    listen_endpoint: IpEndpoint,

    // ===== Sequence Variables (RFC 793 Section 3.2) =====
    // Send sequence space
    snd_una: SeqNumber, // SND.UNA - oldest unacknowledged
    snd_nxt: SeqNumber, // SND.NXT - next sequence to send
    snd_wnd: u16,       // SND.WND - send window (remote's advertised window)
    snd_wl1: SeqNumber, // SEQ of last window update
    snd_wl2: SeqNumber, // ACK of last window update
    iss: SeqNumber,     // ISS - initial send sequence

    // Receive sequence space
    rcv_nxt: SeqNumber, // RCV.NXT - next sequence expected
    rcv_wnd: u16,       // RCV.WND - receive window (our advertised window)
    irs: SeqNumber,     // IRS - initial receive sequence

    remote_last_seq: SeqNumber,

    // ===== Buffers =====
    rx_buffer: RingBuffer<'static, u8>,
    tx_buffer: RingBuffer<'static, u8>,
    assembler: Assembler,

    // ===== Options =====
    remote_mss: u16, // Remote's MSS
    local_mss: u16,  // Our MSS

    // ===== Timers =====
    retransmit_at: Option<u64>, // When to retransmit (milliseconds)
    timewait_at: Option<u64>,   // TIME-WAIT expiry
    rto: u64,                   // Retransmission timeout (milliseconds)

    // ===== Flags =====
    fin_sent: bool,     // We have sent FIN
    fin_received: bool, // We have received FIN
}

impl TcpSocket {
    /// Create a new TCP socket with pre-allocated buffers.
    pub fn new(rx_storage: &'static mut [u8], tx_storage: &'static mut [u8]) -> Self {
        TcpSocket {
            state: State::Closed,
            tuple: None,
            listen_endpoint: IpEndpoint::unspecified(),
            snd_una: SeqNumber::new(0),
            snd_nxt: SeqNumber::new(0),
            snd_wnd: 0,
            snd_wl1: SeqNumber::new(0),
            snd_wl2: SeqNumber::new(0),
            iss: SeqNumber::new(0),
            rcv_nxt: SeqNumber::new(0),
            rcv_wnd: 0,
            irs: SeqNumber::new(0),
            remote_last_seq: SeqNumber::new(0),
            rx_buffer: RingBuffer::new(rx_storage),
            tx_buffer: RingBuffer::new(tx_storage),
            assembler: Assembler::new(),
            remote_mss: DEFAULT_MSS,
            local_mss: DEFAULT_MSS,
            retransmit_at: None,
            timewait_at: None,
            rto: 1000,
            fin_sent: false,
            fin_received: false,
        }
    }

    /// Get the current state.
    pub fn state(&self) -> State {
        self.state
    }

    /// Get connection tuple.
    pub fn tuple(&self) -> Option<&Tuple> {
        self.tuple.as_ref()
    }

    /// Get local endpoint.
    pub fn local_endpoint(&self) -> IpEndpoint {
        self.tuple.map(|t| t.local).unwrap_or(self.listen_endpoint)
    }

    /// Get remote endpoint.
    pub fn remote_endpoint(&self) -> IpEndpoint {
        self.tuple
            .map(|t| t.remote)
            .unwrap_or(IpEndpoint::unspecified())
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

    /// Check if socket is open (not closed).
    pub fn is_open(&self) -> bool {
        self.state != State::Closed
    }

    /// Check if there is data available to send.
    pub fn may_send(&self) -> bool {
        self.can_send() && !self.tx_buffer.is_empty()
    }

    /// Check if there is data available to receive.
    pub fn may_recv(&self) -> bool {
        self.can_recv() && !self.rx_buffer.is_empty()
    }

    /// Check if socket is listening.
    pub fn is_listening(&self) -> bool {
        self.state == State::Listen
    }

    /// Check if a connection is ready to be accepted.
    /// This is true when a listening socket has completed the handshake.
    pub fn has_pending_connection(&self) -> bool {
        // A pending connection exists when we have a tuple and are in SYN-RECEIVED or ESTABLISHED
        matches!(self.state, State::Established | State::SynReceived) && self.tuple.is_some()
    }

    /// Extract connection state for accept.
    /// Resets this socket back to Listen state.
    pub(crate) fn accept_connection(&mut self) -> Option<AcceptedConnection> {
        if !self.has_pending_connection() {
            return None;
        }

        let tuple = self.tuple?;
        let conn = AcceptedConnection {
            tuple,
            snd_una: self.snd_una,
            snd_nxt: self.snd_nxt,
            snd_wnd: self.snd_wnd,
            snd_wl1: self.snd_wl1,
            snd_wl2: self.snd_wl2,
            iss: self.iss,
            rcv_nxt: self.rcv_nxt,
            rcv_wnd: self.rcv_wnd,
            irs: self.irs,
            remote_mss: self.remote_mss,
            state: self.state,
        };

        // Reset to Listen state
        self.state = State::Listen;
        self.tuple = None;
        // listen_endpoint stays the same
        self.snd_una = SeqNumber::new(0);
        self.snd_nxt = SeqNumber::new(0);
        self.snd_wnd = 0;
        self.rcv_nxt = SeqNumber::new(0);
        self.irs = SeqNumber::new(0);
        self.iss = SeqNumber::new(0);
        self.remote_last_seq = SeqNumber::new(0);
        self.fin_sent = false;
        self.fin_received = false;
        self.retransmit_at = None;

        Some(conn)
    }

    /// Apply accepted connection state to this socket.
    pub(crate) fn apply_accepted(&mut self, conn: AcceptedConnection) {
        self.state = conn.state;
        self.tuple = Some(conn.tuple);
        self.snd_una = conn.snd_una;
        self.snd_nxt = conn.snd_nxt;
        self.snd_wnd = conn.snd_wnd;
        self.snd_wl1 = conn.snd_wl1;
        self.snd_wl2 = conn.snd_wl2;
        self.iss = conn.iss;
        self.rcv_nxt = conn.rcv_nxt;
        self.rcv_wnd = conn.rcv_wnd;
        self.irs = conn.irs;
        self.remote_mss = conn.remote_mss;
        self.remote_last_seq = conn.snd_nxt;
    }

    // ========== API Methods ==========

    /// Listen for connections (passive open).
    pub fn listen(&mut self, local_endpoint: IpEndpoint) -> Result<()> {
        if self.is_open() {
            return Err(Error::SocketAlreadyOpen);
        }

        self.listen_endpoint = local_endpoint;
        self.tuple = None;
        self.state = State::Listen;

        // Initialize receive window
        self.rcv_wnd = self.rx_buffer.capacity() as u16;

        Ok(())
    }

    pub fn connect(&mut self, local: IpEndpoint, remote: IpEndpoint) -> Result<()> {
        if self.is_open() {
            return Err(Error::SocketAlreadyOpen);
        }

        let local_addr = if local.addr.0 != 0 {
            local.addr
        } else {
            crate::net::ip::get_source_address(remote.addr).ok_or(Error::Unaddressable)?
        };

        self.tuple = Some(Tuple {
            local: IpEndpoint::new(local_addr, local.port),
            remote,
        });

        // Generate ISS (simplified - use static value + port for now)
        // In production, should use cryptographic random
        self.iss = SeqNumber::new((local.port as u32) * 1000 + 12345);
        self.snd_una = self.iss;
        self.snd_nxt = self.iss;
        self.remote_last_seq = self.iss; // No data sent yet
        self.snd_wl1 = SeqNumber::new(0);
        self.snd_wl2 = self.iss;

        self.rcv_wnd = self.rx_buffer.capacity() as u16;
        self.state = State::SynSent;

        Ok(())
    }

    /// Send data.
    pub fn send_slice(&mut self, data: &[u8]) -> Result<usize> {
        if !self.can_send() {
            return Err(Error::SocketNotOpen);
        }

        let written = self.tx_buffer.enqueue_slice(data);
        if written == 0 && !data.is_empty() {
            return Err(Error::BufferFull);
        }

        Ok(written)
    }

    /// Receive data.
    pub fn recv_slice(&mut self, buf: &mut [u8]) -> Result<usize> {
        if !self.can_recv() {
            return Err(Error::SocketNotOpen);
        }

        let read = self.rx_buffer.dequeue_slice(buf);

        // Update receive window
        self.rcv_wnd = (self.rx_buffer.capacity() - self.rx_buffer.len()) as u16;

        Ok(read)
    }

    /// Close the connection.
    pub fn close(&mut self) {
        match self.state {
            State::Closed => {}
            State::Listen | State::SynSent => {
                self.state = State::Closed;
            }
            State::SynReceived | State::Established => {
                self.state = State::FinWait1;
                self.fin_sent = false; // Will be sent in dispatch
            }
            State::CloseWait => {
                self.state = State::LastAck;
                self.fin_sent = false; // Will be sent in dispatch
            }
            _ => {} // Other states don't support user close
        }
    }

    // ========== Packet Processing (RFC 793) ==========

    pub(crate) fn accepts(
        &self,
        src_ip: IpAddr,
        src_port: u16,
        dst_ip: IpAddr,
        dst_port: u16,
        repr: &super::wire::Repr,
    ) -> bool {
        if self.state == State::Closed {
            return false;
        }

        // LISTEN state with ACK or RST should be passed to other sockets
        if self.state == State::Listen
            && (repr.ack_number.is_some() || repr.control == super::wire::Control::Rst)
        {
            return false;
        }

        if let Some(tuple) = &self.tuple {
            // Established connection: match on full 4-tuple
            dst_ip == tuple.local.addr
                && dst_port == tuple.local.port
                && src_ip == tuple.remote.addr
                && src_port == tuple.remote.port
        } else {
            // LISTEN state: match on local port and optional address
            let addr_ok = self.listen_endpoint.addr.0 == 0 || dst_ip == self.listen_endpoint.addr;
            addr_ok && dst_port == self.listen_endpoint.port
        }
    }

    /// Process an incoming TCP segment.
    ///
    /// Returns Some(Repr) if a response should be sent.
    pub(crate) fn process(
        &mut self,
        timestamp_ms: u64,
        src_ip: IpAddr,
        _dst_ip: IpAddr,
        repr: &Repr,
    ) -> Option<Repr<'static>> {
        // Update timers
        self.update_timers(timestamp_ms);

        match self.state {
            State::Closed => self.process_closed(repr),
            State::Listen => self.process_listen(src_ip, _dst_ip, repr),
            State::SynSent => self.process_syn_sent(repr),
            _ => self.process_established_and_beyond(timestamp_ms, repr),
        }
    }

    /// Process segment in CLOSED state.
    fn process_closed(&mut self, repr: &Repr) -> Option<Repr<'static>> {
        // Send RST for any incoming segment (except RST itself)
        if repr.control != Control::Rst {
            return Some(self.rst_reply(repr));
        }
        None
    }

    /// Process segment in LISTEN state.
    fn process_listen(
        &mut self,
        src_ip: IpAddr,
        dst_ip: IpAddr,
        repr: &Repr,
    ) -> Option<Repr<'static>> {
        if repr.control == Control::Rst {
            return None;
        }

        if repr.ack_number.is_some() {
            // Send RST
            return Some(Repr {
                src_port: repr.dst_port,
                dst_port: repr.src_port,
                control: Control::Rst,
                seq_number: repr.ack_number.unwrap(),
                ack_number: None,
                window_len: 0,
                max_seg_size: None,
                window_scale: None,
                sack_permitted: false,
                payload: &[],
            });
        }

        if repr.control == Control::Syn {
            // Accept connection - create tuple for this connection
            self.tuple = Some(Tuple {
                local: IpEndpoint::new(dst_ip, self.listen_endpoint.port),
                remote: IpEndpoint::new(src_ip, repr.src_port),
            });

            self.irs = repr.seq_number;
            self.rcv_nxt = repr.seq_number + 1;

            // Generate ISS
            self.iss = SeqNumber::new((repr.dst_port as u32) * 1000 + 54321);
            self.snd_una = self.iss;
            self.snd_nxt = self.iss + 1; // SYN consumes 1 byte
            self.remote_last_seq = self.snd_nxt; // SYN-ACK will be sent
            self.snd_wl1 = repr.seq_number;
            self.snd_wl2 = self.iss;

            // Extract options
            if let Some(mss) = repr.max_seg_size {
                self.remote_mss = mss;
            }
            self.snd_wnd = repr.window_len;

            self.state = State::SynReceived;

            // Send SYN-ACK
            return Some(Repr {
                src_port: self.listen_endpoint.port,
                dst_port: repr.src_port,
                control: Control::Syn,
                seq_number: self.iss,
                ack_number: Some(self.rcv_nxt),
                window_len: self.rcv_wnd,
                max_seg_size: Some(self.local_mss),
                window_scale: None,
                sack_permitted: false,
                payload: &[],
            });
        }

        None
    }

    /// Process segment in SYN-SENT state.
    fn process_syn_sent(&mut self, repr: &Repr) -> Option<Repr<'static>> {
        // In SYN-SENT, we have a tuple from connect()
        let tuple = self.tuple.as_ref()?;
        let local_port = tuple.local.port;
        let remote_port = tuple.remote.port;

        let acceptable_ack = if let Some(ack) = repr.ack_number {
            if ack <= self.iss || ack > self.snd_nxt {
                // Unacceptable ACK - send RST
                return Some(Repr {
                    src_port: local_port,
                    dst_port: remote_port,
                    control: Control::Rst,
                    seq_number: ack,
                    ack_number: None,
                    window_len: 0,
                    max_seg_size: None,
                    window_scale: None,
                    sack_permitted: false,
                    payload: &[],
                });
            }
            self.snd_una <= ack && ack <= self.snd_nxt
        } else {
            false
        };

        if repr.control == Control::Rst {
            if acceptable_ack {
                self.state = State::Closed;
            }
            return None;
        }

        if repr.control == Control::Syn {
            self.irs = repr.seq_number;
            self.rcv_nxt = repr.seq_number + 1;

            if let Some(ack) = repr.ack_number {
                self.snd_una = ack;
            }

            // Extract options
            if let Some(mss) = repr.max_seg_size {
                self.remote_mss = mss;
            }

            if self.snd_una > self.iss {
                // Our SYN has been ACKed - connection established
                self.state = State::Established;
                self.snd_wnd = repr.window_len;
                self.snd_wl1 = repr.seq_number;
                self.snd_wl2 = repr.ack_number.unwrap();

                // Send ACK
                return Some(Repr {
                    src_port: local_port,
                    dst_port: remote_port,
                    control: Control::None,
                    seq_number: self.snd_nxt,
                    ack_number: Some(self.rcv_nxt),
                    window_len: self.rcv_wnd,
                    max_seg_size: None,
                    window_scale: None,
                    sack_permitted: false,
                    payload: &[],
                });
            } else {
                // Simultaneous open
                self.state = State::SynReceived;
                return Some(Repr {
                    src_port: local_port,
                    dst_port: remote_port,
                    control: Control::Syn,
                    seq_number: self.iss,
                    ack_number: Some(self.rcv_nxt),
                    window_len: self.rcv_wnd,
                    max_seg_size: Some(self.local_mss),
                    window_scale: None,
                    sack_permitted: false,
                    payload: &[],
                });
            }
        }

        None
    }

    /// Process segment in established and beyond states.
    fn process_established_and_beyond(
        &mut self,
        _timestamp_ms: u64,
        repr: &Repr,
    ) -> Option<Repr<'static>> {
        // Get tuple - we should have one in these states
        let tuple = self.tuple.as_ref()?;
        let local_port = tuple.local.port;
        let remote_port = tuple.remote.port;

        // Handle SYN retransmission in SYN-RECEIVED state
        if self.state == State::SynReceived && repr.control == Control::Syn {
            // Retransmit SYN-ACK
            return Some(Repr {
                src_port: local_port,
                dst_port: remote_port,
                control: Control::Syn,
                seq_number: self.iss,
                ack_number: Some(self.rcv_nxt),
                window_len: self.rcv_wnd,
                max_seg_size: Some(self.local_mss),
                window_scale: None,
                sack_permitted: false,
                payload: &[],
            });
        }

        let seg_len = repr.payload.len() + repr.control.len();
        let acceptable = self.is_segment_acceptable(repr.seq_number, seg_len);

        if !acceptable {
            if repr.control != Control::Rst {
                return Some(self.ack_reply());
            }
            return None;
        }

        if repr.control == Control::Rst {
            self.state = State::Closed;
            return None;
        }

        if repr.control == Control::Syn {
            // SYN in established state - reset connection
            self.state = State::Closed;
            return Some(self.rst_reply(repr));
        }

        let mut send_ack = false;

        if let Some(ack) = repr.ack_number {
            match self.state {
                State::SynReceived => {
                    if self.snd_una < ack && ack <= self.snd_nxt {
                        self.snd_una = ack;
                        self.state = State::Established;
                    } else {
                        return Some(self.rst_reply(repr));
                    }
                }
                _ => {}
            }

            // Update window and acknowledge data
            if self.snd_una < ack && ack <= self.snd_nxt {
                // Remove acknowledged bytes from TX buffer
                let acked = (ack - self.snd_una) as usize;
                self.tx_buffer.dequeue_many(acked);
                self.snd_una = ack;

                // Clear retransmission timer if everything is acked
                if self.snd_una == self.snd_nxt {
                    self.retransmit_at = None;
                }

                if self.snd_wl1 < repr.seq_number
                    || (self.snd_wl1 == repr.seq_number && self.snd_wl2 <= ack)
                {
                    self.snd_wnd = repr.window_len;
                    self.snd_wl1 = repr.seq_number;
                    self.snd_wl2 = ack;
                }
            }

            // State-specific ACK processing
            match self.state {
                State::FinWait1 => {
                    if ack == self.snd_nxt && self.fin_sent {
                        self.state = State::FinWait2;
                    }
                }
                State::Closing => {
                    if ack == self.snd_nxt && self.fin_sent {
                        self.state = State::TimeWait;
                        self.timewait_at = Some(_timestamp_ms + TIME_WAIT_DURATION_MS);
                    }
                }
                State::LastAck => {
                    if ack == self.snd_nxt && self.fin_sent {
                        self.state = State::Closed;
                        return None;
                    }
                }
                _ => {}
            }
        } else if !matches!(self.state, State::SynReceived) {
            return None;
        }

        if !repr.payload.is_empty()
            && matches!(
                self.state,
                State::Established | State::FinWait1 | State::FinWait2
            )
        {
            // Check if in-order
            if repr.seq_number == self.rcv_nxt {
                // In-order data
                let written = self.rx_buffer.enqueue_slice(repr.payload);
                self.rcv_nxt += written;

                // Check assembler for more contiguous data
                let contig = self.assembler.front();
                if contig > 0 {
                    self.assembler.remove_front(contig);
                    self.rcv_nxt += contig;
                }

                send_ack = true;
            } else if repr.seq_number > self.rcv_nxt {
                // Out-of-order data - add to assembler
                let offset = (repr.seq_number - self.rcv_nxt) as usize;
                self.assembler.add(offset, repr.payload.len());
                send_ack = true;
            }

            // Update receive window
            self.rcv_wnd = (self.rx_buffer.capacity() - self.rx_buffer.len()) as u16;
        }

        if repr.control == Control::Fin {
            self.rcv_nxt = repr.seq_number + repr.payload.len() + 1;
            self.fin_received = true;
            send_ack = true;

            match self.state {
                State::SynReceived | State::Established => {
                    self.state = State::CloseWait;
                }
                State::FinWait1 => {
                    if self.snd_una == self.snd_nxt && self.fin_sent {
                        self.state = State::TimeWait;
                        self.timewait_at = Some(_timestamp_ms + TIME_WAIT_DURATION_MS);
                    } else {
                        self.state = State::Closing;
                    }
                }
                State::FinWait2 => {
                    self.state = State::TimeWait;
                    self.timewait_at = Some(_timestamp_ms + TIME_WAIT_DURATION_MS);
                }
                _ => {}
            }
        }

        if send_ack {
            Some(self.ack_reply())
        } else {
            None
        }
    }

    /// Check if segment is acceptable.
    fn is_segment_acceptable(&self, seq: SeqNumber, seg_len: usize) -> bool {
        let dominated_by_window =
            |seq: SeqNumber| self.rcv_nxt <= seq && seq < self.rcv_nxt + (self.rcv_wnd as usize);

        match (seg_len == 0, self.rcv_wnd == 0) {
            (true, true) => seq == self.rcv_nxt,
            (true, false) => dominated_by_window(seq),
            (false, true) => false,
            (false, false) => {
                let seg_end = seq + seg_len - 1;
                dominated_by_window(seq) || dominated_by_window(seg_end)
            }
        }
    }

    /// Generate an RST reply.
    fn rst_reply(&self, repr: &Repr) -> Repr<'static> {
        let seq = if repr.ack_number.is_some() {
            repr.ack_number.unwrap()
        } else {
            SeqNumber::new(0)
        };

        let ack = if repr.ack_number.is_none() {
            Some(repr.seq_number + repr.segment_len())
        } else {
            None
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

    /// Generate an ACK reply.
    fn ack_reply(&self) -> Repr<'static> {
        let (src_port, dst_port) = match &self.tuple {
            Some(t) => (t.local.port, t.remote.port),
            None => (self.listen_endpoint.port, 0),
        };
        Repr {
            src_port,
            dst_port,
            control: Control::None,
            seq_number: self.snd_nxt,
            ack_number: Some(self.rcv_nxt),
            window_len: self.rcv_wnd,
            max_seg_size: None,
            window_scale: None,
            sack_permitted: false,
            payload: &[],
        }
    }

    /// Check if there is sequence data to transmit
    /// Returns true if SYN, FIN, or data needs to be sent.
    fn seq_to_transmit(&self) -> bool {
        // Check if there's data in flight
        let data_in_flight = self.remote_last_seq != self.snd_nxt;

        // SYN needs to be sent
        if matches!(self.state, State::SynSent | State::SynReceived) && !data_in_flight {
            return true;
        }

        // FIN needs to be sent
        if matches!(self.state, State::FinWait1 | State::LastAck)
            && !self.fin_sent
            && self.tx_buffer.is_empty()
            && !data_in_flight
        {
            return true;
        }

        // Data needs to be sent
        if self.may_send() {
            let in_flight = (self.snd_nxt - self.snd_una) as usize;
            let unsent = self.tx_buffer.len().saturating_sub(in_flight);
            if unsent > 0 {
                return true;
            }
        }

        false
    }

    /// Check if there is data to send and return a Repr if so.
    pub(crate) fn dispatch(&mut self, timestamp_ms: u64) -> Option<(Repr<'static>, Vec<u8>)> {
        // Need a tuple to send anything
        let tuple = self.tuple?;

        // Update timers
        self.update_timers(timestamp_ms);

        // Check retransmission timeout
        if let Some(retransmit_at) = self.retransmit_at {
            if timestamp_ms >= retransmit_at {
                // Retransmit: reset sequence pointers
                self.snd_nxt = self.snd_una;
                self.remote_last_seq = self.snd_una;
                self.retransmit_at = Some(timestamp_ms + self.rto);
                self.rto = (self.rto * 2).min(60000); // Exponential backoff, max 60s
            }
        }

        // Check if we have anything to transmit
        if !self.seq_to_transmit() {
            return None;
        }

        // Send SYN
        if self.state == State::SynSent {
            let data_in_flight = self.remote_last_seq != self.snd_nxt;
            if !data_in_flight {
                // Set retransmit timer
                if self.retransmit_at.is_none() {
                    self.retransmit_at = Some(timestamp_ms + self.rto);
                }

                // Mark as sent
                self.snd_nxt = self.iss + 1;
                self.remote_last_seq = self.iss; // Keep at original ISS to mark as 'in flight' relative to snd_nxt

                return Some((
                    Repr {
                        src_port: tuple.local.port,
                        dst_port: tuple.remote.port,
                        control: Control::Syn,
                        seq_number: self.iss,
                        ack_number: None,
                        window_len: self.rcv_wnd,
                        max_seg_size: Some(self.local_mss),
                        window_scale: None,
                        sack_permitted: false,
                        payload: &[],
                    },
                    Vec::new(),
                ));
            }
        }

        // Send FIN
        if matches!(self.state, State::FinWait1 | State::LastAck) && !self.fin_sent {
            if self.tx_buffer.is_empty() {
                self.fin_sent = true;
                let seq = self.snd_nxt;
                self.snd_nxt += 1; // FIN consumes 1 byte
                self.remote_last_seq = self.snd_nxt;

                return Some((
                    Repr {
                        src_port: tuple.local.port,
                        dst_port: tuple.remote.port,
                        control: Control::Fin,
                        seq_number: seq,
                        ack_number: Some(self.rcv_nxt),
                        window_len: self.rcv_wnd,
                        max_seg_size: None,
                        window_scale: None,
                        sack_permitted: false,
                        payload: &[],
                    },
                    Vec::new(),
                ));
            }
        }

        // Send data
        if self.may_send() {
            let in_flight = (self.snd_nxt - self.snd_una) as usize;
            let window_available = (self.snd_wnd as usize).saturating_sub(in_flight);

            // Calculate unsent data (buffer contains unacked + unsent)
            let unsent = self.tx_buffer.len().saturating_sub(in_flight);

            if window_available > 0 && unsent > 0 {
                let to_send = core::cmp::min(
                    unsent,
                    core::cmp::min(self.remote_mss as usize, window_available),
                );

                if to_send > 0 {
                    let mut payload = vec![0u8; to_send];
                    // Peek from offset past already-sent (but unacked) data
                    self.tx_buffer.peek_slice(in_flight, &mut payload);

                    let seq = self.snd_nxt;
                    self.snd_nxt += to_send;
                    self.remote_last_seq = self.snd_nxt;

                    // Set retransmission timer
                    if self.retransmit_at.is_none() {
                        self.retransmit_at = Some(timestamp_ms + self.rto);
                    }

                    return Some((
                        Repr {
                            src_port: tuple.local.port,
                            dst_port: tuple.remote.port,
                            control: Control::None,
                            seq_number: seq,
                            ack_number: Some(self.rcv_nxt),
                            window_len: self.rcv_wnd,
                            max_seg_size: None,
                            window_scale: None,
                            sack_permitted: false,
                            payload: &[],
                        },
                        payload,
                    ));
                }
            }
        }

        None
    }

    fn update_timers(&mut self, timestamp_ms: u64) {
        // Check TIME-WAIT timeout
        if let Some(timewait_at) = self.timewait_at {
            if timestamp_ms >= timewait_at && self.state == State::TimeWait {
                self.state = State::Closed;
            }
        }
    }
}

impl Default for TcpSocket {
    fn default() -> Self {
        panic!("TcpSocket::default() should not be called - use new() with storage");
    }
}
