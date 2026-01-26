use crate::error::{Error, Result};
use crate::net::ip::{self, IpAddr};
use crate::net::socket::{SocketHandle, SocketSet};
use crate::spinlock::Mutex;
use alloc::{collections::VecDeque, vec::Vec};
use core::cmp;
use core::fmt;
use core::sync::atomic::{AtomicU16, Ordering};

mod wire {
    use super::IpAddr;
    use crate::error::{Error, Result};
    use crate::net::util::{read_u16, write_u16};

    pub mod field {
        pub type Field = core::ops::Range<usize>;

        pub const SRC_PORT: Field = 0..2;
        pub const DST_PORT: Field = 2..4;
        pub const SEQ_NUM: Field = 4..8;
        pub const ACK_NUM: Field = 8..12;
        pub const FLAGS: Field = 12..14;
        pub const WIN_SIZE: Field = 14..16;
        pub const CHECKSUM: Field = 16..18;
        pub const URGENT: Field = 18..20;

        pub const FLG_FIN: u8 = 0x01;
        pub const FLG_SYN: u8 = 0x02;
        pub const FLG_RST: u8 = 0x04;
        pub const FLG_PSH: u8 = 0x08;
        pub const FLG_ACK: u8 = 0x10;
    }

    pub const HEADER_LEN: usize = field::URGENT.end;
    pub const PROTOCOL_TCP: u8 = 6;

    pub struct Packet<'a> {
        buffer: &'a [u8],
    }
    impl<'a> Packet<'a> {
        pub fn new_checked(buffer: &'a [u8]) -> Result<Self> {
            if buffer.len() < HEADER_LEN {
                return Err(Error::PacketTooShort);
            }
            let packet = Self { buffer };
            let header_len = packet.header_len();
            if header_len < HEADER_LEN || header_len > buffer.len() {
                return Err(Error::InvalidHeaderLen);
            }
            Ok(packet)
        }

        pub fn header_len(&self) -> usize {
            ((self.buffer[field::FLAGS.start] >> 4) as usize) * 4
        }

        pub fn src_port(&self) -> u16 {
            read_u16(&self.buffer[field::SRC_PORT])
        }

        pub fn dst_port(&self) -> u16 {
            read_u16(&self.buffer[field::DST_PORT])
        }

        pub fn seq_number(&self) -> u32 {
            read_u32(&self.buffer[field::SEQ_NUM])
        }

        pub fn ack_number(&self) -> u32 {
            read_u32(&self.buffer[field::ACK_NUM])
        }

        pub fn flags(&self) -> u8 {
            self.buffer[field::FLAGS.start + 1]
        }

        pub fn window_len(&self) -> u16 {
            read_u16(&self.buffer[field::WIN_SIZE])
        }

        pub fn payload(&self) -> &'a [u8] {
            let header_len = self.header_len();
            &self.buffer[header_len..]
        }

        pub fn verify_checksum(&self, src: IpAddr, dst: IpAddr) -> bool {
            checksum_sum(src, dst, self.buffer) == 0xffff
        }
    }

    pub struct PacketMut<'a> {
        buffer: &'a mut [u8],
    }
    impl<'a> PacketMut<'a> {
        pub fn new_unchecked(buffer: &'a mut [u8]) -> Self {
            Self { buffer }
        }

        pub fn set_src_port(&mut self, value: u16) {
            write_u16(&mut self.buffer[field::SRC_PORT], value);
        }

        pub fn set_dst_port(&mut self, value: u16) {
            write_u16(&mut self.buffer[field::DST_PORT], value);
        }

        pub fn set_seq_number(&mut self, value: u32) {
            write_u32(&mut self.buffer[field::SEQ_NUM], value);
        }

        pub fn set_ack_number(&mut self, value: u32) {
            write_u32(&mut self.buffer[field::ACK_NUM], value);
        }

        pub fn set_header_len(&mut self, header_len: usize) {
            self.buffer[field::FLAGS.start] = ((header_len / 4) as u8) << 4;
        }

        pub fn set_flags(&mut self, flags: u8) {
            self.buffer[field::FLAGS.start + 1] = flags;
        }

        pub fn set_window_len(&mut self, value: u16) {
            write_u16(&mut self.buffer[field::WIN_SIZE], value);
        }

        pub fn set_checksum(&mut self, value: u16) {
            write_u16(&mut self.buffer[field::CHECKSUM], value);
        }

        pub fn set_urg_ptr(&mut self, value: u16) {
            write_u16(&mut self.buffer[field::URGENT], value);
        }

        pub fn payload_mut(&mut self) -> &mut [u8] {
            &mut self.buffer[HEADER_LEN..]
        }

        pub fn fill_checksum(&mut self, src: IpAddr, dst: IpAddr) {
            self.set_checksum(0);
            let sum = checksum_sum(src, dst, self.buffer);
            let checksum = (!sum) as u16;
            self.set_checksum(checksum);
        }
    }

    fn read_u32(data: &[u8]) -> u32 {
        u32::from_be_bytes([data[0], data[1], data[2], data[3]])
    }

    fn write_u32(data: &mut [u8], value: u32) {
        data[..4].copy_from_slice(&value.to_be_bytes());
    }

    fn checksum_sum(src: IpAddr, dst: IpAddr, segment: &[u8]) -> u32 {
        let mut sum: u32 = 0;
        let src_bytes = src.0.to_be_bytes();
        let dst_bytes = dst.0.to_be_bytes();

        sum = checksum_acc(&src_bytes, sum);
        sum = checksum_acc(&dst_bytes, sum);
        sum = checksum_acc(&[0, 6], sum);
        let len = (segment.len() as u16).to_be_bytes();
        sum = checksum_acc(&len, sum);
        sum = checksum_acc(segment, sum);

        while (sum >> 16) != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        sum
    }

    fn checksum_acc(data: &[u8], mut sum: u32) -> u32 {
        let mut i = 0;
        while i + 1 < data.len() {
            let word = u16::from_be_bytes([data[i], data[i + 1]]);
            sum += word as u32;
            i += 2;
        }
        if i < data.len() {
            sum += (data[i] as u32) << 8;
        }
        while (sum >> 16) != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        sum
    }
}

/// [RFC 9293](https://datatracker.ietf.org/doc/html/rfc9293#name-state-machine-overview)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct IpEndpoint {
    pub addr: IpAddr,
    pub port: u16,
}

impl IpEndpoint {
    pub const fn new(addr: IpAddr, port: u16) -> Self {
        Self { addr, port }
    }

    pub const fn unspecified() -> Self {
        Self {
            addr: IpAddr(0),
            port: 0,
        }
    }

    pub fn is_unspecified(&self) -> bool {
        self.addr.0 == 0 && self.port == 0
    }
}

struct RetransmitEntry {
    first_at: u64,
    last_at: u64,
    rto: u64,
    seq: u32,
    flags: u8,
    payload: Vec<u8>,
}

struct SendRequest {
    seq: u32,
    ack: u32,
    flags: u8,
    wnd: u16,
    payload: Vec<u8>,
    local: IpEndpoint,
    foreign: IpEndpoint,
}

pub struct Socket {
    state: State,
    local: IpEndpoint,
    foreign: IpEndpoint,

    snd_nxt: u32,
    snd_una: u32,
    snd_wnd: u16,
    snd_wl1: u32,
    snd_wl2: u32,

    rcv_nxt: u32,
    rcv_wnd: u16,

    iss: u32,
    irs: u32,

    mss: u16,

    rx_buf: VecDeque<u8>,
    rx_capacity: usize,
    tx_buf: VecDeque<u8>,
    tx_capacity: usize,

    retransmit: VecDeque<RetransmitEntry>,
    pending: VecDeque<SendRequest>,

    timewait_deadline: Option<u64>,

    parent: Option<usize>,
    backlog: VecDeque<usize>,
    accept_ready: bool,
}

impl Socket {
    const RX_BUFFER_SIZE: usize = 8192;
    const TX_BUFFER_SIZE: usize = 8192;
    const DEFAULT_MSS: usize = 1460;
    const DEFAULT_RTO_MS: u64 = 200;
    const RETRANSMIT_DEADLINE_MS: u64 = 12_000;
    const TIMEWAIT_MS: u64 = 30_000;

    pub fn new(rx_capacity: usize, tx_capacity: usize) -> Self {
        Self {
            state: State::Closed,
            local: IpEndpoint::unspecified(),
            foreign: IpEndpoint::unspecified(),
            snd_nxt: 0,
            snd_una: 0,
            snd_wnd: 0,
            snd_wl1: 0,
            snd_wl2: 0,
            rcv_nxt: 0,
            rcv_wnd: 0,
            iss: 0,
            irs: 0,
            mss: Self::DEFAULT_MSS as u16,
            rx_buf: VecDeque::with_capacity(rx_capacity),
            rx_capacity,
            tx_buf: VecDeque::with_capacity(tx_capacity),
            tx_capacity,
            retransmit: VecDeque::new(),
            pending: VecDeque::new(),
            timewait_deadline: None,
            parent: None,
            backlog: VecDeque::new(),
            accept_ready: false,
        }
    }

    pub fn state(&self) -> State {
        self.state
    }

    pub fn local_endpoint(&self) -> IpEndpoint {
        self.local
    }

    pub fn remote_endpoint(&self) -> IpEndpoint {
        self.foreign
    }

    pub fn is_listening(&self) -> bool {
        self.state == State::Listen
    }

    pub fn has_pending_connection(&self) -> bool {
        !self.backlog.is_empty()
    }

    pub fn may_recv(&self) -> bool {
        self.can_recv() && !self.rx_buf.is_empty()
    }

    pub fn listen(&mut self, local: IpEndpoint) -> Result<()> {
        if self.state != State::Closed {
            return Err(Error::SocketAlreadyOpen);
        }
        self.local = local;
        self.state = State::Listen;
        Ok(())
    }

    pub fn connect(&mut self, local: IpEndpoint, remote: IpEndpoint) -> Result<()> {
        if self.state != State::Closed {
            return Err(Error::SocketAlreadyOpen);
        }

        let mut local_ep = local;
        if local_ep.addr.0 == 0 {
            local_ep.addr = ip::get_source_address(remote.addr).ok_or(Error::Unaddressable)?;
        }
        if local_ep.port == 0 {
            local_ep.port = next_ephemeral_port();
        }

        self.local = local_ep;
        self.foreign = remote;
        self.rcv_wnd = self.rx_capacity as u16;
        self.iss = initial_iss(local_ep.port);
        self.snd_una = self.iss;
        self.snd_nxt = self.iss + 1;
        self.state = State::SynSent;
        let _ = self.output(wire::field::FLG_SYN, &[]);
        Ok(())
    }

    pub fn send_slice(&mut self, data: &[u8]) -> Result<usize> {
        if !self.can_send() {
            return Err(Error::SocketNotOpen);
        }
        let available = self.tx_capacity.saturating_sub(self.tx_buf.len());
        let to_write = cmp::min(data.len(), available);
        if to_write == 0 {
            return Err(Error::BufferFull);
        }
        self.tx_buf.extend(data[..to_write].iter().copied());
        self.flush_tx(get_time_ms());
        Ok(to_write)
    }

    pub fn recv_slice(&mut self, buf: &mut [u8]) -> Result<usize> {
        if !self.can_recv() {
            return Err(Error::SocketNotOpen);
        }
        let to_read = cmp::min(buf.len(), self.rx_buf.len());
        for byte in buf.iter_mut().take(to_read) {
            if let Some(b) = self.rx_buf.pop_front() {
                *byte = b;
            }
        }
        self.rcv_wnd = (self.rx_capacity - self.rx_buf.len()) as u16;
        Ok(to_read)
    }

    pub fn close(&mut self) {
        match self.state {
            State::Closed => {}
            State::Listen | State::SynSent => {
                self.state = State::Closed;
            }
            State::SynReceived | State::Established => {
                let _ = self.output(wire::field::FLG_ACK | wire::field::FLG_FIN, &[]);
                self.snd_nxt = self.snd_nxt.wrapping_add(1);
                self.state = State::FinWait1;
            }
            State::CloseWait => {
                let _ = self.output(wire::field::FLG_ACK | wire::field::FLG_FIN, &[]);
                self.snd_nxt = self.snd_nxt.wrapping_add(1);
                self.state = State::LastAck;
            }
            _ => {}
        }
    }

    fn can_recv(&self) -> bool {
        matches!(
            self.state,
            State::Established | State::FinWait1 | State::FinWait2 | State::CloseWait
        )
    }

    fn can_send(&self) -> bool {
        matches!(self.state, State::Established | State::CloseWait)
    }

    fn drain_pending(&mut self, out: &mut Vec<SendRequest>) {
        while let Some(req) = self.pending.pop_front() {
            out.push(req);
        }
    }

    fn handle_segment(
        &mut self,
        seg_seq: u32,
        seg_ack: u32,
        seg_len: u32,
        seg_wnd: u16,
        flags: u8,
        payload: &[u8],
    ) {
        fn seq_lt(a: u32, b: u32) -> bool {
            (a.wrapping_sub(b) as i32) < 0
        }

        fn seq_le(a: u32, b: u32) -> bool {
            (a.wrapping_sub(b) as i32) <= 0
        }

        fn seq_between(start: u32, seq: u32, end: u32) -> bool {
            !seq_lt(seq, start) && seq_lt(seq, end)
        }

        let flag_syn = (flags & wire::field::FLG_SYN) != 0;
        let flag_ack = (flags & wire::field::FLG_ACK) != 0;
        let flag_fin = (flags & wire::field::FLG_FIN) != 0;
        let flag_rst = (flags & wire::field::FLG_RST) != 0;

        let send_rst_for_segment =
            |this: &mut Socket, seg_seq: u32, seg_ack: u32, seg_len: u32, ack_present: bool| {
                if ack_present {
                    this.pending.push_back(SendRequest {
                        seq: seg_ack,
                        ack: 0,
                        flags: wire::field::FLG_RST,
                        wnd: 0,
                        payload: Vec::new(),
                        local: this.local,
                        foreign: this.foreign,
                    });
                } else {
                    this.pending.push_back(SendRequest {
                        seq: 0,
                        ack: seg_seq.wrapping_add(seg_len),
                        flags: wire::field::FLG_RST | wire::field::FLG_ACK,
                        wnd: 0,
                        payload: Vec::new(),
                        local: this.local,
                        foreign: this.foreign,
                    });
                }
            };

        if self.state == State::SynSent {
            if flag_ack {
                if seq_le(seg_ack, self.iss) || seq_lt(self.snd_nxt, seg_ack) {
                    send_rst_for_segment(self, seg_seq, seg_ack, seg_len, true);
                    return;
                }
            }

            let acceptable_ack =
                flag_ack && seq_le(self.snd_una, seg_ack) && seq_le(seg_ack, self.snd_nxt);

            if flag_rst {
                if acceptable_ack {
                    self.state = State::Closed;
                }
                return;
            }

            if flag_syn {
                self.irs = seg_seq;
                self.rcv_nxt = seg_seq.wrapping_add(1);

                if flag_ack {
                    self.snd_una = seg_ack;
                    self.cleanup_retransmit();
                    self.snd_wnd = seg_wnd;
                    self.snd_wl1 = seg_seq;
                    self.snd_wl2 = seg_ack;
                }

                if flag_ack && seq_lt(self.iss, self.snd_una) {
                    self.state = State::Established;
                    let _ = self.output(wire::field::FLG_ACK, &[]);
                } else {
                    self.state = State::SynReceived;
                    let _ = self.output(wire::field::FLG_SYN | wire::field::FLG_ACK, &[]);
                }
            }

            return;
        }

        if self.state == State::SynReceived && flag_syn {
            let _ = self.output(wire::field::FLG_SYN | wire::field::FLG_ACK, &[]);
            return;
        }

        let acceptable = if seg_len == 0 {
            if self.rcv_wnd == 0 {
                seg_seq == self.rcv_nxt
            } else {
                let end = self.rcv_nxt.wrapping_add(self.rcv_wnd as u32);
                seq_between(self.rcv_nxt, seg_seq, end)
            }
        } else if self.rcv_wnd == 0 {
            false
        } else {
            let end = self.rcv_nxt.wrapping_add(self.rcv_wnd as u32);
            let seg_end = seg_seq.wrapping_add(seg_len - 1);
            seq_between(self.rcv_nxt, seg_seq, end) || seq_between(self.rcv_nxt, seg_end, end)
        };

        if !acceptable {
            if !flag_rst {
                let _ = self.output(wire::field::FLG_ACK, &[]);
            }
            return;
        }

        if flag_rst {
            self.state = State::Closed;
            return;
        }

        if flag_syn {
            self.state = State::Closed;
            send_rst_for_segment(self, seg_seq, seg_ack, seg_len, flag_ack);
            return;
        }

        if flag_ack {
            if self.state == State::SynReceived {
                if seq_lt(self.snd_una, seg_ack) && seq_le(seg_ack, self.snd_nxt) {
                    self.snd_una = seg_ack;
                    self.cleanup_retransmit();
                    self.snd_wnd = seg_wnd;
                    self.snd_wl1 = seg_seq;
                    self.snd_wl2 = seg_ack;
                    self.state = State::Established;
                    if self.parent.is_some() {
                        self.accept_ready = true;
                    }
                } else {
                    send_rst_for_segment(self, seg_seq, seg_ack, seg_len, true);
                    return;
                }
            }

            if seq_lt(self.snd_una, seg_ack) && seq_le(seg_ack, self.snd_nxt) {
                self.snd_una = seg_ack;
                self.cleanup_retransmit();

                if seq_lt(self.snd_wl1, seg_seq)
                    || (self.snd_wl1 == seg_seq && seq_le(self.snd_wl2, seg_ack))
                {
                    self.snd_wnd = seg_wnd;
                    self.snd_wl1 = seg_seq;
                    self.snd_wl2 = seg_ack;
                }

                match self.state {
                    State::FinWait1 => {
                        if self.snd_una == self.snd_nxt {
                            self.state = State::FinWait2;
                        }
                    }
                    State::Closing => {
                        if self.snd_una == self.snd_nxt {
                            self.state = State::TimeWait;
                            self.timewait_deadline =
                                Some(get_time_ms().saturating_add(Self::TIMEWAIT_MS));
                        }
                    }
                    State::LastAck => {
                        if self.snd_una == self.snd_nxt {
                            self.state = State::Closed;
                            return;
                        }
                    }
                    _ => {}
                }
            }
        } else if self.state != State::SynReceived {
            return;
        }

        let mut send_ack = false;

        if !payload.is_empty()
            && matches!(
                self.state,
                State::Established | State::FinWait1 | State::FinWait2
            )
        {
            if seg_seq == self.rcv_nxt {
                let space = self.rx_capacity.saturating_sub(self.rx_buf.len());
                let to_copy = cmp::min(space, payload.len());
                for b in payload.iter().take(to_copy) {
                    self.rx_buf.push_back(*b);
                }
                self.rcv_nxt = self.rcv_nxt.wrapping_add(to_copy as u32);
                send_ack = true;
            } else {
                send_ack = true;
            }

            self.rcv_wnd = (self.rx_capacity - self.rx_buf.len()) as u16;
        }

        if flag_fin {
            let fin_end = seg_seq.wrapping_add(payload.len() as u32).wrapping_add(1);
            if seq_lt(self.rcv_nxt, fin_end) {
                self.rcv_nxt = fin_end;
            }
            send_ack = true;

            match self.state {
                State::SynReceived | State::Established => {
                    self.state = State::CloseWait;
                }
                State::FinWait1 => {
                    if self.snd_una == self.snd_nxt {
                        self.state = State::TimeWait;
                        self.timewait_deadline =
                            Some(get_time_ms().saturating_add(Self::TIMEWAIT_MS));
                    } else {
                        self.state = State::Closing;
                    }
                }
                State::FinWait2 => {
                    self.state = State::TimeWait;
                    self.timewait_deadline = Some(get_time_ms().saturating_add(Self::TIMEWAIT_MS));
                }
                State::TimeWait => {
                    self.timewait_deadline = Some(get_time_ms().saturating_add(Self::TIMEWAIT_MS));
                }
                _ => {}
            }
        }

        if send_ack {
            let _ = self.output(wire::field::FLG_ACK, &[]);
        }
    }

    fn output(&mut self, flags: u8, payload: &[u8]) -> Result<()> {
        let mut seq = self.snd_nxt;
        if (flags & wire::field::FLG_SYN) != 0 {
            seq = self.iss;
        }
        let payload_vec = payload.to_vec();
        if (flags & (wire::field::FLG_SYN | wire::field::FLG_FIN)) != 0 || !payload.is_empty() {
            self.retransmit.push_back(RetransmitEntry {
                first_at: get_time_ms(),
                last_at: get_time_ms(),
                rto: Self::DEFAULT_RTO_MS,
                seq,
                flags,
                payload: payload_vec.clone(),
            });
        }
        self.pending.push_back(SendRequest {
            seq,
            ack: self.rcv_nxt,
            flags,
            wnd: self.rcv_wnd,
            payload: payload_vec,
            local: self.local,
            foreign: self.foreign,
        });
        Ok(())
    }

    fn cleanup_retransmit(&mut self) {
        while let Some(entry) = self.retransmit.front() {
            if entry.seq >= self.snd_una {
                break;
            }
            self.retransmit.pop_front();
        }
    }

    fn flush_tx(&mut self, _now: u64) {
        if !self.can_send() {
            return;
        }
        let in_flight = self.snd_nxt.wrapping_sub(self.snd_una);
        let mut window_available = self.snd_wnd as u32;
        if window_available > in_flight {
            window_available -= in_flight;
        } else {
            window_available = 0;
        }
        while window_available > 0 && !self.tx_buf.is_empty() {
            let mss = self.mss as usize;
            let to_send = cmp::min(mss, cmp::min(window_available as usize, self.tx_buf.len()));
            let mut payload = Vec::with_capacity(to_send);
            for _ in 0..to_send {
                if let Some(b) = self.tx_buf.pop_front() {
                    payload.push(b);
                }
            }
            let _ = self.output(wire::field::FLG_ACK | wire::field::FLG_PSH, &payload);
            self.snd_nxt = self.snd_nxt.wrapping_add(to_send as u32);
            window_available = window_available.saturating_sub(to_send as u32);
        }
    }

    fn poll_timewait(&mut self, now: u64) {
        if let Some(deadline) = self.timewait_deadline {
            if now >= deadline && self.state == State::TimeWait {
                self.state = State::Closed;
                self.timewait_deadline = None;
            }
        }
    }

    fn poll_retransmit(&mut self, now: u64) {
        for entry in self.retransmit.iter_mut() {
            if now.saturating_sub(entry.first_at) >= Self::RETRANSMIT_DEADLINE_MS {
                self.state = State::Closed;
                return;
            }
            if now.saturating_sub(entry.last_at) >= entry.rto {
                self.pending.push_back(SendRequest {
                    seq: entry.seq,
                    ack: self.rcv_nxt,
                    flags: entry.flags,
                    wnd: self.rcv_wnd,
                    payload: entry.payload.clone(),
                    local: self.local,
                    foreign: self.foreign,
                });
                entry.last_at = now;
                entry.rto = entry.rto.saturating_mul(2);
            }
        }
    }

    fn matches_established(&self, local: &IpEndpoint, foreign: &IpEndpoint) -> bool {
        if self.state == State::Closed {
            return false;
        }
        self.local.addr == local.addr
            && self.local.port == local.port
            && self.foreign.addr == foreign.addr
            && self.foreign.port == foreign.port
    }

    fn matches_listen(&self, local: &IpEndpoint) -> bool {
        if self.state != State::Listen {
            return false;
        }
        let addr_ok = self.local.addr.0 == 0 || self.local.addr == local.addr;
        let port_ok = self.local.port == 0 || self.local.port == local.port;
        addr_ok && port_ok
    }
}

pub struct Tcp {
    sockets: Mutex<SocketSet<Socket>>,
    next_ephemeral_port: AtomicU16,
}

impl Tcp {
    const SOCKET_CAPACITY: usize = 16;
    const EPHEMERAL_PORT_MIN: u16 = 49152;
    const EPHEMERAL_PORT_MAX: u16 = 65535;

    const fn new() -> Self {
        Self {
            sockets: Mutex::new(SocketSet::new(Self::SOCKET_CAPACITY), "tcp_sockets"),
            next_ephemeral_port: AtomicU16::new(Self::EPHEMERAL_PORT_MIN),
        }
    }

    pub fn socket_alloc(&self) -> Result<usize> {
        let mut sockets = self.sockets.lock();
        let socket = Socket::new(Socket::RX_BUFFER_SIZE, Socket::TX_BUFFER_SIZE);
        let handle = sockets.alloc(socket)?;
        Ok(handle.index())
    }

    pub fn socket_free(&self, index: usize) -> Result<()> {
        let mut sockets = self.sockets.lock();
        sockets.free(SocketHandle::new(index))
    }

    pub fn socket_get_mut<R, F>(&self, index: usize, f: F) -> Result<R>
    where
        F: FnOnce(&mut Socket) -> R,
    {
        let mut sockets = self.sockets.lock();
        let socket = sockets.get_mut(SocketHandle::new(index))?;
        Ok(f(socket))
    }

    pub fn socket_get<R, F>(&self, index: usize, f: F) -> Result<R>
    where
        F: FnOnce(&Socket) -> R,
    {
        let sockets = self.sockets.lock();
        let socket = sockets.get(SocketHandle::new(index))?;
        Ok(f(socket))
    }

    pub fn socket_accept(&self, listen_index: usize) -> Result<usize> {
        let mut sockets = self.sockets.lock();
        let listen_socket = sockets.get_mut(SocketHandle::new(listen_index))?;

        let child_index = listen_socket.backlog.pop_front().ok_or(Error::WouldBlock)?;

        let child_socket = sockets.get_mut(SocketHandle::new(child_index))?;
        child_socket.parent = None;

        Ok(child_index)
    }

    pub fn input(&self, src_ip: IpAddr, dst_ip: IpAddr, data: &[u8]) -> Result<()> {
        crate::trace!(
            TCP,
            "[tcp] input: {} bytes from {:?}",
            data.len(),
            src_ip.to_bytes()
        );

        let packet = wire::Packet::new_checked(data)?;
        if !packet.verify_checksum(src_ip, dst_ip) {
            return Err(Error::ChecksumError);
        }

        crate::trace!(
            TCP,
            "[tcp] packet: sport={} dport={} seq={} ack={} flags=0x{:02x}",
            packet.src_port(),
            packet.dst_port(),
            packet.seq_number(),
            packet.ack_number(),
            packet.flags()
        );

        let seg_seq = packet.seq_number();
        let seg_ack = packet.ack_number();
        let flags = packet.flags();
        let seg_wnd = packet.window_len();
        let payload = packet.payload();

        let mut seg_len = payload.len() as u32;
        if (flags & wire::field::FLG_SYN) != 0 {
            seg_len += 1;
        }
        if (flags & wire::field::FLG_FIN) != 0 {
            seg_len += 1;
        }

        let local = IpEndpoint::new(dst_ip, packet.dst_port());
        let foreign = IpEndpoint::new(src_ip, packet.src_port());

        let mut sends = Vec::new();
        {
            let mut sockets = self.sockets.lock();

            let (established_idx, listen_idx) = self.find_sockets(&sockets, &local, &foreign);

            if let Some(index) = established_idx {
                self.handle_on_socket(
                    &mut sockets,
                    index,
                    seg_seq,
                    seg_ack,
                    seg_len,
                    seg_wnd,
                    flags,
                    payload,
                    &mut sends,
                );
            } else if let Some(index) = listen_idx {
                self.handle_on_listen(
                    &mut sockets,
                    index,
                    &local,
                    &foreign,
                    seg_seq,
                    seg_len,
                    flags,
                    &mut sends,
                )?;
            } else {
                self.send_rst_response(
                    &local, &foreign, seg_seq, seg_ack, seg_len, flags, &mut sends,
                );
            }
        }

        for req in sends {
            self.output_segment(&req)?;
        }

        Ok(())
    }

    pub fn poll(&self) -> Result<()> {
        let now = get_time_ms();
        let mut sends = Vec::new();

        {
            let mut sockets = self.sockets.lock();
            for (_, socket) in sockets.iter_mut() {
                socket.poll_timewait(now);
                socket.poll_retransmit(now);
                socket.flush_tx(now);
                socket.drain_pending(&mut sends);
            }
        }

        for req in sends {
            self.output_segment(&req)?;
        }

        Ok(())
    }

    fn next_ephemeral_port(&self) -> u16 {
        let mut port = self.next_ephemeral_port.fetch_add(1, Ordering::Relaxed);
        if port < Self::EPHEMERAL_PORT_MIN || port > Self::EPHEMERAL_PORT_MAX {
            self.next_ephemeral_port
                .store(Self::EPHEMERAL_PORT_MIN, Ordering::Relaxed);
            port = Self::EPHEMERAL_PORT_MIN;
        }
        port
    }

    fn find_sockets(
        &self,
        sockets: &SocketSet<Socket>,
        local: &IpEndpoint,
        foreign: &IpEndpoint,
    ) -> (Option<usize>, Option<usize>) {
        let mut established_idx = None;
        let mut listen_idx = None;

        for (handle, socket) in sockets.iter() {
            if socket.matches_established(local, foreign) {
                established_idx = Some(handle.index());
                break;
            }
            if socket.matches_listen(local) {
                listen_idx = Some(handle.index());
            }
        }

        (established_idx, listen_idx)
    }

    fn handle_on_socket(
        &self,
        sockets: &mut SocketSet<Socket>,
        index: usize,
        seg_seq: u32,
        seg_ack: u32,
        seg_len: u32,
        seg_wnd: u16,
        flags: u8,
        payload: &[u8],
        sends: &mut Vec<SendRequest>,
    ) {
        let socket = sockets.get_mut(SocketHandle::new(index)).unwrap();
        socket.handle_segment(seg_seq, seg_ack, seg_len, seg_wnd, flags, payload);
        socket.drain_pending(sends);

        if socket.accept_ready {
            socket.accept_ready = false;
            if let Some(parent_idx) = socket.parent {
                let parent = sockets.get_mut(SocketHandle::new(parent_idx)).unwrap();
                parent.backlog.push_back(index);
            }
        }
    }

    fn handle_on_listen(
        &self,
        sockets: &mut SocketSet<Socket>,
        listen_index: usize,
        local: &IpEndpoint,
        foreign: &IpEndpoint,
        seg_seq: u32,
        _seg_len: u32,
        flags: u8,
        sends: &mut Vec<SendRequest>,
    ) -> Result<()> {
        if (flags & wire::field::FLG_RST) != 0 {
            return Ok(());
        }

        if (flags & wire::field::FLG_ACK) != 0 {
            sends.push(SendRequest {
                seq: seg_seq,
                ack: 0,
                flags: wire::field::FLG_RST,
                wnd: 0,
                payload: Vec::new(),
                local: *local,
                foreign: *foreign,
            });
            return Ok(());
        }

        if (flags & wire::field::FLG_SYN) != 0 {
            let mut child = Socket::new(Socket::RX_BUFFER_SIZE, Socket::TX_BUFFER_SIZE);
            child.parent = Some(listen_index);
            child.local = *local;
            child.foreign = *foreign;
            child.rcv_wnd = child.rx_capacity as u16;
            child.rcv_nxt = seg_seq.wrapping_add(1);
            child.irs = seg_seq;
            child.iss = initial_iss(local.port);
            child.snd_una = child.iss;
            child.snd_nxt = child.iss + 1;
            child.state = State::SynReceived;

            let handle = sockets.alloc(child)?;
            let child = sockets.get_mut(handle).unwrap();
            let _ = child.output(wire::field::FLG_SYN | wire::field::FLG_ACK, &[]);
            child.drain_pending(sends);
        }

        Ok(())
    }

    fn send_rst_response(
        &self,
        local: &IpEndpoint,
        foreign: &IpEndpoint,
        seg_seq: u32,
        seg_ack: u32,
        seg_len: u32,
        flags: u8,
        sends: &mut Vec<SendRequest>,
    ) {
        if (flags & wire::field::FLG_RST) != 0 {
            return;
        }

        if (flags & wire::field::FLG_ACK) == 0 {
            sends.push(SendRequest {
                seq: 0,
                ack: seg_seq.wrapping_add(seg_len),
                flags: wire::field::FLG_RST | wire::field::FLG_ACK,
                wnd: 0,
                payload: Vec::new(),
                local: *local,
                foreign: *foreign,
            });
        } else {
            sends.push(SendRequest {
                seq: seg_ack,
                ack: 0,
                flags: wire::field::FLG_RST,
                wnd: 0,
                payload: Vec::new(),
                local: *local,
                foreign: *foreign,
            });
        }
    }

    fn output_segment(&self, req: &SendRequest) -> Result<()> {
        let total_len = wire::HEADER_LEN + req.payload.len();
        let mut buf = alloc::vec![0u8; total_len];

        {
            let mut packet = wire::PacketMut::new_unchecked(&mut buf);
            packet.set_src_port(req.local.port);
            packet.set_dst_port(req.foreign.port);
            packet.set_seq_number(req.seq);
            packet.set_ack_number(req.ack);
            packet.set_header_len(wire::HEADER_LEN);
            packet.set_flags(req.flags);
            packet.set_window_len(req.wnd);
            packet.set_checksum(0);
            packet.set_urg_ptr(0);
            if !req.payload.is_empty() {
                packet.payload_mut().copy_from_slice(&req.payload);
            }
            packet.fill_checksum(req.local.addr, req.foreign.addr);
        }

        ip::output_route(req.foreign.addr, wire::PROTOCOL_TCP, &buf)?;
        Ok(())
    }
}

static TCP: Tcp = Tcp::new();

pub fn socket_alloc() -> Result<usize> {
    TCP.socket_alloc()
}

pub fn socket_free(index: usize) -> Result<()> {
    TCP.socket_free(index)
}

pub fn socket_get_mut<R, F>(index: usize, f: F) -> Result<R>
where
    F: FnOnce(&mut Socket) -> R,
{
    TCP.socket_get_mut(index, f)
}

pub fn socket_get<R, F>(index: usize, f: F) -> Result<R>
where
    F: FnOnce(&Socket) -> R,
{
    TCP.socket_get(index, f)
}

pub fn socket_accept(listen_index: usize) -> Result<usize> {
    TCP.socket_accept(listen_index)
}

pub fn input(src_ip: IpAddr, dst_ip: IpAddr, data: &[u8]) -> Result<()> {
    TCP.input(src_ip, dst_ip, data)
}

pub fn poll() -> Result<()> {
    TCP.poll()
}

fn get_time_ms() -> u64 {
    let ticks = crate::trap::TICKS.lock();
    (*ticks as u64) * (crate::param::TICK_MS as u64)
}

fn next_ephemeral_port() -> u16 {
    TCP.next_ephemeral_port()
}

fn initial_iss(port: u16) -> u32 {
    (port as u32).wrapping_mul(1000).wrapping_add(12345)
}

#[cfg(test)]
mod tests {
    use super::*;

    mod wire_tests {
        use super::*;

        #[test_case]
        fn test_packet_parse_valid() {
            let data = [
                0x00, 0x50, // src port = 80
                0x04, 0xd2, // dst port = 1234
                0x00, 0x00, 0x03, 0xe8, // seq = 1000
                0x00, 0x00, 0x07, 0xd0, // ack = 2000
                0x50, 0x12, // data offset=5, flags=SYN+ACK
                0x20, 0x00, // window = 8192
                0x00, 0x00, // checksum
                0x00, 0x00, // urgent pointer
            ];

            let packet = wire::Packet::new_checked(&data).unwrap();

            assert_eq!(packet.src_port(), 80);
            assert_eq!(packet.dst_port(), 1234);
            assert_eq!(packet.seq_number(), 1000);
            assert_eq!(packet.ack_number(), 2000);
            assert_eq!(packet.flags() & wire::field::FLG_SYN, wire::field::FLG_SYN);
            assert_eq!(packet.flags() & wire::field::FLG_ACK, wire::field::FLG_ACK);
            assert_eq!(packet.window_len(), 8192);
            assert_eq!(packet.header_len(), 20);
        }

        #[test_case]
        fn test_packet_too_short() {
            let data = [0x00; 10];
            let result = wire::Packet::new_checked(&data);
            assert!(result.is_err());
        }

        #[test_case]
        fn test_packet_mut_construction() {
            let mut buffer = [0u8; 20];
            let mut packet = wire::PacketMut::new_unchecked(&mut buffer);

            packet.set_src_port(80);
            packet.set_dst_port(1234);
            packet.set_seq_number(1000);
            packet.set_ack_number(2000);
            packet.set_header_len(20);
            packet.set_flags(wire::field::FLG_SYN | wire::field::FLG_ACK);
            packet.set_window_len(8192);
            packet.set_checksum(0);
            packet.set_urg_ptr(0);

            let packet_read = wire::Packet::new_checked(&buffer).unwrap();
            assert_eq!(packet_read.src_port(), 80);
            assert_eq!(packet_read.dst_port(), 1234);
            assert_eq!(packet_read.seq_number(), 1000);
            assert_eq!(packet_read.ack_number(), 2000);
        }

        #[test_case]
        fn test_checksum_verification() {
            let src_ip = IpAddr(0x0a000001); // 10.0.0.1
            let dst_ip = IpAddr(0x0a000002); // 10.0.0.2

            let mut buffer = [0u8; 20];
            {
                let mut packet = wire::PacketMut::new_unchecked(&mut buffer);
                packet.set_src_port(12345);
                packet.set_dst_port(80);
                packet.set_seq_number(1000);
                packet.set_ack_number(0);
                packet.set_header_len(20);
                packet.set_flags(wire::field::FLG_SYN);
                packet.set_window_len(65535);
                packet.set_urg_ptr(0);
                packet.fill_checksum(src_ip, dst_ip);
            }

            let packet = wire::Packet::new_checked(&buffer).unwrap();
            assert!(packet.verify_checksum(src_ip, dst_ip));
        }
    }
}
