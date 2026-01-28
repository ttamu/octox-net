use crate::error::{Error, Result};
use crate::net::ip::{self, IpAddr, IpEndpoint};
use crate::net::socket::{SocketHandle, SocketSet};
use crate::spinlock::Mutex;
use crate::trace;
use alloc::{collections::VecDeque, vec::Vec};
use core::cmp;
use core::sync::atomic::{AtomicU16, Ordering};

use super::{
    retransmit::{RetransmitEntry, SendRequest},
    segment::{SegmentInfo, SegmentProcessor},
    state::State,
    timer, wire,
};

pub struct Socket {
    pub(super) state: State,
    pub(super) local: IpEndpoint,
    pub(super) foreign: IpEndpoint,

    pub(super) snd_nxt: u32,
    pub(super) snd_una: u32,
    pub(super) snd_wnd: u16,
    pub(super) snd_wl1: u32,
    pub(super) snd_wl2: u32,

    pub(super) rcv_nxt: u32,
    pub(super) rcv_wnd: u16,

    pub(super) iss: u32,
    pub(super) irs: u32,

    pub(super) mss: u16,

    pub(super) rx_buf: VecDeque<u8>,
    pub(super) rx_capacity: usize,
    pub(super) tx_buf: VecDeque<u8>,
    pub(super) tx_capacity: usize,

    pub(super) retransmit: VecDeque<RetransmitEntry>,
    pub(super) pending: VecDeque<SendRequest>,

    pub(super) timewait_deadline: Option<u64>,

    pub(super) parent: Option<usize>,
    pub(super) backlog: VecDeque<usize>,
    pub(super) accept_ready: bool,
}

impl Socket {
    const RX_BUFFER_SIZE: usize = 8192;
    const TX_BUFFER_SIZE: usize = 8192;
    const DEFAULT_MSS: usize = 1460;
    const DEFAULT_RTO_MS: u64 = 200;
    const RETRANSMIT_DEADLINE_MS: u64 = 12_000;
    pub(crate) const TIMEWAIT_MS: u64 = 30_000;

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
        let _ = self.egress(wire::field::FLG_SYN, &[]);
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
        self.flush_tx(timer::get_time_ms());
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
                let _ = self.egress(wire::field::FLG_ACK | wire::field::FLG_FIN, &[]);
                self.snd_nxt = self.snd_nxt.wrapping_add(1);
                self.state = State::FinWait1;
            }
            State::CloseWait => {
                let _ = self.egress(wire::field::FLG_ACK | wire::field::FLG_FIN, &[]);
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
        let seg = SegmentInfo::new(seg_seq, seg_ack, seg_len, seg_wnd, flags, payload);
        let mut processor = SegmentProcessor::new(self, seg);
        processor.run();
    }

    pub(super) fn egress(&mut self, flags: u8, payload: &[u8]) -> Result<()> {
        let mut seq = self.snd_nxt;
        if (flags & wire::field::FLG_SYN) != 0 {
            seq = self.iss;
        }
        let payload_vec = payload.to_vec();
        if (flags & (wire::field::FLG_SYN | wire::field::FLG_FIN)) != 0 || !payload.is_empty() {
            self.retransmit.push_back(RetransmitEntry {
                first_at: timer::get_time_ms(),
                last_at: timer::get_time_ms(),
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

    pub(super) fn cleanup_retransmit(&mut self) {
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
            let _ = self.egress(wire::field::FLG_ACK | wire::field::FLG_PSH, &payload);
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

struct Tcp {
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

    pub fn ingress(&self, src_ip: IpAddr, dst_ip: IpAddr, data: &[u8]) -> Result<()> {
        trace!(
            TCP,
            "[tcp] ingress: {} bytes from {:?}",
            data.len(),
            src_ip.to_bytes()
        );

        let packet = wire::Packet::new_checked(data)?;
        if !packet.verify_checksum(src_ip, dst_ip) {
            return Err(Error::ChecksumError);
        }

        trace!(
            TCP,
            "[tcp] packet: sport={} dport={} seq={} ack={} flags=0x{:02x}",
            packet.src_port(),
            packet.dst_port(),
            packet.seq_number(),
            packet.ack_number(),
            packet.flags()
        );

        let flags = packet.flags();
        let payload = packet.payload();

        let mut seg_len = payload.len() as u32;
        if (flags & wire::field::FLG_SYN) != 0 {
            seg_len += 1;
        }
        if (flags & wire::field::FLG_FIN) != 0 {
            seg_len += 1;
        }

        let seg = SegmentInfo::new(
            packet.seq_number(),
            packet.ack_number(),
            seg_len,
            packet.window_len(),
            flags,
            payload,
        );

        let local = IpEndpoint::new(dst_ip, packet.dst_port());
        let foreign = IpEndpoint::new(src_ip, packet.src_port());

        let mut sends = Vec::new();
        {
            let mut sockets = self.sockets.lock();

            let (established_idx, listen_idx) = self.find_sockets(&sockets, &local, &foreign);

            if let Some(index) = established_idx {
                self.handle_on_socket(&mut sockets, index, &seg, &mut sends);
            } else if let Some(index) = listen_idx {
                self.handle_on_listen(&mut sockets, index, &local, &foreign, &seg, &mut sends)?;
            } else {
                self.send_rst_response(&local, &foreign, &seg, &mut sends);
            }
        }

        for req in sends {
            self.output_segment(&req)?;
        }

        Ok(())
    }

    pub fn poll(&self) -> Result<()> {
        let now = timer::get_time_ms();
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
        if !(Self::EPHEMERAL_PORT_MIN..=Self::EPHEMERAL_PORT_MAX).contains(&port) {
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
        seg: &SegmentInfo<'_>,
        sends: &mut Vec<SendRequest>,
    ) {
        let socket = sockets.get_mut(SocketHandle::new(index)).unwrap();
        socket.handle_segment(seg.seq, seg.ack, seg.len, seg.wnd, seg.flags, seg.payload);
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
        seg: &SegmentInfo<'_>,
        sends: &mut Vec<SendRequest>,
    ) -> Result<()> {
        if seg.has_rst() {
            return Ok(());
        }

        if seg.has_ack() {
            sends.push(SendRequest {
                seq: seg.seq,
                ack: 0,
                flags: wire::field::FLG_RST,
                wnd: 0,
                payload: Vec::new(),
                local: *local,
                foreign: *foreign,
            });
            return Ok(());
        }

        if seg.has_syn() {
            let mut child = Socket::new(Socket::RX_BUFFER_SIZE, Socket::TX_BUFFER_SIZE);
            child.parent = Some(listen_index);
            child.local = *local;
            child.foreign = *foreign;
            child.rcv_wnd = child.rx_capacity as u16;
            child.rcv_nxt = seg.seq.wrapping_add(1);
            child.irs = seg.seq;
            child.iss = initial_iss(local.port);
            child.snd_una = child.iss;
            child.snd_nxt = child.iss + 1;
            child.state = State::SynReceived;

            let handle = sockets.alloc(child)?;
            let child = sockets.get_mut(handle).unwrap();
            let _ = child.egress(wire::field::FLG_SYN | wire::field::FLG_ACK, &[]);
            child.drain_pending(sends);
        }

        Ok(())
    }

    fn send_rst_response(
        &self,
        local: &IpEndpoint,
        foreign: &IpEndpoint,
        seg: &SegmentInfo<'_>,
        sends: &mut Vec<SendRequest>,
    ) {
        if seg.has_rst() {
            return;
        }

        if !seg.has_ack() {
            sends.push(SendRequest {
                seq: 0,
                ack: seg.seq.wrapping_add(seg.len),
                flags: wire::field::FLG_RST | wire::field::FLG_ACK,
                wnd: 0,
                payload: Vec::new(),
                local: *local,
                foreign: *foreign,
            });
        } else {
            sends.push(SendRequest {
                seq: seg.ack,
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

        ip::egress_route(req.foreign.addr, wire::PROTOCOL_TCP, &buf)?;
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

pub fn ingress(src_ip: IpAddr, dst_ip: IpAddr, data: &[u8]) -> Result<()> {
    TCP.ingress(src_ip, dst_ip, data)
}

pub fn poll() -> Result<()> {
    TCP.poll()
}

fn next_ephemeral_port() -> u16 {
    TCP.next_ephemeral_port()
}

fn initial_iss(port: u16) -> u32 {
    (port as u32).wrapping_mul(1000).wrapping_add(12345)
}
