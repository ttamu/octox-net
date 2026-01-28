use alloc::vec::Vec;
use core::cmp;

use super::{retransmit::SendRequest, socket::Socket, state::State, timer, wire};

pub(crate) struct SegmentInfo<'a> {
    pub(crate) seq: u32,
    pub(crate) ack: u32,
    pub(crate) len: u32,
    pub(crate) wnd: u16,
    pub(crate) flags: u8,
    pub(crate) payload: &'a [u8],
}

impl<'a> SegmentInfo<'a> {
    pub(crate) fn new(
        seq: u32,
        ack: u32,
        len: u32,
        wnd: u16,
        flags: u8,
        payload: &'a [u8],
    ) -> Self {
        Self {
            seq,
            ack,
            len,
            wnd,
            flags,
            payload,
        }
    }

    pub(crate) fn has_syn(&self) -> bool {
        (self.flags & wire::field::FLG_SYN) != 0
    }

    pub(crate) fn has_ack(&self) -> bool {
        (self.flags & wire::field::FLG_ACK) != 0
    }

    pub(crate) fn has_fin(&self) -> bool {
        (self.flags & wire::field::FLG_FIN) != 0
    }

    pub(crate) fn has_rst(&self) -> bool {
        (self.flags & wire::field::FLG_RST) != 0
    }
}

pub(crate) struct SegmentProcessor<'a> {
    sock: &'a mut Socket,
    seg: SegmentInfo<'a>,
    send_ack: bool,
}

impl<'a> SegmentProcessor<'a> {
    pub(crate) fn new(sock: &'a mut Socket, seg: SegmentInfo<'a>) -> Self {
        Self {
            sock,
            seg,
            send_ack: false,
        }
    }

    pub(crate) fn run(&mut self) {
        if self.handle_syn_sent() {
            return;
        }
        if self.handle_syn_received_duplicate() {
            return;
        }
        if !self.validate_window() {
            return;
        }

        if self.seg.has_rst() {
            self.sock.state = State::Closed;
            return;
        }

        if self.seg.has_syn() {
            self.sock.state = State::Closed;
            self.send_rst_for_segment(self.seg.has_ack());
            return;
        }

        if !self.handle_ack() {
            return;
        }

        self.handle_payload();
        self.handle_fin();

        if self.send_ack {
            let _ = self.sock.egress(wire::field::FLG_ACK, &[]);
        }
    }

    fn handle_syn_sent(&mut self) -> bool {
        if self.sock.state != State::SynSent {
            return false;
        }

        if self.seg.has_ack()
            && (Self::seq_le(self.seg.ack, self.sock.iss)
                || Self::seq_lt(self.sock.snd_nxt, self.seg.ack))
        {
            self.send_rst_for_segment(true);
            return true;
        }

        let acceptable_ack = self.seg.has_ack()
            && Self::seq_le(self.sock.snd_una, self.seg.ack)
            && Self::seq_le(self.seg.ack, self.sock.snd_nxt);

        if self.seg.has_rst() {
            if acceptable_ack {
                self.sock.state = State::Closed;
            }
            return true;
        }

        if self.seg.has_syn() {
            self.sock.irs = self.seg.seq;
            self.sock.rcv_nxt = self.seg.seq.wrapping_add(1);

            if self.seg.has_ack() {
                self.sock.snd_una = self.seg.ack;
                self.sock.cleanup_retransmit();
                self.sock.snd_wnd = self.seg.wnd;
                self.sock.snd_wl1 = self.seg.seq;
                self.sock.snd_wl2 = self.seg.ack;
            }

            if self.seg.has_ack() && Self::seq_lt(self.sock.iss, self.sock.snd_una) {
                self.sock.state = State::Established;
                let _ = self.sock.egress(wire::field::FLG_ACK, &[]);
            } else {
                self.sock.state = State::SynReceived;
                let _ = self
                    .sock
                    .egress(wire::field::FLG_SYN | wire::field::FLG_ACK, &[]);
            }
        }

        true
    }

    fn handle_syn_received_duplicate(&mut self) -> bool {
        if self.sock.state != State::SynReceived || !self.seg.has_syn() {
            return false;
        }
        let _ = self
            .sock
            .egress(wire::field::FLG_SYN | wire::field::FLG_ACK, &[]);
        true
    }

    pub(crate) fn validate_window(&mut self) -> bool {
        let rcv_nxt = self.sock.rcv_nxt;
        let rcv_wnd = self.sock.rcv_wnd;
        let seg_seq = self.seg.seq;
        let seg_len = self.seg.len;

        if seg_len == 0 {
            if rcv_wnd == 0 {
                return self.accept_or_ack(seg_seq == rcv_nxt);
            }
            let end = rcv_nxt.wrapping_add(rcv_wnd as u32);
            return self.accept_or_ack(Self::seq_between(rcv_nxt, seg_seq, end));
        }

        if rcv_wnd == 0 {
            return self.accept_or_ack(false);
        }

        let end = rcv_nxt.wrapping_add(rcv_wnd as u32);
        let seg_end = seg_seq.wrapping_add(seg_len - 1);
        self.accept_or_ack(
            Self::seq_between(rcv_nxt, seg_seq, end) || Self::seq_between(rcv_nxt, seg_end, end),
        )
    }

    pub(crate) fn handle_ack(&mut self) -> bool {
        if !self.seg.has_ack() {
            return self.sock.state == State::SynReceived;
        }

        let ack_ok = self.ack_in_window();

        if self.sock.state == State::SynReceived {
            if !ack_ok {
                self.send_rst_for_segment(true);
                return false;
            }

            self.sock.snd_una = self.seg.ack;
            self.sock.cleanup_retransmit();
            self.sock.snd_wnd = self.seg.wnd;
            self.sock.snd_wl1 = self.seg.seq;
            self.sock.snd_wl2 = self.seg.ack;
            self.sock.state = State::Established;
            if self.sock.parent.is_some() {
                self.sock.accept_ready = true;
            }
            return true;
        }

        if !ack_ok {
            return true;
        }

        self.sock.snd_una = self.seg.ack;
        self.sock.cleanup_retransmit();

        if Self::seq_lt(self.sock.snd_wl1, self.seg.seq)
            || (self.sock.snd_wl1 == self.seg.seq && Self::seq_le(self.sock.snd_wl2, self.seg.ack))
        {
            self.sock.snd_wnd = self.seg.wnd;
            self.sock.snd_wl1 = self.seg.seq;
            self.sock.snd_wl2 = self.seg.ack;
        }

        match self.sock.state {
            State::FinWait1 => {
                if self.sock.snd_una == self.sock.snd_nxt {
                    self.sock.state = State::FinWait2;
                }
            }
            State::Closing => {
                if self.sock.snd_una == self.sock.snd_nxt {
                    self.sock.state = State::TimeWait;
                    self.sock.timewait_deadline =
                        Some(timer::get_time_ms().saturating_add(Socket::TIMEWAIT_MS));
                }
            }
            State::LastAck => {
                if self.sock.snd_una == self.sock.snd_nxt {
                    self.sock.state = State::Closed;
                    return false;
                }
            }
            _ => {}
        }

        true
    }

    fn handle_payload(&mut self) {
        if self.seg.payload.is_empty() {
            return;
        }
        if !matches!(
            self.sock.state,
            State::Established | State::FinWait1 | State::FinWait2
        ) {
            return;
        }

        if self.seg.seq == self.sock.rcv_nxt {
            let space = self.sock.rx_capacity.saturating_sub(self.sock.rx_buf.len());
            let to_copy = cmp::min(space, self.seg.payload.len());
            for b in self.seg.payload.iter().take(to_copy) {
                self.sock.rx_buf.push_back(*b);
            }
            self.sock.rcv_nxt = self.sock.rcv_nxt.wrapping_add(to_copy as u32);
            self.send_ack = true;
        } else {
            self.send_ack = true;
        }

        self.sock.rcv_wnd = (self.sock.rx_capacity - self.sock.rx_buf.len()) as u16;
    }

    fn handle_fin(&mut self) {
        if !self.seg.has_fin() {
            return;
        }

        let fin_end = self
            .seg
            .seq
            .wrapping_add(self.seg.payload.len() as u32)
            .wrapping_add(1);
        if Self::seq_lt(self.sock.rcv_nxt, fin_end) {
            self.sock.rcv_nxt = fin_end;
        }
        self.send_ack = true;

        match self.sock.state {
            State::SynReceived | State::Established => {
                self.sock.state = State::CloseWait;
            }
            State::FinWait1 => {
                if self.sock.snd_una == self.sock.snd_nxt {
                    self.sock.state = State::TimeWait;
                    self.sock.timewait_deadline =
                        Some(timer::get_time_ms().saturating_add(Socket::TIMEWAIT_MS));
                } else {
                    self.sock.state = State::Closing;
                }
            }
            State::FinWait2 => {
                self.sock.state = State::TimeWait;
                self.sock.timewait_deadline =
                    Some(timer::get_time_ms().saturating_add(Socket::TIMEWAIT_MS));
            }
            State::TimeWait => {
                self.sock.timewait_deadline =
                    Some(timer::get_time_ms().saturating_add(Socket::TIMEWAIT_MS));
            }
            _ => {}
        }
    }

    fn send_rst_for_segment(&mut self, ack_present: bool) {
        if ack_present {
            self.sock.pending.push_back(SendRequest {
                seq: self.seg.ack,
                ack: 0,
                flags: wire::field::FLG_RST,
                wnd: 0,
                payload: Vec::new(),
                local: self.sock.local,
                foreign: self.sock.foreign,
            });
        } else {
            self.sock.pending.push_back(SendRequest {
                seq: 0,
                ack: self.seg.seq.wrapping_add(self.seg.len),
                flags: wire::field::FLG_RST | wire::field::FLG_ACK,
                wnd: 0,
                payload: Vec::new(),
                local: self.sock.local,
                foreign: self.sock.foreign,
            });
        }
    }

    fn accept_or_ack(&mut self, acceptable: bool) -> bool {
        if !acceptable && !self.seg.has_rst() {
            let _ = self.sock.egress(wire::field::FLG_ACK, &[]);
        }
        acceptable
    }

    fn ack_in_window(&self) -> bool {
        Self::seq_lt(self.sock.snd_una, self.seg.ack)
            && Self::seq_le(self.seg.ack, self.sock.snd_nxt)
    }

    fn seq_lt(a: u32, b: u32) -> bool {
        (a.wrapping_sub(b) as i32) < 0
    }

    fn seq_le(a: u32, b: u32) -> bool {
        (a.wrapping_sub(b) as i32) <= 0
    }

    fn seq_between(start: u32, seq: u32, end: u32) -> bool {
        !Self::seq_lt(seq, start) && Self::seq_lt(seq, end)
    }
}
