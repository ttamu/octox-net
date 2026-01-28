mod retransmit;
mod segment;
mod socket;
mod state;
mod timer;
mod wire;

pub use socket::Socket;
pub use socket::{
    ingress, poll, socket_accept, socket_alloc, socket_free, socket_get, socket_get_mut,
};
pub use state::State;

#[cfg(test)]
mod tests {
    use super::{
        segment::SegmentInfo, segment::SegmentProcessor, socket::Socket, state::State, wire,
    };
    use crate::net::ip::IpAddr;

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

    mod segment_tests {
        use super::*;

        #[test_case]
        fn validate_window_zero_len_zero_wnd() {
            let mut socket = Socket::new(1, 1);
            socket.rcv_nxt = 100;
            socket.rcv_wnd = 0;

            let seg_ok = SegmentInfo::new(100, 0, 0, 0, wire::field::FLG_RST, &[]);
            let mut proc_ok = SegmentProcessor::new(&mut socket, seg_ok);
            assert!(proc_ok.validate_window());

            let seg_ng = SegmentInfo::new(99, 0, 0, 0, wire::field::FLG_RST, &[]);
            let mut proc_ng = SegmentProcessor::new(&mut socket, seg_ng);
            assert!(!proc_ng.validate_window());
        }

        #[test_case]
        fn handle_ack_synreceived_transitions() {
            let mut socket = Socket::new(1, 1);
            socket.state = State::SynReceived;
            socket.snd_una = 10;
            socket.snd_nxt = 20;
            socket.parent = Some(0);

            let seg = SegmentInfo::new(5, 15, 0, 4096, wire::field::FLG_ACK, &[]);
            let mut proc = SegmentProcessor::new(&mut socket, seg);
            assert!(proc.handle_ack());
            assert_eq!(socket.state, State::Established);
            assert!(socket.accept_ready);
            assert_eq!(socket.snd_una, 15);
            assert_eq!(socket.snd_wnd, 4096);
        }
    }
}
