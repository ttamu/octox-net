# TCP Implementation for octox-net

## Architecture

```text
User Programs
    |
    v
Syscall Layer (syscall.rs)
    |
    v
+-------------------+
| tcp/manager.rs    |  Socket pool, tcp_input, tcp_poll
+-------------------+
    |
    v
+-------------------+
| tcp/socket.rs     |  TcpSocket state machine
+-------------------+
    |
    v
+-------------------+
| tcp/wire.rs       |  Packet parsing/emission
+-------------------+
    |
    v
+-------------------+
| tcp/storage.rs    |  RingBuffer, Assembler
+-------------------+
    |
    v
IP Layer (ip.rs)
```

## Modules

### storage.rs

- `RingBuffer<'a, T>`: Borrowed lifetime ring buffer
- `Assembler`: Out-of-order segment reassembly (4 holes max)

### wire.rs

- `SeqNumber`: i32-based sequence number with wraparound-safe arithmetic
- `Packet<T>`: Zero-copy TCP header accessor
- `Repr<'a>`: High-level packet representation with borrowed payload
- `Control`: SYN, FIN, RST, PSH, None
- `TcpOption`: MSS, Window Scale, SACK Permitted, Timestamp

### socket.rs

- `State`: 11 TCP states (Closed, Listen, SynSent, SynReceived, Established, FinWait1, FinWait2, Closing, TimeWait, CloseWait, LastAck)
- `IpEndpoint`: IP address + port
- `TcpSocket`: Main state machine
  - Public API: `new`, `listen`, `connect`, `send_slice`, `recv_slice`, `close`
  - Query: `state`, `local_endpoint`, `remote_endpoint`, `can_send`, `can_recv`, `is_open`
  - Internal: `process`, `dispatch`, `matches`

### manager.rs

- Global socket pool: 32 sockets, 8KB buffers each
- `socket_alloc`, `socket_free`, `socket_get`, `socket_get_mut`
- `tcp_input`: Called from IP layer on protocol 6
- `tcp_poll`: Called from timer interrupt

## Data Flow

### Incoming Packet

```text
virtio_net driver
    |
    v
ethernet::input()
    |
    v
ip::input()
    | (protocol == 6)
    v
tcp::tcp_input(src_ip, dst_ip, data)
    |
    v
Packet::parse() -> Repr
    |
    v
socket.process()
    |
    v
(optional) send_segment()
```

### Outgoing Data

```text
User: socket.send_slice(data)
    |
    v
tx_buffer.enqueue_slice(data)
    |
    v
(timer interrupt)
    |
    v
tcp_poll()
    |
    v
socket.dispatch()
    |
    v
send_segment_with_payload()
    |
    v
ip::output_route()
```

## Integration Points

### IP Layer (ip.rs)

```rust
match header.protocol {
    IpHeader::TCP => tcp::tcp_input(src, dst, payload),
    // ...
}
```

### Timer (trap.rs)

Note: TCP polling is currently triggered by network receive interrupts via `tcp_input()`. Dedicated timer-based polling may be added later for retransmission.

## State Machine

```text
              +--------+
              | CLOSED |
              +--------+
             /          \
      listen/            \connect (send SYN)
           v              v
      +--------+      +----------+
      | LISTEN |      | SYN-SENT |
      +--------+      +----------+
           |               |
   recv SYN|               |recv SYN-ACK
  send SYN-ACK             |send ACK
           v               v
      +---------------+----+
      | SYN-RECEIVED  |
      +---------------+
           |
      recv ACK
           v
      +-------------+
      | ESTABLISHED |<---- data transfer
      +-------------+
           |
      close/
           v
      +-----------+  recv FIN   +------------+
      | FIN-WAIT-1|------------>|  CLOSING   |
      +-----------+             +------------+
           |                         |
      recv ACK                  recv ACK
           v                         v
      +-----------+             +------------+
      | FIN-WAIT-2|             | TIME-WAIT  |
      +-----------+             +------------+
           |                         |
      recv FIN                  2MSL timeout
           v                         v
      +------------+            +--------+
      | TIME-WAIT  |----------->| CLOSED |
      +------------+            +--------+
```

## Timers

- Retransmission: RFC 6298 exponential backoff, max 60s
- TIME-WAIT: 30 seconds (simplified from 2*MSL)

## Buffer Management

- Static allocation: `32 sockets * 2 * 8KB = 512KB`
- Borrowed lifetimes via `'static` transmute from global pool
- RingBuffer for both TX and RX per socket

## Sequence Number Handling

- i32 internal representation for wraparound-safe comparison
- Wrapping arithmetic for all operations
- `SeqNumber::cmp` uses signed subtraction

## Syscalls

| Syscall     | Number | Description                          |
|-------------|--------|--------------------------------------|
| TcpSocket   | 28     | Allocate a TCP socket                |
| TcpConnect  | 29     | Connect to remote (blocking)         |
| TcpListen   | 30     | Listen on a port                     |
| TcpSend     | 31     | Send data                            |
| TcpRecv     | 32     | Receive data (blocking)              |
| TcpClose    | 33     | Close connection and free socket     |
| TcpAccept   | 34     | Accept incoming connection (blocking)|

## Error Types

| Error              | Code | Description                    |
|--------------------|------|--------------------------------|
| SocketNotOpen      | -50  | Socket not in valid state      |
| SocketAlreadyOpen  | -51  | Socket already connected       |
| ConnectionRefused  | -52  | Connection refused by remote   |
| ConnectionReset    | -53  | Connection reset               |
| ConnectionAborted  | -54  | Connection aborted             |
| BufferFull         | -55  | Send/receive buffer full       |

## Test Programs

### Echo Server

```bash
echoserver [port]
```

- `port`: Port to listen on (default: 7)

The server listens for incoming TCP connections and echoes back any received data.

Example:

```bash
$ echoserver 8000
[echo server] starting on port 8000
[echo server] listening...
```

### Echo Client

```bash
echoclient [addr] [port] [message]
```

- `addr`: Server IP address (default: 127.0.0.1)
- `port`: Server port (default: 7)
- `message`: Message to send (default: "Hello, TCP!")

Example:

```bash
$ echoclient 127.0.0.1 8000 "Hello World"
[echo client] connecting to 127.0.0.1:8000
[echo client] connected
[echo client] sent 11 bytes: Hello World
[echo client] received 11 bytes: Hello World
[echo client] connection closed
```

### 現状について(修正後に削除する)

- 通信ができていない
- macOSからも無理. 別terminalで立ち上げているqemu同士からも無理
- というか, デフォルトポートは7で本当にいいのか?? そこはwell known portじゃないのかな?

```text
# 1. 自作OS側
$ echoserver
[echo server] starting on port 7
[echo server] listening...
[virtio-net] poll_rx: received 1 packets
[ether] input: ethertype=0x0806, len=60
[arp] oper=1 sender=[192, 0, 2, 1] target=[192, 0, 2, 2]
[virtio-net] poll_rx: received 1 packets
[ether] input: ethertype=0x0800, len=60
[ip] received packet: [192, 0, 2, 1] -> [192, 0, 2, 2], proto=6

# 2. macOS側
% nc -v localhost 8080
nc: connectx to localhost port 8080 (tcp) failed: Connection refused
Connection to localhost port 8080 [tcp/http-alt] succeeded!
aaa
bbb
(入力してもOS側のアプリ層には届かず、エコーバックも返ってこない)
```

```text
# 1. macOS側
% nc -lk 12345
(待機状態のまま変化なし)

# 2. 自作OS側
$ echoclient 192.0.2.1 12345
(送信側のログが一切出力されない)
```

## TODO

- [ ] Proper ISS generation (cryptographic random)
- [ ] RTT estimation for RTO calculation
- [ ] Window scaling support
