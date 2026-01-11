# smoltcp 参照ガイド - TCP/IP実装の参考資料

## 目次
1. [smoltcpとは](#smoltcpとは)
2. [Architecture概要](#architecture概要)
3. [ディレクトリ構造](#ディレクトリ構造)
4. [各Layerの詳細](#各layerの詳細)
5. [Data flow](#data-flow)
6. [TCP state machine](#tcp-state-machine)
7. [重要な実装ファイル](#重要な実装ファイル)
8. [参考資料](#参考資料)

---

## smoltcpとは

smoltcpは、**ベアメタル・リアルタイムシステム向けに設計された、スタンドアロンのイベント駆動型TCP/IPスタック**です。

### 基本情報
- **言語**: Rust
- **ライセンス**: 0BSD
- **リポジトリ**: https://github.com/smoltcp-rs/smoltcp
- **公式ドキュメント**: https://docs.rs/smoltcp/

### 設計の特徴
- シンプルで理解しやすいコード設計
- Layered structure（階層化されたアーキテクチャ）
- IPv4/IPv6、TCP/UDP対応
- RFC 793準拠のTCP実装

---

## Architecture概要

smoltcpは明確な**layered structure**を持っています：

```
┌─────────────────────────────────────┐
│   Application                       │
│   (User code)                       │
└─────────────────────────────────────┘
              ↕
┌─────────────────────────────────────┐
│   Socket layer (src/socket/)        │
│   - TCP socket                      │
│   - UDP socket                      │
│   - ICMP socket                     │
│   - Raw socket                      │
└─────────────────────────────────────┘
              ↕
┌─────────────────────────────────────┐
│   Interface layer (src/iface/)      │
│   - Packet routing                  │
│   - Address resolution (ARP/NDP)    │
│   - Control message handling        │
│   - Fragmentation/reassembly        │
└─────────────────────────────────────┘
              ↕
┌─────────────────────────────────────┐
│   Physical layer (src/phy/)         │
│   - Device driver interface         │
│   - Loopback                        │
│   - TAP/TUN                         │
└─────────────────────────────────────┘
              ↕
┌─────────────────────────────────────┐
│   Wire layer (src/wire/)            │
│   - Packet parse/serialize          │
│   - Protocol structures             │
│   - Checksum computation            │
└─────────────────────────────────────┘
```

### 各Layerの責務

1. **Wire layer**: Packetの解析と構築（最下層）
2. **Physical layer**: ハードウェアとの実際のI/O
3. **Interface layer**: Packetの振り分けと制御
4. **Socket layer**: Application向けAPIの提供（最上層）

---

## ディレクトリ構造

```
smoltcp/
├── src/
│   ├── lib.rs              # Entry point
│   ├── wire/               # Wire layer implementation
│   │   ├── mod.rs
│   │   ├── ethernet.rs     # Ethernet frame
│   │   ├── arp.rs          # ARP protocol
│   │   ├── ipv4.rs         # IPv4 packet
│   │   ├── ipv6.rs         # IPv6 packet
│   │   ├── icmpv4.rs       # ICMPv4
│   │   ├── tcp.rs          # TCP segment
│   │   ├── udp.rs          # UDP datagram
│   │   └── ...
│   ├── phy/                # Physical layer implementation
│   │   ├── mod.rs          # Device trait definition
│   │   ├── loopback.rs     # Loopback device
│   │   └── ...
│   ├── iface/              # Interface layer implementation
│   │   ├── mod.rs
│   │   ├── interface/
│   │   │   ├── mod.rs      # Interface core logic
│   │   │   ├── ethernet.rs # Ethernet-specific handling
│   │   │   ├── ipv4.rs     # IPv4 handling
│   │   │   ├── tcp.rs      # TCP handling
│   │   │   └── udp.rs      # UDP handling
│   │   ├── neighbor.rs     # Neighbor cache (ARP/NDP)
│   │   └── route.rs        # Routing table
│   ├── socket/             # Socket layer implementation
│   │   ├── mod.rs
│   │   ├── tcp.rs          # TCP socket (state machine)
│   │   ├── tcp/
│   │   │   └── congestion.rs # Congestion control
│   │   ├── udp.rs          # UDP socket
│   │   └── ...
│   ├── storage/            # Data structures
│   │   ├── ring_buffer.rs  # Ring buffer
│   │   └── assembler.rs    # Segment reassembly
│   └── time.rs             # Time management
└── examples/               # Example programs
    ├── loopback.rs         # Minimal example
    ├── server.rs           # TCP server example
    └── ...
```

---

## 各Layerの詳細

### 1. Wire layer (`src/wire/`)

**役割**: Packetの解析と構築。生のバイト列とプロトコル構造体を相互変換。

#### 重要な概念
- **Packet**: Bufferのゼロコピーラッパー
- **Repr (Representation)**: プロトコル固有の高レベル表現
- **Checksum**: プロトコルごとの計算と検証

#### 例: TCP packet (`src/wire/tcp.rs`)

```rust
// TCP packet structure
pub struct Packet<T: AsRef<[u8]>> {
    buffer: T,
}

// TCP packet representation
pub struct Repr<'a> {
    pub src_port: u16,
    pub dst_port: u16,
    pub control: TcpControl,
    pub seq_number: SeqNumber,
    pub ack_number: Option<SeqNumber>,
    pub window_len: u16,
    pub payload: &'a [u8],
    // ...
}
```

#### 参照すべきファイル
- `tcp.rs`: TCP実装の基礎、sequence numberの扱い方
- `ipv4.rs`: IPv4 headerのparse、checksum計算
- `ethernet.rs`: Ethernet frameの構造

### 2. Physical layer (`src/phy/`)

**役割**: ハードウェアdeviceとの実際のI/O。Device traitの実装。

#### Device trait
```rust
pub trait Device {
    type RxToken: RxToken;
    type TxToken: TxToken;

    fn receive(&mut self) -> Option<(Self::RxToken, Self::TxToken)>;
    fn transmit(&mut self) -> Option<Self::TxToken>;
    fn capabilities(&self) -> DeviceCapabilities;
}
```

#### 参照すべきファイル
- `mod.rs`: Device traitの定義
- `loopback.rs`: Device traitの最小実装

### 3. Interface layer (`src/iface/`)

**役割**: Packetのrouting、ARP/NDP、IPアドレス管理、socketへの配送。

#### Interfaceの主要メソッド
```rust
impl Interface {
    // Packet処理のメインループ
    pub fn poll(&mut self, timestamp: Instant,
                device: &mut Device,
                sockets: &mut SocketSet) -> PollResult;

    // IPアドレスの管理
    pub fn update_ip_addrs<F: FnOnce(&mut Vec<IpCidr>)>(&mut self, f: F);

    // Routing table操作
    pub fn routes_mut(&mut self) -> &mut Routes;
}
```

#### 重要な処理
- **Ingress**: 受信packetを解析し、適切なsocketに配送
- **Egress**: Socketからのデータを適切なpacketにカプセル化
- **ARP/NDP**: MACアドレス解決とcache管理
- **Fragmentation**: 大きいpacketの分割と再構築

#### 参照すべきファイル
- `interface/mod.rs`: Interfaceの中核ロジック
- `neighbor.rs`: ARP/NDP cache
- `route.rs`: Routing table

### 4. Socket layer (`src/socket/`)

**役割**: Application向けAPI。Protocol state machineの実装。

#### TCP socket (`src/socket/tcp.rs`)

##### State transitions
RFC 793で定義されたTCP state machineを完全実装：
- CLOSED → LISTEN (server)
- CLOSED → SYN-SENT → ESTABLISHED (client)
- ESTABLISHED → FIN-WAIT-1 → ... → CLOSED (termination)

##### 主要なメソッド
```rust
impl Socket {
    // Serverとしてlisten
    pub fn listen<T>(&mut self, local_endpoint: T) -> Result<(), ListenError>;

    // Clientとして接続
    pub fn connect<T, U>(&mut self, local: T, remote: U)
        -> Result<(), ConnectError>;

    // データ送信
    pub fn send_slice(&mut self, data: &[u8]) -> Result<usize, SendError>;

    // データ受信
    pub fn recv(&mut self, f: impl FnOnce(&[u8]) -> R)
        -> Result<R, RecvError>;
}
```

##### TCP実装の重要な機能
- **Retransmission**: RTT推定とtimeout管理
- **Congestion control**: CUBIC（デフォルト）とReno
- **Flow control**: Window size管理
- **Reordering**: Out-of-order segmentの再構築

#### 参照すべきファイル
- `tcp.rs`: TCP state machine、すべての主要ロジック
- `tcp/congestion.rs`: Congestion controlアルゴリズム

### 5. Storage layer (`src/storage/`)

**役割**: Data structureの提供。

- **RingBuffer**: 循環buffer（送受信buffer用）
- **Assembler**: Out-of-order segmentの管理

---

## Data flow

### Ingress (受信フロー)

```
┌──────────────────────────────────────────────────────────┐
│ 1. Hardware NIC                                          │
│    Packet arrival                                        │
└────────────────┬─────────────────────────────────────────┘
                 ↓
┌──────────────────────────────────────────────────────────┐
│ 2. Device::receive()                                     │
│    Generate RxToken/TxToken                              │
└────────────────┬─────────────────────────────────────────┘
                 ↓
┌──────────────────────────────────────────────────────────┐
│ 3. Interface::poll()                                     │
│    Fetch received packet                                 │
└────────────────┬─────────────────────────────────────────┘
                 ↓
┌──────────────────────────────────────────────────────────┐
│ 4. RxToken::consume()                                    │
│    Read packet from buffer                               │
└────────────────┬─────────────────────────────────────────┘
                 ↓
┌──────────────────────────────────────────────────────────┐
│ 5. Wire layer packet parsing                             │
│    - Ethernet::Packet::new()                             │
│    - Ipv4::Packet::new()                                 │
│    - Tcp::Packet::new()                                  │
└────────────────┬─────────────────────────────────────────┘
                 ↓
┌──────────────────────────────────────────────────────────┐
│ 6. Interface layer dispatch                              │
│    Route by protocol and port number                     │
└────────────────┬─────────────────────────────────────────┘
                 ↓
┌──────────────────────────────────────────────────────────┐
│ 7. Socket::process()                                     │
│    For TCP: state machine processing                     │
│    - SYN received → send SYN-ACK                         │
│    - Data received → store in receive buffer             │
│    - FIN received → state transition                     │
└────────────────┬─────────────────────────────────────────┘
                 ↓
┌──────────────────────────────────────────────────────────┐
│ 8. Application                                           │
│    Retrieve data via socket.recv()                       │
└──────────────────────────────────────────────────────────┘
```

### Egress (送信フロー)

```
┌──────────────────────────────────────────────────────────┐
│ 1. Application                                           │
│    socket.send_slice(data)                               │
└────────────────┬─────────────────────────────────────────┘
                 ↓
┌──────────────────────────────────────────────────────────┐
│ 2. Socket::dispatch()                                    │
│    Add data to transmit buffer                           │
│    For TCP: segmentation, sequence number assignment     │
└────────────────┬─────────────────────────────────────────┘
                 ↓
┌──────────────────────────────────────────────────────────┐
│ 3. Interface::poll()                                     │
│    Collect packets to transmit from sockets              │
└────────────────┬─────────────────────────────────────────┘
                 ↓
┌──────────────────────────────────────────────────────────┐
│ 4. Wire layer packet construction                        │
│    - Tcp::Repr::emit()                                   │
│    - Ipv4::Repr::emit()                                  │
│    - Ethernet::Frame::emit()                             │
└────────────────┬─────────────────────────────────────────┘
                 ↓
┌──────────────────────────────────────────────────────────┐
│ 5. Device::transmit()                                    │
│    Acquire TxToken                                       │
└────────────────┬─────────────────────────────────────────┘
                 ↓
┌──────────────────────────────────────────────────────────┐
│ 6. TxToken::consume()                                    │
│    Write packet to buffer and transmit via NIC           │
└────────────────┬─────────────────────────────────────────┘
                 ↓
┌──────────────────────────────────────────────────────────┐
│ 7. Hardware NIC                                          │
│    Packet transmission                                   │
└──────────────────────────────────────────────────────────┘
```

---

## TCP state machine

smoltcpはRFC 793で定義されたTCP state machineを実装しています（`src/socket/tcp.rs`）。

```text
Connection establishment (client):
CLOSED → SYN-SENT → ESTABLISHED

Connection establishment (server):
CLOSED → LISTEN → SYN-RECEIVED → ESTABLISHED

Data transfer:
ESTABLISHED ⇄ ESTABLISHED
(bidirectional data exchange)

Connection termination (active close):
ESTABLISHED → FIN-WAIT-1 → FIN-WAIT-2 → TIME-WAIT → CLOSED

Connection termination (passive close):
ESTABLISHED → CLOSE-WAIT → LAST-ACK → CLOSED
```

### 主要なStateの説明

| State | 説明 | `src/socket/tcp.rs` |
|-------|------|---------------------|
| **CLOSED** | 初期状態、接続なし | State::Closed |
| **LISTEN** | Serverが接続待ち | State::Listen |
| **SYN-SENT** | ClientがSYN送信後 | State::SynSent |
| **SYN-RECEIVED** | ServerがSYN受信、SYN-ACK送信後 | State::SynReceived |
| **ESTABLISHED** | 接続確立、data転送可能 | State::Established |
| **FIN-WAIT-1** | Active close開始 | State::FinWait1 |
| **FIN-WAIT-2** | 相手のFIN待ち | State::FinWait2 |
| **CLOSE-WAIT** | Passive close、applicationの終了待ち | State::CloseWait |
| **LAST-ACK** | 最後のACK待ち | State::LastAck |
| **TIME-WAIT** | 2MSL待ち（デフォルト10秒） | State::TimeWait |

---

## 重要な実装ファイル

### 必読ファイル（優先度順）

#### 1. 全体理解のため

- `src/lib.rs`: プロジェクト構造の概観
- `README.md`: 機能一覧と制限事項
- `examples/loopback.rs`: 最小限の動作例

#### 2. TCP実装のため

- `src/socket/tcp.rs`: TCP state machine (1500行以上、core実装)
  - `State` enum: State定義
  - `dispatch()`: Packet処理のdispatch
  - `process()`: 受信segment処理
- `src/wire/tcp.rs`: TCP packet構造
  - `Packet`: Parse処理
  - `Repr`: 論理表現
- `src/socket/tcp/congestion.rs`: Congestion control

#### 3. IP layerのため

- `src/wire/ipv4.rs`: IPv4 packet処理
- `src/iface/interface/ipv4.rs`: IPv4 routing
- `src/iface/fragmentation.rs`: Fragmentation

#### 4. Ethernet layerのため

- `src/wire/ethernet.rs`: Ethernet frame
- `src/wire/arp.rs`: ARP protocol
- `src/iface/neighbor.rs`: ARP cache

#### 5. Device driverのため

- `src/phy/mod.rs`: Device traitの定義
- `src/phy/loopback.rs`: 参考実装

### ファイル別重要度表

| ファイル | 難易度 | 重要度 | 行数 | 推奨読む順 |
|---------|--------|--------|------|-----------|
| `examples/loopback.rs` | ⭐ | ⭐⭐⭐⭐⭐ | 200 | 1 |
| `src/phy/loopback.rs` | ⭐ | ⭐⭐⭐⭐ | 100 | 2 |
| `src/lib.rs` | ⭐ | ⭐⭐⭐ | 100 | 3 |
| `src/wire/ethernet.rs` | ⭐⭐ | ⭐⭐⭐⭐ | 300 | 4 |
| `src/wire/ipv4.rs` | ⭐⭐ | ⭐⭐⭐⭐⭐ | 500 | 5 |
| `src/wire/tcp.rs` | ⭐⭐⭐ | ⭐⭐⭐⭐⭐ | 800 | 6 |
| `src/iface/neighbor.rs` | ⭐⭐ | ⭐⭐⭐ | 400 | 7 |
| `src/iface/interface/mod.rs` | ⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | 1000 | 8 |
| `src/socket/tcp.rs` | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | 1500+ | 9 |

難易度: ⭐(簡単) 〜 ⭐⭐⭐⭐⭐(難しい)

---

## 参考資料

### RFC (TCP/IP仕様書)
- **RFC 793**: TCP基本仕様 (必読)
- **RFC 1122**: Host要件 (TCPの詳細)
- **RFC 7323**: TCP拡張（window scalingなど）
- **RFC 5681**: TCP congestion control
- **RFC 8312**: CUBIC congestion control
- **RFC 791**: IPv4
- **RFC 826**: ARP

### smoltcp公式
- **ドキュメント**: https://docs.rs/smoltcp/
- **リポジトリ**: https://github.com/smoltcp-rs/smoltcp
- **Matrix チャット**: #smoltcp:matrix.org

### 学習リソース
- TCP/IP Illustrated Vol. 1 (Stevens)
- 『マスタリングTCP/IP』

### 重要なAPI

#### 必ず理解すべきメソッド

1. `Device::receive()` / `Device::transmit()`
   - Physical layerの基礎
2. `RxToken::consume()` / `TxToken::consume()`
   - Zero-copyの仕組み
3. `Interface::new()` / `Interface::poll()`
   - Stackの中核
4. `Socket::listen()` / `Socket::connect()`
   - TCP接続確立
5. `Socket::send_slice()` / `Socket::recv()`
   - Data送受信
6. `Packet::new()` / `Packet::check_len()`
   - Packet解析
7. `Repr::parse()` / `Repr::emit()`
   - Protocol変換
