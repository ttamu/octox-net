# tcp-spec

- [tcp-spec](#tcp-spec)
  - [参考資料](#参考資料)
  - [実装の流れ](#実装の流れ)
    - [セグメント](#セグメント)
    - [PCB](#pcb)
    - [パッシブオープンの実装](#パッシブオープンの実装)
    - [データ転送](#データ転送)
    - [セグメント再送](#セグメント再送)
    - [アクティブオープンの実装](#アクティブオープンの実装)
    - [パッシブクローズ](#パッシブクローズ)
    - [アクティブクローズ](#アクティブクローズ)
    - [同時オープン・同時クローズ](#同時オープン同時クローズ)
    - [ソケット互換のユーザコマンド](#ソケット互換のユーザコマンド)
    - [ソケットAPI](#ソケットapi)
  - [wasabiOSのTCPの実装について (wasabi)](#wasabiosのtcpの実装について-wasabi)
  - [micropsのTCPの実装について (microps)](#micropsのtcpの実装について-microps)
  - [microkernel-bookのtcpの実装について (microkernel-book)](#microkernel-bookのtcpの実装について-microkernel-book)

## 参考資料

- ~/dev/operating-system/smoltcp
- ~/dev/operating-system/microps
- [RFC 9293](https://datatracker.ietf.org/doc/html/rfc9293)

## 実装の流れ

### セグメント

- TCPヘッダ構造体、セグメント情報構造体、フラグ定義、状態定数の定義

### PCB

- TCP制御ブロック（状態、エンドポイント、送受信シーケンス変数、バッファ、再送キュー）とPCB管理関数

### パッシブオープンの実装

- LISTEN状態でのSYN受信処理とSYN+ACK送信

### データ転送

- ESTABLISHED状態でのデータ送受信処理

### セグメント再送

- 再送キューの管理とタイムアウト処理

### アクティブオープンの実装

- SYN送信とSYN_SENT状態の処理

### パッシブクローズ

- FIN受信時の処理とCLOSE_WAIT/LAST_ACK状態遷移

### アクティブクローズ

- FIN送信とFIN_WAIT1/FIN_WAIT2/TIME_WAIT状態遷移

### 同時オープン・同時クローズ

- 同時オープン・同時クローズのエッジケース処理

### ソケット互換のユーザコマンド

- tcp_open, tcp_bind, tcp_listen, tcp_accept, tcp_connect, tcp_send, tcp_receive, tcp_close

### ソケットAPI

- 上記関数群のAPI提供

## wasabiOSのTCPの実装について ([wasabi](https://github.com/hikalium/wasabi/blob/main/os/src/net/tcp.rs))

- `struct TcpPacket`
- `impl TcpPacket` : ポート番号、シーケンス番号、ACK番号、フラグ（SYN/ACK/FIN/RST）、ウィンドウサイズなどのゲッター/セッター
- `enum TcpSocketState` : RFC 9293 : Listen, SynSentなど
- `struct TcpSocket` : IPアドレス, ポート番号, シーケンス番号などを保持
- `impl TcpSocket`
  - `new_serve` : パッシブオープン
  - `new_client`  : アクティブオープン
  - `gen_syn_packet`
  - `gen_tcp_packet`
  - `handle_rx` : TCPパケットを処理. 状態遷移と応答パケットの送信
  - `poll_tx` : 送信バッファにデータがあれば送信
  - `open` : クライアント側でSYNパケットを送信して接続開始
  - `wait_until_connection_is_established` : 接続がEstablishedになるまで非同期で待機
  - `wait_on_rx` : データが到着するまで非同期で待機
  - `is_established`
  - `is_trying_to_connect`

## micropsのTCPの実装について ([microps](https://github.com/pandax381/microps/tree/master))

**tcp.h** ([microps/tcp.h](https://github.com/pandax381/microps/blob/master/tcp.h))

- TCP_STATEの定義
  - `CLOSED`, `LISTEN`, `SYN_SENT`, `SYN_RECEIVED`など
- インタフェースの定義
  - `tcp_state`, `tcp_close`, `tcp_send`, `tcp_receive`など

**tcp.c** ([microps/tcp.c](https://github.com/pandax381/microps/blob/master/tcp.c))

- `#define TCP_FLG`
  - FIN, SYN, RST, PSH, ACK, URG
- `#define TCP_PCB_STATE`
  - FREE, CLOSED, LISTEN, SY_SENT, SYN_RECEIVEDなどの状態定数
- `TCP_SOURCE_PORT_MIN`, `MAX` : エフェメラルポートの範囲
- `struct tcp_hdr` : TCPヘッダ（src, dst, seq, ack, off, flg, wnd, sum, up）
- `struct tcp_segment_info` : se, ack, wndなど
- `struct tcp_pcb`
- `struct tcp_queue_entry`
- `static mutex_t, tcp_pcb`
- `static void tcp_dump`
- tcp_pcb
  - `tcp_pcb_alloc(void)`
  - `tcp_pcb_release`
  - `tcp_pcb_select`
  - `tcp_pcb_get`
  - `tcp_pcb_id`
- tcp_retransmit
  - `tcp_retransmit_queue_add`
  - `tcp_retransmit_queue_cleanup`
  - `tcp_retransmit_queue_emit`
  - `tcp_set_timewait_timer`
- `tcp_output_segment` : セグメント送信
- `tcp_output` : PCBからセグメント送信
- `tcp_segment_arrives`
- `tcp_input` : ip layerからの受信処理
- `tcp_timer`
- `event_handler`
- `tcp_init`
- `tcp_open_rfc793`
- `tcp_state` : 状態取得
- `tcp_open` : PCB作成
- `tcp_connect` : アクティブオープン
- `tcp_bind`
- `tcp_listen` : パッシブオープン
- `tcp_accept` : 接続を確立
- `tcp_send` : データ送信
- `tcp_receive` : データ受信
- `tcp_close` : 接続クローズ

## microkernel-bookのtcpの実装について ([microkernel-book](https://github.com/keisuke713/microkernel-book/blob/main/servers/tcpip/tcp.c))

- `tcp_pcb` : TCPソケット管理構造体のテーブル
- `active_pcbs` : 使用中のTCPソケット管理構造体のリスト
- `passive_pcbs` : 使用中のTCPソケット管理構造体のリスト(パッシブ)
- `tcp_lookup_local` : ローカルのIPアドレス, ポート番号からPCBを検索
- `tcp_lookup` : IPアドレス,ポート番号からPCBを検索
- `tcp_lookup_passive` : IPアドレス,ポート番号からパッシブオープンのPCBを探す
- `tcp_new` : 新たなPCBを作成
- `tcp_connect` : TCPコネクションを開く(アクティブオープン)
- `tcp_connect_passive` : TCPコネクションを開く(パッシブオープン)
- `tcp_close` : TCPコネクションを削除
- `tcp_write` : 送信するデータをバッファに追加
- `tcp_read` : 受信済みデータをバッファから読み出す
- `tcp_transmit` : PCBに未送信データ・フラグがあれば送信
- `tcp_process` : TCPパケットの受信処理
- `tcp_receive` : TCPパケットの受信処理(該当するPCBを探してtcp_process()を呼び出す)
- `tcp_flush` : 各PCBをチェックして、未送信データがあれば送信する
- `tcp_init` : TCP実装の初期化
