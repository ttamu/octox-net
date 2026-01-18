# ping

## Usage

**Format:**

```sh
ping <ip_address>
```

**Examples:**

public DNS server:

```sh
$ ping 8.8.8.8
PING 8.8.8.8 (8.8.8.8): 56 data bytes
64 bytes from 8.8.8.8: icmp_seq=0 ttl=64 time=25.087 ms
64 bytes from 8.8.8.8: icmp_seq=1 ttl=64 time=22.729 ms
```

loopback address:

```sh
$ ping 127.0.0.1
PING 127.0.0.1 (127.0.0.1): 56 data bytes
64 bytes from 127.0.0.1: icmp_seq=0 ttl=64 time=4.276 ms
64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=2.464 ms
```
