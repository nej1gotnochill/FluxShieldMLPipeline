# Feature Dictionary — DDoS-AT-2022 Flow Table

**Source module:** `src/feature_engineering.py` (direct struct-based dissection; NOT CICFlowMeter — no compatibility claim is made).
**Schema version:** 1.0 · **Flow table:** `data/processed/flows/*.parquet` · **66 feature columns, all float32.**

## General conventions

- **Frame length** = captured Ethernet frame length (`incl_len` from the pcap record header), i.e. L2 framing included. Byte counts and length statistics are therefore L2 frame bytes, not IP payload bytes.
- **Direction:** the *first* packet of a flow defines the forward direction. Forward = initiator→responder, Backward = responder→initiator.
- **Flow key:** `(IP protocol, src IP, src port, dst IP, dst port)` — bidirectional grouping (reverse key maps to the same flow).
- **Flow termination:** a flow ends on idle timeout (`flow_timeout_sec = 120 s`), activity cap (`activity_timeout_sec = 1800 s`), packet cap (`max_packets_per_flow = 100_000`), or capture end. The `ended_by` metadata column records which.
- **Online vs TERMINAL:** ONLINE features are well-defined from the first packets of an active flow (documented boundary per feature); TERMINAL features depend on flow completion or full-history statistics. This classification is per *feature*, evaluated on the full flow row; early-window variants (1/3/5 s) must recompute ONLINE features over packets with `t ≤ flow_start + W` only — no future packets.
- **Timestamp boundary for early windows:** all ONLINE features in a window W use packets with `start_ts ≤ t ≤ start_ts + W` exclusively.
- All features are computed per flow and stored as float32; every emitted value passes a NaN/inf guard (non-finite → 0.0, counted in extraction stats).

## Availability summary

| # | Feature | Type | Units | ONLINE boundary |
|---|---------|------|-------|-----------------|
| 1 | `protocol` | ONLINE | nominal (IANA number) | from packet 1 |
| 2 | `flow_duration_s` | TERMINAL | s | — |
| 3 | `fwd_packets` | ONLINE | count | ≥1 fwd pkt |
| 4 | `bwd_packets` | ONLINE | count | ≥1 bwd pkt |
| 5 | `fwd_bytes` | ONLINE | bytes (L2) | ≥1 fwd pkt |
| 6 | `bwd_bytes` | ONLINE | bytes (L2) | ≥1 bwd pkt |
| 7 | `fwd_len_max` | ONLINE | bytes | ≥1 fwd pkt |
| 8 | `fwd_len_min` | ONLINE | bytes | ≥1 fwd pkt |
| 9 | `fwd_len_mean` | ONLINE | bytes | ≥1 fwd pkt |
| 10 | `fwd_len_std` | ONLINE | bytes | ≥2 fwd pkts |
| 11 | `bwd_len_max` | ONLINE | bytes | ≥1 bwd pkt |
| 12 | `bwd_len_min` | ONLINE | bytes | ≥1 bwd pkt |
| 13 | `bwd_len_mean` | ONLINE | bytes | ≥1 bwd pkt |
| 14 | `bwd_len_std` | ONLINE | bytes | ≥2 bwd pkts |
| 15 | `pkt_len_max` | ONLINE | bytes | ≥1 pkt |
| 16 | `pkt_len_min` | ONLINE | bytes | ≥1 pkt |
| 17 | `pkt_len_mean` | ONLINE | bytes | ≥1 pkt |
| 18 | `pkt_len_std` | ONLINE | bytes | ≥2 pkts |
| 19 | `flow_iat_mean` | ONLINE | s | ≥2 pkts |
| 20 | `flow_iat_std` | ONLINE | s | ≥3 pkts |
| 21 | `flow_iat_max` | ONLINE | s | ≥2 pkts |
| 22 | `flow_iat_min` | ONLINE | s | ≥2 pkts |
| 23 | `fwd_iat_total` | ONLINE | s | ≥1 fwd pkt |
| 24 | `fwd_iat_mean` | ONLINE | s | ≥2 fwd pkts |
| 25 | `fwd_iat_std` | ONLINE | s | ≥3 fwd pkts |
| 26 | `fwd_iat_max` | ONLINE | s | ≥2 fwd pkts |
| 27 | `fwd_iat_min` | ONLINE | s | ≥2 fwd pkts |
| 28 | `bwd_iat_total` | ONLINE | s | ≥1 bwd pkt |
| 29 | `bwd_iat_mean` | ONLINE | s | ≥2 bwd pkts |
| 30 | `bwd_iat_std` | ONLINE | s | ≥3 bwd pkts |
| 31 | `bwd_iat_max` | ONLINE | s | ≥2 bwd pkts |
| 32 | `bwd_iat_min` | ONLINE | s | ≥2 bwd pkts |
| 33 | `fwd_psh` | ONLINE | count | ≥1 TCP fwd pkt |
| 34 | `bwd_psh` | ONLINE | count | ≥1 TCP bwd pkt |
| 35 | `fwd_urg` | ONLINE | count | ≥1 TCP fwd pkt |
| 36 | `bwd_urg` | ONLINE | count | ≥1 TCP bwd pkt |
| 37 | `fin_count` | ONLINE | count | ≥1 TCP pkt |
| 38 | `syn_count` | ONLINE | count | ≥1 TCP pkt |
| 39 | `rst_count` | ONLINE | count | ≥1 TCP pkt |
| 40 | `psh_count` | ONLINE | count | ≥1 TCP pkt |
| 41 | `ack_count` | ONLINE | count | ≥1 TCP pkt |
| 42 | `urg_count` | ONLINE | count | ≥1 TCP pkt |
| 43 | `ece_count` | ONLINE | count | ≥1 TCP pkt |
| 44 | `cwr_count` | ONLINE | count | ≥1 TCP pkt |
| 45 | `fwd_header_bytes` | ONLINE | bytes | ≥1 fwd pkt |
| 46 | `bwd_header_bytes` | ONLINE | bytes | ≥1 bwd pkt |
| 47 | `down_up_ratio` | ONLINE | ratio | ≥1 fwd pkt |
| 48 | `avg_pkt_size` | ONLINE | bytes | ≥1 pkt |
| 49 | `avg_fwd_seg` | ONLINE | bytes | ≥1 fwd pkt |
| 50 | `avg_bwd_seg` | ONLINE | bytes | ≥1 bwd pkt |
| 51 | `init_fwd_win` | ONLINE | TCP window | first fwd TCP pkt |
| 52 | `init_bwd_win` | ONLINE | TCP window | first bwd TCP pkt |
| 53 | `fwd_data_pkts` | ONLINE | count | ≥1 fwd pkt w/ payload |
| 54 | `bwd_data_pkts` | ONLINE | count | ≥1 bwd pkt w/ payload |
| 55 | `active_mean` | TERMINAL | s | — |
| 56 | `active_std` | TERMINAL | s | — |
| 57 | `active_max` | TERMINAL | s | — |
| 58 | `active_min` | TERMINAL | s | — |
| 59 | `idle_mean` | TERMINAL | s | — |
| 60 | `idle_std` | TERMINAL | s | — |
| 61 | `idle_max` | TERMINAL | s | — |
| 62 | `idle_min` | TERMINAL | s | — |
| 63 | `flow_bytes_s` | ONLINE | bytes/s | ≥2 pkts |
| 64 | `flow_packets_s` | ONLINE | pkts/s | ≥2 pkts |
| 65 | `fwd_win_mean` | ONLINE | TCP window | ≥1 TCP fwd pkt |
| 66 | `bwd_win_mean` | ONLINE | TCP window | ≥1 TCP bwd pkt |

## Exact definitions

All statistics use running sum/sum-of-squares accumulators (float64 internally, float32 on write). `std` is the sample standard deviation (ddof=1); 0.0 when fewer than 2 observations. Ratios use safe division (0.0 when denominator is 0).

### Identity & timing
1. **`protocol`** — IP protocol number from the IPv4 header (`ihl`-independent, byte 9). Units: nominal. ONLINE: packet 1.
2. **`flow_duration_s`** — `end_ts − start_ts` of the flow (last packet − first packet, wall-clock from pcap timestamps). TERMINAL.
3. **`fwd_packets` / `bwd_packets`** — count of packets per direction. ONLINE: ≥1 packet in that direction.
4. **`fwd_bytes` / `bwd_bytes`** — Σ `incl_len` per direction (captured L2 frame bytes). ONLINE: ≥1 packet in that direction.

### Packet-length statistics (per direction and pooled)
5–18. **`fwd_len_*`, `bwd_len_*`, `pkt_len_*`** — max / min / mean / sample-std of captured frame lengths, computed separately per direction and pooled. ONLINE: ≥1 (mean/max/min) or ≥2 (std) packets in scope.

### Inter-arrival times
19–22. **`flow_iat_*`** — IAT = `t_i − t_{i−1}` over all packets of the flow in capture order; mean/std/max/min. ONLINE: ≥2 (mean/max/min) or ≥3 (std) packets.
23–32. **`fwd_iat_*`, `bwd_iat_*`** — same, restricted to per-direction packet sequences. `fwd_iat_total` = `last_fwd_ts − start_ts` (span, not Σ IAT); `bwd_iat_total` = `last_bwd_ts − start_ts`. ONLINE boundaries per direction as above.

### TCP flag counts
33–44. **`fwd_psh`, `bwd_psh`, `fwd_urg`, `bwd_urg`** — per-direction PSH/URG counts (TCP only). **`fin_count` … `cwr_count`** — both-direction counts of FIN/SYN/RST/PSH/ACK/URG/ECE/CWR. Flags read from TCP header byte 13 (`data offset<<4 | flags`). UDP/ICMP flows: all TCP flag features = 0. ONLINE: ≥1 TCP packet in scope.

### Header & payload structure
45–46. **`fwd_header_bytes` / `bwd_header_bytes`** — Σ (IPv4 header length + L4 header length) per direction. IPv4 header length = `ihl×4`; L4 = TCP data-offset×4, UDP 8, ICMP 8. ONLINE: ≥1 packet in that direction.
47. **`down_up_ratio`** — `bwd_packets / fwd_packets` (0.0 if no forward packets). ONLINE: ≥1 fwd pkt.
48. **`avg_pkt_size`** — `(fwd_bytes + bwd_bytes) / (fwd_packets + bwd_packets)`. ONLINE: ≥1 pkt.
49. **`avg_fwd_seg`** — `fwd_bytes / fwd_packets`. **`avg_bwd_seg`** — `bwd_bytes / bwd_packets` (0.0 if no bwd packets). ONLINE: ≥1 pkt in that direction.
51–52. **`init_fwd_win` / `init_bwd_win`** — TCP window of the first forward / first backward packet (0 for non-TCP or absent direction). ONLINE: first packet in that direction.
53–54. **`fwd_data_pkts` / `bwd_data_pkts`** — packets with `payload_len = max(ip_total − ihl×4 − l4_hdr_len, 0) > 0`. ONLINE: ≥1 such packet in that direction.

### Active/idle periods (TERMINAL)
55–62. **`active_*` / `idle_*`** — the flow timeline is split at every IAT > 1.0 s (`IDLE_GAP_S`): a run of consecutive IAT ≤ 1 s forms an *active period* (length = sum of those IATs); each IAT > 1 s forms an *idle gap*. `active_mean/std/max/min` and `idle_mean/std/max/min` are statistics over those period lengths. Both are 0.0 when no such periods exist. TERMINAL: the full flow timeline is required (an "active" period can only be confirmed closed by a later idle gap or flow end).
63. **`flow_bytes_s`** — `(fwd_bytes + bwd_bytes) / flow_duration_s` (0.0 if duration = 0). ONLINE: ≥2 pkts (needs a non-zero duration).
64. **`flow_packets_s`** — `(fwd_packets + bwd_packets) / flow_duration_s` (0.0 if duration = 0). ONLINE: ≥2 pkts.
65–66. **`fwd_win_mean` / `bwd_win_mean`** — mean TCP window over the direction's packets (0.0 for non-TCP). ONLINE: ≥1 TCP packet in that direction.

## Early-detection windows (1 s / 3 s / 5 s)

For window W ∈ {1, 3, 5} s, ONLINE features are recomputed over packets with `start_ts ≤ t ≤ start_ts + W`. TERMINAL features are excluded from early-window mode (they are replaced by their ONLINE counterparts where meaningful). No future packets are used: the boundary is exclusive of `start_ts + W + ε`.

## Leakage policy (explicit)

- `src_ip`, `dst_ip`, `src_port`, `dst_port`, `start_ts`, `end_ts`, `capture_file`, `flow_id`, `family`, `binary_label`, `n_packets`, `ended_by` are **metadata only** — never model features. Ports and IPs would encode capture identity (e.g. "same port vs random port" UDP variants) and are excluded.
- Flow rows are grouped by `capture_file` for all splits; a capture never spans splits.
- The dataset's mirrored-duplicate frames (plain + 802.1Q copies) were removed at extraction (2 µs identity window); no duplicate flow rows exist (verified: 0 exact duplicates in 1,236,285 rows).

## Metadata columns

| Column | Meaning |
|---|---|
| `capture_file` | source pcap filename (group key for splits) |
| `flow_id` | `proto\|src\|sport\|dst\|dport` |
| `family` | attack family / benign (12 classes) |
| `binary_label` | `benign` / `attack` |
| `src_ip`, `dst_ip`, `src_port`, `dst_port` | endpoint metadata (never features) |
| `start_ts`, `end_ts` | absolute flow times (epoch s, float64) |
| `n_packets` | total packets in flow |
| `ended_by` | `timeout` \| `capture_end` \| `packet_cap` \| `activity_cap` \| `sweep_forced` |
