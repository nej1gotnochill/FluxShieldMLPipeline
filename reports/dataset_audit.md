# DDoS-AT-2022 — Dataset Audit Report

- Generated: 2026-09-07T18:48:59.201230+00:00
- Dataset root: local read-only copy (path configured via `DDOS_AT_DATASET_PATH`; pipeline never writes here)
- Files: **45** (37.84 GB on disk)
- Capture files (classic pcap, little-endian usec): **45** — 98,658,747 packets, 36.26 GB on wire
- Parser validation: chunked parser cross-checked against explicit sequential offset walk (`src/validate_pcap_parser.py`)
- Anomalous files (parse errors / truncation / record-header violations): **0**

## Labels (derived from capture directory taxonomy)

| Attack family (label) | Layer | Binary label | Files | Packets | GB on disk | GB on wire |
|---|---|---|---:|---:|---:|---:|
| `benign` | benign | benign | 17 | 56,900,386 | 30.15 | 29.24 |
| `http_slow_read` | application | attack | 2 | 13,827,511 | 1.96 | 1.74 |
| `udp_flood` | transport | attack | 3 | 10,865,380 | 0.91 | 0.74 |
| `http_flood` | application | attack | 5 | 6,162,843 | 3.78 | 3.68 |
| `tcp_syn_flood` | transport | attack | 1 | 4,268,670 | 0.38 | 0.31 |
| `tcp_rst` | transport | attack | 1 | 3,291,454 | 0.32 | 0.26 |
| `flash_traffic` | application | attack | 2 | 1,345,086 | 0.12 | 0.10 |
| `http_low_rate` | application | attack | 3 | 593,436 | 0.07 | 0.06 |
| `http_slow_header` | application | attack | 3 | 590,301 | 0.06 | 0.05 |
| `http_slow_body` | application | attack | 3 | 323,562 | 0.04 | 0.04 |
| `tcp_syn_fast` | transport | attack | 3 | 289,374 | 0.02 | 0.02 |
| `tcp_syn_low` | transport | attack | 2 | 200,744 | 0.02 | 0.01 |

**Packet-level class balance:** benign 56,900,386 (57.7%) vs attack 41,758,361 (42.3%).

## Per-capture inventory

| Capture file | Family | Label | Size GB | Packets | Duration (s) | Avg pkt (B) | Wire GB | Link type |
|---|---|---|---:|---:|---:|---:|---:|---|
| `Constant Packet size and mix IDP_1-1.pcap` | `benign` | benign | 1.72 | 4,118,969 | 306.4 | 401.5 | 1.65 | Ethernet |
| `Constant Packet size and mix IDP_1-2.pcap` | `benign` | benign | 1.72 | 4,118,969 | 325.4 | 401.5 | 1.65 | Ethernet |
| `Constant Packet size and mix IDP_1-3.pcap` | `benign` | benign | 1.72 | 4,118,970 | 354.1 | 401.5 | 1.65 | Ethernet |
| `Constant Packet size and exponentially distributed IDP_1-1.pcap` | `benign` | benign | 2.14 | 5,088,018 | 1105.4 | 404.3 | 2.06 | Ethernet |
| `Constant Packet size and exponentially distributed IDP_1-2.pcap` | `benign` | benign | 2.14 | 5,088,018 | 1130.5 | 404.1 | 2.06 | Ethernet |
| `Constant Packet size and IDP_1-1.pcap` | `benign` | benign | 1.26 | 2,192,413 | 192.0 | 559.1 | 1.23 | Ethernet |
| `Constant Packet size and IDP_1-2.pcap` | `benign` | benign | 1.20 | 2,192,414 | 224.0 | 532.7 | 1.17 | Ethernet |
| `Constant Packet size and IDP_2-1.pcap` | `benign` | benign | 2.11 | 3,709,286 | 430.3 | 553.6 | 2.05 | Ethernet |
| `Constant Packet size and IDP_2-2.pcap` | `benign` | benign | 2.08 | 3,709,286 | 437.1 | 543.7 | 2.02 | Ethernet |
| `Constant Packet size and IDP_2-3.pcap` | `benign` | benign | 2.06 | 3,709,286 | 370.2 | 538.3 | 2.00 | Ethernet |
| `Constant Packet size and poisson distributed IDP_1-1.pcap` | `benign` | benign | 2.16 | 3,827,676 | 426.8 | 547.6 | 2.10 | Ethernet |
| `Constant Packet size and poisson distributed IDP_1-2.pcap` | `benign` | benign | 2.16 | 3,827,675 | 421.0 | 548.7 | 2.10 | Ethernet |
| `Constant Packet size and Uniformly distributed IDP_1-1.pcap` | `benign` | benign | 2.43 | 3,527,237 | 555.8 | 674.0 | 2.38 | Ethernet |
| `Constant Packet size and Uniformly distributed IDP_1-2.pcap` | `benign` | benign | 2.44 | 3,527,237 | 558.2 | 676.1 | 2.38 | Ethernet |
| `Constant Packet size and Uniformly distributed IDP_1-3.pcap` | `benign` | benign | 2.45 | 3,527,237 | 637.8 | 678.1 | 2.39 | Ethernet |
| `httperf_1st.pcap` | `benign` | benign | 0.21 | 361,342 | 202.9 | 572.1 | 0.21 | Ethernet |
| `httperf_2nd.pcap` | `benign` | benign | 0.15 | 256,353 | 193.3 | 563.4 | 0.14 | Ethernet |
| `flash traffic_with_r.pcap` | `flash_traffic` | attack | 0.06 | 664,535 | 321.7 | 76.0 | 0.05 | Ethernet |
| `flash traffic_without r.pcap` | `flash_traffic` | attack | 0.06 | 680,551 | 326.0 | 76.0 | 0.05 | Ethernet |
| `http flood get_1st.pcap` | `http_flood` | attack | 0.56 | 925,413 | 34.1 | 584.5 | 0.54 | Ethernet |
| `http flood get_2nd.pcap` | `http_flood` | attack | 0.92 | 1,489,272 | 52.4 | 604.8 | 0.90 | Ethernet |
| `http flood post_1st.pcap` | `http_flood` | attack | 0.61 | 1,019,012 | 40.9 | 586.9 | 0.60 | Ethernet |
| `http flood post_2nd.pcap` | `http_flood` | attack | 0.87 | 1,419,529 | 57.6 | 600.0 | 0.85 | Ethernet |
| `http flood_random.pcap` | `http_flood` | attack | 0.81 | 1,309,617 | 38.8 | 601.7 | 0.79 | Ethernet |
| `http low rate_1st.pcap` | `http_low_rate` | attack | 0.02 | 197,909 | 1030.1 | 107.9 | 0.02 | Ethernet |
| `http low rate_2nd.pcap` | `http_low_rate` | attack | 0.02 | 197,222 | 1030.0 | 109.9 | 0.02 | Ethernet |
| `http low rate_3rd.pcap` | `http_low_rate` | attack | 0.02 | 198,305 | 1026.1 | 108.2 | 0.02 | Ethernet |
| `slowbody_1st.pcap` | `http_slow_body` | attack | 0.02 | 113,856 | 1840.0 | 128.2 | 0.01 | Ethernet |
| `slowbody_2nd.pcap` | `http_slow_body` | attack | 0.01 | 96,358 | 1016.3 | 119.0 | 0.01 | Ethernet |
| `slowbody_3rd.pcap` | `http_slow_body` | attack | 0.01 | 113,348 | 1813.9 | 104.7 | 0.01 | Ethernet |
| `slow header_1st.pcap` | `http_slow_header` | attack | 0.02 | 196,932 | 1026.3 | 94.3 | 0.02 | Ethernet |
| `slow header_2nd.pcap` | `http_slow_header` | attack | 0.02 | 196,568 | 1006.0 | 90.8 | 0.02 | Ethernet |
| `slow header_3rd.pcap` | `http_slow_header` | attack | 0.02 | 196,801 | 1034.0 | 90.5 | 0.02 | Ethernet |
| `slow read_1st.pcap` | `http_slow_read` | attack | 0.98 | 6,918,021 | 1812.9 | 126.1 | 0.87 | Ethernet |
| `slow read_2nd.pcap` | `http_slow_read` | attack | 0.98 | 6,909,490 | 1825.3 | 126.0 | 0.87 | Ethernet |
| `TCP-RST.pcap` | `tcp_rst` | attack | 0.32 | 3,291,454 | 45.9 | 80.0 | 0.26 | Ethernet |
| `tcp syn fast_1st.pcap` | `tcp_syn_fast` | attack | 0.01 | 96,447 | 407.2 | 62.3 | 0.01 | Ethernet |
| `tcp syn fast_2nd.pcap` | `tcp_syn_fast` | attack | 0.01 | 96,477 | 431.6 | 62.3 | 0.01 | Ethernet |
| `tcp syn fast_3rd.pcap` | `tcp_syn_fast` | attack | 0.01 | 96,450 | 416.0 | 62.3 | 0.01 | Ethernet |
| `tcp syn flood.pcap` | `tcp_syn_flood` | attack | 0.38 | 4,268,670 | 44.0 | 72.4 | 0.31 | Ethernet |
| `tcp syn low_1st.pcap` | `tcp_syn_low` | attack | 0.01 | 100,371 | 4031.5 | 64.9 | 0.01 | Ethernet |
| `tcp syn low_2nd.pcap` | `tcp_syn_low` | attack | 0.01 | 100,373 | 4029.9 | 64.9 | 0.01 | Ethernet |
| `udp flood random port.pcap` | `udp_flood` | attack | 0.34 | 4,035,627 | 26.2 | 68.0 | 0.27 | Ethernet |
| `udp flood same port.pcap` | `udp_flood` | attack | 0.29 | 3,466,408 | 30.1 | 68.0 | 0.24 | Ethernet |
| `UDP flood.pcap` | `udp_flood` | attack | 0.28 | 3,363,345 | 30.0 | 68.0 | 0.23 | Ethernet |

## Notes

- Raw material is packet captures (pcap): there are **no pre-extracted columns**. Flow-level features (CICFlowMeter-style) will be derived by the pipeline's flow meter; the flow table schema is documented in `src/feature_engineering.py`.
- Every capture file is an independent capture session -> natural group key for leakage-aware train/val/test splitting.
- Repeated runs of the same scenario (`*_1st`, `*_2nd`, `1-1/1-2`) are near-duplicate conditions; group-disjoint splitting keeps whole captures out of foreign splits.
- `packets` above are exact record counts from the validated parser (not estimates); flow-level row counts will be reported after feature extraction.
