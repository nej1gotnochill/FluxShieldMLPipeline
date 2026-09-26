# Final Test Report (STEP 12) — untouched May 4-6 captures

**Flows:** 448,076 (5,555 benign / 442,521 attack) · **Captures:** 17 · **Threshold:** 0.500000 (frozen, validated op point) · **Calibrator:** sigmoid

| Metric | Value |
|---|---:|
| Precision | 1.0000 |
| Recall | 0.9978 |
| F1 | 0.9989 |
| PR-AUC | 1.0000 |
| ROC-AUC | 1.0000 |
| FPR | 0.00018 (1 of 5,555 benign) |
| FNR | 0.00215 (952 of 442,521 attack) |
| Confusion (tn, fp, fn, tp) | 5,554, 1, 952, 441,569 |

## Per attack family

| Family | Flows | Recall | Mean proba |
|---|---:|---:|---:|
| benign | 5,555 | 0.0002 | 0.0003 |
| flash_traffic | 224,836 | 0.9970 | 0.9970 |
| http_flood | 116,501 | 0.9978 | 0.9978 |
| http_low_rate | 9,597 | 0.9998 | 0.9998 |
| http_slow_body | 11,074 | 0.9999 | 0.9999 |
| http_slow_header | 10,660 | 0.9999 | 0.9999 |
| http_slow_read | 21,826 | 1.0000 | 1.0000 |
| tcp_syn_fast | 32,010 | 0.9998 | 0.9998 |
| tcp_syn_low | 16,017 | 0.9998 | 0.9998 |

## Per capture

| Capture | Family | Flows | Recall | FPR |
|---|---|---:|---:|---:|
| Constant Packet size and mix IDP_1-3.pcap | benign | 238 | 0.0000 | 0.00420 |
| flash traffic_with_r.pcap | flash_traffic | 111,148 | 0.9969 | nan |
| flash traffic_without r.pcap | flash_traffic | 113,688 | 0.9970 | nan |
| http flood get_2nd.pcap | http_flood | 41,354 | 0.9975 | nan |
| http flood post_2nd.pcap | http_flood | 39,027 | 0.9980 | nan |
| http flood_random.pcap | http_flood | 36,120 | 0.9979 | nan |
| http low rate_2nd.pcap | http_low_rate | 4,798 | 0.9998 | nan |
| http low rate_3rd.pcap | http_low_rate | 4,799 | 0.9998 | nan |
| httperf_2nd.pcap | benign | 5,317 | 0.0000 | 0.00000 |
| slow header_2nd.pcap | http_slow_header | 5,328 | 0.9998 | nan |
| slow header_3rd.pcap | http_slow_header | 5,332 | 1.0000 | nan |
| slow read_2nd.pcap | http_slow_read | 21,826 | 1.0000 | nan |
| slowbody_2nd.pcap | http_slow_body | 5,330 | 0.9998 | nan |
| slowbody_3rd.pcap | http_slow_body | 5,744 | 1.0000 | nan |
| tcp syn fast_2nd.pcap | tcp_syn_fast | 16,005 | 0.9998 | nan |
| tcp syn fast_3rd.pcap | tcp_syn_fast | 16,005 | 0.9998 | nan |
| tcp syn low_2nd.pcap | tcp_syn_low | 16,017 | 0.9998 | nan |

Inference: 500878 flows/s, latency median 45.90 ms / p95 56.44 ms
