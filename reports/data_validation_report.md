# Data Validation Report

Files: 45 · Rows: 1,236,285 · Exact duplicate feature rows: 31,243

Features constant in every capture: ['fwd_urg', 'bwd_urg', 'urg_count', 'ece_count', 'cwr_count']
Features constant within ≥1 capture: 31

Cross-capture identical sampled feature vectors:
- tcp syn fast_1st.pcap ↔ tcp syn fast_2nd.pcap: 1694
- tcp syn fast_2nd.pcap ↔ tcp syn fast_3rd.pcap: 1332
- tcp syn fast_1st.pcap ↔ tcp syn fast_3rd.pcap: 1323
- tcp syn fast_3rd.pcap ↔ tcp syn low_1st.pcap: 1220
- tcp syn fast_2nd.pcap ↔ tcp syn low_1st.pcap: 991
- tcp syn fast_1st.pcap ↔ tcp syn low_1st.pcap: 969
- tcp syn fast_2nd.pcap ↔ tcp syn low_2nd.pcap: 887
- tcp syn fast_1st.pcap ↔ tcp syn low_2nd.pcap: 881
- tcp syn fast_3rd.pcap ↔ tcp syn low_2nd.pcap: 747
- tcp syn low_1st.pcap ↔ tcp syn low_2nd.pcap: 541
- flash traffic_with_r.pcap ↔ flash traffic_without r.pcap: 14
- slow read_1st.pcap ↔ slow read_2nd.pcap: 4
- flash traffic_with_r.pcap ↔ http flood get_2nd.pcap: 2
- flash traffic_with_r.pcap ↔ http flood post_2nd.pcap: 2
- flash traffic_with_r.pcap ↔ http flood_random.pcap: 2

Hard failures: NONE

Warnings: flash traffic_with_r.pcap: 1801 exact duplicate feature rows; flash traffic_without r.pcap: 1928 exact duplicate feature rows; http flood get_2nd.pcap: 101 exact duplicate feature rows; http flood post_2nd.pcap: 78 exact duplicate feature rows; http flood_random.pcap: 74 exact duplicate feature rows; slow read_1st.pcap: 92 exact duplicate feature rows; slow read_2nd.pcap: 73 exact duplicate feature rows; tcp syn fast_1st.pcap: 4996 exact duplicate feature rows; tcp syn fast_2nd.pcap: 4780 exact duplicate feature rows; tcp syn fast_3rd.pcap: 5512 exact duplicate feature rows