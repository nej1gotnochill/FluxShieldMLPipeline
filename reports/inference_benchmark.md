# Inference Benchmark (STEP 13)

**Model:** calibrated pipeline from `models/calibrated_model.joblib` · **Data:** untouched final test (448,076 flows, 17 captures)

| Metric | Value |
|---|---:|
| cold_start_ms | 53.801 |
| throughput_flows_s@1000 | 11414.0 |
| throughput_flows_s@10000 | 90912.0 |
| throughput_flows_s@100000 | 415575.0 |
| throughput_flows_s@full | 480513.0 |
| latency_median_ms | 49.817 |
| latency_mean_ms | 52.347 |
| latency_p95_ms | 60.353 |
| latency_p99_ms | 64.542 |
| model_size_mb | 5.3 |
| accuracy_at_operating_threshold | 0.997873 |

Operating threshold: 0.500000
