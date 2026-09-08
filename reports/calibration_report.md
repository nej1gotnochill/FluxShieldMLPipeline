# Calibration & Threshold Report (STEPS 10-11)

**Model:** `extra_trees` · **Calibrator:** sigmoid · **Calibration data:** A-2 fold(s) [5] validation captures (5 captures, 173,678 flows) · final test untouched

| Calibrator | Brier | ECE |
|---|---:|---:|
| uncalibrated | 0.000034 | 0.000221 |
| isotonic | 0.000010 | 0.000000 |
| sigmoid | 0.000013 | 0.000028 |

## Threshold candidates (calibration fold only)

| Point | Threshold | Precision | Recall | F1 | FPR | FNR |
|---|---:|---:|---:|---:|---:|---:|
| t_f1 (0.7620) | 0.761958 | 1.0000 | 1.0000 | 1.0000 | 0.00000 | 0.00001 |
| t_fpr (0.5074) | 0.507384 | 1.0000 | 1.0000 | 1.0000 | 0.00085 | 0.00001 |
| t_youden (0.7620) | 0.761958 | 1.0000 | 1.0000 | 1.0000 | 0.00000 | 0.00001 |
| t_op (0.5000) | 0.500000 | 1.0000 | 1.0000 | 1.0000 | 0.00085 | 0.00001 |

FPR target for t_fpr: 0.001
