"""Netra streaming layer — passive one-way multi-threat detection service.

Modules (flat-import style, consistent with src/ conventions):
    schema       standardized AlertEvent contract (single authoritative schema)
    pcap_source  read-only classic-pcap packet iterator (no return path)
    state        bounded, TTL-expiring cross-flow state store
    windows      causal window manager over the shared Flow machinery
    metrics      internal observability counters and latency histograms
    bus          bounded event bus with drop accounting
    detectors    the six threat detectors + cross-flow Aggregator
    fusion       transparent risk fusion (weights from configuration)
    service      end-to-end loop: ingest -> window -> score -> alert -> emit
    emit         dashboard bridge writing the DATA_CONTRACT.md document

The validated offline pipeline (feature_engineering, train, calibrate,
final_test, ...) is untouched: this layer reuses its Flow/flow_to_row math
under causal windows, exactly as src/early_detection.py already does.
"""
from __future__ import annotations

import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_SRC = os.path.dirname(_HERE)
for _p in (_SRC, _HERE):
    if _p not in sys.path:
        sys.path.insert(0, _p)
