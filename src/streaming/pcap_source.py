"""Read-only packet source for classic PCAP files.

Passive by construction: opens the file read-only, never transmits, never
responds. Yields immutable PacketView records carrying the L3/L4 metadata the
feature layers need (including header-grade L7 slices for DNS/TLS metadata
layers — never used for decryption).

Parser intentionally mirrors feature_engineering.process_capture (same link/
VLAN unwrap, IPv4/fragment/TCP/UDP/ICMP dissection, mirrored-duplicate
removal) so a PacketView stream reproduces the flow behaviour the frozen DDoS
model was validated on. Flow-state math itself lives in the shared Flow class.
"""
from __future__ import annotations

import socket
import struct
from collections import deque
from dataclasses import dataclass
from pathlib import Path

# --- constants shared with the validated extractor (imported, never redefined) ---
from feature_engineering import (
    DEDUP_MEMORY, DEDUP_WINDOW_US, ETH_P_8021Q, ETH_P_IP,
    MAX_HDR_BYTES, PROTO_ICMP, PROTO_TCP, PROTO_UDP,
)

CHUNK = 1 << 24          # 16 MiB read buffer (same as extractor)
L7_SLICE = 512           # header-grade L7 bytes retained for DNS/TLS metadata


@dataclass(slots=True, frozen=True)
class PacketView:
    ts: float
    incl_len: int
    proto: int
    src_b: bytes
    dst_b: bytes
    sport: int
    dport: int
    tcp_flags: int          # 0 for non-TCP
    win: int                # TCP window (0 for non-TCP)
    ip_hdr_len: int
    l4_hdr_len: int
    payload_len: int        # from IP total length (wire truth), not incl
    payload: bytes          # header-grade L7 slice (<= L7_SLICE bytes)


def src_str(b: bytes) -> str:
    try:
        return socket.inet_ntoa(b) if len(b) == 4 \
            else socket.inet_ntop(socket.AF_INET6, b)
    except (OSError, ValueError):
        return repr(b)


class PcapPacketSource:
    """Iterate one classic pcap read-only, yielding PacketView records.

    Usage:
        src = PcapPacketSource(path)
        for pkt in src:
            ...
        print(src.stats)   # after exhaustion
    """

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.stats: dict[str, int] = {
            "packets": 0, "parsed": 0, "non_ip": 0, "malformed": 0,
            "nonfirst_frag": 0, "vlan_frames": 0, "duplicates": 0,
        }

    def __iter__(self):
        stats = self.stats
        recent: deque = deque(maxlen=DEDUP_MEMORY)
        with open(self.path, "rb") as f:
            head = f.read(24)
            if head[:4] == b"\x0a\x0d\x0d\x0a":
                raise ValueError("pcapng not supported (dataset is classic pcap)")
            magic = head[:4]
            endian = ">" if magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d") else "<"
            unpack = struct.Struct(endian + "IIII").unpack_from
            buf = b""
            while True:
                chunk = f.read(CHUNK)
                if not chunk:
                    break
                buf = buf + chunk if buf else chunk
                total = len(buf)
                i = 0
                while True:
                    if i + 16 > total:
                        break
                    ts_s, ts_f, incl, _orig = unpack(buf, i)
                    if incl > (1 << 31):
                        raise ValueError(
                            f"implausible record length {incl} at packet {stats['packets']}")
                    end = i + 16 + incl
                    if end > total:
                        break
                    i = end
                    stats["packets"] += 1
                    # keep enough bytes for headers + L7 metadata slice
                    frame = bytes(buf[end - incl:end - incl + min(incl, MAX_HDR_BYTES + L7_SLICE)])
                    ts = ts_s + ts_f / 1e6

                    # -------- link / network dissection (extractor parity) -------
                    try:
                        if len(frame) < 14:
                            raise ValueError("short ethernet frame")
                        etype = (frame[12] << 8) | frame[13]
                        off = 14
                        while etype == ETH_P_8021Q:
                            if len(frame) < off + 4:
                                raise ValueError("truncated VLAN tag")
                            etype = (frame[off + 2] << 8) | frame[off + 3]
                            off += 4
                            stats["vlan_frames"] += 1
                        l3 = frame[off:]
                        if etype != ETH_P_IP:
                            stats["non_ip"] += 1
                            continue
                        if len(l3) < 20:
                            raise ValueError("short IPv4 header")
                        ip_hdr = (l3[0] & 0x0F) * 4
                        if ip_hdr < 20 or len(l3) < ip_hdr:
                            raise ValueError("bad IPv4 header length")
                        proto = l3[9]
                        ip_total = (l3[2] << 8) | l3[3]
                        frag_bits = (l3[6] << 8) | l3[7]
                        if frag_bits & 0x1FFF:      # non-first fragment
                            stats["nonfirst_frag"] += 1
                            continue
                        src_b, dst_b = l3[12:16], l3[16:20]
                    except Exception:
                        stats["malformed"] += 1
                        continue

                    # -------- transport dissection -------------------------------
                    sport = dport = win = flags = 0
                    l4_hdr = 0
                    if proto == PROTO_TCP:
                        if len(l3) < ip_hdr + 20:
                            stats["malformed"] += 1
                            continue
                        sport, dport = struct.unpack_from(">HH", l3, ip_hdr)
                        doff = (l3[ip_hdr + 12] >> 4) * 4
                        if doff < 20:
                            stats["malformed"] += 1
                            continue
                        l4_hdr = doff
                        flags = l3[ip_hdr + 13]
                        win = struct.unpack_from(">H", l3, ip_hdr + 14)[0]
                    elif proto == PROTO_UDP:
                        if len(l3) < ip_hdr + 8:
                            stats["malformed"] += 1
                            continue
                        sport, dport = struct.unpack_from(">HH", l3, ip_hdr)
                        l4_hdr = 8
                    elif proto == PROTO_ICMP:
                        l4_hdr = 8
                    payload_len = max(ip_total - ip_hdr - l4_hdr, 0)

                    # -------- mirrored-duplicate removal (extractor parity) ------
                    if proto == PROTO_TCP:
                        ident = bytes(l3[ip_hdr + 4:ip_hdr + 12])       # seq+ack
                    else:
                        p0 = ip_hdr + l4_hdr
                        ident = bytes(l3[p0:p0 + 8])
                    identity = (proto, src_b, sport, dst_b, dport, ip_total, ident)
                    ts_us = round(ts * 1e6)
                    if any(abs(ts_us - r_ts) <= DEDUP_WINDOW_US and r_id == identity
                           for r_ts, r_id in recent):
                        stats["duplicates"] += 1
                        continue
                    recent.append((ts_us, identity))

                    # -------- header-grade L7 slice for DNS/TLS metadata ---------
                    p7 = ip_hdr + l4_hdr
                    payload = l3[p7:p7 + L7_SLICE] if p7 < len(l3) else b""

                    stats["parsed"] += 1
                    yield PacketView(
                        ts=ts, incl_len=incl, proto=proto,
                        src_b=src_b, dst_b=dst_b, sport=sport, dport=dport,
                        tcp_flags=flags if proto == PROTO_TCP else 0,
                        win=win if proto == PROTO_TCP else 0,
                        ip_hdr_len=ip_hdr, l4_hdr_len=l4_hdr,
                        payload_len=payload_len, payload=payload,
                    )
