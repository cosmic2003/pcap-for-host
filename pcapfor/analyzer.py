"""분석 오케스트레이터.

파일 읽기 -> 디코딩 -> 세션/재조립 -> 프로토콜 추출(DNS/HTTP/FTP) -> 탐지 순으로
돌리고, 결과를 AnalysisResult 하나에 담는다. 증거 무결성을 위해 입력 파일의
SHA-256 을 기록하고 모든 시각은 UTC 로 다룬다.
"""
from __future__ import annotations

import hashlib
import os
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone

from . import detect, dnsparse, httpparse
from .layers import decode
from .pcapio import read_packets
from .sessions import SessionTable


@dataclass
class AnalysisData:
    """탐지기들이 공유하는 중간 산출물."""
    sessions: list = field(default_factory=list)
    http_transactions: list = field(default_factory=list)  # [(Session, HttpTransaction)]
    ftp_streams: list = field(default_factory=list)        # [(Session, c2s, s2c)]
    smtp_streams: list = field(default_factory=list)       # [(Session, c2s, s2c)]
    telnet_streams: list = field(default_factory=list)     # [(Session, c2s, s2c)]
    dns_messages: list = field(default_factory=list)       # [(질의 호스트 IP, DnsMessage, ts)]
    arp_records: list = field(default_factory=list)        # [(ts, Arp)]


@dataclass
class AnalysisResult:
    path: str
    sha256: str
    analyzed_at: str            # ISO 8601 UTC
    packet_count: int = 0
    byte_count: int = 0
    first_ts: float = 0.0
    last_ts: float = 0.0
    protocol_counts: Counter = field(default_factory=Counter)
    timeline: Counter = field(default_factory=Counter)  # int(ts) -> 패킷 수 (GUI 차트용)
    top_talkers: list = field(default_factory=list)   # [(ip, packets)]
    data: AnalysisData = field(default_factory=AnalysisData)
    findings: list = field(default_factory=list)

    @property
    def duration(self) -> float:
        return max(0.0, self.last_ts - self.first_ts)

    @property
    def max_severity(self) -> str:
        return self.findings[0].severity if self.findings else "none"

    def severity_counts(self) -> Counter:
        return Counter(f.severity for f in self.findings)


def _sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def analyze(path: str, ioc_path: str | None = None) -> AnalysisResult:
    result = AnalysisResult(
        path=os.path.abspath(path),
        sha256=_sha256(path),
        analyzed_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
    )
    data = result.data
    table = SessionTable()
    talkers: Counter = Counter()

    for raw in read_packets(path):
        pkt = decode(raw)
        if pkt is None:
            continue
        result.packet_count += 1
        result.byte_count += raw.orig_len
        if result.first_ts == 0.0:
            result.first_ts = pkt.ts
        result.last_ts = max(result.last_ts, pkt.ts)
        result.timeline[int(pkt.ts)] += 1

        if pkt.arp:
            result.protocol_counts["arp"] += 1
            data.arp_records.append((pkt.ts, pkt.arp))
            continue
        if not pkt.src:
            result.protocol_counts["l2-other"] += 1
            continue
        talkers[pkt.src] += 1
        result.protocol_counts[pkt.proto or "other"] += 1

        table.feed(pkt)

        # DNS: 포트 53 UDP. 응답이면 질의 호스트는 패킷의 목적지다.
        if pkt.proto == "udp" and 53 in (pkt.sport, pkt.dport) and pkt.payload:
            msg = dnsparse.parse(pkt.payload)
            if msg is not None and (msg.questions or msg.answers):
                querier = pkt.dst if msg.is_response else pkt.src
                data.dns_messages.append((querier, msg, pkt.ts))

    data.sessions = table.sessions
    result.top_talkers = talkers.most_common(10)

    # TCP 재조립 후 상위 프로토콜 추출
    for s in table.sessions:
        if s.proto != "tcp":
            continue
        c2s = s.stream(c2s=True)
        s2c = s.stream(c2s=False)
        if not c2s and not s2c:
            continue
        banner = s2c[:200].upper()
        # SMTP 를 먼저 판별한다 (ESMTP 배너에 "FTP"가 부분 문자열로 들어가므로)
        if s.sport == 23:
            data.telnet_streams.append((s, c2s, s2c))
        elif s.sport in (25, 587) or (s2c.startswith(b"220") and b"SMTP" in banner):
            data.smtp_streams.append((s, c2s, s2c))
        elif s.sport == 21 or (s2c.startswith(b"220 ") and b"FTP" in banner):
            data.ftp_streams.append((s, c2s, s2c))
        elif httpparse.looks_like_http(c2s):
            for tx in httpparse.parse_transactions(c2s, s2c):
                data.http_transactions.append((s, tx))

    result.findings = detect.run_all(data, ioc_path)
    return result
