"""실시간 탐지 모드 (패킷 모드 전용).

관리자 권한 세션에서 Windows raw socket(SIO_RCVALL)으로 이 호스트의 IPv4
패킷을 수신해, 파일 분석과 동일한 파이프라인(디코딩→세션→재조립→탐지)을
주기적으로 돌린다. 받은 패킷은 LINKTYPE_RAW_IP pcap으로 저장해 증거를 남길 수 있다.

제약: 관리자 권한 필수(미승격이면 즉시 종료), 이더넷/ARP 계층이 없어
ARP 스푸핑 탐지는 불가, 루프백 트래픽 제외, 기본 라우트 인터페이스의 IPv4만 수신.
"""
from __future__ import annotations

import ctypes
import socket
import threading
import time
from collections import Counter

from . import detect, dnsparse, httpparse
from .detect import Finding
from .analyzer import AnalysisData
from .layers import decode
from .pcapio import LINKTYPE_RAW_IP, PcapWriter, RawPacket
from .report import SEV_KO
from .sessions import SessionTable


def is_elevated() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


def default_iface_ip() -> str:
    """기본 라우트가 쓰는 로컬 IP (UDP connect 트릭, 패킷은 나가지 않음)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 53))
        return s.getsockname()[0]
    finally:
        s.close()


def _print_finding(f: Finding) -> None:
    stamp = time.strftime("%H:%M:%S")
    print(f"\n[{stamp}] [!] ({SEV_KO[f.severity]}/{f.category}) {f.title}")
    print(f"           {f.description}")
    for ev in f.evidence[:3]:
        print(f"           증거: {ev}")


class PacketCapture:
    """SIO_RCVALL raw socket 캡처. with 문으로 열고 닫는다."""

    def __init__(self, iface_ip: str | None = None):
        self.iface_ip = iface_ip or default_iface_ip()
        self._sock = None

    def __enter__(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        s.bind((self.iface_ip, 0))
        s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        s.settimeout(1.0)  # Ctrl+C가 먹히도록 주기적으로 깨어난다
        self._sock = s
        return self

    def __exit__(self, *exc):
        if self._sock is not None:
            try:
                self._sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            except OSError:
                pass
            self._sock.close()

    def recv(self) -> bytes | None:
        try:
            return self._sock.recv(65535)
        except socket.timeout:
            return None


class LiveEngine:
    """패킷을 들어오는 대로 적재하고, sweep() 호출 시 새 탐지만 돌려준다.

    파일 분석(analyzer.analyze)과 같은 자료구조를 쓰므로 탐지기는 그대로 재사용된다.
    소켓 없이 ingest()에 패킷을 직접 넣어도 동작한다.
    """

    def __init__(self, ioc_path: str | None = None):
        self.data = AnalysisData()
        self.table = SessionTable()
        self.ioc_path = ioc_path
        self.packet_count = 0
        self.byte_count = 0
        self.timeline: Counter = Counter()   # int(ts) -> 패킷 수
        self.started_at = time.time()
        self.findings: list[Finding] = []    # 지금까지 보고된 탐지(누적)
        self.lock = threading.Lock()         # GUI 서버 스레드와 공유 보호
        self._seen: set[tuple[str, str]] = set()

    def ingest(self, raw: RawPacket) -> None:
        pkt = decode(raw)
        if pkt is None or not pkt.src:
            return
        with self.lock:
            self.packet_count += 1
            self.byte_count += raw.orig_len
            self.timeline[int(raw.ts)] += 1
            self.table.feed(pkt)
            if pkt.proto == "udp" and 53 in (pkt.sport, pkt.dport) and pkt.payload:
                msg = dnsparse.parse(pkt.payload)
                if msg is not None and (msg.questions or msg.answers):
                    querier = pkt.dst if msg.is_response else pkt.src
                    self.data.dns_messages.append((querier, msg, raw.ts))

    def sweep(self) -> list[Finding]:
        with self.lock:
            return self._sweep_locked()

    def _sweep_locked(self) -> list[Finding]:
        # 세션에서 HTTP/FTP 추출을 다시 계산 (라이브 중엔 스트림이 계속 자란다)
        self.data.sessions = self.table.sessions
        self.data.http_transactions = []
        self.data.ftp_streams = []
        self.data.smtp_streams = []
        self.data.telnet_streams = []
        for s in self.table.sessions:
            if s.proto != "tcp":
                continue
            c2s = s.stream(c2s=True)
            s2c = s.stream(c2s=False)
            if not c2s and not s2c:
                continue
            banner = s2c[:200].upper()
            if s.sport == 23:
                self.data.telnet_streams.append((s, c2s, s2c))
            elif s.sport in (25, 587) or (s2c.startswith(b"220") and b"SMTP" in banner):
                self.data.smtp_streams.append((s, c2s, s2c))
            elif s.sport == 21 or (s2c.startswith(b"220 ") and b"FTP" in banner):
                self.data.ftp_streams.append((s, c2s, s2c))
            elif httpparse.looks_like_http(c2s):
                for tx in httpparse.parse_transactions(c2s, s2c):
                    self.data.http_transactions.append((s, tx))
        fresh = []
        for f in detect.run_all(self.data, self.ioc_path):
            key = (f.category, f.title)
            if key not in self._seen:
                self._seen.add(key)
                fresh.append(f)
                self.findings.append(f)
        return fresh


def run_live(duration: float, sweep_sec: float, ioc_path: str | None,
             save_path: str | None, gui: bool = False) -> int:
    print("pcap-for :: 실시간 탐지")
    print("[주의] 본인 소유/관리 호스트의 트래픽 모니터링 용도로만 사용하세요.\n")
    if not is_elevated():
        print("오류: 실시간 모드는 관리자 권한 세션이 필요합니다.")
        print("터미널을 '관리자 권한으로 실행'으로 연 뒤 다시 실행하세요.")
        return 1

    engine = LiveEngine(ioc_path)
    writer = PcapWriter(save_path, LINKTYPE_RAW_IP) if save_path else None
    server = None
    with PacketCapture() as cap:
        print(f"{cap.iface_ip} 인터페이스 감시 시작 "
              f"(탐지 스윕 {sweep_sec:.0f}초 주기, Ctrl+C 종료)")
        if gui:
            import webbrowser
            from .gui import start_live_server
            server, url = start_live_server(engine, cap.iface_ip)
            print(f"라이브 GUI: {url}")
            webbrowser.open(url)
        start = last_sweep = time.time()
        number = 0
        try:
            while True:
                now = time.time()
                if duration and now - start >= duration:
                    break
                data = cap.recv()
                if data:
                    number += 1
                    ts = time.time()
                    engine.ingest(RawPacket(ts, data, len(data), LINKTYPE_RAW_IP, number))
                    if writer:
                        writer.write(ts, data)
                if now - last_sweep >= sweep_sec:
                    last_sweep = now
                    for f in engine.sweep():
                        _print_finding(f)
                    print(f"  … 패킷 {engine.packet_count:,} / 세션 {len(engine.table.sessions)}",
                          end="\r")
        except KeyboardInterrupt:
            print("\n중단됨 - 최종 스윕 실행")
        for f in engine.sweep():
            _print_finding(f)
        if writer:
            writer.close()
            print(f"\n증거 pcap 저장: {save_path} ({writer.count:,} packets) - "
                  f"파일 모드로 재분석 가능")
    if server is not None:
        server.shutdown()

    n = len(engine._seen)
    print(f"\n종료 - 누적 탐지 {n}건")
    return 2 if n else 0
