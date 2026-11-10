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

    def __init__(self, ioc_path: str | None = None, hostmon=None):
        self.hostmon = hostmon               # HostMonitor (프로세스 귀속·프로파일). 없으면 기존 동작
        self.new_events: list = []           # 마지막 스윕에서 새로 생긴 호스트 이벤트
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
            sess = self.table.feed(pkt)
            if self.hostmon is not None:
                self.hostmon.on_packet(pkt, sess)
            if pkt.proto == "udp" and 53 in (pkt.sport, pkt.dport) and pkt.payload:
                msg = dnsparse.parse(pkt.payload)
                if msg is not None and (msg.questions or msg.answers):
                    querier = pkt.dst if msg.is_response else pkt.src
                    self.data.dns_messages.append((querier, msg, raw.ts))

    def sweep(self, now: float | None = None) -> list[Finding]:
        """새 탐지(Finding)를 돌려준다. 호스트 이벤트는 self.new_events 에 담긴다."""
        with self.lock:
            return self._sweep_locked(time.time() if now is None else now)

    def _sweep_locked(self, now: float) -> list[Finding]:
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
        all_findings = detect.run_all(self.data, self.ioc_path)
        for f in all_findings:
            key = (f.category, f.title)
            if key not in self._seen:
                self._seen.add(key)
                fresh.append(f)
                self.findings.append(f)
        self.new_events = (self.hostmon.sweep(self.data, all_findings, now)
                           if self.hostmon is not None else [])
        return fresh


def _print_event(e) -> None:
    stamp = time.strftime("%H:%M:%S", time.localtime(e.ts))
    if e.points:
        print(f"\n[{stamp}] [+{e.points} → 위험도 {e.risk:.0f} {e.level}] "
              f"{e.proc_name}(PID {e.pid}) {e.text}  <{e.certainty}>")
    elif e.code == "block_suggest":
        print(f"\n[{stamp}] [!!] {e.proc_name}(PID {e.pid}) {e.text}")


def _write_outputs(engine, blocker, host_ip: str, events_path: str | None,
                   report_path: str | None, save_path: str | None = None,
                   saved_packets: int = 0) -> dict:
    import hashlib
    import json
    import os
    from .incident_report import write_report
    from .ledger import build_doc
    ev_pcap = None
    if save_path and os.path.exists(save_path):
        h = hashlib.sha256()
        with open(save_path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        ev_pcap = {"path": os.path.abspath(save_path), "sha256": h.hexdigest(), "packets": saved_packets}
    doc = build_doc(engine, blocker, now=time.time(), host_ip=host_ip, evidence_pcap=ev_pcap)
    doc["events"] = [e.to_dict() for e in engine.hostmon.timeline.events]
    if events_path:
        with open(events_path, "w", encoding="utf-8") as f:
            json.dump(doc, f, ensure_ascii=False, indent=1)
        print(f"이벤트·사건 저장: {events_path}")
    if report_path and doc["incidents"]:
        write_report(doc, report_path)
        print(f"사고 보고서: {report_path} (브라우저에서 Ctrl+P → PDF로 저장)")
    return doc


HELP_CMDS = ("명령: approve N / deny N / unblock N / kill N / list / rollback / help "
             "(입력 후 Enter)")


def _stdin_reader(q) -> None:
    import sys
    for line in sys.stdin:
        q.put(line.strip())


def _handle_command(cmd: str, blocker, resolver, now: float) -> None:
    parts = cmd.split()
    if not parts:
        return
    op, arg = parts[0].lower(), (parts[1] if len(parts) > 1 else "")
    try:
        if op in ("approve", "a", "y"):
            b = blocker.approve(int(arg), now)
            print(f"  → {blocker.describe(b)}" + (f" / 오류: {b.error}" if b.error else ""))
        elif op in ("deny", "n"):
            print(f"  → {blocker.describe(blocker.deny(int(arg), now))}")
        elif op == "unblock":
            print(f"  → {blocker.describe(blocker.unblock(int(arg), now))}")
        elif op == "kill":
            b = blocker.get(int(arg))
            cur = None
            if b and resolver:
                info = resolver.source.process(b.pid)
                cur = info.start_time if info else None
            print(f"  → {blocker.kill_process(int(arg), now, cur)}")
        elif op == "rollback":
            print(f"  → 해제한 차단 {blocker.rollback_all(now)}개")
        elif op == "list":
            for b in blocker.blocks:
                print("  " + blocker.describe(b))
            if not blocker.blocks:
                print("  (차단 기록 없음)")
        else:
            print("  " + HELP_CMDS)
    except (ValueError, IndexError) as exc:
        print(f"  → {exc}")


def _offer(blocker, sug, now: float) -> None:
    b = blocker.offer(sug, now)
    if b is None:
        return
    print(f"\n[차단 제안] {blocker.describe(b)}")
    for r in b.reasons[-4:]:
        print(f"    근거: {r}")
    if b.skipped:
        print(f"    제외(차단 금지 목록): {'; '.join(b.skipped)}")
    if b.status == "active":
        print("    → 자동 모드: 바로 적용됨 (실험 기능)")
    elif b.status == "failed":
        print(f"    → 적용 실패: {b.error}")
    elif b.status == "pending" and blocker.mode == "ask":
        print(f"    → 승인하려면 'approve {b.bid}', 거절하려면 'deny {b.bid}' 입력")
    elif b.status == "pending":
        print("    → 제안 모드: 직접 적용하려면 관리자 터미널에서 아래 명령 실행 (또는 --block ask)")
        for argv in blocker.add_commands(b):
            print("      " + blocker.show(argv))


def run_live(duration: float, sweep_sec: float, ioc_path: str | None,
             save_path: str | None, gui: bool = False, learn: bool = False,
             profile_path: str | None = "pcapfor_profiles.json",
             events_path: str | None = "pcapfor_events.json",
             report_path: str | None = "pcapfor_incidents.html",
             block_mode: str = "suggest", block_ttl: float = 1800.0,
             allow_path: str | None = None, dry_run: bool = False,
             keep_blocks: bool = False) -> int:
    import queue
    from .block import Blocker
    from .hostmon import HostMonitor
    from .procmap import ProcessResolver, default_source
    from .profiles import ProfileStore

    print("pcap-for :: 실시간 탐지" + (" [학습 모드]" if learn else ""))
    print("[주의] 본인 소유/관리 호스트의 트래픽 모니터링 용도로만 사용하세요.\n")
    if not is_elevated():
        print("오류: 실시간 모드는 관리자 권한 세션이 필요합니다.")
        print("터미널을 '관리자 권한으로 실행'으로 연 뒤 다시 실행하세요.")
        return 1

    store = ProfileStore(profile_path)
    if learn:
        print(f"학습 모드: 이 PC 의 평소 통신을 '{profile_path}' 에 기록합니다 (경고·차단 없음).")
        print("전제: 학습 중인 PC 가 깨끗해야 합니다. 감염 상태에서 학습하면 그 통신이 정상으로 굳습니다.")
        block_mode = "off"
    elif not store.has_baseline:
        print("알림: 학습된 프로파일이 없어 '평소 대비' 비교는 꺼집니다. 먼저 --learn 으로 학습하세요.")
    else:
        print(f"프로파일 {len(store.profiles)}개 로드 (누적 학습 {store.learning_sec / 60:.0f}분)")

    source = default_source()
    resolver = ProcessResolver(source) if source else None
    if resolver is None:
        print("알림: 이 OS 에서는 프로세스 귀속을 쓸 수 없어 모든 연결이 '미귀속'으로 기록됩니다.")

    engine = LiveEngine(ioc_path)
    writer = PcapWriter(save_path, LINKTYPE_RAW_IP) if save_path else None
    server = None
    cmds: queue.Queue = queue.Queue()
    with PacketCapture() as cap:
        hm = HostMonitor(resolver, store, local_ips={cap.iface_ip},
                         learning=learn, started_at=engine.started_at)
        engine.hostmon = hm
        allow = Blocker.load_allow_file(allow_path) if allow_path else []
        blocker = Blocker(block_mode, ttl=block_ttl, allow=allow, local_ips={cap.iface_ip},
                          dry_run=dry_run, timeline=hm.timeline)
        for b in blocker.recover(time.time()):
            print(f"이전 실행의 만료된 차단 정리: #{b.bid}")
        if block_mode != "off":
            print(f"차단 모드: {block_mode}{' (dry-run: 명령을 실행하지 않음)' if dry_run else ''} · "
                  f"TTL {block_ttl / 60:.0f}분 · 사설망/이 PC/DNS 서버는 차단 금지")
            threading.Thread(target=_stdin_reader, args=(cmds,), daemon=True).start()
            print(HELP_CMDS)
        if resolver:
            resolver.start()
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
                while not cmds.empty():
                    with engine.lock:
                        _handle_command(cmds.get(), blocker, resolver, now)
                if now - last_sweep >= sweep_sec:
                    last_sweep = now
                    for f in engine.sweep(now):
                        _print_finding(f)
                    with engine.lock:
                        for e in engine.new_events:
                            _print_event(e)
                        for ip in hm.dns_servers:
                            blocker.add_allow(ip, "DNS 서버")
                        for sug in hm.take_suggestions():
                            _offer(blocker, sug, now)
                        blocker.tick(now)
                    print(f"  … 패킷 {engine.packet_count:,} / 세션 {len(engine.table.sessions)}"
                          f" / 프로세스 {len(store.profiles)}", end="\r")
        except KeyboardInterrupt:
            print("\n중단됨 - 최종 스윕 실행")
        print()   # 진행 표시줄(\r) 뒤에 출력이 겹치지 않게
        for f in engine.sweep():
            _print_finding(f)
        for e in engine.new_events:
            _print_event(e)
        for sug in hm.take_suggestions():
            _offer(blocker, sug, time.time())
        if resolver:
            resolver.stop()
        if writer:
            writer.close()
            print(f"\n증거 pcap 저장: {save_path} ({writer.count:,} packets) - "
                  f"파일 모드로 재분석 가능")
        active = [b for b in blocker.blocks if b.status == "active"]
        if active and not keep_blocks:
            n = blocker.rollback_all(time.time())
            print(f"종료와 함께 적용 중이던 차단 {n}개 해제 (유지하려면 --keep-blocks)")
        elif active:
            print(f"적용 중인 차단 {len(active)}개 유지 — TTL 이 지나면 다음 실행 때 정리, "
                  f"즉시 해제는 'python -m pcapfor --unblock-all'")
        doc = _write_outputs(engine, blocker, cap.iface_ip, events_path, report_path,
                             save_path, writer.count if writer else 0)
    if server is not None:
        server.shutdown()

    store.forget_stale(time.time())
    store.save()
    summ = hm.summary()
    print(f"\n프로파일 저장: {profile_path} (프로세스 {summ['profiles']}개, 누적 학습 {summ['learning_min']}분)")
    if summ["attribution_rate"] is not None:
        print(f"프로세스 귀속 성공률 {summ['attribution_rate']:.0%} · 미귀속 세션 {summ['unattributed_sessions']}개"
              f" (DNS 질의 {summ['dns_sessions']}개는 OS 리졸버 몫이라 제외)")
        if summ["unattributed_by"]:
            print("  미귀속 내역: " + ", ".join(f"{k} {n}개" for k, n in summ["unattributed_by"]))
    for inc in doc["incidents"]:
        print(f"  사건 #{inc['id']} [{inc['level']}] {inc['process']['name']} - 최고 위험도 "
              f"{inc['peak_risk']:.0f}점, 의심 전송 {inc['totals']['flagged_out']:,}바이트")

    n = len(engine._seen)
    print(f"\n종료 - 누적 탐지 {n}건 · 사건 {len(doc['incidents'])}건")
    high = any(i["level"] == "높음" for i in doc["incidents"])
    return 2 if (n or high) else 0


def unblock_all() -> int:
    """--unblock-all: 이 도구가 만든 방화벽 규칙을 모두 지운다."""
    from .block import Blocker
    if not is_elevated():
        print("오류: 방화벽 규칙 삭제에는 관리자 권한이 필요합니다.")
        return 1
    b = Blocker("suggest")
    n = b.rollback_all(time.time())
    print(f"pcap-for 차단 규칙 정리 완료 (상태 파일 기준 {n}개 + 'pcapfor-block-*' 이름 규칙)")
    return 0
