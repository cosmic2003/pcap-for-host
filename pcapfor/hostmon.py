"""호스트 감시: 프로세스 귀속 + 프로파일 비교 + 확신도 점수 + 타임라인.

LiveEngine 이 패킷마다 on_packet() 을, 탐지 스윕마다 sweep() 을 부른다.
기존 탐지기(detect.py)는 그대로 돌고, 여기서는 그 결과를 프로세스에 붙이고
프로세스별 '평소 대비' 신호를 더해 위험도를 매긴다.

학습 모드: 점수 이벤트를 만들지 않고 프로파일(평소 모습)만 쌓는다.
감시 모드: 프로파일과 비교해 이상 신호를 점수로 만든다.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from typing import Optional

from . import behavior as B
from .evidence import EvidenceStore
from .hostid import FileIdentity, location_flags
from .procmap import UNATTRIBUTED, ProcInfo, ProcessResolver
from .profiles import MAX_TIMES, DestBaseline, ProfileStore
from .timeline import (CONFIRMED, ESTIMATED, PARTIAL, UNKNOWN, Event, Suggestion,
                       Timeline, level_of)
from .tlsparse import client_hello_sni

REFIRE_SEC = 1800.0   # 같은 (프로세스, 신호, 목적지)는 이 시간 안에 다시 알리지 않음


def _registered(name: str) -> Optional[str]:
    """도메인의 마지막 두 라벨 (IP 면 None). 공개 접미사 목록은 쓰지 않는 단순 근사."""
    parts = name.rstrip(".").split(".")
    if len(parts) < 2 or parts[-1].isdigit():
        return None
    if len(parts) >= 3 and parts[-2] in ("co", "or", "go", "ac", "ne", "com"):  # kakao.co.kr 등
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


class HostMonitor:
    def __init__(self, resolver: Optional[ProcessResolver], store: ProfileStore,
                 identity: Optional[FileIdentity] = None, local_ips=(),
                 learning: bool = False, window: float = 600.0, grace: float = 5.0,
                 started_at: float = 0.0):
        self.resolver = resolver
        self.store = store
        self.identity = identity or FileIdentity()
        self.local_ips = set(local_ips)
        self.learning = learning
        self.window = window          # 패턴 분석 창 (초)
        self.grace = grace            # 이 시간 동안은 귀속을 더 기다린다
        self.timeline = Timeline()
        self.attr: dict[int, Optional[ProcInfo]] = {}
        self.sess_proc: dict[int, str] = {}       # sid -> 프로파일 키 (보고서·피해 장부용)
        self.stats: Counter = Counter()
        self._fired: dict[tuple, float] = {}
        self._counted: dict[int, int] = {}        # sid -> 이미 반영한 업로드 바이트
        self._conn_counted: set[int] = set()
        self._names: dict[str, tuple[str, str]] = {}   # ip -> (도메인, 확신도)
        self._dns_idx = 0
        self._sni: dict[int, tuple[Optional[str], bool]] = {}
        self._context_done: set[tuple] = set()
        self._identity_done: set[str] = set()
        self._suggested: dict[str, float] = {}
        self.dest_ips: dict[tuple, set] = defaultdict(set)   # (프로세스, 목적지) -> 원격 IP
        self.proc_info: dict[str, ProcInfo] = {}            # 프로세스 키 -> 최근 ProcInfo
        self.dns_servers: set[str] = set()                   # 차단 금지 목록에 넣을 DNS 서버
        self.suggestions: list[Suggestion] = []              # 아직 차단 모듈이 안 가져간 제안
        self.dns_sessions: set[int] = set()                  # 귀속 대상에서 뺀 DNS 질의 세션
        self._sid_label: dict[int, str] = {}
        self.evidence = EvidenceStore()                      # 판단 → 원본 증거 추적용 ID
        self._last_sweep = started_at

    # ------------------------------------------------------------ 패킷 단위
    def _orient(self, s) -> Optional[tuple]:
        """(로컬 IP, 로컬 포트, 원격 IP, 원격 포트, 나가는 연결인가)."""
        if s.client in self.local_ips:
            return s.client, s.cport, s.server, s.sport, True
        if s.server in self.local_ips:
            return s.server, s.sport, s.client, s.cport, False
        if not self.local_ips:  # 로컬 IP 를 모르면 사설 대역 쪽을 로컬로 본다
            if not B.is_external(s.client) and B.is_external(s.server):
                return s.client, s.cport, s.server, s.sport, True
            if not B.is_external(s.server) and B.is_external(s.client):
                return s.server, s.sport, s.client, s.cport, False
        return None

    def on_packet(self, pkt, s) -> None:
        if s is None or self.attr.get(s.sid) is not None or not self.resolver:
            return
        o = self._orient(s)
        if o:
            first_try = s.sid not in self.attr
            info = self.resolver.resolve(s.proto, *o[:4])
            self.attr[s.sid] = info
            if info is None and first_try:
                self.resolver.wake()   # 새 연결의 첫 패킷: 끝나기 전에 테이블을 바로 다시 읽는다

    # ------------------------------------------------------------ 목적지 이름
    def _update_names(self, data) -> None:
        msgs = data.dns_messages
        for _, msg, _ in msgs[self._dns_idx:]:
            if not msg.is_response or not msg.questions:
                continue
            qname = msg.questions[0][0].rstrip(".").lower()
            for _, rtype, rdata in msg.answers:
                if rtype == "A":
                    self._names[rdata] = (qname, PARTIAL)
        self._dns_idx = len(msgs)

    def _dest(self, s, remote: str, rport: int) -> tuple[str, str, str]:
        """(프로파일 키로 쓸 목적지 이름, 표시용 문자열, 이름 확신도)."""
        if s.proto == "tcp":
            if s.sid not in self._sni and s.bytes_c2s:
                self._sni[s.sid] = client_hello_sni(s.stream(c2s=True)[:4096])
            sni, ech = self._sni.get(s.sid, (None, False))
            if sni:
                cert = ESTIMATED if ech else CONFIRMED
                note = " (ECH: 공용 이름일 수 있음)" if ech else ""
                return sni, f"{sni} [{remote}:{rport}]{note}", cert
        if remote in self._names:
            name, cert = self._names[remote]
            return name, f"{name} [{remote}:{rport}] (DNS 응답 기반)", cert
        if s.proto == "udp" and rport == 443:
            return remote, f"{remote}:{rport} (QUIC, 서버 이름 확인 불가)", UNKNOWN
        return remote, f"{remote}:{rport} (서버 이름 확인 불가)", UNKNOWN

    # ------------------------------------------------------------ 이벤트
    def _event(self, key, info, ts, code, points, text, cert=CONFIRMED, dest="",
               evidence=None, name=None, refs=None, measure=None) -> Optional[Event]:
        """refs: 근거 증거 [("net", 세션, orient, 이름) | ("host", 경로, sha, 서명상태, 서명자)
        | ("base", 목적지, DestBaseline) | ("rule", Finding)]. 이벤트가 실제로 기록될 때만 ID 를 만든다."""
        dedup = (key, code, dest)
        last = self._fired.get(dedup)
        if last is not None and ts - last < REFIRE_SEC:
            return None
        self._fired[dedup] = ts
        ids = []
        for r in refs or []:
            if r[0] == "net":
                ids.append(self.evidence.net(key, r[1], r[2], r[3]))
            elif r[0] == "host" and (r[1] or r[2]):
                ids.append(self.evidence.host(key, r[1], r[2], r[3], r[4]))
            elif r[0] == "base":
                ids.append(self.evidence.base(key, r[1], r[2]))
            elif r[0] == "rule":
                ids.append(self.evidence.rule(key, r[1]))
        ev = Event(ts=ts, proc_key=key, proc_name=name or (info.name if info else UNATTRIBUTED),
                   pid=info.pid if info else 0, code=code, text=text, points=points,
                   certainty=cert, dest=dest, evidence=list(evidence or []),
                   evidence_ids=list(dict.fromkeys(ids)), measure=dict(measure or {}))
        self.timeline.add(ev)
        if points > 0:
            prof = self.store.profiles.get(key)
            if prof is not None:
                prof.record_anomaly(ts, code, text)
        return ev

    def _capped(self, key: str, code: str, ts: float) -> int:
        """같은 종류 신호는 위험도 창 안에서 한 번만 점수를 준다 (이후는 0점 기록)."""
        for e in self.timeline.events:
            if e.proc_key == key and e.code == code and e.points > 0 \
                    and abs(ts - e.ts) < self.timeline.risk_window:
                return 0
        return B.WEIGHTS[code]

    # ------------------------------------------------------------ 스윕
    def sweep(self, data, findings, now: float) -> list[Event]:
        before = len(self.timeline.events)
        self._update_names(data)
        elapsed = max(1.0, now - self._last_sweep) if self._last_sweep else 1.0
        if self.learning and self._last_sweep:
            self.store.learning_sec += now - self._last_sweep
        self._last_sweep = now

        groups: dict[str, list] = defaultdict(list)
        for s in data.sessions:
            if s.proto == "udp" and s.sport == 53:
                self.dns_servers.add(s.server)
            o = self._orient(s)
            if not o or not B.is_external(o[2]):
                continue
            if s.proto == "udp" and o[3] == 53:
                # DNS 질의는 프로그램이 아니라 OS 리졸버(Dnscache)가 수 ms 짜리 소켓으로 대신 보낸다.
                # 프로세스 귀속·프로파일 대상에서 빼고, DNS 터널링/DGA 는 detect.py 가 따로 본다.
                self.dns_sessions.add(s.sid)
                continue
            # 핸드셰이크만 오고 첫 데이터(ClientHello)가 아직이면 목적지 이름을 모르니 기다린다
            if s.proto == "tcp" and not (s.bytes_c2s or s.bytes_s2c) \
                    and not (s.fin_seen or s.rst_seen) and now - s.first_ts < self.grace:
                continue
            info = self.attr.get(s.sid)
            linger = self.resolver.linger_sec if self.resolver else 0
            if info is None and self.resolver and now - s.last_ts <= linger:
                info = self.resolver.resolve(s.proto, *o[:4])   # 캐시에 늦게 들어온 경우
                if info:
                    self.attr[s.sid] = info
            if info is None and now - s.first_ts < self.grace:
                continue                      # 아직 귀속을 기다리는 중
            key = info.key if info else UNATTRIBUTED
            self.sess_proc[s.sid] = key
            if info is None:
                self._sid_label[s.sid] = f"{s.proto}/{o[3]}"
            groups[key].append((s, info, o))

        rule_by_sid = defaultdict(list)
        for f in findings:
            if f.title.startswith("C2 비커닝"):
                continue   # 프로세스별 비커닝 분석이 대신한다 (이중 계산 방지)
            for sid in f.session_ids:
                rule_by_sid[sid].append(f)

        for key, items in groups.items():
            self._analyze(key, items, rule_by_sid, now, elapsed)
        return self.timeline.events[before:]

    def _analyze(self, key, items, rule_by_sid, now, elapsed) -> None:
        items.sort(key=lambda it: it[0].first_ts)
        infos = [it[1] for it in items if it[1] is not None]
        info = infos[-1] if infos else None
        attributed = info is not None
        if info:
            self.proc_info[key] = info
        name = info.name if info else UNATTRIBUTED
        prof, is_new = self.store.get(key, name, info.path if info else "",
                                      items[0][0].first_ts, self.learning)
        prof.last_seen = max(prof.last_seen, now)
        browser = name.lower() in B.BROWSERS
        monitor = not self.learning
        cert_proc = CONFIRMED if attributed else ESTIMATED

        # -- 맥락: 실행 관측
        if (key, "proc") not in self._context_done:
            self._context_done.add((key, "proc"))
            if attributed:
                start = info.start_time or items[0][0].first_ts
                parent = f", 부모 {info.parent_name}({info.ppid})" if info.parent_name else ""
                self._event(key, info, start, "proc_seen", 0,
                            f"{name} 실행 (PID {info.pid}{parent})",
                            CONFIRMED if info.start_time else ESTIMATED,
                            evidence=[f"경로: {info.path or '(권한 부족으로 확인 불가)'}"])
            else:
                self._event(key, None, items[0][0].first_ts, "unattributed", 0,
                            "프로세스를 특정하지 못한 외부 연결 발생 (짧은 연결이거나 권한 부족)",
                            UNKNOWN)

        # -- 실행 파일 신원 (해시가 바뀔 때마다 한 번)
        if attributed and info.path:
            self._check_identity(key, info, prof, now, monitor)

        # -- 학습 기간에 없던 프로세스 (감시 중에 기록된 것도 '평소'로 치지 않는다 → 재시연해도 동일)
        if monitor and not prof.learned and attributed and not browser and self.store.has_baseline \
                and (key, "newproc") not in self._context_done:
            self._context_done.add((key, "newproc"))
            installed = B.installed_location(info.path)
            trusted = prof.sig_status == "Valid" and (prof.signer in B.TRUSTED_SIGNERS or installed)
            pts = B.WEIGHTS["new_process"] - (1 if trusted else 0)
            ev = [f"경로: {info.path or '-'}"]
            if trusted:
                why = (f"OS 구성요소 서명({prof.signer})" if prof.signer in B.TRUSTED_SIGNERS
                       else f"유효한 서명({prof.signer}) + 정식 설치 위치")
                ev.append(f"{why}라 가중치 1 낮춤 — 다른 신호는 그대로 적용")
            s0, _, o0 = items[0]
            self._event(key, info, s0.first_ts, "new_process", pts,
                        f"학습 기간에 없던 프로세스 {name} 가 외부와 통신 시작", cert_proc, evidence=ev,
                        refs=[("host", info.path, prof.sha256, prof.sig_status, prof.signer),
                              ("net", s0, o0, self._dest(s0, o0[2], o0[3])[1])],
                        measure={"summary": f"학습된 프로세스 {sum(1 for x in self.store.profiles.values() if x.learned)}개 중 "
                                            f"이 실행 파일 경로가 없음 · 가중치 {pts}",
                                 "trusted_signer": trusted})

        # -- 업로드량 집계 (델타)
        delta_out = 0
        contrib = []                     # 이번 스윕에 업로드가 늘어난 세션 (업로드 급증의 증거)
        for s, _, o in items:
            out_bytes = s.bytes_c2s if o[4] else s.bytes_s2c
            d = max(0, out_bytes - self._counted.get(s.sid, 0))
            if d:
                contrib.append((d, s, o))
            delta_out += d
            self._counted[s.sid] = out_bytes
        prof.bytes_out += delta_out
        rate = delta_out / (elapsed / 60.0)

        # -- 목적지별
        flows = defaultdict(list)
        for s, inf, o in items:
            dkey, label, dcert = self._dest(s, o[2], o[3])
            flows[dkey].append((s, inf, o, label, dcert))
            self.dest_ips[(key, dkey)].add(o[2])
        for dkey, fl in flows.items():
            self._analyze_flow(key, info, prof, dkey, fl, browser, monitor, now)

        # -- 업로드 급증
        if self.learning:
            prof.out_rate_peak = max(prof.out_rate_peak, rate)
        elif rate >= B.THRESH["upload_floor"] and rate >= prof.out_rate_peak * B.THRESH["upload_ratio"]:
            pts = 1 if browser else B.WEIGHTS["upload_spike"]
            contrib.sort(key=lambda x: -x[0])
            top = contrib[:5]
            floor = B.THRESH["upload_floor"]
            need = max(floor, prof.out_rate_peak * B.THRESH["upload_ratio"])
            self._event(key, info, now, "upload_spike", pts,
                        f"외부 전송량 급증: 분당 {rate / 1024:.0f}KB (평소 최대 {prof.out_rate_peak / 1024:.0f}KB/분)",
                        CONFIRMED, evidence=["전송 '양'은 확인됨, 암호화 구간의 '내용'은 확인 불가"],
                        refs=[("net", s_, o_, self._dest(s_, o_[2], o_[3])[1]) for _, s_, o_ in top],
                        measure={"summary": f"{elapsed:.0f}초 동안 {delta_out:,}B 전송 → 분당 {rate / 1024:.0f}KB "
                                            f"≥ 기준 분당 {need / 1024:.0f}KB (평소 최대 {prof.out_rate_peak / 1024:.0f}KB/분 × "
                                            f"{B.THRESH['upload_ratio']:.0f}, 최소 {floor / 1024:.0f}KB)",
                                 "delta_bytes": delta_out, "window_sec": round(elapsed, 1),
                                 "rate_per_min": round(rate), "learned_peak": round(prof.out_rate_peak),
                                 "threshold": round(need),
                                 "by_session": [{"sid": s_.sid, "bytes": d_} for d_, s_, _ in top]})

        # -- 기존 규칙 탐지 결과를 이 프로세스에 귀속
        for s, _, o in items:
            for f in rule_by_sid.get(s.sid, []):
                self._event(key, info, s.first_ts, "rule:" + f.title, B.RULE_POINTS.get(f.severity, 0),
                            f"규칙 탐지: {f.title}", CONFIRMED, evidence=list(f.evidence[:3]),
                            refs=[("rule", f), ("net", s, o, self._dest(s, o[2], o[3])[1])],
                            measure={"summary": f"{f.severity} 등급 규칙 → {B.RULE_POINTS.get(f.severity, 0)}점"})

        # -- 차단 제안 (위험도 '높음' 도달)
        risk = self.timeline.risk(key, now)
        if monitor and level_of(risk) == "높음" and now - self._suggested.get(key, -1e18) > REFIRE_SEC:
            self._suggested[key] = now
            scored = [e for e in self.timeline.for_process(key) if e.points > 0]
            bad = sorted({e.dest for e in scored if e.dest})
            ips = sorted({ip for d in bad for ip in self.dest_ips.get((key, d), ())
                          if B.is_external(ip)})
            window = [e for e in scored if now - self.timeline.risk_window <= e.ts <= now]
            self._event(key, info, now, "block_suggest", 0,
                        f"위험도 {risk:.0f}점(높음) → 차단 제안: {', '.join(ips) or '목적지 미상'}",
                        cert_proc, evidence=["자동 차단 아님: 사용자 승인 후 적용"],
                        measure={"summary": " + ".join(f"{e.points}" for e in window) + f" = {risk:.0f}점 ≥ 6점(높음)",
                                 "parts": [{"code": e.code, "points": e.points,
                                            "evidence_ids": e.evidence_ids} for e in window]})
            if ips:
                self.suggestions.append(Suggestion(
                    ts=now, proc_key=key, proc_name=name, pid=info.pid if info else 0,
                    start_time=info.start_time if info else 0.0, risk=risk, ips=ips,
                    dests=bad, reasons=[e.text for e in scored][-8:]))

    def take_suggestions(self) -> list[Suggestion]:
        out, self.suggestions = self.suggestions, []
        return out

    def _analyze_flow(self, key, info, prof, dkey, fl, browser, monitor, now) -> None:
        label, dcert = fl[0][3], fl[0][4]
        rport = fl[0][2][3]
        first_ref = [("net", fl[0][0], fl[0][2], label)]
        base: Optional[DestBaseline] = prof.dests.get(dkey)
        first = fl[0][0]
        if base is None:
            base = DestBaseline(first_seen=first.first_ts, last_seen=first.first_ts,
                                learned=self.learning)
            prof.dests[dkey] = base
        known = base.learned
        # 평소 도메인의 새 하위 서버(cdn3.kakao.com 등)는 새 목적지로 보지 않는다
        reg = _registered(dkey)
        known_domain = (not known and reg is not None and any(
            b.learned and _registered(d) == reg for d, b in prof.dests.items()))

        for s, _, o, _, _ in fl:
            if s.sid in self._conn_counted:
                continue
            self._conn_counted.add(s.sid)
            prof.conn_count += 1
            base.count += 1
            base.last_seen = max(base.last_seen, s.first_ts)
            if self.learning:   # 감시 모드에선 '평소'를 오염시키지 않는다
                base.times.append(s.first_ts)
                del base.times[:-MAX_TIMES]
                if o[3] not in base.ports:
                    base.ports.append(o[3])
            base.bytes_out += s.bytes_c2s if o[4] else s.bytes_s2c

        if not monitor:
            return

        if known:
            if (key, "known", dkey) not in self._context_done:
                self._context_done.add((key, "known", dkey))
                self._event(key, info, first.first_ts, "known_dest", 0,
                            f"평소 접속하던 서버 연결: {label}", dcert, dest=dkey,
                            refs=first_ref + [("base", dkey, base)])
        elif known_domain:
            self._event(key, info, first.first_ts, "known_domain", 0,
                        f"평소 쓰던 도메인의 새 서버: {label}", dcert, dest=dkey, refs=first_ref,
                        measure={"summary": f"등록 도메인 '{reg}' 가 학습 프로파일에 있음"})
        elif not browser and self.store.has_baseline:
            # 새 목적지가 여러 개여도 점수는 한 번만 (업데이트 CDN 등으로 점수가 부풀지 않게)
            pts = self._capped(key, "new_dest", first.first_ts)
            self._event(key, info, first.first_ts, "new_dest", pts,
                        f"새로운 외부 목적지 연결: {label}", dcert, dest=dkey, refs=first_ref,
                        measure={"summary": (f"이 프로세스의 학습 목적지 {nl}곳에 없음" if (nl := sum(
                                     1 for b in prof.dests.values() if b.learned)) else
                                     "이 프로세스는 학습된 목적지가 없음 (학습 기간에 통신 기록 없음)")
                                 + ("" if pts else " · 같은 위험도 창에서 이미 점수를 줘서 0점")})

        if not browser and rport not in B.STD_PORTS and not (known and rport in base.ports):
            self._event(key, info, first.first_ts, "nonstd_port",
                        self._capped(key, "nonstd_port", first.first_ts),
                        f"비표준 포트 {rport} 사용: {label}", CONFIRMED, dest=dkey, refs=first_ref,
                        measure={"summary": f"포트 {rport} 는 표준 포트 목록({len(B.STD_PORTS)}개)에 없음"})

        recent = [it for it in fl if it[0].first_ts >= now - self.window]
        times = [it[0].first_ts for it in recent]
        n, mean, c = B.interval_stats(times)
        t = B.THRESH
        if n >= t["beacon_min_gaps"] and mean >= t["beacon_min_interval"] and c <= t["beacon_max_cv"] \
                and (not browser or not known):
            ordered = sorted(recent, key=lambda it: it[0].first_ts)
            at = ordered[t["beacon_min_gaps"]][0].first_ts
            used = ordered[: t["beacon_min_gaps"] + 1] if len(ordered) > 20 else ordered
            refs = [("net", it[0], it[2], it[3]) for it in used]
            gaps = [round(b[0].first_ts - a[0].first_ts, 1) for a, b in zip(ordered, ordered[1:])
                    if b[0].first_ts - a[0].first_ts > 0.5]
            self._event(key, info, at, "beacon", 1 if browser else B.WEIGHTS["beacon"],
                        f"{mean:.0f}초 간격으로 반복 통신 ({n + 1}회, 간격 변동계수 {c:.3f}): {label}",
                        CONFIRMED, dest=dkey,
                        evidence=[f"평균 간격 {mean:.1f}s · CV {c:.3f} (기준 ≤ {t['beacon_max_cv']})",
                                  "접속 '시각'만으로 판단하므로 암호화 통신에도 적용됨"],
                        refs=refs,
                        measure={"summary": f"간격 {n}개 평균 {mean:.1f}s, 변동계수 {c:.3f} ≤ 기준 {t['beacon_max_cv']} "
                                            f"(최소 간격 {t['beacon_min_gaps']}개, 평균 ≥ {t['beacon_min_interval']}s)",
                                 "gaps": gaps[:30], "mean": round(mean, 2), "cv": round(c, 4),
                                 "threshold_cv": t["beacon_max_cv"], "window_sec": self.window})
        ordered = sorted(recent, key=lambda it: it[0].first_ts)
        if len(ordered) >= t["beacon_min_gaps"] + 1 and not browser:
            at = ordered[t["beacon_min_gaps"]][0].first_ts
            refs = [("net", it[0], it[2], it[3]) for it in ordered[:20]]
            sizes = [it[0].bytes_c2s if it[2][4] else it[0].bytes_s2c for it in ordered]
            sc = B.cv([float(x) for x in sizes if x])
            if sc <= t["size_max_cv"]:
                self._event(key, info, at, "size_regular", B.WEIGHTS["size_regular"],
                            f"매번 비슷한 크기의 데이터 전송 (크기 변동계수 {sc:.3f}): {label}",
                            CONFIRMED, dest=dkey, refs=refs,
                            measure={"summary": f"송신 크기 {len(sizes)}개, 변동계수 {sc:.3f} ≤ 기준 {t['size_max_cv']}",
                                     "sizes": sizes[:30], "cv": round(sc, 4)})

        bi = base.interval() if base.learned else None
        if bi and n >= t["period_min_gaps"] and mean and bi / mean >= t["period_ratio"]:
            ordered = sorted(recent, key=lambda it: it[0].first_ts)
            at = ordered[t["period_min_gaps"]][0].first_ts
            self._event(key, info, at, "period_change", B.WEIGHTS["period_change"],
                        f"통신 주기 급변: 평소 약 {bi:.0f}초 → 현재 {mean:.0f}초 ({label})",
                        ESTIMATED, dest=dkey,
                        evidence=["평소 주기는 학습 구간 기준 (학습 구간이 깨끗했다는 전제)"],
                        refs=[("base", dkey, base)] + [("net", it[0], it[2], it[3])
                                                       for it in ordered[: t["period_min_gaps"] + 1]],
                        measure={"summary": f"평소 {bi:.0f}s ÷ 현재 {mean:.1f}s = {bi / mean:.1f}배 ≥ 기준 "
                                            f"{t['period_ratio']:.0f}배",
                                 "learned_interval": round(bi, 1), "current_mean": round(mean, 2),
                                 "ratio": round(bi / mean, 2)})

        for s, _, o, _, _ in fl:
            if s.duration >= t["long_conn_sec"] and not browser and not s.fin_seen and not s.rst_seen \
                    and (rport not in B.STD_PORTS or not known):
                self._event(key, info, s.first_ts + t["long_conn_sec"], "long_conn",
                            self._capped(key, "long_conn", s.first_ts + t["long_conn_sec"]),
                            f"외부 연결을 {s.duration / 60:.0f}분 이상 유지: {label}", CONFIRMED, dest=dkey,
                            refs=[("net", s, o, label)],
                            measure={"summary": f"연결 유지 {s.duration:.0f}s ≥ 기준 {t['long_conn_sec']:.0f}s, 종료 패킷 없음"})
                break

    def _check_identity(self, key, info, prof, now, monitor) -> None:
        sha = self.identity.sha256(info.path)
        ident_key = f"{key}|{sha}"
        if ident_key in self._identity_done:
            return
        self._identity_done.add(ident_key)
        sig = self.identity.signature(info.path, sha)
        ts = info.start_time or now

        href = [("host", info.path, sha, sig.status, sig.signer)]
        if prof.sha256 and sha and sha != prof.sha256:
            same_signer = sig.signed and prof.sig_status == "Valid" and sig.signer == prof.signer
            prof.file_history.append({"ts": now, "sha256": sha, "sig_status": sig.status,
                                      "signer": sig.signer})
            if same_signer:
                self._event(key, info, ts, "binary_updated", 0,
                            f"실행 파일 변경 (서명자 동일: {sig.signer}) → 정상 업데이트로 추정", ESTIMATED,
                            refs=href, measure={"summary": f"이전 {prof.sha256[:12]}… → 현재 {sha[:12]}…"})
            elif monitor:
                why = "서명이 사라짐" if not sig.signed else f"서명자 변경: {prof.signer or '없음'} → {sig.signer}"
                self._event(key, info, ts, "binary_changed", B.WEIGHTS["binary_changed"],
                            f"실행 파일이 바뀌었고 {why}", CONFIRMED,
                            evidence=[f"이전 SHA-256 {prof.sha256[:16]}…", f"현재 SHA-256 {sha[:16]}…"],
                            refs=href, measure={"summary": f"이전 {prof.sha256[:12]}…({prof.signer or '서명 없음'}) → "
                                                           f"현재 {sha[:12]}…({sig.signer or '서명 없음'})"})
        if sha:
            prof.sha256, prof.sig_status, prof.signer = sha, sig.status, sig.signer

        if not monitor:
            return
        if sig.status not in ("Valid", "Unknown"):
            self._event(key, info, ts, "unsigned", B.WEIGHTS["unsigned"],
                        f"코드 서명 없음/무효 ({sig.status}) — 단독으로는 악성 근거가 아님", CONFIRMED,
                        evidence=[f"경로: {info.path}"], refs=href,
                        measure={"summary": f"Get-AuthenticodeSignature 결과 {sig.status}"})
        for code, text in location_flags(info.path, info.name):
            self._event(key, info, ts, code, B.WEIGHTS[code], text, CONFIRMED, refs=href,
                        measure={"summary": "실행 경로 문자열 규칙 일치 (hostid.location_flags)"})

    # ------------------------------------------------------------ 요약
    def _unattributed_breakdown(self, data=None) -> list:
        """미귀속 세션을 '프로토콜/원격 포트'별로 집계 (무엇이 안 붙는지 진단용)."""
        c = Counter()
        for sid, key in self.sess_proc.items():
            if key == UNATTRIBUTED:
                c[self._sid_label.get(sid, "?")] += 1
        return c.most_common(6)

    def summary(self) -> dict:
        r = self.resolver.stats if self.resolver else Counter()
        total = len(self.sess_proc)
        attributed = sum(1 for k in self.sess_proc.values() if k != UNATTRIBUTED)
        return {
            "dns_sessions": len(self.dns_sessions),
            "unattributed_by": self._unattributed_breakdown(),
            "profiles": len(self.store.profiles),
            "learning_min": round(self.store.learning_sec / 60, 1),
            "attribution_rate": round(attributed / total, 3) if total else None,   # 외부 세션 기준
            "unattributed_sessions": total - attributed,
            "pid_reuse": r.get("pid_reuse", 0),
        }
