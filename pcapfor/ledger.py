"""피해 장부: 사건마다 '무엇이 얼마나 어디로 나갔는가'를 확신도와 함께 정리한다.

세 칸으로 나눠 말한다.
- 확인됨: 패킷에서 직접 확인한 사실 (전송 바이트 수, 시각, 평문으로 보인 계정 등)
- 추정됨: 근거는 있지만 해석이 섞인 것 (DNS 로 붙인 서버 이름, 암호화로 보이는 데이터 등)
- 확인 불가: 이 도구로는 원리상 알 수 없는 것 (암호화된 내용, 감염 경로 등)

결과는 JSON 직렬화 가능한 dict 하나(build_doc)다. 사고 보고서(incident_report.py)는
이 dict 만 보고 그리므로, 저장된 JSON 으로 보고서를 언제든 다시 만들 수 있다.
"""
from __future__ import annotations

import math
from collections import Counter, defaultdict
from datetime import datetime, timezone

from .behavior import MITRE
from .procmap import UNATTRIBUTED
from .timeline import CONFIRMED, ESTIMATED, PARTIAL, UNKNOWN

CONTENT = {   # 종류 -> (표시, 내용 확인 가능 여부의 확신도)
    "plain": ("평문 프로토콜 (HTTP/FTP/SMTP/Telnet)", CONFIRMED),
    "plain_guess": ("평문으로 보이는 자체 프로토콜", PARTIAL),
    "tls": ("TLS 암호화", UNKNOWN),
    "quic": ("QUIC 암호화 (UDP 443)", UNKNOWN),
    "enc_guess": ("암호화/압축 데이터로 추정 (높은 엔트로피)", ESTIMATED),
    "empty": ("데이터 없음 (연결 시도만)", CONFIRMED),
}


def _entropy(b: bytes) -> float:
    if not b:
        return 0.0
    n = len(b)
    return -sum(c / n * math.log2(c / n) for c in Counter(b).values())


def _printable(b: bytes, n: int = 90) -> str:
    return "".join(chr(c) if 32 <= c < 127 else "." for c in b[:n])


def _classify(s, plain_sids: set, sni: dict) -> tuple[str, float, bytes]:
    if s.proto == "udp":
        return ("quic" if 443 in (s.sport, s.cport) else "plain_guess"), 0.0, b""
    head = s.stream(c2s=True)[:2048]
    if s.sid in plain_sids:
        return "plain", 0.0, head
    if sni.get(s.sid, (None,))[0] or head[:1] == b"\x16":
        return "tls", 0.0, b""
    if not head:
        return "empty", 0.0, b""
    ent = _entropy(head)
    limit = 7.2 if len(head) >= 1024 else 6.0
    if len(head) >= 128 and ent >= limit:
        return "enc_guess", ent, b""
    return "plain_guess", ent, head


def _ts(ts: float) -> str:
    if not ts:
        return "-"
    return datetime.fromtimestamp(ts).astimezone().strftime("%Y-%m-%d %H:%M:%S")


def _fmt_bytes(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f}{unit}" if unit == "B" else f"{n:.1f}{unit}"
        n /= 1024
    return f"{n:.1f}GB"


def build_doc(engine, blocker=None, now: float = 0.0, host_ip: str = "",
              evidence_pcap: dict | None = None) -> dict:
    """LiveEngine(+HostMonitor) 상태 -> 보고서용 dict.

    evidence_pcap: {"path", "sha256", "packets"} — --save 로 저장한 증거 pcap. 있으면 증거의
    패킷 번호(frame.number)가 이 파일 기준이라고 보고서에 명시한다.
    """
    hm = engine.hostmon
    hm.evidence.refresh()              # 세션은 계속 자라므로 증거 값을 최신으로
    data = engine.data
    now = now or max((s.last_ts for s in data.sessions), default=0.0)
    blocks = blocker.blocks if blocker else []

    plain_sids = {s.sid for s, *_ in data.ftp_streams + data.smtp_streams + data.telnet_streams}
    plain_sids |= {s.sid for s, _ in data.http_transactions}
    by_proc = defaultdict(list)
    for s in data.sessions:
        k = hm.sess_proc.get(s.sid)
        if k:
            by_proc[k].append(s)

    incidents = []
    for inc in hm.timeline.incidents():
        key = inc.proc_key
        info = hm.proc_info.get(key)
        prof = hm.store.profiles.get(key)
        scored = [e for e in inc.events if e.points > 0]
        flagged_dests = {e.dest for e in scored if e.dest}
        flagged_ips = {ip for d in flagged_dests for ip in hm.dest_ips.get((key, d), ())}
        pblocks = [b for b in blocks if b.proc_key == key]
        blocked_at = min((b.applied for b in pblocks if b.applied), default=0.0)

        # -- 목적지별 통신 기록
        dests: dict[str, dict] = {}
        kinds = Counter()
        kind_bytes = Counter()
        previews = []
        for s in by_proc[key]:
            if s.last_ts < inc.start - 60:
                continue
            o = hm._orient(s)
            if not o:
                continue
            remote, rport, outbound = o[2], o[3], o[4]
            out_b = s.bytes_c2s if outbound else s.bytes_s2c
            in_b = s.bytes_s2c if outbound else s.bytes_c2s
            kind, ent, head = _classify(s, plain_sids, hm._sni)
            kinds[kind] += 1
            kind_bytes[kind] += out_b
            if kind in ("plain", "plain_guess") and head.strip() and len(previews) < 3:
                previews.append(f"{remote}:{rport} → {_printable(head)}")
            name, cert = None, UNKNOWN
            sni = hm._sni.get(s.sid, (None, False))
            if sni[0]:
                name, cert = sni[0], ESTIMATED if sni[1] else CONFIRMED
            elif remote in hm._names:
                name, cert = hm._names[remote]
            d = dests.setdefault(remote, {
                "ip": remote, "name": name, "name_certainty": cert, "ports": [],
                "conns": 0, "bytes_out": 0, "bytes_in": 0, "first": s.first_ts, "last": s.last_ts,
                "flagged": remote in flagged_ips, "content": Counter(),
                "after_block_attempts": 0, "after_block_bytes_out": 0, "after_block_established": 0,
            })
            if name and not d["name"]:
                d["name"], d["name_certainty"] = name, cert
            if rport not in d["ports"]:
                d["ports"].append(rport)
            d["conns"] += 1
            d["bytes_out"] += out_b
            d["bytes_in"] += in_b
            d["first"] = min(d["first"], s.first_ts)
            d["last"] = max(d["last"], s.last_ts)
            d["content"][kind] += 1
            for b in pblocks:
                if b.applied and remote in b.ips and s.first_ts >= b.applied:
                    d["after_block_attempts"] += 1
                    d["after_block_bytes_out"] += out_b
                    d["after_block_established"] += 1 if s.synack_seen else 0
        dest_list = sorted(dests.values(), key=lambda d: (not d["flagged"], -d["bytes_out"]))
        for d in dest_list:
            d["content"] = {CONTENT[k][0]: n for k, n in d["content"].items()}
        total_out = sum(d["bytes_out"] for d in dest_list)
        flagged_out = sum(d["bytes_out"] for d in dest_list if d["flagged"])
        before_block_out = sum(d["bytes_out"] - d["after_block_bytes_out"] for d in dest_list if d["flagged"])
        after_attempts = sum(d["after_block_attempts"] for d in dest_list)
        after_out = sum(d["after_block_bytes_out"] for d in dest_list)
        after_est = sum(d["after_block_established"] for d in dest_list)

        # -- 확인된 노출 (평문 규칙 탐지)
        exposures = [{"text": e.text, "evidence": e.evidence} for e in scored if e.code.startswith("rule:")]

        # -- 세 칸 정리
        confirmed, estimated, unknown = [], [], []
        if info:
            confirmed.append(f"프로세스: {info.name} (PID {info.pid}), 경로 {info.path or '확인 불가(권한)'}")
            if info.parent_name:
                confirmed.append(f"부모 프로세스: {info.parent_name} (PID {info.ppid})")
            elif info.ppid:
                confirmed.append(f"부모 프로세스: PID {info.ppid} (보고서 작성 시점에 이미 종료)")
        if prof and prof.sha256:
            confirmed.append(f"실행 파일 SHA-256: {prof.sha256}")
            confirmed.append(f"코드 서명: {prof.sig_status or '미확인'}"
                             + (f" (서명자 {prof.signer})" if prof.signer else ""))
        confirmed.append(f"최초 이상 행동 {_ts(inc.first_anomaly)}, 의심 목적지 {len(flagged_ips)}곳")
        confirmed.append(f"의심 목적지로 나간 데이터 {_fmt_bytes(flagged_out)} "
                         f"(이 프로세스 전체 외부 전송 {_fmt_bytes(total_out)}) — 바이트 수는 패킷 기준 확인")
        for x in exposures:
            confirmed.append(f"평문 노출: {x['text']}")
        if blocked_at:
            confirmed.append(f"차단 규칙 적용 {_ts(blocked_at)} (netsh 성공 응답)")
            if after_attempts:
                confirmed.append(f"차단 이후 해당 목적지로 나간 연결 시도 패킷 {after_attempts}건, "
                                 f"연결 성립 {after_est}회, 전송 {_fmt_bytes(after_out)}")
            else:
                confirmed.append(f"차단 이후 해당 목적지로 나간 패킷 0개, 전송 {_fmt_bytes(after_out)}")
        if kinds["plain_guess"]:
            confirmed.append(f"평문으로 보이는 데이터 {_fmt_bytes(kind_bytes['plain_guess'])} — 내용 일부 확인 가능")

        for d in dest_list:
            if d["name"] and d["name_certainty"] == PARTIAL:
                estimated.append(f"{d['ip']} 의 서버 이름 '{d['name']}' 은 DNS 응답으로 붙인 것 (같은 IP 에 다른 사이트가 있을 수 있음)")
            elif d["name"] and d["name_certainty"] == ESTIMATED:
                estimated.append(f"{d['ip']} 의 SNI '{d['name']}' 은 ECH 공용 이름일 수 있음")
        if any(e.code == "period_change" for e in scored):
            estimated.append("'평소 주기'는 학습 구간 기준이며, 학습 구간이 깨끗했다는 전제에 의존")
        if kinds["enc_guess"]:
            estimated.append(f"{_fmt_bytes(kind_bytes['enc_guess'])} 는 엔트로피가 높아 암호화/압축 데이터로 추정 (프로토콜 불명)")
        estimated.append("행동 패턴상 원격 제어(C2)·데이터 유출 의심 — 감염 확정이 아니라 근거의 합에 따른 판단")
        if not blocked_at:
            estimated.append("차단이 적용되지 않아 보고서 작성 시점까지 통신이 계속됐을 수 있음")

        enc_bytes = kind_bytes["tls"] + kind_bytes["quic"] + kind_bytes["enc_guess"]
        if enc_bytes:
            unknown.append(f"암호화 구간 {_fmt_bytes(enc_bytes)} 의 실제 내용 (어떤 파일·정보였는지)")
        unknown.append("유출된 데이터에 개인정보·계정이 포함됐는지 (평문으로 확인된 항목 제외)")
        unknown.append("감염 경로와 캡처 시작 이전의 활동")
        if blocked_at and not after_attempts:
            unknown.append("차단 이후 프로세스의 접속 시도 횟수 (Windows 방화벽이 패킷을 캡처 전에 막아 보이지 않음)")
        if any(d["name_certainty"] == UNKNOWN for d in dest_list):
            unknown.append("이름이 보이지 않는 목적지의 실제 서비스 (IP 만 확인)")
        if key == UNATTRIBUTED:
            unknown.append("이 연결을 만든 프로세스 (조회 전에 끝났거나 권한 부족)")

        mitre = sorted({MITRE[e.code] for e in scored if e.code in MITRE})
        # 최고 위험도가 어떤 신호들의 합인지 (위험도 창 안의 점수 이벤트)
        peak_ev = max(scored, key=lambda e: (e.risk, -e.ts)) if scored else None
        breakdown = ([{"code": e.code, "text": e.text, "points": e.points, "ts": e.ts,
                       "evidence_ids": e.evidence_ids}
                      for e in scored if peak_ev.ts - hm.timeline.risk_window <= e.ts <= peak_ev.ts]
                     if peak_ev else [])
        incidents.append({
            "id": inc.iid, "level": inc.level, "peak_risk": inc.peak_risk,
            "start": inc.start, "end": inc.end, "first_anomaly": inc.first_anomaly,
            "process": {
                "key": key, "name": inc.proc_name,
                "pid": info.pid if info else 0, "path": info.path if info else "",
                "start_time": info.start_time if info else 0.0,
                "parent": (f"{info.parent_name} (PID {info.ppid})" if info and info.parent_name
                           else f"PID {info.ppid} (이미 종료됨)" if info and info.ppid else ""),
                "sha256": prof.sha256 if prof else "", "sig_status": prof.sig_status if prof else "",
                "signer": prof.signer if prof else "",
                "first_seen": prof.first_seen if prof else 0.0,
                "learned": bool(prof and prof.learned),
                "file_history": prof.file_history if prof else [],
            },
            "evidence": [{"ts": e.ts, "points": e.points, "risk": e.risk, "level": e.level,
                          "certainty": e.certainty, "text": e.text, "code": e.code,
                          "mitre": MITRE.get(e.code, ""), "detail": e.evidence,
                          "evidence_ids": e.evidence_ids, "measure": e.measure} for e in scored],
            "risk_breakdown": breakdown,
            "evidence_items": hm.evidence.for_ids(
                [i for e in hm.timeline.for_process(key) if inc.start - 60 <= e.ts <= max(inc.end, now)
                 for i in e.evidence_ids]),
            "timeline": [e.to_dict() for e in hm.timeline.for_process(key)
                         if inc.start - 60 <= e.ts <= max(inc.end, now)],
            "destinations": dest_list,
            "totals": {"out": total_out, "flagged_out": flagged_out, "before_block_out": before_block_out,
                       "after_block_attempts": after_attempts, "after_block_out": after_out,
                       "after_block_established": after_est},
            "content_kinds": {CONTENT[k][0]: {"sessions": n, "bytes_out": kind_bytes[k],
                                              "content_certainty": CONTENT[k][1]}
                              for k, n in kinds.items()},
            "previews": previews,
            "exposures": exposures,
            "blocks": [{"id": b.bid, "status": b.status, "ips": b.ips, "created": b.created,
                        "applied": b.applied, "expires": b.expires, "removed": b.removed,
                        "approved_by": b.approved_by, "skipped": b.skipped, "log": b.log,
                        "error": b.error} for b in pblocks],
            "facts": {"confirmed": confirmed, "estimated": estimated, "unknown": unknown},
            "mitre": mitre,
        })

    summ = hm.summary()
    return {
        "generated": now, "generated_str": _ts(now),
        "tz": datetime.now(timezone.utc).astimezone().strftime("UTC%z"),
        "host_ip": host_ip, "mode": "학습" if hm.learning else "감시",
        "capture_start": engine.started_at, "packets": engine.packet_count,
        "summary": summ,
        "baseline_note": "학습 구간의 PC 가 깨끗했다는 전제로 '평소'를 판단합니다.",
        "incidents": incidents,
        "blocks_total": len(blocks),
        "evidence_pcap": evidence_pcap,
        "evidence_total": len(hm.evidence.items),
    }
