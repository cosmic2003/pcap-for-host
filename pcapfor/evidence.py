"""증거 저장소: 모든 판단을 원본 증거까지 거슬러 올라갈 수 있게 ID 를 붙인다.

  E-xxxx  네트워크 증거 = 세션 하나 (시각·바이트·패킷 번호 범위·Wireshark 필터)
  H-xxxx  호스트 증거   = 실행 파일 하나의 경로·SHA-256·코드 서명
  B-xxxx  기준 증거     = 학습 프로파일의 '평소 값' (예: 평소 주기와 그 근거가 된 학습 간격 수)
  R-xxxx  규칙 증거     = 기존 탐지기(detect.py)의 결과

추적 경로:  위험도 → 신호(이벤트, 점수·측정값) → 증거 ID → 세션 → 증거 pcap 의 frame.number
--save 로 저장한 증거 pcap 은 수신한 패킷을 모두 순서대로 기록하므로, 세션의 패킷 순번이
그 파일의 Wireshark frame.number 와 같다. 보고서에 그 pcap 의 SHA-256 을 함께 남긴다.

증거 ID 는 실제로 판단에 쓰일 때만 만든다(이벤트가 중복이라 버려지면 만들지 않음).
네트워크 증거의 바이트·시각은 세션이 계속 자라므로 보고서를 만들 때 최신 값으로 갱신한다.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Optional


@dataclass
class Evidence:
    eid: str
    kind: str            # net | host | base | rule
    title: str
    proc_key: str = ""
    sid: int = 0
    data: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


def wireshark_filter(proto: str, lip: str, lport: int, rip: str, rport: int) -> str:
    l4 = "tcp" if proto == "tcp" else "udp"
    return (f"ip.addr=={lip} && ip.addr=={rip} && {l4}.port=={lport} && {l4}.port=={rport}")


class EvidenceStore:
    PREFIX = {"net": "E", "host": "H", "base": "B", "rule": "R"}

    def __init__(self) -> None:
        self.items: dict[str, Evidence] = {}
        self._index: dict[tuple, str] = {}
        self._count = {k: 0 for k in self.PREFIX}
        self._sessions: dict[int, tuple] = {}      # sid -> (세션 객체, orient 결과, 표시 이름)

    def _new(self, kind: str, dedup: tuple, title: str, proc_key: str, sid: int = 0,
             data: Optional[dict] = None) -> str:
        if dedup in self._index:
            return self._index[dedup]
        self._count[kind] += 1
        eid = f"{self.PREFIX[kind]}-{self._count[kind]:04d}"
        self.items[eid] = Evidence(eid, kind, title, proc_key, sid, data or {})
        self._index[dedup] = eid
        return eid

    # ------------------------------------------------------------ 종류별 등록
    def net(self, proc_key: str, s, o: tuple, label: str) -> str:
        eid = self._new("net", ("net", s.sid), f"세션 #{s.sid} {s.proto.upper()} → {label}",
                        proc_key, s.sid)
        self._sessions[s.sid] = (s, o, label)
        self._refresh_one(eid)
        return eid

    def host(self, proc_key: str, path: str, sha: str, sig_status: str, signer: str,
             extra: Optional[dict] = None) -> str:
        data = {"path": path, "sha256": sha, "sig_status": sig_status, "signer": signer}
        data.update(extra or {})
        return self._new("host", ("host", proc_key, sha or path),
                         f"실행 파일 {path.replace(chr(92), '/').rsplit('/', 1)[-1] or proc_key}",
                         proc_key, data=data)

    def base(self, proc_key: str, dest: str, base) -> str:
        ts = sorted(base.times)
        gaps = [round(b - a, 1) for a, b in zip(ts, ts[1:]) if b - a > 0.5]
        data = {"dest": dest, "learned_first_seen": base.first_seen, "learned_conns": base.count,
                "learned_ports": list(base.ports), "learned_gaps": gaps[-20:],
                "learned_interval": base.interval()}
        return self._new("base", ("base", proc_key, dest), f"학습 프로파일: {dest} 의 평소 통신",
                         proc_key, data=data)

    def rule(self, proc_key: str, f) -> str:
        data = {"severity": f.severity, "category": f.category, "description": f.description,
                "evidence": list(f.evidence), "mitre": f.mitre}
        return self._new("rule", ("rule", proc_key, f.title), f"규칙 탐지: {f.title}", proc_key,
                         data=data)

    # ------------------------------------------------------------ 갱신/조회
    def _refresh_one(self, eid: str) -> None:
        ev = self.items[eid]
        s, o, label = self._sessions[ev.sid]
        lip, lport, rip, rport, outbound = o
        ev.data = {
            "proto": s.proto, "local": f"{lip}:{lport}", "remote": f"{rip}:{rport}", "dest": label,
            "direction": "나가는 연결" if outbound else "들어오는 연결",
            "first_ts": s.first_ts, "last_ts": s.last_ts, "duration": round(s.duration, 3),
            "bytes_out": s.bytes_c2s if outbound else s.bytes_s2c,
            "bytes_in": s.bytes_s2c if outbound else s.bytes_c2s,
            "packets": s.packets, "pkt_first": s.pkt_first, "pkt_last": s.pkt_last,
            "handshake": "완료" if s.synack_seen else ("SYN만" if s.syn_seen else "중간부터 관측"),
            "closed": "RST" if s.rst_seen else ("FIN" if s.fin_seen else "열림/미확인"),
            "filter": wireshark_filter(s.proto, lip, lport, rip, rport),
            "frame_filter": (f"frame.number >= {s.pkt_first} && frame.number <= {s.pkt_last}"
                             if s.pkt_first else ""),
        }

    def refresh(self) -> None:
        for eid, ev in self.items.items():
            if ev.kind == "net" and ev.sid in self._sessions:
                self._refresh_one(eid)

    def get(self, eid: str) -> Optional[Evidence]:
        return self.items.get(eid)

    def for_ids(self, ids) -> list[dict]:
        out = []
        for eid in sorted(set(ids), key=lambda x: (x[0], x)):
            ev = self.items.get(eid)
            if ev:
                out.append(ev.to_dict())
        return out
