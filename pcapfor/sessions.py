"""세션(플로우) 추적 + TCP 스트림 재조립.

세션 키는 5-튜플을 정규화한 것이고, 최초 패킷(가능하면 SYN)의 송신자를
클라이언트로 본다. TCP는 방향별로 (seq -> payload) 조각을 모아 뒀다가
순서 재정렬·중복 제거 후 하나의 바이트 스트림으로 잇는다.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from .layers import Packet, TCP_ACK, TCP_FIN, TCP_RST, TCP_SYN

MAX_STREAM_BYTES = 4 * 1024 * 1024  # 세션당 방향별 재조립 상한 (메모리 보호)


@dataclass
class Session:
    sid: int
    proto: str
    client: str
    cport: int
    server: str
    sport: int
    first_ts: float
    last_ts: float = 0.0
    packets: int = 0
    bytes_c2s: int = 0
    bytes_s2c: int = 0
    syn_seen: bool = False
    synack_seen: bool = False
    fin_seen: bool = False
    rst_seen: bool = False
    # TCP 재조립 버퍼: {seq: payload}
    _segs_c2s: dict = field(default_factory=dict, repr=False)
    _segs_s2c: dict = field(default_factory=dict, repr=False)
    _isn_c: Optional[int] = None
    _isn_s: Optional[int] = None

    @property
    def key_str(self) -> str:
        return f"{self.client}:{self.cport} -> {self.server}:{self.sport}/{self.proto}"

    @property
    def duration(self) -> float:
        return max(0.0, self.last_ts - self.first_ts)

    def stream(self, c2s: bool) -> bytes:
        """방향별 재조립 결과. 중복/재전송은 먼저 온 조각이 이긴다."""
        segs = self._segs_c2s if c2s else self._segs_s2c
        if not segs:
            return b""
        out = bytearray()
        expected = None
        for seq in sorted(segs):
            chunk = segs[seq]
            if expected is None:
                expected = seq
            if seq > expected:
                # 구멍(유실 세그먼트): 그대로 이어붙이면 오프셋이 틀어지므로 경계 표시 없이 skip
                expected = seq
            elif seq < expected:
                # 겹침: 이미 가진 부분은 버린다
                overlap = expected - seq
                if overlap >= len(chunk):
                    continue
                chunk = chunk[overlap:]
            out += chunk
            expected += len(chunk)
            if len(out) >= MAX_STREAM_BYTES:
                break
        return bytes(out)


class SessionTable:
    def __init__(self) -> None:
        self._map: dict[tuple, Session] = {}
        self.sessions: list[Session] = []

    @staticmethod
    def _key(p: Packet) -> tuple:
        a = (p.src, p.sport)
        b = (p.dst, p.dport)
        return (p.proto,) + (a + b if a <= b else b + a)

    def feed(self, p: Packet) -> Optional[Session]:
        if p.proto not in ("tcp", "udp") or not p.src:
            return None
        key = self._key(p)
        s = self._map.get(key)
        if s is None:
            # 새 세션: 이 패킷의 송신자를 클라이언트로 가정 (SYN이면 확실)
            client, cport, server, sport = p.src, p.sport, p.dst, p.dport
            fresh_syn = p.proto == "tcp" and p.flag(TCP_SYN) and not p.flag(TCP_ACK)
            # 캡처가 연결 도중에 시작되면 첫 패킷이 서버발일 수 있다.
            # SYN 이 아니고 출발 포트만 잘 알려진 포트면 그쪽을 서버로 본다.
            if not fresh_syn and p.sport < 1024 <= p.dport:
                client, cport, server, sport = p.dst, p.dport, p.src, p.sport
            s = Session(
                sid=len(self.sessions) + 1,
                proto=p.proto,
                client=client, cport=cport,
                server=server, sport=sport,
                first_ts=p.ts, last_ts=p.ts,
            )
            self._map[key] = s
            self.sessions.append(s)
        # SYN+ACK가 먼저 잡힌 캡처라면 방향을 바로잡는다
        if (
            p.proto == "tcp"
            and p.flag(TCP_SYN) and p.flag(TCP_ACK)
            and (p.src, p.sport) == (s.client, s.cport)
            and not s.syn_seen
        ):
            s.client, s.cport, s.server, s.sport = s.server, s.sport, s.client, s.cport

        c2s = (p.src, p.sport) == (s.client, s.cport)
        s.packets += 1
        s.last_ts = max(s.last_ts, p.ts)
        if c2s:
            s.bytes_c2s += len(p.payload)
        else:
            s.bytes_s2c += len(p.payload)

        if p.proto == "tcp":
            if p.flag(TCP_SYN) and not p.flag(TCP_ACK):
                s.syn_seen = True
                if c2s:
                    s._isn_c = p.seq
            if p.flag(TCP_SYN) and p.flag(TCP_ACK):
                s.synack_seen = True
                if not c2s:
                    s._isn_s = p.seq
            if p.flag(TCP_FIN):
                s.fin_seen = True
            if p.flag(TCP_RST):
                s.rst_seen = True
            if p.payload:
                segs = s._segs_c2s if c2s else s._segs_s2c
                if len(segs) < 65536 and p.seq not in segs:
                    segs[p.seq] = p.payload
        return s

    @property
    def count(self) -> int:
        return len(self.sessions)
