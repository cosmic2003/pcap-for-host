"""DNS 메시지 파서.

압축 포인터(0xC0)를 지원하고, 포인터가 서로를 가리키는 악성 메시지에서
무한 루프에 빠지지 않도록 점프 횟수를 제한한다.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from ipaddress import ip_address

QTYPE = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 10: "NULL", 12: "PTR", 15: "MX",
         16: "TXT", 28: "AAAA", 33: "SRV", 255: "ANY"}


@dataclass
class DnsMessage:
    txid: int
    is_response: bool
    rcode: int                      # 0=NOERROR, 3=NXDOMAIN ...
    questions: list = field(default_factory=list)   # [(name, qtype_str)]
    answers: list = field(default_factory=list)     # [(name, type_str, rdata_str)]


def parse_name(msg: bytes, off: int, depth: int = 0) -> tuple[str, int]:
    """off에서 도메인 이름을 읽어 (이름, 다음 오프셋)을 돌려준다."""
    labels = []
    jumps = 0
    next_off = -1  # 포인터를 따라간 뒤 돌아올 위치
    while True:
        if off >= len(msg) or jumps > 20 or len(labels) > 127:
            break  # 깨진/악성 메시지 보호
        length = msg[off]
        if length == 0:
            off += 1
            break
        if length & 0xC0 == 0xC0:  # 압축 포인터
            if off + 2 > len(msg):
                break
            ptr = struct.unpack("!H", msg[off : off + 2])[0] & 0x3FFF
            if next_off < 0:
                next_off = off + 2
            if ptr >= off:  # 앞쪽만 가리킬 수 있음 (루프 방지)
                break
            off = ptr
            jumps += 1
            continue
        if length & 0xC0:  # 예약된 라벨 타입
            break
        labels.append(msg[off + 1 : off + 1 + length].decode("ascii", "replace"))
        off += 1 + length
    return ".".join(labels), (next_off if next_off >= 0 else off)


def parse(payload: bytes) -> DnsMessage | None:
    """UDP 페이로드를 DNS 메시지로 파싱. 아니면 None."""
    if len(payload) < 12:
        return None
    txid, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", payload[:12])
    msg = DnsMessage(txid=txid, is_response=bool(flags & 0x8000), rcode=flags & 0x0F)
    off = 12
    try:
        for _ in range(min(qd, 32)):
            name, off = parse_name(payload, off)
            if off + 4 > len(payload):
                return msg
            qtype = struct.unpack("!H", payload[off : off + 2])[0]
            off += 4
            msg.questions.append((name, QTYPE.get(qtype, str(qtype))))
        for _ in range(min(an, 64)):
            name, off = parse_name(payload, off)
            if off + 10 > len(payload):
                return msg
            rtype, _, _, rdlen = struct.unpack("!HHIH", payload[off : off + 10])
            off += 10
            rdata = payload[off : off + rdlen]
            off += rdlen
            msg.answers.append(
                (name, QTYPE.get(rtype, str(rtype)), _rdata_str(rtype, rdata, payload, off - rdlen))
            )
    except (struct.error, IndexError):
        pass  # 읽을 수 있는 데까지만
    return msg


def _rdata_str(rtype: int, rdata: bytes, msg: bytes, rd_off: int) -> str:
    try:
        if rtype == 1 and len(rdata) == 4:
            return str(ip_address(rdata))
        if rtype == 28 and len(rdata) == 16:
            return str(ip_address(rdata))
        if rtype in (2, 5, 12):  # NS / CNAME / PTR : 이름(압축 가능)
            return parse_name(msg, rd_off)[0]
        if rtype == 15 and len(rdata) >= 2:  # MX
            return parse_name(msg, rd_off + 2)[0]
        if rtype == 16:  # TXT: 길이 프리픽스 문자열 연쇄
            parts, off = [], 0
            while off < len(rdata):
                ln = rdata[off]
                parts.append(rdata[off + 1 : off + 1 + ln].decode("ascii", "replace"))
                off += 1 + ln
            return "".join(parts)
    except (ValueError, IndexError):
        pass
    return rdata.hex()
