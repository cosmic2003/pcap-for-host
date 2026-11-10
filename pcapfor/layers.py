"""링크/네트워크/전송 계층 디코더.

Ethernet(+VLAN) -> ARP | IPv4 | IPv6 -> TCP | UDP | ICMP 를 순수 파이썬으로 디코딩한다.
체크섬 검증은 하지 않는다(포렌식 입장에선 깨진 패킷도 증거다).
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from ipaddress import ip_address
from typing import Optional

from .pcapio import LINKTYPE_ETHERNET, LINKTYPE_LINUX_SLL, LINKTYPE_RAW_IP, RawPacket

ETH_IPV4 = 0x0800
ETH_ARP = 0x0806
ETH_VLAN = 0x8100
ETH_QINQ = 0x88A8
ETH_IPV6 = 0x86DD

TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_RST = 0x04
TCP_PSH = 0x08
TCP_ACK = 0x10


@dataclass
class Arp:
    op: int                 # 1=request, 2=reply
    sender_mac: str
    sender_ip: str
    target_mac: str
    target_ip: str


@dataclass
class Packet:
    """디코딩이 끝난 패킷 1개 (분석기가 쓰는 단위)."""
    number: int
    ts: float
    eth_src: str = ""
    eth_dst: str = ""
    vlan: Optional[int] = None
    arp: Optional[Arp] = None
    # IP
    src: str = ""
    dst: str = ""
    proto: str = ""          # "tcp" | "udp" | "icmp" | "other" | "" (IP 아님)
    ttl: int = 0
    # TCP/UDP
    sport: int = 0
    dport: int = 0
    tcp_flags: int = 0
    seq: int = 0
    ack: int = 0
    payload: bytes = b""
    icmp_type: int = -1

    def flag(self, f: int) -> bool:
        return bool(self.tcp_flags & f)


def _mac(b: bytes) -> str:
    return ":".join(f"{x:02x}" for x in b)


def decode(raw: RawPacket) -> Optional[Packet]:
    """RawPacket -> Packet. 디코딩 불가능하면 None."""
    pkt = Packet(number=raw.number, ts=raw.ts)
    data = raw.data
    if raw.linktype == LINKTYPE_ETHERNET:
        if len(data) < 14:
            return None
        pkt.eth_dst = _mac(data[0:6])
        pkt.eth_src = _mac(data[6:12])
        etype = struct.unpack("!H", data[12:14])[0]
        off = 14
        # VLAN 태그(중첩 QinQ 포함)를 벗긴다
        while etype in (ETH_VLAN, ETH_QINQ) and len(data) >= off + 4:
            tci = struct.unpack("!H", data[off : off + 2])[0]
            pkt.vlan = tci & 0x0FFF
            etype = struct.unpack("!H", data[off + 2 : off + 4])[0]
            off += 4
        return _dispatch_ethertype(pkt, etype, data[off:])
    if raw.linktype == LINKTYPE_LINUX_SLL:
        # Linux cooked capture: 패킷타입(2)+ARPHRD(2)+주소길이(2)+주소(8)+프로토콜(2)
        if len(data) < 16:
            return None
        etype = struct.unpack("!H", data[14:16])[0]
        return _dispatch_ethertype(pkt, etype, data[16:])
    if raw.linktype == LINKTYPE_RAW_IP:
        if data and (data[0] >> 4) == 6:
            return _decode_ipv6(pkt, data)
        return _decode_ipv4(pkt, data)
    return None


def _dispatch_ethertype(pkt: Packet, etype: int, body: bytes) -> Optional[Packet]:
    if etype == ETH_ARP:
        return _decode_arp(pkt, body)
    if etype == ETH_IPV4:
        return _decode_ipv4(pkt, body)
    if etype == ETH_IPV6:
        return _decode_ipv6(pkt, body)
    return pkt  # 알 수 없는 ethertype이라도 L2 정보는 유지


def _decode_arp(pkt: Packet, b: bytes) -> Optional[Packet]:
    # Ethernet/IPv4 ARP 고정 포맷 (28바이트)
    if len(b) < 28:
        return pkt
    op = struct.unpack("!H", b[6:8])[0]
    pkt.arp = Arp(
        op=op,
        sender_mac=_mac(b[8:14]),
        sender_ip=str(ip_address(b[14:18])),
        target_mac=_mac(b[18:24]),
        target_ip=str(ip_address(b[24:28])),
    )
    return pkt


def _decode_ipv4(pkt: Packet, b: bytes) -> Optional[Packet]:
    if len(b) < 20 or (b[0] >> 4) != 4:
        return pkt
    ihl = (b[0] & 0x0F) * 4
    total_len = struct.unpack("!H", b[2:4])[0]
    pkt.ttl = b[8]
    proto = b[9]
    pkt.src = str(ip_address(b[12:16]))
    pkt.dst = str(ip_address(b[16:20]))
    # 이더넷 패딩 제거: IP total length 기준으로 자른다
    end = min(len(b), total_len) if 20 <= total_len else len(b)
    return _decode_l4(pkt, proto, b[ihl:end])


def _decode_ipv6(pkt: Packet, b: bytes) -> Optional[Packet]:
    if len(b) < 40 or (b[0] >> 4) != 6:
        return pkt
    payload_len = struct.unpack("!H", b[4:6])[0]
    nxt = b[6]
    pkt.ttl = b[7]  # hop limit
    pkt.src = str(ip_address(b[8:24]))
    pkt.dst = str(ip_address(b[24:40]))
    body = b[40 : 40 + payload_len]
    # 확장 헤더 체인 추적 (hop-by-hop=0, routing=43, fragment=44, dest=60)
    hops = 0
    while nxt in (0, 43, 44, 60) and len(body) >= 8 and hops < 8:
        hdr_len = 8 if nxt == 44 else (body[1] + 1) * 8
        nxt = body[0]
        body = body[hdr_len:]
        hops += 1
    proto_map = {6: 6, 17: 17, 58: 1}  # ICMPv6은 icmp로 취급
    return _decode_l4(pkt, proto_map.get(nxt, nxt), body)


def _decode_l4(pkt: Packet, proto: int, b: bytes) -> Packet:
    if proto == 6 and len(b) >= 20:
        pkt.proto = "tcp"
        pkt.sport, pkt.dport, pkt.seq, pkt.ack = struct.unpack("!HHII", b[0:12])
        data_off = (b[12] >> 4) * 4
        pkt.tcp_flags = b[13]
        pkt.payload = b[data_off:]
    elif proto == 17 and len(b) >= 8:
        pkt.proto = "udp"
        pkt.sport, pkt.dport, ulen = struct.unpack("!HHH", b[0:6])
        pkt.payload = b[8 : max(8, min(len(b), ulen))]
    elif proto == 1 and len(b) >= 4:
        pkt.proto = "icmp"
        pkt.icmp_type = b[0]
        pkt.payload = b[4:]
    else:
        pkt.proto = "other"
        pkt.payload = b
    return pkt
