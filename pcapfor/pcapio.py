"""pcap / pcapng 파일 리더 (외부 의존성 없음).

둘 다 바이너리 포맷을 직접 파싱한다.
- pcap  : 24바이트 전역 헤더 + (16바이트 레코드 헤더 + 패킷 데이터) 반복
- pcapng: 블록 단위 (SHB / IDB / EPB ...), 블록마다 길이가 앞뒤로 붙는다

잘린(truncated) 파일은 에러 대신 읽을 수 있는 데까지 읽고 끝낸다.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Iterator

# 링크 타입 (우리가 디코딩할 수 있는 것)
LINKTYPE_ETHERNET = 1
LINKTYPE_RAW_IP = 101
LINKTYPE_LINUX_SLL = 113   # Linux cooked capture (tcpdump -i any)

PCAP_MAGIC_US = 0xA1B2C3D4   # 마이크로초 타임스탬프
PCAP_MAGIC_NS = 0xA1B23C4D   # 나노초 타임스탬프
PCAPNG_SHB = 0x0A0D0D0A      # Section Header Block 타입
PCAPNG_BYTE_ORDER = 0x1A2B3C4D


@dataclass
class RawPacket:
    """파일에서 꺼낸 원시 패킷 1개."""
    ts: float          # epoch 초 (UTC)
    data: bytes        # 캡처된 바이트 (스냅랩 적용분)
    orig_len: int      # 와이어 상의 원래 길이
    linktype: int      # LINKTYPE_*
    number: int        # 파일 내 1-base 순번


class PcapFormatError(ValueError):
    pass


def read_packets(path: str) -> Iterator[RawPacket]:
    """pcap인지 pcapng인지 매직으로 판별해서 패킷을 순서대로 낸다."""
    with open(path, "rb") as f:
        head = f.read(4)
        if len(head) < 4:
            raise PcapFormatError("파일이 너무 짧습니다")
        magic = struct.unpack("<I", head)[0]
        f.seek(0)
        if magic == PCAPNG_SHB:
            yield from _read_pcapng(f)
        elif magic in (PCAP_MAGIC_US, PCAP_MAGIC_NS) or struct.unpack(">I", head)[0] in (
            PCAP_MAGIC_US,
            PCAP_MAGIC_NS,
        ):
            yield from _read_pcap(f)
        else:
            raise PcapFormatError(f"pcap/pcapng 매직이 아님: 0x{magic:08X}")


def _read_pcap(f) -> Iterator[RawPacket]:
    header = f.read(24)
    if len(header) < 24:
        raise PcapFormatError("pcap 전역 헤더가 잘려 있습니다")
    magic_le = struct.unpack("<I", header[:4])[0]
    if magic_le in (PCAP_MAGIC_US, PCAP_MAGIC_NS):
        endian = "<"
        magic = magic_le
    else:
        endian = ">"
        magic = struct.unpack(">I", header[:4])[0]
        if magic not in (PCAP_MAGIC_US, PCAP_MAGIC_NS):
            raise PcapFormatError("알 수 없는 pcap 매직")
    ts_div = 1e9 if magic == PCAP_MAGIC_NS else 1e6
    # version_major, version_minor, thiszone, sigfigs, snaplen, network
    _, _, _, _, _, linktype = struct.unpack(endian + "HHiIII", header[4:24])

    number = 0
    while True:
        rec = f.read(16)
        if len(rec) < 16:
            return  # 정상 EOF 또는 잘린 꼬리
        ts_sec, ts_frac, incl_len, orig_len = struct.unpack(endian + "IIII", rec)
        if incl_len > 0x7FFFFFFF:
            return  # 깨진 레코드
        data = f.read(incl_len)
        if len(data) < incl_len:
            return  # 잘린 패킷은 버린다
        number += 1
        yield RawPacket(ts_sec + ts_frac / ts_div, data, orig_len, linktype, number)


def _read_pcapng(f) -> Iterator[RawPacket]:
    endian = "<"
    interfaces: list[tuple[int, float]] = []  # (linktype, 타임스탬프 해상도 초/틱)
    number = 0
    while True:
        bh = f.read(8)
        if len(bh) < 8:
            return
        btype = struct.unpack(endian + "I", bh[:4])[0]
        # SHB는 바이트 오더가 블록 안에서 결정되므로 먼저 처리
        if btype == PCAPNG_SHB or struct.unpack(">I", bh[:4])[0] == PCAPNG_SHB:
            body_peek = f.read(4)
            if len(body_peek) < 4:
                return
            bom = struct.unpack("<I", body_peek)[0]
            endian = "<" if bom == PCAPNG_BYTE_ORDER else ">"
            blen = struct.unpack(endian + "I", bh[4:8])[0]
            # 남은 본문(이미 12바이트 소비) + 끝 길이 4바이트를 건너뜀
            f.read(blen - 12)
            interfaces = []  # 새 섹션이면 인터페이스 목록 리셋
            continue
        blen = struct.unpack(endian + "I", bh[4:8])[0]
        if blen < 12 or blen % 4 != 0:
            return
        body = f.read(blen - 12)
        if len(body) < blen - 12:
            return
        f.read(4)  # trailing block length

        if btype == 1:  # Interface Description Block
            if len(body) < 8:
                continue
            linktype = struct.unpack(endian + "H", body[0:2])[0]
            tsresol = 1e-6  # 기본: 마이크로초
            for code, val in _iter_options(body[8:], endian):
                if code == 9 and len(val) == 1:  # if_tsresol
                    v = val[0]
                    tsresol = 2.0 ** -(v & 0x7F) if v & 0x80 else 10.0 ** -v
            interfaces.append((linktype, tsresol))
        elif btype == 6:  # Enhanced Packet Block
            if len(body) < 20:
                continue
            if_id, ts_hi, ts_lo, cap_len, orig_len = struct.unpack(
                endian + "IIIII", body[:20]
            )
            data = body[20 : 20 + cap_len]
            if if_id < len(interfaces):
                linktype, tsresol = interfaces[if_id]
            else:
                linktype, tsresol = LINKTYPE_ETHERNET, 1e-6
            ts = ((ts_hi << 32) | ts_lo) * tsresol
            number += 1
            yield RawPacket(ts, data, orig_len, linktype, number)
        # 그 외 블록(SPB, NRB, ISB...)은 건너뛴다


def _iter_options(buf: bytes, endian: str):
    """pcapng 옵션 TLV 나열. (끝 옵션 0에서 중단)"""
    off = 0
    while off + 4 <= len(buf):
        code, length = struct.unpack(endian + "HH", buf[off : off + 4])
        off += 4
        if code == 0:
            return
        yield code, buf[off : off + length]
        off += (length + 3) & ~3  # 4바이트 패딩


class PcapWriter:
    """패킷을 받는 즉시 기록하는 스트리밍 pcap 라이터 (라이브 모드 증거 저장용)."""

    def __init__(self, path: str, linktype: int = LINKTYPE_ETHERNET):
        self._f = open(path, "wb")
        self._f.write(struct.pack("<IHHiIII", PCAP_MAGIC_US, 2, 4, 0, 0, 65535, linktype))
        self.count = 0

    def write(self, ts: float, data: bytes) -> None:
        sec = int(ts)
        usec = int(round((ts - sec) * 1e6))
        self._f.write(struct.pack("<IIII", sec, usec, len(data), len(data)))
        self._f.write(data)
        self.count += 1

    def close(self) -> None:
        self._f.close()


def write_pcap(path: str, packets, linktype: int = LINKTYPE_ETHERNET) -> None:
    """(ts, bytes) 목록을 리틀엔디언 마이크로초 pcap으로 저장."""
    w = PcapWriter(path, linktype)
    try:
        for ts, data in packets:
            w.write(ts, data)
    finally:
        w.close()
