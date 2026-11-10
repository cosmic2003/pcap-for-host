"""TLS ClientHello 에서 SNI(접속하려는 서버 이름)를 꺼낸다. 복호화는 하지 않는다.

ECH(Encrypted Client Hello) 확장(0xfe0d)이 있으면 바깥 SNI 는 실제 사이트가 아니라
공용 이름(예: cloudflare-ech.com)이므로, 호출자가 확신도를 '추정됨'으로 낮춰야 한다.
"""
from __future__ import annotations

from typing import Optional

EXT_SERVER_NAME = 0x0000
EXT_ECH = 0xFE0D


def client_hello_sni(stream: bytes) -> tuple[Optional[str], bool]:
    """(SNI 또는 None, ECH 사용 여부)."""
    try:
        if len(stream) < 9 or stream[0] != 0x16:   # handshake record
            return None, False
        rec_len = int.from_bytes(stream[3:5], "big")
        body = stream[5: 5 + rec_len]
        if not body or body[0] != 0x01:            # ClientHello
            return None, False
        p = 4 + 2 + 32                              # 헤더 + 버전 + random
        p += 1 + body[p]                            # session id
        p += 2 + int.from_bytes(body[p: p + 2], "big")   # cipher suites
        p += 1 + body[p]                            # compression
        end = min(len(body), p + 2 + int.from_bytes(body[p: p + 2], "big"))
        p += 2
        sni, ech = None, False
        while p + 4 <= end:
            etype = int.from_bytes(body[p: p + 2], "big")
            elen = int.from_bytes(body[p + 2: p + 4], "big")
            ext = body[p + 4: p + 4 + elen]
            if etype == EXT_SERVER_NAME and len(ext) >= 5 and ext[2] == 0:
                nlen = int.from_bytes(ext[3:5], "big")
                sni = ext[5: 5 + nlen].decode("ascii", "replace").lower() or None
            elif etype == EXT_ECH:
                ech = True
            p += 4 + elen
        return sni, ech
    except IndexError:
        return None, False
