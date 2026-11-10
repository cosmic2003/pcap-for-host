"""재조립된 TCP 스트림에서 HTTP/1.x 트랜잭션을 복원한다.

지원: 파이프라인된 다중 요청/응답, Content-Length, chunked 전송 인코딩,
gzip/deflate 응답 본문 해제, HEAD(본문 없음), 100 Continue.
"""
from __future__ import annotations

import gzip
import zlib
from dataclasses import dataclass, field
from typing import Optional

METHODS = (b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ", b"OPTIONS ", b"PATCH ")
MAX_BODY = 1024 * 1024  # 트랜잭션당 본문 보관 상한


@dataclass
class HttpRequest:
    method: str
    uri: str
    version: str
    headers: dict = field(default_factory=dict)
    body: bytes = b""

    @property
    def host(self) -> str:
        return self.headers.get("host", "")


@dataclass
class HttpResponse:
    status: int
    reason: str
    headers: dict = field(default_factory=dict)
    body: bytes = b""


@dataclass
class HttpTransaction:
    request: Optional[HttpRequest]
    response: Optional[HttpResponse]


def looks_like_http(c2s: bytes) -> bool:
    return c2s.startswith(METHODS)


def parse_transactions(c2s: bytes, s2c: bytes) -> list[HttpTransaction]:
    requests = _parse_messages(c2s, is_request=True)
    responses = _parse_messages(s2c, is_request=False)
    # 100 Continue 는 짝에서 제외
    responses = [r for r in responses if not (isinstance(r, HttpResponse) and r.status == 100)]
    out = []
    for i in range(max(len(requests), len(responses))):
        req = requests[i] if i < len(requests) else None
        # HEAD 요청의 응답 본문은 규격상 없음 → 파서가 이미 처리
        resp = responses[i] if i < len(responses) else None
        out.append(HttpTransaction(req, resp))
    return out


def _parse_messages(stream: bytes, is_request: bool) -> list:
    msgs = []
    off = 0
    prev_method = None
    while off < len(stream) and len(msgs) < 500:
        head_end = stream.find(b"\r\n\r\n", off)
        if head_end < 0:
            break
        head = stream[off : head_end].decode("latin-1", "replace")
        lines = head.split("\r\n")
        start = lines[0]
        headers: dict[str, str] = {}
        for line in lines[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().lower()] = v.strip()
        body_off = head_end + 4

        if is_request:
            parts = start.split(" ", 2)
            if len(parts) < 3 or not start.startswith(tuple(m.decode() for m in METHODS)):
                break
            msg = HttpRequest(parts[0], parts[1], parts[2], headers)
            prev_method = parts[0]
            has_body = "content-length" in headers or headers.get("transfer-encoding", "").lower() == "chunked"
        else:
            if not start.startswith("HTTP/"):
                break
            parts = start.split(" ", 2)
            try:
                status = int(parts[1])
            except (IndexError, ValueError):
                break
            msg = HttpResponse(status, parts[2] if len(parts) > 2 else "", headers)
            # HEAD 응답과 1xx/204/304 는 본문 없음
            has_body = status >= 200 and status not in (204, 304)

        body = b""
        if has_body:
            te = headers.get("transfer-encoding", "").lower()
            if "chunked" in te:
                body, consumed = _read_chunked(stream, body_off)
                off = consumed
            elif "content-length" in headers:
                try:
                    clen = int(headers["content-length"])
                except ValueError:
                    clen = 0
                body = stream[body_off : body_off + clen]
                off = body_off + clen
            elif not is_request:
                body = stream[body_off:]  # 연결 종료로 끝나는 본문
                off = len(stream)
            else:
                off = body_off
        else:
            off = body_off

        if not is_request:
            body = _decompress(body, headers.get("content-encoding", "").lower())
        msg.body = body[:MAX_BODY]
        msgs.append(msg)
        if off <= head_end:  # 전진 보장
            break
    return msgs


def _read_chunked(stream: bytes, off: int) -> tuple[bytes, int]:
    body = bytearray()
    while off < len(stream):
        line_end = stream.find(b"\r\n", off)
        if line_end < 0:
            break
        size_token = stream[off:line_end].split(b";")[0].strip()
        try:
            size = int(size_token, 16)
        except ValueError:
            break
        off = line_end + 2
        if size == 0:
            # 트레일러 스킵
            trailer_end = stream.find(b"\r\n", off)
            off = (trailer_end + 2) if trailer_end >= 0 else len(stream)
            break
        body += stream[off : off + size]
        off += size + 2  # 데이터 + CRLF
        if len(body) > MAX_BODY:
            break
    return bytes(body), off


def _decompress(body: bytes, encoding: str) -> bytes:
    try:
        if "gzip" in encoding and body[:2] == b"\x1f\x8b":
            return gzip.decompress(body)
        if "deflate" in encoding:
            try:
                return zlib.decompress(body)
            except zlib.error:
                return zlib.decompress(body, -zlib.MAX_WBITS)  # raw deflate
    except (OSError, zlib.error, EOFError):
        pass  # 압축이 깨졌으면 원문 그대로 (포렌식: 증거 보존)
    return body
