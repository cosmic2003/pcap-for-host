"""실행 파일 신원: SHA-256, 코드 서명, 실행 위치, 시스템 프로세스 사칭 검사.

서명은 PowerShell Get-AuthenticodeSignature 로 확인한다(카탈로그 서명 포함).
PowerShell 실행은 느리므로 해시 단위로 캐시한다. 경로는 명령줄이 아니라
환경변수로 넘겨서 따옴표·특수문자에 의한 명령 주입을 막는다.

원칙: 서명이 없다는 사실만으로 악성이라 판단하지 않는다(정상 오픈소스도 서명이 없다).
여기서 나온 값은 점수의 '근거 하나'일 뿐이다.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass

# 정상 프로그램이 거의 실행되지 않는 위치 (소문자, 경로 부분 문자열)
SUSPICIOUS_DIRS = (
    "\\appdata\\local\\temp\\", "\\windows\\temp\\", "\\downloads\\",
    "\\users\\public\\", "\\$recycle.bin\\",
)
# 이름이 같으면 반드시 \Windows\ 아래에 있어야 하는 시스템 프로세스
SYSTEM_NAMES = {
    "svchost.exe", "lsass.exe", "csrss.exe", "services.exe", "winlogon.exe",
    "smss.exe", "explorer.exe", "spoolsv.exe", "taskhostw.exe", "rundll32.exe",
    "dllhost.exe", "conhost.exe", "wininit.exe", "lsm.exe", "searchindexer.exe",
}


@dataclass(frozen=True)
class SigInfo:
    status: str   # Valid | NotSigned | HashMismatch | ... | Unknown
    signer: str   # 인증서 CN ("" 이면 없음)

    @property
    def signed(self) -> bool:
        return self.status == "Valid"


def _levenshtein1(a: str, b: str) -> bool:
    """편집 거리가 정확히 1 인가 (svch0st.exe 같은 유사 이름 탐지)."""
    if a == b or abs(len(a) - len(b)) > 1:
        return False
    if len(a) == len(b):
        return sum(x != y for x, y in zip(a, b)) == 1
    if len(a) > len(b):
        a, b = b, a
    i = 0
    while i < len(a) and a[i] == b[i]:
        i += 1
    return a[i:] == b[i + 1:]


def location_flags(path: str, name: str) -> list[tuple[str, str]]:
    """(코드, 설명) 목록. 경로를 모르면 판단하지 않는다."""
    flags = []
    p = path.lower().replace("/", "\\")
    n = name.lower()
    if p:
        for d in SUSPICIOUS_DIRS:
            if d in p:
                flags.append(("suspicious_dir", f"비정상 실행 위치({d.strip(chr(92))}): {path}"))
                break
        if n in SYSTEM_NAMES and "\\windows\\" not in p:
            flags.append(("masquerade", f"시스템 프로세스 이름({name})인데 Windows 폴더 밖에서 실행: {path}"))
    if n not in SYSTEM_NAMES:
        for sysname in SYSTEM_NAMES:
            if _levenshtein1(n, sysname):
                flags.append(("lookalike", f"시스템 프로세스와 한 글자 다른 이름: {name} ≈ {sysname}"))
                break
    return flags


class FileIdentity:
    """해시·서명 캐시. 경로+크기+수정시각이 같으면 다시 해시하지 않는다."""

    def __init__(self) -> None:
        self._hash_cache: dict[tuple, str] = {}
        self._sig_cache: dict[str, SigInfo] = {}

    def sha256(self, path: str) -> str:
        if not path:
            return ""
        try:
            st = os.stat(path)
        except OSError:
            return ""
        key = (path.lower(), st.st_size, st.st_mtime_ns)
        if key in self._hash_cache:
            return self._hash_cache[key]
        h = hashlib.sha256()
        try:
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(1 << 20), b""):
                    h.update(chunk)
        except OSError:
            return ""
        self._hash_cache[key] = h.hexdigest()
        return self._hash_cache[key]

    def signature(self, path: str, sha: str) -> SigInfo:
        if not path or sys.platform != "win32":
            return SigInfo("Unknown", "")
        cache_key = sha or path.lower()
        if cache_key in self._sig_cache:
            return self._sig_cache[cache_key]
        script = (
            "$s = Get-AuthenticodeSignature -LiteralPath $env:PCAPFOR_SIGPATH;"
            "$sub = ''; if ($s.SignerCertificate) { $sub = $s.SignerCertificate.Subject };"
            "[pscustomobject]@{Status=[string]$s.Status; Subject=$sub} | ConvertTo-Json -Compress"
        )
        env = dict(os.environ, PCAPFOR_SIGPATH=path)
        info = SigInfo("Unknown", "")
        try:
            r = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
                capture_output=True, text=True, timeout=20, env=env,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            doc = json.loads(r.stdout.strip() or "{}")
            m = re.search(r"CN=\"?([^,\"]+)", doc.get("Subject", "") or "")
            info = SigInfo(doc.get("Status", "Unknown") or "Unknown", m.group(1).strip() if m else "")
        except (OSError, subprocess.TimeoutExpired, ValueError):
            pass
        self._sig_cache[cache_key] = info
        return info
