"""연결 -> 프로세스 귀속 (Windows).

iphlpapi 의 GetExtendedTcpTable / GetExtendedUdpTable 로 소켓을 소유한 PID 를 얻고,
Toolhelp 스냅샷(이름·부모 PID)과 QueryFullProcessImageNameW(실행 경로),
GetProcessTimes(시작 시각)로 프로세스 정보를 붙인다. 외부 라이브러리 없음.

한계 대응
- 짧은 연결: 백그라운드 스레드가 poll_sec 마다 테이블을 읽고, 사라진 연결도
  linger_sec 동안 캐시에 남겨 패킷 도착과 조회 사이의 시차를 메운다.
- PID 재사용: 프로세스를 (pid, 시작 시각) 쌍으로 식별한다. 같은 PID 라도
  시작 시각이 다르면 다른 프로세스다.
- 매핑 실패: resolve() 가 None 을 돌려주고, 호출자가 '미귀속'으로 기록한다.
"""
from __future__ import annotations

import socket
import struct
import sys
import threading
import time
from collections import Counter
from dataclasses import dataclass
from typing import Optional

UNATTRIBUTED = "<미귀속>"


@dataclass(frozen=True)
class ProcInfo:
    pid: int
    name: str
    path: str            # 실행 파일 전체 경로 (권한 부족이면 "")
    start_time: float    # epoch 초. 0 이면 알 수 없음
    ppid: int = 0
    parent_name: str = ""

    @property
    def key(self) -> str:
        """프로파일 키: 경로가 있으면 경로, 없으면 이름 (대소문자 무시)."""
        return (self.path or self.name).lower()


def _v4(b16: bytes) -> Optional[str]:
    """IPv6 주소 바이트 -> IPv4 문자열. ::ffff:a.b.c.d 는 a.b.c.d, :: 는 0.0.0.0, 그 외 None."""
    if b16 == b"\x00" * 16:
        return "0.0.0.0"
    if b16[:12] == b"\x00" * 10 + b"\xff\xff":
        return socket.inet_ntoa(b16[12:])
    return None


class ConnSource:
    """연결 테이블 공급자 인터페이스 (테스트에선 가짜 구현을 끼운다)."""

    def connections(self) -> dict[tuple, int]:
        """{("tcp", lip, lport, rip, rport) | ("udp", lip, lport): pid}"""
        raise NotImplementedError

    def process(self, pid: int) -> Optional[ProcInfo]:
        raise NotImplementedError

    def refresh_names(self) -> None:
        """폴링마다 한 번 호출된다 (프로세스 이름/부모 스냅샷 갱신용)."""


# --------------------------------------------------------------- Windows 구현

class WindowsConnSource(ConnSource):
    TCP_TABLE_OWNER_PID_ALL = 5
    UDP_TABLE_OWNER_PID = 1
    ERROR_INSUFFICIENT_BUFFER = 122
    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    TH32CS_SNAPPROCESS = 0x2
    _EPOCH_DIFF = 116444736000000000  # 1601-01-01 -> 1970-01-01 (100ns 단위)

    def __init__(self) -> None:
        import ctypes
        from ctypes import wintypes

        self._ct = ctypes
        self._wt = wintypes
        self._iphlp = ctypes.WinDLL("iphlpapi")
        self._k32 = ctypes.WinDLL("kernel32", use_last_error=True)

        class PROCESSENTRY32W(ctypes.Structure):
            _fields_ = [
                ("dwSize", wintypes.DWORD), ("cntUsage", wintypes.DWORD),
                ("th32ProcessID", wintypes.DWORD), ("th32DefaultHeapID", ctypes.c_size_t),
                ("th32ModuleID", wintypes.DWORD), ("cntThreads", wintypes.DWORD),
                ("th32ParentProcessID", wintypes.DWORD), ("pcPriClassBase", wintypes.LONG),
                ("dwFlags", wintypes.DWORD), ("szExeFile", wintypes.WCHAR * 260),
            ]
        self._PE = PROCESSENTRY32W

        k = self._k32
        k.OpenProcess.restype = wintypes.HANDLE
        k.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        k.CloseHandle.argtypes = [wintypes.HANDLE]
        k.QueryFullProcessImageNameW.argtypes = [
            wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
        k.GetProcessTimes.argtypes = [wintypes.HANDLE] + [ctypes.POINTER(ctypes.c_ulonglong)] * 4
        k.GetLongPathNameW.argtypes = [wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD]
        k.GetLongPathNameW.restype = wintypes.DWORD
        k.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
        k.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
        k.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
        k.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]

        self._names: dict[int, tuple[str, int]] = {}   # pid -> (exe 이름, 부모 pid)
        # 서비스(svchost 등)의 경로·시작 시각을 읽으려면 관리자 세션에서 SeDebugPrivilege 를 켜야 한다
        self.debug_privilege = self._enable_debug_privilege()

    def _enable_debug_privilege(self) -> bool:
        ct, wt = self._ct, self._wt
        try:
            adv = ct.WinDLL("advapi32", use_last_error=True)

            class LUID(ct.Structure):
                _fields_ = [("LowPart", wt.DWORD), ("HighPart", wt.LONG)]

            class TOKEN_PRIVILEGES(ct.Structure):
                _fields_ = [("PrivilegeCount", wt.DWORD), ("Luid", LUID), ("Attributes", wt.DWORD)]

            self._k32.GetCurrentProcess.restype = wt.HANDLE
            adv.OpenProcessToken.argtypes = [wt.HANDLE, wt.DWORD, ct.POINTER(wt.HANDLE)]
            adv.LookupPrivilegeValueW.argtypes = [wt.LPCWSTR, wt.LPCWSTR, ct.POINTER(LUID)]
            adv.AdjustTokenPrivileges.argtypes = [wt.HANDLE, wt.BOOL, ct.POINTER(TOKEN_PRIVILEGES),
                                                  wt.DWORD, ct.c_void_p, ct.c_void_p]
            token = wt.HANDLE()
            if not adv.OpenProcessToken(self._k32.GetCurrentProcess(), 0x20 | 0x8, ct.byref(token)):
                return False
            try:
                luid = LUID()
                if not adv.LookupPrivilegeValueW(None, "SeDebugPrivilege", ct.byref(luid)):
                    return False
                tp = TOKEN_PRIVILEGES(1, luid, 0x2)   # SE_PRIVILEGE_ENABLED
                adv.AdjustTokenPrivileges(token, False, ct.byref(tp), 0, None, None)
                return ct.get_last_error() == 0       # 1300 = 권한이 토큰에 없음(비관리자)
            finally:
                self._k32.CloseHandle(token)
        except (OSError, AttributeError):
            return False

    # -- 연결 테이블
    def _table(self, fn, table_class: int, family: int = socket.AF_INET) -> bytes:
        ct, wt = self._ct, self._wt
        size = wt.DWORD(0)
        fn(None, ct.byref(size), False, family, table_class, 0)
        for _ in range(4):  # 조회 사이에 테이블이 커질 수 있다
            buf = ct.create_string_buffer(size.value or 4)
            ret = fn(buf, ct.byref(size), False, family, table_class, 0)
            if ret == 0:
                return buf.raw[: size.value]
            if ret != self.ERROR_INSUFFICIENT_BUFFER:
                return b""
        return b""

    def connections(self) -> dict[tuple, int]:
        out: dict[tuple, int] = {}
        raw = self._table(self._iphlp.GetExtendedTcpTable, self.TCP_TABLE_OWNER_PID_ALL)
        if len(raw) >= 4:
            n = struct.unpack_from("<I", raw, 0)[0]
            for i in range(n):
                off = 4 + i * 24  # MIB_TCPROW_OWNER_PID: DWORD x 6
                if off + 24 > len(raw):
                    break
                pid = struct.unpack_from("<I", raw, off + 20)[0]
                if pid == 0:      # TIME_WAIT 등 주인 없는 행 (System Idle 로 오귀속 방지)
                    continue
                lip = socket.inet_ntoa(raw[off + 4: off + 8])
                lport = struct.unpack_from(">H", raw, off + 8)[0]
                rip = socket.inet_ntoa(raw[off + 12: off + 16])
                rport = struct.unpack_from(">H", raw, off + 16)[0]
                out[("tcp", lip, lport, rip, rport)] = pid
        raw = self._table(self._iphlp.GetExtendedUdpTable, self.UDP_TABLE_OWNER_PID)
        if len(raw) >= 4:
            n = struct.unpack_from("<I", raw, 0)[0]
            for i in range(n):
                off = 4 + i * 12  # MIB_UDPROW_OWNER_PID: DWORD x 3
                if off + 12 > len(raw):
                    break
                pid = struct.unpack_from("<I", raw, off + 8)[0]
                if pid == 0:
                    continue
                lip = socket.inet_ntoa(raw[off: off + 4])
                lport = struct.unpack_from(">H", raw, off + 4)[0]
                out[("udp", lip, lport)] = pid
        # 듀얼스택(IPv4/IPv6 겸용) 소켓은 IPv6 테이블에만 나온다. 크롬 QUIC 등.
        # IPv4-mapped(::ffff:a.b.c.d) 와 와일드카드(::)만 IPv4 키로 옮긴다.
        raw = self._table(self._iphlp.GetExtendedTcpTable, self.TCP_TABLE_OWNER_PID_ALL, socket.AF_INET6)
        if len(raw) >= 4:
            n = struct.unpack_from("<I", raw, 0)[0]
            for i in range(n):
                off = 4 + i * 56  # MIB_TCP6ROW_OWNER_PID
                if off + 56 > len(raw):
                    break
                pid = struct.unpack_from("<I", raw, off + 52)[0]
                lip, rip = _v4(raw[off: off + 16]), _v4(raw[off + 24: off + 40])
                if pid == 0 or lip is None or rip is None:
                    continue
                lport = struct.unpack_from(">H", raw, off + 20)[0]
                rport = struct.unpack_from(">H", raw, off + 44)[0]
                out.setdefault(("tcp", lip, lport, rip, rport), pid)
        raw = self._table(self._iphlp.GetExtendedUdpTable, self.UDP_TABLE_OWNER_PID, socket.AF_INET6)
        if len(raw) >= 4:
            n = struct.unpack_from("<I", raw, 0)[0]
            for i in range(n):
                off = 4 + i * 28  # MIB_UDP6ROW_OWNER_PID
                if off + 28 > len(raw):
                    break
                pid = struct.unpack_from("<I", raw, off + 24)[0]
                lip = _v4(raw[off: off + 16])
                if pid == 0 or lip is None:
                    continue
                lport = struct.unpack_from(">H", raw, off + 20)[0]
                out.setdefault(("udp", lip, lport), pid)
        return out

    # -- 프로세스 정보
    def refresh_names(self) -> None:
        ct, k = self._ct, self._k32
        snap = k.CreateToolhelp32Snapshot(self.TH32CS_SNAPPROCESS, 0)
        if not snap or snap == self._wt.HANDLE(-1).value:
            return
        names: dict[int, tuple[str, int]] = {}
        try:
            pe = self._PE()
            pe.dwSize = ct.sizeof(self._PE)
            ok = k.Process32FirstW(snap, ct.byref(pe))
            while ok:
                names[pe.th32ProcessID] = (pe.szExeFile, pe.th32ParentProcessID)
                ok = k.Process32NextW(snap, ct.byref(pe))
        finally:
            k.CloseHandle(snap)
        self._names = names

    def _long_path(self, path: str) -> str:
        """C:\\Users\\OHHYEO~1\\... 같은 8.3 짧은 이름을 긴 경로로 바꾼다 (실패하면 그대로)."""
        if "~" not in path:
            return path
        ct = self._ct
        buf = ct.create_unicode_buffer(1024)
        n = self._k32.GetLongPathNameW(path, buf, 1024)
        return buf.value if 0 < n < 1024 else path

    def process(self, pid: int) -> Optional[ProcInfo]:
        ct, wt, k = self._ct, self._wt, self._k32
        name, ppid = self._names.get(pid, ("", 0))
        if pid == 0:
            return ProcInfo(0, "System Idle Process", "", 0.0)
        if pid == 4:
            return ProcInfo(4, "System", "", 0.0)
        path, start = "", 0.0
        h = k.OpenProcess(self.PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if h:
            try:
                buf = ct.create_unicode_buffer(1024)
                size = wt.DWORD(1024)
                if k.QueryFullProcessImageNameW(h, 0, buf, ct.byref(size)):
                    path = self._long_path(buf.value)
                created = ct.c_ulonglong()
                dummy = [ct.c_ulonglong() for _ in range(3)]
                if k.GetProcessTimes(h, ct.byref(created), *[ct.byref(d) for d in dummy]):
                    start = (created.value - self._EPOCH_DIFF) / 1e7
            finally:
                k.CloseHandle(h)
        if not name and path:
            name = path.replace("/", "\\").rsplit("\\", 1)[-1]
        if not name and not path:
            return None  # 이미 종료됐거나 접근 불가
        parent = self._names.get(ppid, ("", 0))[0]
        return ProcInfo(pid, name, path, start, ppid, parent)


# --------------------------------------------------------------- 귀속기

class ProcessResolver:
    """연결 4-튜플 -> ProcInfo. poll() 을 주기적으로 불러야 한다."""

    def __init__(self, source: ConnSource, poll_sec: float = 0.5, linger_sec: float = 120.0):
        self.source = source
        self.poll_sec = poll_sec
        self.linger_sec = linger_sec
        self._conns: dict[tuple, tuple[ProcInfo, float]] = {}  # 연결 -> (프로세스, 마지막 관측)
        self._procs: dict[int, ProcInfo] = {}                   # pid -> 현재 프로세스
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._wake = threading.Event()
        self.min_gap = 0.05
        self.recheck_sec = 5.0
        self._checked: dict[int, float] = {}
        self._thread: Optional[threading.Thread] = None
        self.stats: Counter = Counter()

    def poll(self, now: Optional[float] = None) -> None:
        now = time.time() if now is None else now
        try:
            self.source.refresh_names()
            conns = self.source.connections()
        except OSError:
            self.stats["poll_error"] += 1
            return
        fresh: dict[int, Optional[ProcInfo]] = {}
        for key, pid in conns.items():
            if pid in fresh:
                continue
            # 프로세스 정보는 PID 당 recheck_sec 마다만 다시 읽는다 (빠른 재조회 시 부하 억제)
            cached = self._procs.get(pid)
            if cached is not None and now - self._checked.get(pid, 0) < self.recheck_sec:
                fresh[pid] = cached
            else:
                fresh[pid] = self.source.process(pid)
                self._checked[pid] = now
        with self._lock:
            for pid, info in fresh.items():
                if info is None:
                    continue
                old = self._procs.get(pid)
                # PID 재사용 감지: 시작 시각이 달라졌으면 다른 프로세스
                if old is not None and old.start_time and info.start_time \
                        and abs(old.start_time - info.start_time) > 1.0:
                    self.stats["pid_reuse"] += 1
                self._procs[pid] = info
            for key, pid in conns.items():
                info = fresh.get(pid)
                if info is not None:
                    self._conns[key] = (info, now)
                    if key[0] == "udp":   # 어떤 로컬 주소에 묶였든 포트로 찾을 수 있게
                        self._conns[("udp", "*", key[2])] = (info, now)
            cutoff = now - self.linger_sec
            for key in [k for k, (_, seen) in self._conns.items() if seen < cutoff]:
                del self._conns[key]
            self.stats["polls"] += 1

    def resolve(self, proto: str, local_ip: str, lport: int,
                remote_ip: str, rport: int) -> Optional[ProcInfo]:
        if proto == "tcp":
            keys = [("tcp", local_ip, lport, remote_ip, rport),
                    ("tcp", "0.0.0.0", lport, remote_ip, rport)]
        elif proto == "udp":
            keys = [("udp", local_ip, lport), ("udp", "0.0.0.0", lport), ("udp", "*", lport)]
        else:
            return None
        with self._lock:
            for k in keys:
                hit = self._conns.get(k)
                if hit:
                    self.stats["hit"] += 1
                    return hit[0]
        self.stats["miss"] += 1
        return None

    # -- 백그라운드 폴링
    def wake(self) -> None:
        """조회 실패 시 호출: 다음 주기를 기다리지 않고 곧바로 테이블을 다시 읽게 한다."""
        self._wake.set()

    def start(self) -> None:
        def loop():
            while not self._stop.is_set():
                self._wake.wait(self.poll_sec)
                self._wake.clear()
                if self._stop.is_set():
                    break
                self.poll()
                time.sleep(self.min_gap)   # 깨우기가 몰려도 CPU 를 잡아먹지 않게
        self.poll()
        self._thread = threading.Thread(target=loop, daemon=True, name="procmap-poll")
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._wake.set()
        if self._thread:
            self._thread.join(timeout=2)


def default_source() -> Optional[ConnSource]:
    """현재 OS 에서 쓸 수 있는 연결 소스. 윈도우가 아니면 None (전부 미귀속)."""
    if sys.platform == "win32":
        try:
            return WindowsConnSource()
        except (OSError, AttributeError):
            return None
    return None


def _diagnose() -> int:
    """python -m pcapfor.procmap : 이 PC 에서 프로세스 귀속이 얼마나 되는지 점검."""
    import ctypes
    src = default_source()
    if src is None:
        print("이 OS 에서는 프로세스 귀속을 쓸 수 없습니다 (Windows 전용)")
        return 1
    try:
        admin = bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        admin = False
    r = ProcessResolver(src)
    r.poll()
    procs = {i.pid: i for i, _ in r._conns.values()}
    with_path = [i for i in procs.values() if i.path or i.pid in (0, 4)]
    print(f"관리자 세션: {'예' if admin else '아니오 (서비스 프로세스 정보는 못 읽음)'}")
    print(f"SeDebugPrivilege: {'켜짐' if getattr(src, 'debug_privilege', False) else '꺼짐'}")
    print(f"연결 {len(r._conns)}개 · 프로세스 {len(procs)}개 · 경로 확인 {len(with_path)}/{len(procs)}")
    missing = sorted({i.name for i in procs.values() if not i.path and i.pid not in (0, 4)})
    if missing:
        print("경로를 못 읽은 프로세스:", ", ".join(missing[:15]))
    for i in sorted(procs.values(), key=lambda x: x.name.lower())[:12]:
        st = time.strftime("%H:%M:%S", time.localtime(i.start_time)) if i.start_time else "-"
        print(f"  {i.name:<28} PID {i.pid:<6} 시작 {st}  {i.path or '(경로 없음)'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(_diagnose())
