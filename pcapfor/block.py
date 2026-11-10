"""차단 모듈: 의심 목적지를 Windows 방화벽(netsh advfirewall)으로 막고 되돌린다.

설계 원칙 (오탐 하나로 인터넷이 끊기는 일을 막기 위해)
1. 차단 금지 목록: 사설·루프백·멀티캐스트 대역, 이 PC 의 IP, 관측된 DNS 서버,
   사용자 --allow 파일. 여기에 걸리는 IP 는 절대 규칙으로 만들지 않는다.
2. 단계: off(아무것도 안 함) / suggest(명령만 보여줌, 기본) / ask(콘솔에서 승인)
   / auto(실험적: 위험도 '높음' 제안을 바로 적용).
3. TTL: 모든 차단은 기본 30분 뒤 자동 해제된다. 프로그램이 죽어도 다음 실행 때
   상태 파일을 보고 만료된 규칙을 지운다.
4. 롤백: 이 도구가 만든 규칙(이름이 pcapfor-block- 로 시작)만 지운다.
5. 행동 로그: 언제, 누가(사용자/자동), 어떤 근거로, 무엇을 막았는지 상태 파일과
   타임라인에 남긴다.
6. --dry-run 이면 명령을 실행하지 않고 보여주기만 한다.

막는 단위는 '목적지 IP'다. Windows 방화벽은 프로그램 경로 기준 규칙도 되지만,
감염된 실행 파일이 이름·위치를 바꾸면 무력해지므로 목적지 기준을 기본으로 한다.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
from dataclasses import asdict, dataclass, field
from ipaddress import ip_address
from typing import Callable, Optional

from .behavior import is_external
from .timeline import Event, Suggestion, Timeline

RULE_PREFIX = "pcapfor-block-"
MODES = ("off", "suggest", "ask", "auto")


@dataclass
class Block:
    bid: int
    rule: str
    ips: list
    proc_key: str
    proc_name: str
    pid: int
    start_time: float
    risk: float
    reasons: list
    created: float                 # 제안 시각
    status: str = "pending"        # pending | active | denied | expired | removed | failed | dry-run
    approved_by: str = ""          # user | auto
    applied: float = 0.0           # 실제 적용 시각
    expires: float = 0.0
    removed: float = 0.0
    skipped: list = field(default_factory=list)   # 차단 금지 목록이라 뺀 IP와 이유
    log: list = field(default_factory=list)       # [{ts, action, detail}]
    error: str = ""

    def note(self, ts: float, action: str, detail: str = "") -> None:
        self.log.append({"ts": ts, "action": action, "detail": detail})


def _default_executor(argv: list[str]) -> tuple[int, str]:
    if sys.platform != "win32":
        return 1, "Windows 방화벽은 Windows 에서만 조작할 수 있습니다"
    try:
        r = subprocess.run(argv, capture_output=True, text=True, errors="replace", timeout=30,
                           creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        return r.returncode, (r.stdout + r.stderr).strip()
    except (OSError, subprocess.TimeoutExpired) as e:
        return 1, str(e)


class Blocker:
    def __init__(self, mode: str = "suggest", ttl: float = 1800.0, allow=(),
                 local_ips=(), dry_run: bool = False,
                 state_path: Optional[str] = "pcapfor_blocks.json",
                 executor: Optional[Callable[[list], tuple]] = None,
                 timeline: Optional[Timeline] = None):
        if mode not in MODES:
            raise ValueError(f"mode 는 {MODES} 중 하나")
        self.mode = mode
        self.ttl = ttl
        self.dry_run = dry_run
        self.state_path = state_path
        self.run = executor or _default_executor
        self.timeline = timeline
        self.allow: dict[str, str] = {ip: "사용자 허용 목록" for ip in allow}
        for ip in local_ips:
            self.allow[ip] = "이 PC 의 IP"
        self.blocks: list[Block] = []
        self._load()

    # ------------------------------------------------------------ 허용 목록
    def add_allow(self, ip: str, why: str) -> None:
        self.allow.setdefault(ip, why)

    def why_not(self, ip: str) -> Optional[str]:
        """차단하면 안 되는 이유. None 이면 차단 가능."""
        try:
            ip_address(ip)
        except ValueError:
            return "IP 형식 아님"
        if ip in self.allow:
            return self.allow[ip]
        if not is_external(ip):
            return "사설/루프백/멀티캐스트 대역 (게이트웨이 등 내부망 보호)"
        return None

    @staticmethod
    def load_allow_file(path: str) -> list[str]:
        out = []
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.split("#", 1)[0].strip()
                if line:
                    out.append(line)
        return out

    # ------------------------------------------------------------ 명령
    @staticmethod
    def add_commands(b: Block) -> list[list[str]]:
        ips = ",".join(b.ips)
        return [["netsh", "advfirewall", "firewall", "add", "rule", f"name={b.rule}",
                 f"dir={d}", "action=block", f"remoteip={ips}", "enable=yes"]
                for d in ("out", "in")]   # 근거는 규칙 설명 대신 상태 파일·보고서에 남긴다

    @staticmethod
    def delete_command(rule: str) -> list[str]:
        return ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule}"]

    @staticmethod
    def show(argv: list[str]) -> str:
        return " ".join(f'"{a}"' if " " in a else a for a in argv)

    # ------------------------------------------------------------ 흐름
    def offer(self, sug: Suggestion, now: float) -> Optional[Block]:
        """차단 제안을 받는다. off 면 무시, auto 면 즉시 적용."""
        if self.mode == "off":
            return None
        ok_ips, skipped = [], []
        for ip in sug.ips:
            why = self.why_not(ip)
            (skipped.append(f"{ip}: {why}") if why else ok_ips.append(ip))
        if any(b.status in ("pending", "active") and b.proc_key == sug.proc_key
               and set(ok_ips) <= set(b.ips) for b in self.blocks):
            return None  # 이미 같은 제안이 대기 중이거나 적용 중
        bid = max((b.bid for b in self.blocks), default=0) + 1
        b = Block(bid=bid, rule=f"{RULE_PREFIX}{bid}", ips=ok_ips, proc_key=sug.proc_key,
                  proc_name=sug.proc_name, pid=sug.pid, start_time=sug.start_time,
                  risk=sug.risk, reasons=list(sug.reasons), created=now, skipped=skipped)
        b.note(now, "제안", f"위험도 {sug.risk:.0f}, 대상 {', '.join(ok_ips) or '없음'}")
        self.blocks.append(b)
        if not ok_ips:
            b.status = "denied"
            b.note(now, "보류", "차단 가능한 IP 가 없음 (모두 차단 금지 목록)")
        elif self.mode == "auto":
            self.approve(bid, now, by="auto")
        self._save()
        return b

    def get(self, bid: int) -> Optional[Block]:
        return next((b for b in self.blocks if b.bid == bid), None)

    def approve(self, bid: int, now: float, by: str = "user") -> Block:
        b = self.get(bid)
        if b is None or b.status != "pending":
            raise ValueError(f"대기 중인 차단 #{bid} 가 없습니다")
        b.approved_by = by
        if self.dry_run:
            b.status = "dry-run"
            b.note(now, "dry-run", " / ".join(self.show(c) for c in self.add_commands(b)))
            self._save()
            return b
        for argv in self.add_commands(b):
            rc, out = self.run(argv)
            if rc != 0:
                b.status, b.error = "failed", out[:300]
                b.note(now, "적용 실패", b.error)
                self.run(self.delete_command(b.rule))   # 반쯤 만들어진 규칙 정리
                self._emit(b, now, "block_failed", f"차단 실패 #{b.bid}: {b.error[:80]}")
                self._save()
                return b
        b.status, b.applied, b.expires = "active", now, now + self.ttl
        b.note(now, "적용", f"승인: {'사용자' if by == 'user' else '자동(실험)'} · {self.ttl / 60:.0f}분 뒤 자동 해제")
        self._emit(b, now, "blocked",
                   f"차단 적용 #{b.bid}: {', '.join(b.ips)} ({'사용자 승인' if by == 'user' else '자동'}, "
                   f"{self.ttl / 60:.0f}분 뒤 해제)")
        self._save()
        return b

    def deny(self, bid: int, now: float) -> Block:
        b = self.get(bid)
        if b is None or b.status != "pending":
            raise ValueError(f"대기 중인 차단 #{bid} 가 없습니다")
        b.status = "denied"
        b.note(now, "거절", "사용자가 차단을 거절함 (오탐 판단 기록)")
        self._save()
        return b

    def unblock(self, bid: int, now: float, reason: str = "사용자 해제") -> Block:
        b = self.get(bid)
        if b is None or b.status != "active":
            raise ValueError(f"적용 중인 차단 #{bid} 가 없습니다")
        rc, out = self.run(self.delete_command(b.rule))
        b.status = "expired" if reason == "TTL 만료" else "removed"
        b.removed = now
        b.note(now, "해제", reason + ("" if rc == 0 else f" (삭제 명령 오류: {out[:120]})"))
        self._emit(b, now, "unblocked", f"차단 해제 #{b.bid}: {reason}")
        self._save()
        return b

    def tick(self, now: float) -> list[Block]:
        expired = [b for b in self.blocks if b.status == "active" and b.expires <= now]
        for b in expired:
            self.unblock(b.bid, now, "TTL 만료")
        return expired

    def rollback_all(self, now: float) -> int:
        """이 도구가 만든 규칙을 모두 지운다 (상태 파일 + 이름 접두사 이중 확인)."""
        n = 0
        for b in self.blocks:
            if b.status == "active":
                self.unblock(b.bid, now, "전체 롤백")
                n += 1
        if sys.platform == "win32" and not self.dry_run:   # 상태 파일이 없어진 경우까지 정리
            self.run(["powershell", "-NoProfile", "-NonInteractive", "-Command",
                      f"Get-NetFirewallRule -DisplayName '{RULE_PREFIX}*' -ErrorAction SilentlyContinue"
                      " | Remove-NetFirewallRule"])
        return n

    def kill_process(self, bid: int, now: float, current_start: Optional[float]) -> str:
        """차단 대상 프로세스 종료. PID 가 재사용됐으면 거부한다."""
        b = self.get(bid)
        if b is None or not b.pid:
            return "해당 차단에 프로세스 정보가 없습니다"
        if current_start is None:
            return f"PID {b.pid} 는 이미 종료됐습니다"
        if b.start_time and abs(current_start - b.start_time) > 1.0:
            return f"PID {b.pid} 가 다른 프로세스에 재사용되어 종료하지 않았습니다"
        if self.dry_run:
            return f"[dry-run] taskkill /PID {b.pid} /F"
        rc, out = self.run(["taskkill", "/PID", str(b.pid), "/F"])
        b.note(now, "프로세스 종료" if rc == 0 else "종료 실패", out[:120])
        self._emit(b, now, "killed" if rc == 0 else "kill_failed",
                   f"{b.proc_name}(PID {b.pid}) 종료 {'완료' if rc == 0 else '실패'}")
        self._save()
        return out or ("종료됨" if rc == 0 else "실패")

    # ------------------------------------------------------------ 기록
    def _emit(self, b: Block, ts: float, code: str, text: str) -> None:
        if self.timeline is not None:
            self.timeline.add(Event(ts=ts, proc_key=b.proc_key, proc_name=b.proc_name, pid=b.pid,
                                    code=code, text=text, dest=",".join(b.ips),
                                    measure={"summary": f"방화벽 규칙 {b.rule} · 대상 {', '.join(b.ips)}"}))

    def _load(self) -> None:
        if not self.state_path or not os.path.exists(self.state_path):
            return
        try:
            with open(self.state_path, encoding="utf-8") as f:
                self.blocks = [Block(**raw) for raw in json.load(f).get("blocks", [])]
        except (OSError, ValueError, TypeError):
            self.blocks = []

    def recover(self, now: float) -> list[Block]:
        """이전 실행이 남긴 규칙 중 만료된 것을 정리 (비정상 종료 대비)."""
        return self.tick(now)

    def _save(self) -> None:
        if not self.state_path:
            return
        d = os.path.dirname(os.path.abspath(self.state_path))
        fd, tmp = tempfile.mkstemp(dir=d, suffix=".tmp")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump({"blocks": [asdict(b) for b in self.blocks]}, f, ensure_ascii=False, indent=1)
        os.replace(tmp, self.state_path)

    def describe(self, b: Block) -> str:
        s = {"pending": "승인 대기", "active": "적용 중", "denied": "거절/보류", "expired": "만료 해제",
             "removed": "해제됨", "failed": "실패", "dry-run": "dry-run"}[b.status]
        left = f" · {max(0, b.expires - time.time()) / 60:.0f}분 남음" if b.status == "active" else ""
        return f"#{b.bid} [{s}{left}] {b.proc_name}(PID {b.pid}) → {', '.join(b.ips) or '-'} (위험도 {b.risk:.0f})"
