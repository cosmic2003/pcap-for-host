"""프로세스별 이벤트 타임라인과 사건(incident) 묶기.

이벤트는 두 종류다.
- 맥락 이벤트(points=0): 실행 관측, 평소 서버 연결 등. 흐름을 설명하려고 남긴다.
- 점수 이벤트(points>0): 이상 신호. 최근 risk_window 초 안의 점수 합이 위험도다.

같은 프로세스에서 gap 초 이상 끊기지 않고 이어진 점수 이벤트를 사건 하나로 묶고,
최고 위험도가 '중간' 이상인 것만 사건으로 보고한다.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field

# 4단계 확신도 (탐지·피해 장부·보고서가 같은 값을 쓴다)
CONFIRMED = "확인됨"
PARTIAL = "일부 확인됨"
ESTIMATED = "추정됨"
UNKNOWN = "확인 불가"


def level_of(risk: float) -> str:
    if risk >= 6:
        return "높음"
    if risk >= 3:
        return "중간"
    if risk > 0:
        return "낮음"
    return "정보"


def _order(e) -> tuple:
    """같은 시각이면 맥락 이벤트(실행 관측 등)를 먼저 둔다."""
    return (e.ts, e.points > 0)


@dataclass
class Event:
    ts: float
    proc_key: str
    proc_name: str
    pid: int
    code: str
    text: str
    points: int = 0
    certainty: str = CONFIRMED
    dest: str = ""
    evidence: list = field(default_factory=list)
    risk: float = 0.0        # 이 이벤트 시점의 누적 위험도
    level: str = "정보"
    evidence_ids: list = field(default_factory=list)   # 근거 증거 ID (E-/H-/B-/R-)
    measure: dict = field(default_factory=dict)        # 판단에 쓴 실제 측정값 ("summary" + 원값)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Suggestion:
    """위험도 '높음' 도달 시 만들어지는 차단 제안 (차단 모듈이 소비한다)."""
    ts: float
    proc_key: str
    proc_name: str
    pid: int
    start_time: float          # PID 재사용 확인용
    risk: float
    ips: list                  # 차단 후보 원격 IP
    dests: list                # 표시용 목적지 이름
    reasons: list              # 근거가 된 점수 이벤트 문장


@dataclass
class Incident:
    iid: int
    proc_key: str
    proc_name: str
    start: float
    end: float
    peak_risk: float
    level: str
    events: list

    @property
    def first_anomaly(self) -> float:
        return min((e.ts for e in self.events if e.points > 0), default=self.start)


class Timeline:
    def __init__(self, risk_window: float = 1800.0):
        self.risk_window = risk_window
        self.events: list[Event] = []

    def add(self, ev: Event) -> Event:
        self.events.append(ev)
        self._recompute(ev.proc_key)
        return ev

    def _recompute(self, key: str) -> None:
        evs = sorted((e for e in self.events if e.proc_key == key), key=_order)
        for i, e in enumerate(evs):
            e.risk = sum(x.points for x in evs[: i + 1] if x.ts >= e.ts - self.risk_window)
            e.level = level_of(e.risk)

    def risk(self, key: str, now: float) -> float:
        return sum(e.points for e in self.events
                   if e.proc_key == key and now - self.risk_window <= e.ts <= now)

    def for_process(self, key: str) -> list[Event]:
        return sorted((e for e in self.events if e.proc_key == key), key=_order)

    def incidents(self, gap: float = 900.0, min_risk: float = 3.0) -> list[Incident]:
        out: list[Incident] = []
        for key in dict.fromkeys(e.proc_key for e in self.events):
            evs = self.for_process(key)
            scored = [e for e in evs if e.points > 0]
            groups: list[list[Event]] = []
            for e in scored:
                if groups and e.ts - groups[-1][-1].ts <= gap:
                    groups[-1].append(e)
                else:
                    groups.append([e])
            for g in groups:
                peak = max(e.risk for e in g)
                if peak < min_risk:
                    continue
                start, end = g[0].ts, g[-1].ts
                # 사건 직전 맥락(실행, 평소 서버 연결)과 사건 중 제안 이벤트를 함께 싣는다
                ctx = [e for e in evs if e.points == 0 and start - gap <= e.ts <= end + gap]
                members = sorted(g + ctx, key=_order)
                out.append(Incident(len(out) + 1, key, g[0].proc_name,
                                    members[0].ts, members[-1].ts, peak, level_of(peak), members))
        out.sort(key=lambda i: (-i.peak_risk, i.start))
        for n, inc in enumerate(out, 1):
            inc.iid = n
        return out
