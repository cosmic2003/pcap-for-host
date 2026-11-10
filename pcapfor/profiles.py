"""프로세스 프로파일: 프로세스마다 '평소 모습'을 기록하고 JSON 으로 저장한다.

프로파일 하나 = 실행 파일 하나(경로 기준). 기록하는 것:
  코드 서명·서명자 / SHA-256 / 경로 / 최초·최근 관측 / 실행 파일 변경 이력 /
  평소 목적지(목적지별 포트·연결 시각·업로드량) / 평소 업로드 속도 / 최근 이상 기록

학습 모드(learning=True)에서 본 것만 '평소'로 인정한다. 감시 모드에서 새로 본 목적지도
기록은 하지만 learned=False 로 남겨, 공격 트래픽이 슬그머니 정상으로 굳지 않게 한다.

전제(리포트에 명시할 것): 학습 구간의 PC 가 깨끗했다고 가정한다. 학습 중 이미 감염돼
있었다면 그 통신은 정상으로 학습된다.
"""
from __future__ import annotations

import json
import os
import statistics
import tempfile
from dataclasses import asdict, dataclass, field
from typing import Optional

PROFILE_VERSION = 1
MAX_TIMES = 64            # 목적지별로 보관하는 최근 연결 시각 수
MAX_ANOMALIES = 50
FORGET_SEC = 30 * 86400   # 30일 안 보인 목적지는 평소 목록에서 뺀다


@dataclass
class DestBaseline:
    first_seen: float
    last_seen: float
    count: int = 0
    ports: list = field(default_factory=list)
    times: list = field(default_factory=list)   # 최근 연결 시작 시각
    bytes_out: int = 0
    learned: bool = True                         # 학습 모드에서 본 목적지인가

    def interval(self) -> Optional[float]:
        """학습된 평소 연결 주기(간격 중앙값). 간격 4개 미만이면 None."""
        ts = sorted(self.times)
        gaps = [b - a for a, b in zip(ts, ts[1:]) if b - a > 0.5]
        return statistics.median(gaps) if len(gaps) >= 4 else None


@dataclass
class ProcessProfile:
    key: str
    name: str
    path: str
    first_seen: float
    last_seen: float
    learned: bool = True                 # 학습 모드에서 처음 본 프로세스인가
    sha256: str = ""
    sig_status: str = ""
    signer: str = ""
    file_history: list = field(default_factory=list)   # [{ts, sha256, sig_status, signer}]
    dests: dict = field(default_factory=dict)          # 목적지 -> DestBaseline
    conn_count: int = 0
    bytes_out: int = 0
    out_rate_peak: float = 0.0           # 학습 중 관측한 최대 업로드 속도(바이트/분)
    anomalies: list = field(default_factory=list)      # [{ts, code, text}]

    def record_anomaly(self, ts: float, code: str, text: str) -> None:
        self.anomalies.append({"ts": ts, "code": code, "text": text})
        del self.anomalies[:-MAX_ANOMALIES]


class ProfileStore:
    def __init__(self, path: Optional[str]):
        self.path = path
        self.profiles: dict[str, ProcessProfile] = {}
        self.learning_sec = 0.0          # 누적 학습 시간 (베이스라인이 얼마나 믿을 만한지)
        if path and os.path.exists(path):
            self._load()

    @property
    def has_baseline(self) -> bool:
        return any(p.learned for p in self.profiles.values())

    def _load(self) -> None:
        with open(self.path, encoding="utf-8") as f:
            doc = json.load(f)
        self.learning_sec = doc.get("learning_sec", 0.0)
        for key, raw in doc.get("profiles", {}).items():
            dests = {d: DestBaseline(**v) for d, v in raw.pop("dests", {}).items()}
            self.profiles[key] = ProcessProfile(**raw, dests=dests)

    def save(self) -> None:
        if not self.path:
            return
        doc = {"version": PROFILE_VERSION, "learning_sec": self.learning_sec,
               "profiles": {k: asdict(p) for k, p in self.profiles.items()}}
        d = os.path.dirname(os.path.abspath(self.path))
        fd, tmp = tempfile.mkstemp(dir=d, suffix=".tmp")
        with os.fdopen(fd, "w", encoding="utf-8") as f:   # 원자적 저장 (중간에 죽어도 안 깨짐)
            json.dump(doc, f, ensure_ascii=False, indent=1)
        os.replace(tmp, self.path)

    def get(self, key: str, name: str, path: str, now: float,
            learning: bool) -> tuple[ProcessProfile, bool]:
        """(프로파일, 이번에 처음 본 프로세스인가)."""
        p = self.profiles.get(key)
        if p is not None:
            p.last_seen = max(p.last_seen, now)
            return p, False
        p = ProcessProfile(key=key, name=name, path=path, first_seen=now,
                           last_seen=now, learned=learning)
        self.profiles[key] = p
        return p, True

    def forget_stale(self, now: float) -> None:
        for p in self.profiles.values():
            for d in [d for d, b in p.dests.items() if now - b.last_seen > FORGET_SEC]:
                del p.dests[d]
