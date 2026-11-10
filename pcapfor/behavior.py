"""통신 패턴 특징과 점수 가중치.

임계값·가중치를 한 곳에 모아 팀이 튜닝·실험하기 쉽게 했다.
점수는 '감염 판정'이 아니라 '의심의 근거 합'이다. 신호 하나는 약하고,
서로 독립인 신호가 겹칠수록 위험도가 올라간다.
"""
from __future__ import annotations

import statistics
from ipaddress import ip_address, ip_network

# 새 사이트 접속이 일상인 프로그램: 새 목적지·패턴 신호를 약하게 적용
BROWSERS = {"chrome.exe", "msedge.exe", "firefox.exe", "whale.exe", "brave.exe",
            "opera.exe", "iexplore.exe", "vivaldi.exe"}
# OS 구성요소 서명자: '새 프로세스' 가중치만 1 낮춘다. rundll32·powershell 처럼 MS 서명 도구도
# 악용되므로(LOLBin) 비커닝·업로드 등 다른 신호는 그대로 적용한다.
TRUSTED_SIGNERS = {"Microsoft Windows", "Microsoft Windows Publisher", "Microsoft Corporation"}
# 유효한 서명 + 이 위치(설치 프로그램이 관리자 권한으로만 쓸 수 있는 곳)도 같은 완화를 받는다.
# Temp·Downloads·AppData 처럼 사용자가 마음대로 쓰는 곳은 해당 없음.
INSTALLED_DIRS = ("\\program files\\", "\\program files (x86)\\", "\\windows\\")


def installed_location(path: str) -> bool:
    p = path.lower().replace("/", "\\")
    return any(d in p for d in INSTALLED_DIRS) and "\\temp\\" not in p
STD_PORTS = {53, 80, 123, 443, 853, 993, 995, 465, 587, 5222, 5223, 8080, 8443}

WEIGHTS = {
    "new_process":     2,   # 학습 기간에 없던 프로세스가 외부 접속
    "new_dest":        1,   # 프로세스가 평소 가지 않던 목적지
    "nonstd_port":     1,   # 비표준 포트
    "beacon":          2,   # 기계적으로 일정한 주기의 반복 연결
    "size_regular":    1,   # 매번 비슷한 크기의 전송 (비커닝과 함께일 때만)
    "period_change":   2,   # 평소 주기 대비 급격한 변화 (예: 10분 -> 30초)
    "long_conn":       1,   # 외부 연결을 오래 유지
    "upload_spike":    2,   # 평소 대비 외부 전송량 급증
    "unsigned":        1,   # 서명 없음 (단독으론 약한 신호)
    "suspicious_dir":  2,   # Temp / Downloads 등에서 실행
    "masquerade":      3,   # 시스템 프로세스 사칭
    "lookalike":       2,   # 시스템 프로세스와 한 글자 다른 이름
    "binary_changed":  3,   # 실행 파일이 바뀌었는데 서명이 사라지거나 서명자가 바뀜
}
# 신호 -> MITRE ATT&CK (보고서 표기용. 행동 근거와 '연관된' 기법이지 확정 매핑이 아니다)
MITRE = {
    "beacon": "T1071 Application Layer Protocol",
    "period_change": "T1071 Application Layer Protocol",
    "size_regular": "T1071 Application Layer Protocol",
    "nonstd_port": "T1571 Non-Standard Port",
    "upload_spike": "T1041 Exfiltration Over C2 Channel",
    "long_conn": "T1219 Remote Access Software",
    "masquerade": "T1036.005 Masquerading: Match Legitimate Name or Location",
    "lookalike": "T1036 Masquerading",
    "suspicious_dir": "T1204.002 User Execution: Malicious File",
    "binary_changed": "T1554 Compromise Host Software Binary",
}

RULE_POINTS ={"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

THRESH = {
    "beacon_min_gaps": 6,
    "beacon_max_cv": 0.15,
    "beacon_min_interval": 2.0,
    "size_max_cv": 0.10,
    "period_ratio": 5.0,          # 평소 주기 / 현재 주기 가 이 이상이면 주기 변화
    "period_min_gaps": 4,
    "long_conn_sec": 600.0,
    "upload_ratio": 5.0,          # 평소 최대 업로드 속도 대비 배수
    "upload_floor": 512 * 1024,   # 바이트/분: 이보다 적으면 급증으로 보지 않음
}

_INTERNAL = [ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
                                     "127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4",
                                     "255.255.255.255/32", "0.0.0.0/8")]


def is_external(ip: str) -> bool:
    try:
        a = ip_address(ip)
    except ValueError:
        return False
    return a.version == 4 and not any(a in n for n in _INTERNAL)


def interval_stats(times: list[float]) -> tuple[int, float, float]:
    """(간격 수, 평균 간격, 변동계수). 간격이 부족하면 (n, 0, 99)."""
    ts = sorted(times)
    gaps = [b - a for a, b in zip(ts, ts[1:]) if b - a > 0.5]
    if len(gaps) < 2:
        return len(gaps), 0.0, 99.0
    mean = statistics.fmean(gaps)
    return len(gaps), mean, (statistics.pstdev(gaps) / mean if mean else 99.0)


def cv(values: list[float]) -> float:
    if len(values) < 2:
        return 99.0
    mean = statistics.fmean(values)
    return statistics.pstdev(values) / mean if mean else 99.0
