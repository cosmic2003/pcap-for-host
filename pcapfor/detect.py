"""탐지 엔진: 세션/HTTP/DNS/ARP 데이터를 받아 Finding 목록을 만든다.

각 탐지기는 독립 함수이고, analyzer 가 모은 AnalysisData 하나를 입력으로 받는다.
임계값은 THRESHOLDS 로 한 곳에 모아 과제 중 튜닝하기 쉽게 했다.
"""
from __future__ import annotations

import base64
import math
import re
import statistics
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from ipaddress import ip_address, ip_network
from urllib.parse import unquote_plus

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

THRESHOLDS = {
    "portscan_min_ports": 15,      # 한 src가 건드린 서로 다른 포트 수
    "hostscan_min_hosts": 10,      # 한 src가 같은 포트로 건드린 호스트 수
    "brute_min_attempts": 8,       # 같은 서비스에 대한 로그인 실패/짧은 연결 수
    "dns_min_queries": 20,         # 터널링 판단 최소 질의 수
    "dns_label_len": 30,           # 의심 서브도메인 평균 길이
    "dns_entropy": 3.5,            # 서브도메인 샤논 엔트로피
    "dns_len_extreme": 60,         # 이 길이를 넘는 평균 서브도메인은 그 자체로 의심
    "dns_null_min": 20,            # NULL(qtype 10) 질의 수: iodine 계열 시그니처
    "beacon_min_events": 8,        # 비커닝 판단 최소 연결 수
    "beacon_max_cv": 0.15,         # 간격 변동계수(낮을수록 기계적)
    "beacon_min_interval": 2.0,    # 초
}


@dataclass
class Finding:
    severity: str          # critical | high | medium | low | info
    category: str          # recon | bruteforce | webattack | credential | c2 | spoofing | ioc
    title: str
    description: str
    evidence: list = field(default_factory=list)   # 사람이 읽을 증거 문자열들
    mitre: str = ""                                 # MITRE ATT&CK 기법 ID
    recommendation: str = ""
    session_ids: list = field(default_factory=list)
    ts: float = 0.0        # 탐지 근거가 처음 관찰된 시각 (epoch, 타임라인용)

    @property
    def rank(self) -> int:
        return SEVERITY_ORDER.get(self.severity, 0)


def _b64(raw: bytes) -> bytes:
    """패딩이 틀려도 죽지 않는 base64 디코드 (와이어의 값은 깨져 있을 수 있다)."""
    return base64.b64decode(raw + b"=" * (-len(raw) % 4))


def _strip_telnet(raw: bytes) -> bytes:
    """Telnet IAC 협상 시퀀스와 NUL 을 제거하고 백스페이스를 적용한 텍스트."""
    b = re.sub(rb"\xff\xfa.*?\xff\xf0", b"", raw, flags=re.S)   # 부협상 SB ... SE
    b = re.sub(rb"\xff[\xfb-\xfe].", b"", b, flags=re.S)        # WILL/WONT/DO/DONT <옵션>
    b = re.sub(rb"\xff[\xf0-\xfa]", b"", b)                     # 그 외 2바이트 명령
    b = b.replace(b"\xff\xff", b"\xff").replace(b"\x00", b"")
    out = bytearray()
    for ch in b:
        if ch in (0x08, 0x7F):          # 백스페이스: 직전 글자 지움
            if out and out[-1] not in (0x0A, 0x0D):
                out.pop()
        else:
            out.append(ch)
    return bytes(out)


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def run_all(data, ioc_path: str | None = None) -> list[Finding]:
    findings: list[Finding] = []
    for det in (
        detect_port_scan, detect_host_scan, detect_bruteforce,
        detect_cleartext_credentials, detect_web_attacks,
        detect_dns_tunneling, detect_beaconing, detect_arp_spoofing,
        detect_http_post_c2, detect_rat_screen_exfil,
    ):
        findings.extend(det(data))
    if ioc_path:
        findings.extend(detect_ioc(data, ioc_path))
    findings.sort(key=lambda f: -f.rank)
    return findings


# ---------------------------------------------------------------- 정찰

def detect_port_scan(data) -> list[Finding]:
    out = []
    # src -> dst -> {미완성 연결의 dst 포트}
    probes = defaultdict(lambda: defaultdict(set))
    opened = defaultdict(lambda: defaultdict(set))  # 스캔에 SYN/ACK 로 응답한 포트
    first_ts = defaultdict(lambda: defaultdict(lambda: float("inf")))
    for s in data.sessions:
        if s.proto != "tcp" or not s.syn_seen:
            continue
        if not s.synack_seen and s.bytes_s2c == 0:
            probes[s.client][s.server].add(s.sport)
            first_ts[s.client][s.server] = min(first_ts[s.client][s.server], s.first_ts)
        elif s.synack_seen and s.bytes_c2s == 0:
            opened[s.client][s.server].add(s.sport)
    for src, by_dst in probes.items():
        for dst, ports in by_dst.items():
            if len(ports) >= THRESHOLDS["portscan_min_ports"]:
                sample = sorted(ports)[:12]
                ev = [f"대상 포트 예시: {', '.join(map(str, sample))} ..."]
                found = sorted(opened[src][dst])
                if found:
                    ev.append(f"응답한 열린 포트(공격자가 발견한 서비스): "
                              f"{', '.join(map(str, found[:15]))}")
                out.append(Finding(
                    "high", "recon",
                    f"포트 스캔 의심: {src} -> {dst}",
                    f"{src} 가 {dst} 의 서로 다른 포트 {len(ports) + len(found)}개에 SYN을 보냈고, "
                    f"그중 {len(ports)}개는 응답이 없는 미완성 연결입니다.",
                    evidence=ev,
                    mitre="T1046 (Network Service Discovery)",
                    recommendation="해당 출발지 IP 차단 여부 검토, 스캔 이후 성공한 연결이 있는지 추적",
                    ts=first_ts[src][dst],
                ))
    return out


def detect_host_scan(data) -> list[Finding]:
    out = []
    sweep = defaultdict(lambda: defaultdict(set))  # src -> port -> {hosts}
    first_ts = defaultdict(lambda: defaultdict(lambda: float("inf")))
    for s in data.sessions:
        if s.proto == "tcp" and s.syn_seen and not s.synack_seen:
            sweep[s.client][s.sport].add(s.server)
            first_ts[s.client][s.sport] = min(first_ts[s.client][s.sport], s.first_ts)
    for src, by_port in sweep.items():
        for port, hosts in by_port.items():
            if len(hosts) >= THRESHOLDS["hostscan_min_hosts"]:
                out.append(Finding(
                    "medium", "recon",
                    f"호스트 스윕 의심: {src} (포트 {port})",
                    f"{src} 가 포트 {port} 로 호스트 {len(hosts)}대를 차례로 접촉했습니다. "
                    f"내부망 수평 이동 전 정찰 패턴입니다.",
                    evidence=[f"대상 호스트 예시: {', '.join(sorted(hosts)[:8])} ..."],
                    mitre="T1018 (Remote System Discovery)",
                    recommendation="출발지 호스트의 감염 여부 점검",
                    ts=first_ts[src][port],
                ))
    return out


# ---------------------------------------------------------------- 계정 공격

def detect_bruteforce(data) -> list[Finding]:
    out = []
    # FTP: 530 응답 수 세기
    fail_by_attacker = defaultdict(int)
    ftp_first = defaultdict(lambda: float("inf"))
    for sess, c2s, s2c in data.ftp_streams:
        fails = s2c.count(b"530")
        if fails:
            fail_by_attacker[(sess.client, sess.server)] += fails
            ftp_first[(sess.client, sess.server)] = min(
                ftp_first[(sess.client, sess.server)], sess.first_ts)
    for (src, dst), fails in fail_by_attacker.items():
        if fails >= THRESHOLDS["brute_min_attempts"]:
            out.append(Finding(
                "high", "bruteforce",
                f"FTP 브루트포스 의심: {src} -> {dst}",
                f"로그인 실패(530) 응답이 {fails}회 관찰되었습니다.",
                evidence=[f"실패 횟수: {fails}"],
                mitre="T1110 (Brute Force)",
                recommendation="해당 계정 잠금/비밀번호 변경, 출발지 차단",
                ts=ftp_first[(src, dst)],
            ))
    # HTTP: 같은 URI에 401/403 반복
    auth_fail = defaultdict(int)
    auth_first = defaultdict(lambda: float("inf"))
    for sess, tx in data.http_transactions:
        if tx.response and tx.response.status in (401, 403) and tx.request:
            key = (sess.client, sess.server, tx.request.uri)
            auth_fail[key] += 1
            auth_first[key] = min(auth_first[key], sess.first_ts)
    for (src, dst, uri), n in auth_fail.items():
        if n >= THRESHOLDS["brute_min_attempts"]:
            out.append(Finding(
                "high", "bruteforce",
                f"HTTP 인증 브루트포스 의심: {src} -> {dst}{uri}",
                f"동일 경로에 인증 실패 응답이 {n}회 반복되었습니다.",
                evidence=[f"경로: {uri}", f"실패 횟수: {n}"],
                mitre="T1110.001 (Password Guessing)",
                recommendation="계정 잠금 정책·레이트 리밋 적용 검토",
                ts=auth_first[(src, dst, uri)],
            ))
    # SSH/Telnet/RDP: 같은 서비스로 짧은 연결 다수
    quick = defaultdict(int)
    quick_first = defaultdict(lambda: float("inf"))
    for s in data.sessions:
        if s.proto == "tcp" and s.sport in (22, 23, 3389) and s.synack_seen:
            if s.duration < 10 and (s.fin_seen or s.rst_seen):
                quick[(s.client, s.server, s.sport)] += 1
                quick_first[(s.client, s.server, s.sport)] = min(
                    quick_first[(s.client, s.server, s.sport)], s.first_ts)
    for (src, dst, port), n in quick.items():
        if n >= THRESHOLDS["brute_min_attempts"]:
            svc = {22: "SSH", 23: "Telnet", 3389: "RDP"}[port]
            out.append(Finding(
                "medium", "bruteforce",
                f"{svc} 반복 접속 의심: {src} -> {dst}",
                f"{svc}({port}) 로 짧은 연결이 {n}회 반복되었습니다. "
                f"암호화 구간이라 내용 대신 연결 패턴으로 판단했습니다.",
                evidence=[f"짧은 연결 수: {n}"],
                mitre="T1110 (Brute Force)",
                recommendation="인증 로그와 대조하여 실패 로그인 확인",
                ts=quick_first[(src, dst, port)],
            ))
    return out


# ---------------------------------------------------------------- 자격증명 노출

def detect_cleartext_credentials(data) -> list[Finding]:
    out = []
    for sess, c2s, s2c in data.ftp_streams:
        user = re.search(rb"USER (\S+)", c2s)
        pw = re.search(rb"PASS (\S+)", c2s)
        # 로그인에 성공(230)한 세션만 보고한다. 실패 시도는 브루트포스 탐지가 맡는다.
        if user and pw and b"230" in s2c:
            out.append(Finding(
                "high", "credential",
                f"FTP 평문 자격증명 노출: {sess.key_str}",
                "FTP 로그인 정보가 암호화 없이 전송되었습니다.",
                evidence=[
                    f"USER: {user.group(1).decode('latin-1')}",
                    f"PASS: {'*' * len(pw.group(1))} (캡처에 평문 존재)",
                ],
                mitre="T1040 (Network Sniffing)",
                recommendation="FTPS/SFTP 전환, 노출된 비밀번호 즉시 변경",
                session_ids=[sess.sid], ts=sess.first_ts,
            ))
    # SMTP: AUTH LOGIN/PLAIN 평문(base64) 인증 + 메일 유출 징후
    # (Agent Tesla 류 정보 탈취 멀웨어의 전형적 유출 경로)
    for sess, c2s, s2c in data.smtp_streams:
        user = pw = None
        lines = c2s.split(b"\r\n")
        for i, line in enumerate(lines):
            up = line.strip().upper()
            if up.startswith(b"AUTH LOGIN"):
                parts = line.strip().split()
                try:
                    if len(parts) >= 3:          # AUTH LOGIN <user_b64>
                        user = _b64(parts[2]).decode("latin-1")
                        if i + 1 < len(lines):
                            pw = _b64(lines[i + 1].strip()).decode("latin-1")
                    elif i + 2 < len(lines):     # AUTH LOGIN \n user \n pass
                        user = _b64(lines[i + 1].strip()).decode("latin-1")
                        pw = _b64(lines[i + 2].strip()).decode("latin-1")
                except Exception:
                    user = user or "(base64 디코딩 실패)"
                break
            if up.startswith(b"AUTH PLAIN"):
                parts = line.strip().split()
                try:
                    if len(parts) >= 3:
                        fields = _b64(parts[2]).split(b"\x00")
                        if len(fields) >= 3:
                            user = fields[1].decode("latin-1")
                            pw = fields[2].decode("latin-1")
                except Exception:
                    user = "(base64 디코딩 실패)"
                break
        if user is None:
            continue
        evidence = [f"AUTH 사용자: {user}"]
        if pw:
            evidence.append(f"비밀번호: {'*' * min(len(pw), 12)} (캡처에 base64 평문 존재)")
        rcpt = re.search(rb"RCPT TO:<([^>\r\n]+)>", c2s, re.I)
        subj = re.search(rb"Subject: ([^\r\n]{1,60})", c2s, re.I)
        if rcpt:
            evidence.append(f"수신자: {rcpt.group(1).decode('latin-1')}")
        if subj:
            evidence.append(f"메일 제목: {subj.group(1).decode('latin-1', 'replace')}")
        out.append(Finding(
            "high", "credential",
            f"SMTP 평문 자격증명·메일 전송: {sess.key_str}",
            "SMTP 인증 정보가 암호화 없이 전송되었습니다(base64는 암호화가 아님). "
            "정보 탈취 멀웨어가 수집 데이터를 메일로 내보내는 경로로도 쓰입니다.",
            evidence=evidence,
            mitre="T1048.003 (Exfiltration Over Unencrypted Protocol), T1040",
            recommendation="해당 계정 비밀번호 즉시 변경, 수신자 주소 차단, 발신 호스트 격리·점검",
            session_ids=[sess.sid], ts=sess.first_ts,
        ))
    # Telnet: 협상 바이트(IAC)를 걷어내면 클라이언트가 친 계정·명령이 그대로 나온다
    for sess, c2s, s2c in getattr(data, "telnet_streams", []):
        srv = _strip_telnet(s2c).lower()
        if not (b"login:" in srv or b"username:" in srv) or b"password" not in srv:
            continue
        typed = _strip_telnet(c2s)
        lines = [ln.strip() for ln in re.split(rb"\r\n|\r|\n", typed) if ln.strip()]
        if not lines:
            continue
        user = lines[0].decode("latin-1", "replace")[:40]
        pw = lines[1] if len(lines) > 1 else b""
        cmds = [ln.decode("latin-1", "replace")[:40] for ln in lines[2:7]]
        failed = b"incorrect" in srv or b"failed" in srv
        ev = [f"사용자명: {user}"]
        if pw:
            ev.append(f"비밀번호: {'*' * min(len(pw), 12)} (캡처에 평문 존재)")
        ev.append("로그인 결과: " + ("실패 응답 관찰" if failed else "성공으로 보임 (실패 응답 없음)"))
        if cmds:
            ev.append("로그인 후 실행 명령: " + ", ".join(cmds))
        out.append(Finding(
            "high", "credential",
            f"Telnet 평문 자격증명 노출: {sess.key_str}",
            "Telnet 은 로그인 정보와 입력 명령을 암호화 없이 전송합니다. "
            "같은 구간을 캡처한 누구나 계정과 작업 내용을 그대로 볼 수 있습니다.",
            evidence=ev,
            mitre="T1040 (Network Sniffing), T1021 (Remote Services)",
            recommendation="Telnet 비활성화 후 SSH 로 전환, 노출된 계정 비밀번호 즉시 변경",
            session_ids=[sess.sid], ts=sess.first_ts,
        ))
    seen_form = set()
    for sess, tx in data.http_transactions:
        if not tx.request:
            continue
        auth = tx.request.headers.get("authorization", "")
        if auth.lower().startswith("basic "):
            try:
                decoded = base64.b64decode(auth[6:]).decode("latin-1")
                user = decoded.split(":", 1)[0]
            except Exception:
                user = "(디코딩 실패)"
            out.append(Finding(
                "high", "credential",
                f"HTTP Basic 인증 평문 노출: {sess.key_str}",
                "Authorization: Basic 헤더는 base64일 뿐 암호화가 아닙니다.",
                evidence=[f"URI: {tx.request.uri}", f"사용자명: {user}"],
                mitre="T1040 (Network Sniffing)",
                recommendation="HTTPS 적용, 해당 계정 비밀번호 변경",
                session_ids=[sess.sid], ts=sess.first_ts,
            ))
        if tx.request.method == "POST" and tx.request.body:
            body = unquote_plus(tx.request.body.decode("latin-1", "replace"))
            m = re.search(r"(?:^|&)(passw(?:or)?d|pwd|pass)=([^&\s]+)", body, re.I)
            if m:
                dedup = (sess.client, sess.server, tx.request.uri)
                if dedup in seen_form:
                    continue
                seen_form.add(dedup)
                ev = [f"필드명: {m.group(1)}"]
                um = re.search(r"(?:^|&)(user(?:name)?|login|id|email|uid)=([^&\s]+)", body, re.I)
                if um:
                    ev.insert(0, f"사용자명: {um.group(2)[:40]}")
                ev.append(f"비밀번호: {'*' * min(len(m.group(2)), 12)} (본문에 평문 존재)")
                out.append(Finding(
                    "medium", "credential",
                    f"HTTP 폼 비밀번호 평문 전송: {sess.key_str}",
                    f"POST {tx.request.uri} 본문에 비밀번호 필드가 평문으로 포함되어 있습니다.",
                    evidence=ev,
                    mitre="T1040 (Network Sniffing)",
                    recommendation="HTTPS 적용",
                    session_ids=[sess.sid], ts=sess.first_ts,
                ))
    return out


# ---------------------------------------------------------------- 웹 공격

WEB_ATTACK_RULES = [
    # (이름, 심각도, MITRE, 패턴)  -- URI와 본문 양쪽을 검사한다
    ("SQL 인젝션", "high", "T1190", re.compile(
        # 항진식은 '1'='1 뿐 아니라 '0'='0, 'a'='a 처럼 같은 값을 비교하는 모든 형태
        r"(union(\s|\+|/\*.*?\*/)+select|'\s*or\s+'?(?P<t>\w+)'?\s*=\s*'?(?P=t)"
        r"|sleep\(\d+\)|benchmark\(|information_schema)", re.I)),
    ("XSS(크로스사이트 스크립팅)", "medium", "T1189", re.compile(
        r"(<script[\s>]|javascript:|onerror\s*=|onload\s*=|document\.cookie)", re.I)),
    ("경로 조작/LFI", "high", "T1190", re.compile(
        r"(\.\./){2,}|/etc/passwd|\\windows\\system32|php://(filter|input)", re.I)),
    ("Log4Shell(JNDI 조회)", "critical", "T1190", re.compile(
        r"\$\{jndi:(ldap|rmi|dns)s?://", re.I)),
    ("Shellshock", "critical", "T1190", re.compile(
        r"\(\)\s*\{\s*:?\s*;\s*\}\s*;", re.I)),
    ("명령 주입", "high", "T1190", re.compile(
        r"(;|\||%3b|%7c)\s*(cat|whoami|wget|curl|nc|bash|powershell)(\s|%20|\+)", re.I)),
]


def detect_web_attacks(data) -> list[Finding]:
    out = []
    seen = set()
    for sess, tx in data.http_transactions:
        if not tx.request:
            continue
        haystacks = [unquote_plus(tx.request.uri)]
        if tx.request.body:
            haystacks.append(unquote_plus(tx.request.body.decode("latin-1", "replace")))
        # User-Agent 등 헤더로 들어오는 공격(Log4Shell, Shellshock)도 잡는다
        if tx.request.headers:
            haystacks.append(" ".join(tx.request.headers.values()))
        for name, sev, mitre, rx in WEB_ATTACK_RULES:
            for text in haystacks:
                m = rx.search(text)
                if m:
                    dedup = (name, sess.client, sess.server, tx.request.uri[:80])
                    if dedup in seen:
                        break
                    seen.add(dedup)
                    out.append(Finding(
                        sev, "webattack",
                        f"{name} 시도: {sess.client} -> {sess.server}",
                        f"{tx.request.method} {tx.request.uri[:120]} 에서 공격 패턴이 발견되었습니다.",
                        evidence=[f"일치 문자열: {m.group(0)[:100]}",
                                  f"응답 상태: {tx.response.status if tx.response else '(없음)'}"],
                        mitre=f"{mitre} (Exploit Public-Facing Application)",
                        recommendation="WAF 룰 점검, 해당 엔드포인트 입력 검증 확인, 응답 코드로 성공 여부 판단",
                        session_ids=[sess.sid], ts=sess.first_ts,
                    ))
                    break
    return out


# ---------------------------------------------------------------- C2 / 유출

def _registered_domain(name: str) -> str:
    parts = name.rstrip(".").split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else name


def detect_dns_tunneling(data) -> list[Finding]:
    out = []
    # 존(zone)은 2라벨과 3라벨 깊이를 모두 후보로 집계한다.
    # weberlab.de 처럼 정상 질의가 많은 도메인 아래에 터널 존(io2.weberlab.de)이
    # 숨어 있으면 2라벨 평균 통계가 희석되어 놓치기 때문.
    by_domain = defaultdict(list)  # 존 -> [(질의 호스트, 풀 쿼리네임)]
    txt_count = Counter()
    null_count = Counter()
    nx_by_host = defaultdict(set)  # 질의 호스트 -> {NXDOMAIN 난 등록 도메인}
    dom_first = defaultdict(lambda: float("inf"))
    nx_first = defaultdict(lambda: float("inf"))
    for src, msg, mts in data.dns_messages:
        for qname, qtype in msg.questions:
            if not qname or "." not in qname:
                continue
            # 역방향 조회(PTR) 이름은 니블 단위라 원래 길다 → 터널링 집계에서 제외
            if qname.rstrip(".").endswith((".in-addr.arpa", ".ip6.arpa")):
                continue
            parts = qname.rstrip(".").split(".")
            zones = []
            if len(parts) >= 3:
                zones.append(".".join(parts[-2:]))
            if len(parts) >= 4:
                zones.append(".".join(parts[-3:]))
            if not msg.is_response:
                for dom in zones:
                    by_domain[dom].append((src, qname))
                    dom_first[dom] = min(dom_first[dom], mts)
                    if qtype == "TXT":
                        txt_count[dom] += 1
                    elif qtype == "NULL":
                        null_count[dom] += 1
            elif msg.rcode == 3:
                dom = _registered_domain(qname)
                nx_by_host[src].add(dom)  # src = 질의를 보냈던 호스트 (analyzer가 보정)
                nx_first[src] = min(nx_first[src], mts)
    suspicious_zones = {}
    for dom, queries in by_domain.items():
        if len(queries) < THRESHOLDS["dns_min_queries"]:
            continue
        subs = []
        for _, q in queries:
            sub = q[: -(len(dom) + 1)] if q.rstrip(".").endswith("." + dom) else ""
            if sub:
                subs.append(sub)
        if not subs:
            continue
        uniq_ratio = len(set(subs)) / len(subs)
        avg_len = sum(len(s) for s in subs) / len(subs)
        avg_entropy = sum(shannon_entropy(s) for s in subs) / len(subs)
        # 세 가지 패턴 중 하나면 의심: ① 길이+엔트로피+고유율 복합(dnscat 류 패턴)
        # ② 평균 길이가 극단적(정상 서비스엔 없음) ③ NULL 타입 질의 다발(iodine 시그니처)
        rule_mix = (avg_len >= THRESHOLDS["dns_label_len"]
                    and avg_entropy >= THRESHOLDS["dns_entropy"]
                    and uniq_ratio > 0.8)
        rule_len = avg_len >= THRESHOLDS["dns_len_extreme"]
        rule_null = null_count[dom] >= THRESHOLDS["dns_null_min"]
        if rule_mix or rule_len or rule_null:
            suspicious_zones[dom] = (queries, subs, uniq_ratio, avg_len, avg_entropy)
    for dom, (queries, subs, uniq_ratio, avg_len, avg_entropy) in suspicious_zones.items():
        # 더 구체적인 하위 존이 함께 의심되면 상위 존 중복 보고는 생략
        if any(child != dom and child.endswith("." + dom) for child in suspicious_zones):
            continue
        srcs = sorted({s for s, _ in queries})
        out.append(Finding(
            "critical", "c2",
            f"DNS 터널링 의심: {dom}",
            f"{dom} 으로 질의 {len(queries)}건. 서브도메인 평균 길이 {avg_len:.0f}자, "
            f"평균 엔트로피 {avg_entropy:.2f}, 고유 비율 {uniq_ratio:.0%} — "
            f"데이터를 서브도메인에 인코딩해 내보내는 패턴입니다.",
            evidence=[f"질의 호스트: {', '.join(srcs[:5])}",
                      f"서브도메인 예시: {subs[0][:60]}...",
                      f"TXT 질의: {txt_count[dom]}건 · NULL 질의: {null_count[dom]}건 / 총 {len(queries)}건"],
            mitre="T1071.004 (DNS), T1048 (Exfiltration)",
            recommendation="해당 도메인 차단 및 질의 호스트 격리, DNS 로그로 유출량 추정",
            ts=dom_first[dom],
        ))
    for host, failed_doms in nx_by_host.items():
        if len(failed_doms) >= THRESHOLDS["dns_min_queries"]:
            avg_ent = sum(shannon_entropy(d.split(".")[0]) for d in failed_doms) / len(failed_doms)
            if avg_ent >= 3.0:  # 무작위 생성 도메인은 엔트로피가 높다
                sample = sorted(failed_doms)[:5]
                out.append(Finding(
                    "high", "c2",
                    f"DGA 의심 (NXDOMAIN 다발): {host}",
                    f"{host} 가 서로 다른 도메인 {len(failed_doms)}개를 질의했지만 모두 "
                    f"존재하지 않았습니다(NXDOMAIN). 도메인 생성 알고리즘(DGA)으로 "
                    f"C2 서버를 찾는 멀웨어 패턴입니다.",
                    evidence=[f"실패 도메인 예시: {', '.join(sample)}",
                              f"평균 엔트로피: {avg_ent:.2f}"],
                    mitre="T1568.002 (Domain Generation Algorithms)",
                    recommendation="질의 호스트의 프로세스/작업 스케줄러 점검",
                    ts=nx_first[host],
                ))
    return out


def detect_beaconing(data) -> list[Finding]:
    out = []
    conn_times = defaultdict(list)  # (client, server, port) -> [first_ts]
    for s in data.sessions:
        if s.proto == "tcp":
            conn_times[(s.client, s.server, s.sport)].append(s.first_ts)
    for (src, dst, port), times in conn_times.items():
        if len(times) < THRESHOLDS["beacon_min_events"]:
            continue
        times.sort()
        gaps = [b - a for a, b in zip(times, times[1:]) if b - a > 0]
        if len(gaps) < THRESHOLDS["beacon_min_events"] - 1:
            continue
        mean = statistics.fmean(gaps)
        if mean < THRESHOLDS["beacon_min_interval"]:
            continue
        cv = statistics.pstdev(gaps) / mean if mean else 99
        if cv <= THRESHOLDS["beacon_max_cv"]:
            out.append(Finding(
                "high", "c2",
                f"C2 비커닝 의심: {src} -> {dst}:{port}",
                f"평균 {mean:.1f}초 간격으로 {len(times)}회 연결 (간격 변동계수 {cv:.3f}). "
                f"사람의 통신은 이렇게 규칙적이지 않습니다.",
                evidence=[f"연결 횟수: {len(times)}", f"평균 간격: {mean:.2f}s", f"CV: {cv:.3f}"],
                mitre="T1071 (Application Layer Protocol), T1573 (Encrypted Channel)",
                recommendation=f"{dst} 평판 조회, 출발 호스트 메모리/자동실행 항목 점검",
                ts=times[0],
            ))
    return out


_HEX_POST = re.compile(rb"[A-Za-z]{1,3}=[0-9a-fA-F]{64,}")


def detect_http_post_c2(data) -> list[Finding]:
    """암호문을 16진수로 담은 단일 파라미터 POST 가 같은 경로로 반복되는 C2 패턴.

    정상 폼은 여러 필드를 사람이 읽을 수 있는 값으로 보낸다. 반면 랜섬웨어 계열
    C2 체크인은 암호화한 바이트를 hex 로 바꿔 `x=6b78…` 한 필드에 담아 같은 스크립트로
    반복 전송하는 경우가 많다 (CryptoWall 류).
    """
    out = []
    groups = defaultdict(list)  # (server, host, path) -> [(sess, tx)]
    for sess, tx in data.http_transactions:
        q = tx.request
        if not q or q.method != "POST" or not q.body:
            continue
        if _HEX_POST.fullmatch(q.body.strip()):
            groups[(sess.server, q.host, q.uri.split("?")[0])].append((sess, tx))
    for (server, host, path), items in groups.items():
        if len(items) < 2:
            continue
        clients = sorted({s.client for s, _ in items})
        first = items[0][1].request
        statuses = [str(t.response.status) if t.response else "-" for _, t in items]
        out.append(Finding(
            "high", "c2",
            f"HTTP POST C2 의심: {', '.join(clients)} -> {host or server}{path}",
            f"같은 스크립트로 암호화된 16진수 페이로드를 담은 POST 가 {len(items)}회 반복되었습니다. "
            f"감염 PC 가 C2 서버에 체크인하는 랜섬웨어 계열의 전형적인 패턴입니다.",
            evidence=[f"서버: {server} (Host: {host or '-'})",
                      f"요청 예시: POST {first.uri[:70]}",
                      f"본문 예시: {first.body[:44].decode('latin-1')}… ({len(first.body)}바이트)",
                      f"응답 코드: {', '.join(statuses)}"],
            mitre="T1071.001 (Web Protocols), T1132 (Data Encoding)",
            recommendation=f"{host or server} 차단, 요청을 보낸 호스트 격리 후 랜섬웨어 감염 여부 점검",
            session_ids=[s.sid for s, _ in items],
            ts=min(s.first_ts for s, _ in items),
        ))
    return out


_IMG_MAGIC = (b"\xff\xd8\xff", b"\x89PNG\r\n\x1a\n")
_STD_TCP_PORTS = {20, 21, 25, 80, 110, 143, 443, 587, 993, 995, 8000, 8080, 8443}


def _printable(b: bytes, n: int = 70) -> str:
    return "".join(chr(c) if 32 <= c < 127 else "." for c in b[:n])


def detect_rat_screen_exfil(data) -> list[Finding]:
    """비표준 포트로 이미지(화면 캡처)를 반복 업로드하는 원격 제어 악성코드(RAT) 패턴.

    RAT 는 사람이 조종하므로 접속 간격이 불규칙해 비커닝 규칙으로는 안 잡힌다.
    대신 '평문 커스텀 프로토콜 + 이미지 업로드 + 서버 응답은 몇 바이트' 라는
    행위 자체를 본다.
    """
    out = []
    uploads = defaultdict(list)  # (client, server, port) -> [(sess, header)]
    for s in data.sessions:
        if s.proto != "tcp" or s.sport in _STD_TCP_PORTS or s.bytes_c2s < 1024:
            continue
        head = s.stream(c2s=True)[:4096]
        positions = [p for p in (head.find(m) for m in _IMG_MAGIC) if p >= 0]
        if positions and min(positions) <= 512 and s.bytes_s2c < 200:
            uploads[(s.client, s.server, s.sport)].append((s, head[:min(positions)]))
    for (client, server, port), items in uploads.items():
        if len(items) < 3:
            continue
        total = sum(s.bytes_c2s for s, _ in items)
        ev = [f"이미지 업로드 세션 {len(items)}개, 총 {total:,}바이트 (서버 응답은 세션당 200바이트 미만)"]
        header = items[0][1].strip()
        if header:
            ev.append(f"업로드 헤더: {_printable(header)}")
        pair = [x for x in data.sessions
                if (x.client, x.server, x.sport) == (client, server, port)]
        ctrl = max(pair, key=lambda x: x.duration)
        if ctrl.duration > 10:
            ev.append(f"명령 채널: 세션 #{ctrl.sid} {ctrl.duration:.0f}초 지속")
            ev.append(f"  감염 PC → 서버: {_printable(ctrl.stream(c2s=True))}")
            ev.append(f"  서버 → 감염 PC: {_printable(ctrl.stream(c2s=False))}")
        out.append(Finding(
            "high", "c2",
            f"원격 화면 캡처 유출 의심(RAT): {client} -> {server}:{port}",
            f"비표준 포트 {port} 로 이미지 파일을 {len(items)}회 업로드하고 서버는 짧은 명령만 "
            f"보냈습니다. 원격 제어 악성코드가 화면을 찍어 공격자에게 보내는 행위로 보입니다.",
            evidence=ev,
            mitre="T1113 (Screen Capture), T1041 (Exfiltration Over C2 Channel), T1219",
            recommendation=f"{server}:{port} 통신 차단, {client} 즉시 격리 후 원격 제어 악성코드 점검",
            session_ids=[s.sid for s, _ in items],
            ts=min(s.first_ts for s, _ in items),
        ))
    return out


# ---------------------------------------------------------------- 스푸핑

def detect_arp_spoofing(data) -> list[Finding]:
    out = []
    claims = defaultdict(set)  # IP -> {MAC}
    reply_count = Counter()
    ip_first = defaultdict(lambda: float("inf"))
    for ats, pkt_arp in data.arp_records:
        if pkt_arp.op == 2:  # reply
            claims[pkt_arp.sender_ip].add(pkt_arp.sender_mac)
            reply_count[(pkt_arp.sender_ip, pkt_arp.sender_mac)] += 1
            ip_first[pkt_arp.sender_ip] = min(ip_first[pkt_arp.sender_ip], ats)
    for ip, macs in claims.items():
        if len(macs) > 1:
            detail = ", ".join(f"{m}({reply_count[(ip, m)]}회)" for m in sorted(macs))
            out.append(Finding(
                "critical", "spoofing",
                f"ARP 스푸핑 의심: {ip} 를 MAC {len(macs)}개가 주장",
                f"같은 IP에 대해 서로 다른 MAC 주소가 ARP 응답을 보냈습니다. "
                f"중간자(MITM) 공격의 전형적인 흔적입니다.",
                evidence=[f"{ip} <- {detail}"],
                mitre="T1557.002 (ARP Cache Poisoning)",
                recommendation="정적 ARP/DAI(Dynamic ARP Inspection) 적용, 해당 구간 트래픽 전수 조사",
                ts=ip_first[ip],
            ))
    # 반대 방향 규칙: MAC 하나가 IP 여러 개의 주인이라고 알린다.
    # 진짜 게이트웨이 MAC 이 캡처에 없으면 위 규칙은 비교 대상이 없어 놓친다.
    # ARP 요청의 sender 필드도 상대 캐시를 갱신하므로 함께 본다.
    mac_ips = defaultdict(set)
    mac_ops = Counter()
    mac_first = defaultdict(lambda: float("inf"))
    for ats, a in data.arp_records:
        if a.sender_ip == "0.0.0.0" or a.sender_mac in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"):
            continue  # ARP 프로브는 주장이 아니다
        mac_ips[a.sender_mac].add(a.sender_ip)
        mac_ops[(a.sender_mac, a.sender_ip, a.op)] += 1
        mac_first[a.sender_mac] = min(mac_first[a.sender_mac], ats)
    for mac, ips in mac_ips.items():
        if len(ips) < 2:
            continue
        detail = []
        for ip in sorted(ips):
            req, rep = mac_ops[(mac, ip, 1)], mac_ops[(mac, ip, 2)]
            detail.append(f"{ip} (요청 {req}회 · 응답 {rep}회)")
        out.append(Finding(
            "high", "spoofing",
            f"ARP 스푸핑 의심: MAC {mac} 가 IP {len(ips)}개를 주장",
            "한 장비(MAC)가 서로 다른 IP 여러 개의 주인이라고 ARP 로 알렸습니다. "
            "다른 호스트(특히 게이트웨이)의 IP를 사칭해 트래픽을 가로채는 캐시 포이즈닝 패턴입니다.",
            evidence=[f"{mac} 가 주장한 IP: " + ", ".join(detail)],
            mitre="T1557.002 (ARP Cache Poisoning)",
            recommendation="스위치 MAC 테이블·DHCP 기록으로 정상 소유자 확인, 정적 ARP/DAI 적용, "
                           "해당 MAC 장비 격리",
            ts=mac_first[mac],
        ))
    return out


# ---------------------------------------------------------------- IOC

def detect_ioc(data, path: str) -> list[Finding]:
    ips, nets, domains = set(), [], set()
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                try:
                    if "/" in line:
                        nets.append(ip_network(line, strict=False))
                    else:
                        ips.add(str(ip_address(line)))
                except ValueError:
                    domains.add(line.lower().rstrip("."))
    except OSError as e:
        return [Finding("info", "ioc", "IOC 파일을 읽지 못함", str(e))]

    out = []
    hit_ips = set()
    for s in data.sessions:
        for peer in (s.client, s.server):
            if peer in hit_ips:
                continue
            matched = peer in ips
            if not matched and nets:
                try:
                    addr = ip_address(peer)
                    matched = any(addr in n for n in nets)
                except ValueError:
                    pass
            if matched:
                hit_ips.add(peer)
                out.append(Finding(
                    "critical", "ioc",
                    f"IOC 일치 (IP): {peer}",
                    f"침해지표 목록의 IP가 트래픽에 등장했습니다. 예: {s.key_str}",
                    evidence=[f"세션 수 집계 필요: '{peer}' 로 필터링"],
                    mitre="-",
                    recommendation="해당 IP와 통신한 모든 호스트 격리·점검",
                    session_ids=[s.sid], ts=s.first_ts,
                ))
    hit_doms = set()
    for _, msg, mts in data.dns_messages:
        for qname, _ in msg.questions:
            q = qname.lower().rstrip(".")
            for d in domains:
                if (q == d or q.endswith("." + d)) and d not in hit_doms:
                    hit_doms.add(d)
                    out.append(Finding(
                        "critical", "ioc",
                        f"IOC 일치 (도메인): {qname}",
                        f"침해지표 도메인 '{d}' 에 대한 DNS 질의가 관찰되었습니다.",
                        mitre="-",
                        recommendation="질의 호스트 격리, DNS 싱크홀 적용",
                        ts=mts,
                    ))
    return out
