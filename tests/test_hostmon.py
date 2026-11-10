"""호스트 감시 시뮬레이션 테스트 (윈도우 없이 어디서나 실행 가능).

가짜 연결 테이블(FakeSource)이 윈도우 iphlpapi 역할을 하고, 직접 만든 raw IP 패킷을
LiveEngine 에 흘려 넣는다. 실제 악성코드는 쓰지 않는다.

시나리오
  [학습 1시간]  weather.exe 가 10분마다 날씨 서버 접속 / chrome, KakaoTalk 일반 사용
  [감시 15분]   weather.exe 주기가 30초로 급변
                Temp 폴더의 서명 없는 update.exe 가 4444 포트로 30초마다 비커닝 후 대량 업로드
                chrome 새 사이트 방문(정상), KakaoTalk 새 CDN 서버(정상), 귀속 실패 연결 1개

실행: python -m pytest tests -q   또는   python tests/test_hostmon.py
"""
import os
import random
import socket
import struct
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pcapfor.hostid import FileIdentity, SigInfo  # noqa: E402
from pcapfor.hostmon import HostMonitor  # noqa: E402
from pcapfor.live import LiveEngine  # noqa: E402
from pcapfor.pcapio import LINKTYPE_RAW_IP, RawPacket  # noqa: E402
from pcapfor.procmap import ConnSource, ProcInfo, ProcessResolver  # noqa: E402
from pcapfor.profiles import ProfileStore  # noqa: E402
from pcapfor.tlsparse import client_hello_sni  # noqa: E402

LOCAL = "192.168.0.10"
T0 = 1_700_000_000.0

PROCS = {
    2000: ProcInfo(2000, "weather.exe", r"C:\Program Files\Weather\weather.exe", T0 - 100, 900, "explorer.exe"),
    3000: ProcInfo(3000, "chrome.exe", r"C:\Program Files\Google\Chrome\Application\chrome.exe", T0 - 50),
    3100: ProcInfo(3100, "KakaoTalk.exe", r"C:\Program Files (x86)\Kakao\KakaoTalk\KakaoTalk.exe", T0 - 40),
    4312: ProcInfo(4312, "update.exe", r"C:\Users\me\AppData\Local\Temp\update.exe", T0 + 7200 + 290, 3000, "chrome.exe"),
}
SIGS = {
    "weather.exe": SigInfo("Valid", "Weather Inc"),
    "chrome.exe": SigInfo("Valid", "Google LLC"),
    "kakaotalk.exe": SigInfo("Valid", "Kakao Corp."),
    "update.exe": SigInfo("NotSigned", ""),
}


class FakeSource(ConnSource):
    def __init__(self):
        self.conns = {}

    def connections(self):
        return dict(self.conns)

    def process(self, pid):
        return PROCS.get(pid)


class FakeIdentity(FileIdentity):
    def sha256(self, path):
        return "ab" * 32 if path else ""

    def signature(self, path, sha):
        return SIGS.get(path.rsplit("\\", 1)[-1].lower(), SigInfo("Unknown", ""))


# ------------------------------------------------------------- 패킷 생성
def ip_tcp(src, dst, sport, dport, seq, ack, flags, payload=b""):
    tcp = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 5 << 4, flags, 65535, 0, 0) + payload
    total = 20 + len(tcp)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 0, 0, 64, 6, 0,
                     socket.inet_aton(src), socket.inet_aton(dst))
    return ip + tcp


def client_hello(sni):
    name = sni.encode()
    sn = struct.pack("!HBH", len(name) + 3, 0, len(name)) + name
    ext = struct.pack("!HH", 0, len(sn)) + sn
    body = b"\x03\x03" + os.urandom(32) + b"\x00" + b"\x00\x02\x13\x01" + b"\x01\x00"
    body += struct.pack("!H", len(ext)) + ext
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs


class Sim:
    def __init__(self, engine, source):
        self.engine, self.source = engine, source
        self.pkts = []          # (ts, bytes)
        self.ingested = []      # 엔진에 넣은 순서 그대로 (= 증거 pcap 의 frame 순서)
        self.port = 50000
        self.n = 0

    def conn(self, ts, pid, rip, rport, sni=None, up=300, down=200, chunks=1, hold=1.0):
        lport = self.port
        self.port += 1
        if pid is not None:
            self.source.conns[("tcp", LOCAL, lport, rip, rport)] = pid
        first = client_hello(sni) if sni else os.urandom(up)
        cs, ss = 1000, 5000
        seq = [
            (ts, ip_tcp(LOCAL, rip, lport, rport, cs, 0, 0x02)),
            (ts + 0.02, ip_tcp(rip, LOCAL, rport, lport, ss, cs + 1, 0x12)),
        ]
        off = cs + 1
        payloads = [first] + [os.urandom(60000) for _ in range(chunks - 1)]
        for i, p in enumerate(payloads):
            seq.append((ts + 0.05 + i * 0.01, ip_tcp(LOCAL, rip, lport, rport, off, ss + 1, 0x18, p)))
            off += len(p)
        seq.append((ts + 0.3, ip_tcp(rip, LOCAL, rport, lport, ss + 1, off, 0x18, os.urandom(down))))
        seq.append((ts + hold, ip_tcp(LOCAL, rip, lport, rport, off, ss + 1 + down, 0x11)))
        self.pkts.extend(seq)

    def run(self, until, sweep=10.0):
        self.pkts.sort(key=lambda x: x[0])
        events = []
        next_sweep = self.pkts[0][0] + sweep if self.pkts else until
        for ts, data in self.pkts:
            while ts >= next_sweep:
                self.engine.sweep(next_sweep)
                events += self.engine.new_events
                next_sweep += sweep
            self.n += 1
            self.ingested.append((ts, data))
            self.engine.ingest(RawPacket(ts, data, len(data), LINKTYPE_RAW_IP, self.n))
        while next_sweep <= until:
            self.engine.sweep(next_sweep)
            events += self.engine.new_events
            next_sweep += sweep
        self.pkts = []
        return events


def make(store, learning, source):
    resolver = ProcessResolver(source)
    resolver.poll(now=T0)
    hm = HostMonitor(resolver, store, identity=FakeIdentity(), local_ips={LOCAL},
                     learning=learning, started_at=T0)
    return LiveEngine(hostmon=hm), resolver


def scenario(tmpdir):
    random.seed(1)
    prof_path = os.path.join(tmpdir, "profiles.json")

    # ---------------- 학습 1시간
    src = FakeSource()
    store = ProfileStore(prof_path)
    eng, res = make(store, True, src)
    sim = Sim(eng, src)
    for i in range(7):
        sim.conn(T0 + i * 600 + random.uniform(-3, 3), 2000, "198.51.100.20", 443, "api.weather.example")
    for i in range(20):
        sim.conn(T0 + random.uniform(0, 3500), 3000, "203.0.113.80", 443, "www.youtube.com", down=5000)
    for i in range(5):
        sim.conn(T0 + random.uniform(0, 3500), 3100, "203.0.113.90", 443, "talk.kakao.com")
    res.poll(now=T0)
    learn_events = sim.run(T0 + 3600)
    store.save()

    # ---------------- 감시 15분 (2시간 뒤)
    T1 = T0 + 7200
    src2 = FakeSource()
    store2 = ProfileStore(prof_path)
    eng2, res2 = make(store2, False, src2)
    sim2 = Sim(eng2, src2)
    for i in range(14):
        sim2.conn(T1 + 60 + i * 30 + random.uniform(-0.5, 0.5), 2000, "198.51.100.20", 443,
                  "api.weather.example")
    for i in range(13):  # update.exe: 30초 비커닝 (매번 같은 크기)
        sim2.conn(T1 + 300 + i * 30 + random.uniform(-0.8, 0.8), 4312, "203.0.113.5", 4444, up=256)
    sim2.conn(T1 + 700, 4312, "203.0.113.5", 4444, up=1000, chunks=60, hold=20)   # 약 3.5MB 업로드
    sim2.conn(T1 + 120, 3000, "203.0.113.81", 443, "news.example")
    sim2.conn(T1 + 130, 3100, "203.0.113.91", 443, "cdn.kakao.com")
    sim2.conn(T1 + 140, None, "203.0.113.200", 443, "unknown.example")             # 귀속 실패
    res2.poll(now=T1)
    events = sim2.run(T1 + 900)
    return store, learn_events, store2, eng2, events


# ------------------------------------------------------------- 테스트
def test_sni_parse():
    assert client_hello_sni(client_hello("a.example.com")) == ("a.example.com", False)


def run_scenario():
    with tempfile.TemporaryDirectory() as d:
        store, learn_events, store2, eng2, events = scenario(d)
        # 학습 중엔 점수 이벤트가 없어야 한다
        assert not [e for e in learn_events if e.points > 0]
        w = store.profiles[PROCS[2000].key]
        iv = w.dests["api.weather.example"].interval()
        assert iv and 580 < iv < 620, iv

        hm = eng2.hostmon
        by = {}
        for e in hm.timeline.events:
            by.setdefault(e.proc_name, []).append(e)

        codes = lambda n: {e.code for e in by.get(n, []) if e.points > 0}  # noqa: E731
        assert {"period_change", "beacon"} <= codes("weather.exe"), codes("weather.exe")
        u = codes("update.exe")
        for c in ("new_process", "suspicious_dir", "unsigned", "nonstd_port", "beacon",
                  "size_regular", "upload_spike"):
            assert c in u, (c, u)
        assert any(e.code == "block_suggest" for e in by["update.exe"])
        assert not codes("chrome.exe"), codes("chrome.exe")       # 브라우저 새 사이트는 정상
        assert not codes("KakaoTalk.exe")
        assert any(e.code == "known_domain" for e in by["KakaoTalk.exe"])
        assert "<미귀속>" in by

        incs = hm.timeline.incidents()
        top = incs[0]
        assert top.proc_name == "update.exe" and top.level == "높음"
        return hm, incs


def test_scenario():
    run_scenario()


def test_pid_reuse_and_linger():
    src = FakeSource()
    r = ProcessResolver(src, linger_sec=60)
    key = ("tcp", LOCAL, 51000, "203.0.113.7", 443)
    src.conns[key] = 2000
    r.poll(now=T0)
    assert r.resolve("tcp", LOCAL, 51000, "203.0.113.7", 443).name == "weather.exe"
    del src.conns[key]                       # 연결 종료 후에도 linger 동안은 귀속 유지
    r.poll(now=T0 + 30)
    assert r.resolve("tcp", LOCAL, 51000, "203.0.113.7", 443) is not None
    r.poll(now=T0 + 120)                     # linger 지나면 미귀속
    assert r.resolve("tcp", LOCAL, 51000, "203.0.113.7", 443) is None
    # 같은 PID 를 다른 프로그램이 재사용 (시작 시각이 다름)
    PROCS[2000], old = ProcInfo(2000, "evil.exe", r"C:\Temp\evil.exe", T0 + 200), PROCS[2000]
    try:
        src.conns[("tcp", LOCAL, 51001, "203.0.113.8", 443)] = 2000
        r.poll(now=T0 + 130)
        assert r.resolve("tcp", LOCAL, 51001, "203.0.113.8", 443).name == "evil.exe"
        assert r.stats["pid_reuse"] == 1
    finally:
        PROCS[2000] = old


def test_v6_mapping_and_udp_wildcard():
    import socket as so
    from pcapfor.procmap import _v4
    assert _v4(b"\x00" * 10 + b"\xff\xff" + so.inet_aton("1.2.3.4")) == "1.2.3.4"
    assert _v4(b"\x00" * 16) == "0.0.0.0"
    assert _v4(so.inet_pton(so.AF_INET6, "2001:db8::1")) is None
    src = FakeSource()
    src.conns[("udp", "192.168.0.99", 61000)] = 3000          # 다른 로컬 주소에 묶인 QUIC 소켓
    r = ProcessResolver(src)
    r.poll(now=T0)
    assert r.resolve("udp", LOCAL, 61000, "203.0.113.80", 443).name == "chrome.exe"


def test_rerun_demo_still_flags_new_process():
    """감시 중 기록된 프로세스는 '평소'가 아니므로 두 번째 시연에서도 new_process 가 떠야 한다."""
    import tempfile as tf
    with tf.TemporaryDirectory() as d:
        scenario(d)                                       # 학습 + 1차 감시 (프로파일 저장 안 함)
        path = os.path.join(d, "profiles.json")
        for round_ in range(2):
            store = ProfileStore(path)
            src = FakeSource()
            eng, res = make(store, False, src)
            sim = Sim(eng, src)
            t = T0 + 20000 + round_ * 5000
            for i in range(3):
                sim.conn(t + i * 30, 4312, "203.0.113.5", 4444, up=256)
            res.poll(now=t)
            sim.run(t + 120)
            store.save()
            codes = {e.code for e in eng.hostmon.timeline.events if e.proc_name == "update.exe"}
            assert "new_process" in codes, (round_, codes)


if __name__ == "__main__":
    test_sni_parse()
    test_pid_reuse_and_linger()
    hm, incs = run_scenario()
    for inc in incs:
        print(f"\n=== 사건 #{inc.iid} [{inc.level}] {inc.proc_name} (최고 {inc.peak_risk:.0f}점)")
        for e in inc.events:
            t = e.ts - T0 - 7200
            print(f"  +{t:6.0f}s  {'+' + str(e.points) if e.points else '  '}  "
                  f"위험도 {e.risk:>2.0f} {e.level:<2}  [{e.certainty}] {e.text}")
    print("\nsummary:", hm.summary())
    print("OK")
