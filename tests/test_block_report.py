"""차단 모듈 + 피해 장부 + 사고 보고서 시뮬레이션 테스트.

시나리오 (test_hostmon 의 학습 프로파일을 재사용)
  T1+300  update.exe 30초 비커닝 시작 → T1+310 차단 제안 (ask 모드, 사용자는 자리 비움)
  T1+700  약 3.5MB 업로드
  T1+725  사용자가 'approve 1' → netsh 규칙 적용 (가짜 실행기)
  T1+730~ update.exe 가 계속 접속 시도하지만 SYN 만 나가고 응답 없음
  보고서: 차단 전 전송량, 차단 후 시도 횟수·전송 0바이트, 확인됨/추정/확인 불가

실행: python -m pytest tests -q   또는   python tests/test_block_report.py  (보고서 HTML 저장)
"""
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import test_hostmon as H  # noqa: E402
from pcapfor.block import RULE_PREFIX, Blocker  # noqa: E402
from pcapfor.incident_report import render_html, report_from_json  # noqa: E402
from pcapfor.layers import decode  # noqa: E402
from pcapfor.ledger import build_doc  # noqa: E402
from pcapfor.pcapio import LINKTYPE_RAW_IP, read_packets, write_pcap  # noqa: E402
from pcapfor.profiles import ProfileStore  # noqa: E402
from pcapfor.timeline import Suggestion  # noqa: E402


class FakeExec:
    def __init__(self, fail_on=None):
        self.calls = []
        self.fail_on = fail_on

    def __call__(self, argv):
        self.calls.append(argv)
        if self.fail_on and self.fail_on in " ".join(argv):
            return 1, "액세스가 거부되었습니다."
        return 0, "확인됨."


def blocked_attempt(sim, ts, pid, rip, rport):
    """방화벽에 막혀 SYN 재전송만 보이는 연결 시도."""
    lport = sim.port
    sim.port += 1
    sim.source.conns[("tcp", H.LOCAL, lport, rip, rport)] = pid
    for dt in (0, 1, 3):
        sim.pkts.append((ts + dt, H.ip_tcp(H.LOCAL, rip, lport, rport, 1000, 0, 0x02)))


def scenario(tmpdir):
    store, *_ = H.scenario(tmpdir)          # 학습 프로파일 생성 (감시 결과는 버림)
    prof_path = os.path.join(tmpdir, "profiles.json")
    T1 = H.T0 + 7200
    src = H.FakeSource()
    eng, res = H.make(ProfileStore(prof_path), False, src)
    ex = FakeExec()
    blocker = Blocker("ask", ttl=1800, local_ips={H.LOCAL}, executor=ex,
                      state_path=os.path.join(tmpdir, "blocks.json"), timeline=eng.hostmon.timeline)
    sim = H.Sim(eng, src)
    for i in range(13):
        sim.conn(T1 + 300 + i * 30, 4312, "203.0.113.5", 4444, up=256)
    sim.conn(T1 + 700, 4312, "203.0.113.5", 4444, up=1000, chunks=60, hold=20)
    sim.conn(T1 + 120, 3000, "203.0.113.81", 443, "news.example")
    res.poll(now=T1)
    sim.run(T1 + 720)

    sugs = eng.hostmon.take_suggestions()
    offered = [blocker.offer(s, s.ts) for s in sugs]
    b = blocker.approve(offered[0].bid, T1 + 725)

    for i in range(6):
        blocked_attempt(sim, T1 + 730 + i * 30, 4312, "203.0.113.5", 4444)
    res.poll(now=T1 + 730)
    sim.run(T1 + 920)
    pcap_path = os.path.join(tmpdir, "evidence.pcap")
    write_pcap(pcap_path, sim.ingested, LINKTYPE_RAW_IP)      # --save 와 같은 순서로 기록
    ev_pcap = {"path": pcap_path, "sha256": "test", "packets": len(sim.ingested)}
    doc = build_doc(eng, blocker, now=T1 + 920, host_ip=H.LOCAL, evidence_pcap=ev_pcap)
    doc["_pcap"] = pcap_path
    return eng, blocker, ex, b, doc


def test_block_flow_and_report():
    with tempfile.TemporaryDirectory() as d:
        eng, blocker, ex, b, doc = scenario(d)
        # 차단 명령: out / in 두 규칙, 대상 IP 만
        assert b.status == "active" and b.ips == ["203.0.113.5"]
        adds = [c for c in ex.calls if "add" in c]
        assert len(adds) == 2 and all(f"name={RULE_PREFIX}1" in c for c in adds)
        assert {c[6] for c in adds} == {"dir=out", "dir=in"}
        assert all("remoteip=203.0.113.5" in c for c in adds)

        inc = next(i for i in doc["incidents"] if i["process"]["name"] == "update.exe")
        t = inc["totals"]
        assert t["flagged_out"] > 3_000_000                      # 차단 전 업로드 포함
        assert t["after_block_attempts"] == 6 and t["after_block_out"] == 0
        assert t["after_block_established"] == 0
        assert any("엔트로피" in x for x in inc["facts"]["estimated"])
        assert any("실제 내용" in x for x in inc["facts"]["unknown"])
        assert any("차단 규칙 적용" in x for x in inc["facts"]["confirmed"])
        assert any(e["code"] == "blocked" for e in inc["timeline"])
        assert "T1571 Non-Standard Port" in inc["mitre"]

        html = render_html(doc)
        for i in range(1, 9):
            assert f"<h3>{i}." in html
        # JSON 저장 → 보고서 재생성
        jp, hp = os.path.join(d, "ev.json"), os.path.join(d, "r.html")
        with open(jp, "w", encoding="utf-8") as f:
            json.dump(doc, f, ensure_ascii=False)
        assert report_from_json(jp, hp) >= 1

        # 상태 파일 복구 + TTL 만료
        again = Blocker("ask", state_path=os.path.join(d, "blocks.json"), executor=ex)
        assert again.get(1).status == "active"
        again.tick(b.expires + 1)
        assert again.get(1).status == "expired"
        assert ex.calls[-1][:5] == ["netsh", "advfirewall", "firewall", "delete", "rule"]


def test_allowlist_and_safety():
    ex = FakeExec()
    bl = Blocker("auto", allow=["8.8.8.8"], local_ips={"192.168.0.10"}, executor=ex, state_path=None)
    bl.add_allow("1.1.1.1", "DNS 서버")
    sug = Suggestion(0, "k", "x.exe", 10, 5.0, 9, ["8.8.8.8", "1.1.1.1", "192.168.0.1", "203.0.113.9"],
                     [], [])
    b = bl.offer(sug, 100)
    assert b.ips == ["203.0.113.9"] and len(b.skipped) == 3 and b.status == "active"
    assert bl.offer(sug, 101) is None                 # 같은 제안 중복 방지
    only_private = Suggestion(0, "k2", "y.exe", 11, 5.0, 9, ["192.168.0.1"], [], [])
    assert bl.offer(only_private, 102).status == "denied"
    # PID 재사용 시 프로세스 종료 거부
    assert "재사용" in bl.kill_process(b.bid, 103, current_start=99.0)
    # 적용 실패 시 반쯤 생긴 규칙 정리
    ex2 = FakeExec(fail_on="dir=in")
    bl2 = Blocker("ask", executor=ex2, state_path=None)
    b2 = bl2.offer(Suggestion(0, "k", "x.exe", 1, 0, 9, ["203.0.113.9"], [], []), 0)
    bl2.approve(b2.bid, 1)
    assert b2.status == "failed" and ex2.calls[-1][3] == "delete"
    # dry-run 은 아무것도 실행하지 않는다
    ex3 = FakeExec()
    bl3 = Blocker("ask", executor=ex3, dry_run=True, state_path=None)
    b3 = bl3.offer(Suggestion(0, "k", "x.exe", 1, 0, 9, ["203.0.113.9"], [], []), 0)
    assert bl3.approve(b3.bid, 1).status == "dry-run" and not ex3.calls


def test_evidence_chain():
    """위험도 → 신호 → 증거 ID → 증거 pcap 패킷까지 실제로 이어지는지."""
    with tempfile.TemporaryDirectory() as d:
        eng, blocker, ex, b, doc = scenario(d)
        inc = next(i for i in doc["incidents"] if i["process"]["name"] == "update.exe")
        items = {x["eid"]: x for x in inc["evidence_items"]}
        # 1) 모든 점수 신호에 증거가 있고, 그 증거가 목록에 실려 있다
        for sig in inc["evidence"]:
            assert sig["evidence_ids"], sig["code"]
            assert all(i in items for i in sig["evidence_ids"]), sig
            assert sig["measure"].get("summary"), sig["code"]
        # 2) 산정 내역의 합 = 최고 위험도
        assert sum(x["points"] for x in inc["risk_breakdown"]) == inc["peak_risk"]
        # 3) 비커닝 측정값: 간격 30초 근처, 근거 세션 수 = 간격 수 + 1
        beacon = next(x for x in inc["evidence"] if x["code"] == "beacon")
        assert all(29 <= g <= 31 for g in beacon["measure"]["gaps"])
        assert len(beacon["evidence_ids"]) == len(beacon["measure"]["gaps"]) + 1
        # 4) E- 증거의 패킷 번호가 증거 pcap 의 해당 세션 패킷을 정확히 가리킨다
        frames = {r.number: decode(r) for r in read_packets(doc["_pcap"])}
        nets = [x for x in items.values() if x["kind"] == "net"]
        assert nets
        for ev in nets:
            dd = ev["data"]
            lip, lport = dd["local"].rsplit(":", 1)
            rip, rport = dd["remote"].rsplit(":", 1)
            want = {(lip, int(lport), rip, int(rport)), (rip, int(rport), lip, int(lport))}
            for n in (dd["pkt_first"], dd["pkt_last"]):
                p = frames[n]
                assert (p.src, p.sport, p.dst, p.dport) in want, (ev["eid"], n)
        # 5) 보고서: 모든 링크에 대응하는 앵커가 있다
        html = render_html(doc)
        import re
        links = set(re.findall(r'href="#(i\d+-[EHBR]-\d{4})"', html))
        anchors = set(re.findall(r'id="(i\d+-[EHBR]-\d{4})"', html))
        assert links and links <= anchors, links - anchors
        assert "<h3>9. 증거 목록</h3>" in html and "산정 내역" in html


if __name__ == "__main__":
    test_allowlist_and_safety()
    out = sys.argv[1] if len(sys.argv) > 1 else "sim_incident_report.html"
    with tempfile.TemporaryDirectory() as d:
        eng, blocker, ex, b, doc = scenario(d)
    with open(out, "w", encoding="utf-8") as f:
        f.write(render_html(doc))
    for inc in doc["incidents"]:
        print(f"사건 #{inc['id']} [{inc['level']}] {inc['process']['name']} totals={inc['totals']}")
    print("실행된 방화벽 명령:")
    for c in ex.calls:
        print("  ", " ".join(c))
    print(f"보고서: {out}")
