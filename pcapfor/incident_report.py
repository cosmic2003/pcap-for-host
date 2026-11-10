"""사고 보고서: ledger.build_doc() 결과(dict)를 인쇄용 단일 HTML 로 그린다.

외부 라이브러리 없이 PDF 로 만들려고 인쇄용 CSS(A4, 사건마다 새 페이지)를 넣었다.
브라우저에서 열고 Ctrl+P -> 'PDF로 저장' 하면 된다.

    python -m pcapfor --report-from pcapfor_events.json --report pcapfor_incidents.html
"""
from __future__ import annotations

import html
import json
from datetime import datetime

from .ledger import _fmt_bytes

LEVEL_COLOR = {"높음": "#c62828", "중간": "#ef6c00", "낮음": "#9e9d24", "정보": "#78909c"}
CERT_COLOR = {"확인됨": "#2e7d32", "일부 확인됨": "#1565c0", "추정됨": "#ef6c00", "확인 불가": "#757575"}
STATUS_KO = {"pending": "승인 대기", "active": "적용 중", "denied": "거절/보류", "expired": "TTL 만료로 해제",
             "removed": "해제됨", "failed": "적용 실패", "dry-run": "dry-run (실행 안 함)"}
e = html.escape


def _t(ts: float, date: bool = False) -> str:
    if not ts:
        return "-"
    return datetime.fromtimestamp(ts).astimezone().strftime("%Y-%m-%d %H:%M:%S" if date else "%H:%M:%S")


def _cert(c: str) -> str:
    return f'<span class="cert" style="border-color:{CERT_COLOR.get(c, "#999")};color:{CERT_COLOR.get(c, "#999")}">{e(c)}</span>'


def _level(lv: str) -> str:
    return f'<span class="lv" style="background:{LEVEL_COLOR.get(lv, "#999")}">{e(lv)}</span>'


def _risk_chart(inc: dict) -> str:
    """시간에 따른 누적 위험도 계단 그래프 + 차단 시점 세로선."""
    evs = sorted(inc["timeline"], key=lambda x: x["ts"])
    if not evs:
        return ""
    t0, t1 = evs[0]["ts"], max(evs[-1]["ts"], evs[0]["ts"] + 1)
    t1 += (t1 - t0) * 0.08          # 오른쪽 끝 라벨(차단 등)이 잘리지 않게 여백
    W, H, L, R, T, B = 720, 170, 40, 14, 12, 26
    ymax = max(12, max(x["risk"] for x in evs))
    x = lambda ts: L + (ts - t0) / (t1 - t0) * (W - L - R)          # noqa: E731
    y = lambda r: T + (1 - r / ymax) * (H - T - B)                    # noqa: E731
    parts = []
    w = W - L - R
    parts.append(f'<rect x="{L}" y="{y(ymax):.1f}" width="{w}" height="{y(6) - y(ymax):.1f}" '
                 f'fill="{LEVEL_COLOR["높음"]}" opacity="0.06"/>')
    parts.append(f'<rect x="{L}" y="{y(6):.1f}" width="{w}" height="{y(3) - y(6):.1f}" '
                 f'fill="{LEVEL_COLOR["중간"]}" opacity="0.06"/>')
    for lvl, lo in (("높음", 6), ("중간", 3)):
        parts.append(f'<line x1="{L}" x2="{W - R}" y1="{y(lo):.1f}" y2="{y(lo):.1f}" '
                     f'stroke="{LEVEL_COLOR[lvl]}" stroke-dasharray="3 3" stroke-width="1"/>'
                     f'<text x="{W - R}" y="{y(lo) - 3:.1f}" text-anchor="end" class="ax" '
                     f'fill="{LEVEL_COLOR[lvl]}">{lvl} {lo}점</text>')
    pts, prev = [], 0.0
    for ev in evs:
        pts.append(f"{x(ev['ts']):.1f},{y(prev):.1f}")
        pts.append(f"{x(ev['ts']):.1f},{y(ev['risk']):.1f}")
        prev = ev["risk"]
    pts.append(f"{x(t1):.1f},{y(prev):.1f}")
    parts.append(f'<polyline points="{" ".join(pts)}" fill="none" stroke="#263445" stroke-width="2"/>')
    for ev in evs:
        if ev["points"] > 0:
            parts.append(f'<circle cx="{x(ev["ts"]):.1f}" cy="{y(ev["risk"]):.1f}" r="3.2" '
                         f'fill="{LEVEL_COLOR.get(ev["level"], "#999")}"><title>{e(_t(ev["ts"]))} '
                         f'+{ev["points"]} {e(ev["text"])}</title></circle>')
        if ev["code"] in ("blocked", "unblocked", "block_suggest"):
            col = {"blocked": "#2e7d32", "unblocked": "#757575", "block_suggest": "#c62828"}[ev["code"]]
            lab = {"blocked": "차단", "unblocked": "해제", "block_suggest": "제안"}[ev["code"]]
            parts.append(f'<line x1="{x(ev["ts"]):.1f}" x2="{x(ev["ts"]):.1f}" y1="{T}" y2="{H - B}" '
                         f'stroke="{col}" stroke-width="1.5"/><text x="{x(ev["ts"]) + 3:.1f}" y="{T + 10}" '
                         f'class="ax" fill="{col}">{lab}</text>')
    parts.append(f'<line x1="{L}" x2="{W - R}" y1="{H - B}" y2="{H - B}" stroke="#bbb"/>')
    for i in range(5):
        ts = t0 + (t1 - t0) * i / 4
        anchor = "start" if i == 0 else "end" if i == 4 else "middle"
        parts.append(f'<text x="{x(ts):.1f}" y="{H - 8}" text-anchor="{anchor}" class="ax">{_t(ts)}</text>')
    parts.append(f'<text x="{L - 6}" y="{y(0) + 4}" text-anchor="end" class="ax">0</text>'
                 f'<text x="{L - 6}" y="{y(ymax) + 8}" text-anchor="end" class="ax">{ymax:.0f}</text>')
    return f'<svg class="chart" viewBox="0 0 {W} {H}" role="img" aria-label="위험도 변화">{"".join(parts)}</svg>'


KIND_KO = {"net": "네트워크", "host": "실행 파일", "base": "학습 기준", "rule": "규칙 탐지"}


def _links(inc_id: int, ids) -> str:
    return " ".join(f'<a class="eid" href="#i{inc_id}-{e(i)}">{e(i)}</a>' for i in ids)


def _meas(m: dict) -> str:
    return f'<div class="meas">측정: {e(m["summary"])}</div>' if m and m.get("summary") else ""


def _breakdown(inc: dict) -> str:
    parts = inc.get("risk_breakdown") or []
    if not parts:
        return ""
    rows = "".join(
        f'<tr><td>{_t(x["ts"])}</td><td>{e(x["text"])}</td><td class="n pts">+{x["points"]}</td>'
        f'<td>{_links(inc["id"], x["evidence_ids"]) or "-"}</td></tr>' for x in parts)
    total = sum(x["points"] for x in parts)
    return (f'<details class="bd" open><summary>최고 위험도 {inc["peak_risk"]:.0f}점 산정 내역 '
            f'(신호 {len(parts)}개의 점수 합, 위험도 창 30분)</summary>'
            f'<table><tr><th>시각</th><th>신호</th><th>점수</th><th>근거 증거</th></tr>{rows}'
            f'<tr class="sum"><td></td><td>합계</td><td class="n">{total}</td><td>'
            f'{"높음(≥6)" if total >= 6 else "중간(≥3)" if total >= 3 else "낮음"}</td></tr></table></details>')


def _evidence_rows(inc: dict, doc: dict) -> str:
    rows = []
    pcap = doc.get("evidence_pcap")
    for ev in inc.get("evidence_items", []):
        d = ev["data"]
        anchor = f'i{inc["id"]}-{ev["eid"]}'
        if ev["kind"] == "net":
            body = (f'{e(d["dest"])}<div class="sub">{e(d["direction"])} · {e(d["proto"].upper())} '
                    f'{e(d["local"])} → {e(d["remote"])} · 핸드셰이크 {e(d["handshake"])} · 종료 {e(d["closed"])}</div>')
            meas = (f'{_t(d["first_ts"])} ~ {_t(d["last_ts"])} ({d["duration"]:.1f}s)<br>'
                    f'송신 {d["bytes_out"]:,}B · 수신 {d["bytes_in"]:,}B · 패킷 {d["packets"]}')
            frames = (f'#{d["pkt_first"]} ~ #{d["pkt_last"]}' if d.get("pkt_first") else "-")
            filt = f'<code class="flt">{e(d["filter"])}</code>'
            if pcap and d.get("frame_filter"):
                filt += f'<code class="flt">{e(d["frame_filter"])}</code>'
        elif ev["kind"] == "host":
            body = f'{e(d["path"])}'
            meas = (f'SHA-256 <code>{e(d["sha256"] or "-")}</code><br>'
                    f'서명 {e(d["sig_status"] or "-")}' + (f' · {e(d["signer"])}' if d.get("signer") else ""))
            frames, filt = "-", '<span class="sub">파일 해시로 VirusTotal 등에서 조회 가능</span>'
        elif ev["kind"] == "base":
            iv = d.get("learned_interval")
            body = f'{e(d["dest"])}<div class="sub">학습 기간에 기록된 평소 통신</div>'
            meas = (f'학습 연결 {d["learned_conns"]}회 · 포트 {e(", ".join(map(str, d["learned_ports"])) or "-")}<br>'
                    f'평소 주기 {f"{iv:.0f}s" if iv else "산출 불가(간격 부족)"} · '
                    f'학습 간격 {e(", ".join(f"{g:.0f}" for g in d["learned_gaps"][-8:]) or "-")}')
            frames, filt = "-", '<span class="sub">pcapfor_profiles.json</span>'
        else:
            body = f'{e(ev["title"])}<div class="sub">{e(d.get("description", ""))}</div>'
            meas = "<br>".join(e(x) for x in d.get("evidence", [])[:4])
            frames, filt = "-", e(d.get("mitre", ""))
        rows.append(f'<tr id="{anchor}"><td><b class="eid">{e(ev["eid"])}</b><div class="sub">{KIND_KO[ev["kind"]]}</div></td>'
                    f'<td>{body}</td><td class="sub2">{meas}</td><td class="n">{frames}</td><td>{filt}</td></tr>')
    if not rows:
        return '<p class="sub">연결된 증거가 없습니다.</p>'
    note = (f'<p class="sub">패킷 번호는 증거 pcap <code>{e(pcap["path"])}</code> '
            f'(SHA-256 <code>{e(pcap["sha256"])}</code>, {pcap["packets"]:,} packets) 의 Wireshark frame.number 와 같습니다.</p>'
            if pcap else
            '<p class="sub">증거 pcap 을 저장하지 않았습니다(<code>--save</code>). 패킷 번호는 이번 캡처 안의 순번이며, '
            '아래 Wireshark 필터는 같은 시간대의 다른 캡처에도 그대로 쓸 수 있습니다.</p>')
    nets = [ev["data"] for ev in inc.get("evidence_items", []) if ev["kind"] == "net"]
    whole = ""
    if nets:
        pairs = sorted({(d["local"].rsplit(":", 1)[0], d["remote"].rsplit(":", 1)[0]) for d in nets})
        f = " || ".join(f"(ip.addr=={a} && ip.addr=={b})" for a, b in pairs)
        if pcap:
            lo = min(d["pkt_first"] for d in nets if d["pkt_first"])
            hi = max(d["pkt_last"] for d in nets if d["pkt_last"])
            f = f"({f}) && frame.number >= {lo} && frame.number <= {hi}"
        whole = (f'<div class="all"><b>이 사건 전체를 Wireshark 로 보기</b> — 증거 pcap 을 열고 표시 필터에 붙여넣기'
                 f'<code class="flt">{e(f)}</code></div>')
    return (note + whole + '<table class="evt"><tr><th>ID</th><th>대상</th><th>실제 측정값</th><th>패킷 번호</th>'
            '<th>Wireshark 필터 / 확인 방법</th></tr>' + "".join(rows) + "</table>")


def _incident(inc: dict, doc: dict) -> str:
    p = inc["process"]
    tot = inc["totals"]
    blocks = inc["blocks"]
    active = [b for b in blocks if b["applied"]]
    block_line = (f"차단 {_t(active[0]['applied'])} ({STATUS_KO[active[0]['status']]})" if active
                  else ("차단 제안됨 · 미적용" if blocks else "차단 제안 없음"))

    proc_rows = [
        ("프로세스", f"{e(p['name'])} (PID {p['pid'] or '-'})"),
        ("실행 경로", e(p["path"] or "확인 불가 (권한 부족 또는 미귀속)")),
        ("부모 프로세스", e(p["parent"] or "-")),
        ("프로세스 시작", _t(p["start_time"], True)),
        ("SHA-256", f'<code>{e(p["sha256"] or "-")}</code>'),
        ("코드 서명", e(p["sig_status"] or "미확인") + (f" · 서명자 {e(p['signer'])}" if p["signer"] else "")),
        ("최초 관측", _t(p["first_seen"], True) + (" (학습 기간에 관측된 프로세스)" if p["learned"]
                                                  else " (학습 기간에 없던 프로세스)")),
    ]
    for h in p["file_history"]:
        proc_rows.append(("실행 파일 변경", f"{_t(h['ts'], True)} → {e(h['sha256'][:16])}… "
                                       f"({e(h['sig_status'])} {e(h['signer'])})"))

    dest_rows = "".join(
        f'<tr class="{"flag" if d["flagged"] else ""}"><td>{"⚠ " if d["flagged"] else ""}<code>{e(d["ip"])}</code>'
        f'<br><span class="sub">{e(d["name"] or "이름 확인 불가")}</span> {_cert(d["name_certainty"])}</td>'
        f'<td>{e(", ".join(map(str, d["ports"])))}</td><td class="n">{d["conns"]}</td>'
        f'<td class="n">{_fmt_bytes(d["bytes_out"])}</td><td class="n">{_fmt_bytes(d["bytes_in"])}</td>'
        f'<td>{_t(d["first"])}<br>~ {_t(d["last"])}</td>'
        f'<td class="sub">{e(", ".join(f"{k} {v}" for k, v in d["content"].items()))}</td></tr>'
        for d in inc["destinations"])

    ev_rows = "".join(
        f'<tr><td>{_t(x["ts"])}</td><td class="n pts">+{x["points"]}</td>'
        f'<td class="n">{x["risk"]:.0f} {_level(x["level"])}</td><td>{_cert(x["certainty"])}</td>'
        f'<td>{e(x["text"])}{_meas(x.get("measure"))}'
        + "".join(f'<div class="sub">· {e(d)}</div>' for d in x["detail"]) +
        f'</td><td>{_links(inc["id"], x.get("evidence_ids", [])) or "-"}</td>'
        f'<td class="sub">{e(x["mitre"])}</td></tr>' for x in inc["evidence"])

    flow_rows = "".join(
        f'<tr><td>{e(k)}</td><td class="n">{v["sessions"]}</td><td class="n">{_fmt_bytes(v["bytes_out"])}</td>'
        f'<td>{_cert(v["content_certainty"])}</td></tr>' for k, v in inc["content_kinds"].items())
    previews = "".join(f"<li><code>{e(x)}</code></li>" for x in inc["previews"])
    tl_rows = "".join(
        f'<tr class="{"ctx" if not x["points"] else ""}"><td>{_t(x["ts"])}</td>'
        f'<td>{e(x["text"])}</td><td>{_links(inc["id"], x.get("evidence_ids", []))}</td>'
        f'<td class="n">{x["risk"]:.0f}</td></tr>' for x in inc["timeline"])

    if blocks:
        blk = "".join(
            f'<div class="blk"><b>차단 #{b["id"]}</b> · {e(STATUS_KO[b["status"]])} · 대상 '
            f'<code>{e(", ".join(b["ips"]) or "-")}</code>'
            + (f' · 승인: {"사용자" if b["approved_by"] == "user" else "자동(실험)"}' if b["approved_by"] else "")
            + (f'<div class="sub">차단 금지 목록이라 제외: {e("; ".join(b["skipped"]))}</div>' if b["skipped"] else "")
            + (f'<div class="sub err">오류: {e(b["error"])}</div>' if b["error"] else "")
            + "<ul>" + "".join(f'<li>{_t(g["ts"])} {e(g["action"])} — {e(g["detail"])}</li>' for g in b["log"])
            + "</ul></div>" for b in blocks)
    else:
        blk = '<p class="sub">위험도가 \'높음\'에 이르지 않아 차단 제안이 없었습니다.</p>'

    if active:
        applied = _t(active[0]["applied"])
        if tot["after_block_out"]:
            after = (f'<p class="err">차단({applied}) 이후에도 의심 목적지로 {_fmt_bytes(tot["after_block_out"])} 전송이 '
                     '관측됐습니다. 규칙 적용 범위(다른 IP 사용 여부)를 확인하세요.</p>')
        elif tot["after_block_attempts"]:
            after = (f'<p>차단({applied}) 이후 의심 목적지로 <b>연결 시도 패킷 {tot["after_block_attempts"]}건</b>, '
                     f'연결 성립 {tot["after_block_established"]}회, 전송 <b>0B</b>.</p>'
                     '<p class="good">추가 유출은 관측되지 않았습니다. 프로세스가 계속 접속을 시도하므로 '
                     '프로세스 종료·악성코드 점검이 필요합니다.</p>')
        else:
            after = (f'<p>차단({applied}) 이후 의심 목적지로 나간 패킷 <b>0개</b>, 전송 <b>0B</b>.</p>'
                     '<p class="good">차단 이후 추가 유출은 관측되지 않았습니다.</p>'
                     '<p class="sub">단, Windows 방화벽은 패킷이 캡처되기 전에 막으므로 프로세스가 계속 접속을 '
                     '시도하는지는 캡처로 알 수 없습니다. 프로세스가 아직 실행 중이면 종료·점검이 필요합니다.</p>')
        after += f'<p class="sub">차단 전까지 의심 목적지로 나간 데이터: {_fmt_bytes(tot["before_block_out"])}</p>'
    else:
        after = '<p class="sub">차단이 적용되지 않아 비교할 수 없습니다.</p>'

    facts = inc["facts"]
    col = lambda title, items, c: (f'<div class="fact" style="border-top-color:{c}"><h4 style="color:{c}">{title}</h4><ul>'  # noqa: E731
                                   + "".join(f"<li>{e(i)}</li>" for i in items) + "</ul></div>")

    return f"""
<section class="incident">
  <div class="ihead" style="border-left-color:{LEVEL_COLOR.get(inc['level'], '#999')}">
    <div><div class="iid">사건 #{inc['id']}</div><h2>{e(p['name'])} {_level(inc['level'])}</h2>
      <div class="sub">최고 위험도 {inc['peak_risk']:.0f}점 · {_t(inc['start'], True)} ~ {_t(inc['end'])} · {e(block_line)}</div></div>
    <div class="kpis">
      <div><b>{_fmt_bytes(tot['flagged_out'])}</b><span>의심 목적지로 전송</span></div>
      <div><b>{sum(1 for d in inc['destinations'] if d['flagged'])}</b><span>의심 목적지</span></div>
      <div><b>{len(inc['evidence'])}</b><span>탐지 근거</span></div>
    </div>
  </div>
  {_risk_chart(inc)}
  {_breakdown(inc)}

  <h3>1. 최초 이상 행동 발생 시각</h3>
  <p class="big">{_t(inc['first_anomaly'], True)}</p>
  <p class="sub">{e(inc['evidence'][0]['text']) if inc['evidence'] else ''}</p>

  <h3>2. 의심 프로세스 정보</h3>
  <table class="kv">{''.join(f'<tr><th>{k}</th><td>{v}</td></tr>' for k, v in proc_rows)}</table>

  <h3>3. 연결된 목적지</h3>
  <table><tr><th>목적지 (이름 확신도)</th><th>포트</th><th>연결</th><th>송신</th><th>수신</th><th>기간</th><th>내용 종류</th></tr>{dest_rows}</table>
  <p class="sub">⚠ = 이상 신호가 나온 목적지</p>

  <h3>4. 이상 행동 탐지 근거</h3>
  <table><tr><th>시각</th><th>점수</th><th>누적</th><th>확신도</th><th>근거 · 측정값</th><th>증거</th><th>MITRE ATT&amp;CK (연관)</th></tr>{ev_rows}</table>
  <details open><summary>전체 흐름 (맥락 이벤트 포함)</summary>
  <table class="tl"><tr><th>시각</th><th>이벤트</th><th>증거</th><th>위험도</th></tr>{tl_rows}</table></details>

  <h3>5. 외부 전송량 및 통신 기록</h3>
  <p>이 프로세스의 외부 전송 <b>{_fmt_bytes(tot['out'])}</b> 중 의심 목적지로 <b>{_fmt_bytes(tot['flagged_out'])}</b>.</p>
  <table><tr><th>데이터 종류</th><th>세션</th><th>송신</th><th>내용 확인 가능성</th></tr>{flow_rows}</table>
  {f'<p class="sub">평문 미리보기</p><ul class="pv">{previews}</ul>' if previews else ''}

  <h3>6. 차단 여부와 차단 시각</h3>
  {blk}

  <h3>7. 차단 이후 변화</h3>
  {after}

  <h3>8. 확인된 사실과 확인할 수 없는 사실</h3>
  <div class="facts">
    {col('확인됨', facts['confirmed'], CERT_COLOR['확인됨'])}
    {col('추정됨', facts['estimated'], CERT_COLOR['추정됨'])}
    {col('확인 불가', facts['unknown'], CERT_COLOR['확인 불가'])}
  </div>

  <h3>9. 증거 목록</h3>
  {_evidence_rows(inc, doc)}
</section>"""


CSS = """
@page{size:A4;margin:14mm}
*{box-sizing:border-box}
body{font-family:'Malgun Gothic','Apple SD Gothic Neo','Segoe UI',sans-serif;color:#1f2933;margin:0;background:#eef1f5;font-size:12.5px;line-height:1.55}
.wrap{max-width:900px;margin:24px auto;background:#fff;padding:28px 34px;box-shadow:0 1px 4px rgba(0,0,0,.08)}
header{display:flex;justify-content:space-between;align-items:flex-start;border-bottom:2px solid #263445;padding-bottom:12px;margin-bottom:18px}
header h1{margin:0;font-size:21px}
.brand{font-family:Consolas,monospace;font-weight:700;color:#263445}.brand span{color:#1565c0}
.meta{font-size:11.5px;color:#52606d;text-align:right}
.note{background:#fff8e1;border-left:3px solid #ef6c00;padding:8px 12px;font-size:11.5px;margin:10px 0 18px}
.overview td,.overview th{padding:5px 8px}
.incident{page-break-before:always;break-before:page;margin-top:30px}
.incident:first-of-type{page-break-before:auto;break-before:auto}
.ihead{display:flex;justify-content:space-between;gap:14px;border-left:5px solid;padding:6px 0 6px 14px;margin-bottom:8px}
.ihead h2{margin:2px 0;font-size:19px}.iid{font-size:11px;color:#7b8794;letter-spacing:.06em}
.kpis{display:flex;gap:16px;text-align:right;flex-shrink:0;padding-right:4px}.kpis div{white-space:nowrap}.kpis b{display:block;font-size:17px}.kpis span{font-size:10.5px;color:#7b8794}
h3{font-size:13.5px;margin:20px 0 6px;padding-bottom:3px;border-bottom:1px solid #d9e2ec;color:#263445}
table{width:100%;border-collapse:collapse;font-size:11.5px}
th,td{border-bottom:1px solid #e4e7eb;padding:5px 7px;text-align:left;vertical-align:top}
th{background:#f5f7fa;font-weight:600;color:#3e4c59}
.kv th{width:120px}
td.n{text-align:right;white-space:nowrap}.pts{color:#c62828;font-weight:700}
tr.flag td{background:#fff5f5}tr.ctx td{color:#7b8794}
code{font-family:Consolas,monospace;font-size:11px;word-break:break-all}
.sub{color:#7b8794;font-size:11px}.big{font-size:17px;font-weight:700;margin:4px 0}
.lv{color:#fff;border-radius:9px;padding:0 8px;font-size:10.5px;font-weight:700;vertical-align:middle}
.cert{border:1px solid;border-radius:9px;padding:0 6px;font-size:10px;white-space:nowrap}
.chart{width:100%;height:auto;margin:6px 0 4px;background:#fafbfc;border:1px solid #e4e7eb;border-radius:6px}
.ax{font-size:9.5px;fill:#7b8794}
.blk{border:1px solid #e4e7eb;border-radius:6px;padding:8px 12px;margin:6px 0}.blk ul{margin:4px 0 0;padding-left:18px}
.good{color:#2e7d32;font-weight:600}.err{color:#c62828}
.facts{display:grid;grid-template-columns:1fr 1fr 1fr;gap:10px}
.fact{border:1px solid #e4e7eb;border-top:3px solid;border-radius:6px;padding:6px 10px}
.fact h4{margin:2px 0 4px;font-size:12.5px}.fact ul{margin:0;padding-left:16px;font-size:11px}
.pv code{white-space:pre-wrap}
a.eid,b.eid{font-family:Consolas,monospace;font-size:10.5px;white-space:nowrap}
a.eid{color:#1565c0;text-decoration:none;border:1px solid #bbdefb;background:#f3f8fe;border-radius:4px;padding:0 4px;margin:1px;display:inline-block}
a.eid:hover{background:#e3f2fd}
.meas{font-size:11px;color:#3e4c59;background:#f5f7fa;border-left:2px solid #90a4ae;padding:2px 6px;margin:3px 0}
.bd{margin:6px 0 4px}.bd summary{font-weight:600;color:#263445;font-size:12px}
tr.sum td{font-weight:700;border-top:2px solid #263445}
.evt td{font-size:11px}.sub2{font-size:11px;color:#3e4c59}
code.flt{display:block;background:#f5f7fa;border:1px solid #e4e7eb;border-radius:4px;padding:2px 5px;margin:2px 0;font-size:10.5px;word-break:normal;overflow-wrap:anywhere}
.evt{table-layout:fixed}.evt th:nth-child(1){width:74px}.evt th:nth-child(2){width:27%}.evt th:nth-child(3){width:23%}
.evt th:nth-child(4){width:72px}
.all{background:#e8f5e9;border:1px solid #c8e6c9;border-radius:6px;padding:6px 10px;margin:6px 0}
tr:target td{background:#fff8e1!important}
details summary{cursor:pointer;color:#52606d;font-size:11.5px;margin:8px 0 4px}
footer{margin-top:26px;color:#9aa5b1;font-size:10.5px;border-top:1px solid #e4e7eb;padding-top:8px}
@media print{body{background:#fff}.wrap{box-shadow:none;margin:0;max-width:none;padding:0}details{display:block}details>summary{display:none}}
"""


def render_html(doc: dict) -> str:
    s = doc["summary"]
    incs = doc["incidents"]
    rows = "".join(
        f'<tr><td>#{i["id"]}</td><td>{_level(i["level"])}</td><td>{e(i["process"]["name"])}</td>'
        f'<td class="n">{i["peak_risk"]:.0f}</td><td>{_t(i["first_anomaly"], True)}</td>'
        f'<td class="n">{_fmt_bytes(i["totals"]["flagged_out"])}</td>'
        f'<td>{e(next((STATUS_KO[b["status"]] for b in i["blocks"] if b["applied"]), "미차단"))}</td></tr>'
        for i in incs) or '<tr><td colspan="7">사건 없음 — 위험도 \'중간\' 이상인 이상 행동이 관측되지 않았습니다.</td></tr>'
    attr = (f"{s['attribution_rate']:.0%}" if s.get("attribution_rate") is not None else "-")
    return f"""<!doctype html><html lang="ko"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>pcap for 사고 보고서</title>
<style>{CSS}</style></head><body><div class="wrap">
<header><div><div class="brand">pcap <span>for</span></div><h1>호스트 사고 보고서</h1></div>
<div class="meta">작성 {e(doc['generated_str'])} ({e(doc['tz'])})<br>감시 호스트 {e(doc['host_ip'] or '-')} · {e(doc['mode'])} 모드<br>
캡처 시작 {_t(doc['capture_start'], True)} · 패킷 {doc['packets']:,}<br>
증거 {doc.get('evidence_total', 0)}건 · 증거 pcap {('저장됨 SHA-256 ' + e(doc['evidence_pcap']['sha256'][:16]) + '…') if doc.get('evidence_pcap') else '미저장'}</div></header>
<div class="note">이 보고서는 <b>감염 판정이 아니라 근거가 붙은 의심</b>입니다. 각 항목의 확신도
({_cert('확인됨')} {_cert('일부 확인됨')} {_cert('추정됨')} {_cert('확인 불가')})를 함께 보세요.
{e(doc['baseline_note'])} 누적 학습 {s['learning_min']}분 · 프로세스 귀속 성공률 {attr}
(미귀속 외부 세션 {s['unattributed_sessions']}개).</div>
<h3>사건 요약</h3>
<table class="overview"><tr><th>사건</th><th>수준</th><th>프로세스</th><th>최고 위험도</th><th>최초 이상</th><th>의심 전송량</th><th>차단</th></tr>{rows}</table>
{''.join(_incident(i, doc) for i in incs)}
<footer>generated by pcap-for · 시각은 분석 PC 현지 시각({e(doc['tz'])}) · 브라우저에서 Ctrl+P → 'PDF로 저장'으로 PDF 를 만들 수 있습니다.</footer>
</div></body></html>"""


def write_report(doc: dict, path: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        f.write(render_html(doc))


def report_from_json(json_path: str, out_path: str) -> int:
    with open(json_path, encoding="utf-8") as f:
        doc = json.load(f)
    if "incidents" not in doc or "summary" not in doc or "generated_str" not in doc:
        raise ValueError("pcap-for 이벤트 JSON 이 아닙니다 (--live 종료 시 저장되는 파일을 쓰세요)")
    write_report(doc, out_path)
    return len(doc["incidents"])
