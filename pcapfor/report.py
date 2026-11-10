"""분석 결과 출력: 콘솔 요약 / JSON / CSV / 단일 HTML 리포트."""
from __future__ import annotations

import csv
import html
import json
from datetime import datetime, timezone

from .analyzer import AnalysisResult

SEV_KO = {"critical": "심각", "high": "높음", "medium": "중간", "low": "낮음", "info": "정보"}
SEV_COLOR = {"critical": "#d32f2f", "high": "#f57c00", "medium": "#fbc02d",
             "low": "#7cb342", "info": "#90a4ae"}


def _fmt_ts(ts: float) -> str:
    if ts <= 0:
        return "-"
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def console_summary(r: AnalysisResult, verbose: bool = False) -> str:
    lines = []
    lines.append("=" * 70)
    lines.append(f"파일      : {r.path}")
    lines.append(f"SHA-256   : {r.sha256}")
    lines.append(f"분석 시각 : {r.analyzed_at}")
    lines.append(f"캡처 구간 : {_fmt_ts(r.first_ts)} ~ {_fmt_ts(r.last_ts)} "
                 f"({r.duration:.1f}초)")
    lines.append(f"패킷/바이트: {r.packet_count:,} / {r.byte_count:,}")
    proto = ", ".join(f"{k}={v}" for k, v in r.protocol_counts.most_common())
    lines.append(f"프로토콜  : {proto}")
    lines.append(f"세션 수   : {len(r.data.sessions)}  "
                 f"(HTTP 트랜잭션 {len(r.data.http_transactions)}, "
                 f"DNS 메시지 {len(r.data.dns_messages)})")
    if r.top_talkers:
        top = ", ".join(f"{ip}({n})" for ip, n in r.top_talkers[:5])
        lines.append(f"상위 통신 : {top}")
    lines.append("-" * 70)
    sev = r.severity_counts()
    if not r.findings:
        lines.append("탐지 결과: 없음 (이상 징후가 발견되지 않았습니다)")
    else:
        summary = "  ".join(f"{SEV_KO[k]} {sev[k]}" for k in
                            ("critical", "high", "medium", "low", "info") if sev.get(k))
        lines.append(f"탐지 결과: 총 {len(r.findings)}건  [{summary}]")
        lines.append("")
        for i, f in enumerate(r.findings, 1):
            lines.append(f"[{i}] ({SEV_KO[f.severity]}/{f.category}) {f.title}")
            lines.append(f"    {f.description}")
            if verbose:
                for ev in f.evidence:
                    lines.append(f"    증거: {ev}")
                if f.mitre and f.mitre != "-":
                    lines.append(f"    MITRE ATT&CK: {f.mitre}")
                if f.recommendation:
                    lines.append(f"    대응: {f.recommendation}")
    lines.append("=" * 70)
    return "\n".join(lines)


def to_json(r: AnalysisResult, path: str) -> None:
    doc = {
        "file": r.path,
        "sha256": r.sha256,
        "analyzed_at": r.analyzed_at,
        "capture": {
            "first": _fmt_ts(r.first_ts), "last": _fmt_ts(r.last_ts),
            "duration_sec": round(r.duration, 3),
            "packets": r.packet_count, "bytes": r.byte_count,
            "protocols": dict(r.protocol_counts),
            "sessions": len(r.data.sessions),
        },
        "findings": [
            {
                "severity": f.severity, "category": f.category, "title": f.title,
                "description": f.description, "evidence": f.evidence,
                "mitre": f.mitre, "recommendation": f.recommendation,
                "session_ids": f.session_ids,
            }
            for f in r.findings
        ],
    }
    with open(path, "w", encoding="utf-8") as fp:
        json.dump(doc, fp, ensure_ascii=False, indent=2)


def to_csv(r: AnalysisResult, path: str) -> None:
    """세션 목록 CSV (엑셀에서 바로 열리도록 utf-8-sig)."""
    with open(path, "w", encoding="utf-8-sig", newline="") as fp:
        w = csv.writer(fp)
        w.writerow(["sid", "proto", "client", "cport", "server", "sport",
                    "first", "last", "packets", "bytes_c2s", "bytes_s2c",
                    "handshake", "closed"])
        for s in r.data.sessions:
            w.writerow([s.sid, s.proto, s.client, s.cport, s.server, s.sport,
                        _fmt_ts(s.first_ts), _fmt_ts(s.last_ts), s.packets,
                        s.bytes_c2s, s.bytes_s2c,
                        "완성" if s.synack_seen else "미완성",
                        "RST" if s.rst_seen else ("FIN" if s.fin_seen else "-")])


def to_html(r: AnalysisResult, path: str) -> None:
    sev = r.severity_counts()
    e = html.escape

    badges = "".join(
        f'<span class="badge" style="background:{SEV_COLOR[k]}">{SEV_KO[k]} {sev[k]}</span>'
        for k in ("critical", "high", "medium", "low", "info") if sev.get(k)
    ) or '<span class="badge" style="background:#7cb342">탐지 없음</span>'

    rows = []
    for i, f in enumerate(r.findings, 1):
        ev = "<br>".join(e(x) for x in f.evidence)
        rows.append(f"""
      <tr>
        <td>{i}</td>
        <td><span class="badge" style="background:{SEV_COLOR[f.severity]}">{SEV_KO[f.severity]}</span></td>
        <td>{e(f.category)}</td>
        <td><b>{e(f.title)}</b><br>{e(f.description)}
            {f'<div class="ev">{ev}</div>' if ev else ''}
            {f'<div class="mitre">MITRE: {e(f.mitre)}</div>' if f.mitre and f.mitre != '-' else ''}
            {f'<div class="rec">대응: {e(f.recommendation)}</div>' if f.recommendation else ''}</td>
      </tr>""")

    sess_rows = []
    for s in r.data.sessions[:300]:
        sess_rows.append(
            f"<tr><td>{s.sid}</td><td>{s.proto}</td><td>{e(s.client)}:{s.cport}</td>"
            f"<td>{e(s.server)}:{s.sport}</td><td>{s.packets}</td>"
            f"<td>{s.bytes_c2s + s.bytes_s2c:,}</td><td>{s.duration:.2f}s</td></tr>"
        )

    proto = ", ".join(f"{k}={v}" for k, v in r.protocol_counts.most_common())
    doc = f"""<!doctype html>
<html lang="ko"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>pcap-for 리포트</title>
<style>
 body{{font-family:'Malgun Gothic',system-ui,sans-serif;margin:24px;background:#fafafa;color:#212121}}
 h1{{font-size:22px}} h2{{font-size:17px;margin-top:28px}}
 table{{border-collapse:collapse;width:100%;background:#fff;font-size:13px}}
 th,td{{border:1px solid #e0e0e0;padding:6px 10px;text-align:left;vertical-align:top}}
 th{{background:#eceff1}}
 .badge{{color:#fff;padding:2px 8px;border-radius:10px;font-size:12px;margin-right:6px;white-space:nowrap}}
 .meta td:first-child{{width:110px;color:#616161}}
 .ev{{color:#455a64;font-size:12px;margin-top:4px;font-family:Consolas,monospace}}
 .mitre{{color:#6a1b9a;font-size:12px;margin-top:2px}}
 .rec{{color:#1565c0;font-size:12px;margin-top:2px}}
</style></head><body>
<h1>pcap-for 분석 리포트</h1>
<p>{badges}</p>
<table class="meta">
 <tr><td>파일</td><td>{e(r.path)}</td></tr>
 <tr><td>SHA-256</td><td style="font-family:monospace">{r.sha256}</td></tr>
 <tr><td>분석 시각</td><td>{e(r.analyzed_at)}</td></tr>
 <tr><td>캡처 구간</td><td>{_fmt_ts(r.first_ts)} ~ {_fmt_ts(r.last_ts)} ({r.duration:.1f}초)</td></tr>
 <tr><td>패킷 / 바이트</td><td>{r.packet_count:,} / {r.byte_count:,}</td></tr>
 <tr><td>프로토콜</td><td>{e(proto)}</td></tr>
</table>
<h2>탐지 결과 ({len(r.findings)}건)</h2>
<table><tr><th>#</th><th>심각도</th><th>분류</th><th>내용</th></tr>{''.join(rows) or '<tr><td colspan="4">이상 징후가 발견되지 않았습니다.</td></tr>'}</table>
<h2>세션 목록 (상위 {min(len(r.data.sessions), 300)}건)</h2>
<table><tr><th>ID</th><th>프로토콜</th><th>클라이언트</th><th>서버</th><th>패킷</th><th>바이트</th><th>지속</th></tr>{''.join(sess_rows)}</table>
<p style="color:#9e9e9e;font-size:12px">generated by pcap-for · 모든 시각은 UTC</p>
</body></html>"""
    with open(path, "w", encoding="utf-8") as fp:
        fp.write(doc)
