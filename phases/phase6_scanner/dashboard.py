"""
Enigma pqc-scanner v4.0: Interactive HTML Dashboard.

Generates a self-contained single HTML file with:
  - Risk gauge (SVG arc)
  - PQC Readiness grade badge
  - Algorithm breakdown donut chart
  - CNSA 2.0 deadline timeline
  - Severity distribution bar chart
  - Searchable findings table
  - QARS score details
  - Auto-fix suggestions

Zero external dependencies — all CSS/JS inline.
Dark theme matching Enigma Psi branding (navy + gold).
"""

from __future__ import annotations
import html as html_mod
import json
import os
import math
import hashlib
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from pqc_scanner import ScanResult, Finding, Severity, __version__


# ============================================================================
# COLOR SCHEME (Enigma Psi branding)
# ============================================================================

COLORS = {
    'bg': '#0a0e1a',
    'card': '#141828',
    'card_border': '#1e2640',
    'text': '#e0e4f0',
    'text_muted': '#8890a8',
    'gold': '#d4af37',
    'cyan': '#7eb8da',
    'purple': '#bb86fc',
    'critical': '#ff4444',
    'high': '#ff8800',
    'medium': '#ffcc00',
    'low': '#44aaff',
    'info': '#888888',
    'safe': '#00cc66',
}

SEV_COLORS = {
    'CRITICAL': COLORS['critical'],
    'HIGH': COLORS['high'],
    'MEDIUM': COLORS['medium'],
    'LOW': COLORS['low'],
    'INFO': COLORS['info'],
}


def _risk_color(score: int) -> str:
    """Color based on risk score (0-100)."""
    if score >= 80: return COLORS['critical']
    if score >= 60: return COLORS['high']
    if score >= 40: return COLORS['medium']
    if score >= 20: return COLORS['low']
    return COLORS['safe']


def _grade_color(grade: str) -> str:
    """Color based on readiness grade."""
    colors = {'A+': COLORS['safe'], 'A': COLORS['safe'], 'B': COLORS['cyan'],
              'C': COLORS['medium'], 'D': COLORS['high'], 'F': COLORS['critical']}
    return colors.get(grade, COLORS['text_muted'])


# ============================================================================
# SVG GENERATORS
# ============================================================================

def _svg_gauge(score: int, label: str, size: int = 180) -> str:
    """Generate an SVG arc gauge for risk score."""
    cx, cy = size // 2, size // 2 + 10
    r = size // 2 - 20
    start_angle = 220
    end_angle = -40
    total_arc = start_angle - end_angle
    fill_arc = total_arc * (score / 100)

    def polar_to_cart(angle_deg):
        rad = math.radians(angle_deg)
        return cx + r * math.cos(rad), cy - r * math.sin(rad)

    # Background arc
    sx, sy = polar_to_cart(start_angle)
    ex, ey = polar_to_cart(end_angle)
    bg_path = f'M {sx:.1f} {sy:.1f} A {r} {r} 0 1 1 {ex:.1f} {ey:.1f}'

    # Fill arc
    fill_end = start_angle - fill_arc
    fex, fey = polar_to_cart(fill_end)
    large = 1 if fill_arc > 180 else 0
    fill_path = f'M {sx:.1f} {sy:.1f} A {r} {r} 0 {large} 1 {fex:.1f} {fey:.1f}'

    color = _risk_color(score)

    return f'''<svg width="{size}" height="{size + 20}" viewBox="0 0 {size} {size + 20}">
  <path d="{bg_path}" fill="none" stroke="{COLORS['card_border']}" stroke-width="16" stroke-linecap="round"/>
  <path d="{fill_path}" fill="none" stroke="{color}" stroke-width="16" stroke-linecap="round"/>
  <text x="{cx}" y="{cy - 5}" text-anchor="middle" fill="{color}" font-size="42" font-weight="bold" font-family="monospace">{score}</text>
  <text x="{cx}" y="{cy + 20}" text-anchor="middle" fill="{COLORS['text_muted']}" font-size="13" font-family="sans-serif">{label}</text>
</svg>'''


def _svg_donut(data: Dict[str, int], size: int = 200) -> str:
    """Generate an SVG donut chart for algorithm distribution."""
    if not data:
        return '<svg width="200" height="200"></svg>'

    total = sum(data.values())
    if total == 0:
        return '<svg width="200" height="200"></svg>'

    cx, cy = size // 2, size // 2
    r = size // 2 - 30
    inner_r = r - 25

    algo_colors = [COLORS['critical'], COLORS['high'], COLORS['medium'],
                   COLORS['cyan'], COLORS['purple'], COLORS['gold'],
                   '#ff6b9d', '#c084fc', '#67e8f9', '#fbbf24', '#a3e635', '#f87171']

    paths = []
    legend = []
    angle = 0

    for i, (algo, count) in enumerate(sorted(data.items(), key=lambda x: -x[1])):
        pct = count / total
        sweep = pct * 360
        color = algo_colors[i % len(algo_colors)]

        # Outer arc
        start_rad = math.radians(angle - 90)
        end_rad = math.radians(angle + sweep - 90)
        large = 1 if sweep > 180 else 0

        x1 = cx + r * math.cos(start_rad)
        y1 = cy + r * math.sin(start_rad)
        x2 = cx + r * math.cos(end_rad)
        y2 = cy + r * math.sin(end_rad)
        ix1 = cx + inner_r * math.cos(end_rad)
        iy1 = cy + inner_r * math.sin(end_rad)
        ix2 = cx + inner_r * math.cos(start_rad)
        iy2 = cy + inner_r * math.sin(start_rad)

        path = (f'M {x1:.1f} {y1:.1f} A {r} {r} 0 {large} 1 {x2:.1f} {y2:.1f} '
                f'L {ix1:.1f} {iy1:.1f} A {inner_r} {inner_r} 0 {large} 0 {ix2:.1f} {iy2:.1f} Z')
        paths.append(f'<path d="{path}" fill="{color}" opacity="0.85"/>')
        legend.append(f'<div style="display:flex;align-items:center;gap:6px;margin:2px 0">'
                     f'<span style="width:10px;height:10px;background:{color};border-radius:2px;display:inline-block"></span>'
                     f'<span style="font-size:12px;color:{COLORS["text_muted"]}">{algo}: {count} ({pct:.0%})</span></div>')
        angle += sweep

    svg = f'''<svg width="{size}" height="{size}" viewBox="0 0 {size} {size}">
  {"".join(paths)}
  <text x="{cx}" y="{cy - 2}" text-anchor="middle" fill="{COLORS['text']}" font-size="22" font-weight="bold" font-family="monospace">{total}</text>
  <text x="{cx}" y="{cy + 16}" text-anchor="middle" fill="{COLORS['text_muted']}" font-size="11" font-family="sans-serif">findings</text>
</svg>'''

    return svg, "\n".join(legend)


def _svg_severity_bars(summary: Dict[str, int]) -> str:
    """Generate horizontal severity bars."""
    max_count = max(summary.values()) if summary else 1
    bars = []
    for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
        count = summary.get(sev, 0)
        if count == 0:
            continue
        width = max(4, (count / max(max_count, 1)) * 100)
        color = SEV_COLORS.get(sev, COLORS['text_muted'])
        bars.append(f'''<div style="display:flex;align-items:center;gap:10px;margin:6px 0">
  <span style="width:70px;font-size:12px;color:{color};font-weight:bold;text-align:right">{sev}</span>
  <div style="flex:1;background:{COLORS['card_border']};border-radius:4px;height:22px;overflow:hidden">
    <div style="width:{width}%;background:{color};height:100%;border-radius:4px;display:flex;align-items:center;padding-left:8px">
      <span style="font-size:12px;color:#fff;font-weight:bold">{count}</span>
    </div>
  </div>
</div>''')
    return "\n".join(bars)


# ============================================================================
# DASHBOARD GENERATOR
# ============================================================================

def generate_dashboard(result: ScanResult,
                       grade_info: Optional[dict] = None,
                       qars_info: Optional[dict] = None,
                       deadline_info: Optional[list] = None,
                       fix_info: Optional[list] = None) -> str:
    """Generate the complete interactive HTML dashboard."""
    result.compute_summary()

    # Grade info
    grade_str = html_mod.escape(str(grade_info.get('grade', '?'))) if grade_info else '?'
    grade_score = grade_info.get('score', 0) if grade_info else 0
    grade_summary = grade_info.get('summary', '') if grade_info else ''
    recs = grade_info.get('recommendations', []) if grade_info else []

    # Algorithm distribution
    algo_dist = {}
    for f in result.findings:
        algo_dist[f.algorithm] = algo_dist.get(f.algorithm, 0) + 1

    # SVG components
    gauge_svg = _svg_gauge(result.risk_score, 'Risk Score')
    donut_result = _svg_donut(algo_dist)
    if isinstance(donut_result, tuple):
        donut_svg, donut_legend = donut_result
    else:
        donut_svg, donut_legend = donut_result, ''
    severity_bars = _svg_severity_bars(result.summary)

    # Findings table rows
    findings_rows = ''
    for f in result.findings:
        color = SEV_COLORS.get(f.severity.value, COLORS['text_muted'])
        snippet = html_mod.escape(f.code_snippet[:80])
        algo = html_mod.escape(f.algorithm)
        desc = html_mod.escape(f.description[:60])
        rel_file = html_mod.escape(os.path.basename(f.file))
        replacement = html_mod.escape(f.pqc_replacement)
        findings_rows += f'''<tr class="finding-row" data-severity="{html_mod.escape(f.severity.value)}" data-algo="{algo}">
  <td style="color:{color};font-weight:bold;width:80px">{html_mod.escape(f.severity.value)}</td>
  <td style="color:{COLORS['gold']}">{algo}</td>
  <td><code style="font-size:11px;color:{COLORS['text_muted']}">{snippet}</code></td>
  <td style="font-size:12px">{rel_file}:{f.line}</td>
  <td style="font-size:11px;color:{COLORS['cyan']}">{replacement}</td>
</tr>\n'''

    # Deadline timeline
    deadline_html = ''
    if deadline_info:
        for d in deadline_info:
            days = d.get('days_remaining', 0)
            algo = html_mod.escape(d.get('algorithm', ''))
            deadline_date = html_mod.escape(str(d.get('deadline_date', '')))
            urgency = html_mod.escape(str(d.get('urgency', '')))
            color = COLORS['critical'] if days < 0 else (
                COLORS['high'] if days < 365 else (
                COLORS['medium'] if days < 1095 else COLORS['safe']))
            status = f'OVERDUE by {abs(days)} days' if days < 0 else f'{days} days'
            deadline_html += f'''<div style="display:flex;align-items:center;gap:12px;padding:8px 0;border-bottom:1px solid {COLORS['card_border']}">
  <span style="width:100px;color:{COLORS['gold']};font-weight:bold">{algo}</span>
  <span style="color:{color};font-weight:bold;width:180px">{status}</span>
  <span style="color:{COLORS['text_muted']};font-size:12px">{deadline_date} [{urgency}]</span>
</div>\n'''

    # Fix suggestions
    fix_html = ''
    if fix_info:
        for fix in fix_info[:10]:
            tier = fix.get('tier', 0)
            tier_label = {1: 'SAFE', 2: 'REVIEW', 3: 'ADVISORY'}.get(tier, '?')
            tier_color = {1: COLORS['safe'], 2: COLORS['medium'], 3: COLORS['low']}.get(tier, COLORS['text_muted'])
            fix_html += f'''<div style="padding:8px 0;border-bottom:1px solid {COLORS['card_border']}">
  <span style="color:{tier_color};font-weight:bold;font-size:11px">[{tier_label}]</span>
  <span style="color:{COLORS['gold']}">{html_mod.escape(fix.get('algorithm_before',''))} → {html_mod.escape(fix.get('algorithm_after',''))}</span>
  <div style="font-size:12px;color:{COLORS['text_muted']};margin-top:4px">{html_mod.escape(fix.get('explanation','')[:100])}</div>
</div>\n'''

    # Recommendations
    recs_html = ''
    for i, r in enumerate(recs[:5], 1):
        recs_html += f'<div style="padding:4px 0;color:{COLORS["text"]};font-size:13px">{i}. {html_mod.escape(r)}</div>\n'

    return f'''<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>PQC Scanner Dashboard — Enigma</title>
<style>
* {{ margin:0; padding:0; box-sizing:border-box; }}
body {{ font-family:'Segoe UI',system-ui,-apple-system,sans-serif; background:{COLORS['bg']}; color:{COLORS['text']}; }}
.container {{ max-width:1400px; margin:0 auto; padding:20px; }}
.header {{ text-align:center; padding:30px 0 20px; }}
.header h1 {{ color:{COLORS['gold']}; font-size:28px; letter-spacing:2px; }}
.header .subtitle {{ color:{COLORS['text_muted']}; font-size:14px; margin-top:6px; }}
.grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(300px,1fr)); gap:16px; margin:20px 0; }}
.card {{ background:{COLORS['card']}; border:1px solid {COLORS['card_border']}; border-radius:12px; padding:20px; }}
.card h2 {{ color:{COLORS['cyan']}; font-size:15px; margin-bottom:14px; text-transform:uppercase; letter-spacing:1px; }}
.grade-badge {{ display:inline-flex; align-items:center; justify-content:center; width:80px; height:80px;
  border-radius:16px; font-size:36px; font-weight:bold; border:3px solid; }}
.findings-table {{ width:100%; border-collapse:collapse; margin-top:10px; }}
.findings-table th {{ background:{COLORS['card_border']}; color:{COLORS['cyan']}; padding:10px 8px; text-align:left; font-size:12px; text-transform:uppercase; }}
.findings-table td {{ padding:8px; border-bottom:1px solid {COLORS['card_border']}; font-size:13px; }}
.findings-table tr:hover {{ background:rgba(126,184,218,0.05); }}
.search {{ width:100%; padding:10px 14px; background:{COLORS['card']}; border:1px solid {COLORS['card_border']};
  border-radius:8px; color:{COLORS['text']}; font-size:14px; margin-bottom:12px; }}
.search::placeholder {{ color:{COLORS['text_muted']}; }}
.filter-btn {{ padding:4px 12px; border-radius:4px; border:1px solid {COLORS['card_border']};
  background:transparent; color:{COLORS['text_muted']}; cursor:pointer; font-size:12px; margin:2px; }}
.filter-btn:hover, .filter-btn.active {{ background:{COLORS['card_border']}; color:{COLORS['text']}; }}
.stat {{ text-align:center; }}
.stat-num {{ font-size:36px; font-weight:bold; color:{COLORS['purple']}; }}
.stat-label {{ font-size:12px; color:{COLORS['text_muted']}; margin-top:4px; }}
code {{ background:rgba(126,184,218,0.1); padding:1px 5px; border-radius:3px; font-size:12px; }}
</style></head><body>
<div class="container">

<div class="header">
  <h1>\u03A8 PQC-SCANNER DASHBOARD</h1>
  <div class="subtitle">Enigma Post-Quantum Cryptography Migration Scanner v{__version__}</div>
  <div class="subtitle" style="margin-top:4px">Scan: {html_mod.escape(result.scan_path)} | {html_mod.escape(result.scan_date[:10])}</div>
</div>

<div class="grid" style="grid-template-columns:repeat(4,1fr)">
  <div class="card stat">
    <div class="stat-num" style="color:{_risk_color(result.risk_score)}">{result.risk_score}</div>
    <div class="stat-label">Risk Score</div>
  </div>
  <div class="card stat">
    <div class="grade-badge" style="color:{_grade_color(grade_str)};border-color:{_grade_color(grade_str)}">{grade_str}</div>
    <div class="stat-label" style="margin-top:8px">Readiness Grade</div>
  </div>
  <div class="card stat">
    <div class="stat-num">{len(result.findings)}</div>
    <div class="stat-label">Findings</div>
  </div>
  <div class="card stat">
    <div class="stat-num">{result.files_scanned}</div>
    <div class="stat-label">Files Scanned</div>
  </div>
</div>

<div class="grid" style="grid-template-columns:1fr 1fr 1fr">
  <div class="card" style="text-align:center">
    <h2>Risk Gauge</h2>
    {gauge_svg}
  </div>
  <div class="card">
    <h2>Algorithm Distribution</h2>
    <div style="display:flex;align-items:center;gap:16px">
      {donut_svg}
      <div>{donut_legend}</div>
    </div>
  </div>
  <div class="card">
    <h2>Severity Breakdown</h2>
    {severity_bars}
  </div>
</div>

<div class="grid" style="grid-template-columns:1fr 1fr">
  <div class="card">
    <h2>CNSA 2.0 Deadlines</h2>
    {deadline_html if deadline_html else f'<div style="color:{COLORS["text_muted"]}">No deadline data available</div>'}
  </div>
  <div class="card">
    <h2>Recommendations</h2>
    {recs_html if recs_html else f'<div style="color:{COLORS["safe"]}">No quantum-vulnerable crypto detected!</div>'}
  </div>
</div>

{f"""<div class="card" style="margin:16px 0">
  <h2>Auto-Fix Suggestions</h2>
  {fix_html}
</div>""" if fix_html else ''}

<div class="card" style="margin:16px 0">
  <h2>All Findings</h2>
  <input type="text" class="search" id="findingSearch" placeholder="Search findings (algorithm, file, code...)">
  <div style="margin-bottom:10px">
    <button class="filter-btn active" onclick="filterSev('ALL')">All</button>
    <button class="filter-btn" onclick="filterSev('CRITICAL')">Critical</button>
    <button class="filter-btn" onclick="filterSev('HIGH')">High</button>
    <button class="filter-btn" onclick="filterSev('MEDIUM')">Medium</button>
    <button class="filter-btn" onclick="filterSev('LOW')">Low</button>
  </div>
  <table class="findings-table">
    <thead><tr><th>Severity</th><th>Algorithm</th><th>Code</th><th>Location</th><th>PQC Replacement</th></tr></thead>
    <tbody id="findingsBody">
{findings_rows}
    </tbody>
  </table>
</div>

<div style="text-align:center;padding:20px;color:{COLORS['text_muted']};font-size:12px">
  Generated by Enigma pqc-scanner v{__version__} | \u03A8 Quantum Shield | CONFIDENTIAL
</div>

</div>

<script>
const searchInput = document.getElementById('findingSearch');
const rows = document.querySelectorAll('.finding-row');
let activeSev = 'ALL';

searchInput.addEventListener('input', () => applyFilters());

function filterSev(sev) {{
  activeSev = sev;
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  event.target.classList.add('active');
  applyFilters();
}}

function applyFilters() {{
  const q = searchInput.value.toLowerCase();
  rows.forEach(row => {{
    const text = row.textContent.toLowerCase();
    const sev = row.dataset.severity;
    const matchSearch = !q || text.includes(q);
    const matchSev = activeSev === 'ALL' || sev === activeSev;
    row.style.display = (matchSearch && matchSev) ? '' : 'none';
  }});
}}
</script>
</body></html>'''


# ============================================================================
# TEAM DASHBOARD — Scan History, Trends, Multi-User Aggregation
# ============================================================================

@dataclass
class ScanHistoryEntry:
    """A single scan result stored for historical tracking."""
    scan_id: str
    scan_date: str              # ISO format
    scan_path: str
    scanner: str                # Who ran the scan (user/team member)
    risk_score: int
    grade: str
    total_findings: int
    critical: int
    high: int
    medium: int
    low: int
    info: int
    files_scanned: int
    algorithms: Dict[str, int]  # algorithm → count
    pqc_ready_pct: float        # 0.0 - 100.0

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> 'ScanHistoryEntry':
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})

    @classmethod
    def from_scan_result(cls, result: ScanResult, scanner: str = 'default',
                         grade: str = '?', pqc_ready_pct: float = 0.0) -> 'ScanHistoryEntry':
        """Create a history entry from a live ScanResult."""
        result.compute_summary()
        algo_dist: Dict[str, int] = {}
        for f in result.findings:
            algo_dist[f.algorithm] = algo_dist.get(f.algorithm, 0) + 1
        scan_id = hashlib.sha256(
            f"{result.scan_path}:{result.scan_date}:{scanner}".encode()
        ).hexdigest()[:12]
        return cls(
            scan_id=scan_id,
            scan_date=result.scan_date[:19],
            scan_path=result.scan_path,
            scanner=scanner,
            risk_score=result.risk_score,
            grade=grade,
            total_findings=len(result.findings),
            critical=result.summary.get('CRITICAL', 0),
            high=result.summary.get('HIGH', 0),
            medium=result.summary.get('MEDIUM', 0),
            low=result.summary.get('LOW', 0),
            info=result.summary.get('INFO', 0),
            files_scanned=result.files_scanned,
            algorithms=algo_dist,
            pqc_ready_pct=pqc_ready_pct,
        )


def save_scan_to_history(entry: ScanHistoryEntry,
                         history_path: str = '.enigma_history.json') -> None:
    """Append a scan result to the history file using atomic write."""
    history = load_scan_history(history_path)
    history.append(entry)
    # Atomic write: write to temp file then rename. Prevents corruption if
    # the process is killed mid-write, and prevents concurrent writers from
    # producing a half-written JSON file that wipes all history.
    import tempfile
    dir_name = os.path.dirname(os.path.abspath(history_path)) or '.'
    fd, tmp_path = tempfile.mkstemp(dir=dir_name, suffix='.enigma-hist-tmp')
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            json.dump([e.to_dict() for e in history], f, indent=2)
        os.replace(tmp_path, history_path)
    except OSError:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def load_scan_history(history_path: str = '.enigma_history.json') -> List[ScanHistoryEntry]:
    """Load scan history from JSON file.

    Skips individual malformed entries rather than wiping the whole history.
    """
    if not os.path.exists(history_path):
        return []
    try:
        with open(history_path, encoding='utf-8') as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError):
        return []
    if not isinstance(data, list):
        return []
    results: List[ScanHistoryEntry] = []
    for d in data:
        try:
            results.append(ScanHistoryEntry.from_dict(d))
        except (KeyError, TypeError, ValueError):
            continue  # skip malformed entry, keep the rest
    return results


def _svg_trend_line(entries: List[ScanHistoryEntry], width: int = 700,
                    height: int = 200) -> str:
    """Generate an SVG line chart of risk score over time."""
    if not entries:
        return f'<svg width="{width}" height="{height}"></svg>'

    pad_x, pad_y = 50, 30
    chart_w = width - pad_x * 2
    chart_h = height - pad_y * 2
    n = len(entries)

    # Scale points
    scores = [e.risk_score for e in entries]
    max_score = max(max(scores), 1)
    min_score = min(scores)
    score_range = max(max_score - min_score, 10)

    points = []
    for i, entry in enumerate(entries):
        x = pad_x + (i / max(n - 1, 1)) * chart_w
        y = pad_y + chart_h - ((entry.risk_score - min_score) / score_range) * chart_h
        points.append((x, y, entry))

    # Build SVG
    polyline_pts = ' '.join(f'{x:.1f},{y:.1f}' for x, y, _ in points)

    # Grid lines
    grid = ''
    for pct in (0, 0.25, 0.5, 0.75, 1.0):
        gy = pad_y + chart_h * (1 - pct)
        val = int(min_score + score_range * pct)
        grid += f'<line x1="{pad_x}" y1="{gy:.0f}" x2="{width - pad_x}" y2="{gy:.0f}" stroke="{COLORS["card_border"]}" stroke-dasharray="4"/>\n'
        grid += f'<text x="{pad_x - 8}" y="{gy + 4:.0f}" text-anchor="end" fill="{COLORS["text_muted"]}" font-size="11">{val}</text>\n'

    # Data points with tooltips — escape all history-sourced strings to prevent stored XSS.
    dots = ''
    for x, y, entry in points:
        color = _risk_color(entry.risk_score)
        short_date = html_mod.escape(entry.scan_date[:10])
        _grade_esc = html_mod.escape(str(entry.grade))
        dots += (f'<circle cx="{x:.1f}" cy="{y:.1f}" r="5" fill="{color}" stroke="{COLORS["bg"]}" stroke-width="2">'
                 f'<title>{short_date}: Risk {entry.risk_score} | {_grade_esc} | {entry.total_findings} findings</title></circle>\n')

    # Date labels (first, last, and middle if >4 entries)
    date_labels = ''
    label_indices = [0]
    if n > 2:
        label_indices.append(n // 2)
    if n > 1:
        label_indices.append(n - 1)
    for idx in label_indices:
        x = points[idx][0]
        date_str = html_mod.escape(str(entries[idx].scan_date)[:10])
        date_labels += f'<text x="{x:.0f}" y="{height - 5}" text-anchor="middle" fill="{COLORS["text_muted"]}" font-size="10">{date_str}</text>\n'

    return f'''<svg width="{width}" height="{height}" viewBox="0 0 {width} {height}">
  {grid}
  <polyline points="{polyline_pts}" fill="none" stroke="{COLORS['cyan']}" stroke-width="2.5" stroke-linejoin="round"/>
  {dots}
  {date_labels}
  <text x="{pad_x}" y="16" fill="{COLORS['text_muted']}" font-size="12">Risk Score Trend</text>
</svg>'''


def _svg_findings_trend(entries: List[ScanHistoryEntry], width: int = 700,
                         height: int = 200) -> str:
    """Generate stacked bar chart of severity distribution over time."""
    if not entries:
        return f'<svg width="{width}" height="{height}"></svg>'

    pad_x, pad_y = 50, 30
    chart_w = width - pad_x * 2
    chart_h = height - pad_y * 2
    n = len(entries)
    bar_w = max(8, min(40, chart_w // max(n, 1) - 4))

    max_findings = max((e.total_findings for e in entries), default=1) or 1
    sev_keys = [('critical', COLORS['critical']), ('high', COLORS['high']),
                ('medium', COLORS['medium']), ('low', COLORS['low'])]

    bars = ''
    for i, entry in enumerate(entries):
        x = pad_x + (i / max(n - 1, 1)) * chart_w - bar_w / 2 if n > 1 else pad_x + chart_w / 2 - bar_w / 2
        y_offset = 0
        for key, color in sev_keys:
            count = getattr(entry, key, 0)
            bar_h = (count / max_findings) * chart_h
            y = pad_y + chart_h - y_offset - bar_h
            if bar_h > 0:
                bars += f'<rect x="{x:.1f}" y="{y:.1f}" width="{bar_w}" height="{bar_h:.1f}" fill="{color}" opacity="0.85" rx="2"><title>{key.upper()}: {count}</title></rect>\n'
            y_offset += bar_h

    # Legend
    legend = ''
    lx = width - pad_x - 200
    for j, (key, color) in enumerate(sev_keys):
        ly = pad_y + j * 18
        legend += f'<rect x="{lx}" y="{ly}" width="10" height="10" fill="{color}" rx="2"/>'
        legend += f'<text x="{lx + 14}" y="{ly + 9}" fill="{COLORS["text_muted"]}" font-size="11">{key.title()}</text>'

    return f'''<svg width="{width}" height="{height}" viewBox="0 0 {width} {height}">
  {bars}
  {legend}
  <text x="{pad_x}" y="16" fill="{COLORS['text_muted']}" font-size="12">Findings by Severity</text>
</svg>'''


def generate_team_dashboard(history: List[ScanHistoryEntry],
                            current_result: Optional[ScanResult] = None) -> str:
    """Generate a multi-scan team dashboard with trends and aggregation.

    Features:
      - Risk score trend line chart
      - Severity distribution trend (stacked bars)
      - Team activity table (who scanned what, when)
      - Project comparison (if multiple targets)
      - Latest vs previous delta view
    """
    if not history:
        return _empty_team_dashboard()

    # Sort by date — parse to datetime so lexicographic format mismatches don't corrupt order.
    def _parse_scan_date(entry):
        s = str(entry.scan_date)
        try:
            return datetime.fromisoformat(s[:19])
        except ValueError:
            return datetime.min
    history = sorted(history, key=_parse_scan_date)
    latest = history[-1]
    previous = history[-2] if len(history) > 1 else None

    # Per-scanner aggregation
    scanners: Dict[str, List[ScanHistoryEntry]] = {}
    for entry in history:
        scanners.setdefault(entry.scanner, []).append(entry)

    # Per-project aggregation
    projects: Dict[str, List[ScanHistoryEntry]] = {}
    for entry in history:
        proj = os.path.basename(entry.scan_path) or entry.scan_path
        projects.setdefault(proj, []).append(entry)

    # SVG charts
    trend_svg = _svg_trend_line(history)
    findings_svg = _svg_findings_trend(history)

    # Delta view (latest vs previous)
    delta_html = ''
    if previous:
        risk_delta = latest.risk_score - previous.risk_score
        findings_delta = latest.total_findings - previous.total_findings
        crit_delta = latest.critical - previous.critical
        risk_arrow = '&#9650;' if risk_delta > 0 else ('&#9660;' if risk_delta < 0 else '&#8212;')
        risk_color = COLORS['critical'] if risk_delta > 0 else (COLORS['safe'] if risk_delta < 0 else COLORS['text_muted'])
        delta_html = f'''
<div class="grid" style="grid-template-columns:repeat(4,1fr)">
  <div class="card stat">
    <div class="stat-num" style="color:{risk_color};font-size:28px">{risk_arrow} {abs(risk_delta)}</div>
    <div class="stat-label">Risk Delta</div>
  </div>
  <div class="card stat">
    <div class="stat-num" style="font-size:28px;color:{COLORS['cyan']}">{findings_delta:+d}</div>
    <div class="stat-label">Findings Delta</div>
  </div>
  <div class="card stat">
    <div class="stat-num" style="font-size:28px;color:{COLORS['critical'] if crit_delta > 0 else COLORS['safe']}">{crit_delta:+d}</div>
    <div class="stat-label">Critical Delta</div>
  </div>
  <div class="card stat">
    <div class="stat-num" style="font-size:28px;color:{_grade_color(latest.grade)}">{html_mod.escape(str(latest.grade))}</div>
    <div class="stat-label">Current Grade</div>
  </div>
</div>'''

    # Team activity table
    scanner_rows = ''
    for scanner, scans in sorted(scanners.items()):
        last_scan = scans[-1]
        total_scans = len(scans)
        avg_risk = sum(s.risk_score for s in scans) // total_scans
        total_findings = sum(s.total_findings for s in scans)
        scanner_rows += f'''<tr>
  <td style="color:{COLORS['gold']};font-weight:bold">{html_mod.escape(scanner)}</td>
  <td>{total_scans}</td>
  <td style="color:{_risk_color(avg_risk)}">{avg_risk}</td>
  <td>{total_findings}</td>
  <td style="color:{COLORS['text_muted']}">{html_mod.escape(str(last_scan.scan_date)[:10])}</td>
</tr>\n'''

    # Project comparison table
    project_rows = ''
    for proj_name, scans in sorted(projects.items()):
        last_scan = scans[-1]
        trend = ''
        if len(scans) > 1:
            diff = last_scan.risk_score - scans[-2].risk_score
            if diff > 0:
                trend = f'<span style="color:{COLORS["critical"]}">&#9650; +{diff}</span>'
            elif diff < 0:
                trend = f'<span style="color:{COLORS["safe"]}">&#9660; {diff}</span>'
            else:
                trend = f'<span style="color:{COLORS["text_muted"]}">&#8212;</span>'
        project_rows += f'''<tr>
  <td style="color:{COLORS['cyan']}">{html_mod.escape(proj_name)}</td>
  <td style="color:{_risk_color(last_scan.risk_score)};font-weight:bold">{last_scan.risk_score}</td>
  <td style="color:{_grade_color(last_scan.grade)};font-weight:bold">{html_mod.escape(str(last_scan.grade))}</td>
  <td>{last_scan.total_findings}</td>
  <td>{trend}</td>
  <td style="color:{COLORS['text_muted']};font-size:12px">{html_mod.escape(str(last_scan.scan_date)[:10])}</td>
</tr>\n'''

    # Scan history table (last 20)
    history_rows = ''
    for entry in reversed(history[-20:]):
        proj = os.path.basename(entry.scan_path) or entry.scan_path
        history_rows += f'''<tr>
  <td style="color:{COLORS['text_muted']};font-size:12px">{html_mod.escape(str(entry.scan_date)[:10])}</td>
  <td>{html_mod.escape(entry.scanner)}</td>
  <td style="color:{COLORS['cyan']}">{html_mod.escape(proj)}</td>
  <td style="color:{_risk_color(entry.risk_score)};font-weight:bold">{entry.risk_score}</td>
  <td style="color:{_grade_color(entry.grade)}">{html_mod.escape(str(entry.grade))}</td>
  <td>{entry.critical}</td>
  <td>{entry.high}</td>
  <td>{entry.medium}</td>
  <td>{entry.total_findings}</td>
</tr>\n'''

    return f'''<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>PQC Scanner — Team Dashboard</title>
<style>
* {{ margin:0; padding:0; box-sizing:border-box; }}
body {{ font-family:'Segoe UI',system-ui,-apple-system,sans-serif; background:{COLORS['bg']}; color:{COLORS['text']}; }}
.container {{ max-width:1400px; margin:0 auto; padding:20px; }}
.header {{ text-align:center; padding:30px 0 20px; }}
.header h1 {{ color:{COLORS['gold']}; font-size:28px; letter-spacing:2px; }}
.header .subtitle {{ color:{COLORS['text_muted']}; font-size:14px; margin-top:6px; }}
.grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(300px,1fr)); gap:16px; margin:20px 0; }}
.card {{ background:{COLORS['card']}; border:1px solid {COLORS['card_border']}; border-radius:12px; padding:20px; }}
.card h2 {{ color:{COLORS['cyan']}; font-size:15px; margin-bottom:14px; text-transform:uppercase; letter-spacing:1px; }}
.stat {{ text-align:center; }}
.stat-num {{ font-size:36px; font-weight:bold; color:{COLORS['purple']}; }}
.stat-label {{ font-size:12px; color:{COLORS['text_muted']}; margin-top:4px; }}
table {{ width:100%; border-collapse:collapse; }}
th {{ background:{COLORS['card_border']}; color:{COLORS['cyan']}; padding:10px 8px; text-align:left; font-size:12px; text-transform:uppercase; }}
td {{ padding:8px; border-bottom:1px solid {COLORS['card_border']}; font-size:13px; }}
tr:hover {{ background:rgba(126,184,218,0.05); }}
</style></head><body>
<div class="container">

<div class="header">
  <h1>\u03A8 TEAM DASHBOARD</h1>
  <div class="subtitle">Enigma PQC Scanner v{__version__} — Multi-Scan Aggregation</div>
  <div class="subtitle" style="margin-top:4px">{len(history)} scans | {len(scanners)} team members | {len(projects)} projects</div>
</div>

<div class="grid" style="grid-template-columns:repeat(4,1fr)">
  <div class="card stat">
    <div class="stat-num" style="color:{_risk_color(latest.risk_score)}">{latest.risk_score}</div>
    <div class="stat-label">Latest Risk Score</div>
  </div>
  <div class="card stat">
    <div class="stat-num" style="color:{_grade_color(latest.grade)}">{html_mod.escape(str(latest.grade))}</div>
    <div class="stat-label">Latest Grade</div>
  </div>
  <div class="card stat">
    <div class="stat-num">{len(history)}</div>
    <div class="stat-label">Total Scans</div>
  </div>
  <div class="card stat">
    <div class="stat-num" style="color:{COLORS['gold']}">{len(scanners)}</div>
    <div class="stat-label">Team Members</div>
  </div>
</div>

{delta_html}

<div class="grid" style="grid-template-columns:1fr 1fr">
  <div class="card">
    <h2>Risk Score Trend</h2>
    {trend_svg}
  </div>
  <div class="card">
    <h2>Findings Trend</h2>
    {findings_svg}
  </div>
</div>

<div class="grid" style="grid-template-columns:1fr 1fr">
  <div class="card">
    <h2>Team Activity</h2>
    <table>
      <thead><tr><th>Scanner</th><th>Scans</th><th>Avg Risk</th><th>Total Findings</th><th>Last Active</th></tr></thead>
      <tbody>{scanner_rows}</tbody>
    </table>
  </div>
  <div class="card">
    <h2>Project Comparison</h2>
    <table>
      <thead><tr><th>Project</th><th>Risk</th><th>Grade</th><th>Findings</th><th>Trend</th><th>Last Scan</th></tr></thead>
      <tbody>{project_rows}</tbody>
    </table>
  </div>
</div>

<div class="card" style="margin:16px 0">
  <h2>Scan History (Last 20)</h2>
  <table>
    <thead><tr><th>Date</th><th>Scanner</th><th>Project</th><th>Risk</th><th>Grade</th><th>Crit</th><th>High</th><th>Med</th><th>Total</th></tr></thead>
    <tbody>{history_rows}</tbody>
  </table>
</div>

<div style="text-align:center;padding:20px;color:{COLORS['text_muted']};font-size:12px">
  Generated by Enigma pqc-scanner v{__version__} | \u03A8 Team Dashboard | CONFIDENTIAL
</div>

</div></body></html>'''


def _empty_team_dashboard() -> str:
    """Return a minimal dashboard when no scan history exists."""
    return f'''<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"><title>PQC Scanner — Team Dashboard</title>
<style>body {{ font-family:sans-serif; background:{COLORS['bg']}; color:{COLORS['text']}; display:flex; align-items:center; justify-content:center; height:100vh; }}
.msg {{ text-align:center; }} h1 {{ color:{COLORS['gold']}; }} p {{ color:{COLORS['text_muted']}; }}</style></head>
<body><div class="msg"><h1>\u03A8 Team Dashboard</h1><p>No scan history yet. Run scans with <code>--save-history</code> to populate this view.</p></div></body></html>'''
