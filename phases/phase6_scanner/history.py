"""
Enigma pqc-scanner v4.0: Historical Scan Tracking.

Stores scan results over time in a local SQLite database.
Shows trends: risk score, finding count, grade changes.
Enables scan-over-scan comparison without --baseline.
Supports multi-project, multi-user tracking with export capability.

Database location: ~/.pqc-scanner/history.db (SQLite)
Legacy: migrates from ~/.pqc-scanner/history.json on first use.
"""

from __future__ import annotations
import json
import os
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from pqc_scanner import ScanResult


# ============================================================================
# DATABASE
# ============================================================================

_DB_SCHEMA_VERSION = 2

def _db_path() -> Path:
    """Get the history database path."""
    db_dir = Path.home() / '.pqc-scanner'
    db_dir.mkdir(exist_ok=True)
    return db_dir / 'history.db'


def _legacy_json_path() -> Path:
    """Legacy JSON database path for migration."""
    return Path.home() / '.pqc-scanner' / 'history.json'


def _get_connection() -> sqlite3.Connection:
    """Get a SQLite connection, creating schema if needed."""
    path = _db_path()
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA journal_mode=WAL')
    conn.execute('PRAGMA foreign_keys=ON')

    # Create schema if needed
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            project TEXT NOT NULL,
            scan_path TEXT,
            files_scanned INTEGER DEFAULT 0,
            total_findings INTEGER DEFAULT 0,
            risk_score REAL DEFAULT 0.0,
            grade TEXT DEFAULT '?',
            qars_score REAL DEFAULT 0.0,
            summary TEXT,
            algorithms TEXT,
            created_at TEXT DEFAULT (datetime('now'))
        );

        CREATE INDEX IF NOT EXISTS idx_scans_project
            ON scans(project);
        CREATE INDEX IF NOT EXISTS idx_scans_timestamp
            ON scans(timestamp);

        CREATE TABLE IF NOT EXISTS schema_version (
            version INTEGER PRIMARY KEY
        );
    """)

    # Check schema version
    row = conn.execute('SELECT MAX(version) FROM schema_version').fetchone()
    current_version = row[0] if row[0] else 0
    if current_version < _DB_SCHEMA_VERSION:
        conn.execute(
            'INSERT OR REPLACE INTO schema_version (version) VALUES (?)',
            (_DB_SCHEMA_VERSION,)
        )
        conn.commit()

    # Migrate legacy JSON if exists and DB is empty
    _migrate_legacy_json(conn)

    return conn


def _migrate_legacy_json(conn: sqlite3.Connection):
    """Migrate data from legacy history.json to SQLite."""
    json_path = _legacy_json_path()
    if not json_path.exists():
        return

    # Check if we already have data
    count = conn.execute('SELECT COUNT(*) FROM scans').fetchone()[0]
    if count > 0:
        return  # Already migrated

    try:
        with open(json_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        scans = data.get('scans', [])
        for s in scans:
            conn.execute("""
                INSERT INTO scans (timestamp, project, scan_path, files_scanned,
                    total_findings, risk_score, grade, qars_score, summary, algorithms)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                s.get('timestamp', ''),
                s.get('project', 'unknown'),
                s.get('scan_path', ''),
                s.get('files_scanned', 0),
                s.get('total_findings', 0),
                s.get('risk_score', 0.0),
                s.get('grade', '?'),
                s.get('qars_score', 0.0),
                json.dumps(s.get('summary', {})),
                json.dumps(s.get('algorithms', [])),
            ))
        conn.commit()
        # Rename legacy file to mark as migrated
        json_path.rename(json_path.with_suffix('.json.migrated'))
    except (json.JSONDecodeError, OSError, KeyError):
        pass


# ============================================================================
# RECORDING
# ============================================================================

def record_scan(result: ScanResult,
                grade: str = '?',
                qars_score: float = 0.0,
                project_name: Optional[str] = None) -> dict:
    """Record a scan result to the history database.

    Returns the recorded entry as a dict.
    """
    result.compute_summary()
    entry = {
        'timestamp': datetime.now().isoformat(),
        'project': project_name or os.path.basename(result.scan_path),
        'scan_path': result.scan_path,
        'files_scanned': result.files_scanned,
        'total_findings': len(result.findings),
        'risk_score': result.risk_score,
        'grade': grade,
        'qars_score': qars_score,
        'summary': result.summary,
        'algorithms': list(set(f.algorithm for f in result.findings)),
    }

    conn = None
    try:
        conn = _get_connection()
        conn.execute("""
            INSERT INTO scans (timestamp, project, scan_path, files_scanned,
                total_findings, risk_score, grade, qars_score, summary, algorithms)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            entry['timestamp'],
            entry['project'],
            entry['scan_path'],
            entry['files_scanned'],
            entry['total_findings'],
            entry['risk_score'],
            entry['grade'],
            entry['qars_score'],
            json.dumps(entry['summary']),
            json.dumps(entry['algorithms']),
        ))

        # Keep last 1000 scans per project — portable SQL (no LIMIT -1)
        conn.execute("""
            DELETE FROM scans WHERE project = ?
            AND id NOT IN (
                SELECT id FROM scans WHERE project = ?
                ORDER BY timestamp DESC LIMIT 1000
            )
        """, (entry['project'], entry['project']))

        conn.commit()
    finally:
        if conn:
            conn.close()

    return entry


# ============================================================================
# QUERYING
# ============================================================================

def get_history(project_name: Optional[str] = None,
                limit: int = 20) -> List[dict]:
    """Get scan history for a project (or all projects)."""
    conn = None
    try:
        conn = _get_connection()
        if project_name:
            rows = conn.execute(
                'SELECT * FROM scans WHERE project = ? ORDER BY timestamp DESC LIMIT ?',
                (project_name, limit)
            ).fetchall()
        else:
            rows = conn.execute(
                'SELECT * FROM scans ORDER BY timestamp DESC LIMIT ?',
                (limit,)
            ).fetchall()

        results = []
        for row in reversed(rows):  # Return chronological order
            entry = dict(row)
            # Parse JSON fields
            for field in ('summary', 'algorithms'):
                if isinstance(entry.get(field), str):
                    try:
                        entry[field] = json.loads(entry[field])
                    except (json.JSONDecodeError, TypeError):
                        pass
            results.append(entry)
        return results
    finally:
        if conn:
            conn.close()


def get_projects() -> List[dict]:
    """Get all projects with their latest scan info."""
    conn = None
    try:
        conn = _get_connection()
        rows = conn.execute("""
            SELECT project,
                   COUNT(*) as scan_count,
                   MAX(timestamp) as last_scan,
                   MIN(timestamp) as first_scan
            FROM scans
            GROUP BY project
            ORDER BY last_scan DESC
        """).fetchall()
        return [dict(row) for row in rows]
    finally:
        if conn:
            conn.close()


def get_trend(project_name: Optional[str] = None,
              limit: int = 10) -> dict:
    """Compute trend data for a project.

    Returns: direction (improving/declining/stable), delta, sparkline data.
    """
    history = get_history(project_name, limit)
    if len(history) < 2:
        return {
            'direction': 'unknown',
            'scans': len(history),
            'delta_risk': 0,
            'delta_findings': 0,
            'sparkline': [],
        }

    first = history[0]
    last = history[-1]

    delta_risk = last['risk_score'] - first['risk_score']
    delta_findings = last['total_findings'] - first['total_findings']

    if delta_risk < -5:
        direction = 'improving'
    elif delta_risk > 5:
        direction = 'declining'
    else:
        direction = 'stable'

    sparkline = [s['risk_score'] for s in history]

    return {
        'direction': direction,
        'scans': len(history),
        'delta_risk': delta_risk,
        'delta_findings': delta_findings,
        'delta_grade': f"{first.get('grade', '?')} -> {last.get('grade', '?')}",
        'sparkline': sparkline,
        'first_scan': first['timestamp'][:10],
        'last_scan': last['timestamp'][:10],
    }


def export_csv(project_name: Optional[str] = None,
               output_path: Optional[str] = None) -> str:
    """Export scan history to CSV for team sharing or BI tools.

    Returns the CSV content as a string. If output_path is given, also writes to file.
    """
    import csv
    import io

    history = get_history(project_name, limit=10000)
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        'timestamp', 'project', 'files_scanned', 'total_findings',
        'risk_score', 'grade', 'qars_score', 'algorithms'
    ])
    for entry in history:
        algos = entry.get('algorithms', [])
        if isinstance(algos, list):
            algos = ';'.join(algos)
        writer.writerow([
            entry.get('timestamp', ''),
            entry.get('project', ''),
            entry.get('files_scanned', 0),
            entry.get('total_findings', 0),
            entry.get('risk_score', 0),
            entry.get('grade', '?'),
            entry.get('qars_score', 0),
            algos,
        ])

    csv_content = output.getvalue()
    if output_path:
        Path(output_path).write_text(csv_content, encoding='utf-8')
    return csv_content


# ============================================================================
# DISPLAY
# ============================================================================

def _text_sparkline(values: List[float], width: int = 20) -> str:
    """Generate a text-based sparkline from values."""
    if not values:
        return ''
    chars = ' _.-~*=#'
    mn, mx = min(values), max(values)
    rng = max(mx - mn, 1)

    # Resample to width
    if len(values) > width:
        step = len(values) / width
        values = [values[int(i * step)] for i in range(width)]

    return ''.join(chars[min(len(chars) - 1, int((v - mn) / rng * (len(chars) - 1)))]
                   for v in values)


def format_history_report(project_name: Optional[str] = None) -> str:
    """Format history as text report with trend and sparkline."""
    history = get_history(project_name, 20)
    trend = get_trend(project_name)

    if not history:
        return "No scan history found. Run a scan to start tracking."

    lines = [
        "=" * 70,
        "  SCAN HISTORY -- Trend Tracking",
        "=" * 70,
        "",
        f"  Project: {history[-1].get('project', 'unknown')}",
        f"  Scans:   {trend['scans']} recorded",
        f"  Period:  {trend.get('first_scan', '?')} -> {trend.get('last_scan', '?')}",
        f"  Storage: SQLite ({_db_path()})",
        "",
    ]

    # Trend indicator
    direction = trend['direction']
    if direction == 'improving':
        icon = 'v IMPROVING'
        color_hint = '(risk decreasing)'
    elif direction == 'declining':
        icon = '^ DECLINING'
        color_hint = '(risk increasing)'
    else:
        icon = '= STABLE'
        color_hint = ''

    lines.extend([
        f"  Trend: {icon} {color_hint}",
        f"  Risk:     {trend['delta_risk']:+.1f} points",
        f"  Findings: {trend['delta_findings']:+d}",
        f"  Grade:    {trend.get('delta_grade', '?')}",
        "",
    ])

    # Sparkline
    if trend['sparkline']:
        spark = _text_sparkline(trend['sparkline'])
        lines.append(f"  Risk trend: [{spark}] {trend['sparkline'][-1]:.0f}/100")
        lines.append("")

    # Recent scans table
    lines.append("  Recent Scans:")
    lines.append(f"  {'Date':<12} {'Grade':>5} {'Risk':>5} {'Findings':>9} {'Files':>6}")
    lines.append("  " + "-" * 45)

    for scan in history[-10:]:
        date_str = scan['timestamp'][:10]
        grade = scan.get('grade', '?')
        risk = scan.get('risk_score', 0)
        findings = scan.get('total_findings', 0)
        files = scan.get('files_scanned', 0)
        lines.append(f"  {date_str:<12} {grade:>5} {risk:>5.0f} {findings:>9} {files:>6}")

    lines.extend(["", "=" * 70])
    return "\n".join(lines)
