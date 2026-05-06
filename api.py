"""
ENIGMA v4.0 — Web API Server

REST API for the PQC Migration Scanner. Wraps all scanner features
into HTTP endpoints with automatic OpenAPI docs at /docs.

Usage:
    python api.py                     # Start on port 8000
    python api.py --port 9000         # Custom port
    python api.py --host 0.0.0.0      # Expose to network
"""

import os
import sys
import json
import tempfile
import shutil
from datetime import datetime
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException, Query, UploadFile, File, Depends, Security
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.security import APIKeyHeader
from pydantic import BaseModel, field_validator

# Add scanner modules to path
_base = os.path.dirname(os.path.abspath(__file__))
_scanner = os.path.join(_base, 'phases', 'phase6_scanner')
if _scanner not in sys.path:
    sys.path.insert(0, _scanner)

from pqc_scanner import (
    PQCScanner, ScanResult, format_text_report, format_json_report,
    format_html_report, format_sarif_report, __version__,
)
from ast_scanner import ast_scan_directory
from dependency_scanner import scan_dependencies
from compliance import analyze_compliance, compute_qars
from readiness import compute_readiness_grade
from autofix import generate_fixes, format_fix_report
from migration_estimator import estimate_migration, format_performance_table
from history import record_scan, get_history
from dashboard import generate_dashboard

app = FastAPI(
    title="Enigma PQC Scanner API",
    description="Post-Quantum Cryptography Migration Scanner — detect quantum-vulnerable crypto via REST API.",
    version=__version__,
)


# ============================================================================
# RATE LIMITING (in-memory, per API-key sliding window)
# ============================================================================
# Protects against DoS from synchronous scanning and unbounded AI API cost abuse.
# Defaults: 10 req/min per key for scan endpoints, 100 req/min for read endpoints.
import time as _time_mod
import threading as _threading
from collections import deque as _rl_deque

_RATE_LIMITS = {
    'scan': (10, 60),     # 10 req / 60 sec
    'estimate': (10, 60),
    'grade': (30, 60),
    'fix': (5, 60),
}
_rl_windows: dict = {}  # (endpoint, api_key) → deque of timestamps
_rl_lock = _threading.Lock()  # Thread safety for multi-worker deployments


def _rate_limit_check(endpoint: str, api_key: str) -> None:
    limit, window = _RATE_LIMITS.get(endpoint, (60, 60))
    key = (endpoint, api_key or 'anonymous')
    now = _time_mod.monotonic()
    with _rl_lock:
        q = _rl_windows.setdefault(key, _rl_deque())
        while q and q[0] < now - window:
            q.popleft()
        if len(q) >= limit:
            raise HTTPException(
                status_code=429,
                detail=f"Rate limit exceeded: {limit} requests per {window}s for {endpoint}",
            )
        q.append(now)


# ============================================================================
# AUTHENTICATION
# ============================================================================

_API_KEY = os.environ.get('ENIGMA_API_KEY', '')
_ALLOWED_ROOT = os.environ.get('ENIGMA_ALLOWED_ROOT', '')
_api_key_header = APIKeyHeader(name='X-API-Key', auto_error=False)


async def verify_api_key(api_key: Optional[str] = Security(_api_key_header)) -> str:
    """Verify API key. FAIL-CLOSED: if ENIGMA_API_KEY is not set, server refuses requests."""
    if not _API_KEY:
        raise HTTPException(
            status_code=503,
            detail="Server not configured: ENIGMA_API_KEY environment variable not set",
        )
    if api_key != _API_KEY:
        raise HTTPException(status_code=403, detail="Invalid or missing API key")
    return api_key or ''


def _auth_and_rate_limit(endpoint: str):
    """Factory producing an auth+rate-limit dependency for a given endpoint bucket."""
    async def _dep(api_key: str = Depends(verify_api_key)) -> str:
        _rate_limit_check(endpoint, api_key)
        return api_key
    return _dep


def _validate_scan_path(path: str) -> str:
    """Validate and resolve a scan path. Prevents path traversal."""
    resolved = os.path.abspath(path)
    if not os.path.exists(resolved):
        raise HTTPException(status_code=404, detail=f"Path not found: {path}")
    if _ALLOWED_ROOT:
        allowed = os.path.abspath(_ALLOWED_ROOT)
        if not resolved.startswith(allowed + os.sep) and resolved != allowed:
            raise HTTPException(status_code=403, detail="Path outside allowed root")
    return resolved


# ============================================================================
# MODELS
# ============================================================================

class ScanRequest(BaseModel):
    path: str
    severity: str = "low"
    include_ast: bool = True
    include_deps: bool = True
    sensitivity: str = "internal"
    exposure: str = "internet"

    @field_validator('path')
    @classmethod
    def path_must_be_absolute_or_relative(cls, v: str) -> str:
        if not v or v.strip() == '':
            raise ValueError('Path cannot be empty')
        return v


class GradeRequest(BaseModel):
    path: str
    sensitivity: str = "internal"
    exposure: str = "internet"

    @field_validator('path')
    @classmethod
    def path_must_be_absolute_or_relative(cls, v: str) -> str:
        if not v or v.strip() == '':
            raise ValueError('Path cannot be empty')
        return v


class FixRequest(BaseModel):
    path: str
    apply_tier1: bool = False

    @field_validator('path')
    @classmethod
    def path_must_be_absolute_or_relative(cls, v: str) -> str:
        if not v or v.strip() == '':
            raise ValueError('Path cannot be empty')
        return v


# ============================================================================
# ENDPOINTS
# ============================================================================

@app.get("/health")
def health():
    """Health check."""
    return {
        "status": "ok",
        "version": __version__,
        "scanner": "Enigma PQC Scanner",
        "timestamp": datetime.utcnow().isoformat(),
    }


@app.post("/scan", dependencies=[Depends(_auth_and_rate_limit('scan'))])
def scan(req: ScanRequest):
    """Scan a directory for quantum-vulnerable cryptography."""
    scan_path = _validate_scan_path(req.path)

    scanner = PQCScanner()
    result = scanner.scan(scan_path)

    if req.include_ast and os.path.isdir(scan_path):
        ast_findings = ast_scan_directory(scan_path)
        existing = {(f.file, f.line, f.algorithm) for f in result.findings}
        for af in ast_findings:
            if (af.file, af.line, af.algorithm) not in existing:
                result.findings.append(af)
        result.compute_summary()

    grade = compute_readiness_grade(result, req.sensitivity, req.exposure)

    deps = []
    if req.include_deps and os.path.isdir(scan_path):
        deps = scan_dependencies(scan_path)

    compliance = analyze_compliance(result)
    fixes = generate_fixes(result.findings, scan_path) if result.findings else []
    migration = estimate_migration(result) if result.findings else None

    # Strip server absolute paths — return user-supplied path, not resolved server path.
    from pqc_scanner import _safe_relpath
    def _strip_path(f):
        f_dict = f.to_dict() if hasattr(f, 'to_dict') else f.__dict__.copy()
        f_dict['file'] = _safe_relpath(f_dict.get('file', ''), scan_path)
        return f_dict

    return {
        "scan_path": req.path,
        "scan_date": result.scan_date,
        "files_scanned": result.files_scanned,
        "findings_count": len(result.findings),
        "findings": [f.to_dict() for f in result.findings],
        "summary": result.summary,
        "risk_score": result.risk_score,
        "grade": {
            "grade": grade.grade,
            "score": grade.score,
            "algorithm_score": grade.algorithm_score,
            "key_management_score": grade.key_management_score,
            "compliance_score": grade.compliance_score,
            "summary": grade.summary,
            "recommendations": grade.recommendations,
        },
        "compliance": {
            fw_name: [
                {"algorithm": getattr(f, 'algorithm', ''), "status": getattr(f, 'status', ''),
                 "deadline": str(getattr(f, 'deadline', '')), "replacement": getattr(f, 'replacement', ''),
                 "notes": getattr(f, 'notes', ''), "finding_count": getattr(f, 'finding_count', 0)}
                for f in findings_list
            ]
            for fw_name, findings_list in (compliance.items() if isinstance(compliance, dict) else [])
        },
        "fixes_available": len(fixes),
        "fixes_tier1": sum(1 for f in fixes if f.tier == 1),
        "migration_estimate": migration,
        "dependencies_scanned": len(deps),
    }


@app.post("/scan/text", dependencies=[Depends(_auth_and_rate_limit('scan'))])
def scan_text(req: ScanRequest):
    """Scan and return plain text report."""
    scan_path = _validate_scan_path(req.path)
    scanner = PQCScanner()
    result = scanner.scan(scan_path)
    result.compute_summary()
    return {"report": format_text_report(result)}


@app.post("/scan/sarif", dependencies=[Depends(_auth_and_rate_limit('scan'))])
def scan_sarif(req: ScanRequest):
    """Scan and return SARIF 2.1.0 output for CI/CD integration."""
    scan_path = _validate_scan_path(req.path)
    scanner = PQCScanner()
    result = scanner.scan(scan_path)
    result.compute_summary()
    sarif = format_sarif_report(result)
    return JSONResponse(content=json.loads(sarif))


@app.post("/grade", dependencies=[Depends(_auth_and_rate_limit('grade'))])
def grade(req: GradeRequest):
    """Get PQC readiness grade (A+ through F)."""
    scan_path = _validate_scan_path(req.path)
    scanner = PQCScanner()
    result = scanner.scan(scan_path)
    result.compute_summary()
    g = compute_readiness_grade(result, req.sensitivity, req.exposure)

    return {
        "grade": g.grade,
        "score": g.score,
        "algorithm_score": g.algorithm_score,
        "key_management_score": g.key_management_score,
        "compliance_score": g.compliance_score,
        "summary": g.summary,
        "recommendations": g.recommendations,
        "details": g.details,
    }


@app.post("/fix", dependencies=[Depends(_auth_and_rate_limit('fix'))])
def fix(req: FixRequest):
    """Generate auto-fix suggestions. Optionally apply Tier 1 fixes."""
    scan_path = _validate_scan_path(req.path)
    scanner = PQCScanner()
    result = scanner.scan(scan_path)
    result.compute_summary()

    fixes = generate_fixes(result.findings, scan_path)

    response = {
        "total_suggestions": len(fixes),
        "tier1": sum(1 for f in fixes if f.tier == 1),
        "tier2": sum(1 for f in fixes if f.tier == 2),
        "tier3": sum(1 for f in fixes if f.tier == 3),
        "suggestions": [f.to_dict() for f in fixes],
        "applied": 0,
    }

    if req.apply_tier1:
        if not _ALLOWED_ROOT:
            raise HTTPException(
                status_code=400,
                detail="apply_tier1 requires ENIGMA_ALLOWED_ROOT environment variable to be set "
                       "(restricts where auto-fixes may write to disk).",
            )
        from autofix import apply_tier1_fixes
        tier1 = [f for f in fixes if f.tier == 1]
        response["applied"] = apply_tier1_fixes(tier1)

    return response


@app.post("/estimate", dependencies=[Depends(_auth_and_rate_limit('estimate'))])
def estimate(path: str = Query(...)):
    """Get migration effort and cost estimate."""
    scan_path = _validate_scan_path(path)
    scanner = PQCScanner()
    result = scanner.scan(scan_path)
    result.compute_summary()

    return estimate_migration(result)


@app.get("/performance", dependencies=[Depends(verify_api_key)])
def performance():
    """PQC vs classical performance comparison table."""
    from migration_estimator import PQC_PERFORMANCE
    return {
        "comparison": PQC_PERFORMANCE,
        "text_table": format_performance_table(),
    }


@app.get("/dashboard", response_class=HTMLResponse, dependencies=[Depends(verify_api_key)])
def dashboard(path: str = Query(...)):
    """Interactive HTML dashboard for a scan."""
    scan_path = _validate_scan_path(path)
    scanner = PQCScanner()
    result = scanner.scan(scan_path)
    result.compute_summary()
    return generate_dashboard(result)


@app.get("/history", dependencies=[Depends(verify_api_key)])
def history_endpoint(project: Optional[str] = None, limit: int = Query(default=20, ge=1, le=1000)):
    """Get scan history."""
    return get_history(project_name=project, limit=limit)


# ============================================================================
# ENTRY POINT
# ============================================================================

if __name__ == '__main__':
    import argparse
    import uvicorn

    parser = argparse.ArgumentParser(description='Enigma PQC Scanner API')
    parser.add_argument('--host', default='127.0.0.1')
    parser.add_argument('--port', type=int, default=8000)
    args = parser.parse_args()

    print(f"\n  ENIGMA v{__version__} — PQC Scanner API")
    print(f"  Docs:   http://{args.host}:{args.port}/docs")
    print(f"  Health: http://{args.host}:{args.port}/health\n")

    uvicorn.run(app, host=args.host, port=args.port)
