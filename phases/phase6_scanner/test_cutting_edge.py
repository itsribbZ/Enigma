"""
Enigma pqc-scanner v4.0: Tests for cutting-edge features.
AI triage, SBOM enrichment, cross-file call graph analysis.
"""
import json
import os
import tempfile
import pytest
from pqc_scanner import Finding, Severity, Category


# ============================================================================
# AI TRIAGE (unit tests — no API calls)
# ============================================================================

class TestAITriage:
    def test_imports(self):
        from ai_triage import (
            triage_findings, format_triage_report, filter_false_positives,
            AITriageResult, _extract_context, _get_file_imports,
        )

    def test_extract_context(self):
        from ai_triage import _extract_context
        # Create a temp file with code
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write('import hashlib\n')
            f.write('def foo():\n')
            f.write('    h = hashlib.md5(data)\n')
            f.write('    return h\n')
            f.flush()
            finding = Finding('T1', Severity.HIGH, Category.HASH, 'MD5',
                              f.name, 3, 'hashlib.md5(data)', 'MD5', 'Upgrade', 'SHA-256')
            context = _extract_context(finding, context_lines=5)
        os.unlink(f.name)
        assert 'hashlib.md5' in context
        assert '>>>' in context  # Marker for the flagged line

    def test_extract_context_missing_file(self):
        from ai_triage import _extract_context
        finding = Finding('T1', Severity.HIGH, Category.HASH, 'MD5',
                          '/nonexistent/file.py', 3, 'hashlib.md5(data)',
                          'MD5', 'Upgrade', 'SHA-256')
        context = _extract_context(finding)
        assert context == 'hashlib.md5(data)'  # Falls back to code_snippet

    def test_get_file_imports(self):
        from ai_triage import _get_file_imports
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write('import hashlib\n')
            f.write('from cryptography.hazmat.primitives import hashes\n')
            f.write('import os\n')
            f.write('\ndef main():\n    pass\n')
            f.flush()
            finding = Finding('T1', Severity.HIGH, Category.HASH, 'MD5',
                              f.name, 5, 'pass', 'MD5', 'Upgrade', 'SHA-256')
            imports = _get_file_imports(finding)
        os.unlink(f.name)
        assert 'import hashlib' in imports
        assert 'from cryptography' in imports

    def test_filter_false_positives(self):
        from ai_triage import filter_false_positives, AITriageResult
        findings = [
            Finding('F1', Severity.HIGH, Category.HASH, 'MD5', 'a.py', 1, 'md5()', 'MD5', 'Up', 'SHA-256'),
            Finding('F2', Severity.CRITICAL, Category.KEY_EXCHANGE, 'RSA', 'b.py', 2, 'rsa.gen()', 'RSA', 'Up', 'ML-KEM'),
        ]
        triage_results = [
            AITriageResult('F1', True, 0.9, 'Test code', 'test', 'not_exploitable', None, '', 'skip'),
            AITriageResult('F2', False, 0.95, 'Production RSA', 'production', 'confirmed', None, '', 'immediate'),
        ]
        filtered = filter_false_positives(findings, triage_results)
        assert len(filtered) == 1
        assert filtered[0].id == 'F2'

    def test_filter_low_confidence_kept(self):
        from ai_triage import filter_false_positives, AITriageResult
        findings = [
            Finding('F1', Severity.HIGH, Category.HASH, 'MD5', 'a.py', 1, 'md5()', 'MD5', 'Up', 'SHA-256'),
        ]
        triage_results = [
            AITriageResult('F1', True, 0.5, 'Unsure', 'unknown', 'unlikely', None, '', 'skip'),
        ]
        # Low confidence (0.5 < 0.7) should NOT filter
        filtered = filter_false_positives(findings, triage_results)
        assert len(filtered) == 1

    def test_format_triage_report(self):
        from ai_triage import format_triage_report, AITriageResult
        results = [
            AITriageResult('F1', True, 0.9, 'Test code', 'test', 'not_exploitable', None, '', 'skip'),
            AITriageResult('F2', False, 0.95, 'Production', 'production', 'confirmed',
                           'from oqs import KeyEncapsulation', 'Replace RSA', 'immediate'),
        ]
        report = format_triage_report(results)
        assert 'AI TRIAGE REPORT' in report
        assert 'False positives:   1' in report
        assert 'MIGRATION CODE' in report

    def test_triage_requires_api_key(self):
        from ai_triage import triage_findings
        findings = [Finding('F1', Severity.HIGH, Category.HASH, 'MD5', 'a.py', 1,
                            'md5()', 'MD5', 'Up', 'SHA-256')]
        # Clear env var if set
        old_key = os.environ.pop('ANTHROPIC_API_KEY', None)
        try:
            with pytest.raises(ValueError, match='API key'):
                triage_findings(findings, api_key='')
        finally:
            if old_key:
                os.environ['ANTHROPIC_API_KEY'] = old_key


# ============================================================================
# SBOM ENRICHMENT
# ============================================================================

class TestSBOMEnrichment:
    @pytest.fixture
    def sample_sbom(self):
        sbom = {
            'bomFormat': 'CycloneDX',
            'specVersion': '1.5',
            'metadata': {},
            'components': [
                {'type': 'library', 'name': 'cryptography', 'version': '42.0.0'},
                {'type': 'library', 'name': 'requests', 'version': '2.31.0'},
                {'type': 'library', 'name': 'pyjwt', 'version': '2.8.0'},
                {'type': 'library', 'name': 'flask', 'version': '3.0.0'},
                {'type': 'library', 'name': 'paramiko', 'version': '3.4.0'},
            ]
        }
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(sbom, f)
            path = f.name
        yield path
        os.unlink(path)

    def test_enrichment_annotates_crypto_packages(self, sample_sbom):
        from sbom_enrichment import enrich_sbom
        enriched = enrich_sbom(sample_sbom)
        # cryptography, pyjwt, paramiko should be annotated
        annotated = []
        for comp in enriched['components']:
            props = {p['name']: p['value'] for p in comp.get('properties', [])}
            if 'enigma:pqc:status' in props:
                annotated.append(comp['name'])
        assert 'cryptography' in annotated
        assert 'pyjwt' in annotated
        assert 'paramiko' in annotated

    def test_enrichment_marks_quantum_vulnerable(self, sample_sbom):
        from sbom_enrichment import enrich_sbom
        enriched = enrich_sbom(sample_sbom)
        for comp in enriched['components']:
            if comp['name'] == 'cryptography':
                props = {p['name']: p['value'] for p in comp.get('properties', [])}
                assert props['enigma:pqc:status'] == 'quantum-vulnerable'
                assert 'RSA' in props.get('enigma:pqc:vulnerable_algorithms', '')

    def test_enrichment_skips_non_crypto(self, sample_sbom):
        from sbom_enrichment import enrich_sbom
        enriched = enrich_sbom(sample_sbom)
        for comp in enriched['components']:
            if comp['name'] in ('requests', 'flask'):
                props = [p for p in comp.get('properties', []) if 'enigma:pqc' in p.get('name', '')]
                assert len(props) == 0

    def test_enrichment_adds_tool_metadata(self, sample_sbom):
        from sbom_enrichment import enrich_sbom
        enriched = enrich_sbom(sample_sbom)
        tools = enriched.get('metadata', {}).get('tools', [])
        assert any('pqc-scanner' in str(t) for t in tools)

    def test_enrichment_writes_output(self, sample_sbom):
        from sbom_enrichment import enrich_sbom
        with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as f:
            output = f.name
        try:
            enrich_sbom(sample_sbom, output_path=output)
            assert os.path.exists(output)
            with open(output) as f:
                data = json.load(f)
            assert 'components' in data
        finally:
            os.unlink(output)

    def test_enrichment_report(self, sample_sbom):
        from sbom_enrichment import enrich_sbom, format_enrichment_report
        enriched = enrich_sbom(sample_sbom)
        report = format_enrichment_report(enriched)
        assert 'SBOM ENRICHMENT REPORT' in report
        assert 'Quantum-vulnerable' in report

    def test_invalid_sbom_raises(self):
        from sbom_enrichment import enrich_sbom
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump({'not': 'a_sbom'}, f)
            path = f.name
        try:
            with pytest.raises(ValueError, match='CycloneDX'):
                enrich_sbom(path)
        finally:
            os.unlink(path)


# ============================================================================
# CALL GRAPH ANALYSIS
# ============================================================================

class TestCallGraph:
    @pytest.fixture
    def crypto_project(self):
        """Create a multi-file Python project with crypto call chains."""
        tmpdir = tempfile.mkdtemp()
        # crypto_utils.py — contains the crypto calls
        with open(os.path.join(tmpdir, 'crypto_utils.py'), 'w') as f:
            f.write('from cryptography.hazmat.primitives.asymmetric import rsa\n\n')
            f.write('def generate_key():\n')
            f.write('    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n')
            f.write('    return key\n\n')
            f.write('def sign_data(data, key):\n')
            f.write('    import hashlib\n')
            f.write('    h = hashlib.md5(data)\n')
            f.write('    return h\n')

        # auth.py — calls crypto_utils
        with open(os.path.join(tmpdir, 'auth.py'), 'w') as f:
            f.write('from crypto_utils import generate_key, sign_data\n\n')
            f.write('def authenticate_user(user):\n')
            f.write('    key = generate_key()\n')
            f.write('    sig = sign_data(user.token, key)\n')
            f.write('    return sig\n')

        # main.py — entry point calling auth
        with open(os.path.join(tmpdir, 'main.py'), 'w') as f:
            f.write('from auth import authenticate_user\n\n')
            f.write('def handle_request(request):\n')
            f.write('    result = authenticate_user(request.user)\n')
            f.write('    return result\n\n')
            f.write('if __name__ == "__main__":\n')
            f.write('    handle_request(None)\n')

        yield tmpdir

        import shutil
        shutil.rmtree(tmpdir)

    def test_callgraph_finds_functions(self, crypto_project):
        from callgraph import analyze_callgraph
        result = analyze_callgraph(crypto_project)
        assert result.total_functions > 0
        assert result.total_edges > 0

    def test_callgraph_finds_crypto_sinks(self, crypto_project):
        from callgraph import analyze_callgraph
        result = analyze_callgraph(crypto_project)
        assert result.crypto_sinks > 0

    def test_callgraph_traces_chains(self, crypto_project):
        from callgraph import analyze_callgraph
        result = analyze_callgraph(crypto_project)
        # Should find chains from main/auth entry points to crypto calls
        assert len(result.confirmed_chains) > 0

    def test_callgraph_reports_algorithm(self, crypto_project):
        from callgraph import analyze_callgraph
        result = analyze_callgraph(crypto_project)
        algos = {chain.algorithm for chain in result.confirmed_chains}
        # Should detect RSA/ECDSA or MD5 somewhere in the chains
        assert len(algos) > 0

    def test_callgraph_analysis_time(self, crypto_project):
        from callgraph import analyze_callgraph
        result = analyze_callgraph(crypto_project)
        assert result.analysis_time_ms >= 0

    def test_callgraph_empty_directory(self):
        from callgraph import analyze_callgraph
        with tempfile.TemporaryDirectory() as tmpdir:
            result = analyze_callgraph(tmpdir)
        assert result.total_functions == 0
        assert result.confirmed_chains == []

    def test_callgraph_single_file(self):
        from callgraph import analyze_callgraph
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write('import hashlib\ndef foo():\n    hashlib.md5(b"test")\n')
            path = f.name
        try:
            result = analyze_callgraph(path)
            assert result.total_functions >= 1
        finally:
            os.unlink(path)

    def test_callgraph_report_format(self, crypto_project):
        from callgraph import analyze_callgraph, format_callgraph_report
        result = analyze_callgraph(crypto_project)
        report = format_callgraph_report(result)
        assert 'CALL GRAPH ANALYSIS' in report
        assert 'Functions analyzed' in report
