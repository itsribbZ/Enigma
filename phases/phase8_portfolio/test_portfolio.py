"""
Enigma Phase 8: Portfolio test suite.
Validates portfolio generation, stats accuracy, and completeness.
"""
import pytest
from portfolio import (
    collect_project_stats, generate_competency_map,
    certification_assessment, go_to_market,
    generate_portfolio_report,
)


def test_project_stats():
    stats = collect_project_stats()
    assert stats['phases_complete'] == 8
    assert stats['total_source_loc'] > 4000
    assert stats['total_tests_passed'] == stats['total_tests']
    assert stats['total_tests'] >= 100

    for p in stats['phases']:
        assert p.status == 'COMPLETE'
        assert p.tests_passed == p.tests_total


def test_competency_map():
    cmap = generate_competency_map()
    for domain in ['Cryptographic Engineering', 'Quantum Computing',
                   'Post-Quantum Cryptography', 'Security Tooling',
                   'Quantum Networking', 'Cryptanalysis']:
        assert domain in cmap
    assert 'Enterprise Value' in cmap


def test_certification_assessment():
    assessment = certification_assessment()
    for cert in ['CompTIA Security+', 'ISC2 CC', 'IBM Quantum', 'CISSP', 'ISARA']:
        assert cert in assessment
    assert 'Readiness' in assessment


def test_go_to_market():
    gtm = go_to_market()
    for opt in ['CONSULTING', 'PRODUCT', 'EMPLOYMENT', 'HYBRID']:
        assert opt in gtm
    assert 'pqc-scanner' in gtm
    assert '$' in gtm


def test_full_portfolio():
    report = generate_portfolio_report()
    for section in ['ENIGMA', 'QUANTUM SECURITY EXPERT', 'PHASE BREAKDOWN',
                    'COMPETENCY MAP', 'CERTIFICATION', 'GO-TO-MARKET']:
        assert section in report
    assert 'pqc-scanner' in report


def test_portfolio_accuracy():
    stats = collect_project_stats()
    assert any('22' in d for d in stats['phases'][0].key_deliverables)
    assert any('pqc-scanner' in d for d in stats['phases'][5].key_deliverables)
    p7_deliverables = ' '.join(stats['phases'][6].key_deliverables)
    assert 'BB84' in p7_deliverables
    assert 'E91' in p7_deliverables
