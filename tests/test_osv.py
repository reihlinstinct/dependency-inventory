from depinv.osv import cvss_score, fixed_versions, severity_of
from depinv.report import markdown


def test_cvss_critical_vector():
    assert cvss_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == 9.8


def test_cvss_none_impact():
    assert cvss_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N") == 0.0


def test_severity_labels():
    v = {"severity": [{"type": "CVSS_V3",
                       "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}
    score, label = severity_of(v)
    assert score == 9.8 and label == "CRITICAL"


def test_severity_fallback_database_specific():
    v = {"affected": [{"database_specific": {"severity": "HIGH"}}]}
    assert severity_of(v) == (None, "HIGH")


def test_fixed_versions_filtered_by_package():
    v = {"affected": [
        {"package": {"name": "a", "ecosystem": "PyPI"},
         "ranges": [{"events": [{"introduced": "0"}, {"fixed": "1.2.3"}]}]},
        {"package": {"name": "b", "ecosystem": "PyPI"},
         "ranges": [{"events": [{"introduced": "0"}, {"fixed": "9.9.9"}]}]},
    ]}
    assert fixed_versions(v, "PyPI", "a") == ["1.2.3"]


def test_markdown_empty_findings():
    md = markdown([], "t", 10, 5)
    assert "No known vulnerabilities" in md


def test_markdown_table_row():
    findings = [{"id": "GHSA-x", "aliases": ["CVE-2026-1"], "summary": "s",
                 "severity_score": 7.5, "severity": "HIGH", "ecosystem": "PyPI",
                 "package": "p", "version": "1.0", "fixed": ["1.1"],
                 "locations": [{"repo": "o/r", "file": "requirements.txt"}]}]
    md = markdown(findings, "t", 10, 5)
    assert "| HIGH (7.5) | `p` | 1.0 | GHSA-x | CVE-2026-1 | 1.1 | o/r |" in md
