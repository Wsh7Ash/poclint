"""Tests for poclint: CVSS handling, calibration rules and CLI exit codes."""

import json

from click.testing import CliRunner

from poclint.cli import main
from poclint.linter import (
    cvss_base,
    lint_report,
    parse_vector,
    severity_band,
    split_levels,
)

VECTOR_98 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
VECTOR_53 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
VECTOR_00 = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N"


def good_report(**over):
    report = {
        "title": "IDOR on GET /api/orders/{id}",
        "description": "Any authenticated user can read another user's order by "
                       "changing the id path parameter.",
        "poc": "1. Log in as user A and capture the order id\n"
               "2. Log in as user B\n"
               "3. Replay GET /api/orders/<A's id> with B's cookie\n"
               "```curl\n$ curl -H 'Cookie: sid=B' https://app/api/orders/42\n```",
        "impact": "Read access to other customers' orders, including addresses.",
        "remediation": "Enforce object-level authorization on every order lookup.",
        "severity": "MEDIUM",
        "cvss_vector": VECTOR_53,
        "cvss_base": 5.3,
        "scope": "app.example.test",
        "timeline": "reported 2026-10-25, fixed 2026-10-25",
        "references": "https://owasp.org/www-community/attacks/Insecure_Direct_Object_Reference",
    }
    report.update(over)
    return report


# ------------------------------------------------------------- structure

def test_missing_sections():
    issues = lint_report({})
    assert any("missing section: title" in i for i in issues)
    assert any("missing section: poc" in i for i in issues)
    errors, _ = split_levels(issues)
    assert errors, "missing required sections must be errors"


def test_clean_report_has_no_errors():
    errors, warnings = split_levels(lint_report(good_report()))
    assert errors == []
    assert warnings == []


def test_severity_mismatch():
    # base 9.8 (CRITICAL) contradicts a LOW claim
    r = good_report(severity="LOW", cvss_vector=VECTOR_98, cvss_base=9.8)
    issues = lint_report(r)
    assert any("inconsistent" in i for i in issues)
    assert any(i.startswith("error:") for i in issues)


def test_severity_vocabulary():
    r = good_report(severity="SEVERE")
    issues = lint_report(r)
    assert any("not one of" in i for i in issues)


def test_exaggerated_claim_flagged():
    r = good_report(remediation="This fix is guaranteed to stop the attack.")
    issues = lint_report(r)
    assert any("exaggerated claim" in i for i in issues)


def test_thin_poc_flagged():
    r = good_report(poc="just try it")
    issues = lint_report(r)
    assert any("reproducible" in i for i in issues)


def test_optional_sections_warn_when_absent():
    r = good_report()
    for key in ("scope", "timeline", "references"):
        r.pop(key)
    _, warnings = split_levels(lint_report(r))
    assert any("scope" in w for w in warnings)


# ------------------------------------------------------------------ CVSS

def test_parse_vector_ok():
    metrics, errors = parse_vector(VECTOR_98)
    assert errors == []
    assert metrics["AV"] == "N" and metrics["S"] == "U"


def test_parse_vector_errors():
    _, errors = parse_vector("AV:N/AC:L")
    assert any("CVSS:3.1" in e for e in errors)
    _, errors = parse_vector("CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    assert any("invalid value" in e for e in errors)
    metrics, errors = parse_vector("CVSS:3.1/AV:N/AC:L")
    assert metrics is None
    assert any("missing base metric" in e for e in errors)


def test_recomputed_base_scores():
    assert cvss_base(parse_vector(VECTOR_98)[0]) == 9.8
    assert cvss_base(parse_vector(VECTOR_53)[0]) == 5.3
    assert cvss_base(parse_vector(VECTOR_00)[0]) == 0.0


def test_score_vector_mismatch_is_error():
    r = good_report(cvss_base=9.8)  # vector implies 5.3
    issues = lint_report(r)
    assert any("does not match vector" in i for i in issues)


def test_severity_bands():
    assert severity_band(0.0) == "NONE"
    assert severity_band(2.0) == "LOW"
    assert severity_band(5.3) == "MEDIUM"
    assert severity_band(7.5) == "HIGH"
    assert severity_band(9.8) == "CRITICAL"


# ------------------------------------------------------------------- CLI

def test_cli_clean_report_exits_0(tmp_path):
    path = tmp_path / "report.json"
    path.write_text(json.dumps(good_report()), encoding="utf-8")
    res = CliRunner().invoke(main, ["lint", str(path)])
    assert res.exit_code == 0, res.output


def test_cli_errors_exit_1(tmp_path):
    path = tmp_path / "report.json"
    path.write_text(json.dumps({"title": "t"}), encoding="utf-8")
    res = CliRunner().invoke(main, ["lint", str(path)])
    assert res.exit_code == 1, res.output


def test_cli_strict_promotes_warnings(tmp_path):
    r = good_report()
    r.pop("scope")
    path = tmp_path / "report.json"
    path.write_text(json.dumps(r), encoding="utf-8")
    res = CliRunner().invoke(main, ["lint", str(path)])
    assert res.exit_code == 0, res.output
    res = CliRunner().invoke(main, ["lint", str(path), "--strict"])
    assert res.exit_code == 1, res.output


def test_cli_json_out(tmp_path):
    path = tmp_path / "report.json"
    path.write_text(json.dumps({"title": "t"}), encoding="utf-8")
    res = CliRunner().invoke(main, ["lint", str(path), "--json-out"])
    payload = json.loads(res.output)
    assert payload["ok"] is False
    assert payload["errors"]
    assert res.exit_code == 1


def test_cli_invalid_json_exits_2(tmp_path):
    path = tmp_path / "report.json"
    path.write_text("{not json", encoding="utf-8")
    res = CliRunner().invoke(main, ["lint", str(path)])
    assert res.exit_code == 2


def test_cli_missing_file_exits_2():
    res = CliRunner().invoke(main, ["lint", "no-such-file.json"])
    assert res.exit_code == 2
