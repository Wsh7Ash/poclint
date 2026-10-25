"""Draft bug-bounty report linter.

Checks a draft finding JSON for structural completeness, CVSS:3.1 vector
sanity (the base score is recomputed from the vector and compared with the
claimed score), severity calibration, reproducibility of the PoC and
over-claiming language.

Every check returns a plain string prefixed with a level:

    ``error: ...``   blocks submission (missing/contradictory content)
    ``warning: ...`` worth fixing before submission
"""

from __future__ import annotations

import math
import re

REQUIRED_SECTIONS = ("title", "description", "poc", "impact", "remediation")
OPTIONAL_SECTIONS = ("severity", "cvss_vector", "cvss_base", "scope",
                     "timeline", "references")
SEVERITIES = ("NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL")

#: Phrases §11 of this workspace's pipeline forbids — and that programs reject.
EXAGGERATED = (
    "production-ready",
    "enterprise-grade",
    "unhackable",
    "guaranteed",
    "100% effective",
    "cannot be exploited",
    "zero risk",
)

CVSS_PREFIX = "CVSS:3.1/"
ALLOWED = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "PR": {"N": None, "L": None, "H": None},   # scope-dependent, see pr_lookup
    "UI": {"N": 0.85, "R": 0.62},
    "S": {"U": None, "C": None},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}
BASE_METRICS = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")


def _error(msg: str) -> str:
    return f"error: {msg}"


def _warn(msg: str) -> str:
    return f"warning: {msg}"


def split_levels(issues: list[str]) -> tuple[list[str], list[str]]:
    """Split issue strings into (errors, warnings)."""
    errors = [i for i in issues if i.startswith("error:")]
    warnings = [i for i in issues if not i.startswith("error:")]
    return errors, warnings


def parse_vector(vector: str) -> tuple[dict | None, list[str]]:
    """Parse a CVSS:3.1 vector into {metric: value}; returns (metrics, errors)."""
    errors = []
    if not isinstance(vector, str) or not vector.strip():
        return None, ["cvss_vector is empty"]
    if not vector.startswith("CVSS:3.1/"):
        if vector.startswith("CVSS:3.0/"):
            return None, ["cvss_vector uses CVSS:3.0; this linter expects CVSS:3.1/"]
        return None, ["cvss_vector must start with 'CVSS:3.1/'"]
    parts = vector[len(CVSS_PREFIX):].split("/")
    metrics: dict[str, str] = {}
    for part in parts:
        if ":" not in part:
            errors.append(f"malformed vector component {part!r} (want METRIC:VALUE)")
            continue
        key, value = part.split(":", 1)
        key = key.upper()
        if key in metrics:
            errors.append(f"duplicate metric {key} in vector")
        if key not in ALLOWED:
            errors.append(f"unknown metric {key!r} in vector")
            continue
        if value.upper() not in ALLOWED[key]:
            errors.append(f"invalid value {value!r} for {key}")
            continue
        metrics[key] = value.upper()
    missing = [m for m in BASE_METRICS if m not in metrics]
    if missing:
        errors.append("vector is missing base metric(s): " + ", ".join(missing))
        return None, errors
    return metrics, errors
    return metrics, errors


def _roundup(value: float) -> float:
    """CVSS 3.1 roundup: ceil to 5 decimal places, then one-decimal rounding."""
    return math.ceil(round(value, 5) * 100000) / 100000


def cvss_base(metrics: dict) -> float:
    """Recompute the CVSS:3.1 base score from parsed base metrics."""
    scope = metrics["S"]
    av = ALLOWED["AV"][metrics["AV"]]
    ac = ALLOWED["AC"][metrics["AC"]]
    ui = ALLOWED["UI"][metrics["UI"]]
    if scope == "C":
        pr = {"N": 0.85, "L": 0.85, "H": 0.55}[metrics["PR"]]
    else:
        pr = {"N": 0.85, "L": 0.62, "H": 0.27}[metrics["PR"]]
    c = ALLOWED["C"][metrics["C"]]
    i = ALLOWED["I"][metrics["I"]]
    a = ALLOWED["A"][metrics["A"]]

    iss = 1 - (1 - c) * (1 - i) * (1 - a)
    if scope == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
    exploitability = 8.22 * av * ac * pr * ui
    if impact <= 0:
        return 0.0
    return round(_roundup(min(impact + exploitability, 10.0)), 1)


def severity_band(score: float) -> str:
    """Severity name implied by a base score."""
    if score == 0.0:
        return "NONE"
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW"


def _text_fields(report: dict) -> dict[str, str]:
    out = {}
    for key in ("title", "description", "poc", "impact", "remediation"):
        val = report.get(key)
        if isinstance(val, str):
            out[key] = val
    return out


def _has_repro_steps(poc: str) -> bool:
    lines = [ln.strip() for ln in poc.splitlines() if ln.strip()]
    numbered = [ln for ln in lines
                if re.match(r"^(\d+[.)]|[-*+]>?)\s+", ln) or ln.startswith("```")]
    return len(numbered) >= 2 or (len(lines) >= 4 and len(poc) >= 120)


def lint_report(report: dict) -> list[str]:
    """Return every issue found in a draft report, errors first at call site."""
    issues: list[str] = []
    if not isinstance(report, dict):
        return [_error("report must be a JSON object")]

    # 1. structure
    for section in REQUIRED_SECTIONS:
        value = report.get(section)
        if value is None or (isinstance(value, str) and not value.strip()):
            issues.append(_error(f"missing section: {section}"))
        elif isinstance(value, str) and len(value.strip()) < 10 and section != "title":
            issues.append(_warn(f"section {section} is too short to be useful "
                                f"({len(value.strip())} chars)"))
    for section in OPTIONAL_SECTIONS:
        if report.get(section) in (None, ""):
            issues.append(_warn(f"optional section not filled in: {section}"))

    # 2. reproducibility of the PoC
    poc = report.get("poc")
    if isinstance(poc, str) and poc.strip() and not _has_repro_steps(poc):
        issues.append(_warn(
            f"poc does not look reproducible ({len(poc)} chars, no numbered "
            "steps or fenced commands)"))

    # 3. over-claiming language
    for field, text in _text_fields(report).items():
        low = text.lower()
        for phrase in EXAGGERATED:
            if phrase in low:
                issues.append(_warn(
                    f"{field} uses exaggerated claim {phrase!r}"))

    # 4. severity vocabulary
    severity = report.get("severity")
    if severity:
        if not isinstance(severity, str) or severity.upper() not in SEVERITIES:
            issues.append(_error(
                f"severity {severity!r} is not one of {', '.join(SEVERITIES)}"))
    # legacy key name kept for compatibility with the original scaffold
    legacy = report.get("claimed_severity")
    if legacy and (not isinstance(legacy, str) or legacy.upper() not in SEVERITIES):
        issues.append(_error(
            f"severity {legacy!r} is not one of {', '.join(SEVERITIES)}"))

    # 5. CVSS vector validity + recomputed base score
    vector = report.get("cvss_vector")
    metrics = None
    if vector:
        metrics, verrs = parse_vector(vector)
        issues.extend(_error(e) for e in verrs)
    claimed = report.get("cvss_base")
    if metrics and claimed is not None:
        implied = cvss_base(metrics)
        try:
            claimed_f = float(claimed)
        except (TypeError, ValueError):
            issues.append(_error(f"cvss_base {claimed!r} is not a number"))
            claimed_f = None
        if claimed_f is not None and abs(implied - claimed_f) > 0.1:
            issues.append(_error(
                f"cvss_base {claimed_f} does not match vector (recomputed {implied})"))
        band = severity_band(implied)
        for name in (severity, legacy):
            if isinstance(name, str) and name.upper() in SEVERITIES and name.upper() != band and band != "NONE":
                issues.append(_error(
                    f"severity {name} inconsistent with base {implied} "
                    f"(expected {band})"))
                break
    elif claimed is None and not vector:
        issues.append(_warn("no severity evidence: neither cvss_vector nor cvss_base given"))
    if claimed is not None and not vector:
        issues.append(_warn("cvss_base given without cvss_vector; score cannot be verified"))

    # dedupe while preserving order
    seen = set()
    unique = []
    for issue in issues:
        if issue not in seen:
            seen.add(issue)
            unique.append(issue)
    return unique
