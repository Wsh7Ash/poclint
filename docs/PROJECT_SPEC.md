# PROJECT SPEC — poclint

| Field | Value |
|---|---|
| Name | `poclint` |
| Category | bug-bounty-tooling |
| Target user | Bug-bounty researchers submitting draft reports |
| Problem | Programs reject drafts for avoidable reasons: missing sections, a CVSS vector that contradicts the claimed severity, over-claiming prose — things the writer is too close to notice. |
| Solution | A pure, offline linter that validates report structure, parses the CVSS:3.1 vector, recomputes the base score, checks the severity band and flags exaggerated claims, with --strict and --json-out for gating. |
| Core workflow | write draft JSON -> poclint lint -> fix errors -> submit |
| Stack | Python >=3.10, click, rich |
| Test strategy | tests/test_linter.py verifies structure rules, the vocabulary check, claim detection, vector parsing errors, recomputed scores for known vectors (9.8, 5.3, 0.0), score/severity mismatch, and CLI exit codes 0/1/2 including --strict and JSON output. |
| Demo strategy | `logs/2026-10-25/run_demos.py` runs the real workflow and captures `results/demo-output.txt` with asserted exit codes |
| Safety | Reads one local JSON file and prints text: no network, no storage, no telemetry. Report content is data, never executed. |
| Definition of done | install + pytest + CLI smoke + demo transcript + secret scan all pass; docs (README, ARCHITECTURE, USAGE, CHANGELOG, CONTRIBUTING, SECURITY) present; pushed with green CI |

## Must-have features

- Core workflow end to end: write draft JSON -> poclint lint -> fix errors -> submit
- Exit-code contract (0/1/2) usable from CI
- `--json-out` machine-readable output where a machine should read it

## Nice-to-have (deferred)

- See README Roadmap.
