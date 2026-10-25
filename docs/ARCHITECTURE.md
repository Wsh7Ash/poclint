# Architecture — poclint

## Overview

`poclint` (bug-bounty-tooling) is a single-package Python CLI: a `src/poclint/` package
with a pure logic module and a Click command layer, console-script entry point
`poclint = poclint.cli:main`, and no runtime services.

### `src/poclint/linter.py`

Pure lint rules over a dict: required/optional sections, CVSS:3.1 vector parsing and base-score recomputation (impact, exploitability, roundup), severity banding, PoC reproducibility heuristic, and over-claiming phrase detection. Issues are prefixed error: or warning:.

### `src/poclint/cli.py`

Click group with `lint FILE` (--strict, --json-out). Exits 0 clean, 1 errors (or warnings under --strict), 2 unreadable/bad file.


## Design decisions

- **Logic/rendering separation.** Every decision (classify, parse, lint, plan,
  probe) lives in a pure module with no console output, so tests assert on data
  rather than on terminal formatting.
- **Exit codes as the CI contract.** 0 = clean/success, 1 = findings or failed
  requirement, 2 = usage or read error. `--json-out` switches stdout to
  machine-readable JSON without changing exit codes.
- **Small dependency surface.** Only `click` (CLI), `rich` (tables) and, where
  network I/O is the point, `requests`; everything else is the standard library.

## Data flow

```
input (file / URL / ports + flags)
   -> Click command validates arguments
   -> pure module computes findings / profiles / verdicts / plan
   -> renderer prints table or JSON
   -> process exits 0 / 1 / 2
```

## Testing strategy

tests/test_linter.py verifies structure rules, the vocabulary check, claim detection, vector parsing errors, recomputed scores for known vectors (9.8, 5.3, 0.0), score/severity mismatch, and CLI exit codes 0/1/2 including --strict and JSON output.
