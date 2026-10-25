# poclint

**Lint a draft bug-bounty report before a program does — section completeness,
CVSS:3.1 vector sanity with a recomputed base score, severity calibration and
over-claiming language.**

## The problem

Reports get rejected for dumb, avoidable reasons: a missing `Remediation`
section, a CVSS vector that doesn't match the claimed severity, prose that
says "production-ready". The writer is too close to the finding to notice.
poclint checks the draft mechanically in milliseconds, offline, before you
paste it into a submission form.

## Features

- **Structure** — required sections (`title`, `description`, `poc`, `impact`,
  `remediation`) and optional ones (`severity`, `cvss_vector`, `cvss_base`,
  `scope`, `timeline`, `references`), each reported at the right level.
- **CVSS:3.1 validation** — parses the vector, rejects unknown metrics and
  values, flags missing base metrics, and **recomputes the base score** to
  compare against your claimed `cvss_base`.
- **Severity calibration** — the claimed severity must match the band
  (`0–3.9 LOW`, `4–6.9 MEDIUM`, `7–8.9 HIGH`, `9–10 CRITICAL`) implied by the
  score.
- **Reproducibility** — a PoC with no numbered steps and no fenced command is
  warned about.
- **Over-claiming** — flags phrases like `guaranteed`, `unhackable`,
  `production-ready`, `100% effective`.
- **`--strict` and `--json-out`** for use as a CI or pre-submit gate.

Every issue is prefixed `error:` (blocks submission) or `warning:` (worth
fixing). Exit codes: `0` clean, `1` errors (or warnings under `--strict`),
`2` bad usage or unreadable file.

## Example output

```console
$ poclint lint examples/finding.json
OK: examples/finding.json — no issues
0 error(s), 0 warning(s)
[exit 0]

$ poclint lint examples/draft-with-issues.json
┌─────────┬───────────────────────────────────────────────────────────────────┐
│ Level   │ Issue                                                             │
├─────────┼───────────────────────────────────────────────────────────────────┤
│ error   │ missing section: impact                                           │
│ error   │ missing section: remediation                                      │
│ error   │ severity 'SEVERE' is not one of NONE, LOW, MEDIUM, HIGH, CRITICAL │
│ error   │ cvss_vector must start with 'CVSS:3.1/'                           │
│ warning │ optional section not filled in: scope                             │
│ warning │ poc does not look reproducible (11 chars, no numbered steps ...)  │
│ warning │ description uses exaggerated claim 'production-ready'             │
└─────────┴───────────────────────────────────────────────────────────────────┘
4 error(s), 6 warning(s)
[exit 1]
```

## Architecture

```
src/poclint/
├── linter.py   # pure: parse_vector(), cvss_base(), lint_report()
└── cli.py      # click: rendering, --strict, --json-out, exit codes
```

`cvss_base()` implements the CVSS:3.1 base metric formulas (impact,
exploitability, `roundup`), so score/vector disagreement is a hard error rather
than a guess. The whole linter is pure functions over a dict — no I/O, no
network, no telemetry.

## Requirements

- Python 3.10+; `click` and `rich` (installed automatically)

## Installation

```shell
git clone https://github.com/Wsh7Ash/poclint
cd poclint
pip install -e .
```

## Quick start

```shell
poclint lint examples/finding.json
```

## Usage

```shell
# gate a draft: errors exit 1
poclint lint draft.json

# treat warnings as failures too
poclint lint draft.json --strict

# machine-readable, for a pre-submit hook
poclint lint draft.json --json-out | jq '.errors'
```

## Configuration

There is no config file by design — the rules are fixed, and the JSON report
schema is documented in [docs/USAGE.md](docs/USAGE.md).

## Testing

```shell
pip install -e . pytest
pytest -q        # 18 tests, including known-good 9.8/5.3/0.0 vectors
```

## Project structure

```
poclint/
├── src/poclint/{linter,cli}.py
├── tests/test_linter.py
├── examples/{finding,draft-with-issues}.json
├── docs/{ARCHITECTURE,USAGE,PROJECT_SPEC}.md
├── results/demo-output.txt
├── RESULTS.md
└── .github/workflows/ci.yml
```

## Limitations

- Only the CVSS **base** score is computed; temporal/environmental metrics and
  CVSS v4.0 are out of scope.
- Reproducibility is a heuristic (numbered steps / fenced commands / length).
- It reads the JSON you give it: it cannot know whether the described impact
  is real.
- Warnings are advisory; `--strict` is how you make them blocking.

## Roadmap

- `poclint init` to scaffold a report skeleton.
- CVSS v4.0 vectors alongside 3.1.
- Optional remediation links per vulnerability class.

## Security

The tool reads one local JSON file and prints text. It performs no network
requests, stores no data, and takes no untrusted input beyond that file. See
[SECURITY.md](SECURITY.md).

## License

MIT — see [LICENSE](LICENSE).
