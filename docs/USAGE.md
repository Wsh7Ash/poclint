# Usage — poclint

## Install

```shell
pip install -e .
```

## Commands

```shell
poclint --help
```

## Examples

### Lint a complete draft

```shell
poclint lint examples/finding.json
```

### A draft with problems (exits 1)

```shell
poclint lint examples/draft-with-issues.json
```

### Gate a draft before submitting

```shell
poclint lint draft.json --strict
```

### Machine-readable issues

```shell
poclint lint draft.json --json-out | jq ".errors"
```

## Report JSON schema

```json
{
  "title": "...", "description": "...", "poc": "...",
  "impact": "...", "remediation": "...",
  "severity": "LOW|MEDIUM|HIGH|CRITICAL|NONE",
  "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
  "cvss_base": 5.3,
  "scope": "...", "timeline": "...", "references": ["..."]
}
```

`title`, `description`, `poc`, `impact`, `remediation` are required. Issues are
prefixed `error:` (exit 1) or `warning:` (exit 1 only with `--strict`). Base scores
are recomputed from the vector with the CVSS:3.1 formulas; a disagreement greater
than 0.1 is an error.

## Validation gates

- **install**: `pip install -e . (fresh venv)`
- **unit tests**: `pytest -q (18 tests)`
- **CLI smoke**: `poclint --help; poclint lint examples/finding.json`
- **demo run**: `logs/2026-10-25/run_demos.py -> results/demo-output.txt`
- **secret scan**: `no tokens/keys/.env/machine paths in tree`

## Exit codes

- `0` — success / nothing at or above the threshold
- `1` — findings, failures, or an unmet `--require`
- `2` — usage error, unreadable input, or rejected target
