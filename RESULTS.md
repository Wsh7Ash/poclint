# Results — poclint

## Environment
- OS: Windows (msys2 shell), Python 3.14.3
- Runtime: python.exe in a fresh virtualenv
- Dependency manager: pip (`pip install -e .`)

## Validation performed
- install: PASS (exit 0)
- unit tests: PASS (exit 0)
- CLI help: PASS (exit 0)
- CLI clean draft: PASS (exit 0)
- CLI failing draft (exit 1 expected): PASS (exit 1)
- demo run: PASS (97 lines captured in results/demo-output.txt)
- secret/path scan: PASS (no secrets, no machine-specific paths)

## Commands executed

```shell
-m pip install -q -e .
```
# -> install: exit 0
```shell
-m pytest -q
```
# -> unit tests: exit 0
```shell
poclint --help
```
# -> CLI help: exit 0
```shell
poclint lint examples/finding.json
```
# -> CLI clean draft: exit 0
```shell
poclint lint examples/draft-with-issues.json
```
# -> CLI failing draft (exit 1 expected): exit 1

## Observed result

**install**

```

```

**unit tests**

```
..................                                                       [100%]
18 passed in 0.21s
```

**CLI help**

```
  --help     Show this message and exit.
Commands:
  lint  Lint draft report FILE (JSON).
```

**CLI clean draft**

```
OK: examples/finding.json — no issues
0 error(s), 0 warning(s)
```

**CLI failing draft (exit 1 expected)**

```
│ warning │ description uses exaggerated claim 'guaranteed'                   │
└─────────┴───────────────────────────────────────────────────────────────────┘
4 error(s), 6 warning(s)
```

## Generated artifacts

- `results/demo-output.txt` — full demo transcript with real exit codes
- `docs/ARCHITECTURE.md`, `docs/USAGE.md`, `docs/PROJECT_SPEC.md`
- `CHANGELOG.md`, `CONTRIBUTING.md`, `SECURITY.md`, `README.md`

## Known limitations

See the **Limitations** section of `README.md`. In short: single-process scope,
heuristic detection where noted, and advisory output that must be interpreted by
a human who knows the system under test.
