# security-claim-audit

An offline, standard-library-only Python CLI that checks documentation promises
about execution safety against Python source. It reads root `README.md` and
`docs/**/*.md`, excluding fenced code blocks, and compares positive claims with
AST call patterns. Inline code spans count as prose. It executes no audited
project code, makes no network requests, and never opens `.env` files.

Requires Python 3.9 or later. Install and run:

```sh
pip install .
security-claim-audit path/to/project
security-claim-audit path/to/project --json
security-claim-audit --verbose --fail-on HIGH
security-claim-audit --ignore documented-no-shell-claim-false
```

The optional path defaults to `.`. `--json` emits findings, verified claims and a
summary. `--verbose` includes verified claims in human output. `--ignore RULE,...`
drops listed rules. `--fail-on HIGH|MEDIUM` defaults to MEDIUM. `--version` prints
`0.1.0`. Exit codes are 0 for PASS, 2 for findings meeting the threshold, and 1 for
usage or input errors. Findings include severity, rule, relative documentation
file, line, claim text, and a short code pattern; no source bodies are emitted.

| Rule | Severity |
| --- | --- |
| documented-no-eval-claim-false | HIGH |
| documented-no-shell-claim-false | HIGH |
| documented-no-pickle-claim-false | HIGH |
| documented-safe-input-claim-false | HIGH |
| documented-no-eval-claim-test-only | MEDIUM |
| documented-no-shell-claim-test-only | MEDIUM |
| documented-no-pickle-claim-test-only | MEDIUM |
| documented-safe-input-claim-test-only | MEDIUM |

Claims such as “no eval”, “never shells out”, “no unsafe deserialization”, and
“safe for untrusted input” are recognized case-insensitively. Warning lines
containing “not enough”, “not sufficient”, “insufficient”, “is not safe”,
“is unsafe”, or “avoid” are excluded. “No system calls” requires command context.
Eval evidence includes builtin `eval`, `exec`, `compile` and nonliteral
`__import__` calls. Shell evidence includes subprocess calls, OS command calls,
and legacy commands calls. Deserialization evidence includes pickle, marshal,
shelve, dill, and `yaml.load` without an explicit `Loader=` keyword.
`ast.literal_eval`, `yaml.safe_load`, and `yaml.load` with explicit `Loader=` are
excluded. This Loader check is syntactic; it does not validate loader safety.

Evidence under tests, fixtures, docs, or test-named files is reported at MEDIUM
only when production evidence is absent. No claims means PASS. Without any
Python source, each claim receives a HIGH finding. Invalid Python syntax is
skipped. Symlink files and directories are skipped.

## Neighbours

Bandit and Ruff identify code issues rather than comparing documentation
promises. privacy-claim-audit checks network and telemetry presence;
readonly-claim-audit checks filesystem writes; auth-claim-audit checks credential
requirements; config-claim-audit checks default values. This tool focuses on
documented execution behaviour.

## Limitations

Static pattern matching is not semantic judgement or a security certification.
Subprocess calls with `shell=False` and literal argv still count because a
promise of no subprocess or shell commands concerns external command execution.
Use `--ignore` if your promise means only absence of `shell=True`.
Dead code counts. Dynamic construction such as `getattr` tricks and string-built
execution names is missed. Alias tracking is per file and resolves one attribute
step. Local definitions and assignments suppress bare builtin evidence across
the file, without scope or control-flow analysis. “Safe input” maps only to eval
evidence, not shell or pickle evidence; this is not a full taint analysis.
Warnings are filtered at line granularity. Audited source is never imported;
the good fixture's YAML examples do not require PyYAML to be installed.

## Development

```sh
PYTHONPATH=src python3 -m unittest discover -s tests -v
python3 -m build
```

MIT licensed. Runtime dependencies: none.
