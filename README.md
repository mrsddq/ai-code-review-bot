# AI Code Review Bot

A fast, deterministic Python reviewer that finds security and maintainability risks and emits terminal, JSON, or GitHub-compatible SARIF output. It is suitable for local pre-commit checks and CI review gates.

## Rules included

| Rule | Severity | Detects |
| --- | --- | --- |
| CRB000 | High | Syntax errors |
| CRB001 | High | Dynamic `eval` / `exec` |
| CRB002 | High | Subprocess calls with `shell=True` |
| CRB003 | Medium | Bare exception handlers |
| CRB004 | Medium | Mutable default arguments |
| CRB005 | Low | Functions longer than 80 lines |
| CRB006 | High | Likely hard-coded credentials |

## Use

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -e ".[dev]"

reviewbot src
reviewbot . --format json --output review.json --fail-on medium
reviewbot . --format sarif --output review.sarif --fail-on none
```

Exit status is non-zero when a finding meets `--fail-on` (high by default). The `action.yml` composite action lets another repository run the reviewer directly:

```yaml
- uses: mrsddq/ai-code-review-bot@main
  with:
    path: src
```

Upload `review.sarif` with `github/codeql-action/upload-sarif` if you want annotations in GitHub's code-scanning UI.

## Extend it

Add an AST visitor rule in `reviewer.py`, assign a stable rule ID, then add a focused fixture in `tests/`. The output adapters automatically carry new findings into text, JSON, and SARIF reports.

```bash
pytest
ruff check .
docker build -t reviewbot .
docker run --rm -v "$PWD:/workspace" reviewbot .
```

MIT licensed.
