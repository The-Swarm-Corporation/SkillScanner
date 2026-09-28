# SkillScanner API Quick Reference

Full documentation lives in the SkillScanner repository under `docs/`.

## Contents

- [Running SkillScanner](#running-skillscanner)
- [Python API](#python-api)
- [Batch audit](#batch-audit)
- [REST API](#rest-api)
- [CI gate](#ci-gate)
- [Customization](#customization)

## Running SkillScanner

| Situation | Command |
| --- | --- |
| Anywhere, no install | `uv run --no-project --with "skills-scanner @ git+https://github.com/The-Swarm-Corporation/SkillScanner" python -` |
| Inside the SkillScanner repository | `uv run python -` |
| Existing environment | `uv pip install "skills-scanner @ git+https://github.com/The-Swarm-Corporation/SkillScanner"` |
| Deployed service | `POST $SKILLS_SCANNER_URL/v1/scan` |

End-to-end mode needs the provider key for `model_name` (for example `ANTHROPIC_API_KEY` for
`claude-sonnet-5`). Without it, the agent review fails gracefully and the report is static-only.

## Python API

```python
from skills_scanner import SkillScanner

scanner = SkillScanner(
    use_agent=True,                 # False for static-only
    model_name="claude-sonnet-5",   # any LiteLLM model ID
    trusted_domains=(),             # domains exempt from link reputation checks
    harmful_terms=(),               # extra terms flagged as HC100
    extra_rules=(),                 # custom Rule objects
    max_file_bytes=1_000_000,
    max_files=1_000,
    agent_max_chars=150_000,        # content budget sent to the agent
)
```

| Method | Input |
| --- | --- |
| `scan(target, use_agent=None)` | A path, an `http(s)` URL, or skill/prompt text (auto-detected) |
| `scan_url(url, use_agent=None)` | A raw `SKILL.md` or prompt `.md` URL; public hosts only, 1 MB cap, text only |
| `scan_text(text, name="prompt.md", use_agent=None)` | One document as text |
| `scan_files(files, name="skill", source="", use_agent=None)` | `{"relative/path": "text", ...}` |

`scan()` raises `FileNotFoundError` for a single-line, space-free string that looks like a path but does
not exist. `scan_url()` raises `ValueError` (non-public host, oversized, binary, bad scheme) or
`httpx.HTTPError` (network or HTTP status).

| Report member | Use |
| --- | --- |
| `report.verdict` | Agent verdict if it ran, else the static recommendation |
| `report.to_json()` | Full JSON report |
| `report.to_markdown()` | Triage report |
| `report.issues`, `report.components`, `report.metadata` | Structured access |

## Batch Audit

```python
from pathlib import Path
from skills_scanner import SkillScanner

scanner = SkillScanner(use_agent=False)
roots = [Path(".claude/skills"), Path("~/.claude/skills").expanduser()]
for skill_dir in sorted(d for root in roots if root.is_dir() for d in root.iterdir() if d.is_dir()):
    r = scanner.scan(skill_dir)
    print(f"{r.risk_assessment.score:>3}  {r.verdict:<14}  {r.skill.name}  ({skill_dir})")
```

For a repository, iterate over the parents of every `SKILL.md` instead
(`sorted(p.parent for p in root.rglob("SKILL.md"))`).

## REST API

| Method | Path | Description |
| --- | --- | --- |
| `POST` | `/v1/scan` | Static analysis plus agent review |
| `POST` | `/v1/scan/static` | Static analysis only |
| `GET` | `/health` | Liveness |

Body: exactly one of

```json
{"url": "https://swarms.world/prompt/<id>.md"}
{"content": "<prompt or SKILL.md text>", "name": "SKILL.md"}
{"name": "my-skill", "files": {"SKILL.md": "...", "scripts/run.sh": "..."}}
```

Statuses: `200` report; `422` invalid body; `400` URL refused (non-public, oversized, binary); `502` URL
fetch failed. Limits: 1,000 files and 10 MB per request, 1 MB per fetched URL. A failed agent review
still returns `200` with `metadata.llm_error` set.

```bash
curl -s -X POST "$SKILLS_SCANNER_URL/v1/scan" -H "Content-Type: application/json" \
  -d '{"url": "https://swarms.world/prompt/32d1e7b4-34da-4035-bc05-d18f8e71a2f1.md"}'
```

Run the service locally with `uv run --extra api uvicorn skills_scanner.api:app --port 8000`, or with
Docker: `docker build -t skills-scanner . && docker run -p 8000:8000 -e ANTHROPIC_API_KEY skills-scanner`.

## CI Gate

Minimal gate that fails a build on blocked verdicts (the repository's `docs/ci-integration.md` has a
complete GitHub Actions workflow with job summaries and report artifacts):

```python
import sys
from pathlib import Path
from skills_scanner import SkillScanner

scanner = SkillScanner(use_agent=False)
blocked = []
for skill_dir in sorted(p.parent for p in Path("skills").rglob("SKILL.md")):
    report = scanner.scan(skill_dir)
    print(f"{report.verdict:<14} {skill_dir}")
    if report.verdict in {"REJECT", "DO_NOT_INSTALL"}:
        blocked.append(skill_dir)
sys.exit(1 if blocked else 0)
```

Pin the scanner to a commit in CI (`...SkillScanner@<sha>`) and keep provider secrets away from
workflows that run on untrusted pull requests.

## Customization

```python
from skills_scanner import Severity, SkillScanner, rule

scanner = SkillScanner(
    trusted_domains=["github.com", "docs.python.org"],
    harmful_terms=["project-codename"],
    extra_rules=[rule("ORG001", "data_exfiltration", Severity.HIGH,
                      "References an internal-only host", r"\b[\w-]+\.corp\.example\.com\b")],
)
scanner.rules = tuple(r for r in scanner.rules if r.id != "HC002")   # disable a built-in rule
```

Accept reviewed findings with a baseline of `issue.match_fingerprint` values and rescore the rest with
`skills_scanner.scanner.assess(remaining_issues, report.components)`.
