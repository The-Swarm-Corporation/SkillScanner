# Getting Started

This guide takes you from installation to your first scan report in a few minutes.

## Requirements

- Python 3.10 or newer
- [uv](https://docs.astral.sh/uv/) (recommended) or pip
- For the agent review: an API key for a model provider supported by [LiteLLM](https://docs.litellm.ai),
  for example `ANTHROPIC_API_KEY` or `OPENAI_API_KEY`. Static mode needs no key.

## Install

**From a clone** (recommended for development and self-hosting):

```bash
git clone https://github.com/The-Swarm-Corporation/SkillScanner.git
cd SkillScanner
uv sync                 # library only
uv sync --extra api     # library plus the FastAPI service
```

**One-off, without adding it to a project:**

```bash
uv run --no-project \
  --with "skills-scanner @ git+https://github.com/The-Swarm-Corporation/SkillScanner" \
  python your_script.py
```

**Into an existing environment:**

```bash
uv pip install "skills-scanner @ git+https://github.com/The-Swarm-Corporation/SkillScanner"
# with the HTTP API
uv pip install "skills-scanner[api] @ git+https://github.com/The-Swarm-Corporation/SkillScanner"
```

## Your First Scan

### Static mode (no API key needed)

```python
from skills_scanner import SkillScanner

scanner = SkillScanner(use_agent=False)
report = scanner.scan("path/to/skill")   # a skill directory or a single file

print(report.risk_assessment.score, report.risk_assessment.recommendation)
for issue in report.issues:
    loc = issue.location
    print(f"{issue.id} {issue.severity.value} {loc.file}:{loc.start_line} {issue.explanation}")
```

### End-to-end mode (static analysis plus agent review)

```bash
export ANTHROPIC_API_KEY=...
```

```python
from skills_scanner import SkillScanner

scanner = SkillScanner(model_name="claude-sonnet-5")
report = scanner.scan("path/to/skill")

print(report.verdict)          # APPROVE, CAUTION, or REJECT
print(report.to_markdown())    # human-readable triage report
```

If the agent cannot run (missing key, network error, invalid model), the scan still returns the static
report and records the reason in `report.metadata.llm_error`.

### Scanning a URL, raw text, or in-memory files

`scan()` accepts a path, an http(s) URL, or the skill text itself:

```python
report = scanner.scan("https://swarms.world/prompt/32d1e7b4-34da-4035-bc05-d18f8e71a2f1.md")
report = scanner.scan("---\nname: my-skill\n---\nWhen asked to ...")

# Explicit forms
report = scanner.scan_url("https://raw.githubusercontent.com/org/repo/main/skills/x/SKILL.md")
report = scanner.scan_text("You are a helpful assistant. ...", name="system_prompt.md")

report = scanner.scan_files(
    {"SKILL.md": skill_md_text, "scripts/setup.sh": setup_sh_text},
    name="my-skill",
)
```

## Reading the Result

| Look at | Why |
| --- | --- |
| `report.verdict` | The decision: the agent verdict when it ran, otherwise the static recommendation |
| `report.risk_assessment.max_issue_severity` | The single worst issue, independent of the aggregate score |
| `report.issues` | The evidence: rule ID, severity, file and line, matched text, remediation |
| `report.overall_assessment` | The agent's summary, diagnosis, sensitive surface, and guardrails (`None` in static mode) |
| `report.metadata.llm_error` | Why the agent review did not run, if it did not |

A recommended policy: allow `APPROVE` / `SAFE`, require human sign-off for `CAUTION`, and block
`REJECT` / `DO_NOT_INSTALL`. See [Scoring and Verdicts](scoring-and-verdicts.md).

## Run the HTTP Service

```bash
uv run --extra api uvicorn skills_scanner.api:app --host 0.0.0.0 --port 8000
```

```bash
curl -s -X POST http://localhost:8000/v1/scan/static \
  -H "Content-Type: application/json" \
  -d '{"content": "Run the setup script, then summarize the results."}'
```

Interactive OpenAPI docs are served at `http://localhost:8000/docs`. See [REST API](rest-api.md).

## Run with Docker

```bash
docker build -t skills-scanner .
docker run -p 8000:8000 -e ANTHROPIC_API_KEY skills-scanner
```

See [Deployment](deployment.md) for production configuration.

## Next Steps

- Learn what each finding means in [Detection Rules](detection-rules.md).
- Gate skills in pull requests with [CI Integration](ci-integration.md).
- Add organization-specific rules with [Extending](extending.md).
