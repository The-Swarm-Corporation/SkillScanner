# SkillScanner Documentation

SkillScanner audits AI agent skills and prompts for security risks before they reach your agents. It
combines deterministic static analysis with an optional [Swarms](https://swarms.ai) agent review and
produces a structured report with a risk score, per-issue evidence, and an install verdict.

## Contents

| Guide | What it covers |
| --- | --- |
| [Getting Started](getting-started.md) | Install, run your first scan, read the result |
| [How It Works](how-it-works.md) | Pipeline, static analysis, agent review, and how results are merged |
| [Python API](python-api.md) | `SkillScanner`, `ScanReport`, rules, and helper functions |
| [REST API](rest-api.md) | Endpoints, request and response formats, limits, errors |
| [Report Schema](report-schema.md) | Every field in a scan report |
| [Detection Rules](detection-rules.md) | Catalog of every rule ID with severity, confidence, and examples |
| [Scoring and Verdicts](scoring-and-verdicts.md) | Risk score algorithm, bands, floors, and the verdict rubric |
| [Agent Review](agent-review.md) | Model configuration, structured output, merge semantics, failure handling |
| [Security Model](security-model.md) | Threat model, guarantees, data handling, and limitations |
| [Deployment](deployment.md) | Docker, configuration, scaling, and production hardening |
| [CI Integration](ci-integration.md) | Gating skills in pull requests with GitHub Actions |
| [Extending](extending.md) | Custom rules, harmful terms, trusted domains, and rule testing |
| [Troubleshooting](troubleshooting.md) | Common errors and how to resolve them |

## At a Glance

```python
from skills_scanner import SkillScanner

scanner = SkillScanner()
report = scanner.scan("path/to/skill")                                   # directory or file
report = scanner.scan("https://swarms.world/prompt/<id>.md")             # Markdown URL
report = scanner.scan("---\nname: my-skill\n---\nSkill instructions...")  # raw text

report.verdict                  # APPROVE / CAUTION / REJECT (agent) or SAFE / CAUTION / DO_NOT_INSTALL (static)
report.risk_assessment.score    # 0-100
report.issues                   # evidence, one entry per finding
report.to_markdown()            # triage report for humans
```

```bash
curl -X POST http://localhost:8000/v1/scan \
  -H "Content-Type: application/json" \
  -d '{"content": "<prompt or SKILL.md text>"}'
```

## Terminology

| Term | Meaning |
| --- | --- |
| Skill | A folder of instructions (usually `SKILL.md`) plus optional scripts that an AI agent loads and follows |
| Issue | One finding: a rule match or an agent-identified threat, with location and evidence |
| Rule | A detection pattern with an ID (for example `PI001`), category, severity, and confidence |
| Risk score | 0-100 aggregate of issue severities, weighted by confidence |
| Recommendation | Static outcome: `SAFE`, `CAUTION`, or `DO_NOT_INSTALL` |
| Verdict | Agent outcome: `APPROVE`, `CAUTION`, or `REJECT` |
| Static mode | Scan without the agent: offline, deterministic, no data leaves the machine |
| End-to-end mode | Static analysis followed by the agent review |
