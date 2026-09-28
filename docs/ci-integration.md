# CI Integration

Gate skills in pull requests so nothing unsafe is merged into a skills repository or marketplace.

## Gate Script

Save as `.github/scripts/scan_skills.py`. It scans every directory containing a `SKILL.md`, writes one
JSON report per skill, prints a summary (and appends it to the GitHub job summary), and exits with code
1 if any skill is `REJECT` or `DO_NOT_INSTALL`.

```python
"""Scan every skill (a directory containing SKILL.md) under a root and fail on blocked verdicts."""

import os
import sys
from pathlib import Path

from skills_scanner import SkillScanner

BLOCKED = {"REJECT", "DO_NOT_INSTALL"}
IGNORED = {".git", "node_modules", ".venv", "venv"}

root = Path(sys.argv[1] if len(sys.argv) > 1 else ".")
report_dir = Path(os.getenv("REPORT_DIR", "skill-reports"))
report_dir.mkdir(parents=True, exist_ok=True)

use_agent = bool(os.getenv("ANTHROPIC_API_KEY"))
scanner = SkillScanner(
    use_agent=use_agent,
    model_name=os.getenv("SKILLS_SCANNER_MODEL", "claude-sonnet-5"),
)

rows, blocked = [], []
for manifest in sorted(root.rglob("SKILL.md")):
    if IGNORED & set(manifest.parts):
        continue
    skill_dir = manifest.parent
    report = scanner.scan(skill_dir)
    slug = skill_dir.relative_to(root).as_posix().replace("/", "__") or "root"
    (report_dir / f"{slug}.json").write_text(report.to_json())
    rows.append(f"| `{skill_dir.relative_to(root)}` | {report.risk_assessment.score} | {report.verdict} |")
    if report.verdict in BLOCKED:
        blocked.append(report)

mode = "end-to-end" if use_agent else "static"
summary = "\n".join(
    [f"## SkillScanner ({mode})", "", "| Skill | Score | Verdict |", "| --- | --- | --- |", *rows]
    + [f"\n{r.to_markdown()}" for r in blocked]
)
print(summary)
if path := os.getenv("GITHUB_STEP_SUMMARY"):
    with open(path, "a") as f:
        f.write(summary + "\n")
sys.exit(1 if blocked else 0)
```

Example output:

```text
## SkillScanner (static)

| Skill | Score | Verdict |
| --- | --- | --- |
| `changelog-writer` | 0 | SAFE |
| `pdf-helper` | 100 | DO_NOT_INSTALL |
```

## GitHub Actions Workflow

Save as `.github/workflows/skill-scan.yml`:

```yaml
name: Skill security scan

on:
  pull_request:
    paths: ["skills/**"]

permissions:
  contents: read

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - run: pip install uv

      - name: Scan skills
        env:
          # Optional: enables the agent review. Without it the scan is static-only.
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
        run: |
          uv run --no-project \
            --with "skills-scanner @ git+https://github.com/The-Swarm-Corporation/SkillScanner" \
            python .github/scripts/scan_skills.py skills

      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: skill-reports
          path: skill-reports/
```

### Notes

- **Pin the scanner.** Replace the Git URL with a commit, for example
  `git+https://github.com/The-Swarm-Corporation/SkillScanner@<commit-sha>`, so results are reproducible.
- **Forks.** Pull requests from forks do not receive repository secrets, so they run static-only. This is
  the safe default. Do not switch to `pull_request_target` with a checkout of the pull request's code.
- **Static-only gating.** To keep all content in CI, omit the secret; the static recommendation gates the build.
- **Stricter policy.** Also block `CAUTION`, or block when `risk_assessment.max_issue_severity` is
  `CRITICAL`, by editing `BLOCKED` or the check.

## Gating Through the REST API

If a SkillScanner service is deployed, CI can call it instead of installing the package:

```bash
verdict=$(jq -n --rawfile c skills/my-skill/SKILL.md '{name: "my-skill", content: $c}' \
  | curl -sf -X POST "$SKILLS_SCANNER_URL/v1/scan" -H "Content-Type: application/json" -d @- \
  | jq -r '.overall_assessment.verdict // .risk_assessment.recommendation')
echo "verdict: $verdict"
case "$verdict" in REJECT|DO_NOT_INSTALL) exit 1 ;; esac
```

## Install-Time Gate

For platforms that install skills on behalf of users, scan before installing:

```python
from skills_scanner import SkillScanner

scanner = SkillScanner()

def install_if_allowed(source: str) -> bool:
    report = scanner.scan(source)            # path, URL, or text
    if report.verdict in {"REJECT", "DO_NOT_INSTALL"}:
        return False
    if report.verdict == "CAUTION":
        return request_human_approval(report.to_markdown())   # your approval flow
    return True
```

Store the JSON report with the installed version so decisions can be audited later.
