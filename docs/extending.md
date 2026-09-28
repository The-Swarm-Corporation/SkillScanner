# Extending

Tailor SkillScanner to your organization's policy with custom rules, harmful terms, trusted domains,
and baselines.

## Custom Rules

```python
from skills_scanner import Severity, SkillScanner, rule

internal_hosts = rule(
    "ORG001",
    "data_exfiltration",
    Severity.HIGH,
    "References an internal-only host",
    r"\b[\w-]+\.corp\.example\.com\b",
)

prod_db = rule(
    "ORG002",
    "credential_access",
    Severity.CRITICAL,
    "Connection string for the production database",
    r"postgres(?:ql)?://[^\s]*@prod-db\.",
    confidence=0.9,
    redact=True,
)

scanner = SkillScanner(extra_rules=[internal_hosts, prod_db])
```

`rule(id, category, severity, message, pattern, flags=re.IGNORECASE, confidence=0.8, redact=False)`:

| Argument | Guidance |
| --- | --- |
| `id` | Unique. Use your own prefix (for example `ORG`) to avoid collisions with built-in IDs. Scoring applies diminishing returns per ID. |
| `category` | Reuse a built-in category to get its remediation text; a new category is fine but has no default remediation. |
| `severity` | CRITICAL for clear compromise, HIGH for likely serious harm, MEDIUM for suspicious but plausibly legitimate, LOW for hygiene. |
| `message` | Short title shown as `pattern` and `explanation`. |
| `pattern` | A regular expression run over the full file text. |
| `flags` | Case-insensitive by default; pass `flags=0` for case-sensitive, or add `re.MULTILINE` when using `^` and `$` per line. |
| `confidence` | Your estimate of precision (0 to 1). It scales the score contribution; 0.8 or more triggers the HIGH and CRITICAL score floors. |
| `redact` | Hide the match in `finding` and `code_snippet`. Use for secrets. |

### Writing Good Patterns

- Anchor on specific phrasing with word boundaries (`\b`) rather than single common words.
- Bound gaps between terms: `[^\n.]{0,40}?` keeps a match within one clause and one line.
- Avoid nested unbounded quantifiers such as `(a+)+`; patterns run over untrusted input.
- A rule reports at most one issue per line, and the first match position determines the line.
- Prefer several narrow rules with accurate confidence over one broad rule.

### Disabling a Built-In Rule

`scanner.rules` is a tuple you can filter:

```python
scanner = SkillScanner()
scanner.rules = tuple(r for r in scanner.rules if r.id != "HC002")
```

## Harmful Terms

For word lists, such as internal code names or banned vocabulary, use `harmful_terms`:

```python
scanner = SkillScanner(harmful_terms=["project-nightingale", "internal only", "do not distribute"])
```

Terms are matched whole-word and case-insensitive as rule `HC100` (HIGH, harmful content). To choose a
different severity or ID, build the rule yourself:

```python
from skills_scanner import Severity
from skills_scanner.rules import harmful_terms_rule

codenames = harmful_terms_rule(["nightingale", "bluebird"], severity=Severity.MEDIUM, id="ORG100")
scanner = SkillScanner(extra_rules=[codenames])
```

## Trusted Domains

```python
scanner = SkillScanner(trusted_domains=["github.com", "docs.python.org", "example.com"])
```

Links to these domains and their subdomains skip reputation checks (`LK005` to `LK012`). Deceptive
authority (`LK003`) and interpolated data (`LK004`) are still reported, because they are dangerous on
any domain. Be conservative: trusting a domain that hosts user content (for example a paste or file
hosting service) disables useful checks.

## Baselines

Every issue has a `match_fingerprint`: a SHA-256 of its rule ID and normalized match, stable across
scans. Use it to accept reviewed findings and surface only new ones:

```python
import json
from pathlib import Path
from skills_scanner import SkillScanner
from skills_scanner.scanner import assess

accepted = set(json.loads(Path("skill-baseline.json").read_text()))

report = SkillScanner().scan("skills/my-skill")
new_issues = [i for i in report.issues if i.match_fingerprint not in accepted]
risk = assess(new_issues, report.components)   # rescore without the accepted issues

# After review, record the current findings as accepted:
Path("skill-baseline.json").write_text(json.dumps(sorted(
    i.match_fingerprint for i in report.issues if i.match_fingerprint
)))
```

Agent findings (`SEM*`) have no fingerprint and are always shown.

## Testing Rules

Keep a positive and a negative example for every custom rule:

```python
import pytest
from skills_scanner import SkillScanner
from my_policy import internal_hosts

scanner = SkillScanner(use_agent=False, extra_rules=[internal_hosts])

@pytest.mark.parametrize("text", ["Upload to build.corp.example.com", "see wiki.corp.example.com/page"])
def test_flags_internal_hosts(text):
    assert "ORG001" in {i.id for i in scanner.scan_text(text).issues}

def test_ignores_public_hosts():
    assert "ORG001" not in {i.id for i in scanner.scan_text("see docs.example.com").issues}
```

## Custom Pipelines

The building blocks are importable for advanced integrations:

```python
from skills_scanner.static import analyze_text
from skills_scanner.scanner import assess
from skills_scanner.rules import DEFAULT_RULES

issues = analyze_text(text, "SKILL.md", DEFAULT_RULES, trusted_domains=["github.com"])
risk = assess(issues, components=[])
```
