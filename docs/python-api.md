# Python API

Everything most integrations need is exported from the top-level package:

```python
from skills_scanner import (
    SkillScanner,        # the scanner
    ScanReport,          # the result
    Issue,               # one finding
    RiskAssessment,      # score, severity band, recommendation
    OverallAssessment,   # the agent's verdict and narrative
    Severity,            # LOW / MEDIUM / HIGH / CRITICAL
    Rule, rule,          # custom detection rules
    DEFAULT_RULES,       # the built-in regex rule set
)
```

## `SkillScanner`

```python
SkillScanner(
    use_agent: bool = True,
    model_name: str = "claude-sonnet-5",
    trusted_domains: Iterable[str] = (),
    harmful_terms: Iterable[str] = (),
    extra_rules: Iterable[Rule] = (),
    max_file_bytes: int = 1_000_000,
    max_files: int = 1_000,
    agent_max_chars: int = 150_000,
)
```

| Parameter | Description |
| --- | --- |
| `use_agent` | Run the agent review after static analysis. Each scan method can override it per call. |
| `model_name` | Any [LiteLLM](https://docs.litellm.ai/docs/providers) model identifier supported by Swarms. The matching provider key must be in the environment. |
| `trusted_domains` | Domains exempt from link reputation checks. Subdomains are included: `github.com` also trusts `api.github.com`, but not `raw.githubusercontent.com`. Deceptive-authority (`LK003`) and interpolated-data (`LK004`) checks still apply. |
| `harmful_terms` | Extra words or phrases to flag as `HC100` (HIGH, harmful content). Matching is case-insensitive and whole-word. Blank entries are ignored. |
| `extra_rules` | Additional `Rule` objects appended to `DEFAULT_RULES`. See [Extending](extending.md). |
| `max_file_bytes` | Files larger than this are reported as `OB003` and not read. Applies to `scan()` only. |
| `max_files` | Maximum files read by `scan()`; the rest are reported as `OB005`. |
| `agent_max_chars` | Character budget for file content sent to the agent. Files beyond the budget are truncated or omitted, and the agent is told which. |

The instance holds no per-scan state and can be shared across threads.

### `scan(target, use_agent=None) -> ScanReport`

Scans a skill from a path, a URL, or raw text.

| `target` | Treated as |
| --- | --- |
| `str` starting with `http://` or `https://` | A URL, fetched with `scan_url` |
| `os.PathLike`, or a `str` naming an existing file or directory | A path on disk (`~` is expanded) |
| Single-line `str` without spaces that looks like a path | A missing path: raises `FileNotFoundError` |
| Any other `str` | Skill or prompt text, scanned with `scan_text` |

- `use_agent`: overrides the instance default for this call.
- `report.skill.name` is the `name:` from the `SKILL.md` frontmatter (or from the only file, for single-document scans) if present, otherwise the directory, file, or URL file name.
- Pass a `pathlib.Path` or call `scan_text` / `scan_url` when you want no ambiguity.

### `scan_url(url, use_agent=None) -> ScanReport`

Fetches a skill or prompt document over http(s) and scans it as one file.

```python
report = scanner.scan_url("https://swarms.world/prompt/32d1e7b4-34da-4035-bc05-d18f8e71a2f1.md")
report.skill.name     # "WARP Git Message Skill", from the YAML frontmatter
report.skill.source   # the URL
```

- Hosts that resolve to non-public addresses are refused, on every redirect (up to 3).
- The download is capped at `max_file_bytes`, times out after 15 seconds, and must be text.
- Raises `ValueError` for unsupported, non-public, oversized, or binary targets and `httpx.HTTPError`
  for network failures or error statuses.
- To scan a document on a private network, fetch it yourself and call `scan_text`.

### `scan_files(files, name="skill", source="", use_agent=None) -> ScanReport`

Scans in-memory files, keyed by relative path.

```python
report = scanner.scan_files(
    {"SKILL.md": "...", "scripts/run.sh": "..."},
    name="my-skill",
    source="https://marketplace.example.com/skills/my-skill",
)
```

- `files`: `Mapping[str, str]` of relative path to text. Paths are labels only; nothing is read from disk.
- `source`: recorded in `report.skill.source` (defaults to `name`).
- Size, binary, and symlink checks do not apply; validate input size yourself (the REST API caps requests at 1,000 files and 10 MB).

### `scan_text(text, name="prompt.md", use_agent=None) -> ScanReport`

Scans a single prompt or `SKILL.md`. Equivalent to `scan_files({name: text}, name=name)`.

## `ScanReport`

A Pydantic model. See [Report Schema](report-schema.md) for every field.

| Member | Description |
| --- | --- |
| `verdict` (property) | `overall_assessment.verdict` when the agent ran, otherwise `risk_assessment.recommendation` |
| `to_json(indent=2) -> str` | JSON serialization |
| `to_markdown() -> str` | SkillScanner triage report: source, verdict, risk, bottom line, signal overview, key evidence, diagnosis, guardrails |
| `model_dump()` | Standard Pydantic dictionary export |
| `ScanReport.model_validate_json(s)` | Load a saved report |

## `Issue`

| Field | Type | Description |
| --- | --- | --- |
| `id` | `str` | Rule ID, for example `PI001`, or `SEM1` for agent findings |
| `finding_id` | `str` | Unique ID for this finding, `finding-<hex>` |
| `category` | `str \| None` | Threat category, for example `prompt_injection` |
| `pattern` | `str \| None` | Rule title |
| `severity` | `Severity` | `LOW`, `MEDIUM`, `HIGH`, or `CRITICAL` |
| `confidence` | `float` | 0.0 to 1.0 |
| `location` | `Location` | `file`, `start_line`, `end_line` |
| `finding` | `str \| None` | The matched text (redacted for secrets) |
| `explanation` | `str \| None` | Why it matters; the agent's explanation when confirmed |
| `remediation` | `str \| None` | How to fix it |
| `code_snippet` | `str \| None` | The full source line |
| `intent` | `str \| None` | `malicious`, `negligent`, or `benign` (set by the agent) |
| `tags` | `list[str]` | `llm-unconfirmed`, `semantic` |
| `evidence` | `dict` | Extra data, for example `llm_judgment` |
| `match_fingerprint` | `str \| None` | SHA-256 of rule ID and normalized match, stable across scans |

## `Severity`

A string enum: `Severity.LOW`, `MEDIUM`, `HIGH`, `CRITICAL`, with two helpers:

| Property | Values |
| --- | --- |
| `points` | 5, 10, 25, 50: base score contribution |
| `rank` | 1, 2, 3, 4: for sorting and comparison |

```python
worst = max(report.issues, key=lambda i: i.severity.rank, default=None)
```

## Rules

```python
from skills_scanner import Severity, rule

my_rule = rule(
    "ORG001",                        # unique ID
    "data_exfiltration",             # category
    Severity.HIGH,                   # severity
    "References an internal-only host",
    r"\b[\w-]+\.corp\.example\.com\b",
    confidence=0.8,                  # default 0.8
    redact=False,                    # redact matches in the report
)
```

`rule(id, category, severity, message, pattern, flags=re.IGNORECASE, confidence=0.8, redact=False)`
compiles the pattern and returns a frozen `Rule` dataclass with the same fields. Pass `flags=0` for a
case-sensitive rule.

`skills_scanner.rules.harmful_terms_rule(terms, severity=Severity.HIGH, id="HC100")` builds a whole-word,
case-insensitive rule from a list of terms. `SkillScanner(harmful_terms=...)` uses it for you.

## Lower-Level Functions

These are stable enough for advanced use such as custom pipelines:

| Function | Description |
| --- | --- |
| `skills_scanner.static.analyze_text(text, file, rules, trusted_domains=()) -> list[Issue]` | Static analysis of one text |
| `skills_scanner.fetch.fetch_text(url, max_bytes=1_000_000, allow_private=False) -> str` | Download a document with the same safeguards as `scan_url` |
| `skills_scanner.scanner.assess(issues, components) -> RiskAssessment` | Score a list of issues |
| `skills_scanner.scanner.apply_review(issues, review) -> tuple[list[Issue], OverallAssessment]` | Merge an `AgentReview` into static issues |
| `skills_scanner.agent.AgentReviewer(model_name, max_chars=150_000, max_retries=1).review(files, issues, risk)` | Run the agent review alone |

## Examples

**Block on the worst outcome:**

```python
report = SkillScanner().scan(path)
blocked = report.verdict in {"REJECT", "DO_NOT_INSTALL"}
```

**Audit every installed skill:**

```python
from pathlib import Path
from skills_scanner import SkillScanner

scanner = SkillScanner(use_agent=False)
for skill_dir in sorted(p for p in Path("~/.claude/skills").expanduser().iterdir() if p.is_dir()):
    r = scanner.scan(skill_dir)
    print(f"{r.risk_assessment.score:>3} {r.verdict:<14} {r.skill.name}")
```

**Save and reload a report:**

```python
Path("report.json").write_text(report.to_json())
restored = ScanReport.model_validate_json(Path("report.json").read_text())
```
