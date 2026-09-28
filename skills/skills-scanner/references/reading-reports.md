# Reading SkillScanner Reports

A report is JSON with these top-level keys: `skill`, `risk_assessment`, `components`, `issues`,
`overall_assessment`, `metadata`, `execution_successful`.

## Contents

- [Skill and risk assessment](#skill-and-risk-assessment)
- [Components](#components)
- [Issues](#issues)
- [Overall assessment](#overall-assessment)
- [Metadata](#metadata)
- [How the score works](#how-the-score-works)
- [How the agent review is merged](#how-the-agent-review-is-merged)
- [Decision shortcuts](#decision-shortcuts)

## Skill and Risk Assessment

| Field | Meaning |
| --- | --- |
| `skill.name` | `name:` from the frontmatter of `SKILL.md` (or of the single scanned document), else the directory, file, or URL file name |
| `skill.source` | Path or URL scanned |
| `risk_assessment.score` | 0-100 aggregate |
| `risk_assessment.severity` | Band: `LOW` 0-20, `MEDIUM` 21-50, `HIGH` 51-80, `CRITICAL` 81-100 |
| `risk_assessment.recommendation` | `SAFE` (LOW), `CAUTION` (MEDIUM), `DO_NOT_INSTALL` (HIGH, CRITICAL) |
| `risk_assessment.max_issue_severity` | Worst single issue, or `NONE` |

The band is confidence-weighted, so `severity: MEDIUM` can coexist with `max_issue_severity: HIGH`.
Always look at both.

## Components

One entry per file: `path`, `type` (`skill_manifest`, `script`, `documentation`, `config`, `other`,
`binary`, `oversized`), `lines`, `executable`, `size_bytes`. Read every component with
`executable: true`; they are what an agent might run. `binary` and `oversized` components were not
analyzed.

## Issues

Sorted by severity, then file, then line.

| Field | Meaning |
| --- | --- |
| `id` | Rule ID (see [rules.md](rules.md)); `SEM<n>` for agent findings |
| `finding_id` | Unique per finding |
| `category`, `pattern` | Threat category and rule title |
| `severity`, `confidence` | Rule severity and 0-1 confidence (raised when the agent confirms) |
| `location` | `file`, `start_line`, `end_line` |
| `finding` | Matched text. Invisible characters appear as `\uXXXX` escapes; secrets are redacted |
| `code_snippet` | The full source line, cleaned and redacted |
| `explanation` | Rule title plus context such as `(inside base64-decoded text)`, or the agent's explanation |
| `remediation` | Suggested fix |
| `intent` | `malicious`, `negligent`, or `benign` when the agent judged it |
| `tags` | `llm-unconfirmed` (agent did not confirm; still active) or `semantic` (agent finding) |
| `evidence.llm_judgment` | The agent's reasoning for an unconfirmed issue |
| `match_fingerprint` | Stable hash of rule and match, for baselines |

Findings inside concealed content are reported at the line where the hidden or encoded payload sits.

## Overall Assessment

Present only when the agent review ran (`null` otherwise):
`verdict` (`APPROVE` / `CAUTION` / `REJECT`), `risk_level`, `summary`, `install_posture`,
`sensitive_surface`, `diagnosis`, `guardrails`.

If the agent returned `APPROVE` while a HIGH or CRITICAL issue it did not explicitly clear remained,
SkillScanner already lowered the verdict to `CAUTION`.

## Metadata

| Field | Meaning |
| --- | --- |
| `llm_requested` | The agent review was requested |
| `llm_available` | The agent review completed and was merged |
| `meta_analysis_applied` | Same as above, kept for schema compatibility |
| `model` | Model used |
| `llm_error` | Why the review did not complete, for example a missing key (`model ... returned no response`) or unusable output (`agent returned an invalid review`) |
| `has_executable_scripts` | Any executable component |

`llm_requested: true` and `llm_available: false` means the report is static-only.

## How the Score Works

- Points per issue: CRITICAL 50, HIGH 25, MEDIUM 10, LOW 5, multiplied by confidence.
- Per rule ID, occurrences count 1, 0.5, 0.25, then nothing.
- Issues in executable files count 1.3x.
- A HIGH issue with confidence of at least 0.8 floors the score at 21; a CRITICAL one at 51.
- Capped at 100.

Examples: one confident HIGH instruction override scores 21 (`CAUTION`); a shell-profile write inside
an install script scores 26 (`CAUTION`); a confident CRITICAL finding scores at least 51
(`DO_NOT_INSTALL`); a malware term in a detection skill scores 5 (`SAFE`).

## How the Agent Review Is Merged

| Agent judgment on a static issue | Effect |
| --- | --- |
| Real vulnerability, confidence of at least 0.6 | Confirmed: confidence can rise; explanation, remediation, and intent come from the agent |
| Anything else, or no judgment | Unchanged and tagged `llm-unconfirmed`; the reasoning goes to `evidence.llm_judgment` |

Agent-only threats are added as `SEM1`, `SEM2`, ... Static issues are never removed or downgraded, and
the score is recomputed after merging.

## Decision Shortcuts

| Signal | Usual outcome |
| --- | --- |
| Any `UN001` or findings `(inside hidden Unicode tag text)` | `REJECT` |
| Instructions or commands `(inside base64-decoded text)` | `REJECT` unless clearly benign data |
| Confirmed `DC001`, `EX001`, `HC003`, `CA001` with transmission, `LK007` used for uploads | `REJECT` |
| `SL001` or `OB004` | `REJECT` unless removed or replaced with source |
| `PS001` / `PS002` that is disclosed and user-confirmed | `CAUTION` with guardrails |
| Only `LK011`, `LK012`, `HC002`, or `DC005` in clearly benign context | `APPROVE` after review |
| Agent did not run | Your own review decides; state lower confidence |
