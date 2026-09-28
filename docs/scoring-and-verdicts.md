# Scoring and Verdicts

SkillScanner produces two outcomes:

- a **recommendation** from the static risk score: `SAFE`, `CAUTION`, or `DO_NOT_INSTALL`
- a **verdict** from the agent review, when it runs: `APPROVE`, `CAUTION`, or `REJECT`

`report.verdict` returns the agent verdict when available and the recommendation otherwise.

## Risk Score

The score is computed by `skills_scanner.scanner.assess()`:

1. **Base points by severity:** CRITICAL 50, HIGH 25, MEDIUM 10, LOW 5.
2. **Confidence weighting:** points are multiplied by the issue's confidence (0 to 1). Issues with
   confidence 0 contribute nothing but stay in the report.
3. **Diminishing returns per rule:** issues are grouped by rule ID. Within a group, sorted by severity,
   the first occurrence counts fully, the second at 0.5, the third at 0.25, and the rest not at all.
   Repeated matches of one pattern cannot inflate the score on their own.
4. **Executable multiplier:** issues in executable files (scripts, shebang files, executable binaries)
   count 1.3x.
5. **Floors:** a HIGH issue with confidence at least 0.8 raises the score to at least 21, and a CRITICAL
   issue with confidence at least 0.8 raises it to at least 51. The recommendation is never softer than
   the worst confident issue warrants.
6. **Cap:** the result is truncated to an integer and capped at 100.

### Bands

| Score | `severity` | `recommendation` |
| --- | --- | --- |
| 0-20 | `LOW` | `SAFE` |
| 21-50 | `MEDIUM` | `CAUTION` |
| 51-80 | `HIGH` | `DO_NOT_INSTALL` |
| 81-100 | `CRITICAL` | `DO_NOT_INSTALL` |

`max_issue_severity` reports the single worst issue independently of the score, so a report can show
`severity: MEDIUM` with `max_issue_severity: HIGH`.

### Worked Examples

These are real results from `SkillScanner(use_agent=False)`:

| Input | Issues | Calculation | Score | Recommendation |
| --- | --- | --- | --- | --- |
| A malware term in a detection skill | HC002 (MEDIUM, 0.5) | 10 x 0.5 = 5 | 5 | `SAFE` |
| Ten URL-shortener links | 10 x LK008 (MEDIUM, 0.6) | 6 + 3 + 1.5, rest ignored = 10.5 | 10 | `SAFE` |
| One instruction override | PI001 (HIGH, 0.8) | 25 x 0.8 = 20, HIGH floor 21 | 21 | `CAUTION` |
| Instruction override plus a shortener | PI001, LK008 | 20 + 6 = 26 | 26 | `CAUTION` |
| Reverse shell written in `SKILL.md` | DC001 (CRITICAL, 0.8) | 50 x 0.8 = 40, CRITICAL floor 51 | 51 | `DO_NOT_INSTALL` |
| Reverse shell in `scripts/x.sh` | DC001 (CRITICAL, 0.8) | 50 x 0.8 x 1.3 = 52 | 52 | `DO_NOT_INSTALL` |

### After the Agent Review

The score is recomputed after merging the agent's judgments:

- A confirmed issue's confidence becomes the higher of the rule's and the agent's, which can raise the score.
- Unconfirmed issues keep their original confidence; they are never discounted.
- Semantic findings (`SEM1`, ...) are added with the agent's severity and confidence, each under its own ID.

## Agent Verdict

The agent applies this rubric:

| Verdict | Meaning |
| --- | --- |
| `APPROVE` | No HIGH or CRITICAL issues, no unexplained sensitive behavior, and the source matches the stated purpose |
| `CAUTION` | Sensitive behavior exists, but it is documented, necessary, bounded, and controllable by the user |
| `REJECT` | Malicious or deceptive behavior, unexplained HIGH or CRITICAL issues, hidden prompt injection, credential theft, unknown exfiltration, obfuscated execution, persistence, or a clear mismatch between description and behavior |

It treats the static score as risk posture, not as the verdict:

| Score | Default posture |
| --- | --- |
| 0-20 | Usually acceptable after a quick source review |
| 21-35 | Acceptable only when the issues are clearly explained |
| 36-50 | Manual review required; default to `CAUTION` unless every concern is explained |
| 51-80 | Default to `REJECT` unless every sensitive behavior is necessary |
| 81-100 | Default to `REJECT` |

**Approval guard.** If the agent returns `APPROVE` while any HIGH or CRITICAL issue remains that it did
not explicitly judge as not a vulnerability, SkillScanner lowers the verdict to `CAUTION`.

## Recommended Policy

| Outcome | Action |
| --- | --- |
| `APPROVE` or `SAFE` | Allow |
| `CAUTION` | Require human review and sign-off; apply the report's `guardrails` |
| `REJECT` or `DO_NOT_INSTALL` | Block |
| Agent requested but `metadata.llm_available` is `false` | Treat as static-only; require human review for anything above `SAFE` |

For stricter environments, also block when `max_issue_severity` is `CRITICAL`, regardless of the verdict.
