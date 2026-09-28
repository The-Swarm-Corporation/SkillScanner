# Security Model

SkillScanner is a pre-installation gate: it inspects skills and prompts before an agent trusts them.
This page describes what it protects against, the guarantees it provides, and its limits.

## Threat Model

**Assets:** the user's machine, files, credentials, and accounts, and the integrity of the agent's
behavior.

**Adversary:** the author of a skill or prompt, who controls every byte the scanner reads. The adversary
may try to:

- make an agent run harmful commands, exfiltrate data, or persist access
- hide instructions from human reviewers (invisible Unicode, HTML comments, encoded payloads)
- mislead the scanner's agent review with instructions aimed at it
- use the scanner itself as a pivot (symlinks to local files, URLs pointing at internal services)

## Guarantees

| Guarantee | How it is enforced |
| --- | --- |
| Scanned content is never executed | Analysis is regex, parsing, and decoding only. Scripts, installers, and hooks are read as text. |
| Local files outside the target are never read | Symlinks are not followed; symlinks escaping the root are reported as `SL001`. |
| Internal services are not reachable through URL scans | Every URL, including each redirect, must resolve to a public IP address. |
| Resource use is bounded | File count, file size, fetched document size, request size, and fetch timeouts are capped. |
| The review agent cannot act | It has no tools and runs a single loop. Injected content can only influence its opinion. |
| Findings cannot be hidden by the agent | The merge is append-only: static issues are never removed or downgraded. |
| A skill cannot supply its own verdict | Agent output is accepted only if the model produced it; a failed call cannot be replaced by JSON embedded in the content. |
| Approval requires explained evidence | An `APPROVE` with unexplained HIGH or CRITICAL issues is lowered to `CAUTION`. |
| Secrets are not propagated | Matches of `SE001` are redacted in `finding` and `code_snippet`. |
| Hidden text is visible in reports | Invisible characters are escaped in evidence, and tag-character text is decoded. |

## Data Handling

| Mode | Data leaving the machine |
| --- | --- |
| Static (`use_agent=False`, `/v1/scan/static`) | None, except the document fetch itself for URL targets |
| End-to-end (`use_agent=True`, `/v1/scan`) | File contents (up to `agent_max_chars`) sent to the configured model provider |

Swarms framework telemetry is enabled by default; set `SWARMS_TELEMETRY_ON=false` to disable it. Swarms
also creates a runtime workspace directory (`WORKSPACE_DIR`, default `agent_workspace` in the working
directory) and an empty `~/.swarms/conversations` directory. SkillScanner does not persist scanned
content or reports to disk; storing reports is up to the caller.

## Limitations

- **Static rules are heuristics.** They favor recall and can miss novel phrasing or match security
  documentation that describes attacks. The agent review improves precision but depends on the model.
- **Prompt injection against the reviewer is mitigated, not eliminated.** Tokenized boundaries, explicit
  instructions, the append-only merge, and the approval guard limit the damage, but a manipulated
  review can still produce a weaker narrative. Always read the evidence for HIGH and CRITICAL issues.
- **Not a sandbox.** SkillScanner does not constrain a skill after installation. Pair it with
  least-privilege agent permissions and user approval for sensitive actions.
- **Point-in-time.** A URL or repository can change after it is scanned. Pin the reviewed version (a
  commit SHA or content hash) and rescan on update.
- **DNS rebinding.** Addresses are validated before each request; a host that changes its DNS answer
  between validation and connection could bypass the check. Deploy the service with egress controls
  when scanning arbitrary URLs.
- **Binary and oversized files are not analyzed.** They are reported (`OB003`, `OB004`, `OB006`) so a
  reviewer can decide.
- **The HTTP service has no authentication or rate limiting.** Run it behind a gateway. See
  [Deployment](deployment.md#production-hardening).

## Reporting a Vulnerability

Please report security issues privately through the repository's
[Security tab](https://github.com/The-Swarm-Corporation/SkillScanner/security) or by contacting the
maintainers directly, rather than opening a public issue.
