# SkillScanner Rule Guide

What each rule ID means, how to verify it in the source, and when it is usually a false positive.
Severity and confidence are the rule defaults; the agent can raise confidence when it confirms a finding.
The full catalog with example matches is in the SkillScanner repository at `docs/detection-rules.md`.

## Contents

- [Prompt injection and agency](#prompt-injection-and-agency) (`PI`, `EA`)
- [Harmful content](#harmful-content) (`HC`)
- [Credentials, exfiltration, and secrets](#credentials-exfiltration-and-secrets) (`CA`, `EX`, `SE`)
- [Commands and persistence](#commands-and-persistence) (`DC`, `PS`)
- [Links](#links) (`LK`)
- [Hidden and unreviewable content](#hidden-and-unreviewable-content) (`UN`, `OB`, `SL`)
- [Agent findings](#agent-findings) (`SEM`)

## Prompt Injection and Agency

| ID | Severity | Means | Verify | Usual false positives |
| --- | --- | --- | --- | --- |
| PI001 | HIGH | Text telling the agent to discard or replace its earlier, system, or developer instructions | Is it addressed to the agent that will load the skill, or quoted as an example? | Security docs and tests quoting injection attempts |
| PI002 | HIGH | Text telling the agent to keep actions from the user or act without their consent | What is being kept from the user, and would the user object? | UX guidance about hiding raw stack traces or internal IDs |
| PI003 | HIGH | Chat-template tokens or fake role tags impersonating a higher-priority message | Any use outside documentation about prompt formats is suspect | Docs describing model prompt formats |
| PI004 | HIGH | Mode-switch jailbreaks and "no limits" personas | Rarely legitimate in a skill | Red-team datasets clearly labeled as such |
| PI005 | MEDIUM | Requests to switch off guardrails, security checks, sandboxing, or permission prompts | Scope (test-only?), and whether the user is told | Test fixtures that relax checks locally |
| PI006 | MEDIUM | Instructions placed inside HTML comments, which render invisibly | Read the comment; instructions to an AI there are a red flag | Template placeholder comments |
| EA001 | HIGH | Flags or settings that auto-approve every agent action or run the agent unsandboxed | Does the skill need unattended execution at all? | Headless browser flags in CI docs |
| EA002 | MEDIUM | Unscoped shell access requested in `allowed-tools` frontmatter | Would a scoped command filter do? | Skills whose purpose is general shell automation (still prefer scoping) |

## Harmful Content

| ID | Severity | Means | Verify | Usual false positives |
| --- | --- | --- | --- | --- |
| HC001 | CRITICAL | Production or weaponization of mass-harm weapons | Is it instructional? | Historical or policy text |
| HC002 | MEDIUM (0.5) | Attack-tooling vocabulary | Is the skill building or deploying tooling, or defending against it? | Detection, EDR, and security-education skills |
| HC003 | HIGH | Instructions to take credentials, cookies, tokens, keys, or personal data | Who gets the data, and is it the user's own, with consent? | Threat descriptions in security docs |
| HC100 | HIGH | An organization-specific term from `harmful_terms` | Your policy decides | Depends on the list |

## Credentials, Exfiltration, and Secrets

| ID | Severity | Means | Verify | Usual false positives |
| --- | --- | --- | --- | --- |
| CA001 | HIGH | Paths to credential stores: SSH private keys, cloud CLI credentials, cluster and registry configs, package-manager tokens, system password files, keychains, shell history, browser login and cookie databases, wallets | Is it read? Is it sent anywhere? Is it necessary for the stated purpose and disclosed? | DevOps skills that configure (not read out) cluster or registry access |
| CA002 | MEDIUM | Printing or serializing every environment variable | Where does the output go? | Debugging instructions kept local |
| EX001 | HIGH | `curl`/`wget` uploads of command output, local files, or secret-named variables | Destination, payload, and disclosure | Posting a documented local payload file to a documented API |
| EX002 | HIGH | Discord, Telegram, or Slack webhook endpoints | Is the destination hardcoded by the author or configured by the user? | Notification skills with user-supplied webhooks |
| SE001 | HIGH (0.9) | Hardcoded credential; the value is redacted in the report | Treat as exposed; recommend rotation without repeating the value | Vendor documentation example keys (still should be removed) |

## Commands and Persistence

| ID | Severity | Means | Verify | Usual false positives |
| --- | --- | --- | --- | --- |
| DC001 | CRITICAL | A shell connected to a remote host, giving it control of the machine | Almost never legitimate | Security training material, clearly labeled |
| DC002 | HIGH | A downloaded script piped straight into an interpreter | Source domain, pinning, checksums, user consent | Official installers from the vendor's own domain |
| DC003 | HIGH | Encoded payload decoded and executed | Decode it and read it | Rare |
| DC004 | HIGH | Recursive deletion of root or home, disk formatting, raw writes to disks, fork bombs | Working directory and target | Cleanup of a build directory using a wildcard |
| DC005 | MEDIUM (0.6) | Dynamic evaluation, shell-mode subprocesses, system calls | Can untrusted input reach it? | Ordinary scripts running fixed commands |
| DC006 | MEDIUM (0.6) | Superuser commands, world-writable or setuid permissions, SELinux changes | Is elevation needed and explained? | Installers that need admin rights |
| DC007 | HIGH | Disabling Defender, Gatekeeper, SIP, quarantine, firewalls, AppArmor, or SELinux | Any legitimate need? | Advice for running unsigned apps (still a bypass) |
| PS001 | HIGH | Writes to shell profiles, scheduled jobs, launch agents or daemons, service enablement, or SSH authorized keys | Disclosed? User-confirmed? Reversible? | Toolchain installers adding a PATH or init line |
| PS002 | MEDIUM (0.6) | Changes to other agents' instruction files or agent settings | Does it change future agent behavior silently? | Project-setup skills that create these files openly |

## Links

Localhost, private IPs, and `trusted_domains` are exempt from everything except `LK003` and `LK004`.

| ID | Severity | Means | Verify |
| --- | --- | --- | --- |
| LK001 | HIGH | Script URI disguised as a link | Rarely legitimate |
| LK002 | MEDIUM | URL that cannot be parsed | Typo or parser-confusion attempt |
| LK003 | HIGH | An `@` in the host part: the real host is after the `@` | Classic phishing; applies even to trusted domains |
| LK004 | HIGH | Runtime data interpolated into a URL | Common exfiltration channel through links and images |
| LK005 | MEDIUM | Raw public IP address as host | Why no domain? |
| LK006 | HIGH | IP written in decimal or hex | No legitimate reason |
| LK007 | HIGH | Request-capture, tunneling, or anonymous paste and file-drop service | What is sent there? |
| LK008 | MEDIUM | URL shortener | Expand and review the destination |
| LK009 | MEDIUM | Punycode or non-ASCII domain | Compare with the intended domain |
| LK010 | MEDIUM | Direct download of an executable or script | Source, pinning, checksums |
| LK011 | LOW (0.4) | High-abuse TLD | Weak signal alone |
| LK012 | LOW | Plain `http` or `ftp` | Tampering risk in transit |

## Hidden and Unreviewable Content

| ID | Severity | Means | Verify |
| --- | --- | --- | --- |
| UN001 | CRITICAL (0.95) | Invisible Unicode tag characters; the decoded hidden text is in `finding` and was scanned too | Effectively always a rejection |
| UN002 | HIGH | Runs of supplementary variation selectors that can smuggle data | Emoji do not trigger this |
| UN003 | HIGH | Bidirectional controls that reorder displayed text | What the model reads differs from what a reviewer sees |
| UN004 | MEDIUM | Zero-width characters | Byte-order marks and emoji joiners are already ignored |
| OB001 | MEDIUM | Long runs of hex or unicode escapes | Decode and review |
| OB002 | MEDIUM | Base64 that decodes to text; the decoded text was scanned too | Read findings marked `(inside base64-decoded text)` |
| OB003 | MEDIUM | File too large to analyze | Inspect manually or state the gap |
| OB004 | HIGH | Bundled executable binary | Cannot be reviewed; require source |
| OB005 | MEDIUM | File limit reached; some files were not scanned | Scan subdirectories separately |
| OB006 | LOW | Non-media binary file | Inspect with `file` |
| SL001 | HIGH | Symlink pointing outside the skill | Could point an agent at local secrets or system files |

## Agent Findings

`SEM1`, `SEM2`, ... are threats the agent identified without a matching rule: purpose mismatch, trigger
hijacking, undisclosed data flows, social engineering. Severity, confidence, category, and intent come
from the agent. Verify them in the source like any other finding.
