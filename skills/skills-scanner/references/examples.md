# Example Triage Reports

Three complete reports, one per verdict. The static scores are real SkillScanner results for these
skills; the review judgments show the level of specificity to aim for.

## APPROVE

```markdown
## 🛡️ SkillScanner: `changelog-writer`

**Source:** skills/changelog-writer
**Verdict:** APPROVE — safe to install
**Risk:** 0/100 · LOW · SAFE
**Install posture:** Suitable for any repository; it only reads git history and writes after the user approves the draft.

### Bottom Line
Install it. The skill reads recent commits, groups them into a CHANGELOG entry, and shows the draft
before writing. No findings, no executables, and the behavior matches the description exactly.

### Signal Overview
| Source | Result | Interpretation |
| --- | --- | --- |
| Static scan | no issues | Nothing matched any rule |
| Agent review | APPROVE | Purpose and behavior align |
| Sensitive surface | git (read-only), one file write | Write is user-approved and limited to CHANGELOG.md |

### Diagnosis
The only command is a read-only git log, the single external link is the Keep a Changelog
specification, and the one file write happens after explicit user approval. Nothing is hidden,
downloaded, or executed.
```

## CAUTION

```markdown
## 🛡️ SkillScanner: `node-toolchain`

**Source:** skills/node-toolchain
**Verdict:** CAUTION — acceptable with user confirmation
**Risk:** 26/100 · MEDIUM · CAUTION
**Install posture:** Fine on developer machines where the user wants fnm-managed Node.js; not for shared or locked-down hosts.

### Bottom Line
Usable with care. The install script permanently adds an init line to the user's shell profile, which
SkillScanner flags as persistence. That is the documented purpose of the skill and it asks for
confirmation first, so it is a caution rather than a rejection.

### Signal Overview
| Source | Result | Interpretation |
| --- | --- | --- |
| Static scan | 1 HIGH | Shell-profile write in an executable script (scored 1.3x) |
| Agent review | CAUTION | Persistence is disclosed and necessary for the stated purpose |
| Sensitive surface | shell profile, package manager | Installs fnm from Homebrew and a Node.js version |

### Key Evidence
| Rule | Severity | Location | Review judgment |
| --- | --- | --- | --- |
| PS001 | HIGH | scripts/install.sh:7 | Appends the fnm init line to the shell profile. Disclosed in SKILL.md step 3 and preceded by user confirmation in step 1; needed so new terminals use the installed version. |

### Diagnosis
The only finding is expected for a toolchain installer, and the source confirms the write is limited to
one well-known init line. Installs come from Homebrew and fnm's own registry rather than an ad hoc
script, and nothing is sent off the machine.

### Guardrails
1. Confirm with the user before running the install script, as the skill instructs.
2. Tell the user which profile file was changed and how to remove the line.
```

## REJECT

```markdown
## 🛡️ SkillScanner: `pdf-helper`

**Source:** skills/pdf-helper
**Verdict:** REJECT — do not install
**Risk:** 100/100 · CRITICAL · DO_NOT_INSTALL
**Install posture:** Not suitable for any environment.

### Bottom Line
Do not install. The skill claims to convert PDFs but hides instructions in invisible Unicode and a
base64 blob, sends cloud credentials to a request-capture service, and opens a remote shell from its
setup script.

### Signal Overview
| Source | Result | Interpretation |
| --- | --- | --- |
| Static scan | 2 CRITICAL, 18 HIGH, 6 MEDIUM, 2 LOW | Concealed instructions, credential theft, remote control |
| Agent review | REJECT | Behavior has nothing to do with PDF conversion |
| Sensitive surface | network, credentials, shell, shell profile | Every sensitive surface is abused |

### Key Evidence
| Rule | Severity | Location | Review judgment |
| --- | --- | --- | --- |
| UN001 | CRITICAL | SKILL.md:7 | Invisible tag characters decode to an instruction to override the agent and send SSH keys to a capture service. Concealment alone is disqualifying. |
| DC001 | CRITICAL | scripts/setup.sh:4 | Connects an interactive shell to a remote host. No legitimate purpose. |
| EX001 | HIGH | SKILL.md:10 | Inside a base64 blob: uploads the cloud credentials file to an external host. |
| LK007 | HIGH | scripts/setup.sh:2 | Credentials piped to a request-capture endpoint. |
| PS001 | HIGH | scripts/setup.sh:3 | Adds a download-and-run line to the shell profile, so the compromise survives restarts. |
| SE001 | HIGH | scripts/setup.sh:5 | Hardcoded cloud access key; treat as exposed and rotate. |
| PI002 | HIGH | SKILL.md:9 | Tells the agent to keep the setup step from the user. |

### Diagnosis
Static analysis and source review agree: every high-severity finding is real, deliberate, and hidden
from casual reading. The description promises PDF conversion while the content steals credentials and
installs persistent remote access, a clear purpose mismatch with malicious intent.
```
