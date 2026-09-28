"""Static detection rules and link-reputation data.

Each rule is a regex run over the full text of a file. Add a rule by appending
to ``DEFAULT_RULES`` or by passing ``extra_rules`` to ``SkillScanner``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from skills_scanner.models import Severity


@dataclass(frozen=True)
class Rule:
    id: str
    category: str
    severity: Severity
    message: str
    pattern: re.Pattern[str]
    confidence: float = 0.8
    redact: bool = False


def rule(
    id: str,
    category: str,
    severity: Severity,
    message: str,
    pattern: str,
    flags: int = re.IGNORECASE,
    confidence: float = 0.8,
    redact: bool = False,
) -> Rule:
    return Rule(
        id, category, severity, message, re.compile(pattern, flags), confidence, redact
    )


def harmful_terms_rule(
    terms: list[str], severity: Severity = Severity.HIGH, id: str = "HC100"
) -> Rule:
    """Build a rule that flags any of ``terms`` as whole words."""
    alternation = "|".join(re.escape(t) for t in sorted(terms, key=len, reverse=True))
    return rule(
        id,
        "harmful_content",
        severity,
        "Custom harmful term",
        rf"\b(?:{alternation})\b",
    )


C, H, M, L = Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW

DEFAULT_RULES: tuple[Rule, ...] = (
    # Prompt injection
    rule(
        "PI001",
        "prompt_injection",
        H,
        "Instruction override",
        r"\b(?:ignore|disregard|forget|override)\b[^\n.]{0,40}?\b(?:previous|prior|above|earlier|all|any|system|developer|original)\b"
        r"[^\n.]{0,20}?\b(?:instructions?|prompts?|rules|guidelines|directives|messages)\b",
    ),
    rule(
        "PI002",
        "prompt_injection",
        H,
        "Instructs the agent to hide actions from the user",
        r"\b(?:do not|don't|never)\s+(?:tell|inform|mention|reveal|show|notify|alert|ask)\b[^\n.]{0,20}?\b(?:the\s+)?(?:user|human|operator)\b"
        r"|\bwithout\s+(?:the\s+)?(?:user|human|operator)(?:'s)?\s+(?:knowing|knowledge|noticing|consent|permission|approval)",
    ),
    rule(
        "PI003",
        "prompt_injection",
        H,
        "Chat-template or role delimiter spoofing",
        r"<\|im_(?:start|end)\|>|<\|(?:system|assistant|user|endoftext)\|>|\[/?INST\]|<</?SYS>>|</?(?:system|system_prompt)>",
    ),
    rule(
        "PI004",
        "prompt_injection",
        H,
        "Jailbreak persona or mode switch",
        r"\b(?:developer|god|jailbreak|jailbroken|unrestricted|dan)\s+mode\b|\bdo anything now\b"
        r"|\b(?:act|behave|respond)\s+as\s+(?:an?\s+)?(?:unrestricted|unfiltered|uncensored|jailbroken)\b",
    ),
    rule(
        "PI005",
        "prompt_injection",
        M,
        "Asks the agent to bypass safety or security controls",
        r"\b(?:bypass|disable|ignore|circumvent|turn off|skip)\b[^\n.]{0,30}?\b(?:safety|guardrails?|content (?:policy|filters?)"
        r"|restrictions|security (?:checks?|controls?|warnings?)|sandbox(?:ing)?|permission (?:prompts?|checks?))\b",
        confidence=0.6,
    ),
    rule(
        "PI006",
        "prompt_injection",
        M,
        "Instructions hidden in an HTML comment",
        r"<!--(?:(?!-->).){0,2000}?\b(?:ignore|instructions?|assistant|you must|you should|execute|run the|send|do not tell)\b(?:(?!-->).)*-->",
        re.IGNORECASE | re.DOTALL,
    ),
    # Excessive agency
    rule(
        "EA001",
        "excessive_agency",
        H,
        "Disables agent permission prompts or sandboxing",
        r"--dangerously-skip-permissions|\bbypassPermissions\b|--no-sandbox\b|--yolo\b|\bauto[-_ ]?approve\s*[:=]\s*true",
    ),
    rule(
        "EA002",
        "excessive_agency",
        M,
        "Skill requests unrestricted shell access",
        r"^allowed[-_]tools\s*:[^\n]*(?:\bBash\b(?!\()|[\"']\*[\"'])",
        re.IGNORECASE | re.MULTILINE,
    ),
    # Harmful content
    rule(
        "HC001",
        "harmful_content",
        C,
        "Weapons of mass harm",
        r"\b(?:synthesi[sz]e|manufactur\w*|produc\w*|weaponi[sz]\w*|make|build|cultur\w*)\b[^\n.]{0,40}?"
        r"\b(?:sarin|vx|tabun|soman|novichok|ricin|anthrax|botulinum|nerve agents?|chemical weapons?|bio-?weapons?"
        r"|biological weapons?|dirty bombs?|nuclear (?:weapons?|devices?))\b",
    ),
    rule(
        "HC002",
        "harmful_content",
        M,
        "Malware or attack tooling term",
        r"\b(?:ransomware|keyloggers?|info-?stealers?|credential stealers?|rootkits?|botnets?|cryptojack\w*"
        r"|reverse shells?|bind shells?|remote access trojans?|phishing (?:kits?|pages?))\b",
        confidence=0.5,
    ),
    rule(
        "HC003",
        "harmful_content",
        H,
        "Instructs theft of credentials or personal data",
        r"\b(?:steal|harvest|exfiltrate|scrape|dump)\b[^\n.]{0,30}?\b(?:passwords?|credentials|cookies|session tokens?"
        r"|api keys?|private keys?|seed phrases?|credit cards?|ssns?)\b",
    ),
    # Credential access
    rule(
        "CA001",
        "credential_access",
        H,
        "References a sensitive credential or secret store",
        r"~/\.ssh\b|\bid_(?:rsa|ed25519|ecdsa|dsa)\b|\.aws/credentials|\.config/gcloud|\.kube/config|\.docker/config\.json"
        r"|\.netrc\b|\.npmrc\b|\.pypirc\b|\.git-credentials|/etc/(?:passwd|shadow)\b|Library/Keychains|login\.keychain"
        r"|\.(?:bash|zsh)_history\b|\bLogin Data\b|\bCookies\.sqlite\b|wallet\.dat\b",
    ),
    rule(
        "CA002",
        "credential_access",
        M,
        "Dumps all environment variables",
        r"\bprintenv\b|(?:^|[;&|]\s*)env\s*(?:\||>|$)|\bdict\(os\.environ\)|os\.environ\.(?:items|copy)\(\)"
        r"|json\.dumps\(\s*(?:dict\()?os\.environ|JSON\.stringify\(\s*process\.env\s*\)|\bGet-ChildItem\s+env:",
        re.IGNORECASE | re.MULTILINE,
        confidence=0.7,
    ),
    # Data exfiltration
    rule(
        "EX001",
        "data_exfiltration",
        H,
        "Uploads local data or secrets over the network",
        r"\b(?:curl|wget)\b[^\n]*?(?:\s(?:-d|--data(?:-binary|-raw|-urlencode)?|-F|--form|-T|--upload-file|--post-(?:data|file))\b)"
        r"[^\n]*?(?:\$\(|`|@[~/.$]|\$\{?\w*(?:KEY|TOKEN|SECRET|PASS\w*|CRED\w*)\b)",
    ),
    rule(
        "EX002",
        "data_exfiltration",
        H,
        "Sends data to a messaging webhook",
        r"discord(?:app)?\.com/api/webhooks/|api\.telegram\.org/bot|hooks\.slack\.com/services/",
    ),
    # Dangerous commands
    rule(
        "DC001",
        "dangerous_command",
        C,
        "Reverse shell",
        r"\b(?:nc|ncat|netcat)\b[^\n]*\s-(?:e|c)\s|/dev/tcp/[\w.]+/\d+|\bbash\s+-i\s*>&|\bsocat\b[^\n]*\bexec:",
    ),
    rule(
        "DC002",
        "dangerous_command",
        H,
        "Pipes remote content into an interpreter",
        r"\b(?:curl|wget|iwr|Invoke-WebRequest|irm|Invoke-RestMethod)\b[^\n|]*\|\s*(?:sudo\s+)?(?:ba|z|da|k)?sh\b"
        r"|\b(?:curl|wget|iwr|irm)\b[^\n|]*\|\s*(?:sudo\s+)?(?:python3?|perl|ruby|node|iex|Invoke-Expression)\b",
    ),
    rule(
        "DC003",
        "dangerous_command",
        H,
        "Decodes and executes an encoded payload",
        r"base64\s+(?:-d|--decode|-D)\b[^\n]*\|\s*(?:ba|z)?sh\b|\bpowershell(?:\.exe)?\b[^\n]*\s-e(?:nc|ncodedcommand)?\s"
        r"|\b(?:exec|eval)\s*\(\s*(?:base64\.b64decode|atob|codecs\.decode|bytes\.fromhex|zlib\.decompress)",
    ),
    rule(
        "DC004",
        "dangerous_command",
        H,
        "Destructive filesystem or disk command",
        r"\brm\s+-(?:[a-z]*r[a-z]*f|[a-z]*f[a-z]*r)[a-z]*\s+(?:--no-preserve-root\s+)?(?:/|~|\$HOME|/\*|\*)(?=\s|$|[;&|])"
        r"|\bmkfs\.\w+|\bdd\s+if=[^\n]*\bof=/dev/(?:sd|disk|nvme|hd)|:\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:",
    ),
    rule(
        "DC005",
        "dangerous_command",
        M,
        "Dynamic code or shell execution",
        r"\beval\s*\(|\bexec\s*\(|subprocess\.\w+\([^\n]*shell\s*=\s*True|\bos\.(?:system|popen)\s*\("
        r"|\bchild_process\b|Runtime\.getRuntime\(\)\.exec|\bInvoke-Expression\b|\biex\s*\(",
        confidence=0.6,
    ),
    rule(
        "DC006",
        "dangerous_command",
        M,
        "Privilege escalation or weakened permissions",
        r"\bsudo\s+\w|\bchmod\s+(?:-R\s+)?(?:777|666|[ugoa]*\+s)\b|\bchown\s+(?:-R\s+)?root\b|\bsetenforce\s+0\b",
        confidence=0.6,
    ),
    rule(
        "DC007",
        "dangerous_command",
        H,
        "Disables OS security features",
        r"Set-MpPreference[^\n]*-Disable\w+\s+\$?true|\bspctl\s+--master-disable|\bcsrutil\s+disable"
        r"|\bxattr\s+-(?:d|c|r)[^\n]*com\.apple\.quarantine|\bufw\s+disable|\bsystemctl\s+(?:stop|disable)\s+\w*(?:firewall|apparmor|selinux)",
    ),
    # Persistence
    rule(
        "PS001",
        "persistence",
        H,
        "Installs persistence (shell profile, cron, launch agent, SSH key)",
        r"(?:>>?|\btee\b(?:\s+-a)?)\s*[\"']?(?:~|\$HOME|/root|/home/\w+)?/?\.(?:bashrc|zshrc|bash_profile|zprofile|profile|zshenv)\b"
        r"|\bcrontab\s+-(?!l\b)|/etc/cron\.|\bLaunch(?:Agents|Daemons)/|\bsystemctl\s+(?:--user\s+)?enable\b|authorized_keys\b",
    ),
    rule(
        "PS002",
        "persistence",
        M,
        "Modifies another agent's instructions or config",
        r"\b(?:write|writes|append|appends|add|adds|modify|modifies|edit|edits|update|updates|overwrite|overwrites|replace|inject)\b"
        r"[^\n]{0,40}?(?:CLAUDE\.md|AGENTS\.md|GEMINI\.md|\.cursorrules|\.cursor/rules|\.claude/settings|\.mcp\.json"
        r"|\.codex/|copilot-instructions\.md|\.windsurfrules)"
        r"|(?:>>?|\btee\b(?:\s+-a)?)\s*[\"']?[\w./~-]*(?:CLAUDE\.md|AGENTS\.md|\.cursorrules|settings\.json|\.mcp\.json)",
        confidence=0.6,
    ),
    # Secrets
    rule(
        "SE001",
        "secrets",
        H,
        "Hardcoded credential",
        r"\bAKIA[0-9A-Z]{16}\b|\bsk-(?:proj-|ant-(?:api\d{2}-)?)?[A-Za-z0-9_-]{32,}|\bgh[pousr]_[A-Za-z0-9]{36,}\b"
        r"|\bgithub_pat_[A-Za-z0-9_]{60,}|\bxox[abprs]-[A-Za-z0-9-]{10,}|\bAIza[0-9A-Za-z_-]{35}\b|\bsk_live_[A-Za-z0-9]{24,}"
        r"|-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY(?: BLOCK)?-----",
        flags=0,
        confidence=0.9,
        redact=True,
    ),
    # Obfuscation
    rule(
        "OB001",
        "obfuscation",
        M,
        "Long hex-escaped string",
        r"(?:\\x[0-9a-fA-F]{2}){24,}|(?:\\u[0-9a-fA-F]{4}){24,}",
        flags=0,
        confidence=0.6,
    ),
)


REMEDIATION = {
    "prompt_injection": "Remove instructions that override, conceal, or bypass the agent's rules; state behavior openly.",
    "excessive_agency": "Request only the tools the skill needs and keep user approval prompts enabled.",
    "harmful_content": "Remove harmful content or confirm it is descriptive and necessary for the skill's purpose.",
    "credential_access": "Do not read credential stores; ask the user to supply the specific secret needed.",
    "data_exfiltration": "Remove outbound transfers of local data, or document the destination and require consent.",
    "dangerous_command": "Remove the command or gate it behind explicit user confirmation with pinned, reviewed inputs.",
    "persistence": "Do not modify startup files, schedulers, SSH keys, or other agents' configuration.",
    "secrets": "Remove the credential from the skill and rotate it.",
    "obfuscation": "Replace encoded or invisible content with plain, reviewable text.",
    "malicious_link": "Link to the canonical HTTPS destination on a trusted domain, or remove the link.",
    "supply_chain": "Remove symlinks and bundled binaries; ship reviewable source instead.",
}

URL_SHORTENERS = frozenset(
    {
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "goo.gl",
        "is.gd",
        "ow.ly",
        "buff.ly",
        "rebrand.ly",
        "cutt.ly",
        "shorturl.at",
        "tiny.cc",
        "rb.gy",
        "t.ly",
        "s.id",
        "v.gd",
        "tr.im",
        "bl.ink",
        "shorte.st",
    }
)

# Request catchers, tunnels, and anonymous paste/file drops commonly used for exfiltration.
EXFIL_DOMAINS = frozenset(
    {
        "webhook.site",
        "requestbin.com",
        "requestbin.net",
        "pipedream.net",
        "ngrok.io",
        "ngrok.app",
        "ngrok-free.app",
        "trycloudflare.com",
        "interact.sh",
        "oast.fun",
        "oast.pro",
        "oast.live",
        "oast.site",
        "oast.online",
        "oast.me",
        "burpcollaborator.net",
        "oastify.com",
        "pastebin.com",
        "paste.ee",
        "hastebin.com",
        "ghostbin.com",
        "transfer.sh",
        "file.io",
        "0x0.st",
        "serveo.net",
        "localtunnel.me",
        "loca.lt",
        "canarytokens.com",
        "beeceptor.com",
        "hookbin.com",
        "postb.in",
        "dnslog.cn",
        "requestcatcher.com",
        "mockbin.org",
    }
)

SUSPICIOUS_TLDS = frozenset(
    {
        "zip",
        "mov",
        "tk",
        "ml",
        "ga",
        "cf",
        "gq",
        "top",
        "xyz",
        "click",
        "icu",
        "cam",
        "rest",
        "work",
        "country",
        "su",
        "buzz",
        "monster",
    }
)

EXECUTABLE_EXTENSIONS = (
    ".exe",
    ".msi",
    ".scr",
    ".bat",
    ".cmd",
    ".ps1",
    ".vbs",
    ".hta",
    ".sh",
    ".apk",
    ".dmg",
    ".pkg",
    ".jar",
    ".dll",
    ".so",
    ".dylib",
    ".bin",
    ".elf",
    ".appimage",
    ".deb",
    ".rpm",
)
