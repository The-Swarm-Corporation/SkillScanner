"""Deterministic analysis of a single text: regex rules, links, hidden Unicode, and encoded payloads."""

from __future__ import annotations

import base64
import binascii
import bisect
import hashlib
import ipaddress
import re
from collections.abc import Iterable, Sequence
from urllib.parse import urlsplit

from skills_scanner.models import Issue, Location, Severity
from skills_scanner.rules import (
    EXECUTABLE_EXTENSIONS,
    EXFIL_DOMAINS,
    REMEDIATION,
    SUSPICIOUS_TLDS,
    URL_SHORTENERS,
    Rule,
)

MAX_EVIDENCE = 200
MAX_DECODE_DEPTH = 2

URL_RE = re.compile(
    r"\b(?:https?|ftp)://[^\s<>\"'`\\)\]]+|\bjavascript:[^\s<>\"'`)]+", re.IGNORECASE
)
BASE64_RE = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{40,}={0,2}(?![A-Za-z0-9+/=])")
TAG_CHARS_RE = re.compile("[\U000e0000-\U000e007f]+")
VARIATION_SELECTOR_RE = re.compile("[\U000e0100-\U000e01ef]{4,}")
BIDI_RE = re.compile("[\u202a-\u202e\u2066-\u2069]")
ZERO_WIDTH_RE = re.compile("[\u200b-\u200d\u2060-\u2064\ufeff]")
INVISIBLE_RE = re.compile(
    "[\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff\U000e0000-\U000e007f\U000e0100-\U000e01ef]"
)


def analyze_text(
    text: str,
    file: str,
    rules: Sequence[Rule],
    trusted_domains: Iterable[str] = (),
) -> list[Issue]:
    """Run every static check over ``text`` and return issues located in ``file``."""
    return _Analyzer(
        file, rules, tuple(d.lower().lstrip(".") for d in trusted_domains)
    ).run(text)


class _Analyzer:
    def __init__(
        self, file: str, rules: Sequence[Rule], trusted_domains: tuple[str, ...]
    ):
        self.file = file
        self.rules = rules
        self.trusted_domains = trusted_domains
        self.issues: dict[tuple[str, int], Issue] = {}

    def run(self, text: str) -> list[Issue]:
        self._scan(text, depth=0, context="", fixed_line=None)
        return list(self.issues.values())

    def _scan(
        self, text: str, depth: int, context: str, fixed_line: int | None
    ) -> None:
        # Nested scans (decoded payloads) report the line of the payload in the original file.
        newlines = [i for i, ch in enumerate(text) if ch == "\n"]

        def line_of(pos: int) -> int:
            return fixed_line or bisect.bisect_right(newlines, pos) + 1

        def add(
            rule_id: str,
            category: str,
            severity: Severity,
            title: str,
            confidence: float,
            pos: int,
            match: str,
            redact: bool = False,
        ) -> None:
            line = line_of(pos)
            if (rule_id, line) in self.issues:
                return
            shown = _redact(match) if redact else match
            snippet = _line_at(text, pos)
            self.issues[(rule_id, line)] = Issue(
                id=rule_id,
                category=category,
                pattern=title,
                severity=severity,
                confidence=confidence,
                location=Location(file=self.file, start_line=line),
                finding=clean_text(shown),
                explanation=title + context,
                remediation=REMEDIATION.get(category),
                code_snippet=clean_text(
                    snippet.replace(match, shown) if redact else snippet
                ),
                match_fingerprint=hashlib.sha256(
                    f"{rule_id}\x1f{' '.join(match.split())}".encode()
                ).hexdigest(),
            )

        for r in self.rules:
            for m in r.pattern.finditer(text):
                add(
                    r.id,
                    r.category,
                    r.severity,
                    r.message,
                    r.confidence,
                    m.start(),
                    m.group(),
                    r.redact,
                )

        for m in URL_RE.finditer(text):
            url = m.group().rstrip(".,;:!?'\"*_~")
            for rule_id, severity, title, confidence in self._check_url(url):
                add(
                    rule_id,
                    "malicious_link",
                    severity,
                    title,
                    confidence,
                    m.start(),
                    url,
                )

        for m in TAG_CHARS_RE.finditer(text):
            hidden = "".join(chr(ord(c) - 0xE0000) for c in m.group())
            add(
                "UN001",
                "obfuscation",
                Severity.CRITICAL,
                "Hidden text in Unicode tag characters",
                0.95,
                m.start(),
                hidden,
            )
            if depth < MAX_DECODE_DEPTH:
                self._scan(
                    hidden,
                    depth + 1,
                    " (inside hidden Unicode tag text)",
                    line_of(m.start()),
                )
        for m in VARIATION_SELECTOR_RE.finditer(text):
            add(
                "UN002",
                "obfuscation",
                Severity.HIGH,
                "Data smuggled in Unicode variation selectors",
                0.8,
                m.start(),
                m.group(),
            )
        for m in BIDI_RE.finditer(text):
            add(
                "UN003",
                "obfuscation",
                Severity.HIGH,
                "Bidirectional control character can disguise text",
                0.8,
                m.start(),
                m.group(),
            )
        for m in ZERO_WIDTH_RE.finditer(text):
            if (m.start() == 0 and m.group() == "\ufeff") or _is_emoji_joiner(
                text, m.start()
            ):
                continue
            add(
                "UN004",
                "obfuscation",
                Severity.MEDIUM,
                "Zero-width character",
                0.6,
                m.start(),
                m.group(),
            )

        for m in BASE64_RE.finditer(text):
            if re.search(
                r"data:(?:image|font)/[\w.+-]+;base64,$",
                text[max(0, m.start() - 64) : m.start()],
            ):
                continue
            decoded = _decode_base64(m.group())
            if decoded is None:
                continue
            add(
                "OB002",
                "obfuscation",
                Severity.MEDIUM,
                "Base64-encoded text payload",
                0.6,
                m.start(),
                m.group(),
            )
            if depth < MAX_DECODE_DEPTH:
                self._scan(
                    decoded,
                    depth + 1,
                    " (inside base64-decoded text)",
                    line_of(m.start()),
                )

    def _check_url(self, url: str) -> list[tuple[str, Severity, str, float]]:
        if url.lower().startswith("javascript:"):
            return [("LK001", Severity.HIGH, "javascript: URI", 0.8)]
        try:
            parts = urlsplit(url)
            host = (parts.hostname or "").rstrip(".")
        except ValueError:
            return [("LK002", Severity.MEDIUM, "Malformed URL", 0.5)]
        if not host:
            return []

        issues: list[tuple[str, Severity, str, float]] = []
        if "@" in parts.netloc:
            issues.append(
                (
                    "LK003",
                    Severity.HIGH,
                    "Credentials or deceptive '@' in URL authority",
                    0.8,
                )
            )
        if re.search(r"\$\(|\$\{|\{\{|%7B%7B|%24%7B", url, re.IGNORECASE):
            issues.append(
                (
                    "LK004",
                    Severity.HIGH,
                    "URL interpolates runtime data (possible exfiltration)",
                    0.8,
                )
            )
        if self._is_trusted(host):
            return issues

        if host in {"localhost"} or host.endswith(".localhost"):
            return issues
        ip = _parse_ip(host)
        if ip is not None:
            if ip.is_loopback or ip.is_private or ip.is_link_local:
                return issues
            issues.append(
                ("LK005", Severity.MEDIUM, "URL points to a raw IP address", 0.6)
            )
        elif re.fullmatch(r"(?:0x[0-9a-f]+|\d+)", host):
            issues.append(
                ("LK006", Severity.HIGH, "URL host is an obfuscated IP address", 0.8)
            )

        if _matches(host, EXFIL_DOMAINS):
            issues.append(
                (
                    "LK007",
                    Severity.HIGH,
                    "Known exfiltration, tunneling, or paste endpoint",
                    0.8,
                )
            )
        if _matches(host, URL_SHORTENERS):
            issues.append(
                (
                    "LK008",
                    Severity.MEDIUM,
                    "URL shortener hides the real destination",
                    0.6,
                )
            )
        if host.startswith("xn--") or ".xn--" in host or not host.isascii():
            issues.append(
                (
                    "LK009",
                    Severity.MEDIUM,
                    "Internationalized domain (possible homograph)",
                    0.6,
                )
            )
        if parts.path.lower().endswith(EXECUTABLE_EXTENSIONS):
            issues.append(
                (
                    "LK010",
                    Severity.MEDIUM,
                    "Direct download of an executable or script",
                    0.6,
                )
            )
        if host.rsplit(".", 1)[-1] in SUSPICIOUS_TLDS:
            issues.append(
                ("LK011", Severity.LOW, "Domain uses a TLD with high abuse rates", 0.4)
            )
        if parts.scheme.lower() in {"http", "ftp"}:
            issues.append(("LK012", Severity.LOW, "Unencrypted link", 0.5))
        return issues

    def _is_trusted(self, host: str) -> bool:
        return _matches(host, self.trusted_domains)


def _matches(host: str, domains: Iterable[str]) -> bool:
    host = host.lower()
    return any(host == d or host.endswith("." + d) for d in domains)


def _parse_ip(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return None


def _decode_base64(blob: str) -> str | None:
    """Return the decoded blob if it is mostly printable text, else None."""
    try:
        raw = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=True)
        text = raw.decode("utf-8")
    except (binascii.Error, ValueError):
        return None
    printable = sum(ch.isprintable() or ch in "\n\r\t" for ch in text)
    return text if text and printable / len(text) > 0.9 else None


def _is_emoji_joiner(text: str, pos: int) -> bool:
    """A zero-width joiner between two non-ASCII symbols is part of an emoji sequence."""
    if text[pos] != "\u200d" or pos == 0 or pos + 1 >= len(text):
        return False
    return ord(text[pos - 1]) > 0x2000 and ord(text[pos + 1]) > 0x2000


def _line_at(text: str, pos: int) -> str:
    start = text.rfind("\n", 0, pos) + 1
    end = text.find("\n", pos)
    return text[start : end if end != -1 else len(text)]


def _redact(secret: str) -> str:
    return secret[:6] + "…[redacted]"


def clean_text(evidence: str) -> str:
    """Make evidence safe to display: escape invisible characters and bound the length."""
    evidence = INVISIBLE_RE.sub(lambda m: f"\\u{ord(m.group()):04x}", evidence)
    evidence = "".join(ch if ch.isprintable() else repr(ch)[1:-1] for ch in evidence)
    return evidence if len(evidence) <= MAX_EVIDENCE else evidence[:MAX_EVIDENCE] + "…"
