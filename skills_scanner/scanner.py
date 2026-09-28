"""SkillScanner: static analysis of skills and prompts, then an optional swarms agent review."""

from __future__ import annotations

import os
import re
from collections.abc import Iterable, Mapping
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from skills_scanner.agent import AgentReview, AgentReviewer
from skills_scanner.fetch import fetch_text, is_url
from skills_scanner.models import (
    Component,
    Issue,
    Location,
    Metadata,
    OverallAssessment,
    RiskAssessment,
    ScanReport,
    Severity,
    SkillInfo,
)
from skills_scanner.rules import DEFAULT_RULES, REMEDIATION, Rule, harmful_terms_rule
from skills_scanner.static import analyze_text, clean_text

SKIP_DIRS = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        "node_modules",
        "__pycache__",
        ".venv",
        "venv",
        ".mypy_cache",
    }
)
SCRIPT_EXTENSIONS = frozenset(
    {
        ".py",
        ".sh",
        ".bash",
        ".zsh",
        ".fish",
        ".js",
        ".mjs",
        ".cjs",
        ".ts",
        ".ps1",
        ".psm1",
        ".rb",
        ".pl",
        ".php",
        ".bat",
        ".cmd",
        ".vbs",
        ".lua",
    }
)
DOC_EXTENSIONS = frozenset({".md", ".markdown", ".mdx", ".txt", ".rst"})
CONFIG_EXTENSIONS = frozenset(
    {".json", ".jsonc", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".env"}
)
MEDIA_EXTENSIONS = frozenset(
    {
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".webp",
        ".ico",
        ".bmp",
        ".pdf",
        ".woff",
        ".woff2",
        ".ttf",
    }
)
EXECUTABLE_MAGIC = (
    bytes.fromhex("7f454c46"),
    b"MZ",
    bytes.fromhex("cffaedfe"),
    bytes.fromhex("cafebabe"),
)

# Scoring: per-rule diminishing returns, confidence-weighted, 1.3x for executable files.
DIMINISHING_WEIGHTS = (1.0, 0.5, 0.25)
EXECUTABLE_MULTIPLIER = 1.3
SEVERITY_BANDS = (
    (81, Severity.CRITICAL),
    (51, Severity.HIGH),
    (21, Severity.MEDIUM),
    (0, Severity.LOW),
)
RECOMMENDATION = {
    "LOW": "SAFE",
    "MEDIUM": "CAUTION",
    "HIGH": "DO_NOT_INSTALL",
    "CRITICAL": "DO_NOT_INSTALL",
}
# The recommendation is never softer than the worst confident issue: HIGH -> CAUTION, CRITICAL -> DO_NOT_INSTALL.
SCORE_FLOORS = {Severity.HIGH: 21, Severity.CRITICAL: 51}
FLOOR_CONFIDENCE = 0.8
# Agent judgments below this confidence do not confirm a static issue.
CONFIRM_THRESHOLD = 0.6


class SkillScanner:
    """Audits AI agent skills and prompts for malicious links, prompt injection, exfiltration, and more.

    Static analysis always runs. When ``use_agent`` is true, a swarms Agent then reviews the
    content and the static issues, confirms or leaves them unconfirmed (never removes them),
    adds threats the static pass missed, and gives an APPROVE / CAUTION / REJECT verdict.

    Example:
        scanner = SkillScanner(model_name="claude-sonnet-5")
        report = scanner.scan("path/to/skill")
        print(report.verdict, report.risk_assessment.score)
        print(report.to_markdown())
    """

    def __init__(
        self,
        use_agent: bool = True,
        model_name: str = "claude-sonnet-5",
        trusted_domains: Iterable[str] = (),
        harmful_terms: Iterable[str] = (),
        extra_rules: Iterable[Rule] = (),
        max_file_bytes: int = 1_000_000,
        max_files: int = 1_000,
        agent_max_chars: int = 150_000,
    ):
        self.use_agent = use_agent
        self.model_name = model_name
        self.trusted_domains = tuple(trusted_domains)
        self.rules: tuple[Rule, ...] = (*DEFAULT_RULES, *extra_rules)
        if terms := [t for t in harmful_terms if t.strip()]:
            self.rules += (harmful_terms_rule(terms),)
        self.max_file_bytes = max_file_bytes
        self.max_files = max_files
        self.reviewer = AgentReviewer(model_name=model_name, max_chars=agent_max_chars)

    def scan(
        self, target: str | os.PathLike[str], use_agent: bool | None = None
    ) -> ScanReport:
        """Scan a skill from a path, an http(s) URL, or raw skill or prompt text.

        ``target`` is read as:

        - a URL when it starts with ``http://`` or ``https://`` (see ``scan_url``);
        - a path when it is path-like or names an existing file or directory;
        - otherwise skill or prompt text (see ``scan_text``). A single-line string that
          looks like a path but does not exist raises ``FileNotFoundError``, so a typo
          is never scanned as text.
        """
        if isinstance(target, str):
            if is_url(target):
                return self.scan_url(target, use_agent=use_agent)
            if not _looks_like_path(target):
                return self.scan_text(target, use_agent=use_agent)
        root = Path(target).expanduser()
        if not root.exists():
            raise FileNotFoundError(f"scan target does not exist: {root}")
        files, components, issues = self._collect(root)
        return self._run(root.name, str(root), files, components, issues, use_agent)

    def scan_url(self, url: str, use_agent: bool | None = None) -> ScanReport:
        """Fetch a skill or prompt document over http(s) and scan it.

        Works with raw ``SKILL.md`` links and prompt endpoints that return Markdown with
        YAML frontmatter. Hosts that resolve to private or internal addresses are refused.
        """
        url = url.strip()
        text = fetch_text(url, max_bytes=self.max_file_bytes)
        name = Path(urlsplit(url).path).name or "prompt.md"
        return self.scan_files({name: text}, name=name, source=url, use_agent=use_agent)

    def scan_files(
        self,
        files: Mapping[str, str],
        name: str = "skill",
        source: str = "",
        use_agent: bool | None = None,
    ) -> ScanReport:
        """Scan in-memory files, keyed by relative path (e.g. ``{"SKILL.md": ..., "scripts/run.sh": ...}``)."""
        components = [
            Component(
                path=path,
                type=_file_type(path),
                lines=text.count("\n") + 1,
                executable=_is_executable(path, text),
                size_bytes=len(text.encode()),
            )
            for path, text in files.items()
        ]
        return self._run(name, source or name, dict(files), components, [], use_agent)

    def scan_text(
        self, text: str, name: str = "prompt.md", use_agent: bool | None = None
    ) -> ScanReport:
        """Scan a single prompt or SKILL.md given as text."""
        return self.scan_files({name: text}, name=name, use_agent=use_agent)

    def _run(
        self,
        name: str,
        source: str,
        files: dict[str, str],
        components: list[Component],
        issues: list[Issue],
        use_agent: bool | None,
    ) -> ScanReport:
        use_agent = self.use_agent if use_agent is None else use_agent
        for path, text in files.items():
            issues += analyze_text(text, path, self.rules, self.trusted_domains)
        risk = assess(issues, components)

        assessment: OverallAssessment | None = None
        llm_error = None
        if use_agent:
            # Any agent failure is recorded; the static report is still valid without it.
            try:
                review = self.reviewer.review(files, issues, risk)
            except Exception as exc:  # noqa: BLE001
                llm_error = f"{type(exc).__name__}: {str(exc)[:500]}"
            else:
                issues, assessment = apply_review(issues, review)
                risk = assess(issues, components)

        return ScanReport(
            skill=SkillInfo(name=_skill_name(files) or name, source=source),
            risk_assessment=risk,
            components=components,
            issues=sorted(
                issues,
                key=lambda i: (
                    -i.severity.rank,
                    i.location.file,
                    i.location.start_line,
                ),
            ),
            overall_assessment=assessment,
            metadata=Metadata(
                has_executable_scripts=any(c.executable for c in components),
                skills_scanner_version=_version(),
                llm_requested=use_agent,
                llm_available=assessment is not None,
                meta_analysis_applied=assessment is not None,
                model=self.model_name if use_agent else None,
                llm_error=llm_error,
            ),
        )

    def _collect(
        self, root: Path
    ) -> tuple[dict[str, str], list[Component], list[Issue]]:
        base = root.parent if root.is_file() else root
        real_base = base.resolve()
        files: dict[str, str] = {}
        components: list[Component] = []
        issues: list[Issue] = []

        def file_issue(
            rule_id: str,
            severity: Severity,
            title: str,
            confidence: float,
            rel: str,
            detail: str,
        ) -> None:
            category = (
                "supply_chain" if rule_id in {"SL001", "OB004"} else "obfuscation"
            )
            issues.append(
                Issue(
                    id=rule_id,
                    category=category,
                    pattern=title,
                    severity=severity,
                    confidence=confidence,
                    location=Location(file=rel, start_line=1),
                    finding=clean_text(detail),
                    explanation=title,
                    remediation=REMEDIATION.get(category),
                )
            )

        for path in _walk(root):
            rel = path.relative_to(base).as_posix()
            if path.is_symlink():
                target = path.resolve()
                if not target.is_relative_to(real_base):
                    file_issue(
                        "SL001",
                        Severity.HIGH,
                        "Symlink points outside the skill",
                        0.9,
                        rel,
                        str(target),
                    )
                continue
            if len(components) >= self.max_files:
                file_issue(
                    "OB005",
                    Severity.MEDIUM,
                    "File limit reached; remaining files not scanned",
                    1.0,
                    rel,
                    rel,
                )
                break
            size = path.stat().st_size
            mode_executable = bool(path.stat().st_mode & 0o111)
            if size > self.max_file_bytes:
                components.append(
                    Component(
                        path=rel,
                        type="oversized",
                        executable=mode_executable,
                        size_bytes=size,
                    )
                )
                file_issue(
                    "OB003",
                    Severity.MEDIUM,
                    "File too large to scan",
                    0.6,
                    rel,
                    f"{size} bytes",
                )
                continue
            data = path.read_bytes()
            if bytes([0]) in data[:8192]:
                is_program = data.startswith(EXECUTABLE_MAGIC)
                components.append(
                    Component(
                        path=rel, type="binary", executable=is_program, size_bytes=size
                    )
                )
                if is_program:
                    file_issue(
                        "OB004",
                        Severity.HIGH,
                        "Bundled executable binary cannot be inspected",
                        0.8,
                        rel,
                        rel,
                    )
                elif path.suffix.lower() not in MEDIA_EXTENSIONS:
                    file_issue(
                        "OB006", Severity.LOW, "Binary file not analyzed", 0.5, rel, rel
                    )
                continue
            text = data.decode("utf-8", errors="replace")
            files[rel] = text
            components.append(
                Component(
                    path=rel,
                    type=_file_type(rel),
                    lines=text.count("\n") + 1,
                    executable=mode_executable or _is_executable(rel, text),
                    size_bytes=size,
                )
            )
        return files, components, issues


def assess(issues: list[Issue], components: list[Component]) -> RiskAssessment:
    """Compute the 0-100 risk score, severity band, and recommendation."""
    executable_files = {c.path for c in components if c.executable}
    occurrences: dict[str, int] = {}
    score = 0.0
    floor = 0
    for issue in sorted(issues, key=lambda i: (i.id, -i.severity.rank)):
        if issue.confidence <= 0:
            continue
        if issue.confidence >= FLOOR_CONFIDENCE:
            floor = max(floor, SCORE_FLOORS.get(issue.severity, 0))
        count = occurrences.get(issue.id, 0)
        occurrences[issue.id] = count + 1
        if count >= len(DIMINISHING_WEIGHTS):
            continue
        points = issue.severity.points * DIMINISHING_WEIGHTS[count] * issue.confidence
        if issue.location.file in executable_files:
            points *= EXECUTABLE_MULTIPLIER
        score += points

    final = min(100, max(floor, int(score)))
    severity = next(band for threshold, band in SEVERITY_BANDS if final >= threshold)
    worst = max(issues, key=lambda i: i.severity.rank, default=None)
    return RiskAssessment(
        score=final,
        severity=severity,
        recommendation=RECOMMENDATION[severity.value],
        max_issue_severity=worst.severity if worst else "NONE",
    )


def apply_review(
    issues: list[Issue], review: AgentReview
) -> tuple[list[Issue], OverallAssessment]:
    """Merge the agent's judgments into the static issues.

    Confirmed issues gain the agent's explanation and may gain confidence; every other
    static issue is kept and tagged ``llm-unconfirmed``. Nothing is removed or downgraded,
    so content that manipulates the agent cannot hide a static finding.
    """
    by_id = {j.finding_id: j for j in review.findings}
    by_rule_line = {(j.pattern_id, j.start_line): j for j in review.findings}
    cleared: set[str] = set()
    merged: list[Issue] = []
    for issue in issues:
        judgment = by_id.get(issue.finding_id) or by_rule_line.get(
            (issue.id, issue.location.start_line)
        )
        if (
            judgment
            and judgment.is_vulnerability
            and judgment.confidence >= CONFIRM_THRESHOLD
        ):
            issue = issue.model_copy(
                update={
                    "confidence": max(issue.confidence, judgment.confidence),
                    "intent": judgment.intent,
                    "explanation": judgment.explanation or issue.explanation,
                    "remediation": judgment.remediation or issue.remediation,
                }
            )
        else:
            update: dict[str, Any] = {"tags": [*issue.tags, "llm-unconfirmed"]}
            if judgment:
                update["intent"] = judgment.intent
                update["evidence"] = {
                    **issue.evidence,
                    "llm_judgment": judgment.explanation,
                }
                if not judgment.is_vulnerability:
                    cleared.add(issue.finding_id)
            issue = issue.model_copy(update=update)
        merged.append(issue)

    for n, s in enumerate(review.semantic_findings, 1):
        merged.append(
            Issue(
                id=f"SEM{n}",
                category=s.category,
                pattern="Semantic review",
                severity=s.severity,
                confidence=s.confidence,
                location=Location(
                    file=s.file, start_line=s.start_line, end_line=s.end_line
                ),
                finding=clean_text(s.finding),
                explanation=s.explanation,
                remediation=s.remediation or None,
                intent=s.intent,
                tags=["semantic"],
            )
        )

    # Rubric: APPROVE requires every HIGH or CRITICAL issue to be explained away.
    assessment = review.overall_assessment
    unexplained = any(
        i.severity.rank >= Severity.HIGH.rank and i.finding_id not in cleared
        for i in merged
    )
    if assessment.verdict == "APPROVE" and unexplained:
        assessment = assessment.model_copy(update={"verdict": "CAUTION"})
    return merged, assessment


def _walk(root: Path) -> Iterable[Path]:
    if root.is_file():
        yield root
        return
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        current = Path(dirpath)
        # os.walk never descends into symlinked directories, but they are still checked for escapes.
        yield from (current / d for d in dirnames if (current / d).is_symlink())
        yield from (current / f for f in sorted(filenames))


def _file_type(path: str) -> str:
    suffix = Path(path).suffix.lower()
    if Path(path).name.lower() == "skill.md":
        return "skill_manifest"
    if suffix in SCRIPT_EXTENSIONS:
        return "script"
    if suffix in DOC_EXTENSIONS:
        return "documentation"
    if suffix in CONFIG_EXTENSIONS:
        return "config"
    return "other"


def _is_executable(path: str, text: str) -> bool:
    return Path(path).suffix.lower() in SCRIPT_EXTENSIONS or text.startswith("#!")


def _looks_like_path(value: str) -> bool:
    """True for a single-line string that exists on disk or has path syntax and no spaces."""
    if "\n" in value or len(value) > 4096:
        return False
    try:
        if Path(value).expanduser().exists():
            return True
    except OSError:
        return False
    stripped = value.strip()
    return " " not in stripped and (
        "/" in stripped or "\\" in stripped or bool(Path(stripped).suffix)
    )


def _skill_name(files: Mapping[str, str]) -> str | None:
    # The SKILL.md manifest, or the only file when a single document was scanned.
    manifest = next(
        (text for path, text in files.items() if Path(path).name.lower() == "skill.md"),
        next(iter(files.values())) if len(files) == 1 else None,
    )
    frontmatter = manifest and re.match(r"---\s*\n(.*?)\n---", manifest, re.DOTALL)
    name = frontmatter and re.search(
        r"^name:\s*[\"']?([^\"'\n]+)", frontmatter.group(1), re.MULTILINE
    )
    return name.group(1).strip() if name else None


def _version() -> str:
    try:
        return version("skills-scanner")
    except PackageNotFoundError:
        return "0.0.0"
