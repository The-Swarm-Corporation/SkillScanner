"""Report schema. Mirrors NVIDIA SkillSpector's JSON report, plus the agent's overall assessment."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, Field, field_validator


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def points(self) -> int:
        return {"LOW": 5, "MEDIUM": 10, "HIGH": 25, "CRITICAL": 50}[self.value]

    @property
    def rank(self) -> int:
        return {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}[self.value]


Recommendation = Literal["SAFE", "CAUTION", "DO_NOT_INSTALL"]
Verdict = Literal["APPROVE", "CAUTION", "REJECT"]


class Location(BaseModel):
    file: str
    start_line: int
    end_line: int | None = None


class Issue(BaseModel):
    id: str  # rule id, e.g. PI001
    finding_id: str = Field(default_factory=lambda: f"finding-{uuid4().hex}")
    category: str | None = None
    pattern: str | None = None
    severity: Severity
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    location: Location
    finding: str | None = None  # short matched snippet
    explanation: str | None = None
    remediation: str | None = None
    code_snippet: str | None = None
    intent: Literal["malicious", "negligent", "benign"] | None = None
    tags: list[str] = Field(default_factory=list)
    evidence: dict[str, Any] = Field(default_factory=dict)
    match_fingerprint: str | None = None


class SkillInfo(BaseModel):
    name: str
    source: str
    scanned_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class RiskAssessment(BaseModel):
    score: int = Field(ge=0, le=100)
    severity: Severity
    recommendation: Recommendation
    max_issue_severity: Severity | Literal["NONE"]


class Component(BaseModel):
    path: str
    type: str
    lines: int | None = None
    executable: bool = False
    size_bytes: int


class OverallAssessment(BaseModel):
    """The agent's semantic verdict (SkillSpector's overall assessment plus the Skill Inspector rubric)."""

    verdict: Verdict = Field(
        description="APPROVE, CAUTION, or REJECT per the verdict rubric"
    )
    risk_level: Severity = Field(
        description="Overall risk level: LOW, MEDIUM, HIGH, or CRITICAL"
    )
    summary: str = Field(
        description="Bottom line in 2-3 sentences: install or not, the main risk, and why"
    )
    install_posture: str = Field(
        default="", description="One sentence on suitable and unsuitable use"
    )
    sensitive_surface: list[str] = Field(
        default_factory=list,
        description="Sensitive capabilities used, e.g. network, env, files, shell, MCP, git",
    )
    diagnosis: str = Field(
        default="",
        description="2-4 sentences connecting static evidence with semantic review",
    )
    guardrails: list[str] = Field(
        default_factory=list, description="Conditions under which the skill may be used"
    )

    @field_validator("verdict", "risk_level", mode="before")
    @classmethod
    def _uppercase(cls, value: Any) -> Any:
        return value.upper() if isinstance(value, str) else value


class Metadata(BaseModel):
    has_executable_scripts: bool
    skills_scanner_version: str
    llm_requested: bool
    llm_available: bool
    meta_analysis_applied: bool
    model: str | None = None
    llm_error: str | None = None


class ScanReport(BaseModel):
    skill: SkillInfo
    risk_assessment: RiskAssessment
    components: list[Component]
    issues: list[Issue]
    overall_assessment: OverallAssessment | None = None
    metadata: Metadata
    execution_successful: bool = True

    @property
    def verdict(self) -> Verdict | Recommendation:
        """The agent verdict when a semantic review ran, else the static recommendation."""
        if self.overall_assessment is not None:
            return self.overall_assessment.verdict
        return self.risk_assessment.recommendation

    def to_json(self, indent: int | None = 2) -> str:
        return self.model_dump_json(indent=indent)

    def to_markdown(self) -> str:
        """Render the Skill Inspector triage report."""
        risk = self.risk_assessment
        review = self.overall_assessment
        lines = [
            f"## 🛡️ Skill Inspector: `{self.skill.name}`",
            "",
            f"**Source:** {self.skill.source}",
        ]
        if review:
            lines.append(f"**Verdict:** {review.verdict}")
        lines.append(
            f"**Risk:** {risk.score}/100 · {risk.severity.value} · {risk.recommendation}"
        )
        if review and review.install_posture:
            lines.append(f"**Install posture:** {review.install_posture}")
        if review:
            lines += ["", "### Bottom Line", review.summary]
        lines += [
            "",
            "### Signal Overview",
            "| Source | Result | Interpretation |",
            "|---|---|---|",
        ]
        counts = ", ".join(
            f"{sum(i.severity is s for i in self.issues)} {s.value}"
            for s in reversed(Severity)
            if any(i.severity is s for i in self.issues)
        )
        lines.append(
            f"| Static scan | {counts or 'no issues'} | score {risk.score}, {risk.recommendation} |"
        )
        if review:
            lines.append(
                f"| Agent semantic review | {review.verdict} | risk {review.risk_level.value} |"
            )
            if review.sensitive_surface:
                lines.append(
                    f"| Sensitive surface | {', '.join(review.sensitive_surface)} | |"
                )
        elif self.metadata.llm_requested:
            lines.append(
                f"| Agent semantic review | unavailable | {self.metadata.llm_error or ''} |"
            )
        if self.issues:
            lines += [
                "",
                "### Key Evidence",
                "| Rule | Severity | Location | Review judgment |",
                "|---|---|---|---|",
            ]
            for i in sorted(self.issues, key=lambda i: -i.severity.rank):
                judgment = (
                    (i.explanation or i.pattern or "")
                    .replace("|", "\\|")
                    .replace("\n", " ")
                )
                lines.append(
                    f"| {i.id} | {i.severity.value} | {i.location.file}:{i.location.start_line} | {judgment} |"
                )
        if review and review.diagnosis:
            lines += ["", "### Diagnosis", review.diagnosis]
        if review and review.guardrails:
            lines += [
                "",
                "### Guardrails",
                *(f"{n}. {g}" for n, g in enumerate(review.guardrails, 1)),
            ]
        return "\n".join(lines)
