"""HTTP API for SkillScanner. Run with: uvicorn skills_scanner.api:app"""

from __future__ import annotations

import os

from fastapi import FastAPI
from pydantic import BaseModel, Field, model_validator

from skills_scanner import ScanReport, SkillScanner

MAX_FILES = 1_000
MAX_TOTAL_BYTES = 10_000_000

app = FastAPI(
    title="SkillScanner",
    version="0.1.0",
    description="Audit AI agent skills and prompts for malicious links, prompt injection, data exfiltration, and more.",
)
scanner = SkillScanner(model_name=os.getenv("SKILLS_SCANNER_MODEL", "claude-sonnet-5"))


class ScanRequest(BaseModel):
    """A prompt or SKILL.md as ``content``, or a whole skill as ``files`` keyed by relative path."""

    name: str = Field(
        default="SKILL.md",
        max_length=256,
        description="Skill name, or the file name for `content`",
    )
    content: str | None = Field(default=None, description="A single prompt or SKILL.md")
    files: dict[str, str] | None = Field(
        default=None, description="Relative path -> file text"
    )

    @model_validator(mode="after")
    def _one_input(self) -> ScanRequest:
        if (self.content is None) == (self.files is None):
            raise ValueError("provide exactly one of `content` or `files`")
        files = self.as_files()
        if len(files) > MAX_FILES:
            raise ValueError(f"at most {MAX_FILES} files per scan")
        if sum(len(k) + len(v.encode()) for k, v in files.items()) > MAX_TOTAL_BYTES:
            raise ValueError(f"request content exceeds {MAX_TOTAL_BYTES} bytes")
        return self

    def as_files(self) -> dict[str, str]:
        return (
            {self.name: self.content}
            if self.content is not None
            else dict(self.files or {})
        )


def _scan(request: ScanRequest, use_agent: bool) -> ScanReport:
    return scanner.scan_files(
        request.as_files(), name=request.name, use_agent=use_agent
    )


@app.post("/v1/scan", response_model=ScanReport)
def scan(request: ScanRequest) -> ScanReport:
    """End-to-end scan: static analysis, then the swarms agent review."""
    return _scan(request, use_agent=True)


@app.post("/v1/scan/static", response_model=ScanReport)
def scan_static(request: ScanRequest) -> ScanReport:
    """Static analysis only: fast, deterministic, no LLM call."""
    return _scan(request, use_agent=False)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}
