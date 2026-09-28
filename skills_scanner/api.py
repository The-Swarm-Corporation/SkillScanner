"""HTTP API for SkillScanner. Run with: uvicorn skills_scanner.api:app"""

from __future__ import annotations

import os

import httpx
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field, model_validator

from skills_scanner import ScanReport, SkillScanner
from skills_scanner.fetch import is_url

MAX_FILES = 1_000
MAX_TOTAL_BYTES = 10_000_000

app = FastAPI(
    title="SkillScanner",
    version="0.1.0",
    description="Audit AI agent skills and prompts for malicious links, prompt injection, data exfiltration, and more.",
)
scanner = SkillScanner(model_name=os.getenv("SKILLS_SCANNER_MODEL", "claude-sonnet-5"))


class ScanRequest(BaseModel):
    """Exactly one input: ``content`` (a prompt or SKILL.md), ``files`` (a whole skill keyed by
    relative path), or ``url`` (an http(s) link to a SKILL.md or prompt ``.md`` document).
    """

    name: str = Field(
        default="SKILL.md",
        max_length=256,
        description="Skill name, or the file name for `content`",
    )
    content: str | None = Field(default=None, description="A single prompt or SKILL.md")
    files: dict[str, str] | None = Field(
        default=None, description="Relative path -> file text"
    )
    url: str | None = Field(
        default=None,
        max_length=2048,
        description="http(s) URL of a SKILL.md or prompt .md document to fetch and scan",
    )

    @model_validator(mode="after")
    def _one_input(self) -> ScanRequest:
        if sum(x is not None for x in (self.content, self.files, self.url)) != 1:
            raise ValueError("provide exactly one of `content`, `files`, or `url`")
        if self.url is not None:
            if not is_url(self.url):
                raise ValueError("`url` must start with http:// or https://")
            return self
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
    if request.url is None:
        return scanner.scan_files(
            request.as_files(), name=request.name, use_agent=use_agent
        )
    try:
        return scanner.scan_url(request.url, use_agent=use_agent)
    except ValueError as exc:  # unsupported, non-public, oversized, or binary target
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except httpx.HTTPError as exc:
        raise HTTPException(
            status_code=502, detail=f"could not fetch url: {exc}"
        ) from exc


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
