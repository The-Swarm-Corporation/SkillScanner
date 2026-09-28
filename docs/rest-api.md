# REST API

SkillScanner ships a FastAPI service in `skills_scanner.api`.

```bash
uv sync --extra api
uv run --extra api uvicorn skills_scanner.api:app --host 0.0.0.0 --port 8000
```

Interactive OpenAPI documentation is available at `/docs`, and the OpenAPI schema at `/openapi.json`.

## Endpoints

| Method | Path | Description |
| --- | --- | --- |
| `POST` | `/v1/scan` | End-to-end scan: static analysis, then the agent review |
| `POST` | `/v1/scan/static` | Static analysis only: deterministic, offline, no LLM call |
| `GET` | `/health` | Liveness probe, returns `{"status": "ok"}` |

Both scan endpoints accept the same request body and return a [scan report](report-schema.md).

## Request

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `content` | string | one input | A single prompt or `SKILL.md` |
| `files` | object | one input | Relative path to file text, for multi-file skills |
| `url` | string | one input | http(s) URL of a `SKILL.md` or prompt `.md` document to fetch and scan (max 2,048 characters) |
| `name` | string | no | Skill name; for `content`, also the file name. Default `SKILL.md`, max 256 characters. Ignored for `url`. |

Provide exactly one of `content`, `files`, or `url`.

**URL:**

```json
{
  "url": "https://swarms.world/prompt/32d1e7b4-34da-4035-bc05-d18f8e71a2f1.md"
}
```

The server fetches the document with the safeguards described in
[Python API: scan_url](python-api.md#scan_urlurl-use_agentnone---scanreport): public hosts only (checked
on every redirect), a 1 MB cap, a 15 second timeout, and text content only.

**Single prompt:**

```json
{
  "name": "system_prompt.md",
  "content": "You are a support assistant. Answer using the knowledge base only."
}
```

**Multi-file skill:**

```json
{
  "name": "pdf-helper",
  "files": {
    "SKILL.md": "---\nname: pdf-helper\ndescription: Extract text from PDFs.\n---\n...",
    "scripts/extract.py": "import sys\n..."
  }
}
```

### Limits

| Limit | Value |
| --- | --- |
| Files per request | 1,000 |
| Total request content (paths plus file bytes) | 10 MB |
| Fetched URL document | 1 MB |

## Responses

| Status | Meaning |
| --- | --- |
| `200` | Scan completed. The body is a `ScanReport`. |
| `400` | `url` could not be scanned: non-public host, too many redirects, oversized, or not text. |
| `422` | Invalid request: not exactly one of `content`, `files`, and `url`; a non-http(s) `url`; a limit exceeded; or a malformed body. |
| `502` | Fetching `url` failed: network error or an error status from the remote server. |

A failed agent review does **not** produce an error status. `/v1/scan` returns `200` with the static
report, `overall_assessment: null`, and the reason in `metadata.llm_error`. Check
`metadata.llm_available` when the agent review is required.

**Example `422`:**

```json
{
  "detail": [
    {
      "type": "value_error",
      "loc": ["body"],
      "msg": "Value error, provide exactly one of `content`, `files`, or `url`",
      "input": {},
      "ctx": { "error": {} }
    }
  ]
}
```

## Examples

**curl:**

```bash
curl -s -X POST http://localhost:8000/v1/scan \
  -H "Content-Type: application/json" \
  -d '{"content": "Summarize the attached document for the user."}'

curl -s -X POST http://localhost:8000/v1/scan \
  -H "Content-Type: application/json" \
  -d '{"url": "https://swarms.world/prompt/32d1e7b4-34da-4035-bc05-d18f8e71a2f1.md"}'
```

**Scan a local skill directory with Python:**

```python
from pathlib import Path
import httpx

root = Path("path/to/skill")
files = {
    p.relative_to(root).as_posix(): p.read_text(errors="replace")
    for p in root.rglob("*")
    if p.is_file() and not p.is_symlink() and ".git" not in p.parts
}
report = httpx.post(
    "http://localhost:8000/v1/scan",
    json={"name": root.name, "files": files},
    timeout=300,
).json()
print(report["risk_assessment"], (report["overall_assessment"] or {}).get("verdict"))
```

**JavaScript:**

```javascript
const res = await fetch("http://localhost:8000/v1/scan/static", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ content: promptText }),
});
const report = await res.json();
if (report.risk_assessment.recommendation === "DO_NOT_INSTALL") {
  throw new Error("Prompt blocked by SkillScanner");
}
```

## Timeouts

Static scans are fast and bounded by input size. End-to-end scans wait on the model, so their latency
depends on the provider, the model, and the size of the skill; set generous client timeouts (for example
300 seconds) and retry on network errors.

## Configuration

The service reads `SKILLS_SCANNER_MODEL` (default `claude-sonnet-5`) at startup, plus the provider key
for that model. See [Deployment](deployment.md).

## Security Notes

The service has no built-in authentication, rate limiting, or CORS configuration. Run it on a private
network or behind an API gateway or reverse proxy that provides authentication and rate limits. See
[Deployment](deployment.md#production-hardening).
