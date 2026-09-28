FROM python:3.12-slim

COPY --from=ghcr.io/astral-sh/uv:0.5.4 /uv /bin/uv

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    PYTHONUNBUFFERED=1 \
    PATH="/app/.venv/bin:$PATH" \
    WORKSPACE_DIR=/tmp/agent_workspace

WORKDIR /app

# Dependencies first, so they are cached independently of source changes.
COPY pyproject.toml uv.lock ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --extra api --no-install-project

COPY README.md LICENSE ./
COPY skills_scanner ./skills_scanner
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --extra api

RUN useradd --create-home --uid 10001 scanner
USER scanner

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health')"
CMD ["uvicorn", "skills_scanner.api:app", "--host", "0.0.0.0", "--port", "8000"]
