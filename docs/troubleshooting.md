# Troubleshooting

## The agent review did not run

Check `report.metadata`:

```python
print(report.metadata.llm_requested, report.metadata.llm_available, report.metadata.llm_error)
```

| `llm_error` | Cause | Fix |
| --- | --- | --- |
| `RuntimeError: model '<name>' returned no response` | The model call failed. Swarms logs the underlying provider error (for example `AuthenticationError: Missing Anthropic API Key`). | Set the provider key for `model_name`; check the model ID, network access, and rate limits. |
| `ValueError: agent returned an invalid review: ...` | The model answered without valid structured output, twice. | Use a stronger model; reduce `agent_max_chars` for very large skills. |
| `None` with `llm_requested: false` | The agent was not requested. | Use `use_agent=True` or `/v1/scan`. |

The scan still returns the full static report in every case.

## `FileNotFoundError: scan target does not exist`

`scan()` treats a single-line string without spaces that looks like a path (it contains `/` or `\`, or
has a file extension) as a path. If you meant to scan that string as text, call `scan_text()` instead.
If you meant a path, check the working directory; `~` is expanded.

## A path was scanned as text

A string is scanned as text when it is not an existing path and contains spaces or line breaks. Pass a
`pathlib.Path` to force path handling, or check that the path exists.

## URL scans fail

| Error | Cause |
| --- | --- |
| `ValueError: refusing to fetch ...: <host> resolves to non-public address ...` | The host (or a redirect) points at localhost, a private network, or a metadata address. Fetch the document yourself and call `scan_text()` if this is intended. |
| `ValueError: unsupported URL` | Only `http` and `https` are supported. |
| `ValueError: ... exceeds <n> bytes` | The document is larger than `max_file_bytes`. |
| `ValueError: ... is not a text document` | The URL returned binary content. |
| `ValueError: too many redirects` | More than 3 redirects. |
| `httpx.HTTPStatusError` / REST `502` | The server returned an error status, for example `404`. |

Over REST, `ValueError` cases return `400` and fetch failures return `502`.

## REST API returns `422`

Send exactly one of `content`, `files`, or `url`; keep `url` to `http(s)`; and stay within 1,000 files and
10 MB. The `detail` field names the problem.

## Too many false positives

- Read the issue's `code_snippet` and `explanation`: documentation that describes attacks often matches.
- Run with the agent: unconfirmed issues are tagged `llm-unconfirmed` with the agent's reasoning.
- Add documentation hosts to `trusted_domains`.
- Accept reviewed findings with a baseline of `match_fingerprint` values. See [Extending](extending.md#baselines).
- Filter a noisy built-in rule for your environment. See [Extending](extending.md#disabling-a-built-in-rule).

## Verbose log output

Swarms logs agent activity and provider errors to the console, including full tracebacks when a model
call fails. Read reports from `report.to_json()` or the REST response rather than parsing console output.

## An `agent_workspace` directory appears

Swarms creates a runtime workspace in the working directory. Set `WORKSPACE_DIR` to control its location
(the Docker image uses `/tmp/agent_workspace`). It is already listed in `.gitignore`.

## `ModuleNotFoundError: No module named 'skills_scanner'` on macOS

If the project lives in an iCloud-synced folder (such as `~/Desktop` or `~/Documents`), macOS can mark
the virtual environment's `.pth` files as hidden, and Python skips hidden `.pth` files, so the editable
install stops loading. Clear the flag:

```bash
chflags nohidden .venv/lib/python3.*/site-packages/*.pth
```

To stop it from recurring, move the project out of the synced folder.

## Scans are slow

Static scans are fast. End-to-end scans wait on the model: use a faster model, lower
`agent_max_chars`, scan in parallel (the scanner is thread-safe), or use static mode where the agent
review is not required.

## `OSError: [Errno 30] Read-only file system: '.../.swarms'`

Swarms creates `~/.swarms` when an agent starts. On a read-only root filesystem, point `HOME` at a
writable path (the Docker image sets `HOME=/tmp`) and mount `/tmp` as writable.

## The Docker health check fails

The container listens on port 8000. If you override the command, keep `--host 0.0.0.0 --port 8000`, or
adjust the health check and port mapping to match.
