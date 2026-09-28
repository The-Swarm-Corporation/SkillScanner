# Deployment

The REST service is stateless and ships as a Docker image.

## Docker

```bash
docker build -t skills-scanner .
docker run -d --name skills-scanner -p 8000:8000 \
  -e ANTHROPIC_API_KEY \
  -e SKILLS_SCANNER_MODEL=claude-sonnet-5 \
  skills-scanner
curl -s localhost:8000/health
```

### Image Details

| Property | Value |
| --- | --- |
| Base image | `python:3.12-slim` |
| Dependencies | Installed from `uv.lock` with `uv sync --frozen --no-dev --extra api` |
| User | Non-root `scanner` (UID 10001) |
| Port | 8000 |
| Health check | `GET /health` every 30 seconds |
| Command | `uvicorn skills_scanner.api:app --host 0.0.0.0 --port 8000` |

## Configuration

| Variable | Default | Description |
| --- | --- | --- |
| `SKILLS_SCANNER_MODEL` | `claude-sonnet-5` | Model for `/v1/scan` |
| `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, ... | none | Provider credentials for the chosen model |
| `WORKSPACE_DIR` | `/tmp/agent_workspace` in the image | Swarms runtime workspace; must be writable |
| `HOME` | `/tmp` in the image | Swarms creates `~/.swarms` at agent start-up; must be writable |
| `SWARMS_TELEMETRY_ON` | enabled | Set to `false` to disable Swarms framework telemetry |

Without a provider key, `/v1/scan` still returns static results with `metadata.llm_error` set, and
`/v1/scan/static` is unaffected.

## Scaling

- Scan endpoints are synchronous and run in FastAPI's thread pool; one process handles concurrent
  requests. End-to-end scans spend most of their time waiting on the model.
- For more throughput, run multiple workers or replicas. The service keeps no state between requests,
  so replicas can sit behind any load balancer.

```bash
docker run -d -p 8000:8000 -e ANTHROPIC_API_KEY skills-scanner \
  uvicorn skills_scanner.api:app --host 0.0.0.0 --port 8000 --workers 4
```

- Set client and load-balancer timeouts high enough for model latency (for example 300 seconds).

## Docker Compose

```yaml
services:
  skills-scanner:
    build: .
    ports: ["8000:8000"]
    environment:
      SKILLS_SCANNER_MODEL: claude-sonnet-5
      ANTHROPIC_API_KEY: ${ANTHROPIC_API_KEY}
      SWARMS_TELEMETRY_ON: "false"
    read_only: true
    tmpfs: ["/tmp"]
    restart: unless-stopped
```

## Kubernetes

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: skills-scanner
spec:
  replicas: 2
  selector:
    matchLabels: { app: skills-scanner }
  template:
    metadata:
      labels: { app: skills-scanner }
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 10001
      containers:
        - name: skills-scanner
          image: registry.example.com/skills-scanner:0.1.0
          ports: [{ containerPort: 8000 }]
          env:
            - { name: SKILLS_SCANNER_MODEL, value: claude-sonnet-5 }
            - { name: SWARMS_TELEMETRY_ON, value: "false" }
            - name: ANTHROPIC_API_KEY
              valueFrom: { secretKeyRef: { name: skills-scanner, key: anthropic-api-key } }
          readinessProbe: { httpGet: { path: /health, port: 8000 }, periodSeconds: 10 }
          livenessProbe: { httpGet: { path: /health, port: 8000 }, periodSeconds: 30 }
          securityContext:
            readOnlyRootFilesystem: true
            allowPrivilegeEscalation: false
          volumeMounts: [{ name: tmp, mountPath: /tmp }]
      volumes:
        - name: tmp
          emptyDir: {}
---
apiVersion: v1
kind: Service
metadata:
  name: skills-scanner
spec:
  selector: { app: skills-scanner }
  ports: [{ port: 80, targetPort: 8000 }]
```

## Production Hardening

The service is designed to sit behind your platform's edge. Before exposing it:

| Concern | Recommendation |
| --- | --- |
| Authentication | The API has none. Require it at an API gateway or reverse proxy (OAuth, mTLS, or API keys). |
| Rate limiting | End-to-end scans spend model tokens; rate-limit per client. |
| Request size | The app rejects content over 10 MB after parsing; also cap request bodies at the proxy. |
| TLS | Terminate TLS at the proxy or load balancer. |
| Egress | Allow the model provider and, if you use `url` scans, public HTTPS. Block cloud metadata and internal ranges at the network layer as defense in depth. |
| Secrets | Inject provider keys from a secret manager; never bake them into the image. |
| Filesystem | Run with a read-only root filesystem and a writable `/tmp`; the image points `HOME` and `WORKSPACE_DIR` there. |
| Data residency | `/v1/scan` sends content to the model provider. Route confidential content to `/v1/scan/static` or use a provider that meets your requirements. |
| Auditing | Store returned reports with the scanned artifact's version or hash. |
| Pinning | Build from a tagged commit and keep `uv.lock` in version control. |

## Upgrading

Rebuild the image from the new commit. The report schema is versioned by `metadata.skills_scanner_version`;
consumers should ignore unknown fields.
