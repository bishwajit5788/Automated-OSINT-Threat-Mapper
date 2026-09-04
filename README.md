# ⚡ AetherMap-OSINT — Automated OSINT Threat Mapper

<p align="center">
  <img src="https://img.shields.io/badge/FastAPI-Python-009688?style=for-the-badge&logo=fastapi&logoColor=white" alt="FastAPI" />
  <img src="https://img.shields.io/badge/React-Vite-61DAFB?style=for-the-badge&logo=react&logoColor=black" alt="React" />
  <img src="https://img.shields.io/badge/Scanner-v3.1-111827?style=for-the-badge" alt="Scanner v3.1" />
  <img src="https://img.shields.io/badge/CI-GitHub_Actions-2088FF?style=for-the-badge&logo=githubactions&logoColor=white" alt="CI" />
</p>

AetherMap-OSINT is a bounded, non-destructive attack-surface and vulnerability-triage platform. It combines Certificate Transparency discovery, public DNS resolution, real TCP connection scanning, protocol/TLS evidence collection, NVD CPE/CVE correlation, confidence scoring, and stable historical change detection.

> **Authorization:** active network probes contact selected target infrastructure. Use only against systems you are explicitly authorized to assess. No exploitation, credential attacks, brute force, persistence, or destructive testing is performed.

## v3.1 production-hardening priorities

- **Asset fan-out:** crt.sh hostnames are individually resolved and scanned within request/deployment ceilings.
- **Network safety:** only globally routable addresses are eligible for active scanning; private, loopback, link-local, multicast, reserved and unspecified addresses are rejected.
- **Real TCP scanning:** bounded TCP connect checks with configurable concurrency and timeouts.
- **Evidence-first detection:** TCP connection, protocol/banner, TLS version, ALPN and certificate SHA-256 evidence are retained when available.
- **CVE triage:** NVD CPE/CVE correlation is explicit and confidence-scored; unresolved products are not assigned fabricated CPEs.
- **Stable history:** timestamps and execution duration do not cause false historical changes.
- **Operational limits:** ports, assets, concurrency and network timeouts are bounded to prevent accidental scan amplification.
- **API hardening:** request validation and history-domain validation share the same FQDN rules.

## Pipeline

```text
Target FQDN
  ├─► DNS ─► public IPv4/IPv6 candidates
  ├─► crt.sh ─► bounded hostname inventory
  │                 └─► DNS each hostname
  └──────────────────────────────► bounded TCP connect scan
                                      ├─► protocol/banner evidence
                                      └─► TLS handshake evidence
                                                │
                                                ▼
                                      product/version evidence
                                                │
                                                ▼
                                         NVD CPE resolution
                                                │
                                                ▼
                                         NVD CVE correlation
                                                │
                                      confidence + CVSS severity
                                                │
                                                ▼
                                         risk/threat score
                                                │
                                                ▼
                                  stable historical snapshots/diff
```

NVD defines CPE as a standardized product/platform identification method and provides CPE/CVE applicability data. A CPE/CVE match is triage evidence, not automatic proof that a deployed instance is exploitable. citeturn0search0

## API

### `POST /api/recon`

```json
{
  "domain": "example.com",
  "ports": [22, 80, 443, 8080],
  "max_assets": 25
}
```

`ports` is limited to 128 TCP ports. `max_assets` is bounded by the request schema and the deployment `MAX_ASSETS` ceiling.

### `GET /api/recon/history/{domain}`

Returns stable changes between the two latest scans, including asset/port additions and removals plus changed service fingerprints/CVEs.

### `GET /api/recon/sample`

Synthetic demo data only. It is not live evidence.

## Configuration

| Variable | Purpose | Default |
|---|---|---|
| `ALLOWED_ORIGINS` | Exact frontend CORS origins | localhost origins |
| `SCAN_PORTS` | Default TCP port profile | common ports |
| `SCAN_CONCURRENCY` | Concurrent TCP probes | `24` |
| `MAX_ASSETS` | Deployment asset ceiling | `25` |
| `SCAN_CONNECT_TIMEOUT` | TCP connect timeout | `1.5s` |
| `NVD_TIMEOUT` | NVD request timeout | `10s` |
| `NVD_API_KEY` | Optional NVD API key | unset |
| `AETHERMAP_HISTORY_DB` | SQLite history path | `data/aethermap_history.sqlite3` |

## Evidence model

```text
TCP connection
 + protocol/banner evidence
 + TLS evidence
       ↓
product + version
       ↓
CPE candidate
       ↓
NVD CVEs
       ↓
confidence score
       ↓
triage finding
```

Every vulnerability finding includes source, confidence, and evidence. The scanner deliberately distinguishes **correlated** from **confirmed** vulnerability status because vendor backports, configuration, mitigations and applicability conditions can change real-world exposure.

## Current scope

Supported now:

- Certificate Transparency enumeration via crt.sh
- Multi-host DNS resolution
- Public-IP safety filtering
- Bounded TCP connect scanning
- HTTP/SSH/limited protocol fingerprinting
- TLS version/ALPN/certificate hash evidence
- NVD CPE/CVE correlation
- CVSS severity classification
- Confidence-scored evidence
- Stable SQLite scan history
- Asset/port/service/CVE change detection
- Request-level port and asset controls

Intentionally not implemented yet:

- Exploitation or credential attacks
- Raw-packet SYN scanning
- Comprehensive UDP scanning
- Full OS fingerprinting
- Complete protocol fingerprint coverage
- Full TLS cipher/compliance auditing
- Full NVD logical configuration/version-range evaluation
- Authenticated application scanning
- Cloud inventory
- RDAP/ASN/BGP enrichment
- Distributed worker queues
- Multi-tenant RBAC
- PostgreSQL/object-storage production persistence
- Full vulnerability verification

These are engineering boundaries, not hidden capabilities.

## Production architecture target

```text
React/Vercel frontend
        │
        ▼
API gateway / authenticated API
        │
        ▼
background scan queue
        │
   ┌────┼────┐
   ▼    ▼    ▼
worker worker worker
   └────┼────┘
        ▼
PostgreSQL + evidence/object storage
```

**Do not deploy the scanner directly to Vercel.** Vercel is reserved for the final frontend deployment after the scanner/backend has passed local and CI validation. Network scanning workers require a runtime designed for controlled outbound network operations and long-running jobs.

## Validation

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m pytest -q
uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

```bash
cd frontend
npm ci
npm run build
```

## Responsible use

Use only within an approved assessment scope. An open port is an observation, not a vulnerability. A CPE/CVE correlation is not proof of exploitability. Keep active scanning disabled for assets outside an explicitly authorized scope.

## License

MIT
