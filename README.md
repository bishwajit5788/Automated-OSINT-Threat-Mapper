# ⚡ AetherMap-OSINT — Automated OSINT Threat Mapper

<p align="center">
  <a href="https://automated-osint-threat-mapper.vercel.app" target="_blank">
    <img src="https://img.shields.io/badge/Live_Demo-Vercel-000000?style=for-the-badge&logo=vercel&logoColor=white" alt="Live Demo" />
  </a>
  <img src="https://img.shields.io/badge/FastAPI-Python-009688?style=for-the-badge&logo=fastapi&logoColor=white" alt="FastAPI" />
  <img src="https://img.shields.io/badge/React-Vite-61DAFB?style=for-the-badge&logo=react&logoColor=black" alt="React" />
  <img src="https://img.shields.io/badge/CI-GitHub_Actions-2088FF?style=for-the-badge&logo=githubactions&logoColor=white" alt="CI" />
  <img src="https://img.shields.io/badge/License-MIT-blue.svg?style=for-the-badge" alt="MIT License" />
</p>

AetherMap-OSINT is a defensive security research application for mapping public-facing assets from passive OSINT sources and presenting findings as an interactive topology.

> **Important:** the current repository intentionally does **not** claim that arbitrary targets have real open ports or CVEs. Certificate Transparency and DNS are real data sources; network-service findings are limited to an explicitly labeled synthetic demo catalog until a real provider integration is added.

## What the current version does

- Normalizes and validates DNS hostnames with Pydantic.
- Resolves the target through the backend using asynchronous DNS resolution.
- Queries `crt.sh` for Certificate Transparency observations.
- Deduplicates certificate names and returns observed assets with source metadata.
- Exposes a transparent heuristic risk score based only on the returned findings.
- Provides an explicit `/api/recon/sample` demo route with synthetic service/CVE records.
- Uses the FastAPI backend as the single source of truth; the browser no longer fabricates a second independent attack surface.
- Includes a JSON dossier export and asset inspector UI.
- Adds CI that runs backend validation tests and the frontend production build.

## Architecture

```text
                        ┌────────────────────────────┐
                        │   React + React Flow UI    │
                        │  topology / inspector /    │
                        │       JSON export          │
                        └─────────────┬──────────────┘
                                      │ HTTPS / JSON
                                      ▼
                        ┌────────────────────────────┐
                        │       FastAPI API          │
                        │ validation + orchestration │
                        └───────┬────────┬───────────┘
                                │        │
                   ┌────────────┘        └─────────────┐
                   ▼                                   ▼
          ┌─────────────────┐                ┌────────────────────┐
          │ Async DNS       │                │ Certificate         │
          │ resolution      │                │ Transparency crt.sh │
          └─────────────────┘                └────────────────────┘

          Demo-only path (explicitly labeled):
          ┌──────────────────────────────────────────┐
          │ Synthetic service/CVE catalog           │
          │ for UI/demo testing; not target evidence │
          └──────────────────────────────────────────┘
```

## Repository structure

```text
Automated-OSINT-Threat-Mapper/
├── .github/workflows/ci.yml
├── backend/
│   ├── app/
│   │   ├── __init__.py
│   │   ├── engines.py
│   │   ├── main.py
│   │   └── schemas.py
│   ├── tests/test_schemas.py
│   └── requirements.txt
├── frontend/
│   ├── src/App.jsx
│   ├── src/index.css
│   ├── src/main.jsx
│   ├── package.json
│   ├── package-lock.json
│   ├── vite.config.js
│   └── vercel.json
├── .gitignore
└── README.md
```

## Local development

### Backend

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m pytest -q
uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

API: `http://localhost:8000`  
Swagger: `http://localhost:8000/docs`

### Frontend

```bash
cd frontend
npm ci
npm run dev
```

UI: `http://localhost:5173`

For production, set `VITE_API_URL` to the deployed API origin. A ready-to-copy template is provided at `frontend/.env.example`. Also set the backend `ALLOWED_ORIGINS` environment variable to the exact frontend origin, for example `https://automated-osint-threat-mapper.vercel.app`.

## API

### `GET /`
Returns service and engine status.

### `GET /api/health`
Returns a minimal health response suitable for deployment probes.

### `POST /api/recon`
Runs passive OSINT discovery for an authorized hostname.

```json
{
  "domain": "example.com"
}
```

The production response reports the actual DNS/CT source status. It does **not** invent IP addresses, subdomains, service banners, or CVEs when an upstream source is unavailable.

### `GET /api/recon/sample`
Returns a synthetic demonstration dossier so the UI can be tested without implying that the target has those services or vulnerabilities. The response sets `metadata.findings_mode` to `demo`.

## Data and vulnerability semantics

A CVE should only be attached to a real observed product/version after that evidence is obtained from an appropriate source. The UI therefore displays finding confidence and source fields.

The demo catalog contains educational examples such as OpenSSH and Log4j. NVD documents CVE-2023-38408 as affecting OpenSSH before the fixed 9.3p2 release and CVE-2021-44228 as affecting vulnerable Log4j2 releases under defined conditions. Always verify product, version, configuration, exploitability, and vendor guidance before acting on a CVE.

## Threat score

The current score is a **heuristic presentation metric**, not a CVSS score and not a statement of compromise likelihood. It is derived from returned vulnerability severities plus modest surface-size penalties. A future production engine should replace this with evidence-backed asset criticality, exploitability, exposure, confidence, and recency signals.

## Roadmap

1. Replace the demo network catalog with an opt-in provider adapter such as Shodan or another authorized asset-intelligence API.
2. Add NVD/CPE correlation from observed product/version data instead of attaching fixed CVEs.
3. Add evidence objects for every finding: source URL, collection time, raw excerpt/hash, and confidence.
4. Add scan jobs, persistence, diffing, and “what changed since last scan” views.
5. Add SSRF protections and egress controls before introducing server-side URL fetching beyond approved providers.
6. Add authentication, rate limiting, structured audit logs, and deployment-specific CORS configuration.
7. Add frontend component tests and end-to-end smoke tests.

## Responsible use

Use this project only for systems and domains you are authorized to assess. Passive OSINT data is not proof that a host is vulnerable. Active network enumeration and vulnerability verification should be performed only within an explicitly approved scope.

## License

MIT
