# RAKSHAK

For the new account, Gmail/Outlook, monitoring, preview, multilingual-rule, feedback and Gemini features, see [INTEGRATIONS.md](INTEGRATIONS.md). It supersedes the original prototype limitations below where noted and includes OAuth setup and verification status.

AI-Powered Email Threat Detection, GeoLocation and Forensic Intelligence Platform.

Rakshak is a public-facing email-checking prototype with a React interface and FastAPI analysis API. The page guides visitors through upload, an explained security risk score, and a downloadable PDF. Content, header, attachment, domain and IP evidence are analyzed on the backend. No message content is sent to an external AI service.

The redesigned interface has no analyst sidebar, global statistics, alerts page, settings page, or feedback form. Results use four sections: Summary, Message & attachments, Sender & route, and All evidence. Maps, graph connections and detailed intelligence remain available inside a result. The existing analyst components are retained in source but are not part of the public bundle.

An HttpOnly, SameSite=Strict browser-session cookie scopes access to uploads, results, PDFs, feedback, metrics and related-case comparisons. Visitors can delete their own saved results. Earlier unowned analyst cases remain in the database and are not exposed to public sessions. A browser cookie is a bearer capability, not an authenticated identity: anyone using that same browser session can see its checks. Closing the session does not delete server records. Plan automatic retention and administrative cleanup before deployment.

For the completed checks and current limitations, see [VALIDATION.md](VALIDATION.md).

## Quick start with Docker

Copy `.env.example` to `.env`, then run `docker compose up --build` from this directory. Open http://localhost:8080. API documentation is at http://localhost:8000/docs. Both published ports bind only to loopback. Docker itself must be installed and running.

## Local development

Requires Python 3.12+ and Node.js 22+ with pnpm.

```sh
python -m venv .venv
# Windows: .venv\Scripts\activate
# macOS/Linux: source .venv/bin/activate
pip install -r backend/requirements.txt
cd backend
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

In another terminal:

```sh
cd frontend
pnpm install
pnpm dev
```

Open http://127.0.0.1:5173. The frontend proxies `/api` to FastAPI. Load a demo investigation or drop a `.eml` file (maximum 10 MB). The six demo messages use reserved `.example` domains and an inert text attachment.

## Verification

```sh
cd backend
python -m pytest -q
cd ../frontend
pnpm build
```

The tests exercise safe and phishing uploads, persistence, additive risk explanations, invalid uploads, HTML handling, and attachment metadata. Test databases are isolated from analyst investigations.

## Implemented investigation tools

- Six safe email scenarios, drag-and-drop upload, persistent history, search, and risk-based alerts.
- MIME parsing, header evidence, sender comparison, text/HTML URL extraction, public IPv4/IPv6 extraction, safe attachment metadata and SHA-256.
- Scikit-learn model plus deterministic rules, source-linked risk explanations, capped category scores, and a separate evidence coverage index.
- DNS A/AAAA/MX/NS/TXT, RDAP for .com/.net/.org, normalized brand similarity and Levenshtein distance. DNS/RDAP requests are bounded and opt-in.
- VirusTotal, AbuseIPDB, URLhaus, and AlienVault OTX adapters. Unconfigured, missing, and failed lookups remain explicit.
- Local MaxMind GeoLite2 City and ASN readers; ISP/Tor information is added only when an available provider returns it. VPN/proxy indicators otherwise remain UNKNOWN.
- Campaign comparison across the latest 200 cases, duplicate-email detection, a selectable React Flow evidence graph, and a Leaflet infrastructure map. External map tiles load only after the analyst requests them.
- Filterable and sortable IOC tables, JSON export, analyst feedback storage, and a ReportLab PDF with metadata, evidence, intelligence, campaign matches, recommendations, and limitations.

Sender-route reconstruction presents Received headers in claimed chronological order, considers only public IPs on the sending side of each hop, and does not treat body or URL IPs as the sender origin. Imported headers remain unverified. The PDF includes this assessment, the raw header chain, extracted message text and available infrastructure location fields.

## Evidence semantics

- **Risk** uses a versioned three-pillar hybrid policy: AI text analysis 40, sender/domain reputation 35, and urgent actions/links/attachments 25. The AI pillar uses the stronger of model probability or deterministic language evidence to avoid double-counting. Missing or unknown data adds no risk. Displayed contributions sum exactly to the total. Levels are Low 0-30, Medium 31-70, and High 71-100.
- **Evidence confidence** is a coverage index, not calibrated statistical confidence. Its formula is returned with every case. Missing evidence decreases coverage and never adds risk points.
- **AI model confidence** is the maximum class probability from the actual classifier. The bundled scikit-learn model is trained on 1,000 balanced, sanitized public-corpus messages (800 from the official training split and 200 from the official test split). Its evaluation is documented in `backend/models/rakshak_tfidf_v2.json`; the source combines phishing and spam under one positive label, so the result is not phishing-only production accuracy.

Rebuild the active classifier with `python backend/training/train_real_classifier.py`. This downloads a deterministic balanced sample from `puyang2025/seven-phishing-email-datasets`, sanitizes personal identifiers and URLs, removes exact duplicates across splits, and regenerates the model and evaluation metadata using seed 42. `train_classifier.py` remains available as an offline synthetic fallback.
- **Authentication** defaults to UNKNOWN for arbitrary imports. A sender can forge Authentication-Results. `TRUSTED_AUTHSERV_IDS` must remain empty unless the message arrives through an independently verified trusted ingestion chain; the header identifier alone does not provide that trust. SPF cannot be reliably recreated without the original SMTP context.
- **Attachment warnings** identify review priorities, never a malware verdict from an extension alone. Nothing is executed or unpacked.
- **Infrastructure geolocation** concerns observed servers, not the physical location or identity of a person.

## Configuration

All secrets are server environment variables. Local development can load a file with `uvicorn --env-file ../.env` after adjusting `DATABASE_URL` to a local path. Docker reads `.env` automatically through Compose.

| Variable | Purpose |
| --- | --- |
| `DATABASE_URL` | SQLAlchemy URL; SQLite locally, `postgresql+psycopg://...` for PostgreSQL |
| `RAKSHAK_API_KEY` | Optional gateway key for controlled deployments; the public UI has no key-entry page |
| `COOKIE_SECURE` | Set true when served over HTTPS; default false for loopback development |
| `ENABLE_NETWORK_LOOKUPS` | Enable bounded DNS, RDAP and provider enrichment; default false |
| `VIRUSTOTAL_API_KEY` | VirusTotal domain/IP/URL/hash reputation |
| `ABUSEIPDB_API_KEY` | AbuseIPDB public-IP reputation |
| `URLHAUS_API_KEY` | URLhaus URL/host/hash reputation |
| `OTX_API_KEY` | AlienVault OTX indicator context |
| `GEMINI_API_KEY` | Optional concise case-summary generation; kept server-side and never sent to the browser |
| `GEOLITE2_CITY_PATH` | Licensed local GeoLite2 City database path |
| `GEOLITE2_ASN_PATH` | Licensed local GeoLite2 ASN database path |
| `MAXMIND_ACCOUNT_ID` | MaxMind account ID for retrieving licensed GeoLite2 archives; never exposed to the frontend |
| `MAXMIND_LICENSE_KEY` | MaxMind license key for retrieving licensed GeoLite2 archives; never exposed to the frontend |
| `RAKSHAK_MODEL_PATH` | Optional local fine-tuned transformer; install `transformers` and PyTorch separately |
| `VERIFY_DKIM` | Opt-in dkimpy signature verification using current public DNS; also requires network lookups |

PostgreSQL deployments should install `backend/requirements-postgres.txt` and provision the database before starting the API. GeoLite2 databases and optional transformer files must be mounted into the backend container at the paths specified by their environment variables.

External lookups disclose the queried indicators to the selected providers. Raw emails and attachments are never submitted. There is no automatic fetching of suspicious URL targets or redirects. This avoids active contact with malicious infrastructure and SSRF through email-controlled URLs; final destinations are explicitly unavailable.

## Security and deployment boundary

This is a local prototype with a public-oriented interface and browser-session isolation. It has not been deployed to the public internet. Before public deployment, provide HTTPS with secure cookies, an approved retention policy and cleanup, operational auditing, shared rate limits, a job queue, model validation and any required account recovery. Session isolation is not a substitute for a full identity and access system when persistent user accounts are required.

The API enforces byte limits before multipart parsing, MIME and extension checks, filename normalization, bounded MIME parts/indicators, timeouts, per-process rate limits, and limited concurrent analysis. The frontend never renders email HTML. Server-side sanitization strips active HTML. UI strings are rendered as React text. The Docker frontend adds a restrictive content policy. DNS-derived private addresses are excluded from IP intelligence. Provider endpoints are fixed, with redirects disabled.

SQLite JSON case payloads keep evidence and source metadata together. The SQLAlchemy repository also supports PostgreSQL. Use a migration tool and an indexed indicator table before growing beyond the bounded local history correlation window.

## API

- `POST /api/analyze-email` — multipart field `file`
- `GET /api/investigations?limit=200&offset=0`
- `GET /api/investigations/{case_id}`
- `DELETE /api/investigations/{case_id}` — delete the visitor's saved case, feedback and references in their related cases
- `GET /api/demos`, `POST /api/demo/{name}`
- `GET /api/settings`, `GET /api/health`
- `GET/POST /api/investigations/{case_id}/feedback`
- `GET /api/investigations/{case_id}/report` — PDF download
- `GET /api/metrics` — database-wide counts; accuracy remains unavailable

See FastAPI's `/docs` for the exact request schemas.

Implementation references: [FastAPI uploads](https://fastapi.tiangolo.com/tutorial/request-files/), [dnspython resolver](https://dnspython.readthedocs.io/en/stable/resolver-class.html), [VirusTotal URL identifiers](https://docs.virustotal.com/reference/url).
