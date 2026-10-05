# Deploy Rakshak: Render API + Vercel website

Rakshak has two services. Deploy the FastAPI backend on Render first, then the Vite frontend on Vercel. The website calls `/api/...` on its own Vercel address; a Vercel rewrite forwards those requests to Render. This keeps login and visitor cookies on one browser origin.

## 1. Render backend

Create a Render **Web Service** from the repository with:

| Setting | Value |
| --- | --- |
| Root Directory | `backend` |
| Runtime | Python 3.12 or Docker |
| Build Command (Python runtime) | `pip install -r requirements-postgres.txt` |
| Start Command (Python runtime) | `uvicorn app.main:app --host 0.0.0.0 --port $PORT --proxy-headers` |
| Health Check Path | `/api/health` |

Alternatively, deploy with the Dockerfile in `backend` and use `backend` as the build context. Its start command reads Render's `PORT` automatically. The Python build/start commands above apply only to a Python runtime service.

Create a PostgreSQL database and set these Render **Environment** variables:

| Variable | Value |
| --- | --- |
| `DATABASE_URL` | Render PostgreSQL **internal** database URL |
| `PUBLIC_BASE_URL` | Exact Vercel website origin, e.g. `https://rakshak.example.vercel.app` |
| `COOKIE_SECURE` | `true` |
| `TOKEN_ENCRYPTION_KEY` | One persistent Fernet key if mailbox connections are used |
| `ENABLE_NETWORK_LOOKUPS` | `true` only when DNS/RDAP/reputation lookups are wanted |
| Provider API keys | Set individually on Render when used; never in Vercel |

The old local `.env` example uses `sqlite:////data/rakshak.db` for Docker Compose. **Do not import that `DATABASE_URL` into Render.** Without a mounted disk, `/data` is not writable and SQLite data would not persist. If PostgreSQL is not ready, leave `DATABASE_URL` unset to start with temporary SQLite for a smoke test only; investigations and accounts may disappear after restart or redeploy. A persistent database is required for real use.

Leave `RAKSHAK_API_KEY` unset for the public website. A backend API key cannot be safely placed in the Vercel browser bundle. Keep any secrets in Render's Environment settings, never in Git or `vercel.json`.

The Render API is live at `https://rakshakai-2-r1lj.onrender.com`. Its `/api/health` endpoint returns `{"status":"ok","engine":"Rakshak AI"}`.

## 2. Connect the Vercel website

From the repository's `frontend` directory, run:

```sh
npm run configure:backend -- https://rakshakai-2-r1lj.onrender.com
```

This writes the public backend origin into `frontend/vercel.json` as a `/api` reverse proxy. Commit and push **that file**; Vercel will redeploy from Git. No Vite API environment variable is needed. The URL must be the HTTPS origin only, with no `/api` suffix or trailing path.

Create a Vercel project from the same repository with:

| Setting | Value |
| --- | --- |
| Root Directory | `frontend` |
| Framework Preset | Vite |
| Build Command | `npm run build` |
| Output Directory | `dist` |

If Vercel gives the project a different domain than expected, update Render's `PUBLIC_BASE_URL` to the final Vercel origin. If using Gmail/Outlook integrations, register the matching OAuth callback URLs at the providers, such as `https://YOUR-VERCEL-DOMAIN/api/mailboxes/gmail/callback`. Redeploy the backend after changing its environment.

## 3. Verify the live flow

1. Open `https://YOUR-VERCEL-DOMAIN/api/health`. It must return the same JSON as Render's health endpoint. If it returns a Vercel 404, the rewrite was not committed or Vercel's Root Directory is wrong.
2. Load a demo email and confirm the analysis appears. Download its PDF report.
3. Sign in and reload the page. The account and investigation should remain available after a Render restart when PostgreSQL is configured.

The provided GeoLite2 databases and trained classifier files are part of `backend` and are copied by the Docker build. Live reputation depends on configured provider keys and network access; unavailable lookups remain marked unavailable. Mailbox background monitoring also depends on a continuously running backend service.
