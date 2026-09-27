# Accounts and mailbox integrations

The upgraded local preview is at http://127.0.0.1:5175 (backend port 8003).
To launch those ports again: `./Launch-Rakshak.ps1 -SkipInstall -BackendPort 8003 -FrontendPort 5175`.

## Available now

- Local registration, login and logout with scrypt password hashing, hashed revocable session tokens, HttpOnly cookies, a seven-day session lifetime and origin checks on mutations.
- Account-owned investigation history; guest upload remains available. Existing guest cases are not silently transferred to an account.
- Gmail and Outlook read-only authorization-code flows with PKCE and single-use state bound to the signed-in account. Tokens are encrypted using the local `TOKEN_ENCRYPTION_KEY`.
- Inbox listing, user-selected MIME imports through the existing analysis pipeline, disconnect and optional monitoring.
- A single-process worker checks the latest 20 inbox messages every two minutes when monitoring is enabled. It analyzes existing recent messages as well as new ones, deduplicates by provider message ID and creates in-app high-risk alerts at 71/100. This is bounded polling, not a guaranteed complete mailbox scan or push notification service. The backend must remain running. Do not run multiple worker instances without a distributed lock/job queue.
- Safe attachment metadata cards, SHA-256 and explanations; visible HTML link text compared with its actual destination.
- Optional HEAD-only redirect checks, disabled by default. Each hop resolves and validates all returned IPs, connects to a pinned public address, validates TLS with the original hostname, rejects credentials/nonstandard ports and limits hops/time. No cookies, page rendering, file downloads or body retrieval. Contacting a link can trigger tracking; the UI explains this before the action.
- Limited auditable security phrase rules for Hindi/Hinglish and selected Bengali, Gujarati, Tamil, Telugu, Kannada, Malayalam and Punjabi phrases. Devanagari also covers some Marathi phrases. Script detection is not language identification. The English-trained model is excluded from scoring when these scripts/Hinglish cues are detected; confidence is unavailable for that model. This is not a validated multilingual model and must be evaluated with native-language datasets before making accuracy claims.
- Persisted phishing/benign/uncertain feedback. Feedback does not automatically retrain the detector.
- On-demand Gemini summaries in ten selectable languages. Only score, category, finding names, authentication status and attachment count are sent. Message text, quoted evidence, names, addresses and attachment bytes are excluded. Model instructions treat all fields as untrusted; generated summaries never alter the deterministic risk score.

## Provider setup required

1. In Google Cloud, enable Gmail API and create a web OAuth client. Set `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET` in the ignored local `.env`. Register `http://127.0.0.1:5175/api/mailboxes/gmail/callback` for this preview. Configure testing users and the consent screen. Gmail read-only access is a restricted scope; public production use may require verification/security assessment depending on Google's requirements.
2. In Microsoft Entra, register a web app supporting the intended personal/work accounts. Grant delegated `Mail.Read` and `offline_access`. Set `MICROSOFT_CLIENT_ID` and `MICROSOFT_CLIENT_SECRET`. Register `http://127.0.0.1:5175/api/mailboxes/outlook/callback`. Tenant policy may require administrator consent.
3. Set `PUBLIC_BASE_URL` to the exact browser origin. The launcher sets it from `FrontendPort`. Register matching production HTTPS callbacks when deploying.
4. Keep `TOKEN_ENCRYPTION_KEY` stable and private. A local key has been generated; replacing it makes existing mailbox tokens unreadable. Use a secret manager for production. Disconnect removes local tokens; revoke the grant in Google/Microsoft account settings to revoke provider consent too.
5. `GEMINI_API_KEY` is server-only. `GEMINI_MODEL` defaults to `gemini-3.6-flash`, selected after Google rejected the older model for this account. The supplied key successfully produced a synthetic summary on 2026-09-16. No personal email was sent in that test.
6. Set `ENABLE_URL_REDIRECT_CHECKS=true` only when active URL checks are desired. Network-isolated deployments may leave this disabled.

## Verification and boundaries

54 backend tests pass, including existing parsing/scoring/report flows and new isolation, OAuth state/replay, encryption, import deduplication, notifications, multilingual rules, summary redaction and private-network redirect defenses. Frontend production build passes. Provider OAuth/import/monitor flows are tested with mocked provider responses; live Gmail/Outlook end-to-end authorization remains unverified until client credentials are supplied and a user consents.

Before public deployment, add email verification, password recovery, shared rate limits, a persistent job queue, retention cleanup and operational auditing; use HTTPS and `COOKIE_SECURE=true`. Accounts currently identify local registrations, not verified ownership of the registration email address. Gmail/Outlook mailbox authority comes separately from provider consent. No automatic mailbox deletion, quarantine, marking-as-read, outgoing email or SMS is implemented.

Provider references: [Gmail authorization](https://developers.google.com/workspace/gmail/api/auth/web-server), [Gmail raw messages](https://developers.google.com/workspace/gmail/api/reference/rest/v1/users.messages/get), [Microsoft message MIME](https://learn.microsoft.com/en-us/graph/api/message-get), [Gemini API](https://ai.google.dev/api).
