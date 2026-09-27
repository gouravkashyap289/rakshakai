# Rakshak verification record

Verified on 14 September 2026.

## Completed checks

- Backend: 25 tests passed, including visitor isolation, private report access, deletion cleanup and origin tracing. Two upstream deprecation warnings; no failing tests.
- Frontend: TypeScript check and Vite production build passed.
- Installed Python dependencies: no broken requirements found.
- Real multipart `.eml` uploads are scored with the three-pillar hybrid policy: AI text 40, sender/domain 35, and urgent actions/links/attachments 25. Levels are Low 0-30, Medium 31-70, and High 71-100.
- The phishing fixture produced eight weighted findings; their contributions sum exactly to 55. Authentication was UNKNOWN because its imported receiver headers are untrusted.
- Evidence confidence for both upload fixtures was 41%, reflecting missing external corroboration. This is a coverage index, not measured accuracy.
- All six supplied scenarios were exercised across upload and demo flows. Invoice, BEC, and brand-impersonation scenarios were classified by their actual content signals.
- Seven additional test investigations persisted in SQLite in an isolated browser session. Case detail retrieval, session-scoped metrics, and feedback read-back passed.
- Invalid extension and unsupported MIME uploads were rejected. The test suite also covers size limits, reserved/private destinations, HTML sanitization, IPv6 extraction, and URLs in subjects and HTML attributes.
- Campaign matching, duplicate evidence labeling, and graph edge/node consistency passed automated tests.
- A real public DNS/RDAP lookup returned an AAAA record and RDAP registration information. Individual DNS record timeouts remained LOOKUP FAILED.
- The updated two-page forensic PDF was downloaded from the API. Text extraction and visual rendering verified sender/recipient details, authentication, risk evidence, domain age, delivery infrastructure, IP geolocation, attachments and limitations.

## Availability and limitations

- VirusTotal, AbuseIPDB, URLhaus, and AlienVault OTX need server-side API keys. Their response mapping and unavailable states were tested with isolated fixtures; authenticated live provider queries were not tested.
- Local MaxMind GeoLite2 City/ASN databases are not supplied. No geolocation markers or VPN/proxy/Tor claims were fabricated.
- The active scikit-learn model uses a reproducible sample of 1,000 sanitized public-corpus emails: 500 phishing/spam and 500 benign. It trains on 800 examples from the dataset's official training split and tests on 200 examples from its official test split, with exact duplicates removed across splits. Current results are 93.5% accuracy, 93.94% positive-class precision, 93% positive-class recall, and 93.47% F1. The positive label combines spam and phishing, so these figures are not phishing-only production accuracy. A separate phishing-specific validation corpus and probability calibration remain future work.
- Imported SPF/DMARC claims cannot be independently verified without trusted mail-receiver context. Optional dkimpy verification uses current DNS and is disabled by default.
- Active URL fetching, redirect following, archive extraction, and attachment execution are intentionally disabled.
- Correlation compares against the visitor's latest 200 stored cases; it indicates possible relationships, not attribution.
- Dockerfiles and Compose configuration are included. Docker is unavailable on this host, so a container build/run was not verified.
- The redesigned public page, sample analysis, result tabs and desktop/narrow layout were checked in the live browser. A file-chooser automation attempt timed out; real multipart uploads were independently tested through the live frontend proxy. WebMCP is no longer exposed by the public UI.

## Starting the prepared workspace again

If the servers stop, use `./Launch-Rakshak.ps1 -SkipInstall` in this project directory. It detects the prepared workspace Python environment. Stop existing Rakshak server processes before relaunching to avoid occupied ports.

For another machine, follow README.md or the Docker Compose instructions. The archive excludes local databases, secrets, installed dependencies, caches, and server logs.
