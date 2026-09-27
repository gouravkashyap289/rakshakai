# Public email checker redesign

Implemented 14 September 2026.

The frontend now centers on selecting or dropping one .eml file, analysis progress, a plain-language risk explanation, and PDF download. The warm ivory, charcoal, sage and orange presentation replaces the analyst dashboard. Navigation scrolls to the checker, how it works, and privacy sections. It has no global metrics, sidebar, separate report library, alert queue, settings, support or analyst-feedback pages.

Risk retains the original direction: 0 means fewer warning signs, 100 means more. The interface explicitly calls it a security risk score; it is not an inverted safety probability. Evidence coverage is separate. Unknown authentication, reputation and locations remain explicit.

Technical evidence is retained behind expandable sections: extracted email text, AI sentences, metadata, authentication, sender mismatch, URLs, domains, hashes, attachment warnings, indicators, provider results, own-session matches, map and graph.

New backend behavior:

- HttpOnly SameSite=Strict session cookie; its SHA-256 hash owns case records through a new case_access table.
- Every case read, report, feedback route, list and metrics request checks session ownership.
- Campaign matching is limited to the visitor's own records.
- Deletion removes the saved case, its feedback, and references in the visitor's other case graphs.
- Sender-route reconstruction separates claimed sending IPs from recipient/server IPs and body or URL indicators. All imported hops remain unverified.
- Reports include extracted body text, observed origin IP assessment, route chronology, original headers, infrastructure location, risk evidence and limitations.

25 backend tests cover existing analysis plus ownership isolation, unauthorized reads/writes/downloads/deletion, scoped correlations, deletion cleanup, IPv6 route extraction, and PDF generation with expected evidence sections. The production frontend build and TypeScript check passed. Live browser checks validate the public layout and phishing sample's 55/100 score with additive explanations.

No GeoLite2 database or threat-intelligence keys have been added. Geolocation and provider results stay unavailable where not configured. This build has not been publicly deployed. Automatic retention, production operations, HTTPS and model validation remain deployment work.
