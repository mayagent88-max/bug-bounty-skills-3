---
name: owasp-ref
description: OWASP Top 10 (2021) and API Top 10 (2023) quick reference with attack patterns, test ideas, and CWE mappings. Load when hunting, code-reviewing for security, or writing bug bounty reports.
---

# OWASP Quick Reference

## Web Top 10 (2021)

### A01 — Broken Access Control
**Test ideas:** IDOR on every ID/UUID/slug; force browsing to admin routes; HTTP verb tampering (GET→PUT); JWT role claim tampering; path traversal in file params; CORS misconfig with credentials.
**CWE:** 200, 201, 352, 639.

### A02 — Cryptographic Failures
**Test ideas:** TLS downgrade; weak ciphers; plaintext secrets in responses; ECB mode; static IVs; predictable tokens (timestamp-based); hardcoded keys in JS bundles.
**CWE:** 327, 328, 330, 331.

### A03 — Injection
**Test ideas:** SQLi (error, union, blind, time-based); NoSQLi (`$ne`, `$gt` operators); command injection in filenames/URLs; SSTI (`{{7*7}}`, `${7*7}`); LDAP, XPath, header injection.
**CWE:** 77, 78, 89, 90, 94, 643.

### A04 — Insecure Design
**Test ideas:** Business logic — negative quantities, price tampering, coupon reuse, race conditions on balance operations; missing rate limits on auth/password-reset; workflow skipping.
**CWE:** 209, 256, 501, 522.

### A05 — Security Misconfiguration
**Test ideas:** Default creds; directory listings; `.git`/`.env` exposure; verbose error pages; missing headers (CSP, HSTS, X-Frame-Options); unnecessary HTTP methods; Swagger/actuator endpoints.
**CWE:** 16, 611.

### A06 — Vulnerable and Outdated Components
**Test ideas:** Fingerprint versions via `httpx -tech-detect`; check for known CVEs; look at JS bundle for outdated libraries (jQuery, lodash, moment).
**CWE:** 1104.

### A07 — Identification & Authentication Failures
**Test ideas:** Credential stuffing (no rate limit); weak password reset tokens; JWT `alg: none`; session fixation; 2FA bypass via response manipulation; OAuth `redirect_uri` / `state` issues.
**CWE:** 287, 297, 384, 521.

### A08 — Software & Data Integrity Failures
**Test ideas:** Insecure deserialization (pickle, Java, YAML, PHP); CI/CD supply chain; missing SRI on script tags; auto-update without signature check.
**CWE:** 502, 565.

### A09 — Security Logging & Monitoring Failures
**Test ideas:** Log injection (CRLF in user-controlled log data); log tampering; logs containing secrets.
**CWE:** 117, 532.

### A10 — Server-Side Request Forgery (SSRF)
**Test ideas:** URL fields in webhooks, avatar import, PDF/screenshot gen, SSO metadata; cloud metadata (`169.254.169.254`); DNS rebinding; `file://`, `gopher://`, `dict://`; internal port scan via blind SSRF + timing.
**CWE:** 918.

## API Top 10 (2023)

- **API1** Broken Object Level Auth (BOLA) — IDOR on object refs
- **API2** Broken Authentication — token/key/session flaws
- **API3** Broken Object Property Level Auth — mass assignment, excessive data exposure
- **API4** Unrestricted Resource Consumption — no rate limits, GraphQL depth/alias abuse
- **API5** Broken Function Level Auth — admin endpoints reachable by regular users
- **API6** Unrestricted Access to Sensitive Business Flows — automation abuse (ticket scalping, coupon farming)
- **API7** SSRF
- **API8** Security Misconfiguration
- **API9** Improper Inventory Management — forgotten v1 endpoints, staging APIs in prod DNS
- **API10** Unsafe Consumption of APIs — trusting third-party API responses as safe input

## Testing tips
- **GraphQL:** introspection, batching, alias overloading, depth limits, field suggestions leak schema
- **JWT:** try `alg: none`, `HS256` with public key as secret, `kid` path traversal/injection
- **OAuth:** `redirect_uri` partial matches, missing `state`, authorization code reuse, PKCE downgrade
- **File upload:** double extensions, MIME confusion, SVG with embedded JS, polyglot files, path traversal in filename
