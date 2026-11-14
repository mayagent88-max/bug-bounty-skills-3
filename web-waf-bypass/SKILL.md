---
name: web-waf-bypass
description: "WAF/filter evasion as a supporting technique when a control sits in front of another lead — encoding/case/comment variation, whitespace and null tricks, HTTP method/header/parameter-pollution quirks, HTTP/2/3 and SNI/Host confusion, and per-class SQLi/XSS/GraphQL obfuscation, plus WAF fingerprinting so you name the control you beat. Load it when the appsec-triage recon/mapping sweep turns up a filtered surface on a claimed target and a payload for another class (SQLi, XSS, traversal) is being blocked — the bypass is not the finding, it feeds one, and the control-efficacy gap is itself reportable."
---

# WAF / Filter Bypass — under the engagement protocol

Deep methodology for beating a filter that stands between you and another class's payload. You reach here from the `appsec-triage` recon/mapping sweep (§Reconnaissance — "Identify WAF/CDN/gateway") with a WAF blocking a lead you already own on the board — this technique feeds a SQLi/XSS/traversal finding, it is not a finding on its own except as a control-efficacy note.

## Under the engagement protocol

- **Claimed and in-scope only.** Every crafted request goes to a target you own on the board that is on the `ROE.md` allowlist. Bypass work does not license reaching a new host — a bypass that would route to an out-of-scope origin or a fronted third-party domain is out of scope even though the WAF let it through.
- **The bypass serves a benign proof, not a bigger blast.** You evade the filter to land the *same* marker-level proof the underlying class calls for — a boolean SQLi, a benign `alert(document.domain)`, a single read — never to slip a destructive or exfil payload past inspection. OOB/callbacks go to a BENIGN in-scope listener only, never a live external pull.
- **Read before write; keep origin-pivot and outward tricks gated.** Origin-server-direct (Shodan/CloudFlair/stale-DNS), domain fronting, SNI spoofing to a different host, and ECH evasion all *change what you are talking to* — mark the surface blocked and route through the lead to the anchor for the human's explicit go before using them. Reaching the origin is only in-scope if that origin IP is itself on the allowlist.
- **Rate-limit and coordinate — evasion fuzzing is loud.** WAF-bypass fuzzing (WAFNinja, GoTestWAF, tamper-script sweeps) trips bans fast, and a ban blocks the whole team off a shared target. Throttle, single-thread, and coordinate load on the board; back off the moment challenge pages or `429`s appear.
- **Log and file.** Every consequential request to `evidence-ledger.csv` as you go, recording *which* obfuscation passed. File the fed finding into `FINDINGS.md` in the `appsec-reporting` format, and note the WAF's presence and the specific bypass in it — a control that failed to stop the payload is a reportable efficacy gap under its own line.

## Quick workflow

1. Fingerprint the control in front of your claimed target.
2. Confirm the base payload is what's blocked (not a syntax error) — get a clean block page.
3. Mutate along one axis at a time (case → comment → encoding → whitespace → protocol) until the marker-level payload lands.
4. Record the winning mutation and feed it back to the underlying-class skill (`web-sqli`, etc.).
5. File the class finding; add the control-efficacy note naming the WAF and the bypass.

## Fingerprint the control

Name the WAF before you fuzz it — the bypass is vendor-shaped, and the finding must cite the control.

```bash
wafw00f https://<in-scope>            # largest fingerprint DB
identywaf https://<in-scope>          # blind fingerprinting
```
Markers to read from headers/cookies/routes: Cloudflare (`__cf_bm`, `cf_clearance`, `/cdn-cgi/`, Turnstile/managed challenge), Imperva/Incapsula (`X-CDN: Incapsula`), AWS WAF (`AWSALB`), Sucuri (`X-Sucuri-ID`), Fastly (`fastly-debug-*`), ModSecurity/NAXSI block pages. Generic tells: Apache often trips on lowercase method (`get`), IIS on a tab before the method.

## Request-mutation techniques (the in-scope core)

These change the *shape* of the request, not its destination — safe to run against a claimed, allowlisted target.

### Case / comment / keyword splitting
```
SeLeCt   UnIoN            -- case folding
UN/**/ION SE/**/LECT      -- inline comments break signatures
/*!50000UNION*/           -- MySQL versioned comment
```

### Encoding variation
```
URL:          UNION -> %55%4E%49%4F%4E
double-URL:   /  -> %2f -> %252f
hex:          SELECT -> 0x53454C454354
unicode:      alert -> alert ; half-width / overlong UTF-8
HTML entity:  javas&#99;ript:
```
Chain half-width Unicode + inline comments + case where a single axis fails; NFKD-normalizing characters can collapse to the blocked token only after the WAF has passed it.

### Whitespace / numeric / concat alternatives
```
UNION/**/SELECT   UNION%0aSELECT   UNION+SELECT      -- whitespace subs
1 -> 1-0 , 1+0 , CHAR(49)                            -- numeric forms
CONCAT('a','b') | 'a'||'b' | 'a'+'b'                 -- MySQL | Oracle | MSSQL
```

### Structural / parser confusion
```
?id=safe&id=malicious                 -- HTTP parameter pollution (proxy precedence)
Content-Encoding: invalid             -- duplicate/conflicting encoding headers
Content-Encoding: gzip
```
JSON-syntax SQLi (CVE-2023-50969) — many WAFs don't parse SQL inside JSON: `{"id":{"$gt":"' OR 1=1--"}}`. GraphQL — alias spamming past depth limits, batched operations, benign operation names masking the payload (`graphql-cop`, `inql`).

### XSS obfuscation (feed `web-xss`)
```
<svg onload=alert(document.domain)>            -- alt tag/event
<img src=x onerror="window['al'+'ert'](1)">    -- string-split sink
<details open ontoggle=alert(1)>
```
Use `alert(document.domain)` as the benign marker, never a cookie-exfil payload — that would send data outward.

### Header spoofing (bypass, do not cross)
`X-Forwarded-For: 127.0.0.1`, `X-Forwarded-Host`, `X-Real-IP`, `Client-IP` can bypass IP/host filters. Keep the target host in scope — spoofing `X-Forwarded-Host: attacker.com` to poison a reset link only proves *reachability* against a benign in-scope collector; the live outward version is gated.

### Protocol-level (gauge middlebox handling; some tricks gated)
HTTP/2 `:authority` vs `Host` mismatch and HTTP/3 (`curl --http3`) can slip past inspection that only understands HTTP/1.1. These stay in-scope while the destination host stays in-scope. **SNI spoofing, `--connect-to` to a different IP, domain fronting, ECH, and origin-direct are destination-changing → gated to the anchor.**

## Automation (throttled, in-scope)

```bash
# Suggest and chain sqlmap tamper scripts for the detected WAF
sqlmap -r req.txt --tamper=space2comment,charencode --delay 1 --threads 1 --batch
# Atlas suggests tamper scripts from a WAF fingerprint
# WAFNinja / GoTestWAF: fuzz which payload class the control blocks
```
Keep `--threads 1` and add `--delay`; never point evasion fuzzing at a host outside the allowlist, and stop on the first challenge page.

## Remediation (for the finding)

1. **Fix** — the WAF is defense-in-depth, not the fix: remediate the *underlying* class (parameterized queries for SQLi, output encoding + CSP for XSS, canonicalized path checks for traversal). A bypassable WAF over an unfixed sink is still a vulnerable app.
2. **Defense in depth** — normalize/decode before inspection (collapse multi-pass encodings, Unicode NFKC) so obfuscation can't split signatures; use a positive (allowlist) model where feasible; enforce SNI≈`Host`/`:authority` and strict cert-SAN checks to kill fronting/spoof; disable non-`chunked` `Transfer-Encoding`; keep the origin IP off the public internet.
3. **Detection** — alert on the block-then-mutate pattern (repeated blocks from one source followed by a passing variant), on encoding-anomaly and duplicate-header signatures, and on WAF challenge-solve rates.

Write it up in the `appsec-reporting` finding format. The bypass maps to the underlying class's CWE (e.g. CWE-89 for the SQLi it enabled); file the evasion itself as a **control-efficacy** note against CWE-693 (Protection Mechanism Failure) so the client sees the WAF gap distinctly from the app bug.
