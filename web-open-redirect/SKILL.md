---
name: web-open-redirect
description: "Open redirect testing for a pentest-team engagement — finding redirect parameters and referer/path-based redirectors, filter and validation bypass (encoding, protocol-relative, backslash, @-userinfo, host confusion), and the high-value chains: OAuth/SSO token theft via redirect_uri, SSRF pivots, and phishing on a trusted domain. Load it when the appsec-triage input-validation sweep turns up an open-redirect lead on a claimed web/API target."
---

# Open Redirect — under the engagement protocol

Deep methodology for the open-redirect class. You reach here from the `appsec-triage` input-validation sweep with a lead on a surface you already own on the board.

## Under the engagement protocol

- **Claimed and in-scope only.** Every redirect probe runs against a target you own on the board and that sits on the `ROE.md` allowlist — the redirector, the OAuth endpoint, the login return-URL are all in-scope surfaces or you do not touch them.
- **The redirect destination is a benign in-scope marker — never a live third party.** Prove the redirect lands where you point it with an in-scope listener or a harmless marker path (`https://<in-scope>/oob-marker`). A PoC that actually forwards a browser to a real external site, or that pulls a live victim's OAuth token to an attacker host, *crosses* scope — reachability is the finding, not the crossing.
- **Read before write; escalations route to the anchor.** A bare 3xx to a marker is read-only proof. Anything outward-facing — a real cross-origin token exfil, a `javascript:`/`data:` XSS payload that runs, an SSRF that reaches internal infrastructure or `169.254.169.254` — is blocked: mark the surface, route through the lead to the anchor for the human's explicit go, and until then prove the *primitive exists* against a benign in-scope target.
- **Rate-limit and coordinate.** Redirect fuzzing across a parameter list can trip a WAF ban that blocks the whole team on a shared host. Throttle, and coordinate load on the board — especially on shared auth endpoints another operator may be mid-testing.
- **Log and file** per PROTOCOL §Evidence and §Findings — findings in the `appsec-reporting` format, with a re-runnable reproduction (the exact parameter, payload, and the `Location` header returned).

## Quick workflow

1. Enumerate every redirect surface on your target — parameters, referer-driven redirects, path-based redirectors, OAuth `redirect_uri`, post-login return URLs, share buttons.
2. Confirm a bare redirect to a benign in-scope marker; read the `Location` header with redirects disabled.
3. If a filter blocks it, work the bypass ladder until the marker lands.
4. Assess the chain: OAuth token theft, SSRF pivot, phishing — prove the primitive benignly; gate any real crossing through the anchor.
5. File the finding with the exact payload, the observed `Location`, and remediation.

## Detection

### Redirect parameter names to hunt
```
redirect redirect_to redirect_uri url link goto return returnTo return_url
return_path next continue destination forward path redir view checkout_url
image_url img_url load_url callback dest out
```
Discover them from crawl + JS analysis, then feed to a param tool:
```bash
hakrawler -url https://<in-scope> | tee crawl
arjun -i crawl -oJ params.json
# historical redirect endpoints
waybackurls <in-scope> | grep -Ei 'redirect|return|url=|next=' | tee redir-candidates
```

### Redirect surfaces beyond parameters
- **Referer-based** — pages that redirect off the `Referer` header (login/logout); set `Referer: https://<in-scope>/oob-marker` and watch.
- **Path-based** — `/redirect/https://<in-scope>/oob-marker`, `/out/…`.
- **Post-auth return** — the `?next=`/`?returnTo=` carried through login.
- **OAuth/SSO** — the `redirect_uri` in the authorize request (highest value; see chains).

### Confirm a bare redirect (read-only)
```bash
# never follow the redirect — read the Location header
curl -sS -i -o /dev/null -D - \
  "https://<in-scope>/redirect?url=https://<in-scope>/oob-marker" | grep -i '^location:'
```
A 3xx whose `Location` is your in-scope marker confirms the sink forwards user input. Point it only at an in-scope host.

## Filter / validation bypass ladder

When the app validates the destination, walk these against a benign in-scope marker until one lands. Keep the target on the right of every trick so nothing leaves scope:

```
# protocol-relative — drops the scheme, browser keeps host
//<in-scope>/oob-marker            /\/<in-scope>/oob-marker
# extra slashes / backslash confusion
////<in-scope>/oob-marker          \/\/<in-scope>/oob-marker
# encoded scheme (single, double)
https%3A%2F%2F<in-scope>%2Foob-marker
%2568%2574%2574%2570%2573...       (double-encode when edge+origin decode twice)
# userinfo / fragment / query host confusion (marker as the REAL host)
https://<in-scope>@<in-scope>/oob-marker
https://<in-scope>#@<in-scope>/oob-marker
https://<in-scope>?next=<in-scope>
# allowlist substring/suffix flaws — keep it in-scope to prove the parser is weak
https://<in-scope>.<in-scope>/       (subdomain the allowlist wrongly accepts)
# mixed-scheme parsing quirk (edge accepts, origin normalizes)
https;/<in-scope>/oob-marker
```
Note in the finding *which* bypass beat the control and at which layer (edge vs origin) — the control's efficacy is itself reportable. When a bypass would require an out-of-scope host to demonstrate real impact, stop at the in-scope proof and describe the crossing.

### CDN / reverse-proxy quirks
Double-decode gaps (`%252F`) between edge and origin, and header-driven redirects (`X-Original-URL`, `X-Forwarded-Proto`, `X-Forwarded-Host`) on misconfigured proxies — test these where an in-scope proxy chain exists.

## High-value chains

### OAuth / SSO token theft (redirect_uri) — gated
The premier open-redirect impact. Test `redirect_uri` validation against a benign in-scope value first:
```
/oauth/authorize?response_type=token&client_id=<id>&redirect_uri=https://<in-scope>/oob-marker
/oauth/authorize?...&redirect_uri=https://<in-scope>@<in-scope>/cb
/oauth/callback?code=MARKER&state=https://<in-scope>/oob-marker
```
Probe for partial/path-only/subdomain-suffix allowlists and case/encoding mismatch. If the token or `code` lands at your in-scope marker with redirects disabled, the takeover primitive is proven **without** ever routing a real victim's token off-domain. Actually exfiltrating a live token to an external host is outward-facing — blocked, route to the anchor. Confirm the `state` binding while here (missing/predictable/reusable feeds a login-CSRF chain — a distinct finding).

### SSRF pivot — gated
A server-side follower (link preview, webhook, image fetcher) that chases a redirect turns open-redirect into SSRF. Point it at a benign in-scope internal marker to prove the fetch follows redirects; **do not** target `169.254.169.254` or real internal services to pull secrets — that is the crossing the ROE exists to prevent. Reachability is the finding.

### XSS via javascript:/data: — gated
```
url=javascript:document.title      url=data:text/html,<in-scope-marker>
```
If the sink emits these into a client navigation, that is a reflected/DOM XSS chain. Prove with a benign marker (title change / DOM write), not a cookie-stealing payload to an external collector; a live exfil is outward-facing and gated.

### Phishing
Trusted-domain credibility is the low-tech impact — document the redirect-to-marker and describe the phishing scenario; do not stand up an actual lookalike site.

## Automation (throttled, in-scope)
```bash
# OpenRedireX against an in-scope list, marker host baked into the payloads
cat redir-candidates | openredirex -p payloads-inscope.txt
```
Keep concurrency low, add delay on shared/production targets, and never let a payload file carry a real external host — every payload's destination is an in-scope marker.

## Remediation (for the finding)

1. **Fix** — do not build redirects from raw user input. Map an indirect reference (a numeric/enum key) to a server-side table of approved destinations; or enforce a strict server-side allowlist of exact hosts. For OAuth, require exact `redirect_uri` match — no prefix, path, or subdomain fuzz.
2. **Defense in depth** — validate scheme (`http`/`https` only) *and* host with a real URL parser, never a substring/`startsWith` check; strip protocol-relative (`//`) and backslash forms; show an interstitial warning page for any external navigation; keep `state`/CSRF protection on redirect and OAuth endpoints.
3. **Detection** — a log/SIEM rule on 3xx responses whose `Location` host is off the allowlist, and on redirect parameters carrying encoded schemes or userinfo (`@`) — the signature that would have caught this.

Write it up in the `appsec-reporting` finding format, CWE-601 / A01:2021, with the exact parameter, the bypass used, and the marker-based `Location` reproduction.
