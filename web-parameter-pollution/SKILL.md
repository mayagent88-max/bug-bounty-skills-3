---
name: web-parameter-pollution
description: "HTTP Parameter Pollution testing for a pentest-team engagement — exploiting how duplicate parameters are parsed differently across the proxy/gateway/app boundary (first-wins vs last-wins vs array vs concat), to bypass a WAF, confuse access-control and logic checks, and slip injections past a front-line filter. Covers URL/body/JSON/cookie/header/GraphQL/WebSocket vectors, array-notation and cloaking tricks, and gateway-vs-backend precedence gaps. Load it when the appsec-triage input-validation sweep turns up an HPP lead on a claimed web/API target."
---

# HTTP Parameter Pollution — under the engagement protocol

Deep methodology for the HPP class. You reach here from the `appsec-triage` input-validation sweep with a lead on a surface you already own on the board — usually a control that looks solid on one layer but is parsed differently on the next.

## Under the engagement protocol

- **Claimed and in-scope only.** Every duplicate-parameter request goes to a target you own on the board and that sits on the `ROE.md` allowlist — nothing else.
- **Prove precedence with a marker, not a real breach.** Confirm HPP by showing which value each layer honours using benign markers (`param=marker-a&param=marker-b`) and a planted or second test tenant for access-control gaps — never override a real user's `id`, drain a real balance, or set a real price to demonstrate. No-real-data means the proof is the precedence gap, not the loot. When HPP smuggles a payload for another class (SQLi/XSS), send it to a benign in-scope callback only, never a live external pull.
- **Read before write; destructive/outward-facing is gated.** HPP that would mutate data (price/quantity/recipient override that actually posts a transaction), bypass a CSRF token to perform a state change, or drive request smuggling that affects other users' requests is destructive/outward-facing — mark the surface blocked and route through the lead to the anchor for the human's explicit go. A precedence-demonstration against a marker makes the point without the write.
- **Rate-limit and coordinate.** Duplicate-parameter fuzzing and GraphQL alias/batch probes hammer shared targets and trip WAF bans for the whole team. Throttle, cap alias counts, and coordinate load on the board — HPP on an auth endpoint touches whoever owns that surface.
- **Log and file** per PROTOCOL §Evidence and §Findings — findings in the `appsec-reporting` format, with a reproduction that names the exact duplicate parameters and which layer honoured which value.

## Quick workflow

1. Map every parameter on your target across all channels (URL, body, JSON, cookie, header, GraphQL variables/aliases).
2. Send each with two distinct benign markers and read which value the response reflects — first, last, concatenated, or array.
3. Where two layers disagree (edge/WAF vs backend), that gap is the vulnerability — probe what it bypasses.
4. Prove impact against a marker or a second test tenant; gate anything that writes, exfils, or affects other users through the anchor.
5. File the finding with the precedence table and a clean reproduction.

## Parsing precedence — the whole game

Different stacks pick a different occurrence of a duplicated parameter. The bug is the *disagreement* between layers:

| Stack | Duplicate `param=a&param=b` yields |
|---|---|
| ASP.NET / IIS | first (`a`) — sometimes comma-joined |
| PHP / Apache | last (`b`) |
| JSP / Tomcat | first (`a`) |
| Perl CGI | concatenated (`a,b`) |
| Python / Flask | array; `.get()` takes first |
| Node / Express | `querystring`=first; `qs`=array/last (config-dependent) |
| Spring MVC | collects into a list |

Gateways (NGINX, Kong, Apigee, Cloudflare) may collapse or normalize differently than the origin. A WAF that inspects the *first* value while the backend runs the *last* is a complete filter bypass.

## Detection — establish precedence with markers

```bash
# which value does the app honour? use distinct benign markers
curl -sS "https://<in-scope>/search?q=marker-a&q=marker-b"     # read reflected value
```
Test each channel:
```
# URL
https://<in-scope>/page?param=marker-a&param=marker-b
# body
param=marker-a&param=marker-b
# hybrid (URL vs body — proves layer split)
URL: ?param=marker-url   BODY: param=marker-body
```
```json
// JSON duplicate keys (most parsers last-wins; some gateways reject)
{ "param": "marker-a", "param": "marker-b" }
```
```http
Cookie: role=marker-a; role=marker-b
X-Role: marker-a
X-Role: marker-b
```
Record the precedence per layer in a small table — it is the core of the finding and it drives every exploit below.

### Array-notation and cloaking
```
param=a&param=b            # no brackets
param[]=a&param[]=b        # PHP array
param[0]=a&param[1]=b      # Rails indexed
param=single&param[]=arr&param[0]=idx   # mixed — confuses parsers
# cloaking: encoding/case/unicode to slip a second occurrence past a filter
param=a&par%61m=b   param=a&PARAM=b   param=a&par%2561m=b   param=a&pαram=b
```

## Exploitation (prove with a marker / second tenant)

### WAF / filter bypass (the headline use)
WAF sees the clean first value, backend runs the second:
```
https://<in-scope>/search?q=safe&q=<payload>
```
Use HPP as the *delivery* for another class — carry a SQLi or XSS probe in the honoured occurrence. Keep the smuggled payload benign: an in-scope marker/callback for XSS, a boolean/time confirmation for SQLi (hand off to `web-sqli`), never a data dump or an external exfil.

### Access-control / logic confusion (gateway vs backend)
```
# gateway authorizes on first id, backend acts on last -> IDOR/AC bypass
/api/user?id=<your-test-id>&id=<second-test-tenant-id>
# role/permission precedence split
/profile?role=user&role=admin
```
Prove cross-tenant breaks against a **second test tenant or a planted marker**, per no-real-data — never a real customer id.

### CSRF-token pollution — gated
```
/transfer?token=<valid>&token=<random>&amount=1     # duplicated anti-CSRF token
```
If one layer validates the first token and another accepts the request, that is a CSRF-protection bypass. Demonstrating it against a *real* state change (an actual transfer) is a destructive write — gate through the anchor; prove the token-precedence gap against a marker endpoint instead.

### SSRF augmentation — gated
```
/fetch?url=<in-scope-safe>&url=<in-scope-internal-marker>
```
Override a validated URL via the honoured occurrence; point the second at a benign in-scope internal marker to prove the fetch follows it — never `169.254.169.254` or a real internal service (crossing → route to anchor).

### GraphQL pollution (throttled)
```graphql
# variable pollution
query ($id: Int!, $id: Int!) { user(id: $id) { name } }
# alias abuse — bypasses per-operation rate limits; cap the count, don't hammer
query { a: user(id: 1){id} b: user(id: 2){id} }
# batch mutation replay — prove idempotency gap with ONE extra alias, not 100
mutation { a: redeemCoupon(code:"MARKER"){success} b: redeemCoupon(code:"MARKER"){success} }
```
Alias/batch fanout is a DoS-shaped probe — keep counts tiny; a large fanout to "prove" resource exhaustion is exactly the availability hit the ROE forbids.

### Request smuggling via header pollution — detection only
Duplicate `Transfer-Encoding`/conflicting `X-Forwarded-Proto` across CDN→WAF→app can smuggle. This affects *other users' requests* — confirm the ROE permits it, stop at timing-based detection, and gate any exploitation through the anchor (see `appsec-triage` §request-smuggling).

## Remediation (for the finding)

1. **Fix** — handle duplicate parameters consistently across every layer; canonicalize to one value (or reject duplicates) *before* any security or business logic reads the parameter. Set the parser explicitly (e.g. Express `query parser`) and forbid un-bracketed duplicates for arrays.
2. **Defense in depth** — enforce a JSON Schema / OpenAPI contract that rejects duplicate keys and unexpected fields; drop or normalize duplicate parameters at the edge/gateway and log the event; align gateway and backend on the same precedence; GraphQL query-depth and alias-count limits.
3. **Detection** — a WAF/SIEM rule that flags requests carrying the same parameter name more than once (URL, body, cookie, header) — the signature that would have caught this.

Write it up in the `appsec-reporting` finding format, CWE-235 / A03:2021, with the per-layer precedence table and the marker-based reproduction.
