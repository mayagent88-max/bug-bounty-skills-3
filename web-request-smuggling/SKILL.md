---
name: web-request-smuggling
description: "HTTP request smuggling / desync testing for a pentest-team engagement — CL.TE / TE.CL / TE.TE detection via timing and differential responses, header obfuscation, HTTP/2 downgrade (H2.CL / H2.TE) and h2c-upgrade desync, plus client-side desync, response-queue poisoning and cache-poisoning impact classes, with smuggler.py / HTTP Request Smuggler / h2csmuggler tooling. Load it when the appsec-triage HTTP-request-smuggling sweep turns up a desync lead on a claimed target with a proxy/LB/CDN chain — and only after confirming the ROE permits it, because this class affects OTHER users' requests."
---

# HTTP Request Smuggling — under the engagement protocol

Deep methodology for the request-smuggling (desync) class. You reach here from the `appsec-triage` "HTTP request smuggling" sweep with a lead on a multi-tier surface you already own on the board — a front-end proxy/LB/CDN in front of a back-end that parses framing differently.

**Same root shape, different axis — pick the right skill.** This class is about *message framing*: where one request ends and the next begins. If the two parsers instead disagree on *URL interpretation* — which route, which normalized/decoded path (an encoded char that misses a front route, `/..;/`, `%2f`/`%252f`, a bare-query suffix, a trailing slash), used to bypass a front auth/routing gate, skip upstream preprocessing, or confuse a cache key — that is **path confusion**, and the methodology is `web-path-confusion`. GitLab CVE-2026-85706 is that class, not this one.

**This class is different: a smuggled request lands in *another user's* connection.** Detection is comparatively safe; exploitation can hijack real users' requests, poison shared caches, and corrupt the request queue for everyone. Treat exploitation as destructive-by-default.

## Under the engagement protocol

- **Claimed and in-scope only — and only if the ROE permits this class at all.** Every request goes to a target you own on the board and on the `ROE.md` allowlist. Because desync affects third parties, confirm in the ROE (or via the lead → anchor) that request smuggling is authorized on this surface *before the first probe*. If it is silent, that is a scope edge — mark the surface blocked and ask.
- **STOP at detection unless exploitation is explicitly cleared.** A time-delay or differential-response confirmation *proves the desync exists* — that is the finding. Actually smuggling a request to `/admin`, capturing another user's request, or poisoning the cache is destructive/outward-facing: mark it blocked and route through the lead to the anchor for the human's explicit go. Reachability beats a live hijack.
- **Prove with a self-directed marker, never a live victim.** Where exploitation is cleared, demonstrate against a *marker of your own* — a benign path that returns a distinctive response, your own second connection — not by capturing a real user's session or credentials. No data dump, no live callback; any OOB goes to a BENIGN in-scope listener only.
- **Rate-limit and coordinate — desync degrades the shared target for everyone.** Queue poisoning and connection-state attacks can wedge the front-end for the whole team and for real users. Single-connection, low-volume, off-hours per the ROE window; coordinate load on the board and back off the instant responses go strange.
- **Log and file.** Every consequential request to `evidence-ledger.csv` as you go (timing deltas included). File the confirmed finding into `FINDINGS.md` in the `appsec-reporting` format with a re-runnable reproduction — capture the exact bytes, since framing whitespace is load-bearing.

## Quick workflow

1. Confirm a proxy/LB/CDN → back-end chain exists (this class needs two parsers).
2. Detect CL.TE / TE.CL / TE.TE by timing, then confirm by differential response — **and stop here** as the default finding.
3. If and only if exploitation is cleared by the anchor, prove impact against a self-directed marker.
4. File the finding with the exact request bytes and remediation.

## Detect (safe — the default stopping point)

Send with framing preserved — in Burp, uncheck "Update Content-Length"; on the wire use `\r\n` exactly.

### Timing probes (front-end vs back-end disagree → the normal next request stalls)
```http
POST / HTTP/1.1
Host: <in-scope>
Transfer-Encoding: chunked
Content-Length: 4

1
A
X
```
```http
POST / HTTP/1.1
Host: <in-scope>
Transfer-Encoding: chunked
Content-Length: 6

0

X
```
First shape probes CL.TE, second TE.CL: send it, then send a normal request — a stall on the normal request signals the desync. Keep delays short and volume minimal.

### Differential confirmation (self-directed — the finding)
```http
POST / HTTP/1.1
Host: <in-scope>
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 6
Transfer-Encoding: chunked

0

G
```
Send twice; a second response complaining about method `GPOST` confirms the smuggled `G` prefixed the next request. This corrupts *your own* follow-up, so it proves the bug without touching a third party — this is where you stop and file.

### TE.TE header obfuscation
```http
Transfer-Encoding: chunked
Transfer-encoding: cow
```
Also: `Transfer-Encoding : chunked` (space before colon), tab/CR/vertical-tab in the name, `Transfer-Encoding: identity, chunked`, duplicate/case-varied `Content-Length`. One tier honoring the obfuscated header and the other ignoring it is the desync.

### HTTP/2 downgrade & h2c
Duplicate/conflicting `content-length` under an H2→H1 downgrade (H2.CL/H2.TE), malformed pseudo-headers, and h2c-upgrade smuggling (`Upgrade: h2c`) are all detectable via the same differential approach against your own connection.

## Tooling (throttled, in-scope, detection-first)

```bash
smuggler.py -u https://<in-scope>/              # CL.TE/TE.CL/TE.TE detection
h2csmuggler check https://<in-scope>/ http://localhost   # h2c upgrade check
```
Burp **HTTP Request Smuggler** (+ Turbo Intruder for custom framing, Param Miner for hidden surface). Run detection modes only; keep concurrency at 1 and volume low — these tools can queue-poison a shared front-end. Never point them at a host off the allowlist.

## Exploitation (GATED — anchor's explicit go, cleared ROE, self-directed marker)

Do **not** run these on your own judgment. Where the human has cleared it, prove the *primitive*, not the maximal impact:

- **Front-end control bypass / access-control evasion** — smuggle to a path the front-end would block, demonstrated to a benign marker path, not to real admin data.
- **Response-queue / cache poisoning** — prove you can influence the *next* response *on your own connection or a marker cache key*; do not poison a shared cache key real users hit.
- **Request capture ("hijacking")** — demonstrate the capture channel with your *own* second request as the "victim", never a real user's session or token.
- **Client-side desync / WebSocket / CONNECT-tunnel variants** — same rule: self-directed proof only, no live third party.

A documented proof-of-reachability (the desync exists and this primitive is available) is the deliverable on a production target — actually hijacking a user is the incident the ROE exists to prevent.

## Remediation (for the finding)

1. **Fix** — use one RFC-compliant HTTP parser across the whole chain; normalize `Host`/`:authority`; reject requests carrying both `Content-Length` and `Transfer-Encoding`, and any non-`chunked` TE; enforce a single, consistent message-framing signal at the edge.
2. **Defense in depth** — prefer end-to-end HTTP/2 and avoid H2→H1 downgrades; disable/tightly control h2c upgrades at the edge; strip hop-by-hop and duplicate headers at the gateway; set `Connection: close` on sensitive responses and reset the back-end connection per request where feasible.
3. **Detection** — alert on requests with duplicate/ambiguous `Content-Length`/`Transfer-Encoding`, on obfuscated TE header names, and on connection-reuse anomalies and response-queue-length spikes at the front-end.

Write it up in the `appsec-reporting` finding format, **CWE-444** (Inconsistent Interpretation of HTTP Requests / HTTP Request Smuggling), with the exact-bytes reproduction and a note stating whether the entry stops at detection or was cleared for the demonstrated primitive.
