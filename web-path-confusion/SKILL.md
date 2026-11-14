---
name: web-path-confusion
description: "Proxy↔backend parser-differential testing for a pentest-team engagement — path confusion / normalization discrepancies where a front layer (WAF/CDN/LB/gateway/upload-accelerator) and the backend read the same URL differently: encoded-character route misses, dot-segment and `..;/` gaps, `%2f`/`%252f` double-decode, path-parameter and bare-query suffixes, trailing-slash tricks — to bypass a front auth/routing gate, skip upstream preprocessing so the backend trusts a value the proxy was meant to author, confuse a cache key, or evade a WAF. The same two-parser shape also occurs *inside a single app* — its own auth filter and request dispatcher normalizing one path differently (no front proxy needed). Load it when the appsec-triage parser-differential sweep turns up a lead: a claimed target with a proxy/gateway in front, or a URL-pattern auth filter whose 401/403 gate you want to walk through."
---

# Path Confusion / Parser Differentials — under the engagement protocol

Deep methodology for the **parser-differential** class: two components interpret the *same* URL differently, so a decision one makes (route, authenticate, buffer, cache, filter) is made against a *different* resource than the one actually served. This runs in two settings, same root shape:

- **External (proxy↔backend):** a WAF/CDN/load-balancer/API-gateway/upload-accelerator sits in front of a different backend, and the front layer's decision applies to the wrong backend resource.
- **Internal (filter↔dispatcher, one app, no proxy):** the app's own **security filter** matches a URL *pattern* against the raw path to decide auth/routing, while the **request dispatcher** strips path-parameters (`;segment`) and suffixes before routing. A `;`-appended segment or a fake static suffix (`;.jsp`/`;.css`) can read as a *public* resource to the filter (so auth is skipped) while the dispatcher still routes it to a *protected* handler — an unauthenticated bypass on a single-server target, no front proxy required. The classic Java-servlet / Spring-Security path-matching bypass (`/..;/`, path-parameters, static-suffix).

You reach here from the `appsec-triage` parser-differential sweep — or from its Authentication "attack the auth wall" step — with a lead on a surface you already own on the board.

Same root shape as `web-request-smuggling` — two parsers, one input, two answers — but a **different axis**: that class is message *framing* (where one request ends); this is *URL interpretation* (which route/normalized path each parser believes it has). If your lead is about framing, use `web-request-smuggling`.

The named class: Orange Tsai's "Breaking Parser Logic" / path normalization (BH & DEF CON 2018), "parsing discrepancies" (WAFFLED). Real bugs of this exact shape: **CVE-2026-85706** (GitLab — encoded char makes Workhorse's upload route miss, backend trusts raw `file.path` → unauth arbitrary file read), **CVE-2025-0108** (PAN-OS Nginx/Apache path confusion → auth bypass), **CVE-2024-8181** (Flowise `?/api/v1/ping` bare-query suffix), Tomcat `/..;/` reverse-proxy traversal, Apache **CVE-2021-41773/42013**.

## Under the engagement protocol

- **Claimed and in-scope only.** Every probe runs against a target you own on the board and that sits on the `ROE.md` allowlist. You are sending crafted paths to the front proxy of an in-scope app — never to an off-allowlist host, even to "compare parsers."
- **Detecting the differential is safe; acting on what it unlocks is not.** Proving that the proxy and backend disagree — a differential response between two logically-equivalent paths — is read-only and is *the finding*. But the payload of that finding is usually a bypass: reaching a route the edge would have gated (`/admin`, a management console), skipping the preprocessing that sanitizes an internal param (→ arbitrary file read/write), or slipping a payload past the WAF. **Stop at reachability.** Actually reading `/etc/shadow`, calling the admin write, or dumping the config is destructive/outward-facing — mark the surface blocked and route through the lead to the anchor for the human's explicit go.
- **Prove with a benign self-directed marker, never real data.** Show the gated route is reachable by hitting a benign in-scope path or an existence/echo oracle that returns *your* marker, not by exfiltrating a real secret. Confirm the auth gate is bypassed against a page you're allowed to see two ways, not by pulling another tenant's record.
- **Rate-limit and coordinate.** Encoding-ladder fuzzing across a route list trips WAF bans that block the whole team on a shared host, and hammering a gateway degrades it for everyone. Low concurrency, throttle on shared/production targets, coordinate load on the board.
- **Log and file** per PROTOCOL §Evidence and §Findings. File the confirmed finding into `FINDINGS.md` in the `appsec-reporting` format with an exact-bytes reproduction — **the encoding is load-bearing**, so capture the literal path (and note `curl --path-as-is`, without which curl rewrites your payload before it leaves).
- **Feed the vault.** This class is stack-specific and expensive to re-derive, so the confirmed map is durable per-app knowledge (`appsec-recon`, PROTOCOL §Vault): the front stack and backend runtime, the normalization bytes on which they diverge, which routes are edge-gated, and any value the front is *supposed* to author for the backend. Promote it (client-neutral or per-app per the engagement's data-handling mode, never live data) so the next re-test starts from the differential instead of re-finding it.

## Quick workflow

1. Confirm a two-parser chain exists — **external** (`appsec-recon` fingerprint: a WAF/CDN/LB/gateway/accelerator in front of a different backend) **or internal** (a single app with a URL-pattern auth filter in front of its own dispatcher — any Java-servlet/Spring app, no proxy needed).
2. Find where the **front layer decides on the path** — an auth/routing gate, a WAF rule, an upload/preprocessing handoff, a cache key.
3. Craft a path that is **equivalent to the backend** but that the front layer reads differently; confirm by **differential response** (same resource, two paths, two front behaviors).
4. Assess what the differential unlocks (see Impact classes) and prove the *primitive* benignly.
5. Turn a blind primitive into evidence via an oracle (existence, verbose parser error, timing) — content extraction only if cleared.
6. File the finding: the exact path, which layer read it which way, and the impact primitive.

## Detect — the two-parser method

Pick a resource the **front layer treats specially** and reach it by a second spelling the **backend normalizes to the same thing**. A divergence in the *front's* response (now un-gated, un-buffered, un-filtered, cached differently) is the differential.

```bash
# baseline vs confused spelling — read status + who answered (Server/headers), redirects OFF
curl -sS -i --path-as-is "https://<in-scope>/admin"          -o /dev/null -D - | grep -iE '^(HTTP|server|x-)'
curl -sS -i --path-as-is "https://<in-scope>/%61dmin"        -o /dev/null -D - | grep -iE '^(HTTP|server|x-)'
```
Front gates `/admin` (403/redirect) but proxies `/%61dmin` untouched while the backend decodes it to `admin` → bypass. Same logic reaches routing (a front route regex *misses* the encoded form and falls through to a generic proxy) and preprocessing (an upload/rewrite handler misses, so the raw request survives to the backend).

### The confusion ladder (walk against a benign in-scope resource)
```
# encode a routing-significant character — front matches literally, backend decodes  (GitLab %66iles)
/admin            → /%61dmin            /a%64min            /repository/%66iles/x
# dot-segment collapse gap — one layer resolves .. , the other doesn't
/..;/admin        /.;/admin             /%2e%2e/admin       /..%2f admin        /.%2e/admin
# encoded / double-encoded slash — decode-order differs edge vs origin
/api%2fadmin      /api%252fadmin        /api%c0%afadmin     (overlong UTF-8)
# path parameters (Tomcat & friends treat ;segment as decoration)
/admin;/          /admin;foo=bar/       /secure/..;/admin
# bare-query / fragment suffix — public suffix satisfies the front gate  (Flowise)
/api/v1/apikey?/api/v1/ping             /admin#/public          /admin%23/public
# trailing / leading normalization
/admin/           /admin/.              /admin//             //admin           /./admin
# backslash, case, null, trailing dot
/Admin            /admin\..             \admin               /admin%00.css      /admin.
# extension/static-file confusion (front allowlists *.css/*.js and skips auth)
/admin/x.css      /admin;/x.js          /admin/..%2fx.js
```
For each: does the **front** behave differently (gate off, route missed, WAF quiet, cache hit) while the **backend still serves the sensitive resource**? Record *which layer* read it *which way* — the control's exact failure is itself reportable.

### Confirm it's a real differential, not just a 404
- **Differential response.** The gated path and the confused path must resolve to the *same backend resource* — compare bodies/headers/`Server`, not just status. A confused path that 404s proved nothing.
- **Who normalized what.** Front-injected headers (`Via`, `X-Cache`, gateway request-IDs) present on one spelling and absent on the other tell you which layer handled it.
- **Encoded-form freshness.** If the front re-encodes before forwarding, the backend may never see your bytes — capture the request the backend actually received (proxy history / an in-scope echo endpoint) where you can.

### Known normalization behaviors — fingerprint both ends, then aim
The ladder above is *what to send*; this is *where it bites*. Fingerprint the front layer and the backend (`appsec-recon`), then target the byte their two parsers are documented to disagree on:

- **Nginx** — `merge_slashes on` (default) collapses `//`; `proxy_pass http://b/` (trailing path) decodes+normalizes the URI before forwarding, `proxy_pass http://b` (no path) forwards the **raw** client path; `location` matches on the decoded/normalized form.
- **Apache httpd** — `MergeSlashes on` by default; `<Location>`/`Require` gates and `mod_proxy` can match *before* some normalization; `%2e%2e`/`%3f`/encoded-slash mishandling is the CVE-2021-41773/42013 family.
- **Tomcat / Java servlets** — strips `;param` path-parameters and resolves `/..;/` to `/../` *after* a reverse proxy has already matched the raw form; inside one app, `getRequestURI()` (raw, encoded) vs `getServletPath()`/`getPathInfo()` (decoded) is itself a differential.
- **Spring** — matrix (`;`) params, historic trailing-slash equivalence (`/admin` == `/admin/`), suffix pattern matching (`.json`/`.html`), and `PathPattern` vs `AntPathMatcher` differences that have slipped payloads past security matchers.
- **Envoy / Istio / API gateways** — `normalize_path` and `merge_slashes` are frequently **off** by default and `path_with_escaped_slashes_action` governs `%2f`; a gateway that leaves `%2f` encoded while the backend decodes it is the CVE-2025-0108 shape.
- **CDN / WAF edge (Cloudflare/Akamai/CloudFront)** — decode and compute the cache key on their *own* normalization, and may forward raw or re-encoded; static-extension routing (`.css`/`.js`) is the lever for auth-skip and cache deception.
- **Language runtimes** — the backend's decode step is what your encoded byte becomes: Rack/Grape decode-then-route (the GitLab side, `%66iles`→`files`), PHP `PATH_INFO`, Node frameworks vary. Match the encoded char to a byte the *front* keeps literal but the *runtime* decodes.

## The reusable heuristic — bypass the upstream, inherit its trust

The highest-impact form, and the crux of GitLab CVE-2026-85706:

> **When a trusted upstream rewrites, sanitizes, or authenticates a request before the backend sees it, find an input that makes the upstream *skip that step while still forwarding the request*. The backend then trusts a value the upstream was supposed to author.**

In GitLab, `files`→`%66iles` made Workhorse's upload-accelerator route **miss**, so it never buffered the body or rewrote `file.path` to a safe signed temp path — but it *still* proxied the request and *still* attached its "came-via-proxy" JWT. The backend, having no `authenticate!` of its own and assuming Workhorse had authored `file.path`, read the attacker's raw `file.path=/etc/passwd`. Two defects lined up: a **skipped preprocessing step** (unlocked by the differential) and a **backend that trusted the upstream's presence as authentication**.

Hunt this wherever a front layer is *supposed* to set/clean a value the backend consumes:
- Upload accelerators / body-buffering proxies that rewrite a temp-path or size param (as above).
- Edge auth/SSO that injects an identity header (`X-Authenticated-User`, `X-Forwarded-*`) — bypass the edge and the backend trusts a now-attacker-supplied header (cross-link `web-parameter-pollution`, header-injection).
- WAFs that normalize/annotate before the origin — a route the WAF doesn't recognize is a route it doesn't filter (cross-link `web-waf-bypass`).
- Cache/edge that computes a key on one normalization while the origin serves another → **cache poisoning / cache deception** (a confused static-extension suffix caches an authenticated page under a public key).

The backend's mistake is trusting *"a trusted component was supposed to handle this"* rather than the *validated object that handling was supposed to produce* — report it as that trust bug, not a routing quirk.

## Impact classes (prove the primitive, gate the payoff)

- **Front-proxy access-control bypass** — reach a route the edge gates (`/admin`, management/API consoles, PAN-OS-style panels). Proof: the gated resource answers via the confused path. Reading privileged data is the gated crossing.
- **Preprocessing-skip → backend trusts a raw param** — file read/write, SSRF, injection, depending on what the skipped step was meant to sanitize. Proof: the backend reaches the raw-param code path (an existence/echo oracle flipping) — not the full dump.
- **Cache poisoning / web cache deception** — a confused key stores or serves the wrong response. Proof against a marker cache key / your own request; poisoning a shared key real users hit is the incident the ROE prevents (same rule as `web-request-smuggling`).
- **WAF / filter evasion** — the payload the backend executes is a payload the front never inspected. Chains into whatever injection the backend is vulnerable to (`web-sqli`, `web-xss`, `web-rce`).

## Turning a blind primitive into evidence — the oracle

The differential often lands you on a handler whose output you don't get back (GitLab's file read fed a commit parser, not a response). Escalate blind → observable *before* asking to cross:
- **Existence / status oracle** — a path that exists vs one that doesn't yields different status/error (`400 local file not present` vs `400 branch is required`) — proves the read happened.
- **Verbose parser-error reflection** — the primary GitLab exfil channel: a downstream parser echoes content in its error. Rack's `parse_nested_query` reflected file bytes as `invalid %-encoding (<file content up to the first bad %>)`. Hunt error branches that interpolate the value/message; a benign marker in the reflected error proves the disclosure channel without extracting a real secret.
- **Timing** — a read/fetch that only fires on the confused path is a timing oracle for reachability.

Pin down *whether the entry stops at reachability or a disclosure channel is proven* — and never run the full extraction on your own judgment.

## Tooling (throttled, in-scope, `--path-as-is`)

```bash
# manual — ALWAYS --path-as-is, or curl normalizes your dot-segments before sending
curl -sS -i --path-as-is "https://<in-scope>/..;/admin" -o /dev/null -D -

# route/encoding fuzz against a known-gated path (low concurrency on shared hosts)
ffuf -u "https://<in-scope>/FUZZWORD" -w confusion-encodings.txt -mc all -o out.json
feroxbuster -u https://<in-scope> --dont-filter    # note differing behavior on encoded dupes

# CVE-shaped detectors — nuclei templates key on the differential response, not a live read
nuclei -u https://<in-scope> -tags path-traversal,misconfig,cve
```
Burp: send the baseline and confused request to Comparer, and use the proxy history to see *what the backend actually received* after the edge re-encoded. Turbo Intruder for large encoding matrices. Keep concurrency at 1–2 on shared/production targets; a route-fuzz is exactly what earns a team-wide WAF ban. Never point any of it off the allowlist.

## Remediation (for the finding)

1. **Canonicalize before you decide.** The front layer must make its routing/auth/cache decision on the *same fully-normalized form the backend will use* — decode once, resolve dot-segments, then match. A single decode-then-match step in the front (or rejecting encoded characters in static route names) closes the differential.
2. **One parser, or reject ambiguity.** Use one RFC-compliant path parser across the chain; where that's impossible, have the edge **reject** requests whose normalized and raw forms differ (encoded slashes/dots in path segments, `;` parameters, bare-query suffixes) rather than pass them through.
3. **Never trust a value a trusted upstream was *supposed* to set.** Consume the *validated object* the preprocessing produces (a signed, path-confined handle), not the raw string that happens to share its name — and re-validate at the backend.
4. **Defense in depth: authenticate at the backend, not only the edge.** Edge auth is a filter, not the identity check; the origin must independently authenticate/authorize, so a bypassed edge doesn't equal a bypassed app.
5. **Detection.** Alert on requests whose path decodes to a different route than it literally matched, on encoded path-segment characters and `..;/`/`%2f`/`%252f` in path names, and on backend routes reached without the front's expected preprocessing markers.

Write it up in the `appsec-reporting` finding format, **CWE-436 (Interpretation Conflict)** as the root, plus the impact CWE (CWE-22 traversal, CWE-289 auth-bypass-by-alternate-name, or the injection CWE the WAF-bypass reached) and OWASP **A01 / A05**. Give the exact confused path, name which layer read it which way, and state whether the entry stops at reachability or a disclosure channel was proven.
