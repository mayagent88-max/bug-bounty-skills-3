---
name: web2-security-recon
description: "Use when reconnoitering or testing web2 targets for the operator."
version: 1.0.0
author: Hermes Agent
license: MIT
platforms: [linux]
metadata:
  hermes:
    tags: [security, recon, bug-bounty, api, web2, red-team]
---

# Web2 Security Recon

Class-level procedure for web2 bug bounty and red-team work: mapping a target's API
surface, testing its auth and rate-limit controls, and verifying a suspected
vulnerability before it is reported.

Load this when mapping a web app's endpoints, testing login/registration/OTP flows,
or checking whether a suspected injection / IDOR / info-disclosure finding is real.

Not for: web3 contract auditing (use `web3-bot-ops`), writing final report prose, or
choosing which bounty program to target.

Program selection per platform lives in `references/`:
- `references/bugcrowd-program-selection.md` — public JSON endpoints, per-program
  stats, and the ranking formula for Bugcrowd.
- YesWeHack has no separate reference: its per-program JSON record (rule 13)
  carries the scope, UA, and rules, and the monthly-report competition signal
  comes from the public program list.

Source-audit state for the Grafana OSS repo (cleared areas, findings, next
candidates) lives in `references/grafana-audit-state.md` — read it before any
Grafana source pass so cleared surface is not re-walked.

## When to Use

- Mapping a web application's API surface from its frontend JavaScript.
- Testing login, registration, OTP, or OAuth flows for control weaknesses.
- Verifying whether a suspected injection, IDOR, rate-limit, or info-disclosure
  finding is real before reporting it.
- Working a target whose assets are behind an IP-based block and need a residential
  exit.

## Always-on rules

0. **Deliver finished reports as Telegram documents, not chat messages.** Long
   reports pasted into chat get chunked into a dozen fragments that arrive out of
   order. Write the report to a file and send it with the Bot API
   (`sendDocument`) to the operator's chat id, then state the absolute path. One file, one
   message, no truncation.

1. **Read the program's rules AND its out-of-scope list before the first request.**
   Note the required User-Agent suffix, testing window, request-rate cap, and whether
   automated scanners are banned. Violating these gets the whole VPS IP range blocked
   and burns the target. The out-of-scope list is equally load-bearing: programs
   routinely exclude ID/UUID enumeration, error-message path disclosure, and missing
   rate limiting on non-sensitive endpoints. Check a finding class against that list
   before building a PoC for it, not after.
2. **Verify before you claim.** A finding is not a finding until a control test proves
   the negative case fails. Two verifications are mandatory — see
   `references/verification-recipes.md`:
   - Rate limiting: burst 25+ attempts and read response headers before reporting
     "missing rate limit".
   - Query injection: test a nonexistent field name and confirm matched documents
     actually contain the term before reporting field-specific injection.
   The recipes also cover the case where the program's rules forbid the burst, the
   data-existence oracle, the CORS wildcard false positive, and auditing in-scope
   source code locally.
3. **Escalate the account blocker instead of grinding.** When every interesting endpoint
   returns 401, IDOR and auth bugs are untestable. Ask the operator for credentials or the
   program's email alias rather than continuing to enumerate — hours of unauthenticated
   probing produce nothing reportable, and registration endpoints are usually
   reCAPTCHA-gated (the site key is visible in the page HTML, which confirms the gate
   but does not open it). A uniform application error on every endpoint —
   `{"message":"The credential is not found"}` rather than a 401 — is a cookie or
   session gate set by the login flow. Header spoofing (`Authorization`, custom
   `X-*-Id` identity headers, partner identifiers) does not satisfy it, so do not
   spend calls trying variants before escalating.
4. **Classify an IP block before spending a tunnel on it.** If a whole host family
   times out from the VPS but DNS resolves, run the two-request diagnostic first: a
   control site in the target's own country plus the target itself. DNS resolving
   while TCP 80/443 times out, with the control site answering, is an IP-region
   geo-block. A datacenter-reputation block lifts through the residential SOCKS
   proxy; a **region** block does not, because the residential exit sits in the same
   region as the VPS — ask the operator to open the host in their own browser before
   investing further, and pivot if that also times out. Route further requests
   through the tunnel only for the datacenter-IP case.
5. **Rate-limit everything, always.** This VPS is 2 vCPU / 3.6GB RAM. Set `-rl` and `-c`
   on every scan; never run an unbounded parallel job.
6. **Recognise bot-protection families early and pivot.** Cloudflare Bot Management,
   Akamai, and PerimeterX each leave a distinct signature (`cf-mitigated: challenge`,
   an `_pxvid` cookie, a press-and-hold interstitial in a non-English locale). When a
   target's whole asset family returns the same challenge page, that program is not
   workable from this VPS — record it as a dead end with its signature and move to the
   next target instead of retrying with different headers.
7. **Never write a secret inline in a command.** When the operator supplies an API token, store
   it once in a `chmod 600` file and read it into a shell variable from there. A token
   typed into a command string is persisted in shell history, the session state
   database, and its full-text index; cleaning all three afterwards is slow and
   error-prone.
8. **Recover the exact request shape before replaying an endpoint.** An endpoint that
   answers from the browser but 404s from curl is almost always a request-shape
   mismatch, not a missing endpoint. Gateways answer a malformed request with a
   routing error (`no service match for your request`) that reads exactly like a dead
   path. Before concluding anything, capture the real request — method, body encoding,
   header set, and cookies — and replay it verbatim. See
   `references/api-endpoint-discovery.md` for the capture procedure and the
   shape-mismatch table.
9. **Check the finding class against the program's out-of-scope list before building
   the PoC, and again before submitting.** User enumeration, error-message
   disclosure, and missing rate limiting on non-sensitive endpoints are excluded by
   most programs even when the bug is real and reproducible. Confirming the bug is
   worthless if the class is excluded — read the exclusion list first, then decide
   whether the finding is worth a write-up at all. CORS is the sharpest trap:
   HackerOne's Core Ineligible Findings and most YesWeHack programs both require a
   PoC that reads authenticated data (200, cookie-based) cross-origin, so a
   reflected `Origin` on endpoints that answer 401 is not submittable at all. The
   full submission gate — duplicate check, class check, re-test — lives in
   `bug-bounty-submission`.
10. **When the program bans high-volume traffic, report the design flaw without
   executing it.** A short numeric verification code (6-8 digits) behind an endpoint
   with no attempt counter, no lockout and no `Retry-After` is a genuine finding even
   if you never send the brute force. State the keyspace, the absence of the counter,
   and the impact of a successful guess, and say explicitly in the report that the
   brute force was not run because the program forbids it. Executing it to "prove" the
   finding violates the rules and burns the target; the missing control is itself the
   proof.
11. **A wildcard `Access-Control-Allow-Origin: *` is not a CORS finding.** Only
   reflection of the sent `Origin` is. Check whether the header stays `*` when you send
   an `Origin`, and whether `Access-Control-Allow-Credentials` is present. A wildcard
   with no credentials header cannot read authenticated responses — record it as safe
   and move on.
12. **Read the preflight OPTIONS response for the API's internal header vocabulary.**
   `Access-Control-Allow-Headers` on a preflight lists every header the gateway
   accepts, including ones never documented (`X-Token`, `X-Signature`, `X-Agent-Token`,
   `X-User-Id`, `X-Cursor`). It is a free map of the auth surface and costs one request.
13. **On YesWeHack, read the program's JSON record before the first request.**
   `curl -H 'Accept: application/json' https://api.yeswehack.com/programs/<slug>` returns
   `user_agent` (a mandatory, program-specific UA), the full `scopes[]` list, the reward
   range, and the rules text including the non-qualifying-vulnerability list. It replaces
   scraping the JS-rendered program page and it is where the out-of-scope list in rule 1
   and the UA requirement in rule 1 actually live.
14. **An endpoint that answers `405` with "supported methods: X, Y" has told you its
   whole method surface.** `DELETE` on an auth/tokens endpoint is logout; a `GET` that
   405s is a write endpoint. Use the error body as the method oracle instead of guessing.
15. **Masked PII in a response is a control, not a leak.** `+417****2329` means the
   server is redacting. Confirm the masking is consistent across the search and detail
   endpoints and that no field-selection or limit parameter defeats it; if both hold,
   the directory endpoint is by design and not reportable.
16. **Check `Access-Control-Expose-Headers` too** — it lists the response headers the
   app is allowed to read cross-origin (`X-Count`, `X-Cursor`), which reveals pagination
   and count mechanics worth testing for enumeration.
17. **A 200 on an SPA catch-all path is not a live endpoint.** Nuxt and several other
   SPA hosts return `index.html` with a 200 for every unknown path. Compare the body to
   the root page, or require that it parses as JSON, before recording an endpoint as
   discovered. This bites hardest on Nuxt, where the catch-all hides the real API host
   that `window.__NUXT__` already disclosed.
18. **Drive SPA auth endpoints with a synchronous XHR inside one `js()` call.**
   `browser_exec`'s `js()` returns before any async callback fires and the page context
   does not survive between calls, so a result stashed on `window` by an async
   `fetch`/XHR reads back empty in the next call. Open with
   `xhr.open(method, url, false)`, send, and return `xhr.status` plus
   `xhr.responseText` from the same expression. This is also how you replay an endpoint
   with the page's own cookies and runtime headers attached.
19. **A 403 from curl with an opaque random error code is a missing-header signature,
   not a WAF block.** `{"s":0,"ec":"mWNUB...","m":"An unexpected error occurred"}`
   means the gateway routed your request and rejected it for a header it expected —
   usually a runtime-injected XSRF token. Read the app's config global from the live page
   (`tv.config.xsrfTokenKey`, `tv.config.xsrfToken`) and replay with those headers plus
   `X-Requested-With`. WAF blocks look like challenge pages or `cf-mitigated`, never like
   an application error object.
20. **Make a schema-validated endpoint enumerate its own contract.** Send a payload that
   is wrong in a specific way — an unknown field plus an empty object — and the
   validation error body lists every required field, the type expectations, and the full
   enum of legal values (`must be one of the following: ...`). One request yields the
   complete request contract, which beats mining the JS bundle for the same fields.
21. **Run a control experiment before naming a root cause.** A PoC that succeeds through
   condition X does not prove X is the cause. Re-run the same exploit with X removed; if
   it still succeeds, the real cause is elsewhere and a report naming X gets closed as a
   misdiagnosis. This matters most when the obvious defect — a missing validation call, a
   degenerate accepted input — is real but incidental: the control tells you whether it is
   load-bearing or just a second bug you happened to walk past. Report the cause the
   control implicates, and list the incidental defect separately.
22. **Read the target project's own threat-model / security-model document before auditing
   its source.** Mature crypto and protocol repositories ship one, and it names both the
   bug categories the maintainers actively want and the patterns they have already
   published rebuttals to. Skipping it means spending the session re-deriving conclusions
   the project has pre-answered, and submitting one of the documented non-issues. Audit the
   **verify** paths first — that is where attacker-controlled input enters; the generate
   paths run with the honest party's own secrets and are not the attack surface. Recipes
   for building and reviewing such a repository locally: `references/verification-recipes.md`.
23. **Grep for encoding asymmetry when auditing source.** When one side of a
   symmetric pair is encoded and the other is not — `encode(value)` beside a raw
   `key`, `quote(file_name)` beside a raw `bucket_name`, `quote(path)` beside a raw
   `query` — the unencoded side is the bug. The same read catches the classic BOLA
   signature: an endpoint taking a parent uuid and a child uuid, validating each
   with its own existence lookup, and never checking the child belongs to the
   parent. Both patterns are one grep away and both are routinely real.
24. **Before reporting a code-review finding, test whether the consuming stack
   accepts the malformed input.** A control character injected into a structured
   field (header name, URL, SQL literal) is only exploitable if the library below
   it forwards it. `requests` and `http.client` both refuse CRLF in a header name
   with `InvalidHeader` / `ValueError`, which turns a "header injection" into an
   unhandled-exception crash — a P4, not a P1. Run the rejection test before
   writing the report, and check whether the SDK translates the exception into its
   own error type or lets it escape past the caller's `except`.

## Procedure

1. **Pick the program before the first request.** Rank candidates with the
   platform reference (`references/bugcrowd-program-selection.md` for Bugcrowd):
   low all-time rewarded count, fast validation window, decent average payout.
   A mature program with hundreds of paid reports is a duplicate farm — the
   low-hanging fruit is gone and every finding you build a PoC for has already
   been reported. Record the ranking table under `~/bounty-hunter/<platform>/`
   so the next session starts from the same shortlist.
2. **Read rules, record constraints.** UA suffix, window, rate cap, scanner policy.
   Write them into the recon command so every later request carries them.
3. **Map the API surface.** Frontend JS is the endpoint oracle — mine it before guessing
   paths. See `references/api-endpoint-discovery.md` for the per-stack recipes
   (Next.js, Angular with DI-injected config, PHP ajax.php, OAuth, Flutter) and for the
   published-OpenAPI-spec shortcut, which beats all of them when it exists.
4. **Probe unauthenticated.** Enumerate every discovered endpoint without a session and
   record status codes. Anything returning 200 with a body is a candidate; anything 401
   marks the auth boundary and feeds step 6.
5. **Test the controls that need no account:** rate limiting on login/OTP, user
   enumeration via response differences, open redirect on OAuth `redirect_uri`, CORS
   reflection, exposed spec files. Apply the verification recipes before believing any
   of them.
6. **Draw the auth boundary.** List every 401 endpoint. That list is the IDOR test plan
   and is only executable with a session — go to rule 3.
7. **Log findings with proof.** Status code, response body, and the exact request. A
   finding without a reproducible request is not reportable.
8. **Audit the source code locally when it is in scope.** Open-source programs put the
   repository in scope, and a local clone is both faster and safer than probing the live
   instance: grep for the vulnerability class across every plugin instead of guessing
   paths, and you never trip a rate limit. Clone shallow (`git clone --depth 1 -b
   <branch>`) to keep the VPS disk and RAM flat, then read the specific files the grep
   points at rather than the whole tree.
9. **For a GDPR / data-subject portal, map the full chain before testing any step.**
   The pattern is `search` (identifier -> existence oracle) -> `send_code` (challenge
   to the victim's email/SMS) -> `validate_code` (returns an access token) ->
   `?action=view&auth=<token>` (renders the subject's full data set). Test each link
   separately: the search step for enumeration, the validate step for rate limiting and
   code entropy, and the view step for token predictability or reuse. The chain is only
   as strong as its weakest link, and the weakest link is usually the one with no
   attempt counter.

## Reporting style

Short, casual Indonesian (gue/lo), results first. What was found, the request that
proves it, and the impact. On a dead end: why, what was tried, what is next. Never
claim a control is missing without the burst test that proves it.
