---
name: web-idor
description: "IDOR / broken object-level access testing for a pentest-team engagement — horizontal and vertical enumeration, numeric/UUID/encoded id manipulation, add-missing-id, method and type switching, array/object wrapping, parameter pollution, mass assignment (BOPLA), and cross-tenant breaks across REST/GraphQL/gRPC/presigned-URL surfaces, proven against a planted marker or a second test tenant. Load it when the appsec-triage access-control sweep turns up an IDOR lead on a claimed web/API target."
---

# Insecure Direct Object References — under the engagement protocol

Deep methodology for the IDOR / broken-object-level-authorization class. You reach here from the `appsec-triage` access-control sweep with a lead on a surface you already own on the board.

## Under the engagement protocol

- **Claimed and in-scope only.** Every id-swap request goes to a target you own on the board and that is on the `ROE.md` allowlist — enumerating IDs on a host you have not claimed risks racing another operator and tripping a shared rate limit.
- **Prove with a marker, not a harvest.** Confirm the broken check against a *record you planted* or a *second test tenant you were assigned*, and stop at a single sample — never enumerate the real customer range to "show scale". No-real-data means the proof is one marker object or a hash, not a scraped table of victims' data.
- **Read before write; write/RCE gated.** A read IDOR (`GET` another tenant's object) is confirmable in-scope. A *write* IDOR — mutating, deleting, mass-assigning `is_admin`, disabling another user's 2FA — is destructive/privilege-changing: mark the surface blocked and route through the lead to the anchor for the human's explicit go before you fire it. Demonstrating the write *primitive exists* against your own planted marker beats mutating a real record.
- **OOB stays in-scope and benign.** Blind-IDOR callbacks (tracking URL in a modifiable param) point at a BENIGN in-scope listener only — never a live external pull. A presigned-URL or SSRF-shaped object reference that could leave the app is proven by reaching an in-scope endpoint; reachability is the finding, crossing is an incident.
- **Rate-limit and coordinate.** Sequential enumeration and Intruder/Turbo Intruder ranges hammer a shared host and trip a WAF/lockout for the whole team. Throttle, keep ranges small, and coordinate load on the board — especially with the auth operator whose lockout tests your probe can disturb.
- **Log and file** per PROTOCOL §Evidence and §Findings — findings in the `appsec-reporting` format, with a reproduction another operator could re-run against the same two test accounts.

## Quick workflow

1. Use the two accounts the lead assigned in Decisions — an *attacker* and a *victim* at the same privilege, plus one lower/higher role for vertical tests. Plant a marker object in the victim account.
2. With your own proxy, browse every sensitive feature and catalog each object reference (URL, body, cookie, header, JWT claim, WebSocket frame).
3. Replay the attacker's request against the victim's marker id; when direct swaps fail, work the bypass ladder.
4. Confirm the break (attacker session reads/writes the victim marker); stop at one sample. Gate any write behind the anchor.
5. File the finding with a clean two-account reproduction and remediation.

## Map the object references

Look for identifiers everywhere, not just the URL:
```
id  user_id  account_id  file  doc  document  record  item  order  number
profile  uuid  guid  key  group  role  owner  target_id  org_id  tenant
```
Also: signed cookies and JWT claims (`sub`, `org_id`, `tenant`) — tamper if the server fails to re-authorize; hidden params in client JS (harvest with `arjun`); IDs leaked in list/search/autocomplete responses, error messages, export files, and analytics beacons. An IDOR that needs an unguessable UUID becomes exploitable the moment another endpoint leaks it.

## Manipulation ladder

Try these against your assigned victim marker, in order:
```
# Direct
id=1001(attacker) -> id=1002(victim marker)
# Add a missing id the endpoint didn't ask for
GET /api/messages            -> GET /api/messages?user_id=<victim>
# Decode-modify encoded ids
/api/document/MjQ2 (b64 "246") -> /api/document/MjQ3 (b64 "247")
# Numeric <-> non-numeric substitution
account_id=<uuid>            -> account_id=1002
```
```json
// Array / object wrapping (parser-dependent auth bypass)
{"id":1002}      ->  {"id":[1002]}
{"id":1002}      ->  {"id":{"id":1002}}
// Array element swap
{"items":[{"id":123,"owner":"me"}]} -> {"items":[{"id":456,"owner":"victim"}]}
```
```
# Type / method / version switch
GET /resource/1002        -> GET /resource/1002.json  (and .xml .config)
GET /api/users/1002       -> POST/PUT /api/users/1002
GET /v3/users/1002 (403)  -> GET /v1/users/1002 (200)   # older API, weaker check
```
```
# HTTP parameter pollution (front-end/back-end disagree on which wins)
GET /api/document?id=<attacker>&id=<victim>
GET /api/users?user_id=<attacker>[]&user_id=<victim>[]
```
```
# Path / case normalization
/admin/profile -> /ADMIN/profile ;  URL-encoded slash %2F ; dot-segments
POST /users/delete/<MY_ID>/../<VICTIM_ID>
```

## Mass assignment (BOPLA)

Set properties the request schema never exposed — a write IDOR against your *own* object, so confirmable read-side, but privilege-elevating variants are gated:
```json
{"name":"me","role":"admin","is_admin":true,"user_id":"<victim>"}
```
Fuzz `camelCase`/`snake_case`/`PascalCase` variants (`userId` vs `user_id` vs `UserId`), nested objects (`{"profile":{"owner_id":"<attacker>"}}`), and JSON Patch (RFC 6902) / Merge Patch (RFC 7386) bodies for forbidden fields. Setting `is_admin`/`role` on a live account is a privilege change — prove it on a planted marker and route the real elevation through the anchor.

## Surface-specific

```graphql
# GraphQL — swap id args in queries AND mutations; auth is often root-only,
# so test aliases, fragments, batched/persisted queries, __typename sibling swaps
query { user(id:"<victim>"){ email totpSecret } }
```
- **gRPC / protobuf** — IDs ride in binary; drive with `grpcurl`, pull `.proto` via server reflection if enabled, re-check authz on every method.
- **Presigned URLs (S3/GCS/Azure)** — the URL *is* the object reference. Tweak the `Key=`/object path or query params and try cross-tenant replay — against your assigned tenant, never a real one.
- **Observability leaks** — trace UIs (Jaeger/Zipkin, `/api/v2/traces`) expose span attributes with user IDs; harvest for your marker, don't scrape real ones.
- **Real-time** — WebSocket/Socket.io room ids as direct references (`?room=<id>`); test the frame the app uses.

## Blind IDOR

When the response body doesn't reveal success: compare status/size/timing/ETag between a valid and an invalid id (existence side-channel), or plant a tracking URL in a modifiable param and watch a **benign in-scope listener** for the callback. Keep probe counts low.

## Automation (throttled, in-scope, two-account)

```bash
# Autorize / AuthMatrix in Burp: replay every request under the victim session,
# flag any that don't drop to 403 — the cleanest two-account auth-diff.
# Small, throttled enumeration only — a marker range, not the real one:
for id in $(seq 1000 1010); do
  curl -s -o /dev/null -w "%{http_code} $id\n" \
    -H "Authorization: Bearer $ATTACKER" \
    "https://<in-scope>/api/documents/$id"
done
arjun -u "https://<in-scope>/api/messages"   # discover a missing id param
```
Keep ranges tight and add delay on shared/production targets; never point automation outside the allowlist, and never let the "range" become the customer base.

## Chaining

Note chains for the reporter — they lead the report: IDOR + info-disclosure (a list endpoint leaks the UUIDs that make the IDOR exploitable), IDOR write + stored XSS (mutate a field other users render), or an MFA IDOR (`/api/users/<id>/disable-2fa`) feeding account takeover. A low read-IDOR plus a leak plus a write is a Critical chain — file it as one narrative entry citing its links.

## Remediation (for the finding)

1. **Fix** — enforce a server-side ownership/tenant check on *every* object request, deny-by-default at the first layer; never trust a client-supplied id as proof of authorization. In GraphQL, authorize per-field, not just at the root resolver.
2. **Defense in depth** — per-session indirect references instead of raw DB ids; ABAC/RBAC authorization framework; strict input validation (type/format/range); short-lived, method-scoped, backend-re-validated presigned URLs; disable gRPC reflection in prod; partition CDN caches by auth so private resources aren't cacheable.
3. **Detection** — log every access to sensitive objects with the acting principal; alert on one session touching many distinct object ids (the enumeration signature); add per-endpoint authorization unit tests and a CI BOLA/IDOR generator that blocks merges.

Write it up in the `appsec-reporting` finding format, CWE-639 / CWE-284 / A01:2021 Broken Access Control, with the two-account, marker-based reproduction.
