---
name: web-race-condition
description: "Race-condition / TOCTOU testing for a pentest-team engagement — spotting the read-modify-write and time-of-check-to-time-of-use windows in limit, coupon, balance, voucher, MFA and inventory flows, then hitting them concurrently with the HTTP/2 single-packet attack (Burp Repeater parallel / Turbo Intruder last-byte sync) or a synchronized-gate script, plus the session-lock and DB-isolation nuances that decide whether a window is exploitable. Load it when the appsec-triage business-logic sweep turns up a race / TOCTOU lead on a claimed web/API target."
---

# Race Conditions — under the engagement protocol

Deep methodology for the race/TOCTOU class. You reach here from the `appsec-triage` business-logic sweep with a lead on a surface you already own on the board.

## Under the engagement protocol

- **Claimed and in-scope only.** Every concurrent request goes to a target you own on the board and that is on the `ROE.md` allowlist — nothing else.
- **Prove with a marker, then reverse the side effect.** Confirm the window with the smallest burst that duplicates a side effect against a *planted* record — a marker coupon, a test-account balance, a marker voucher — then undo it (restore the balance, void the extra seats, cancel the duplicate order) and log both legs. No-real-data means the proof is "the single-use code redeemed twice", not a drained live wallet.
- **Read before write; escalation goes to the anchor.** Racing a real payout, a real withdrawal, a chargeback, or any irreversible mutation is destructive and outward-facing — mark the surface blocked and route through the lead to the anchor for the human's explicit go. Prove the primitive on a reversible marker flow first; a documented double-redeem of a marker beats moving real money.
- **Concurrency is load — rate-limit and coordinate.** A race burst is a spike; 50 parallel requests on a shared host can trip a WAF ban or degrade a service the ROE forbids you to degrade. Keep bursts small (a single-packet group of ~5-20 wins most true races), coordinate load on the board, and back off the moment the target slows. Never race to "confirm" a rate-limit gap by volume the ROE forbids.
- **Log and file** per PROTOCOL §Evidence and §Findings — findings in the `appsec-reporting` format, with the exact concurrent sequence and the state delta another operator could reproduce.

## Quick workflow

1. Spot state-changing, "allowed once" operations on your surface (redeem, withdraw, vote, accept, verify).
2. Baseline the normal single-request flow and its state delta.
3. Fire a small concurrent burst against a marker record with the single-packet attack.
4. Confirm the duplicated side effect, then reverse it and log both legs.
5. File with the request group, thread count, and the before/after state.

## Where the windows are

Read-modify-write and check-then-act flows are TOCTOU-prone. Target: single-use coupon/gift-card/voucher redeem, balance withdraw/transfer, "one per user" vote/like/follow, invite/seat acceptance, free-trial-per-email signup, last-item inventory reservation, MFA/OTP submit before the lockout counter increments, password-reset token issuance, and email-change confirmation.

## The concurrency primitive

Classic HTTP/1.1 pipelining is dead on modern servers; use the **single-packet attack** (HTTP/2, all requests' final frames in one TCP segment → true concurrency, ≤ ~4 µs skew) or **last-byte sync** (HTTP/1, send near-complete requests, flush final bytes together).

```
# Burp: send the request to Repeater as a group of N tabs →
# "Send group in parallel (single-packet attack)". Keep N small.
```
```python
# Turbo Intruder — single-packet gate, small burst against a marker
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=1, engine=Engine.BURP2)
    for _ in range(10):
        engine.queue(target.req, gate='race')
    engine.openGate('race')
```
```python
# Synchronized-gate script when you need it outside Burp — all threads release together
import threading, requests
gate = threading.Event()
def hit():
    gate.wait()
    requests.post('https://<in-scope>/api/redeem',
                  json={'code':'<marker-coupon>'}, headers={'Authorization':'Bearer '+T})
ts=[threading.Thread(target=hit,daemon=True) for _ in range(10)]
[t.start() for t in ts]; gate.set(); [t.join() for t in ts]
```
Point automation only at an allowlisted host, keep the burst small, and target a marker resource.

## Multi- vs single-endpoint races

- **Multi-endpoint:** a chain like `/product` → `/cart` → `/cart/checkout` where the last step must run before an earlier state propagates. Build the group in Repeater in sequence, then send the final step's tabs in parallel.
- **Single-endpoint:** email-change confirmation — set attacker vs victim address in parallel requests so both confirmation links resolve to one mailbox (account-takeover primitive). Prove with two **test** accounts you own, not a real user.

## Nuances that decide exploitability

- **Session locks.** PHP-style `session_start()` serializes same-session requests. If the app allows multiple sessions, mint several session IDs and give each concurrent request its own — the server treats them as distinct and the lock is bypassed.
- **DB isolation.** `READ COMMITTED` (the common default) leaves a window between a `SELECT balance` and the `UPDATE`; `SERIALIZABLE`, `SELECT ... FOR UPDATE`, atomic `UPDATE ... WHERE`, or an idempotency key close it. Whether a window is real is an isolation/locking question — note in the finding what let it through.
- **Rate-limit buckets.** Counters keyed per `(user, ip)` rather than per user, or a mirror endpoint (`/api/v2/login` unthrottled while `/api/v1/login` is), let a burst slip a shared limit. Probe presence — do not brute at volume the ROE forbids.
- **GraphQL batching.** A single POST body with N identical mutations can duplicate a state change and sidestep per-request controls — one request, N effects; test it before a wire-level burst.

## Confirming without harm

Send the small burst against the marker, then read state back: the single-use coupon shows N redemptions, the marker balance went negative, N seats were granted from one invite. That response *is* the proof — stop there, reverse the side effect, and log the reversal. Do not amplify (30 parallel redeems of a real card to "show scale"); state the scaling factor in the write-up instead. If the impactful version of the race is irreversible or moves real money, it is gated — prove the primitive on the reversible marker flow and route the rest to the anchor.

## Remediation (for the finding)

1. **Fix** — make the operation atomic: a single conditional write (`UPDATE ... SET used=true WHERE used=false`, `INSERT ... ON CONFLICT`, DynamoDB conditional expression) or a row lock (`SELECT ... FOR UPDATE`) so the check and the act are one indivisible step; a unique DB constraint on the "once" attribute.
2. **Defense in depth** — `Idempotency-Key` on one-shot endpoints with short-TTL storage, `SERIALIZABLE`/`REPEATABLE READ` on the critical transaction, a distributed lock (Redlock / PostgreSQL advisory lock) for cross-service resources, and per-user (not per-`(user,ip)`) rate buckets.
3. **Detection** — duplicate-call metrics within one trace span (OpenTelemetry), and a SIEM rule on the symptom: N near-simultaneous state-changing requests for one resource, or a side effect counted more than its allowed maximum.

Write it up in the `appsec-reporting` finding format, CWE-362 / A04:2021 Insecure Design, with the concurrent request group and the before/after state delta as the reproduction.
