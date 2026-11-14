# Verification Recipes

Every control test below has a negative case that must fail before the finding is
real. Run the negative case. Skipping it is how false positives get reported.

## Rate limiting on an auth endpoint

Symptom: several failed logins all return the same 401 with no visible throttling.

Do NOT report "missing rate limit" on 3-5 attempts. Burst 25+ and read the headers:

```
for i in $(seq 1 25); do
  curl -s -o /dev/null -w '%{http_code} ' -X POST "$B/api/login" \
    -H 'Content-Type: application/json' \
    -d '{"username":"burst-'$i'@example.com","password":"x"}'
done
```

Interpretation:
- Steady `401` for all 25 with no `429` and no rate-limit headers -> finding.
- `429` appearing mid-burst -> rate limiting EXISTS. Stop; not a finding.
- `x-rate-limit-remaining` present -> the limiter is instrumented. Not a finding.

Also check whether the web login and the mobile/legacy API login differ: a SPA login
behind reCAPTCHA does not imply the older `/api/login` is unprotected, and vice versa.
Test both before concluding.

## OTP / email cooldown enforcement

Symptom: an OTP request returns a cooldown field such as `time_to_next_challenge`
or `resend_available_in`, presented to the user as a wait timer.

A returned cooldown value is a **client-side hint, not a server-side control**. The
only test that matters is whether the server rejects an immediate second request:

```
for i in 1 2 3 4 5; do
  curl -s -w '|%{http_code}\n' "$B/api/oauth2/passwordless/login/start?store_id=$S" \
    -X POST -H 'Content-Type: application/x-www-form-urlencoded' \
    --data-urlencode "identity_type=email" \
    --data-urlencode "identity_value=<address-you-control>" \
    --data-urlencode "client_id=web-standard" \
    --data-urlencode "tenant=$T" \
    --data-urlencode "channel_identity_type=email"
done
```

Interpretation:
- Every request returns 200 with a **new** `challenge_id` -> cooldown is NOT enforced.
  Finding: OTP flood / email bombing, plus invalidation of any previously issued code.
- A later request returns 429, or the same `challenge_id` is reused -> enforced.
  Not a finding.
- A decreasing `time_to_next_challenge` (60 -> 30 -> 30) alongside 200s is the
  tell-tale of an unenforced hint — the server is counting but not blocking.

Use ONLY an address you control. Sending OTP mail to a third party during testing is
out of bounds for every program.

Check the sibling flows too — `register/start` and `reset-password/start` share the
same challenge machinery, and a bypass on one is usually a bypass on all three.
Report them as one finding with the platform-wide host list, not three reports.

## OTP verification brute force

Symptom: the verify endpoint accepts repeated wrong codes.

Before calling this a finding, confirm the challenge is still live — an expired or
superseded `challenge_id` returns `user_unauthorized` on every attempt, which looks
identical to "no attempt counter" but proves nothing. Mint a fresh challenge, then
burst wrong codes against it and read the status codes:

- Identical `401`/`400` for 25+ attempts with no lockout and no `429` -> candidate.
- A distinct `too_many_attempts` / lockout status, or the challenge being invalidated
  after N tries -> the counter exists. Not a finding.

Note that a short numeric OTP with no attempt cap is the real severity driver; state
the code length and the absence of a cap explicitly in the report.

## Missing rate limit where brute force is banned by the rules

Symptom: a verification endpoint accepts repeated wrong codes with no throttle, but the
program forbids automated scanners and high-volume traffic — so the 25-attempt burst
above would itself violate the rules.

Run a **minimal** probe instead: 3 attempts at ~1.5s spacing with a wrong code, and read
the full response headers:

- All 3 return the same status/body, and there is **no** `X-RateLimit-*`,
  `Retry-After`, or lockout field -> the control is absent. Reportable as a design flaw.
- Any `429`, `Retry-After`, or a distinct `too_many_attempts` body -> the counter
  exists. Not a finding.

Then recover the **code entropy** without touching the server: the challenge UI's own
HTML states the format. The response body of the preceding step usually contains the
input element, e.g. `placeholder="Code : 12345678..."` -> 8 numeric digits -> 10^8
keyspace. Read the length from the placeholder or `maxlength`, never by guessing.

Report the finding as: keyspace (from the placeholder) + absence of counter/lockout/
throttle header + the impact of one successful guess + an explicit statement that the
brute force was not executed because the program's rules forbid the traffic. That is a
complete report; the missing control is the evidence.

Before writing it up, check the program's `non_qualifying_vulnerability` list — some
programs exclude "missing rate limiting" outright, in which case the finding is dead on
arrival no matter how well it is proven.

## Content-type confusion is not an auth bypass

Symptom: an endpoint that returns 401 with a well-formed JSON body returns 500 (or anything
other than 401) once you change `Content-Type` — suggesting the auth filter was skipped.

A 500 on a **malformed** body is a parsing failure that happens before the auth filter,
not a bypass. Re-run the probe with a *well-formed* request of that content type:

```
# malformed — header claims multipart but there is no boundary
curl -s -o /dev/null -w '%{http_code}' -X POST "$B/v1/x" -H 'Content-Type: multipart/form-data' -d '{}'   # 500

# well-formed multipart
curl -s -o /dev/null -w '%{http_code}' -X POST "$B/v1/x" -F 'field=value'                              # 401
```

Only a well-formed request that reaches the handler without a session is a finding. Sweep
the other content types too (`application/x-www-form-urlencoded`, `text/plain`,
`multipart/form-data`): a 415 from all of them means the framework's converter rejects
them before any filter runs, which is the safe case.

## Data-existence oracle on a search endpoint

Symptom: a lookup endpoint returns per-category counts (`{"total":0,"email":0,
"mobile":0,"idrgpd":0}`) for an identifier you supply.

Test with a syntactically valid but certainly nonexistent identifier (a random local
part on a real domain, or a random 8-24 char reference). If the counts are all zero for
the fake and non-zero for a real one, the endpoint is an existence oracle — it discloses
whether a given email/phone/reference is registered.

Two caveats before reporting:
- Many programs list user enumeration in `non_qualifying_vulnerability`. Check first.
- A zero result must be *structurally* different from a non-zero one (counts, or a
  distinct "no result" message). If the only difference is wording, it is weak — say so.

The severity comes from what the oracle gates. An oracle in front of a
`send_code` -> `validate_code` -> `view` chain is a precursor to account takeover of the
data-subject portal, not a standalone info leak; report the chain, with the oracle as
step one.

## Search / query injection

Symptom: a search endpoint accepts `field:*` syntax and returns a large result count.

This is usually full-text search, not field-specific injection. Verify with two probes:

1. **Nonexistent field:** `nonexistentfield12345:*` -> must return 0. If it returns 0
   while `email:*` returns hundreds, the engine is doing full-text matching on the
   literal term, not resolving a field name.
2. **Term actually present:** fetch the top hits and confirm the term appears in the
   returned title/description. If every hit contains the word, it is full-text.

Only report injection when a nonexistent field errors differently from a real one, or
when field values that are never rendered (internal ids, cost, margin) leak into the
response. Also try field-selection params (`fl`, `fields`, `include`, `projection`) —
if the response field set is unchanged for all of them, output is whitelisted and
there is no disclosure.

## User enumeration

Symptom: the error message differs between a known and unknown account.

Send the same request with (a) a syntactically valid but nonexistent identity and
(b) an empty/malformed identity. If both return the identical status and body, there
is no enumeration. A distinct "invalid email format" message for malformed input is
input validation, not enumeration.

Consistent response *timing* across known/unknown accounts is weak evidence at best;
do not report timing alone.

### Domain-based SSO routing is not enumeration
Symptom: every address on the company's own domain returns an SSO redirect
(`SsoRedirectionRequired`, an `e:14`-style code, or a `saml/login?email=...` URL) while
off-domain addresses get a captcha or a generic error. That looks like a clean existence
oracle and is not one.

Run the negative case first: send a random, certainly-nonexistent address **on the same
domain** (`zzq-nonexistent-9999@example.com`). If it also returns the SSO redirect, the
gateway forwards the whole domain to the IdP without checking account existence, and the
behaviour is by design. Only report when a nonexistent address on the SSO domain behaves
differently from a real one.

Related: a captcha demanded *before* the credential verdict (a response carrying a
captcha flag and a `CaptchaError`, with no statement about the password) means the
endpoint cannot serve as an oracle at all — the credential check never ran. Record it as
protected and move on.

## Open redirect on OAuth redirect_uri

Request the authorization endpoint with a valid `client_id` and an off-host
`redirect_uri`. A 400 with a validation error means the allowlist is enforced. Only
report when the redirect actually lands on the attacker host, or when a path-confusion
variant (`/callback@evil.com`, `//evil.com`) survives.

## CORS reflection

Symptom: `Access-Control-Allow-Origin` echoes the `Origin` you sent, alongside
`Access-Control-Allow-Credentials: true`.

Send four probes and compare:

| Origin sent | Secure behaviour |
|---|---|
| `https://evil-attacker.com` | no `ACAO` header at all |
| `null` | no `ACAO` header |
| `http://evil-attacker.com` (plain HTTP) | no `ACAO` header |
| `https://evil.<target-domain>.attacker.com` | no `ACAO` header |

A finding requires reflection in **all four**. Reflection of only some variants means
a partial allowlist — state precisely which variants survive.

The impact test is what makes it reportable: repeat the probe against an endpoint that
returns **401 without a session**. If that 401 still carries the reflected `ACAO` plus
`Allow-Credentials: true`, the misconfiguration sits on the authenticated surface and
any logged-in victim's data is reachable cross-origin. If only unauthenticated
endpoints reflect, the finding is informational.

Finally confirm the app actually sends cookies cross-origin to that host: the web
client must be a first-party page on a sibling domain (app on `foo.example.com`, API
on `router-foo.example.com`) so the session cookie for `.example.com` is attached.
Without that, `Allow-Credentials` cannot be exploited and the report will be closed.

### Wildcard is not reflection
An API that returns `Access-Control-Allow-Origin: *` on every request — including when
you send an `Origin` — is **not** misconfigured. The wildcard means "any origin may
read this", which is only exploitable with `Allow-Credentials: true`, and browsers
reject that combination outright. Run the reflection probes above; if the header stays
`*` and no credentials header appears, record the endpoint as safe and spend the budget
elsewhere. This is the single most common false positive on JSON APIs.

### Preflight is free reconnaissance
Before concluding, send an `OPTIONS` with `Access-Control-Request-Method` and
`Access-Control-Request-Headers`. The response's `Allow-Headers` lists every header the
gateway accepts — including undocumented auth headers (`X-Token`, `X-Signature`,
`X-Agent-Token`, `X-User-Id`) — and `Allow-Methods` states the method surface. One
request, no auth, full map of the API's control vocabulary.

## Auditing in-scope source code locally

When a program puts its repository in scope (open-source projects almost always do),
audit the clone instead of the live instance. It is faster, it cannot trip a rate limit,
and it covers plugins you would never think to probe.

1. Clone shallow into the recon tree: `git clone --depth 1 -b <branch> <url> recon/<app>`.
   Check the branch list first — a beta branch (`6.x-dev`) may carry the new, less-audited
   code that production actually runs. Fingerprint the live version from the app itself
   (`API.getMatomoVersion`, `/assets/release.json`) and match the branch to it.
2. Grep for the vulnerability class across **all** plugins, not core:
   `grep -rn '<pattern>' plugins/ --include=*.php | grep -v tests`
3. For access-control gaps, invert the search — find the files that have methods but no
   guard:
   ```
   for f in $(find plugins -name 'API.php' -not -path '*/tests/*'); do
     N=$(grep -c 'public function' "$f"); C=$(grep -cE 'checkUserHas|checkUserIsNotAnonymous' "$f")
     [ "$N" -gt 0 ] && [ "$C" -eq 0 ] && echo "$f ($N methods, 0 checks)"
   done
   ```
   Repeat for `Controller.php`. Most hits are example plugins or are guarded by a parent
   class — read each candidate before calling it a finding.
4. For SSRF, find every outbound HTTP call and check whether it passes the framework's
   own egress guard. The valuable finding is not "no SSRF protection exists" but
   "the framework ships a correct egress validator (`validateEgressIp`, an
   `EgressHostValidator` blocking CGNAT/TEST-NET/link-local/IPv6-transition ranges and
   pinning the resolved IP) and this plugin does not call it". A missed integration is a
   stronger report than a missing feature, and the guard's own source is your proof.
5. Confirm the vulnerable code path is reachable: trace who calls the sink and what
   access check guards that caller. A superuser-only SSRF is still reportable but must
   be labelled with its privilege requirement.
6. Check whether the response body is reflected back. An outbound request whose error
   body is truncated into the exception message returned to the caller is **not blind**
   and materially raises severity — internal banners, error pages and cloud-metadata
   content come back to the attacker.

## Exposed spec / admin surface

A 200 on `/swagger`, `/admin`, or a login page is reconnaissance, not a vulnerability.
It becomes reportable only when it exposes data or functionality without auth. Confirm
by requesting an actual data endpoint, not the UI shell.

### Cloud storage buckets
When a config file names a bucket (`AWS_URL`, `assetsUrl`, a CDN host ending in
`oss-<region>.aliyuncs.com`, `s3.<region>.amazonaws.com`, `blob.core.windows.net`),
probe the bucket root for anonymous listing:

```
curl -s https://<bucket>.<endpoint>/ | head -c 300
```

An XML `AccessDenied` / `AllAccessDisabled` body means listing is correctly denied —
record it and move on. A `ListBucketResult` with `<Contents>` entries is a finding:
enumerate the keys and confirm they contain non-public objects.

## Building an in-scope C/C++ repository without its build system

Code-review engagements name a repository as the target, and the build system is often
unavailable on this box (`cmake` missing, generated headers absent). Build it by hand —
the PoC has to call the real verify function, not a reimplementation of it.

1. **Generate the missing export header yourself.** CMake's
   `generate_export_header(<name>)` produces `<name>_export.h`; it is not in the repo.
   Write it into a private include dir and add that dir to `-I`:
   ```c
   #ifndef COSIGNER_EXPORT_H
   #define COSIGNER_EXPORT_H
   #define COSIGNER_EXPORT
   #define COSIGNER_NO_EXPORT
   #endif
   ```
2. **Compile each translation unit to its own object, then link the minimal set.**
   `gcc -c -O1 -w -I<repo>/include -I<repo>/src/common -I<private>/include <file>.c -o <file>.o`
   Link with **`g++`**, not `gcc` — C++ objects pull in `__cxa_throw` and `operator new`
   and a `gcc` link fails on them.
3. **Drop the units that cannot link, and confirm against the project's own build file
   before assuming they are needed.** Two recurring cases: a vendored crypto file that
   re-defines symbols already exported by the algebra wrapper (duplicate `ED25519_sign` /
   `X25519` at link time), and a hash file whose symbols (`SHA3_absorb`, `SHA3_squeeze`)
   live in an ed25519-only unit you excluded. Grep the repo's `CMakeLists.txt` for the
   filename — if the project does not list it, it is not part of the library and excluding
   it is correct, not a workaround.
4. **Declare internal (non-static) C functions at file scope inside `extern "C" { }`.**
   `extern "C"` inside a function body is a syntax error, and without it the C++ compiler
   mangles the name and the link fails with an undefined reference to a signature you can
   read directly in the source.
5. **Opaque structs: use the public accessors, never `->field`.** A forward-declared
   `typedef struct foo foo_t` hides its members. Serialize/deserialize round-trips and
   sized getters (`*_public_size`, `*_public_serialize`, `*_public_key_n`) recover the
   values you need; read the serializer to learn the byte layout before parsing it.
6. **Derive serialized field offsets from the project's own size function**, and
   cross-check every field width against the `#define` constants it uses. A wrong constant
   produces a well-formed but misaligned blob that fails verification for a reason
   unrelated to the bug you are testing.

## Auditing a cryptographic protocol library

1. **Read the security-model document first** (rule 22). Note the honest-party guarantees
   it enumerates and the attacker model — a finding is only meaningful if it breaks one of
   those guarantees for an honest participant.
2. **Map the verifier's equations and ask what each one actually pins.** For a
   Sigma-protocol-style proof, list every check, the group each operates in, and which
   prover-supplied value it constrains. The soundness gap is usually a value that appears
   in one equation but is unconstrained — or only size-constrained — in another.
3. **Check the range bound against the honest prover's own bound.** A proof that certifies
   "plaintext in range" via a single size check on a combined value is only as tight as
   that check. Compute the maximum the honest prover can produce and the maximum a
   malicious one can, using the same challenge size; if the malicious maximum is a whole
   scalar-width larger, the certified range is too wide and out-of-range values verify.
4. **Grep the test suite for the property you claim is broken.** If no test exercises it,
   that absence is itself part of the report — it explains why the bug survived and hands
   the maintainer the regression test to add.
5. **Run the control experiment** (rule 21) before writing the root cause. Build the
   exploit twice: once through the suspect condition and once without it. Only the
   condition the control implicates belongs in the root-cause section.
6. **Look for validation helpers the project ships but does not call.** A library that
   exposes a `validate_*` function and calls it at some call sites but not others has an
   inconsistency you can point at precisely — quote the comment that states the
   requirement and list the call sites that honour it beside the ones that do not.
