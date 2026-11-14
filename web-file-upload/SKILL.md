---
name: web-file-upload
description: "File-upload testing for a pentest-team engagement — extension/content-type/magic-byte bypass, double-extension and trailing-char tricks, polyglots and metadata injection, filename injection (path traversal / command / SQL), archive Zip-Slip and symlink abuse, post-upload processing chains (ImageTragick/ExifTool/Ghostscript), SVG XSS/XXE/SSRF, and webshell RCE only where it is in scope and cleared. Load it when the appsec-triage file-upload sweep turns up a file-upload lead on a claimed web/API target."
---

# File Upload — under the engagement protocol

Deep methodology for the file-upload class. You reach here from the `appsec-triage` file-upload sweep with a lead on a surface you already own on the board.

## Under the engagement protocol

- **Claimed and in-scope only.** Every upload request runs against a target you own on the board and that is on the `ROE.md` allowlist — nothing else.
- **Prove with a marker, not a shell.** Confirm the bypass with a benign proof: a file that lands where it shouldn't, an SVG that pops a marker `alert`, an EXIF payload that echoes a unique token. Never leave a live webshell on a client host to "demonstrate" — a stored primitive you can re-run is the proof, and you clean up after.
- **Read before write; RCE and outward-facing are gated.** A working webshell, a reverse shell, and anything that mutates the host are destructive/outward-facing — mark the surface blocked and route through the lead to the anchor for the human's explicit go before firing them. SSRF/XXE/OOB callbacks go to a **benign in-scope listener only**, never a live external pull and never real cloud metadata credentials.
- **Do no harm — no DoS.** Skip pixel-flood, zip-bomb, and large-filename tests to "confirm" a limit; note the missing control and move on. Rate-limit uploads and coordinate load on shared targets — a WAF/AV ban blocks the whole team.
- **Log and file** per PROTOCOL §Evidence and §Findings — findings in the `appsec-reporting` format, with a reproduction another operator could re-run.

## Quick workflow

1. Enumerate every upload surface (avatars, docs, media, bulk import, CMS plugin/theme/media, backup-restore, upload-from-URL) — **and every distinct validation *backend* behind them.** UI locations are not code paths: the same app often runs image-library validation (GD/ImageMagick — rejects SVG/HTML/polyglots/null bytes) on one field and extension-allowlist-only or MIME-only validation on another. Test each backend as a separate surface. A clean result against an image-library-validated path says nothing about an extension-only path — the exact seam behind Drupal Image field (GD) vs File field (extension-only, CVE-2019-6341 stored XSS). Do not declare upload defended until every backend is enumerated and tested.
2. Baseline an allowed file; capture the request in the proxy so you can mutate it precisely.
3. Probe validation layers in order: client-side → extension → Content-Type → magic byte → content parsing.
4. Prove reachability (where the file lands, whether it renders/executes) with a marker — stop before a live shell unless RCE is cleared.
5. File the finding with a clean, benign reproduction and remediation.

## Detection and bypass

### Client-side first
Client checks are advisory. Disable JS or intercept and swap the file/filename post-validation in the proxy; the server-side behavior is the real test.

### Extension bypass
```
# alternates that still execute
shell.phtml  shell.php5  shell.phar  shell.pht  shell.inc     # PHP
shell.asp shell.aspx shell.ashx shell.asa shell.cer           # ASP/IIS
shell.jsp shell.jspx shell.jsw                                # Java
# double extension (parser vs webserver disagreement)
shell.php.jpg   shell.jpg.php
# trailing / delimiter tricks
shell.php.        shell.php%20   shell.php%00.jpg   shell.php::$DATA
shell.php%0d%0a.jpg   shell.php.....
# case
shell.PhP  shell.pHp5  shell.PhAr
# config-file routes (Apache override / IIS)
.htaccess   web.config
```

### Content-Type spoof
Send the payload with an allowed MIME (`Content-Type: image/jpeg` on a PHP body); also try removing the header, or sending it twice with one allowed value.

### Magic-byte forge
Prefix the payload with an allowed type's signature so content sniffing passes.
```
GIF89a;
<?php echo 'MARKER-7f3a'; ?>
```

### Polyglots and metadata
A file valid in two formats slips a content check. Inject into image metadata rather than appending raw code — parsers preserve it:
```bash
exiftool -Comment='<?php echo "MARKER-7f3a"; ?>' marker.jpg
mv marker.jpg marker.php.jpg
```

### Filename injection
The filename is often used unsafely downstream. Probe with **benign markers**, never destructive commands:
```
../../uploads/marker.php                 # path traversal → land outside intended dir
a$(sleep 5)z.png    a`sleep 5`z.png      # command injection (time-marker, not rm/curl)
' OR SLEEP(5)-- -.png                     # SQLi in the filename sink
"<svg onload=alert('MARKER')>.jpg"        # filename-reflected XSS
```
An OOB via filename (`filename=http://<in-scope-listener>/hit`) must target the benign in-scope listener only.

### Archive abuse (Zip-Slip / symlink)
```bash
# path traversal on extraction — land a marker, not a live payload
mkdir -p x/../../marker && echo MARKER > "x/../../marker/proof.txt"
zip --symlinks slip.zip x/../../marker/proof.txt
# symlink read of a single non-sensitive file to prove the primitive
ln -s /etc/hostname link.txt && zip --symlinks link.zip link.txt
```
LFI-via-zip reachability: `?page=zip://uploads/archive.zip%23marker.php` — demonstrate inclusion of your marker, not `/etc/passwd`.

### SVG / XML uploads (XSS / XXE / SSRF)
```xml
<!-- stored XSS: benign marker -->
<svg xmlns="http://www.w3.org/2000/svg" onload="alert('MARKER-7f3a')"/>
<!-- XXE / SSRF: point at the in-scope listener, never real metadata creds -->
<!DOCTYPE svg [ <!ENTITY x SYSTEM "http://<in-scope>/oob-marker"> ]>
<svg xmlns="http://www.w3.org/2000/svg"><text>&x;</text></svg>
```
`.xlsx`/`.docx`/`.pdf`/`.pptx` are zip+XML — the same XXE/SSRF applies via their inner XML. Route any callback to the in-scope listener.

### Post-upload processing chains
If the server thumbnails, OCRs, converts, or AV-scans the file, the processor is the target: ImageMagick (ImageTragick `.mvg`/`.svg`, CVE-2016-3714), ExifTool (CVE-2021-22204), Ghostscript EPS-in-JPG (CVE-2024-29510), libheif/libavif, ffmpeg on video. Confirm the processor and version, then prove reachability with a benign marker payload — a converter RCE is an RCE and is gated to the anchor.

### Race conditions
Some apps write to a temp path, validate, then delete. Note the window and the temp path; **do not** flood the endpoint to win the race on a shared/production target — that is a load/DoS event. Report the TOCTOU window as reachable if you can show the file was momentarily served.

## Automation (throttled, in-scope)

```bash
# extension/content-type sweep from a captured, in-scope request
fuxploider -u https://<in-scope>/upload --not-regex "fail"
# ffuf the filename/extension field, low rate
ffuf -w exts.txt -X POST -u https://<in-scope>/upload -d @body -H "..." -rate 10
```
Keep the rate low, point automation only at allowlisted hosts, and stop at first confirmed bypass — the marker makes the point.

## WAF bypass (when a control sits in front)

Try key mangling (`file===x.php`), URL/double-URL encoding of the extension, `%09`/`%20`/`%00` separators, ADS (`::$DATA`), and metadata-carried payloads. Record that a WAF/AV was present and what bypassed it — the client's control efficacy is itself reportable.

## Remediation (for the finding)

1. **Fix** — validate by content inspection and magic bytes, not extension or Content-Type; allowlist both permitted MIME **and** extension; re-encode/convert images and documents (CDR) on a trusted pipeline; assign server-generated random filenames; store outside the web root and serve from a separate no-execute domain.
2. **Defense in depth** — restrictive, non-executable permissions on the upload dir; strip metadata; sandbox converters (seccomp/bubblewrap) and keep them patched with an SBOM; `X-Content-Type-Options: nosniff` and `Content-Disposition: attachment`; for object storage use short-TTL single-use presigned PUTs, `PutObject`-only IAM, key validation rejecting `../`, and quarantine-then-publish with Object Lock.
3. **Detection** — a SIEM rule on uploaded-then-executed content, on filenames with traversal/script markers, or on converter processes spawning shells.

Write it up in the `appsec-reporting` finding format, CWE-434 / A04:2021 Insecure Design, with the marker-based reproduction.
