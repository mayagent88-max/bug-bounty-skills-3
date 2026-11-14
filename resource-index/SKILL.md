---
name: resource-index
description: Curated index of external hacking resources — meta-lists, frameworks, wordlists, payload banks, recon/OSINT, network, exploitation, and CTF tooling. Load when the user asks "what's the tool for X", "where do I find payloads for Y", "is there a wordlist for Z", or when planning which external resource to pull for a task. Always reach for this before suggesting a generic Google search.
---

# External Resource Index

This is a pointer library, not a fetcher. When a task needs a payload, wordlist, tool, or knowledge base, find the right entry here first, then use `WebFetch`, `git clone`, or direct install.

## How to use
1. Identify the task category (meta, framework, web, recon, network, exploit, CTF).
2. Pick the resource whose description matches.
3. For **knowledge bases** (hacktricks, PayloadsAllTheThings, GTFOBins): `WebFetch` the specific page you need — don't clone the whole repo.
4. For **tools** (nuclei, ffuf, sqlmap, etc.): check if already installed (`which`); if not, note the install path but don't install without asking.
5. For **wordlists** (SecLists): `git clone` once to `~/tools/SecLists` and reference by path.
6. For **payloads at hunt time**: grep a cached clone or `WebFetch` the specific file — e.g. `PayloadsAllTheThings/XSS Injection/README.md`.

---

## Meta-lists & Learning

| Resource | URL | Use when |
|---|---|---|
| **Awesome-Hacking** | https://github.com/Hack-with-Github/Awesome-Hacking | You need to discover *more* curated lists for a niche — treat as index of indices |
| **HackTricks** | https://github.com/carlospolop/hacktricks / https://book.hacktricks.wiki | Web / cloud / AD / privesc technique lookup; most complete free pentesting book |
| **SecLists** | https://github.com/danielmiessler/SecLists | Any wordlist need: passwords, usernames, fuzzing strings, subdomain lists, payloads, API patterns |
| **CyberChef** | https://github.com/gchq/CyberChef / https://gchq.github.io/CyberChef/ | Encoding/decoding, quick crypto, data analysis — GCHQ's browser-based Swiss Army knife |

## Frameworks & C2

| Resource | URL | Use when |
|---|---|---|
| **Metasploit** | https://github.com/rapid7/metasploit-framework | Exploit delivery, payload generation, post-ex modules; industry standard |
| **Sliver** | https://github.com/BishopFox/sliver | Modern red-team C2 (Go); use when Cobalt Strike-equivalent is needed with open source |
| **Sn1per** | https://github.com/1N3/Sn1per | Attack-surface management + automated pentest workflow |

## Web & App Testing

| Resource | URL | Use when |
|---|---|---|
| **PayloadsAllTheThings** | https://github.com/swisskyrepo/PayloadsAllTheThings | First stop for XSS / SQLi / SSRF / XXE / SSTI / LFI / command injection payloads and bypasses |
| **nuclei** | https://github.com/projectdiscovery/nuclei | Template-based vuln scanner — fast, low FP |
| **nuclei-templates** | https://github.com/projectdiscovery/nuclei-templates | Community template library; pin version for stable runs |
| **sqlmap** | https://github.com/sqlmapproject/sqlmap | After manual SQLi confirmation, for dump/exfil automation |
| **ffuf** | https://github.com/ffuf/ffuf | Fast fuzzing — dirs, vhosts, parameters, headers |
| **dirsearch** | https://github.com/maurosoria/dirsearch | Web path/directory brute — `ffuf` alternative with good defaults |
| **gobuster** | https://github.com/OJ/gobuster | Directory, DNS, and vhost busting (Go, fast) |

## Recon & OSINT

| Resource | URL | Use when |
|---|---|---|
| **SpiderFoot** | https://github.com/smicallef/spiderfoot | Large-scale automated OSINT across 200+ sources |
| **theHarvester** | https://github.com/laramies/theHarvester | Email, subdomain, and IP discovery from OSINT |
| **Sherlock** | https://github.com/sherlock-project/sherlock | Username enumeration across 400+ social platforms |
| **subfinder** | https://github.com/projectdiscovery/subfinder | Passive subdomain enum (primary recon tool) |

## Network

| Resource | URL | Use when |
|---|---|---|
| **RustScan** | https://github.com/RustScan/RustScan | Ultra-fast port discovery; pipes to Nmap for service detection |
| **bettercap** | https://github.com/bettercap/bettercap | MITM, WiFi, BLE, LAN recon |
| **impacket** | https://github.com/fortra/impacket | Windows/AD protocol attacks — SMB, Kerberos, MSRPC, etc. |

## Exploitation & Post-Exploitation

| Resource | URL | Use when |
|---|---|---|
| **PEASS-ng** | https://github.com/carlospolop/PEASS-ng | LinPEAS/WinPEAS after initial foothold for privesc enum |
| **GTFOBins** | https://gtfobins.github.io | Unix binary abuse (SUID, sudo, file read) — one-stop lookup |
| **CrackMapExec** | https://github.com/byt3bl33d3r/CrackMapExec | AD pentest Swiss Army (note: now maintained as `nxc`/NetExec) |

## CTF

| Resource | URL | Use when |
|---|---|---|
| **awesome-ctf** | https://github.com/apsdehal/awesome-ctf | Discover CTF tools by category |
| **ctf-katana** | https://github.com/JohnHammond/ctf-katana | Quick-reference commands for stego/forensics/crypto/web |

## Claude-native bug-bounty stacks

| Resource | URL | Use when |
|---|---|---|
| **claude-bug-bounty** | https://github.com/shuvonsec/claude-bug-bounty | **Already installed** — see `~/bounty/claude-bug-bounty/`; skills + commands + Python tools + wordlists |
| **hexstrike-ai** | https://github.com/0x4m4/hexstrike-ai | MCP server giving AI agents access to 150+ security tools; add as MCP server for autonomous tool orchestration |

---

## Commands for common fetches

```bash
# One-time SecLists clone (large — ~800MB)
git clone --depth 1 https://github.com/danielmiessler/SecLists.git ~/tools/SecLists

# One-time PayloadsAllTheThings clone
git clone --depth 1 https://github.com/swisskyrepo/PayloadsAllTheThings.git ~/tools/PayloadsAllTheThings

# Grep a payload type from a local PATT clone
rg -l "XSS" ~/tools/PayloadsAllTheThings/XSS\ Injection/

# Fetch a single HackTricks page without cloning
WebFetch https://book.hacktricks.wiki/en/pentesting-web/sql-injection/index.html "summarize detection techniques and bypass patterns"

# GTFOBins lookup for a specific binary
WebFetch https://gtfobins.github.io/gtfobins/vim/ "list all abuse methods for vim"
```

## Grep patterns for "what tool do I need?"
- "payload for X" → **PayloadsAllTheThings**
- "wordlist for X" → **SecLists**
- "how does X work" / "technique for X" → **HackTricks**
- "privesc on this box" → **PEASS-ng** + **GTFOBins**
- "decode this / analyze this" → **CyberChef**
- "AD attack" → **impacket** + **CrackMapExec** + HackTricks AD section
- "scan 150+ tools autonomously" → **hexstrike-ai** MCP
