# Bug Bounty Skills — Part 3 of 3

> **887 agent skills** for security research, bug bounty hunting, penetration testing and smart-contract auditing — ready to use with Claude Code, Codex, Cue and other AI coding agents. Part 3 of the full collection, alphabetically `oracle-safety` → `zkvm-security`.

![Skills](https://img.shields.io/badge/skills-887-blue)
![Cue compatible](https://img.shields.io/badge/Cue-compatible-brightgreen)
![YAML validated](https://img.shields.io/badge/YAML-validated-brightgreen)

## What is this?

A curated collection of agent skills (each a `SKILL.md` with supporting files) covering web security, API testing, smart-contract auditing, OSINT, cloud security, exploit development, fuzzing, reverse engineering and more. Each skill is a focused, reusable playbook: when to use it, how to run it, and what good output looks like.

## Layout

GitHub's web file list truncates directories at 1,000 entries, so the full collection (2,550 skills) is split into three browsable parts:

| Part | Skills | Range |
| --- | --- | --- |
| [bug-bounty-skills-1](https://github.com/mayagent88-max/bug-bounty-skills-1) | 830 | `0xsimao-ai` → `detecting-modbus-command-injection-attacks` |
| [bug-bounty-skills-2](https://github.com/mayagent88-max/bug-bounty-skills-2) | 833 | `detecting-modbus-protocol-anomalies` → `oracle-redundancy` |
| [bug-bounty-skills-3](https://github.com/mayagent88-max/bug-bounty-skills-3) (this repo) | 887 | `oracle-safety` → `zkvm-security` |

This repo is part 3 (830 folders, 887 `SKILL.md` files including nested skills). To find a skill, use GitHub search inside this repo (press `t` for the file finder) or clone it — a clone always contains everything; the 1,000-entry limit affects only the web listing.

## Install a skill

### Claude Code / Codex

Copy the skill folder into your skills directory, e.g. `~/.claude/skills/<skill-name>/`, then restart the agent.

### Cue (Android)

Cue imports one skill at a time: **Add Skills** → upload a zip containing a single skill folder (`SKILL.md` at the folder root). Multi-skill zips are not supported — only the first skill is imported.

### From source

```bash
git clone https://github.com/mayagent88-max/bug-bounty-skills-3.git
cp -r bug-bounty-skills-3/<skill-name> ~/.claude/skills/
```

## Quality

- Every `SKILL.md` carries valid YAML front matter with a `name` field (validated 17 November 2026; 175 files repaired across the collection).
- Skills are collected from public sources; each skill's original license and attribution apply where stated.
- Review a skill before running it. These are offensive-security playbooks — use them only on systems you own or are authorized to test.

## Structure

```
bug-bounty-skills-3/
├── oracle-safety/
│   └── SKILL.md
├── ...
└── zkvm-security/
    └── SKILL.md
```

## Disclaimer

For authorized security research and education only. You are responsible for complying with applicable law and with the rules of any bug bounty program you participate in.
