---
name: verify_before_asserting
description: "Verify a specific claim before stating it"
---
# Verify a specific claim before stating it

## Check the official source first

- Open the official project page, official docs, or official channel before you state a channel link, a procedure step, a quiz answer, or a timing.

- Quote the exact wording or link you checked when you report the claim, so the user can follow the same source.

- Say you do not know when the official source does not state the item, and do not fill the gap with a guessed channel, a guessed step, or a guessed timing.

- Ask the user for the official link when you cannot find one, and wait for that link before you state the claim as fact.

## Identify a token by contract not by ticker

- Match the full contract address against the official project docs or the chain explorer before you name a token, its price, or its sale route.

- Reject a similarly named token and a dust transfer to many wallets as proof of a claim, and check the claim transaction and the destination wallet separately.

- Report the amount that actually arrived in the destination wallet, and keep the token identity marked unverified until the contract match is confirmed.

- Check a live quote only after the contract match is confirmed, and name each quote source and its result separately.

## State timing only from a source

- State a wait time, a deadline, or a window only when a named source gives that time.

- Say the timing is unknown when no source gives it, and name the next check you will run instead of inventing a number of days.

- Correct a stated timing at once when a later check contradicts it, and name the source that changed the answer.

## Present unverified items plainly

- Label each unchecked item as unverified in the same message, and keep it separate from items you checked.

- Give the user the concrete next check for each unverified item, such as the official page to open or the contract to compare.

- Do not present a guess as a price, a value in local currency, or a listing venue until the contract and a live quote both support it.

## Available connectors

- Use `muse.connector_search` to find other connectors and `muse.skill_search` to find related skills.

- If nothing here fits, look on the web for a maintained API or MCP server and set it up with [Custom Connectors and MCPs](/opt/muse/skills/custom-connector-setup/SKILL.md), or build a custom connector.

## Websites

- [BscScan](https://bscscan.com/) for checking a BSC contract address, its token name, and its transfers before you name a token.

- [Etherscan](https://etherscan.io/) for checking an Ethereum contract address and its transfers before you name a token.

## Alternatives for better results

- Check a second official source when the first source is a community post, because a community post can repeat an error.

- Keep a claim as pending when the official source is slow to load, and report the pending status instead of answering from memory.
