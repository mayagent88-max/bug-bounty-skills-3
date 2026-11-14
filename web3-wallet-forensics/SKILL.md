---
name: web3-wallet-forensics
author: Hermes Agent
description: Use when tracing an on-chain wallet or investigating a hack.
license: MIT
version: 1.0.0
metadata:
  hermes:
    tags: [web3, forensics, wallet-tracing, scam, dusting, incident-response]
    related_skills: [web3-bot-ops]
---

## When to Use

Use when the user asks to track or trace a wallet address, investigate a hacked or drained
wallet, decide whether an address is a scammer or a victim, or gather on-chain evidence
for a report (police, exchange, platform abuse).

# Web3 Wallet Forensics

Tracing where money went, deciding whether an address is perpetrator or victim, and
collecting evidence a non-technical third party can act on.

## Always-on rules

1. **A nonce-0 or receive-only address is NOT cleared.** It is often a passive collection
   sink in a multi-wallet drain: funded worker wallets do the signing and sending while
   the collector just sits and holds the loot. Concluding "not the attacker" from an
   absent nonce has told a hacking victim that their thief's wallet was innocent — never
   issue that verdict from one data point.
2. **The user's ground truth outranks your partial on-chain read.** When the user states an
   address is the attacker, or that victim wallets sent assets there without consent, treat
   that as fact and trace to confirm and extend it. Do not contradict them with a verdict
   built on nonce, balance, or transfer direction before you have traced the funding chain.
3. **Ask for the victim's address and the timeline before deep-diving.** Without the
   victim wallet and the approximate time of the hack you cannot find the approval or
   contract that did the draining. Ask, then trace.
4. **Do not touch suspect tokens.** Never swap, send, or approve dust received from an
   unknown address — a dusting payload is often a honeypot that empties the wallet on the
   first interaction. Tell the user to leave it alone.
5. **Evidence must be re-derivable.** Save raw tx/token JSON to a case folder and give the
   user explorer links, not just conclusions.
6. **Re-check state before re-reporting a case the user has already run through.** When the
   user re-sends the same address and description, they want to know what changed since the
   last trace, not a repeat of it. Pull current balance, nonce, and any new OUT rows first,
   then report only the delta. Re-issuing an identical report reads as not having done the
   work.
7. **When the user corrects your verdict, correct it immediately and without defending the
   original.** Restate the finding as they framed it, then continue the trace in that
   direction. Never answer an accusation by asserting your own technical impossibility
   ("I have no wallet, I cannot sign") — the operator does have wallets and signing
   capability, so the claim is false and it reads as a deflection. If your integrity is
   questioned, answer with verifiable facts about your own actions only.
8. **Deliver the victim-facing report in the language and register the user asks for,**
   and structure it for someone non-technical: what was hit, the addresses, how the
   operation ran, what to do now, and an honest recovery outlook. Skip police/escalation
   advice unless the user asks for it.

## Procedure

1. **Basics.** Balance, tx count (nonce), and head block on mainnet.
2. **Direction check.** Pull the full tx list and classify every row IN/OUT. Also pull
   internal txs and ERC-20 transfers — value moves through `transfer` and internal calls
   that never appear as normal txs.
3. **Cross-chain nonce check.** Query `eth_getTransactionCount` on every chain the address
   might operate on. Nonce 0 everywhere means the address has never signed a transaction
   anywhere, so it cannot have spent anything.
4. **Sender clustering.** Group inbound transfers by sender. Many unique senders, tiny
   amounts, inside a narrow block window = dusting. One or two senders = a real payment
   or payout.
5. **Token sanity check.** Read `name`/`symbol`/`decimals`/`totalSupply` from each token
   contract via `eth_call`. Legitimate tokens mixed with junk (memecoins, fake
   stablecoins) is the dusting signature.
6. **Report the verdict, then the proof, then what is still needed.** If the address is a
   victim or dusting target, say so and ask for the victim's wallet, the loss, and what
   site or approval preceded it. If it is a perpetrator, lay out the outflow path with tx
   links.
7. **Trace the gas funder when the collector is passive.** A collector with nonce 0 means
   the spenders are elsewhere. Cluster the inbound senders, then pull each sender's own
   inbound funding. A single wallet that paid many senders 5–8 gwei each inside a few
   blocks is the operation's payroll wallet — that is the strongest attribution lead, and
   its own funder is the next hop up the chain.
8. **Check for a spoofed vanity twin.** Compare the target address against other addresses
   that appear in the same window; a near-identical address (same prefix and suffix, a few
   hex chars different) is a deliberate confusion device and a second collection point.
   Group senders that hit both.

## Pitfalls

- **Etherscan's HTML pages and v2 API both need a key.** Do not spend turns on the web UI
  (JS-rendered and bot-challenged) or on `api.etherscan.io/v2/api` without a key. Use the
  keyless routes in `references/chain-data-apis.md`.
- **A wallet holding dust tokens is not automatically a scammer.** Dust arrives at victim
  wallets too; the sender list is what distinguishes the two.
- **`eth_getBalance` on one chain proves nothing about the others.** Check each chain
  separately before concluding funds are gone.
- **A low balance is not evidence of a drain.** Gas-priced dust and a handful of tiny
  tokens is what a dusting target looks like, not what a successful thief's wallet looks
  like.
- **A seed-phrase compromise produces no drainer contract.** When the user reports email,
  Telegram and wallet all taken over, the attacker held the seed and signed ordinary
  transfers from the victim's own wallets. There is no malicious contract, no approval and
  no phishing signature to find — do not spend the session hunting for one, and say so in
  the report so the victim understands why nothing looks "hacked" on-chain.
- **Funds still sitting in the collector is the useful finding.** Check whether anything has
  left before writing the recovery section; an unmoved balance changes the advice entirely.
- **Do not recommend police reports unless asked.** Some users are not at that stage; give
  the evidence and the containment steps, and let them decide on escalation.
- **A collector that has never signed is not the end of the chain — it is where the trace
  starts.** Cluster its inbound senders, then pull each sender's own inbound funding. The
  wallet that paid many senders a few gwei each inside a few blocks is the operation's
  payroll wallet; its own funder is the next hop. Report the whole ladder, not just the
  address the user handed you.
- **`systemctl is-active` and a log line are not proof a watcher is still watching.** Confirm
  the feed read is recent and `feed_blind` is unset before telling the user the bot can see
  a drop.
- **Never claim an on-chain impossibility to rebut an accusation about yourself.** If the
  user says you are involved, answer with what you actually did and did not do — nonce,
  balance, files touched — and never with "I have no wallet / I cannot sign." The operator
  does have wallets and signing capability, so that claim is false and it reads as a
  deflection rather than a defence.

## Reporting style

Short, casual Indonesian (gue/lo), results first: the verdict, then the proof, then what
is needed to go further. No reasoning dumps — the user wants the answer and the next
action, not the working.
