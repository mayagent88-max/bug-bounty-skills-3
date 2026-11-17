---
name: token_arrival_follow_up
description: "Follow a token until it arrives"
---
# Follow a token until it arrives

## Replace one check with polling

- Schedule repeated checks with `cron.add` when a token claim or launch is pending.

- Set the interval at 30 minutes or less during the launch window, because a longer gap can miss an arrival and a price move.

- Record the expected contract address, chain, amount, destination wallet, launch time and stop condition before the first check.

- Keep polling until the token arrives, the stated deadline passes, or the user cancels the watch.

- Treat a negative first check as pending, not as a closed case, and keep the schedule active until a stop condition is met.

## Confirm arrival before acting

- Check the wallet balance and transaction history for the exact contract address on the stated chain.

- Match the full contract address and the expected amount, and reject a similarly named token.

- Check the sale quote only after arrival is confirmed, starting with the wallet router and then searching with `muse.skill_search` for an aggregator check when that router reports no liquidity.

- Report a blocked quote source as blocked, not as proof that the token has no sale route.

## Sell only on a prior instruction

- Execute a sale only when the user already gave a sell instruction for that arrival, and only after price, liquidity, gas and net value are verified live.

- Ask the user first when no prior sell instruction exists, and report the arrival with the live quote instead of selling on your own.

- Approve only the exact amount in the confirmed sale, and never approve an unlimited spend.

- Report the transaction hash, the amount sold and the net value immediately after a sale.

## Close the watch plainly

- Cancel the polling schedule with `cron.remove` once arrival is handled, the deadline passes, or the user cancels, and tell the user that the watch ended and why.

- Send a short final report when the watch ends without arrival, naming the last check time and the reason the watch stopped.

- Keep the arrival, sale and final report in the same thread as the original instruction, so the user can trace the outcome without asking for a missing report.

## Available connectors

- Use `muse.connector_search` to find other connectors and `muse.skill_search` to find related skills.

- If nothing here fits, look on the web for a maintained API or MCP server and set it up with [Custom Connectors and MCPs](/opt/muse/skills/custom-connector-setup/SKILL.md), or build a custom connector.

## Alternatives for better results

- Ask the user in advance for a minimum net value for an automatic sale, so a fast price fall does not turn a verified arrival into a sale at a loss.

- Check the chain explorer for transfers to the destination wallet when the wallet balance display lags behind the chain.

- Keep polling after a partial arrival when the expected amount has not fully arrived, and report the partial amount rather than treating it as complete.
