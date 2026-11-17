---
name: safu_nft_market_watch
description: "Watch token and NFT floors and sell at the threshold"
---
# Watch token and NFT floors and sell at the threshold

## Run the scheduled watch

- Run the watch about every 6 hours on a schedule the user agreed.

- Record each token price and each NFT floor in a state file after every check.

- Compare each new reading against the last recorded reading and treat the last reading as the baseline for change.

## Report only on change

- Stay silent when nothing changed since the last check.

- Report at once when a token price or an NFT floor moved since the last check.

- Name the changed item and give its new value and its previous value in the report.

- Report at once when a verified net value reaches the sell threshold.

## Sell only on a verified net route

- Read the sell threshold for each item from your own memory before you act.

- Verify the floor and the liquidity live before any sale.

- Use the nft-market-sell skill to compare markets and pick the best net route after fees.

- Use the dex-aggregator skill when a router reports no liquidity and check a second route before you call a token unsellable.

- Prefer proceeds in the native gas token and fall back to a stablecoin only when that route nets more.

- Reject a sale that rests on a single market quote and wait for a second live quote.

- Sell only when the verified net value reaches the threshold from your own memory.

## Hold and clean up after a sale

- Hold the item when its value sits below the threshold and report the hold with its current value.

- Hold the item when no verified sell route exists and report the hold with its current value.

- Revoke every approval the sale created as soon as the transaction confirms.

## Keep price and wallet moves under instruction

- Keep the listing price unchanged unless the user gives a new instruction.

- Ask the user before you move a token to another wallet to try another market.

## Available connectors

- Use `muse.connector_search` to find other connectors and `muse.skill_search` to find related skills.

- If nothing here fits, look on the web for a maintained API or MCP server and set it up with [Custom Connectors and MCPs](/opt/muse/skills/custom-connector-setup/SKILL.md), or build a custom connector.
