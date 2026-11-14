# Switch Wallet When a Browser Wallet Connect Stays Silent

## Check chain support before you send funds

- List the chains the wallet tool supports before you send funds to a new chain.

- Stop when the destination chain is absent from that list and report the chain as unsupported instead of sending funds there.

- Name the chain and the token separately so a chain is never treated as a token and a token is never treated as a chain.

- Check the bridge, the gas token and the withdraw path for the new chain before you promise a transfer or a mint on it.

## Diagnose a silent extension connect

- Treat a connect click with no popup, no account list and no error as a silent failure after one short wait.

- Read the provider response code when one appears and record it with the site and the wallet you tried.

- Stop retrying the same wallet on the same site after the first silent failure and change the route before you try again.

- Check that the wallet is unlocked and that the correct account is selected before you blame the site.

## Switch to the fallback wallet

- Try a second extension wallet that holds the same imported account when the first wallet stays silent.

- Add the site network to the fallback wallet only after you confirm the chain id, the RPC address and the explorer from the official docs.

- Confirm the account appears in the site connect dialog before you look for a swap, mint or sign button.

- Keep the fallback labeled as a workaround when it worked once and keep the first wallet as an option for a later retry.

## Report the result plainly

- Report which wallet connected, which wallet stayed silent and which network the site used.

- Report a missed window at once with the time it closed and the connect step that failed.

- Give the user the concrete next step only the user can take when signing or unlocking stays with the user.

## Available connectors

- Use `muse.connector_search` to find other connectors and `muse.skill_search` to find related skills.

- If nothing here fits, look on the web for a maintained API or MCP server and set it up with [Custom Connectors and MCPs](/opt/muse/skills/custom-connector-setup/SKILL.md), or build a custom connector.

## Alternatives for better results

- Ask the user before the window which wallet they prefer when both wallets hold the same account.

- Use a direct sign link or a QR code when the site offers one instead of repeating a silent browser connect.

- Check the project page again at the window start when the connect button was not visible earlier.
