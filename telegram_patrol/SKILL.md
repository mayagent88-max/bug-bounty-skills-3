---
name: telegram_patrol
description: "Patrol public Telegram channels and report per project"
---
# Patrol public Telegram channels and report per project

## Watch public channels only

- Read only public announcement channels through their public web pages.

- Never log in to the personal Telegram account of the user.

- Never open a private chat, send a message, or connect a wallet from patrol work.

- Read the list of watched channels from your own memory or USER.md, and never hardcode a private group or a personal invite link into the patrol.

- Never ask for a seed phrase or a private key, and never accept one that is offered during patrol work.

## Poll in fast and layered loops

- Poll each watched channel about every 90 seconds in a fast loop.

- Run an hourly check as a second layer over the same channels.

- Store the last seen post ID for each channel in a seen file in the workspace.

- Compare each fetched post ID against the seen file before reporting, and update the seen file after each poll.

- Keep the seen file after a restart, and resume from the stored IDs so no post is reported twice and none is skipped.

## Report each new post per project

- Report one project per post, and never fold several posts into one vague summary.

- Name the source channel and give the post link for each new post.

- Give the mint or register link, the price, and the referral code when the post carries one.

- State plainly whether the post can be executed and why, or why it cannot.

- Report posts that cannot be executed too, and give the reason for each one.

- Report a post that cannot be verified or executed yet as pending, and give the reason it is pending.

## Execute only verified free mints

- Execute only a free mint that is verified live.

- Check the contract is verified, the supply is not sold out, the wallet is eligible, and the preview is clean before you execute.

- Report the transaction hash at once after an execution.

- Leave a post unexecuted when its contract is unverified, its supply is sold out, it costs money, it needs a step only the user can do, or it is not a free mint.

## Handle an unreadable channel honestly

- Report a channel that cannot be read, and name the obstacle such as a block or a login request.

- Never claim there is no new post only because a check failed.

- Retry the channel on the next poll, and keep its last seen ID unchanged until a read succeeds.

## Available connectors

- Use `muse.connector_search` to find other connectors and `muse.skill_search` to find related skills.

- If nothing here fits, look on the web for a maintained API or MCP server and set it up with [Custom Connectors and MCPs](/opt/muse/skills/custom-connector-setup/SKILL.md), or build a custom connector.

## Websites

- [Telegram](https://t.me/) for reading a public channel page and its posts. Carry the channel name into the read and verify the post text and its links there.

## Alternatives for better results

- Cross-check a mint on the official project site or a chain explorer before you execute, because a channel post can carry a wrong or outdated link.
