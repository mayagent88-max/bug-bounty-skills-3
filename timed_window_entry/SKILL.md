---
name: timed_window_entry
description: "Time a timed window entry"
---
# Time a timed window entry

## Classify the window before you act

- Read the live window rules and record the opening time, the closing time and whether entry depends on the action timestamp.

- Treat a window as contested when it has a fixed quota, a first come order or a limited slot count that rewards acting first.

- Treat a window as noncontested when entry is open for a full period and an action counts only when it falls inside that period.

- Do not reuse the timing plan from a contested window for a noncontested window, and do not reuse the timing plan from a noncontested window for a contested window.

## Deliver a noncontested entry at its opening time

- Hold the draft, the link and the submit steps for a noncontested entry until the window opens.

- Give the draft at the opening time so the user can act at once inside the window.

- Never give the draft far ahead of a noncontested window when an early action could be counted for the prior period or rejected for the new period.

- Say the exact opening time in the message that delivers the draft, so the user can check the action falls inside the window.

## Stand by early only for a contested window

- Prepare the draft, the connect step and the submit steps before a contested window opens.

- Stay ready at the opening time for a contested window and act at once when it opens.

- Apply the same early standby to any contested slot, such as a contested mint or a contested waitlist that rewards entering first.

- Say clearly when early standby applies and why, so an early draft is never mistaken for a general habit.

## Connect before you look for the submit step

- Complete the wallet or account connection first for any entry that needs a connected account.

- Confirm the account or card appears on the entry page before you search for a paste link or check control.

- Stop and report a missing connection plainly when the submit control is absent on an unconnected page, instead of searching the page without end.

- Retry the submit step only after the connection and the account display are both confirmed.

## Verify the entry result before you close

- Read the exact result text after each submit attempt and report whether the entry was accepted or rejected.

- Treat a rejection that cites the prior day or prior period as a timing rejection, and prepare a fresh action inside the current window.

- Report the entry count or draw status only after the result text confirms it, and keep the session connected when later periods will need it again.

- Close the task only when the result text shows the entry in the current period, or when you have reported a clear rejection and the next correct step.

## Available connectors

- Use `muse.connector_search` to find other connectors and `muse.skill_search` to find related skills.

- If nothing here fits, look on the web for a maintained API or MCP server and set it up with [Custom Connectors and MCPs](/opt/muse/skills/custom-connector-setup/SKILL.md), or build a custom connector.

## Alternatives for better results

- Offer a single easiest next step when a window is about to open, instead of a list of routes that delays the action.

- Reuse the accepted entry result as the proof for the next period, and start the next period from connection status rather than from a fresh connection.
