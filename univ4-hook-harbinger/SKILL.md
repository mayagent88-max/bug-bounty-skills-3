---
name: univ4-hook-harbinger
description: Review Uniswap v4 hooks and integrations for permission-bit, callback-authentication, pool-identity, custom-accounting, delta, settlement, dynamic-fee, JIT-liquidity, shared-custody, and liveness bugs. Use when a Solidity system implements IHooks or BaseHook, returns hook deltas, or relies on a v4 hook for pricing, authorization, accounting, or custody.
---

Analyze Uniswap v4 hooks as protocol components. Trace routers, PoolManager, hooks, settlement, vaults, and protocol-issued tokens as one system.

Only report issues with a reachable attacker path and a concrete effect on value, authorization, accounting, solvency, pricing, or liveness. Do not report generic hook risks or suspicious code without showing how the target's assumptions break.

## Applicability gates

Proceed if any are present:

- `IHooks`, `BaseHook`, `IUnlockCallback`, or a nonzero `PoolKey.hooks`
- swap, liquidity, donate, or initialization callbacks
- `BeforeSwapDelta`, `BalanceDelta`, return-delta flags, custom accounting, or dynamic fees
- hook-owned liquidity, vaults, receipt tokens, range orders, JIT penalties, or anti-MEV state

Otherwise do not force findings.

## High-signal probes

### 1) Address permissions and deployed identity

Decode the 14 permission bits from the deployed hook address. Compare them with implemented callbacks, `getHookPermissions()`, constructor checks, deployment inputs, tests, and runtime bytecode.

Trace every privileged path that can change the implementation, trusted routers, accepted pool domains, pricing dependencies, fees, or exit behavior. Verify upgrades preserve storage layout and the callback/address-bit invariants. Exercise role transfer, renunciation, pause, and emergency controls against the deployed configuration.

Check for:

- implemented callbacks without encoded permissions
- encoded callbacks that are missing or unexpectedly reachable
- return-delta flags without their parent callback flag
- proxies whose address bits no longer match implementation behavior after an upgrade
- unreproducible CREATE2 inputs
- callback selectors or ABI parameter and return tuples with the wrong length, type, order, or field encoding

Report when a mismatch disables required security logic, enables unintended behavior, corrupts callback handling, causes practical swap or liquidity failure, or changes economic behavior.

### 2) Authentic PoolManager, forged context

Verify every hook entrypoint and unlock callback authenticates the canonical PoolManager or an explicitly trusted dispatcher. Then validate the context carried by the real PoolManager.

For every sensitive callback:

- validate the complete intended `PoolKey` or `PoolId`
- treat callback `sender` as an operator or router unless the flow proves it is the economic user
- treat `hookData` as untrusted; when it authorizes or prices an action, bind every security-relevant domain element, such as chain, hook, PoolId, operation, direction, amount, limits, payer, recipient, nonce, and deadline
- test the trusted router through another route or pool
- create hostile pools with fake or reversed currencies, alternate fees or tick spacing, and protocol-issued receipt or LP tokens
- test fee-on-transfer, rebasing, callback-enabled, pausable, freezable, blacklistable, and unusual-decimal tokens when the hook's accounting claims to support them

Report when a direct call or genuine PoolManager callback can be turned into unauthorized minting, burning, settlement, pricing, fee assignment, or movement of protocol assets.

### 3) Pool isolation and lifecycle paths

Map every state key and liability bucket. Shared state must be partitioned by its complete economic domain, which may include PoolId, owner or operator, ticks, salt, market, vault, epoch, or order identity.

Exercise each operation through the intended router, direct PoolManager calls, a minimal attacker unlocker, and hook-initiated PoolManager calls. Test:

- `noSelfCall`, which can make the hook's own PoolManager actions skip callbacks
- zero-liquidity modifications and fee-only collection
- `donate` as an independent accounting ingress
- partial and full removal, range changes, pause, and emergency exit
- repeated or attacker-controlled initialization
- transient or pending-operation state that is not cleared on every terminal path

Report when an alternate lifecycle path skips authorization or accounting, resets age or penalty state, captures fees, contaminates another pool, replays initialization, or prevents users from withdrawing.

### 4) Deltas, custom accounting, and settlement

Review all four swap quadrants. The specified currency is:

- exact input, zero-for-one: currency0
- exact input, one-for-zero: currency1
- exact output, zero-for-one: currency1
- exact output, one-for-zero: currency0

Trace `amountSpecified`, `BeforeSwapDelta`, native swap delta, after-swap delta, hook delta, caller delta, and final balances. Check sign direction, token ordering, `int128` truncation, signed-to-unsigned casts, return-delta permissions, exact-output fills, and slippage after hook adjustments.

Track transient deltas per address and currency. Do not accept a cross-account or cross-currency sum as proof of settlement; every outstanding currency delta must reach zero before the unlock ends.

If `beforeSwap` offsets the native swap into a no-op, treat the hook as the complete AMM. Verify conservation, available liquidity, pricing, fees, slippage, exact-output fill, and rounding.

Trace every unlock branch through `settle`, `settleFor`, `take`, ERC-6909 claims, native currency, and `clear`. Test direct transfers and donations before settlement. Reject absolute-balance accounting that lets another pool's assets satisfy the current operation.

Report when an asset ledger shows that an attacker gains value, another user or pool loses it, and PoolManager settlement reaches zero while the hook's accounting or solvency invariant remains broken.

### 5) Dynamic fees, JIT penalties, and time state

Separate the dynamic-fee marker, stored LP fee, and per-swap override. Verify initialization, override flags, bounds, and persistent-update authority.

For every oracle or external price input, verify its source, units, decimals, freshness, observation window, manipulation resistance, invalid-value handling, and sequencer liveness or cross-chain finality when applicable. Test stale, reverted, delayed, and out-of-order updates.

Test these sequences:

- fee update, victim swap, and fee restoration
- old position, minimal add, and immediate removal
- fee-only collection followed by penalty-sensitive removal
- penalty donation followed by collection from another account
- price manipulation, first block or epoch checkpoint, value-sensitive action, and price restoration
- direction changes and multiple swaps in one transaction
- exact-output swaps at extreme fee settings

Check that post-swap values are not written across the interval that elapsed before the swap. The first update must not freeze a manipulable spot value as a trusted checkpoint.

Report when an attacker can reset age, evade a penalty, capture accrued value, choose a snapshot, double-spend a fee bucket, or force practical swap, liquidity, or exit failure.

### 6) Math, shared custody, and callback liveness

For range, vault, or custom-curve hooks, trace units and rounding through every conversion. Test zero and maximum inputs, `type(int256).min`, zero denominators, cast bounds, mixed token-decimal and fixed-point scales, discontinuities, monotonicity, invertibility, and cumulative drift.

Test non-aligned ticks, minimum and maximum usable ticks, exact boundary crossings, empty ranges, single-wei liquidity, first deposits, donations, repeated minimum withdrawals, and deposit-withdraw round trips. Bound loops over ticks, orders, epochs, and positions.

Never treat the hook's whole token balance as one pool's reserves. Account for vault yield, rebases, fees, ERC-6909 claims, and recursive pools made from the hook's own receipt or LP token.

Trace external calls made during callbacks. Test:

- cross-pool and cross-operation reentrancy while pending context is live
- read-only observation of incomplete accounting
- overwritten pending context
- malformed, false, or ignored external-call returns and selective reverts
- ERC-20/777, ERC-721/1155, and flash-loan callbacks
- worst-case gas growth as state accumulates, including hot-path storage writes and external calls
- dependencies that fail during swaps, liquidity changes, or emergency withdrawal

Classify each dependency path. Safety checks may need to fail closed. Optional rewards, cleanup, and integrations must not block safe exits. Do not accept stale pricing silently as a fallback.

Report when a reachable sequence causes profitable drift, a corrupted claim, cross-pool insolvency, a broken price, or practical swap, liquidity, or exit failure.
