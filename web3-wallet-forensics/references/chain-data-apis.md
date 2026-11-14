# Keyless chain-data APIs

Routescan and Blockscout serve Etherscan-shaped and native endpoints without an API key.
Use these instead of `api.etherscan.io` (v2 requires a key) or the Etherscan HTML pages
(JS-rendered and bot-challenged).

## Routescan (Etherscan-compatible, no key)

Base: `https://api.routescan.io/v2/network/mainnet/evm/1/etherscan/api`

| action | what it returns |
|---|---|
| `module=account&action=txlist&address=A&startblock=0&endblock=99999999&sort=asc` | normal txs with `from`/`to`/`value`/`isError`/`functionName` |
| `module=account&action=txlistinternal&address=A&...` | internal txs (contract-to-contract value moves) |
| `module=account&action=tokentx&address=A&...` | ERC-20 transfers with `tokenSymbol`, `tokenDecimal`, `contractAddress` |

Response is `{"status":"1","message":"OK","result":[...]}`. On error `result` is a
string, not a list — type-check before iterating.

## Blockscout (native v2)

`https://eth.blockscout.com/api/v2/addresses/<address>/transactions` — paginated JSON
with `raw_input`, `result`, `token_transfers`. Good cross-check when Routescan is thin.

## Raw RPC (any public node)

`https://ethereum-rpc.publicnode.com`, `https://eth.llamarpc.com`,
`https://rpc.mevblocker.io`, `https://eth.drpc.org`

- `eth_getBalance` — current holdings
- `eth_getTransactionCount` — **the nonce; > 0 means the address has sent txs**
- `eth_getBlockByNumber` — base fee, for gas math
- `eth_getTransactionReceipt` — proof a tx landed (`status == '0x1'`)
- `eth_call` with selector `0x06fdde03` (name), `0x95d89b41` (symbol),
  `0x313ce567` (decimals), `0x18160ddd` (totalSupply) — identify an unknown token

## Other chains

Same JSON-RPC surface, different endpoint:

| chain | endpoint |
|---|---|
| Base | `https://mainnet.base.org` |
| Arbitrum | `https://arb1.arbitrum.io/rpc` |
| Optimism | `https://mainnet.optimism.io` |
| BSC | `https://bsc-dataseed.binance.org` |
| Avalanche C-Chain | `https://api.avax.network/ext/bc/C/rpc` |

## Reading a token's identity from `eth_call`

ABI-encoded strings carry a 32-byte offset word; strip it and the trailing zero bytes
before decoding:

```python
b = bytes.fromhex(result[2:])
name = b[32:].rstrip(b'\x00').decode('utf-8', 'replace')
```

## Saving evidence

Write raw API responses to a case folder (`<HOME_DIR>/bounty-hunter/cases/<addr>_txs.json`)
so the trace can be re-derived or handed to someone else without re-querying.
