# Open issues

Only what's still open or accepted is listed here. Each security review and how every finding was resolved is in
[SECURITY.md](SECURITY.md).

## Open

| # | Severity | Issue | Notes |
|---|---|---|---|
| — | Low | ERC-1155 `safeBatchTransferFrom` isn't decoded in the review | Found while fixing F16. It shows as an "Unknown" contract call, as before. Decoding it means showing two arrays of item IDs and amounts. |

## Accepted

| # | Severity | Issue | Why |
|---|---|---|---|
| F13 | Info | Bundler-suggested fees have no sanity cap | The review shows the maximum cost (`max_gas_cost`), and only the apps know the network's current base fee. Apps may warn when fees look high. |
