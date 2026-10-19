# Security

## Reporting

Please report security problems privately via GitHub's "Report a vulnerability" on this repository, not in a
public issue.

## Reviews

| Date | Version reviewed | Report | Resolved in |
|---|---|---|---|
| 18 Oct 2026 | v0.1.0 (`64dc09b`) | [audits/2026-10-18-review-1.md](audits/2026-10-18-review-1.md) | v0.2.0 |
| 18 Oct 2026 | v0.2.1 (`2c37779`) | [audits/2026-10-18-review-2.md](audits/2026-10-18-review-2.md) | v0.3.0 |

Each report keeps the reviewer's text, with a **Status** line added under every finding. Every finding has a test
in `tests/security.rs` named `finding_f<N>_…`. What's still open or accepted is in [ISSUES.md](ISSUES.md).

## Findings

| # | Severity | Issue | Resolution |
|---|---|---|---|
| F1 | High | The paymaster isn't reviewed | v0.2.0: named in the review; "sponsored" only for reviewed sponsors |
| F2 | High | Wallet takeovers look like a settings tweak | v0.2.0: self-calls limited to owner changes; v0.3.0: see F15 |
| F3 | Medium | Function names trusted on a 4-byte selector match | v0.2.0: marked unverified, hidden on collisions; v0.3.0: see F19 |
| F4 | Medium | Control and bidi characters in review text | v0.2.0: escaped; v0.3.0: see F18 |
| F5 | Medium | A touch is enough; no PIN | v0.2.0: per-key PIN; v0.3.0: the key must enforce it (F17) |
| F6 | Medium | Synced passkeys accepted as owners | v0.2.0: refused at registration |
| F7 | Low | RP ID and origin not checked | v0.2.0: RP ID pinned per key |
| F8 | Low | Owner keys not checked against the wallet record | v0.2.0 |
| F9 | Low | Review doesn't name the wallet or network | v0.2.0 |
| F10 | Low | "1,000" parses as 1 | v0.2.0: refused as ambiguous |
| F11 | Low | Duplicate CBOR map keys accepted | v0.2.0; v0.3.0: see F20 |
| F12 | Info | Near-max approvals not called unlimited | v0.2.0 |
| F13 | Info | No sanity cap on bundler fees | Accepted; left to the apps |
| F14 | Info | `is_erc1271_success` ignores trailing bytes | v0.2.0 |
| F15 | **Critical** | Any operation can add an attacker's P-256 key as an owner | v0.3.0: only the key the app just registered, as the only call; owner removal refused |
| F16 | Medium | NFT approvals, allowance increases, Permit2 and `transferFrom` not recognised | v0.3.0: decoded and spelled out |
| F17 | Medium | The PIN requirement is only as strong as stored data | v0.3.0: a PIN key must enforce it itself (`credProtect` 3) |
| F18 | Low | `sanitize` misses 307 invisible characters | v0.3.0: allow-list generated from Unicode 18.0 |
| F19 | Low | Batch summaries show unverified names without the mark | v0.3.0 |
| F20 | Low | Quadratic CBOR duplicate-key check | v0.3.0: size caps, canonical order for authenticator CBOR |
| F21 | Low | Two keys can claim the same owner index | v0.3.0: refused per chain |
| F22 | Info | Cross-origin and duplicate-key `clientDataJSON` accepted | v0.3.0: refused |
