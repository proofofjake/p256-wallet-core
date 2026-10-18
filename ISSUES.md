# Security review: issues and resolutions

Review of `p256-wallet-core` v0.1.0 at commit `64dc09b`, 18 Oct 2026. Every issue has a test in
`tests/security.rs` named `finding_f<N>_…`. Each one asserts the fixed behaviour and is `#[ignore]`d while the
issue is open:

```sh
cargo test --test security -- --ignored        # lists what's still open; each fails until fixed
```

When an issue is fixed, remove the test's `#[ignore]`. If the behaviour is accepted by design, delete the test and
note it here instead.

**Resolution, 18 Oct 2026 (v0.2.0):** every finding is addressed and no `finding_*` test is ignored. Each section
below ends with a **Status** line. Two tests had a line asserting the old behaviour (F1's "free and sponsored", F10's
`0xf4240`); those lines now assert the fix. F5 was resolved as a per-key choice, so its test checks that instead.

## Summary

| # | Severity | Issue | Status (v0.2.0) |
|---|---|---|---|
| F1 | High | The paymaster isn't reviewed | Fixed |
| F2 | High | Wallet takeovers look like a settings tweak | Fixed |
| F3 | Medium | Function names are trusted on a 4-byte selector match | Fixed |
| F4 | Medium | Review text can contain control and bidi characters | Fixed |
| F5 | Medium (design) | A touch is enough; no PIN or biometric | Fixed as a per-key option |
| F6 | Medium (design) | Synced passkeys are accepted as owners | Fixed |
| F7 | Low | RP ID and origin aren't checked | Fixed (RP ID; origin not checked) |
| F8 | Low | `owner_keys` aren't checked against the wallet record | Fixed |
| F9 | Low | The review doesn't name the sending wallet or network | Fixed |
| F10 | Low | "1,000" parses as 1 token | Fixed |
| F11 | Low | Duplicate CBOR map keys are accepted | Fixed |
| F12 | Info | Near-max approvals aren't called unlimited | Fixed |
| F13 | Info | Bundler-suggested fees have no sanity cap | Accepted; left to the apps |
| F14 | Info | `is_erc1271_success` ignores trailing bytes | Fixed |

Fix F1 and F2 first. They're the two where a malicious dapp, app build or bundler can get the user to approve
something the review screen misdescribes.

---

## F1 · High · The paymaster isn't reviewed

**Where:** `api::review_user_operation`, `review::describe`

**What happens:** any non-empty `paymasterAndData` sets `sponsored = true` and `max_gas_cost = 0`. The paymaster's
address isn't shown anywhere in the review. `paymasterAndData` is covered by the signed hash, so the user does
commit to it, but nothing tells them what it is.

**Impact:**
- An ERC-20 paymaster can charge the account in `postOp` using an allowance the wallet has already given it (for
  example, USDC approved to a token paymaster). The user is told the transaction is free.
- A bogus paymaster turns "free" into a failed operation.

The README says endpoints "can't make the key sign something other than what was reviewed". The paymaster is the
exception.

**Fix:**
- Show the paymaster address, plus a name when it's on a known list.
- Only report `sponsored` / zero cost for paymasters on an allowlist (for example, the chain's configured
  sponsor).
- Otherwise say "Paid by paymaster 0x…; it may charge this wallet".

**Test:** `finding_f1_review_shows_the_paymaster`

**Status:** fixed. The review names any paymaster ("Gas paid by: Paymaster 0x…") and adds "Not a known sponsor. It
can charge this wallet through token allowances you've given it." `OperationReview` has a new `paymaster` field, and
`sponsored` is true only for paymasters on the chain's `known_paymasters` list, which is empty until a sponsor's
address is reviewed and added. `max_gas_cost` stays zero with any paymaster, because the EntryPoint charges gas to
the paymaster's deposit, not the wallet's ETH. A `paymasterAndData` too short to name a paymaster is refused.

## F2 · High · Wallet takeovers look like a settings tweak

**Where:** `review::describe_call`, the `call.target == sender` branch

**What happens:** only `addOwnerPublicKey` is decoded. Every other self-call is shown as "Change wallet settings"
plus a hex selector, including:
- `addOwnerAddress(address)`: an EOA becomes an owner (full takeover);
- `upgradeToAndCall(address,bytes)`: the implementation is replaced (full takeover);
- `removeOwnerAtIndex(uint256,bytes)` and `removeLastOwner`.

**Impact:** a dapp-initiated transaction (through the extension) can take over the wallet behind a label that reads
like a harmless setting change.

**Fix:**
- Refuse unknown self-calls by default.
- Decode each owner-management call explicitly, naming the address or key being added or removed.
- Refuse `upgradeToAndCall` outright, or give it a strong warning unless the target is a known implementation.

**Test:** `finding_f2_owner_takeover_calls_are_refused_or_spelled_out`

**Status:** fixed. Self-calls go through an allowlist (`smart_wallet::classify_self_call`), enforced at signing
as well as review:
- `addOwnerPublicKey` shows the full key;
- `removeOwnerAtIndex` shows the index and the owner being removed;
- `addOwnerAddress`, `upgradeToAndCall`, `removeLastOwner` and every other self-call are refused, each with a
  reason.

## F3 · Medium · Function names are trusted on a 4-byte selector match

**Where:** `review::contract_call`

**What happens:** names and argument types come from the app-supplied `function_signatures` and are used whenever
the 4-byte selector matches. Selectors collide by construction. `burn(uint256)` and
`collate_propagate_storage(bytes16)` are both `0x42966c68`, and the test shows a burn reviewed under the second
name.

**Impact:** if an app fills unknown selectors from a public signature database, a malicious contract can register
a benign-looking name for its selector.

**Fix:**
- Mark names that aren't from a bundled or verified ABI as "unverified".
- If several supplied signatures match one selector, show none of them, or all of them.
- Document in the glue checklist that `function_signatures` must come from a trusted source.

**Test:** `finding_f3_colliding_function_names_are_flagged`

**Status:** fixed. A matched name is shown as "Function (unverified)". If more than one supplied signature
matches the selector, none is shown ("several names match this selector"). The README's app checklist now says
`function_signatures` must come from what the user typed or a bundled ABI, never a public selector database.

## F4 · Medium · Review text can contain control and bidi characters

**Where:** `review::describe_call`, `abi::decode_values` (string arguments), and token `symbol`s from the app

**What happens:** decoded strings and token symbols reach `ReviewDetail.value` verbatim. That includes newlines,
tabs and Unicode bidi overrides (U+202A–U+202E, U+2066–U+2069).

**Impact:** calldata can fake extra review rows (for example a string containing `\nSend: 0 ETH`), or visually
reverse part of an address.

**Fix:** escape or strip control and bidi characters in every value the review emits. Consider also capping string
length.

**Test:** `finding_f4_review_text_has_no_control_or_bidi_characters`

**Status:** fixed. Every label and value passes through `review::sanitize`. Control characters, bidi
overrides and isolates, line and paragraph separators, and zero-width or invisible format characters are shown as
visible `\u{…}` escapes, and values are cut at 200 characters.

## F5 · Medium (design) · A touch is enough; no PIN or biometric

**Where:** `webauthn::signature_data` (checks UP only, not UV)

**What happens:** an assertion with only the user-present flag is accepted.

**Impact:** whoever holds the YubiKey and the unlocked app can sign. Matters if a stolen or borrowed key is in the
threat model.

**Fix:** if the design calls for it, request `userVerification: "required"` in both apps and check
`FLAG_USER_VERIFIED` in the core. Otherwise accept this by design and delete the test.

**Test:** `finding_f5_user_verification_is_required`

**Status:** fixed as a per-key choice. Requiring a PIN for every key was rejected in favour of an option at
registration. `verify_registration` takes `require_user_verification`, and refuses a registration that didn't
verify the PIN when it's set. It reports `pin_enforced_by_key` when the key applied `credProtect` level 3, meaning
the key itself refuses to sign without its PIN. `OwnerKey.require_user_verification` makes the core refuse
touch-only assertions from that key. Keys registered without a PIN still sign with a touch, by the owner's choice.
The test is now `finding_f5_pin_is_required_for_keys_registered_with_one`.

## F6 · Medium (design) · Synced passkeys are accepted as owners

**Where:** `webauthn::public_key_from_attestation_object`

**What happens:**
- The backup-eligible / backed-up flags (BE `0x08`, BS `0x10`) aren't checked.
- The attestation statement isn't verified (`fmt: none` is accepted).

So an iCloud Keychain or Google Password Manager passkey registers the same way a YubiKey does.

**Impact:** it breaks "a YubiKey signs every transaction". A synced passkey lives wherever the cloud account does.

**Fix:**
- Reject BE at registration.
- Optionally verify `packed` attestation against Yubico's root, or check the AAGUID against known YubiKey models.

**Test:** `finding_f6_synced_passkeys_are_rejected_at_registration`

**Status:** fixed. `verify_registration` refuses backup-eligible credentials, so only hardware keys become
owners. Attestation statements and AAGUIDs aren't verified: browsers zero the AAGUID under `attestation: "none"`,
and verifying `packed` attestation against Yubico's roots is left as a possible later step.

## F7 · Low · RP ID and origin aren't checked

**Where:** `webauthn::signature_data`

**What happens:** the `rpIdHash` is parsed but never compared, and the `origin` in `clientDataJSON` isn't read.

**Impact:** low. Authenticators scope credentials by RP ID, and webauthn-sol ignores both too, so exploiting this
needs a misbehaving platform. It's a cheap defence in depth.

**Fix:** pin the expected RP ID hash or hashes (the app's and the extension's) and refuse other assertions.

**Test:** `finding_f7_assertions_from_another_rp_are_refused`

**Status:** fixed for the RP ID. Each `OwnerKey` carries the `rp_id` the key was registered under. Assertions
and registrations whose `rpIdHash` doesn't match it are refused. The `origin` in `clientDataJSON` still isn't
parsed, because it differs per platform (`chrome-extension://…`, `https://…`) and the RP ID check covers the same
ground.

## F8 · Low · `owner_keys` aren't checked against the wallet record

**Where:** `api::wrapped_signature`, `api::sign_message`, `api::sign_user_operation`

**What happens:** the app supplies `credential_id → (owner_index, public_key)`, and the core trusts the pairing.
For indexes below the number of initial owners, the record could check it, but doesn't.

**Impact:** a wrong pairing produces a signature the account rejects onchain. That's a confusing failure, not a
loss.

**Fix:** where `initial_owners` is available, require `owner_bytes(public_key) == initial_owners[owner_index]` for
those indexes.

**Test:** `finding_f8_owner_index_must_match_the_wallet_record`

**Status:** fixed. `sign_user_operation` now takes `initial_owners`, as `sign_message` already did. Both check
that the record produces the account's address, and that a key claiming an initial owner's index is that owner.
Indexes above the initial owners (keys added later) are still taken from the app; checking those needs onchain
state.

## F9 · Low · The review doesn't name the sending wallet or network

**Where:** `review::describe`

**What happens:** the review lists calls and costs, but not `sender` or the chain the hash was computed for.

**Impact:** harmless with one wallet on one chain, misleading once an app holds several.

**Fix:** add "From" (checksummed `sender`) and "Network" rows.

**Test:** `finding_f9_review_names_the_sending_wallet`

**Status:** fixed. Every review starts with "From" (the checksummed sender) and "Network" (the chain's name, or
"Chain <id>").

## F10 · Low · "1,000" parses as 1 token

**Where:** `units::parse`

**What happens:** `,` is always treated as a decimal separator, so "1,000" with 6 decimals gives `0xf4240`: one
token, not a thousand.

**Impact:** it sends less than intended (the safe direction), but it's wrong for en-GB and en-US users.

**Fix:** reject input containing both separators, and reject a single comma followed by exactly three digits. Or
make the separator explicit, decided by the app's locale.

**Test:** `finding_f10_ambiguous_comma_is_refused`

**Status:** fixed. Several commas, a comma with a dot, and a single comma followed by exactly three digits are all
refused. "1,5" still reads as 1.5.

## F11 · Low · Duplicate CBOR map keys are accepted

**Where:** `cbor::item` (maps) and `Value::get` (first match wins)

**What happens:** a COSE key with two `-2` / `-3` entries is accepted, and the first pair is used.

**Impact:** CTAP2 requires canonical CBOR without duplicates. A lenient parser can disagree with another parser
about which key was registered.

**Fix:** reject maps with duplicate keys.

**Test:** `finding_f11_duplicate_cose_labels_are_refused`

**Status:** fixed. The CBOR decoder refuses maps with duplicate keys. Registration also refuses authenticator
data with bytes after the public key unless the extensions flag is set.

## F12 · Info · Near-max approvals aren't called unlimited

**Where:** `review::describe_call` (approve)

**What happens:** only `type(uint256).max` reads "Unlimited". An approval of 2^255 shows as a 78-digit amount.

**Fix:** treat amounts at or above, say, 2^128 (or above the token's total supply) as unlimited.

**Test:** `finding_f12_huge_approvals_read_as_unlimited`

**Status:** fixed. Approvals of 2^128 or more read "Unlimited".

## F13 · Info · Bundler-suggested fees have no sanity cap

**Where:** `api::apply_gas_estimate`, `GasPrice` as passed in by the apps

**What happens:** gas limits and fees from the bundler are used as given, plus headroom. The review does show the
resulting `max_gas_cost`.

**Impact:** a malicious bundler can inflate `preVerificationGas` or the priority fee (it keeps the difference). The
user can see it, but only as a maximum cost.

**Fix:** have the apps compare fees against the chain's base fee and warn above a multiple. Optionally add a core
helper that flags implausible values.

**Test:** none

**Status:** accepted for now. The core has no view of the current base fee, so a cap there would be a guess that
could block valid operations when Base fees spike. The review shows the resulting maximum cost, and the app
checklist says apps may warn when fees look high against the network's base fee.

## F14 · Info · `is_erc1271_success` ignores trailing bytes

**Where:** `api::is_erc1271_success`

**What happens:** it checks only the first 4 bytes, so `0x1626ba7e` followed by non-zero bytes passes.

**Impact:** negligible. The apps use it as a sanity check on their own signatures.

**Fix:** require exactly one 32-byte word: the magic value followed by zero padding.

**Test:** none

**Status:** fixed, with a unit test in `api::tests::values`.

---

## Verified (not issues)

These held up under the harness, and the `guarantee_*` tests in `tests/security.rs` keep them that way:

- **Signatures can't be moved:** each one is bound to chain, operation and owner. An assertion is refused if it's:
  - replayed on another chain;
  - over an operation changed after review (calldata, fees, nonce or paymaster);
  - signed by an attacker's key that claims an owner's credential ID;
  - missing user presence;
  - a `webauthn.create` response.
- **Messages and operations are separate:** a signature over a message can't authorise an operation, and the
  reverse.
- **Account checks:** a deployment must create exactly `sender` through the Coinbase factory. Only
  `execute`/`executeBatch` are signed; `executeWithoutChainIdValidation` is refused.
- **Signature format:** signatures are normalised to low-s, and the encoded `WebAuthnAuth` passes the same checks
  as webauthn-sol.
- **No crashes:** about 1.8 million mutated inputs across every exported function caused no panics
  (`tests/fuzz.rs`).
- **Decoding matches Foundry:** account-call encoding is byte-identical to Foundry's `cast`. On mutated calldata
  the core never accepted anything `cast` rejected, and never decoded anything differently
  (`tests/differential.rs`).
