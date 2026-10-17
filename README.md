# p256-wallet-core

The signing core of P256 Wallet, a Base smart wallet where a YubiKey signs every transaction. It's written once in
Rust and compiled into both apps:

| App | Binding | Built by |
|---|---|---|
| [p256-wallet](https://github.com/proofofjake/p256-wallet) (iOS) | Swift package, `bindings/swift` (UniFFI) | `scripts/build-swift.sh` |
| [p256-wallet-extension](https://github.com/proofofjake/p256-wallet-extension) (browser) | TypeScript, `bindings/ts` (WebAssembly) | `scripts/build-wasm.sh` |

Each app pins this repo as a git submodule at a tagged release and builds the binding from source. What ships is
compiled from the code that was reviewed, not from a prebuilt binary.

## What the core decides, and what it doesn't

The core decides **what gets signed**. It takes plain inputs (owner keys, calls, nonce, gas values, chain ID) and
returns:

- the user operation and the exact challenge the security key signs,
- a review of the operation, decoded from its own bytes, which both apps show as-is,
- the final signature, after checking the key's response signed that challenge with a registered owner key.

It does **no I/O**: no network, no storage, no UI, no randomness. The apps fetch nonces, gas prices and balances,
talk to the bundler, store the wallet record, and run the security key prompt. That keeps the core deterministic,
so every output can be checked against a fixed expected value.

### Guarantees the core enforces

| Guarantee | Where |
|---|---|
| The wallet address is derived locally (CREATE2 over the factory's init code hash), so a lying RPC can't substitute an address the user doesn't control. | `smart_wallet::account_address` |
| A security key response is used only if it signed **this** operation's hash (or this message's replay-safe hash), with the user-present flag set, and the P-256 signature verifies against a registered owner's public key. | `api::sign_user_operation`, `api::sign_message`, `webauthn::signature_data` |
| Signatures are normalized to low-s, which the account requires. | `webauthn::parse_signature` |
| The hash is recomputed from the operation at signing time; the apps can't pass in a different hash. | `api::sign_user_operation` |
| Only `execute` / `executeBatch` account calls are signed, and any deployment must create exactly `sender` from the Coinbase factory. Anything else is refused. | `api::check_operation` |
| The review lists every call: ETH and token amounts (raw units for unknown tokens, never a guessed symbol), unlimited approvals, owner changes, and function names only when the selector matches. | `review::describe` |
| A wallet record whose owners don't produce its address is rejected before anything is built or signed. | `api::build_user_operation`, `api::sign_message` |
| Registered public keys must be valid curve points, and must come from the credential that was just created. | `webauthn::public_key_from_attestation_object` |
| Amounts are parsed exactly (no rounding, overflow is an error), and display formatting never rounds up. | `units` |

### What the apps are responsible for (the glue checklist)

The apps stay thin, but a few things can only happen there. Review each app against this list:

1. **Show the core's review, not their own description.** The review screen must render
   `OperationReview.details` and the fee from `max_gas_cost`.
2. **Ask the key to sign `OperationReview.hash`** (or `MessageChallenge.challenge`) and pass the response to the
   core unmodified.
3. **Submit the operation the core returned from `sign_user_operation`**, without changing any field.
4. **Store the wallet record faithfully**: initial owners in order, credential IDs and owner indexes.
5. **Endpoints**: bundler, RPC and paymaster URLs are untrusted. They can cause failed or slow transactions, but
   they can't make the key sign something other than what was reviewed.

## Review guide

Read in this order. Counts are non-blank lines excluding tests.

| File | Lines | What to check |
|---|---|---|
| `src/api.rs` | ~350 | The whole surface the apps call. Each function validates its inputs; the two `sign_*` functions recompute what's signed. |
| `src/webauthn.rs` | ~180 | Attestation parsing, assertion checks, `WebAuthnAuth` encoding (offsets must match the onchain verifier's). |
| `src/smart_wallet.rs` | ~250 | Constants (factory, EntryPoint, init code hash), address derivation, call encoding and decoding, replay-safe hash, ERC-6492. |
| `src/user_operation.rs` | ~70 | `getUserOpHash`, max cost, gas headroom. |
| `src/review.rs` | ~120 | What the user is shown. |
| `src/abi.rs` | ~200 | ABI encoding, and strict decoding (dirty padding and out-of-range offsets are rejected). |
| `src/cbor.rs` | ~135 | Minimal CBOR for attestation objects, with bounded nesting and allocation. |
| `src/units.rs`, `src/function_call.rs`, `src/address.rs`, `src/hex.rs` | ~300 | Amount parsing and formatting, contract call encoding, EIP-55, hex. |
| `src/records.rs`, `src/wasm.rs`, `src/chains.rs` | ~380 | Data types and the one-line-per-function TypeScript wrappers. No logic. |

Cryptography isn't implemented here. It comes from RustCrypto: P-256 ECDSA (`p256` / `ecdsa`), SHA-256 (`sha2`)
and Keccak-256 (`sha3`). 256-bit arithmetic comes from `ruint`.

## Tests

```sh
cargo test                                          # unit tests, offline
CORE_INTEGRATION=1 cargo test --test base_sepolia   # against the live contracts; no funds needed
```

Unit test expectations come from Foundry's `cast` and from the deployed contracts. They cover ABI encodings,
selectors, Keccak vectors, EIP-55, the factory's address for known owners, `getUserOpHash`, `replaySafeHash`,
attestation parsing, low-s normalization, and every refusal listed above.

The live tests prove the core against Base Sepolia (and Base, for addresses) without a transaction:

- `EntryPoint.simulateValidation` with zero fees: the real Coinbase Smart Wallet accepts the core's signatures from
  each owner, and rejects a non-owner's signature even when it is wrapped to claim an owner's index.
- Local address derivation matches `factory.getAddress` on both chains, and `initCodeHash` is still current.
- `getUserOpHash` and `replaySafeHash` match the contracts.
- An ERC-6492 signature from an undeployed account verifies with the reference universal validator.

The bindings have smoke tests too: `swift test` in `bindings/swift`, and `npm test` in `bindings/ts`, each run
after its build script.

## Building the bindings

```sh
./scripts/build-swift.sh   # bindings/swift: XCFramework (iOS, iOS Simulator, macOS) + generated Swift
./scripts/build-wasm.sh    # bindings/ts/pkg: .wasm + JS glue
```

`rust-toolchain.toml` pins the compiler (rustup installs it automatically) and `Cargo.lock` pins every dependency,
so builds are repeatable. The wasm script also checks that `wasm-bindgen-cli` matches the version in `Cargo.lock`.
The Swift build targets Apple Silicon (no x86_64 simulator slice).

## Releasing and auditing

1. Change the core, run both test suites, and bump `version` in `Cargo.toml` (`core_version()` reports it).
2. Review the diff since the last tag, then tag it: `git tag -s v0.x.y`.
3. In each app, move the `core` submodule to the new tag and rebuild. An app's diff then shows exactly which core
   commit it runs.

## Dependencies

| Crate | Version | Used for |
|---|---|---|
| `p256`, `ecdsa` | 0.13.2, 0.16.9 | P-256 public keys and ECDSA verification, DER signatures |
| `sha2`, `sha3` | 0.10.9, 0.10.8 | SHA-256, Keccak-256 |
| `ruint` | 1.17.2 | 256-bit integers |
| `uniffi` | 0.32.2 | Swift binding (feature `uniffi`) |
| `wasm-bindgen`, `serde`, `serde-wasm-bindgen` | 0.2.129, 1.0.228, 0.6.5 | TypeScript binding (feature `wasm`) |

The core without bindings depends on about 30 crates, almost all from RustCrypto: run
`cargo tree -e normal` to list them.
