/**
 * The core for TypeScript: typed wrappers over the WebAssembly build (scripts/build-wasm.sh). Same functions and
 * record shapes as the Swift binding; src/api.rs documents what each one does. Call `initCore()` once first.
 *
 * Byte strings are `0x` hex, numbers are JSON-RPC hex quantities, and errors are thrown as `CoreError`: an `Error`
 * with a message written to be shown to the user, and a `kind`.
 */
import init, * as wasm from './pkg/p256_wallet_core.js'
import type { InitInput } from './pkg/p256_wallet_core.js'

export type Hex = `0x${string}`
export type Address = Hex
/** JSON-RPC hex quantity, e.g. `0x1a`. */
export type Quantity = Hex

/**
 * What the core throws. `refused` means a well-formed request the wallet won't carry out (see `CoreError::Refused` in
 * src/error.rs), as opposed to malformed input or an unusable security key response.
 */
export interface CoreError extends Error {
  kind: 'invalidInput' | 'invalidAssertion' | 'refused'
}

export const isCoreError = (error: unknown): error is CoreError =>
  error instanceof Error && typeof (error as Partial<CoreError>).kind === 'string'

export interface PublicKey {
  x: Hex
  y: Hex
}

export interface Call {
  target: Address
  value: Quantity
  data: Hex
}

/** ERC-4337 v0.6 user operation, in the JSON-RPC shape bundlers use. */
export interface UserOperation {
  sender: Address
  nonce: Quantity
  initCode: Hex
  callData: Hex
  callGasLimit: Quantity
  verificationGasLimit: Quantity
  preVerificationGas: Quantity
  maxFeePerGas: Quantity
  maxPriorityFeePerGas: Quantity
  paymasterAndData: Hex
  signature: Hex
}

export interface GasPrice {
  maxFeePerGas: Quantity
  maxPriorityFeePerGas: Quantity
}

export interface GasEstimate {
  preVerificationGas: Quantity
  verificationGasLimit: Quantity
  callGasLimit: Quantity
}

/** What a security key returns when asked to sign, every field exactly as the authenticator produced it. */
export interface Assertion {
  credentialId: Hex
  authenticatorData: Hex
  clientDataJson: Hex
  /** ASN.1 DER-encoded ECDSA signature. */
  signature: Hex
}

export interface OwnerKey {
  credentialId: Hex
  ownerIndex: number
  publicKey: PublicKey
  /** The WebAuthn relying party ID the key was registered under. */
  rpId: string
  /** The key was registered with a PIN, which it enforces itself (keys registered before core v0.3.0 may not). */
  requireUserVerification: boolean
  /** For an owner added after the wallet was created, the chain it was added on. Null for the initial owners. */
  addedOnChainId: number | null
}

/** A security key registration, checked by `verifyRegistration`. */
export interface Registration {
  publicKey: PublicKey
  userVerified: boolean
  /** The key itself refuses to sign without its PIN (`credProtect` level 3). Always true when a PIN was required. */
  pinEnforcedByKey: boolean
}

export interface KnownContract {
  address: Address
  name: string
}

export interface Token {
  address: Address
  symbol: string
  name: string
  decimals: number
}

export interface ChainConfig {
  id: number
  name: string
  isTestnet: boolean
  rpcUrl: string
  defaultBundlerUrl: string
  explorerUrl: string
  blockscoutUrl?: string
  knownTokens: Token[]
  verificationGasBuffer: number
  /** Paymasters reviewed as pure sponsors. Any other paymaster is flagged in the review. */
  knownPaymasters: KnownContract[]
}

export interface EncodedFunctionCall {
  name: string
  signature: string
  data: Hex
}

export interface ReviewDetail {
  label: string
  value: string
  monospaced: boolean
}

/** What a user operation will do, decoded from the operation itself. Show `details` as-is. */
export interface OperationReview {
  /** The challenge the security key signs. */
  hash: Hex
  details: ReviewDetail[]
  deploysAccount: boolean
  /** The paymaster, if one pays the gas. */
  paymaster?: Address
  /** The paymaster is a known sponsor that charges the wallet nothing. */
  sponsored: boolean
  maxGasCost: Quantity
  totalValue: Quantity
  requiredBalance: Quantity
}

export interface MessageChallenge {
  messageHash: Hex
  challenge: Hex
}

export interface SignedMessage {
  messageHash: Hex
  signature: Hex
}

/** Loads the WebAssembly module. In a browser or extension the bundler serves it next to the JS. */
export async function initCore(moduleOrPath?: InitInput): Promise<void> {
  await init(moduleOrPath === undefined ? undefined : { module_or_path: moduleOrPath })
}

/** For environments with the bytes at hand, such as Node tests. */
export function initCoreSync(bytes: BufferSource): void {
  wasm.initSync({ module: bytes })
}

// Configuration
export const coreVersion = (): string => wasm.coreVersion()
export const chains = (): ChainConfig[] => wasm.chains()
export const entryPointAddress = (): Address => wasm.entryPointAddress() as Address
export const factoryAddress = (): Address => wasm.factoryAddress() as Address

// Values
export const checksumAddress = (address: string): Address => wasm.checksumAddress(address) as Address
export const parseQuantity = (text: string): Quantity => wasm.parseQuantity(text) as Quantity
export const compareQuantities = (a: string, b: string): -1 | 0 | 1 => wasm.compareQuantities(a, b) as -1 | 0 | 1
export const parseUnits = (text: string, decimals: number): Quantity => wasm.parseUnits(text, decimals) as Quantity
export const formatUnits = (quantity: string, decimals: number, maxFractionDigits = 6): string =>
  wasm.formatUnits(quantity, decimals, maxFractionDigits)
export const formatUnitsPlain = (quantity: string, decimals: number): string => wasm.formatUnitsPlain(quantity, decimals)
export const encodeFunctionCall = (signature: string, args: string[]): EncodedFunctionCall =>
  wasm.encodeFunctionCall(signature, args)
export const abiDecode = (types: string[], data: string): string[] => wasm.abiDecode(types, data)
export const decodeRevertReason = (data: string): string | undefined => wasm.decodeRevertReason(data)
export const isErc1271Success = (result: string): boolean => wasm.isErc1271Success(result)

// Keys and accounts
export const verifyRegistration = (
  attestationObject: Hex,
  credentialId: Hex,
  rpId: string,
  requireUserVerification: boolean,
): Registration => wasm.verifyRegistration(attestationObject, credentialId, rpId, requireUserVerification)
export const ownerBytes = (key: PublicKey): Hex => wasm.ownerBytes(key) as Hex
export const accountAddress = (initialOwners: Hex[]): Address => wasm.accountAddress(initialOwners) as Address
/** Checks a wallet record restored from a backup file; returns its checksummed address or throws a readable error. */
export const checkWalletRecord = (address: string, initialOwners: Hex[], keys: OwnerKey[]): Address =>
  wasm.checkWalletRecord(address, initialOwners, keys) as Address

// Calls
export const transferCall = (token: Address | undefined, to: string, amount: Quantity): Call =>
  wasm.transferCall(token, to, amount)
export const addOwnerCall = (account: Address, key: PublicKey): Call => wasm.addOwnerCall(account, key)

// User operations
export const buildUserOperation = (
  sender: Address,
  nonce: Quantity,
  deployed: boolean,
  initialOwners: Hex[],
  calls: Call[],
  gasPrice: GasPrice,
  signingOwnerIndex: number,
): UserOperation => wasm.buildUserOperation(sender, nonce, deployed, initialOwners, calls, gasPrice, signingOwnerIndex)
export const fallbackGasPrice = (baseFeePerGas: Quantity, maxPriorityFeePerGas: Quantity): GasPrice =>
  wasm.fallbackGasPrice(baseFeePerGas, maxPriorityFeePerGas)
export const applyGasEstimate = (op: UserOperation, estimate: GasEstimate, verificationGasBuffer: number): UserOperation =>
  wasm.applyGasEstimate(op, estimate, verificationGasBuffer)
/**
 * `newOwner` is only for the app's own add-key flow: the public key `verifyRegistration` just returned, when `op` adds
 * it as an owner. An operation that adds any other key is refused.
 */
export const reviewUserOperation = (
  op: UserOperation,
  chainId: number,
  tokens: Token[] = [],
  functionSignatures: string[] = [],
  newOwner?: PublicKey,
): OperationReview => wasm.reviewUserOperation(op, chainId, tokens, functionSignatures, newOwner)
export const userOperationHash = (op: UserOperation, chainId: number): Hex => wasm.userOperationHash(op, chainId) as Hex
/** Pass the same `newOwner` as to `reviewUserOperation`. */
export const signUserOperation = (
  op: UserOperation,
  chainId: number,
  assertion: Assertion,
  owners: OwnerKey[],
  initialOwners: Hex[],
  newOwner?: PublicKey,
): UserOperation => wasm.signUserOperation(op, chainId, assertion, owners, initialOwners, newOwner)

// Messages
export const messageChallenge = (message: string, account: Address, chainId: number): MessageChallenge =>
  wasm.messageChallenge(message, account, chainId)
export const signMessage = (
  message: string,
  account: Address,
  chainId: number,
  assertion: Assertion,
  owners: OwnerKey[],
  deployed: boolean,
  initialOwners: Hex[],
): SignedMessage => wasm.signMessage(message, account, chainId, assertion, owners, deployed, initialOwners)
