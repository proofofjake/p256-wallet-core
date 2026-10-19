//! Every function signature the core encodes or recognizes, in one place. Selectors are `abi::selector` of these.

// Coinbase Smart Wallet and its factory.
pub const EXECUTE: &str = "execute(address,uint256,bytes)";
pub const EXECUTE_BATCH: &str = "executeBatch((address,uint256,bytes)[])";
pub const CREATE_ACCOUNT: &str = "createAccount(bytes[],uint256)";
pub const ADD_OWNER_PUBLIC_KEY: &str = "addOwnerPublicKey(bytes32,bytes32)";
pub const ADD_OWNER_ADDRESS: &str = "addOwnerAddress(address)";
pub const REMOVE_OWNER_AT_INDEX: &str = "removeOwnerAtIndex(uint256,bytes)";
pub const REMOVE_LAST_OWNER: &str = "removeLastOwner(uint256,bytes)";
pub const UPGRADE_TO_AND_CALL: &str = "upgradeToAndCall(address,bytes)";

// Tokens. ERC-20 and ERC-721 share `approve` and `transferFrom`; ERC-721 and ERC-1155 share `setApprovalForAll`.
pub const TRANSFER: &str = "transfer(address,uint256)";
pub const APPROVE: &str = "approve(address,uint256)";
pub const INCREASE_ALLOWANCE: &str = "increaseAllowance(address,uint256)";
pub const TRANSFER_FROM: &str = "transferFrom(address,address,uint256)";
pub const SAFE_TRANSFER_FROM: &str = "safeTransferFrom(address,address,uint256)";
pub const SAFE_TRANSFER_FROM_WITH_DATA: &str = "safeTransferFrom(address,address,uint256,bytes)";
pub const SAFE_TRANSFER_FROM_ERC1155: &str = "safeTransferFrom(address,address,uint256,uint256,bytes)";
pub const SET_APPROVAL_FOR_ALL: &str = "setApprovalForAll(address,bool)";
/// Uniswap Permit2's `AllowanceTransfer.approve(token, spender, amount, expiration)`.
pub const PERMIT2_APPROVE: &str = "approve(address,address,uint160,uint48)";

// Solidity reverts.
pub const ERROR: &str = "Error(string)";
pub const PANIC: &str = "Panic(uint256)";
