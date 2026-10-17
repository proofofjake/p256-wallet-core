//! ERC-4337 EntryPoint v0.6 user operations.

use crate::abi::{self, Token};
use crate::error::{invalid, Result};
use crate::hash::keccak256;
use crate::smart_wallet::ENTRY_POINT_V06;
use ruint::aliases::U256;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct UserOperation {
    pub sender: [u8; 20],
    pub nonce: U256,
    pub init_code: Vec<u8>,
    pub call_data: Vec<u8>,
    pub call_gas_limit: U256,
    pub verification_gas_limit: U256,
    pub pre_verification_gas: U256,
    pub max_fee_per_gas: U256,
    pub max_priority_fee_per_gas: U256,
    pub paymaster_and_data: Vec<u8>,
    pub signature: Vec<u8>,
}

impl UserOperation {
    /// `EntryPoint.getUserOpHash(op)`: the 32 bytes the owner key signs. Covers every field except the signature,
    /// plus the EntryPoint and chain, so a signed operation can't be replayed elsewhere.
    pub fn hash(&self, chain_id: u64) -> [u8; 32] {
        let packed = abi::encode(&[
            Token::Address(self.sender),
            Token::Uint(self.nonce),
            Token::FixedBytes(keccak256(&self.init_code).to_vec()),
            Token::FixedBytes(keccak256(&self.call_data).to_vec()),
            Token::Uint(self.call_gas_limit),
            Token::Uint(self.verification_gas_limit),
            Token::Uint(self.pre_verification_gas),
            Token::Uint(self.max_fee_per_gas),
            Token::Uint(self.max_priority_fee_per_gas),
            Token::FixedBytes(keccak256(&self.paymaster_and_data).to_vec()),
        ]);
        keccak256(abi::encode(&[
            Token::FixedBytes(keccak256(packed).to_vec()),
            Token::Address(ENTRY_POINT_V06),
            Token::Uint(U256::from(chain_id)),
        ]))
    }

    /// The most this operation can cost whoever pays for gas, in wei:
    /// `(callGasLimit + verificationGasLimit + preVerificationGas) * maxFeePerGas`.
    pub fn max_cost(&self) -> Result<U256> {
        self.call_gas_limit
            .checked_add(self.verification_gas_limit)
            .and_then(|gas| gas.checked_add(self.pre_verification_gas))
            .and_then(|gas| gas.checked_mul(self.max_fee_per_gas))
            .ok_or_else(|| invalid("Gas values are too large"))
    }

    /// Applies a bundler's gas estimate with headroom: `preVerificationGas` +10%, `callGasLimit` +20%, and
    /// `verificationGasBuffer` extra verification gas. The estimate ran with a placeholder signature that fails
    /// before the P-256 check, so it never paid for verifying a real one.
    pub fn apply_gas_estimate(
        &mut self,
        pre_verification_gas: U256,
        verification_gas_limit: U256,
        call_gas_limit: U256,
        verification_gas_buffer: u64,
    ) -> Result<()> {
        let too_large = || invalid("Bundler returned an implausibly large gas estimate");
        let scale = |value: U256, percent: u64| {
            value.checked_mul(U256::from(percent)).map(|v| v / U256::from(100)).ok_or_else(too_large)
        };
        self.pre_verification_gas = scale(pre_verification_gas, 110)?;
        self.call_gas_limit = scale(call_gas_limit, 120)?;
        self.verification_gas_limit =
            verification_gas_limit.checked_add(U256::from(verification_gas_buffer)).ok_or_else(too_large)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hex::encode as to_hex;

    pub fn sample() -> UserOperation {
        UserOperation {
            sender: [0x12; 20],
            nonce: U256::from(5),
            init_code: vec![1, 2, 3],
            call_data: vec![4, 5, 6],
            call_gas_limit: U256::from(100_000),
            verification_gas_limit: U256::from(3_000_000),
            pre_verification_gas: U256::from(100_000),
            max_fee_per_gas: U256::from(1_000_000),
            max_priority_fee_per_gas: U256::from(1000),
            paymaster_and_data: vec![7, 8, 9],
            signature: vec![0xaa; 10],
        }
    }

    #[test]
    fn hash_matches_entry_point() {
        // EntryPoint(0x5FF1…2789).getUserOpHash(sample()) on Base Sepolia via cast call.
        assert_eq!(to_hex(&sample().hash(84532)), "0xac595c699677356d4f2939f8839448333e3730e076245cd8180d31834183b214");
        // The signature isn't part of the hash.
        let mut unsigned = sample();
        unsigned.signature.clear();
        assert_eq!(unsigned.hash(84532), sample().hash(84532));
        assert_ne!(sample().hash(8453), sample().hash(84532));
    }

    #[test]
    fn max_cost_and_overflow() {
        assert_eq!(sample().max_cost().unwrap(), U256::from(3_200_000u64 * 1_000_000));
        let mut huge = sample();
        huge.max_fee_per_gas = U256::MAX;
        assert!(huge.max_cost().is_err());
    }

    #[test]
    fn gas_headroom() {
        let mut op = sample();
        op.apply_gas_estimate(U256::from(50_000), U256::from(400_000), U256::from(10_000), 30_000).unwrap();
        assert_eq!(op.pre_verification_gas, U256::from(55_000));
        assert_eq!(op.verification_gas_limit, U256::from(430_000));
        assert_eq!(op.call_gas_limit, U256::from(12_000));
        assert!(op.apply_gas_estimate(U256::MAX, U256::ZERO, U256::ZERO, 0).is_err());
    }
}
