//! Supported networks.

use crate::records::{ChainConfig, Token};

fn token(address: &str, symbol: &str, name: &str, decimals: u8) -> Token {
    Token { address: address.into(), symbol: symbol.into(), name: name.into(), decimals }
}

pub fn all() -> Vec<ChainConfig> {
    vec![
        ChainConfig {
            id: 84532,
            name: "Base Sepolia".into(),
            is_testnet: true,
            rpc_url: "https://sepolia.base.org".into(),
            default_bundler_url: "https://public.pimlico.io/v2/84532/rpc".into(),
            explorer_url: "https://sepolia.basescan.org".into(),
            blockscout_url: Some("https://base-sepolia.blockscout.com".into()),
            known_tokens: vec![
                token("0x036CbD53842c5426634e7929541eC2318f3dCF7e", "USDC", "USD Coin", 6),
                token("0x4200000000000000000000000000000000000006", "WETH", "Wrapped Ether", 18),
            ],
            verification_gas_buffer: 30_000,
            known_paymasters: vec![],
        },
        ChainConfig {
            id: 8453,
            name: "Base".into(),
            is_testnet: false,
            rpc_url: "https://mainnet.base.org".into(),
            default_bundler_url: "https://public.pimlico.io/v2/8453/rpc".into(),
            explorer_url: "https://basescan.org".into(),
            blockscout_url: Some("https://base.blockscout.com".into()),
            known_tokens: vec![
                token("0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", "USDC", "USD Coin", 6),
                token("0x4200000000000000000000000000000000000006", "WETH", "Wrapped Ether", 18),
                token("0xcbB7C0000aB88B473b1f5aFd9ef808440eed33Bf", "cbBTC", "Coinbase Wrapped BTC", 8),
            ],
            verification_gas_buffer: 30_000,
            known_paymasters: vec![],
        },
    ]
}

#[cfg(test)]
mod tests {
    #[test]
    fn token_addresses_are_checksummed() {
        for chain in super::all() {
            for token in chain.known_tokens {
                let bytes = crate::address::parse(&token.address).unwrap();
                assert_eq!(crate::address::checksum(&bytes), token.address);
            }
        }
    }
}
