//! Supported networks, as static data. `by_id` looks one up without building the others; `all` builds the records
//! the apps receive.

use crate::address::checksum;
use crate::records::{ChainConfig, KnownContract, Token};

pub struct Chain {
    pub id: u64,
    pub name: &'static str,
    pub is_testnet: bool,
    pub rpc_url: &'static str,
    pub default_bundler_url: &'static str,
    pub explorer_url: &'static str,
    pub blockscout_url: Option<&'static str>,
    pub known_tokens: &'static [KnownToken],
    pub verification_gas_buffer: u64,
    /// Reviewed as pure sponsors: see `ChainConfig::known_paymasters`.
    pub known_paymasters: &'static [KnownPaymaster],
}

pub struct KnownToken {
    /// EIP-55 checksummed.
    pub address: &'static str,
    pub symbol: &'static str,
    pub name: &'static str,
    pub decimals: u8,
}

pub struct KnownPaymaster {
    pub address: [u8; 20],
    pub name: &'static str,
}

const fn token(address: &'static str, symbol: &'static str, name: &'static str, decimals: u8) -> KnownToken {
    KnownToken { address, symbol, name, decimals }
}

pub static CHAINS: [Chain; 2] = [
    Chain {
        id: 84532,
        name: "Base Sepolia",
        is_testnet: true,
        rpc_url: "https://sepolia.base.org",
        default_bundler_url: "https://public.pimlico.io/v2/84532/rpc",
        explorer_url: "https://sepolia.basescan.org",
        blockscout_url: Some("https://base-sepolia.blockscout.com"),
        known_tokens: &[
            token("0x036CbD53842c5426634e7929541eC2318f3dCF7e", "USDC", "USD Coin", 6),
            token("0x4200000000000000000000000000000000000006", "WETH", "Wrapped Ether", 18),
        ],
        verification_gas_buffer: 30_000,
        known_paymasters: &[],
    },
    Chain {
        id: 8453,
        name: "Base",
        is_testnet: false,
        rpc_url: "https://mainnet.base.org",
        default_bundler_url: "https://public.pimlico.io/v2/8453/rpc",
        explorer_url: "https://basescan.org",
        blockscout_url: Some("https://base.blockscout.com"),
        known_tokens: &[
            token("0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", "USDC", "USD Coin", 6),
            token("0x4200000000000000000000000000000000000006", "WETH", "Wrapped Ether", 18),
            token("0xcbB7C0000aB88B473b1f5aFd9ef808440eed33Bf", "cbBTC", "Coinbase Wrapped BTC", 8),
        ],
        verification_gas_buffer: 30_000,
        known_paymasters: &[],
    },
];

pub fn by_id(id: u64) -> Option<&'static Chain> {
    CHAINS.iter().find(|chain| chain.id == id)
}

pub fn all() -> Vec<ChainConfig> {
    CHAINS.iter().map(Chain::config).collect()
}

impl Chain {
    /// The paymaster at `address`, if it's one of this chain's known sponsors.
    pub fn known_paymaster(&self, address: [u8; 20]) -> Option<&KnownPaymaster> {
        self.known_paymasters.iter().find(|known| known.address == address)
    }

    pub fn config(&self) -> ChainConfig {
        ChainConfig {
            id: self.id,
            name: self.name.into(),
            is_testnet: self.is_testnet,
            rpc_url: self.rpc_url.into(),
            default_bundler_url: self.default_bundler_url.into(),
            explorer_url: self.explorer_url.into(),
            blockscout_url: self.blockscout_url.map(Into::into),
            known_tokens: self
                .known_tokens
                .iter()
                .map(|t| Token {
                    address: t.address.into(),
                    symbol: t.symbol.into(),
                    name: t.name.into(),
                    decimals: t.decimals,
                })
                .collect(),
            verification_gas_buffer: self.verification_gas_buffer,
            known_paymasters: self
                .known_paymasters
                .iter()
                .map(|k| KnownContract { address: checksum(&k.address), name: k.name.into() })
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn token_addresses_are_checksummed() {
        for chain in &super::CHAINS {
            for token in chain.known_tokens {
                let bytes = crate::address::parse(token.address).unwrap();
                assert_eq!(crate::address::checksum(&bytes), token.address);
            }
        }
    }

    #[test]
    fn lookup() {
        assert_eq!(super::by_id(8453).unwrap().name, "Base");
        assert!(super::by_id(1).is_none());
        assert_eq!(super::all().len(), super::CHAINS.len());
    }
}
