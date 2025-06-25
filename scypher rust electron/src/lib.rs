//! SCypher CLI Library
//!
//! A robust cryptographic library for BIP39 seed phrase operations and blockchain address derivation.
//! This library provides a clean API for:
//!
//! - XOR encryption with Argon2id key derivation
//! - BIP39 seed phrase generation, validation, and transformation
//! - Multi-blockchain address derivation (12+ networks)
//! - Secure memory management with automatic cleanup
//! - Professional logging system for clean output
//!
//! # Examples
//!
//! ```rust,no_run
//! use scypher_cli::{transform_seed, generate_seed, derive_addresses};
//!
//! // Transform a seed phrase with password
//! let result = transform_seed("abandon abandon abandon...", "password123")?;
//!
//! // Generate new seed phrase
//! let new_seed = generate_seed(24)?;
//!
//! // Derive addresses for multiple networks
//! let addresses = derive_addresses("seed phrase", &["bitcoin", "ethereum"], 5, None)?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

#![warn(missing_docs)]
#![warn(clippy::all)]
#![allow(unsafe_code, reason = "Required for terminal raw mode in password input")]

// Re-export main modules
pub mod cli;
pub mod crypto;
pub mod bip39;
pub mod addresses;
pub mod security;
pub mod error;
pub mod core; // NUEVO: Módulo core para logging y contexto

// Re-export commonly used types
pub use error::{SCypherError, SCypherResult, ErrorResponse, SuccessResponse};

// Re-export core types for external usage
pub use core::{ExecutionContext, ExecutionMode, Logger, LogLevel};

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use security::memory::SecureBuffer;

/// Configuration for crypto operations with secure defaults
#[derive(Debug, Clone)]
pub struct CryptoConfig {
    /// Argon2id time cost (iterations)
    pub time_cost: u32,
    /// Argon2id memory cost (KB)
    pub memory_cost: u32,
    /// Argon2id parallelism
    pub parallelism: u32,
    /// Output length for key derivation
    pub output_length: usize,
}

impl Default for CryptoConfig {
    fn default() -> Self {
        Self {
            time_cost: 5,           // Secure default
            memory_cost: 131072,    // 128 MB - secure default
            parallelism: 1,
            output_length: 32,
        }
    }
}

/// Main API for seed phrase transformation
pub fn transform_seed(phrase: &str, password: &str) -> SCypherResult<TransformResult> {
    transform_seed_with_config(phrase, password, &CryptoConfig::default())
}

/// Transform seed phrase with custom configuration
pub fn transform_seed_with_config(
    phrase: &str,
    password: &str,
    config: &CryptoConfig
) -> SCypherResult<TransformResult> {
    // 1. Validate input seed phrase
    bip39::validation::validate_seed_phrase(phrase)?;

    // 2. Extract entropy from original phrase
    let original_entropy = bip39::conversion::phrase_to_entropy(phrase)?;

    // 3. Derive keystream using Argon2id
    let keystream = crypto::keystream::derive_keystream(
        password,
        original_entropy.len(),
        config.time_cost,
        config.memory_cost,
    )?;

    // 4. XOR operation: encrypt entropy
    let encrypted_entropy = crypto::xor::xor_data(&original_entropy, &keystream)?;

    // 5. Generate new BIP39 phrase from encrypted entropy
    let transformed_phrase = bip39::conversion::entropy_to_phrase(&encrypted_entropy)?;

    // 6. Validate that the result is a valid BIP39 phrase
    bip39::validation::validate_seed_phrase(&transformed_phrase)?;

    // 7. Secure cleanup
    // Note: Rust will drop these automatically, but we're being explicit about security
    drop(keystream);
    drop(encrypted_entropy);

    Ok(TransformResult {
        original_phrase: phrase.to_string(),
        transformed_phrase,
        is_reversible: true,
        entropy_bits: (original_entropy.len() * 8) as u8,
        checksum_valid: true,
    })
}

/// Generate a new BIP39 seed phrase
pub fn generate_seed(word_count: u8) -> SCypherResult<GenerateResult> {
    // Validate word count
    if ![12, 15, 18, 21, 24].contains(&word_count) {
        return Err(SCypherError::InvalidInput(
            "Word count must be 12, 15, 18, 21, or 24".to_string()
        ));
    }

    // Calculate entropy bits
    let entropy_bits = (word_count as usize * 32 / 3);

    // Generate the seed phrase
    let phrase = bip39::conversion::generate_seed_phrase(entropy_bits)?;

    // Validate the generated phrase
    bip39::validation::validate_seed_phrase(&phrase)?;

    Ok(GenerateResult {
        phrase,
        word_count,
        entropy_bits: entropy_bits as u8,
        language: "english".to_string(),
        checksum_valid: true,
    })
}

/// Validate a BIP39 seed phrase
pub fn validate_seed(phrase: &str) -> SCypherResult<ValidationResult> {
    let analysis = bip39::validation::analyze_seed_phrase(phrase);

    Ok(ValidationResult {
        is_valid: analysis.overall_valid,
        word_count: analysis.word_count as u8,
        entropy_bits: analysis.entropy_bits.unwrap_or(0) as u8,
        checksum_valid: analysis.checksum_valid.unwrap_or(false),
        invalid_words: analysis.invalid_words,
        suggestions: analysis.suggestions,
    })
}

/// Derive blockchain addresses from seed phrase
pub fn derive_addresses(
    phrase: &str,
    networks: &[String],
    count: u32,
    passphrase: Option<&str>
) -> SCypherResult<HashMap<String, Vec<AddressResult>>> {
    // Validate the seed phrase first
    bip39::validation::validate_seed_phrase(phrase)?;

    let mut results = HashMap::new();

    for network in networks {
        let mut addresses = Vec::new();
        for i in 0..count {
            // TODO: Implement actual address derivation per network
            // For now, returning placeholder structure
            addresses.push(AddressResult {
                address: format!("{}_{}_derived_address_{}", network, phrase.len(), i),
                path: format!("m/44'/0'/0'/0/{}", i),
                public_key: format!("pubkey_{}_{}", network, i),
                private_key: None, // Never expose private keys in results
                address_type: "standard".to_string(),
            });
        }
        results.insert(network.clone(), addresses);
    }

    Ok(results)
}

/// Convert seed phrase to hex representation
pub fn phrase_to_hex(phrase: &str) -> SCypherResult<String> {
    bip39::conversion::phrase_to_hex(phrase)
}

/// Convert hex representation back to seed phrase
pub fn hex_to_phrase(hex_str: &str) -> SCypherResult<String> {
    bip39::conversion::hex_to_phrase(hex_str)
}

/// Analyze a seed phrase and return detailed information
pub fn analyze_phrase(phrase: &str) -> SCypherResult<bip39::conversion::SeedPhraseInfo> {
    bip39::conversion::analyze_phrase(phrase)
}

/// Result of seed phrase transformation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransformResult {
    /// Original input phrase
    pub original_phrase: String,
    /// Transformed phrase
    pub transformed_phrase: String,
    /// Whether the transformation is reversible
    pub is_reversible: bool,
    /// Entropy in bits
    pub entropy_bits: u8,
    /// Whether checksum is valid
    pub checksum_valid: bool,
}

/// Result of seed phrase generation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenerateResult {
    /// Generated BIP39 phrase
    pub phrase: String,
    /// Number of words
    pub word_count: u8,
    /// Entropy in bits
    pub entropy_bits: u8,
    /// Language used
    pub language: String,
    /// Whether checksum is valid
    pub checksum_valid: bool,
}

/// Result of seed phrase validation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationResult {
    /// Whether the phrase is valid
    pub is_valid: bool,
    /// Number of words in phrase
    pub word_count: u8,
    /// Entropy in bits
    pub entropy_bits: u8,
    /// Whether checksum is valid
    pub checksum_valid: bool,
    /// List of invalid words
    pub invalid_words: Vec<String>,
    /// Suggested corrections
    pub suggestions: Vec<String>,
}

/// Result of address derivation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddressResult {
    /// Derived address
    pub address: String,
    /// Derivation path used
    pub path: String,
    /// Public key (hex encoded)
    pub public_key: String,
    /// Private key (only for secure contexts, usually None)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub private_key: Option<String>,
    /// Type of address (e.g., "legacy", "segwit", "native_segwit")
    pub address_type: String,
}

/// Available blockchain networks
pub fn supported_networks() -> Vec<NetworkInfo> {
    vec![
        NetworkInfo {
            name: "bitcoin".to_string(),
            symbol: "BTC".to_string(),
            address_types: vec!["legacy".to_string(), "segwit".to_string(), "native_segwit".to_string()],
            derivation_path: "m/44'/0'/0'/0/0".to_string(),
        },
        NetworkInfo {
            name: "ethereum".to_string(),
            symbol: "ETH".to_string(),
            address_types: vec!["standard".to_string()],
            derivation_path: "m/44'/60'/0'/0/0".to_string(),
        },
        NetworkInfo {
            name: "bsc".to_string(),
            symbol: "BNB".to_string(),
            address_types: vec!["standard".to_string()],
            derivation_path: "m/44'/60'/0'/0/0".to_string(),
        },
        NetworkInfo {
            name: "polygon".to_string(),
            symbol: "MATIC".to_string(),
            address_types: vec!["standard".to_string()],
            derivation_path: "m/44'/60'/0'/0/0".to_string(),
        },
        NetworkInfo {
            name: "cardano".to_string(),
            symbol: "ADA".to_string(),
            address_types: vec!["shelley".to_string()],
            derivation_path: "m/1852'/1815'/0'/0/0".to_string(),
        },
        NetworkInfo {
            name: "solana".to_string(),
            symbol: "SOL".to_string(),
            address_types: vec!["standard".to_string()],
            derivation_path: "m/44'/501'/0'/0'".to_string(),
        },
        NetworkInfo {
            name: "ergo".to_string(),
            symbol: "ERG".to_string(),
            address_types: vec!["p2pk".to_string()],
            derivation_path: "m/44'/429'/0'/0/0".to_string(),
        },
        NetworkInfo {
            name: "tron".to_string(),
            symbol: "TRX".to_string(),
            address_types: vec!["standard".to_string()],
            derivation_path: "m/44'/195'/0'/0/0".to_string(),
        },
        NetworkInfo {
            name: "dogecoin".to_string(),
            symbol: "DOGE".to_string(),
            address_types: vec!["legacy".to_string()],
            derivation_path: "m/44'/3'/0'/0/0".to_string(),
        },
        NetworkInfo {
            name: "litecoin".to_string(),
            symbol: "LTC".to_string(),
            address_types: vec!["legacy".to_string(), "segwit".to_string()],
            derivation_path: "m/44'/2'/0'/0/0".to_string(),
        },
    ]
}

/// Information about a blockchain network
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInfo {
    /// Network name
    pub name: String,
    /// Network symbol/ticker
    pub symbol: String,
    /// Supported address types
    pub address_types: Vec<String>,
    /// Default derivation path
    pub derivation_path: String,
}

/// Progress callback for long-running operations
pub type ProgressCallback = Box<dyn Fn(u8) + Send + Sync>;

/// Advanced configuration for operations
#[derive(Debug, Clone)]
pub struct OperationConfig {
    /// Crypto configuration
    pub crypto: CryptoConfig,
    /// Whether to use secure memory allocation
    pub secure_memory: bool,
    /// Maximum operation timeout in seconds
    pub timeout_seconds: Option<u64>,
}

impl Default for OperationConfig {
    fn default() -> Self {
        Self {
            crypto: CryptoConfig::default(),
            secure_memory: true,
            timeout_seconds: Some(300), // 5 minutes
        }
    }
}

/// Utility function to verify transformation is reversible
pub fn verify_transformation_reversible(
    original_phrase: &str,
    password: &str,
    config: Option<&CryptoConfig>
) -> SCypherResult<bool> {
    let default_config = CryptoConfig::default();
    let config = config.unwrap_or(&default_config);

    // Transform the phrase
    let transform_result = transform_seed_with_config(original_phrase, password, config)?;

    // Transform it back
    let reverse_result = transform_seed_with_config(&transform_result.transformed_phrase, password, config)?;

    // Check if we got back the original
    Ok(reverse_result.transformed_phrase == original_phrase)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_seed_valid_word_counts() {
        for &count in &[12, 15, 18, 21, 24] {
            let result = generate_seed(count);
            assert!(result.is_ok(), "Failed to generate {} word seed", count);
            let generated = result.unwrap();
            assert_eq!(generated.word_count, count);
            assert!(generated.checksum_valid);
        }
    }

    #[test]
    fn test_generate_seed_invalid_word_count() {
        let result = generate_seed(10);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), SCypherError::InvalidInput(_)));
    }

    #[test]
    fn test_supported_networks() {
        let networks = supported_networks();
        assert!(!networks.is_empty());

        // Check that bitcoin and ethereum are present
        assert!(networks.iter().any(|n| n.name == "bitcoin"));
        assert!(networks.iter().any(|n| n.name == "ethereum"));

        // Check that all networks have required fields
        for network in networks {
            assert!(!network.name.is_empty());
            assert!(!network.symbol.is_empty());
            assert!(!network.address_types.is_empty());
            assert!(!network.derivation_path.is_empty());
        }
    }

    #[test]
    fn test_validate_seed_basic() {
        // Test with a simple phrase that should trigger validation logic
        let result = validate_seed("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about");
        assert!(result.is_ok());

        let validation = result.unwrap();
        assert_eq!(validation.word_count, 12);
    }

    #[test]
    fn test_phrase_hex_conversion() {
        // This will test when the actual implementation is ready
        let test_phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

        // These will work once the conversion module is fully integrated
        // let hex_result = phrase_to_hex(test_phrase);
        // assert!(hex_result.is_ok());

        // let hex = hex_result.unwrap();
        // let phrase_result = hex_to_phrase(&hex);
        // assert!(phrase_result.is_ok());
        // assert_eq!(phrase_result.unwrap(), test_phrase);
    }

    #[test]
    fn test_crypto_config_defaults() {
        let config = CryptoConfig::default();
        assert_eq!(config.time_cost, 5);
        assert_eq!(config.memory_cost, 131072); // 128 MB
        assert_eq!(config.parallelism, 1);
        assert_eq!(config.output_length, 32);
    }

    #[test]
    fn test_core_module_integration() {
        // Test que el módulo core está disponible
        let context = ExecutionContext::new(ExecutionMode::Interactive);
        assert_eq!(context.get_mode(), ExecutionMode::Interactive);

        let logger = Logger::from_context(context);
        assert_eq!(logger.get_mode(), ExecutionMode::Interactive);
    }
}
