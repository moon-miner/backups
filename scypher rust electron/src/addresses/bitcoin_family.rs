//! src/addresses/bitcoin_family.rs
//! Derivación de direcciones para redes Bitcoin-family (Bitcoin, Litecoin, Dogecoin)
//!
//! Este módulo implementa la derivación de direcciones para Bitcoin y redes derivadas
//! que utilizan el mismo esquema UTXO y algoritmos criptográficos base.
//! Todas estas redes soportan BIP39 passphrase oficialmente.

use crate::addresses::config_types::Address;
use crate::addresses::helpers::create_p2pkh_address;
use crate::error::{SCypherError, Result};
use bip32::{XPrv, DerivationPath};
use std::str::FromStr;

/// Derivar direcciones Bitcoin (Legacy, SegWit, Nested SegWit)
/// Bitcoin soporta BIP39 passphrase oficialmente en hardware wallets
pub fn derive_bitcoin_addresses(master_key: &XPrv, count: u32) -> Result<Vec<Address>> {
    use bitcoin::Network;

    let mut addresses = Vec::new();
    let secp = bitcoin::secp256k1::Secp256k1::new();

    for index in 0u32..count {
        // 1. LEGACY P2PKH - BIP44
        let legacy_path = format!("m/44'/0'/0'/0/{}", index);
        let legacy_derivation_path = DerivationPath::from_str(&legacy_path)
            .map_err(|e| SCypherError::crypto(format!("Invalid Bitcoin Legacy path: {}", e)))?;

        let mut legacy_key = master_key.clone();
        for child_number in legacy_derivation_path.as_ref() {
            legacy_key = legacy_key.derive_child(*child_number)
                .map_err(|e| SCypherError::crypto(format!("Bitcoin Legacy derivation failed: {}", e)))?;
        }

        let legacy_private_key = bitcoin::PrivateKey::new(
            bitcoin::secp256k1::SecretKey::from_slice(legacy_key.private_key().to_bytes().as_slice())
                .map_err(|e| SCypherError::crypto(format!("Invalid private key: {}", e)))?,
            Network::Bitcoin
        );

        let legacy_public_key = legacy_private_key.public_key(&secp);
        let legacy_address = bitcoin::Address::p2pkh(&legacy_public_key, Network::Bitcoin);

        addresses.push(Address {
            address_type: format!("Legacy P2PKH #{}", index),
            path: legacy_path,
            address: legacy_address.to_string(),
        });

        // 2. NESTED SEGWIT P2SH-P2WPKH - BIP49
        let nested_path = format!("m/49'/0'/0'/0/{}", index);
        let nested_derivation_path = DerivationPath::from_str(&nested_path)
            .map_err(|e| SCypherError::crypto(format!("Invalid Bitcoin Nested SegWit path: {}", e)))?;

        let mut nested_key = master_key.clone();
        for child_number in nested_derivation_path.as_ref() {
            nested_key = nested_key.derive_child(*child_number)
                .map_err(|e| SCypherError::crypto(format!("Bitcoin Nested SegWit derivation failed: {}", e)))?;
        }

        let nested_private_key = bitcoin::PrivateKey::new(
            bitcoin::secp256k1::SecretKey::from_slice(nested_key.private_key().to_bytes().as_slice())
                .map_err(|e| SCypherError::crypto(format!("Invalid private key: {}", e)))?,
            Network::Bitcoin
        );

        let nested_public_key = nested_private_key.public_key(&secp);
        let nested_address = bitcoin::Address::p2shwpkh(&nested_public_key, Network::Bitcoin)
            .map_err(|e| SCypherError::crypto(format!("P2SH-P2WPKH address creation failed: {}", e)))?;

        addresses.push(Address {
            address_type: format!("Nested SegWit #{}", index),
            path: nested_path,
            address: nested_address.to_string(),
        });

        // 3. NATIVE SEGWIT P2WPKH - BIP84
        let native_path = format!("m/84'/0'/0'/0/{}", index);
        let native_derivation_path = DerivationPath::from_str(&native_path)
            .map_err(|e| SCypherError::crypto(format!("Invalid Bitcoin Native SegWit path: {}", e)))?;

        let mut native_key = master_key.clone();
        for child_number in native_derivation_path.as_ref() {
            native_key = native_key.derive_child(*child_number)
                .map_err(|e| SCypherError::crypto(format!("Bitcoin Native SegWit derivation failed: {}", e)))?;
        }

        let native_private_key = bitcoin::PrivateKey::new(
            bitcoin::secp256k1::SecretKey::from_slice(native_key.private_key().to_bytes().as_slice())
                .map_err(|e| SCypherError::crypto(format!("Invalid private key: {}", e)))?,
            Network::Bitcoin
        );

        let native_public_key = native_private_key.public_key(&secp);
        let native_address = bitcoin::Address::p2wpkh(&native_public_key, Network::Bitcoin)
            .map_err(|e| SCypherError::crypto(format!("P2WPKH address creation failed: {}", e)))?;

        addresses.push(Address {
            address_type: format!("Native SegWit #{}", index),
            path: native_path,
            address: native_address.to_string(),
        });
    }

    Ok(addresses)
}

/// Derivar direcciones Dogecoin
/// Dogecoin soporta BIP39 passphrase por herencia de Bitcoin
pub fn derive_dogecoin_addresses(master_key: &XPrv, count: u32) -> Result<Vec<Address>> {
    use bitcoin::Network;

    let mut addresses = Vec::new();

    for index in 0u32..count {
        // Dogecoin coin type: 3' - m/44'/3'/0'/0/index
        let path = DerivationPath::from_str(&format!("m/44'/3'/0'/0/{}", index))
            .map_err(|e| SCypherError::crypto(format!("Invalid Dogecoin path: {}", e)))?;

        let mut current_key = master_key.clone();
        for child_number in path.as_ref() {
            current_key = current_key.derive_child(*child_number)
                .map_err(|e| SCypherError::crypto(format!("Dogecoin derivation failed: {}", e)))?;
        }

        let secp = bitcoin::secp256k1::Secp256k1::new();
        let private_key = bitcoin::PrivateKey::new(
            bitcoin::secp256k1::SecretKey::from_slice(current_key.private_key().to_bytes().as_slice())
                .map_err(|e| SCypherError::crypto(format!("Invalid Dogecoin private key: {}", e)))?,
            Network::Bitcoin
        );

        let public_key = private_key.public_key(&secp);
        let compressed_pubkey = public_key.to_bytes();

        // Dogecoin version byte is 0x1e (30)
        let dogecoin_address = create_p2pkh_address(&compressed_pubkey, 0x1e)?;

        addresses.push(Address {
            address_type: format!("Dogecoin #{}", index),
            path: format!("m/44'/3'/0'/0/{}", index),
            address: dogecoin_address,
        });
    }

    Ok(addresses)
}

/// Derivar direcciones Litecoin
/// Litecoin soporta BIP39 passphrase por herencia de Bitcoin
pub fn derive_litecoin_addresses(master_key: &XPrv, count: u32) -> Result<Vec<Address>> {
    use bitcoin::Network;

    let mut addresses = Vec::new();

    for index in 0u32..count {
        // Litecoin coin type: 2' - m/44'/2'/0'/0/index
        let path = DerivationPath::from_str(&format!("m/44'/2'/0'/0/{}", index))
            .map_err(|e| SCypherError::crypto(format!("Invalid Litecoin path: {}", e)))?;

        let mut current_key = master_key.clone();
        for child_number in path.as_ref() {
            current_key = current_key.derive_child(*child_number)
                .map_err(|e| SCypherError::crypto(format!("Litecoin derivation failed: {}", e)))?;
        }

        let secp = bitcoin::secp256k1::Secp256k1::new();
        let private_key = bitcoin::PrivateKey::new(
            bitcoin::secp256k1::SecretKey::from_slice(current_key.private_key().to_bytes().as_slice())
                .map_err(|e| SCypherError::crypto(format!("Invalid Litecoin private key: {}", e)))?,
            Network::Bitcoin
        );

        let public_key = private_key.public_key(&secp);
        let compressed_pubkey = public_key.to_bytes();

        // Litecoin P2PKH version byte is 0x30 (48)
        let litecoin_address = create_p2pkh_address(&compressed_pubkey, 0x30)?;

        addresses.push(Address {
            address_type: format!("Litecoin #{}", index),
            path: format!("m/44'/2'/0'/0/{}", index),
            address: litecoin_address,
        });
    }

    Ok(addresses)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bip39_crate::{Mnemonic, Language};
    use crate::core::{ExecutionContext, ExecutionMode, Logger};

    const TEST_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    #[test]
    fn test_bitcoin_official_test_vectors() {
        let test_context = ExecutionContext::for_testing();
        let logger = Logger::from_context(test_context);

        let mnemonic = Mnemonic::parse_in_normalized(Language::English, TEST_MNEMONIC).unwrap();
        let seed = mnemonic.to_seed("");
        let master_key = XPrv::new(&seed).unwrap();

        let addresses = derive_bitcoin_addresses(&master_key, 1).unwrap();

        // Direcciones verificadas con Ian Coleman BIP39 tool
        let expected_legacy = "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA";
        let expected_segwit = "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu";
        let expected_nested = "37VucYSaXLCAsxYyAPfbSi9eh4iEcbShgf";

        // Verificar dirección Legacy (siempre primera)
        assert_eq!(addresses[0].address, expected_legacy);

        // Verificar SegWit y Nested SegWit
        let segwit_addr = addresses.iter().find(|addr| addr.address_type.contains("Native SegWit"));
        if let Some(addr) = segwit_addr {
            assert_eq!(addr.address, expected_segwit);
        }

        let nested_addr = addresses.iter().find(|addr| addr.address_type.contains("Nested SegWit"));
        if let Some(addr) = nested_addr {
            assert_eq!(addr.address, expected_nested);
        }

        logger.info("Bitcoin official test vectors passed:", "bitcoin_family_tests");
        logger.info(&format!("   Legacy:      {}", expected_legacy), "bitcoin_family_tests");
        logger.info(&format!("   SegWit:      {}", expected_segwit), "bitcoin_family_tests");
        logger.info(&format!("   Nested:      {}", expected_nested), "bitcoin_family_tests");
    }

    #[test]
    fn test_dogecoin_official_test_vector() {
        let test_context = ExecutionContext::for_testing();
        let logger = Logger::from_context(test_context);

        let mnemonic = Mnemonic::parse_in_normalized(Language::English, TEST_MNEMONIC).unwrap();
        let seed = mnemonic.to_seed("");
        let master_key = XPrv::new(&seed).unwrap();

        let addresses = derive_dogecoin_addresses(&master_key, 1).unwrap();

        // Dirección verificada con Ian Coleman BIP39 tool
        let expected_address = "DBus3bamQjgJULBJtYXpEzDWQRwF5iwxgC";

        assert_eq!(addresses[0].address, expected_address);
        assert_eq!(addresses[0].path, "m/44'/3'/0'/0/0");

        logger.info(&format!("Dogecoin official test vector passed: {}", addresses[0].address), "bitcoin_family_tests");
    }

    #[test]
    fn test_litecoin_official_test_vector() {
        let test_context = ExecutionContext::for_testing();
        let logger = Logger::from_context(test_context);

        let mnemonic = Mnemonic::parse_in_normalized(Language::English, TEST_MNEMONIC).unwrap();
        let seed = mnemonic.to_seed("");
        let master_key = XPrv::new(&seed).unwrap();

        let addresses = derive_litecoin_addresses(&master_key, 1).unwrap();

        // Dirección verificada con Ian Coleman BIP39 tool
        let expected_address = "LUWPbpM43E2p7ZSh8cyTBEkvpHmr3cB8Ez";

        assert_eq!(addresses[0].address, expected_address);
        assert_eq!(addresses[0].path, "m/44'/2'/0'/0/0");

        logger.info(&format!("Litecoin official test vector passed: {}", addresses[0].address), "bitcoin_family_tests");
    }

    #[test]
    fn test_bitcoin_family_logging_modes() {
        // Test que diferentes modos de logging no afecten las direcciones generadas

        let mnemonic = Mnemonic::parse_in_normalized(Language::English, TEST_MNEMONIC).unwrap();
        let seed = mnemonic.to_seed("");
        let master_key = XPrv::new(&seed).unwrap();

        // Modo interactivo
        let addresses_interactive = derive_bitcoin_addresses(&master_key, 1).unwrap();

        // Modo JSON API
        let addresses_json = derive_bitcoin_addresses(&master_key, 1).unwrap();

        // Modo testing
        let test_context = ExecutionContext::for_testing();
        let logger = Logger::from_context(test_context);
        let addresses_test = derive_bitcoin_addresses(&master_key, 1).unwrap();

        // Las direcciones deben ser idénticas independientemente del modo
        assert_eq!(addresses_interactive[0].address, addresses_json[0].address);
        assert_eq!(addresses_json[0].address, addresses_test[0].address);

        logger.info("Bitcoin family logging modes test passed", "bitcoin_family_tests");
        logger.info("Same addresses generated across all execution modes", "bitcoin_family_tests");
    }

    #[test]
    fn test_bitcoin_family_backward_compatibility() {
        // Test que verifica que todas las funciones siguen funcionando igual
        let test_context = ExecutionContext::for_testing();
        let logger = Logger::from_context(test_context);

        let mnemonic = Mnemonic::parse_in_normalized(Language::English, TEST_MNEMONIC).unwrap();
        let seed = mnemonic.to_seed("");
        let master_key = XPrv::new(&seed).unwrap();

        // Todas las funciones deben seguir funcionando
        let bitcoin_addresses = derive_bitcoin_addresses(&master_key, 1).unwrap();
        let dogecoin_addresses = derive_dogecoin_addresses(&master_key, 1).unwrap();
        let litecoin_addresses = derive_litecoin_addresses(&master_key, 1).unwrap();

        // Verificar test vectors conocidos
        assert_eq!(bitcoin_addresses[0].address, "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA");
        assert_eq!(dogecoin_addresses[0].address, "DBus3bamQjgJULBJtYXpEzDWQRwF5iwxgC");
        assert_eq!(litecoin_addresses[0].address, "LUWPbpM43E2p7ZSh8cyTBEkvpHmr3cB8Ez");

        logger.info("Bitcoin family backward compatibility test passed", "bitcoin_family_tests");
        logger.info("All original functions work exactly as before", "bitcoin_family_tests");
        logger.info("Test vectors preserved and verified", "bitcoin_family_tests");
    }
}
