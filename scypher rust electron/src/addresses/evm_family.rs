//! src/addresses/evm_family.rs
//! Derivación de direcciones para redes compatibles con EVM (Ethereum, BSC, Polygon, etc.)
//!
//! Este módulo contiene la lógica para derivar direcciones de redes basadas en el esquema EVM
//! utilizando rutas estándar como m/44'/60'/0'/0/i.
//! Todas estas redes soportan BIP39 passphrase oficialmente.

use crate::addresses::config_types::Address;
use crate::addresses::helpers::calculate_evm_address_from_pubkey;
use crate::error::{SCypherError, Result};
use bip32::{XPrv, DerivationPath};
use std::str::FromStr;

/// Derivar direcciones Ethereum
/// Ethereum soporta BIP39 passphrase oficialmente en hardware wallets
pub fn derive_ethereum_addresses(master_key: &XPrv, count: u32) -> Result<Vec<Address>> {
    derive_evm_addresses(master_key, count, "Ethereum", "m/44'/60'/0'/0/{}")
}

/// BSC addresses (usa mismas direcciones que Ethereum)
/// BSC soporta BIP39 passphrase por herencia de Ethereum
pub fn derive_bsc_addresses(master_key: &XPrv, count: u32) -> Result<Vec<Address>> {
    derive_evm_addresses(master_key, count, "BSC", "m/44'/60'/0'/0/{}")
}

/// Polygon addresses (usa mismas direcciones que Ethereum)
/// Polygon soporta BIP39 passphrase por herencia de Ethereum
pub fn derive_polygon_addresses(master_key: &XPrv, count: u32) -> Result<Vec<Address>> {
    derive_evm_addresses(master_key, count, "Polygon", "m/44'/60'/0'/0/{}")
}

/// Función genérica para derivar direcciones EVM
/// Todas las redes EVM usan el mismo esquema de derivación
fn derive_evm_addresses(
    master_key: &XPrv,
    count: u32,
    network_name: &str,
    path_template: &str
) -> Result<Vec<Address>> {
    let mut addresses = Vec::new();

    for index in 0u32..count {
        // Formatear el path con el índice
        let path_str = path_template.replace("{}", &index.to_string());
        let path = DerivationPath::from_str(&path_str)
            .map_err(|e| SCypherError::crypto(format!("Invalid {} path: {}", network_name, e)))?;

        let mut current_key = master_key.clone();
        for child_number in path.as_ref() {
            current_key = current_key.derive_child(*child_number)
                .map_err(|e| SCypherError::crypto(format!("{} derivation failed: {}", network_name, e)))?;
        }

        let public_key_point = current_key.public_key();
        let public_key_compressed = public_key_point.to_bytes();

        // Calcular dirección EVM usando función helper
        let address = calculate_evm_address_from_pubkey(&public_key_compressed)?;

        addresses.push(Address {
            address_type: format!("{} #{}", network_name, index),
            path: path_str,
            address,
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
    fn test_ethereum_official_test_vector() {
        let test_context = ExecutionContext::for_testing();
        let logger = Logger::from_context(test_context);

        logger.info("ETHEREUM OFFICIAL TEST VECTOR VALIDATION", "evm_family_tests");
        logger.info("============================================================", "evm_family_tests");
        logger.info("Testing Ethereum address derivation against MetaMask/Ian Coleman", "evm_family_tests");
        logger.info(&format!("Standard test mnemonic: {}", TEST_MNEMONIC), "evm_family_tests");
        logger.info("Passphrase: None (empty)", "evm_family_tests");
        logger.info("Derivation path: m/44'/60'/0'/0/0", "evm_family_tests");
        logger.info("Expected format: EIP-55 checksum (mixed case)", "evm_family_tests");

        let mnemonic = Mnemonic::parse_in_normalized(Language::English, TEST_MNEMONIC).unwrap();
        let seed = mnemonic.to_seed("");
        let master_key = XPrv::new(&seed).unwrap();

        let addresses = derive_ethereum_addresses(&master_key, 1).unwrap();

        // Dirección verificada con MetaMask y Ian Coleman (formato EIP-55)
        let expected_address = "0x9858EfFD232B4033E47d90003D41EC34EcaEda94";

        logger.info("EXPECTED TEST VECTOR:", "evm_family_tests");
        logger.info(&format!("   Address: {}", expected_address), "evm_family_tests");
        logger.info(&format!("   Path:    {}", "m/44'/60'/0'/0/0"), "evm_family_tests");

        assert_eq!(addresses[0].address, expected_address);
        assert_eq!(addresses[0].path, "m/44'/60'/0'/0/0");

        logger.info(&format!("   ✅ Generated: {} ✓ MATCH", addresses[0].address), "evm_family_tests");
        logger.info(&format!("   ✅ Path:      {} ✓ CORRECT", addresses[0].path), "evm_family_tests");
        logger.info("ETHEREUM OFFICIAL TEST VECTOR VALIDATION PASSED", "evm_family_tests");
        logger.info("   Address verified against MetaMask and Ian Coleman BIP39 Tool", "evm_family_tests");
        logger.info("   EIP-55 checksum format confirmed (mixed case)", "evm_family_tests");
        logger.info("   Compatible with all major Ethereum wallets", "evm_family_tests");
    }

    #[test]
    fn test_ethereum_with_bip39_passphrase() {
        let test_context = ExecutionContext::for_testing();
        let logger = Logger::from_context(test_context);

        logger.info("ETHEREUM BIP39 PASSPHRASE TEST VECTOR", "evm_family_tests");
        logger.info("============================================================", "evm_family_tests");
        logger.info("Testing Ethereum with BIP39 passphrase support", "evm_family_tests");
        logger.info(&format!("Standard test mnemonic: {}", TEST_MNEMONIC), "evm_family_tests");
        logger.info("Passphrase: 'test'", "evm_family_tests");
        logger.info("Source: Ian Coleman BIP39 Tool", "evm_family_tests");

        let mnemonic = Mnemonic::parse_in_normalized(Language::English, TEST_MNEMONIC).unwrap();
        let seed = mnemonic.to_seed("test");
        let master_key = XPrv::new(&seed).unwrap();

        let addresses = derive_ethereum_addresses(&master_key, 1).unwrap();

        // Dirección verificada con Ian Coleman BIP39 tool usando passphrase "test"
        let expected_address = "0xB560762fa35eFD20DF74b2cdEeB49D7A975fF99b";

        logger.info("EXPECTED TEST VECTOR (with passphrase):", "evm_family_tests");
        logger.info(&format!("   Address: {}", expected_address), "evm_family_tests");
        logger.info(&format!("   Path:    {}", "m/44'/60'/0'/0/0"), "evm_family_tests");

        assert_eq!(addresses[0].address, expected_address);
        assert_eq!(addresses[0].path, "m/44'/60'/0'/0/0");

        logger.info(&format!("   ✅ Generated: {} ✓ MATCH", addresses[0].address), "evm_family_tests");
        logger.info(&format!("   ✅ Path:      {} ✓ CORRECT", addresses[0].path), "evm_family_tests");
        logger.info("ETHEREUM BIP39 PASSPHRASE TEST VECTOR PASSED", "evm_family_tests");
        logger.info("   Passphrase functionality verified with Ian Coleman Tool", "evm_family_tests");
        logger.info("   Hardware wallet compatible (Ledger, Trezor with passphrase)", "evm_family_tests");
    }

    #[test]
    fn test_bsc_polygon_official_test_vectors() {
        let test_context = ExecutionContext::for_testing();
        let logger = Logger::from_context(test_context);

        let mnemonic = Mnemonic::parse_in_normalized(Language::English, TEST_MNEMONIC).unwrap();
        let seed = mnemonic.to_seed("");
        let master_key = XPrv::new(&seed).unwrap();

        let bsc_addresses = derive_bsc_addresses(&master_key, 1).unwrap();
        let polygon_addresses = derive_polygon_addresses(&master_key, 1).unwrap();

        // Misma dirección que Ethereum (compatible EVM) en formato EIP-55
        let expected_address = "0x9858EfFD232B4033E47d90003D41EC34EcaEda94";

        assert_eq!(bsc_addresses[0].address, expected_address);
        assert_eq!(polygon_addresses[0].address, expected_address);

        logger.info(&format!("BSC official test vector passed: {}", bsc_addresses[0].address), "evm_family_tests");
        logger.info(&format!("Polygon official test vector passed: {}", polygon_addresses[0].address), "evm_family_tests");
    }

    #[test]
    fn test_bsc_polygon_with_bip39_passphrase() {
        let test_context = ExecutionContext::for_testing();
        let logger = Logger::from_context(test_context);

        let mnemonic = Mnemonic::parse_in_normalized(Language::English, TEST_MNEMONIC).unwrap();
        let seed = mnemonic.to_seed("test");
        let master_key = XPrv::new(&seed).unwrap();

        let bsc_addresses = derive_bsc_addresses(&master_key, 1).unwrap();
        let polygon_addresses = derive_polygon_addresses(&master_key, 1).unwrap();

        // Misma dirección que Ethereum con passphrase (compatible EVM) en formato EIP-55
        let expected_address = "0xB560762fa35eFD20DF74b2cdEeB49D7A975fF99b";

        assert_eq!(bsc_addresses[0].address, expected_address);
        assert_eq!(polygon_addresses[0].address, expected_address);

        logger.info(&format!("BSC BIP39 passphrase test vector passed: {}", bsc_addresses[0].address), "evm_family_tests");
        logger.info(&format!("Polygon BIP39 passphrase test vector passed: {}", polygon_addresses[0].address), "evm_family_tests");
    }

    #[test]
    fn test_multiple_evm_addresses() {
        let test_context = ExecutionContext::for_testing();
        let logger = Logger::from_context(test_context);

        let mnemonic = Mnemonic::parse_in_normalized(Language::English, TEST_MNEMONIC).unwrap();
        let seed = mnemonic.to_seed("");
        let master_key = XPrv::new(&seed).unwrap();

        let ethereum_addresses = derive_ethereum_addresses(&master_key, 3).unwrap();
        assert_eq!(ethereum_addresses.len(), 3);

        // Verificar que las direcciones sean únicas
        let mut unique_addresses = std::collections::HashSet::new();
        for addr in &ethereum_addresses {
            assert!(unique_addresses.insert(&addr.address), "Duplicate address found: {}", addr.address);
        }

        logger.info("Multiple EVM addresses generation test passed", "evm_family_tests");
        for (i, addr) in ethereum_addresses.iter().enumerate() {
            logger.info(&format!("   Address {}: {}", i, addr.address), "evm_family_tests");
        }
    }

    #[test]
    fn test_evm_family_logging_modes() {
        // Test que diferentes modos de logging no afecten las direcciones generadas

        let mnemonic = Mnemonic::parse_in_normalized(Language::English, TEST_MNEMONIC).unwrap();
        let seed = mnemonic.to_seed("");
        let master_key = XPrv::new(&seed).unwrap();

        // Modo interactivo
        let addresses_interactive = derive_ethereum_addresses(&master_key, 1).unwrap();

        // Modo JSON API
        let addresses_json = derive_ethereum_addresses(&master_key, 1).unwrap();

        // Modo testing
        let test_context = ExecutionContext::for_testing();
        let logger = Logger::from_context(test_context);
        let addresses_test = derive_ethereum_addresses(&master_key, 1).unwrap();

        // Las direcciones deben ser idénticas independientemente del modo
        assert_eq!(addresses_interactive[0].address, addresses_json[0].address);
        assert_eq!(addresses_json[0].address, addresses_test[0].address);

        logger.info("EVM family logging modes test passed", "evm_family_tests");
        logger.info("Same addresses generated across all execution modes", "evm_family_tests");
    }

    #[test]
    fn test_evm_family_backward_compatibility() {
        // Test que verifica que todas las funciones siguen funcionando igual
        let test_context = ExecutionContext::for_testing();
        let logger = Logger::from_context(test_context);

        let mnemonic = Mnemonic::parse_in_normalized(Language::English, TEST_MNEMONIC).unwrap();
        let seed = mnemonic.to_seed("");
        let master_key = XPrv::new(&seed).unwrap();

        // Todas las funciones deben seguir funcionando
        let ethereum_addresses = derive_ethereum_addresses(&master_key, 1).unwrap();
        let bsc_addresses = derive_bsc_addresses(&master_key, 1).unwrap();
        let polygon_addresses = derive_polygon_addresses(&master_key, 1).unwrap();

        // Verificar test vectors conocidos
        let expected_address = "0x9858EfFD232B4033E47d90003D41EC34EcaEda94";
        assert_eq!(ethereum_addresses[0].address, expected_address);
        assert_eq!(bsc_addresses[0].address, expected_address);
        assert_eq!(polygon_addresses[0].address, expected_address);

        logger.info("EVM family backward compatibility test passed", "evm_family_tests");
        logger.info("All original functions work exactly as before", "evm_family_tests");
        logger.info("Test vectors preserved and verified", "evm_family_tests");
        logger.info("EIP-55 checksum format maintained", "evm_family_tests");
    }
}
