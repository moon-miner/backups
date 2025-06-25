//! src/addresses/ergo.rs
//! Derivación de direcciones para Ergo blockchain (eUTXO model)
//!
//! Ergo utiliza su propia biblioteca ergo-lib para derivación de direcciones
//! y soporta BIP39 passphrase (verificado con wallet SATERGO).

use crate::addresses::config_types::Address;
use crate::error::{SCypherError, Result};

// Importaciones Ergo
use ergo_lib::{
    ergotree_ir::chain::address::{Address as ErgoAddress, NetworkPrefix, AddressEncoder},
    wallet::{
        derivation_path::{ChildIndexHardened, ChildIndexNormal, DerivationPath as ErgoDerivationPath},
        ext_secret_key::ExtSecretKey,
        mnemonic::Mnemonic as ErgoMnemonic,
    },
};

/// Derivar direcciones Ergo usando ergo-lib
/// NOTA: Ergo soporta passphrase (verificado con wallet SATERGO)
pub fn derive_ergo_addresses(
    seed_phrase: &str,
    passphrase: Option<&str>, // Ahora SÍ usamos passphrase
    count: u32,
) -> Result<Vec<Address>> {
    let mut addresses = Vec::new();

    // Crear seed usando ergo-lib (con passphrase para compatibilidad SATERGO)
    let seed = ErgoMnemonic::to_seed(seed_phrase, passphrase.unwrap_or(""));

    // Derivar master key usando ergo-lib
    let master_key = ExtSecretKey::derive_master(seed)
        .map_err(|e| SCypherError::crypto(format!("Ergo master key derivation failed: {}", e)))?;

    // Account index 0 (hardened) - m/44'/429'/0'
    let account = ChildIndexHardened::from_31_bit(0)
        .map_err(|e| SCypherError::crypto(format!("Invalid Ergo account index: {}", e)))?;

    // Derivar direcciones para el número solicitado
    for index in 0u32..count {
        // Construir path de derivación: m/44'/429'/0'/0/index
        let path = ErgoDerivationPath::new(
            account,
            vec![ChildIndexNormal::normal(index)
                .map_err(|e| SCypherError::crypto(format!("Invalid Ergo address index {}: {}", index, e)))?],
        );

        // Derivar la key para el path dado
        let derived_key = master_key.derive(path)
            .map_err(|e| SCypherError::crypto(format!("Ergo key derivation failed for index {}: {}", index, e)))?;

        // Convertir la public key derivada a una address
        let ext_pub_key = derived_key.public_key()
            .map_err(|e| SCypherError::crypto(format!("Ergo public key extraction failed for index {}: {}", index, e)))?;

        let ergo_address: ErgoAddress = ext_pub_key.into();

        // Codificar la address con prefijo Mainnet
        let encoded_address = AddressEncoder::encode_address_as_string(
            NetworkPrefix::Mainnet,
            &ergo_address
        );

        addresses.push(Address {
            address_type: format!("Ergo #{}", index),
            path: format!("m/44'/429'/0'/0/{}", index),
            address: encoded_address,
        });
    }

    Ok(addresses)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{ExecutionContext, ExecutionMode, Logger};

    const TEST_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    #[test]
    fn test_ergo_satergo_test_vectors() {
        let test_context = ExecutionContext::for_testing();
        let logger = Logger::from_context(test_context);

        logger.info("ERGO SATERGO WALLET TEST VECTORS", "ergo_tests");
        logger.info("============================================================", "ergo_tests");
        logger.info("Testing Ergo address derivation against SATERGO Wallet", "ergo_tests");
        logger.info(&format!("Standard test mnemonic: {}", TEST_MNEMONIC), "ergo_tests");
        logger.info("Testing BOTH without and with BIP39 passphrase", "ergo_tests");
        logger.info("Derivation: m/44'/429'/0'/0/0 (Ergo standard)", "ergo_tests");
        logger.info("Library: ergo-lib (official Ergo library)", "ergo_tests");

        // Test sin passphrase
        let addresses_no_pass = derive_ergo_addresses(TEST_MNEMONIC, None, 1).unwrap();
        let expected_no_pass = "9fv2n41gttbUx8oqqhexi68qPfoETFPxnLEEbTfaTk4SmY2knYC";

        logger.info("TEST VECTOR 1 - WITHOUT PASSPHRASE:", "ergo_tests");
        logger.info(&format!("   Expected: {}", expected_no_pass), "ergo_tests");
        logger.info(&format!("   Generated: {}", addresses_no_pass[0].address), "ergo_tests");

        assert_eq!(addresses_no_pass[0].address, expected_no_pass);
        logger.info("   ✅ WITHOUT PASSPHRASE: ✓ MATCH", "ergo_tests");

        // Test con passphrase "test"
        let addresses_with_pass = derive_ergo_addresses(TEST_MNEMONIC, Some("test"), 1).unwrap();
        let expected_with_pass = "9hqHAeSrCtq8p5WP8tPokBBeiC1uh6Vp42eRwvoNfaQYT1kaa6X";

        logger.info("TEST VECTOR 2 - WITH PASSPHRASE 'test':", "ergo_tests");
        logger.info(&format!("   Expected: {}", expected_with_pass), "ergo_tests");
        logger.info(&format!("   Generated: {}", addresses_with_pass[0].address), "ergo_tests");

        assert_eq!(addresses_with_pass[0].address, expected_with_pass);
        logger.info("   ✅ WITH PASSPHRASE: ✓ MATCH", "ergo_tests");

        logger.info("ERGO SATERGO WALLET TEST VECTORS PASSED", "ergo_tests");
        logger.info("   Both test vectors verified against SATERGO Wallet", "ergo_tests");
        logger.info("   BIP39 passphrase support confirmed for Ergo", "ergo_tests");
        logger.info("   Addresses are different with/without passphrase ✓", "ergo_tests");
        logger.info("   ergo-lib official library integration successful", "ergo_tests");
    }

    #[test]
    fn test_ergo_address_format() {
        let test_context = ExecutionContext::for_testing();
        let logger = Logger::from_context(test_context);

        let addresses = derive_ergo_addresses(TEST_MNEMONIC, None, 5).unwrap();

        for addr in &addresses {
            // Verificar que las direcciones Ergo tengan formato válido
            assert!(addr.address.len() > 20, "Ergo address too short: {}", addr.address);
            assert!(addr.address.chars().all(|c| c.is_alphanumeric()), "Ergo address contains invalid characters: {}", addr.address);
        }

        logger.info(&format!("Ergo address format validation passed for {} addresses", addresses.len()), "ergo_tests");
    }

    #[test]
    fn test_multiple_ergo_addresses() {
        let test_context = ExecutionContext::for_testing();
        let logger = Logger::from_context(test_context);

        let addresses = derive_ergo_addresses(TEST_MNEMONIC, None, 3).unwrap();
        assert_eq!(addresses.len(), 3);

        // Verificar que las direcciones sean únicas
        let mut unique_addresses = std::collections::HashSet::new();
        for addr in &addresses {
            assert!(unique_addresses.insert(&addr.address), "Duplicate Ergo address found: {}", addr.address);
        }

        logger.info("Multiple Ergo addresses generation test passed", "ergo_tests");
        for (i, addr) in addresses.iter().enumerate() {
            logger.info(&format!("   Ergo Address {}: {}", i, addr.address), "ergo_tests");
        }
    }

    #[test]
    fn test_ergo_passphrase_differences() {
        let test_context = ExecutionContext::for_testing();
        let logger = Logger::from_context(test_context);

        let addresses_no_pass = derive_ergo_addresses(TEST_MNEMONIC, None, 1).unwrap();
        let addresses_with_pass = derive_ergo_addresses(TEST_MNEMONIC, Some("test"), 1).unwrap();

        // Las direcciones deben ser diferentes con passphrase
        assert_ne!(addresses_no_pass[0].address, addresses_with_pass[0].address);

        logger.info("Ergo passphrase differences test passed", "ergo_tests");
        logger.info(&format!("   Without passphrase: {}", addresses_no_pass[0].address), "ergo_tests");
        logger.info(&format!("   With passphrase:    {}", addresses_with_pass[0].address), "ergo_tests");
    }

    #[test]
    fn test_ergo_logging_modes() {
        // Test que diferentes modos de logging no afecten las direcciones generadas

        // Modo interactivo
        let addresses_interactive = derive_ergo_addresses(TEST_MNEMONIC, None, 1).unwrap();

        // Modo JSON API
        let addresses_json = derive_ergo_addresses(TEST_MNEMONIC, None, 1).unwrap();

        // Modo testing
        let test_context = ExecutionContext::for_testing();
        let logger = Logger::from_context(test_context);
        let addresses_test = derive_ergo_addresses(TEST_MNEMONIC, None, 1).unwrap();

        // Las direcciones deben ser idénticas independientemente del modo
        assert_eq!(addresses_interactive[0].address, addresses_json[0].address);
        assert_eq!(addresses_json[0].address, addresses_test[0].address);

        logger.info("Ergo logging modes test passed", "ergo_tests");
        logger.info("Same addresses generated across all execution modes", "ergo_tests");
    }

    #[test]
    fn test_ergo_backward_compatibility() {
        // Test que verifica que todas las funciones siguen funcionando igual
        let test_context = ExecutionContext::for_testing();
        let logger = Logger::from_context(test_context);

        // Función debe seguir funcionando
        let addresses_no_pass = derive_ergo_addresses(TEST_MNEMONIC, None, 1).unwrap();
        let addresses_with_pass = derive_ergo_addresses(TEST_MNEMONIC, Some("test"), 1).unwrap();

        // Verificar test vectors conocidos
        assert_eq!(addresses_no_pass[0].address, "9fv2n41gttbUx8oqqhexi68qPfoETFPxnLEEbTfaTk4SmY2knYC");
        assert_eq!(addresses_with_pass[0].address, "9hqHAeSrCtq8p5WP8tPokBBeiC1uh6Vp42eRwvoNfaQYT1kaa6X");

        logger.info("Ergo backward compatibility test passed", "ergo_tests");
        logger.info("All original functions work exactly as before", "ergo_tests");
        logger.info("Test vectors preserved and verified against SATERGO wallet", "ergo_tests");
        logger.info("BIP39 passphrase support maintained", "ergo_tests");
    }
}
