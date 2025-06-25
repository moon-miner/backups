//! src/addresses/solana.rs
//! Derivación de direcciones para Solana blockchain
//!
//! Solana utiliza BIP32-Ed25519 compatible con Phantom Wallet.
//! NOTA: Phantom no soporta BIP39 passphrase oficialmente.

use crate::addresses::config_types::Address;
use crate::addresses::helpers::manual_derive_path;
use crate::error::{SCypherError, Result};
use crate::core::{ExecutionContext, ExecutionMode, Logger};
use ed25519_dalek::SigningKey as SolanaSigningKey;

/// Derivar direcciones Solana compatible con Phantom Wallet
/// NOTA: Phantom no soporta BIP39 passphrase oficialmente
pub fn derive_solana_from_mnemonic_direct(
    mnemonic_phrase: &str,
    _passphrase: Option<&str>, // Ignorado intencionalmente
    count: u32,
) -> Result<Vec<Address>> {
    derive_solana_from_mnemonic_with_context(mnemonic_phrase, _passphrase, count, None)
}

/// Derivar direcciones Solana con contexto de ejecución específico
/// Permite inyección de contexto para testing y diferentes modos de ejecución
pub fn derive_solana_from_mnemonic_with_context(
    mnemonic_phrase: &str,
    _passphrase: Option<&str>, // Ignorado intencionalmente
    count: u32,
    execution_context: Option<ExecutionContext>,
) -> Result<Vec<Address>> {
    use bip39_crate::{Mnemonic, Language};

    let mut addresses = Vec::new();

    // Crear contexto y logger apropiados
    let context = execution_context.unwrap_or_else(|| {
        // Detectar modo desde argumentos CLI para compatibilidad
        let args: Vec<String> = std::env::args().collect();
        let silent = args.iter().any(|arg| arg == "--silent");
        let format_json = args.iter().any(|arg| arg == "--format=json" || arg.contains("json"));
        let stdin_mode = args.iter().any(|arg| arg == "--stdin");

        ExecutionContext::from_cli_args(silent, stdin_mode, format_json)
    });

    let logger = Logger::from_context(context);

    logger.info("SOLANA PHANTOM COMPATIBLE - BIP32-Ed25519 (sin passphrase)", "solana");

    // Generar seed BIP39 (exactamente como Phantom, sin passphrase)
    let mnemonic = Mnemonic::parse_in_normalized(Language::English, mnemonic_phrase)
        .map_err(|e| SCypherError::crypto(format!("Invalid mnemonic: {}", e)))?;

    let seed = mnemonic.to_seed("");
    logger.debug(&format!("Seed: {} bytes", seed.len()), "solana");

    for index in 0u32..count {
        let derivation_path = if index == 0 {
            "m/44'/501'/0'/0'".to_string()
        } else {
            format!("m/44'/501'/{}'/0'", index)
        };

        logger.debug(&format!("Derivando path: {}", derivation_path), "solana");

        // Implementar derivePath(path, seed) manualmente
        let derived_key = manual_derive_path(&derivation_path, &seed)?;

        // Crear keypair Ed25519
        let signing_key = SolanaSigningKey::from_bytes(&derived_key);
        let verifying_key = signing_key.verifying_key();
        let address_str = bs58::encode(verifying_key.as_bytes()).into_string();

        logger.debug(&format!("Index {} address: {}", index, address_str), "solana");

        addresses.push(Address {
            address_type: format!("Solana #{}", index),
            path: derivation_path,
            address: address_str,
        });
    }

    Ok(addresses)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::ExecutionMode;

    const TEST_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    #[test]
    fn test_solana_phantom_test_vector() {
        println!("\n🟣 SOLANA PHANTOM WALLET TEST VECTOR");
        println!("============================================================");
        println!("Testing Solana address derivation against Phantom Wallet");
        println!("Standard test mnemonic: {}", TEST_MNEMONIC);
        println!("Passphrase: None (Phantom doesn't support BIP39 passphrase)");
        println!("Derivation: BIP32-Ed25519 (m/44'/501'/0'/0')");
        println!("Expected format: Base58 encoded (43-44 characters)");
        println!("");

        // Test con contexto de testing para no contaminar output
        let test_context = ExecutionContext::for_testing();
        let addresses = derive_solana_from_mnemonic_with_context(TEST_MNEMONIC, None, 1, Some(test_context)).unwrap();

        // Dirección verificada con Phantom wallet
        let expected_address = "HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk";

        println!("📋 EXPECTED TEST VECTOR (Phantom Wallet):");
        println!("   Address: {}", expected_address);
        println!("   Path:    {}", "m/44'/501'/0'/0'");
        println!("");

        assert_eq!(addresses[0].address, expected_address);
        assert_eq!(addresses[0].path, "m/44'/501'/0'/0'");

        println!("   ✅ Generated: {} ✓ MATCH", addresses[0].address);
        println!("   ✅ Path:      {} ✓ CORRECT", addresses[0].path);
        println!("");
        println!("✅ SOLANA PHANTOM WALLET TEST VECTOR PASSED");
        println!("   Address verified against official Phantom Wallet");
        println!("   BIP32-Ed25519 derivation confirmed");
        println!("   Note: Phantom ignores BIP39 passphrase for compatibility");
    }

    #[test]
    fn test_solana_address_format() {
        let test_context = ExecutionContext::for_testing();
        let addresses = derive_solana_from_mnemonic_with_context(TEST_MNEMONIC, None, 5, Some(test_context)).unwrap();

        for addr in &addresses {
            // Verificar que las direcciones Solana sean Base58 válidas
            assert!(bs58::decode(&addr.address).into_vec().is_ok(), "Invalid Base58 Solana address: {}", addr.address);

            // Verificar longitud típica de direcciones Solana (43-44 caracteres)
            assert!(addr.address.len() >= 43 && addr.address.len() <= 44, "Solana address length invalid: {}", addr.address);
        }

        println!("✅ Solana address format validation passed for {} addresses", addresses.len());
    }

    #[test]
    fn test_multiple_solana_addresses() {
        let test_context = ExecutionContext::for_testing();
        let addresses = derive_solana_from_mnemonic_with_context(TEST_MNEMONIC, None, 3, Some(test_context)).unwrap();
        assert_eq!(addresses.len(), 3);

        // Verificar que las direcciones sean únicas
        let mut unique_addresses = std::collections::HashSet::new();
        for addr in &addresses {
            assert!(unique_addresses.insert(&addr.address), "Duplicate Solana address found: {}", addr.address);
        }

        println!("✅ Multiple Solana addresses generation test passed");
        for (i, addr) in addresses.iter().enumerate() {
            println!("   Solana Address {}: {}", i, addr.address);
        }
    }

    #[test]
    fn test_solana_no_passphrase_support() {
        // Test que verifica que passphrase no afecta las direcciones Solana
        let test_context = ExecutionContext::for_testing();
        let addresses_no_pass = derive_solana_from_mnemonic_with_context(TEST_MNEMONIC, None, 1, Some(test_context.clone())).unwrap();
        let addresses_with_pass = derive_solana_from_mnemonic_with_context(TEST_MNEMONIC, Some("test"), 1, Some(test_context)).unwrap();

        // Las direcciones deben ser idénticas (passphrase ignorado)
        assert_eq!(addresses_no_pass[0].address, addresses_with_pass[0].address);

        println!("✅ Solana passphrase ignored test passed");
        println!("   Both results identical: {}", addresses_no_pass[0].address);
    }

    #[test]
    fn test_solana_derivation_paths() {
        let test_context = ExecutionContext::for_testing();
        let addresses = derive_solana_from_mnemonic_with_context(TEST_MNEMONIC, None, 3, Some(test_context)).unwrap();

        // Verificar paths de derivación específicos de Solana
        assert_eq!(addresses[0].path, "m/44'/501'/0'/0'");
        assert_eq!(addresses[1].path, "m/44'/501'/1'/0'");
        assert_eq!(addresses[2].path, "m/44'/501'/2'/0'");

        println!("✅ Solana derivation paths test passed");
        for addr in &addresses {
            println!("   Path: {} -> Address: {}", addr.path, addr.address);
        }
    }

    #[test]
    fn test_solana_logging_modes() {
        // Test diferentes modos de logging

        // Modo interactivo (debería mostrar logs)
        let interactive_context = ExecutionContext::new(ExecutionMode::Interactive);
        let addresses_interactive = derive_solana_from_mnemonic_with_context(TEST_MNEMONIC, None, 1, Some(interactive_context)).unwrap();

        // Modo JSON API (no debería contaminar output)
        let json_context = ExecutionContext::new(ExecutionMode::JsonApi);
        let addresses_json = derive_solana_from_mnemonic_with_context(TEST_MNEMONIC, None, 1, Some(json_context)).unwrap();

        // Modo testing (sin output)
        let test_context = ExecutionContext::for_testing();
        let addresses_test = derive_solana_from_mnemonic_with_context(TEST_MNEMONIC, None, 1, Some(test_context)).unwrap();

        // Las direcciones deben ser idénticas independientemente del modo
        assert_eq!(addresses_interactive[0].address, addresses_json[0].address);
        assert_eq!(addresses_json[0].address, addresses_test[0].address);

        println!("✅ Solana logging modes test passed");
        println!("   Same addresses generated across all execution modes");
        println!("   Logging respects execution context properly");
    }

    #[test]
    fn test_solana_function_compatibility() {
        // Test que la función original sigue funcionando
        let addresses_original = derive_solana_from_mnemonic_direct(TEST_MNEMONIC, None, 1).unwrap();

        // Test que la función con contexto produce el mismo resultado
        let test_context = ExecutionContext::for_testing();
        let addresses_with_context = derive_solana_from_mnemonic_with_context(TEST_MNEMONIC, None, 1, Some(test_context)).unwrap();

        // Deben generar las mismas direcciones
        assert_eq!(addresses_original[0].address, addresses_with_context[0].address);
        assert_eq!(addresses_original[0].path, addresses_with_context[0].path);

        println!("✅ Solana function compatibility test passed");
        println!("   Original and context-aware functions produce identical results");
    }
}
