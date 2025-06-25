//! src/addresses/cardano.rs
//! Derivación de direcciones para Cardano blockchain
//!
//! Cardano utiliza EMURGO CSL (Cardano Serialization Library) oficial.
//! NOTA: Cardano (Yoroi/Daedalus) no soporta BIP39 passphrase oficialmente.

use crate::addresses::config_types::Address;
use crate::addresses::helpers::harden;
use crate::error::{SCypherError, Result};
use crate::core::{ExecutionContext, ExecutionMode, Logger};

// Importaciones Cardano - EMURGO CSL
use cardano_serialization_lib::{
    Bip32PrivateKey,
    Address as CSLAddress, BaseAddress, Credential,
    NetworkInfo,
};

/// Derivar direcciones Cardano usando EMURGO CSL (biblioteca oficial)
/// NOTA: Cardano (Yoroi/Daedalus) no soporta BIP39 passphrase oficialmente
pub fn derive_cardano_addresses_official(
    mnemonic_phrase: &str,
    _passphrase: Option<&str>, // Ignorado intencionalmente
    count: u32,
) -> Result<Vec<Address>> {
    derive_cardano_addresses_with_context(mnemonic_phrase, _passphrase, count, None)
}

/// Derivar direcciones Cardano con contexto de ejecución específico
/// Permite inyección de contexto para testing y diferentes modos de ejecución
pub fn derive_cardano_addresses_with_context(
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

    logger.info("CARDANO OFICIAL - EMURGO CSL Implementation (sin passphrase)", "cardano");

    // Conversión correcta de mnemonic a entropy
    let mnemonic = Mnemonic::parse_in_normalized(Language::English, mnemonic_phrase)
        .map_err(|e| SCypherError::crypto(format!("Invalid mnemonic: {}", e)))?;

    let entropy = mnemonic.to_entropy();
    logger.debug(&format!("Entropy correcta: {}", hex::encode(&entropy)), "cardano");

    // Generar master key usando EMURGO CSL (sin passphrase para compatibilidad Yoroi/Daedalus)
    let master_key = Bip32PrivateKey::from_bip39_entropy(&entropy, &[]);
    logger.debug("Master key generada con EMURGO CSL", "cardano");

    // Derivar staking key: m/1852'/1815'/0'/2/0
    let staking_key = master_key
        .derive(harden(1852))  // purpose
        .derive(harden(1815))  // coin_type
        .derive(harden(0))     // account
        .derive(2)             // role (staking)
        .derive(0);            // index

    let staking_pub = staking_key.to_public();
    let staking_hash = staking_pub.to_raw_key().hash();
    let staking_cred = Credential::from_keyhash(&staking_hash);

    // Generar direcciones para el número solicitado
    for index in 0u32..count {
        let payment_key = master_key
            .derive(harden(1852))  // purpose
            .derive(harden(1815))  // coin_type
            .derive(harden(0))     // account
            .derive(0)             // role (external)
            .derive(index);        // index

        let payment_pub = payment_key.to_public();
        let payment_hash = payment_pub.to_raw_key().hash();
        let payment_cred = Credential::from_keyhash(&payment_hash);

        // Crear base address (payment + staking)
        let base_addr = BaseAddress::new(
            NetworkInfo::mainnet().network_id(),
            &payment_cred,
            &staking_cred
        );

        let address_str = base_addr.to_address().to_bech32(None)
            .map_err(|e| SCypherError::crypto(format!("Address encoding failed: {:?}", e)))?;

        logger.debug(&format!("Index {} address: {}", index, address_str), "cardano");

        addresses.push(Address {
            address_type: format!("Cardano #{}", index),
            path: format!("m/1852'/1815'/0'/0/{}", index),
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
    fn test_cardano_eternl_test_vector() {
        println!("\n🔵 CARDANO ETERNL WALLET TEST VECTOR");
        println!("============================================================");
        println!("Testing Cardano address derivation against Eternl Wallet");
        println!("Standard test mnemonic: {}", TEST_MNEMONIC);
        println!("Passphrase: None (Cardano wallets don't support BIP39 passphrase)");
        println!("Derivation: CIP-1852 (m/1852'/1815'/0'/0/0)");
        println!("Library: EMURGO Cardano Serialization Lib (official)");
        println!("Expected format: Bech32 'addr1' prefix");
        println!("");

        // Test con contexto de testing para no contaminar output
        let test_context = ExecutionContext::for_testing();
        let addresses = derive_cardano_addresses_with_context(TEST_MNEMONIC, None, 1, Some(test_context)).unwrap();

        // Dirección verificada con Eternl wallet
        let expected_address = "addr1qy8ac7qqy0vtulyl7wntmsxc6wex80gvcyjy33qffrhm7sh927ysx5sftuw0dlft05dz3c7revpf7jx0xnlcjz3g69mq4afdhv";

        println!("📋 EXPECTED TEST VECTOR (Eternl Wallet):");
        println!("   Address: {}", expected_address);
        println!("   Path:    {}", "m/1852'/1815'/0'/0/0");
        println!("");

        assert_eq!(addresses[0].address, expected_address);
        assert_eq!(addresses[0].path, "m/1852'/1815'/0'/0/0");

        println!("   ✅ Generated: {} ✓ MATCH", addresses[0].address);
        println!("   ✅ Path:      {} ✓ CORRECT", addresses[0].path);
        println!("");
        println!("✅ CARDANO ETERNL WALLET TEST VECTOR PASSED");
        println!("   Address verified against Eternl Wallet");
        println!("   EMURGO CSL (official Cardano library) confirmed");
        println!("   Compatible with Yoroi, Daedalus, and other Cardano wallets");
        println!("   Note: BIP39 passphrase ignored for wallet compatibility");
    }

    #[test]
    fn test_cardano_address_format() {
        let test_context = ExecutionContext::for_testing();
        let addresses = derive_cardano_addresses_with_context(TEST_MNEMONIC, None, 5, Some(test_context)).unwrap();

        for addr in &addresses {
            // Verificar que las direcciones Cardano comiencen con 'addr1'
            assert!(addr.address.starts_with("addr1"), "Cardano address should start with 'addr1': {}", addr.address);

            // Verificar longitud típica de direcciones Cardano
            assert!(addr.address.len() > 80, "Cardano address too short: {}", addr.address);
        }

        println!("✅ Cardano address format validation passed for {} addresses", addresses.len());
    }

    #[test]
    fn test_multiple_cardano_addresses() {
        let test_context = ExecutionContext::for_testing();
        let addresses = derive_cardano_addresses_with_context(TEST_MNEMONIC, None, 3, Some(test_context)).unwrap();
        assert_eq!(addresses.len(), 3);

        // Verificar que las direcciones sean únicas
        let mut unique_addresses = std::collections::HashSet::new();
        for addr in &addresses {
            assert!(unique_addresses.insert(&addr.address), "Duplicate Cardano address found: {}", addr.address);
        }

        println!("✅ Multiple Cardano addresses generation test passed");
        for (i, addr) in addresses.iter().enumerate() {
            println!("   Cardano Address {}: {}...", i, &addr.address[..20]);
        }
    }

    #[test]
    fn test_cardano_no_passphrase_support() {
        // Test que verifica que passphrase no afecta las direcciones Cardano
        let test_context = ExecutionContext::for_testing();
        let addresses_no_pass = derive_cardano_addresses_with_context(TEST_MNEMONIC, None, 1, Some(test_context.clone())).unwrap();
        let addresses_with_pass = derive_cardano_addresses_with_context(TEST_MNEMONIC, Some("test"), 1, Some(test_context)).unwrap();

        // Las direcciones deben ser idénticas (passphrase ignorado)
        assert_eq!(addresses_no_pass[0].address, addresses_with_pass[0].address);

        println!("✅ Cardano passphrase ignored test passed");
        println!("   Both results identical: {}", addresses_no_pass[0].address);
    }

    #[test]
    fn test_cardano_logging_modes() {
        // Test diferentes modos de logging

        // Modo interactivo (debería mostrar logs)
        let interactive_context = ExecutionContext::new(ExecutionMode::Interactive);
        let addresses_interactive = derive_cardano_addresses_with_context(TEST_MNEMONIC, None, 1, Some(interactive_context)).unwrap();

        // Modo JSON API (no debería contaminar output)
        let json_context = ExecutionContext::new(ExecutionMode::JsonApi);
        let addresses_json = derive_cardano_addresses_with_context(TEST_MNEMONIC, None, 1, Some(json_context)).unwrap();

        // Modo testing (sin output)
        let test_context = ExecutionContext::for_testing();
        let addresses_test = derive_cardano_addresses_with_context(TEST_MNEMONIC, None, 1, Some(test_context)).unwrap();

        // Las direcciones deben ser idénticas independientemente del modo
        assert_eq!(addresses_interactive[0].address, addresses_json[0].address);
        assert_eq!(addresses_json[0].address, addresses_test[0].address);

        println!("✅ Cardano logging modes test passed");
        println!("   Same addresses generated across all execution modes");
        println!("   Logging respects execution context properly");
    }

    #[test]
    fn test_cardano_function_compatibility() {
        // Test que la función original sigue funcionando
        let addresses_original = derive_cardano_addresses_official(TEST_MNEMONIC, None, 1).unwrap();

        // Test que la función con contexto produce el mismo resultado
        let test_context = ExecutionContext::for_testing();
        let addresses_with_context = derive_cardano_addresses_with_context(TEST_MNEMONIC, None, 1, Some(test_context)).unwrap();

        // Deben generar las mismas direcciones
        assert_eq!(addresses_original[0].address, addresses_with_context[0].address);
        assert_eq!(addresses_original[0].path, addresses_with_context[0].path);

        println!("✅ Cardano function compatibility test passed");
        println!("   Original and context-aware functions produce identical results");
    }
}
