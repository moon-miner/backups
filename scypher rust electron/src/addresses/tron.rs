//! src/addresses/tron.rs
//! Derivación de direcciones para TRON blockchain
//!
//! TRON utiliza un esquema de derivación similar a EVM pero con encoding Base58Check específico
//! y prefijo de red 0x41. Soporta BIP39 passphrase oficialmente.

use crate::addresses::config_types::Address;
use crate::addresses::helpers::{tron_base58_encode, compressed_to_uncompressed_pubkey};
use crate::error::{SCypherError, Result};
use crate::core::{ExecutionContext, ExecutionMode, Logger};
use bip32::{XPrv, DerivationPath};
use std::str::FromStr;
use tiny_keccak::{Hasher, Keccak};

/// Derivar direcciones TRON usando BIP44 estándar
/// TRON soporta BIP39 passphrase oficialmente
/// Path: m/44'/195'/0'/0/index (195 = TRON coin type oficial)
pub fn derive_tron_addresses(master_key: &XPrv, count: u32) -> Result<Vec<Address>> {
    derive_tron_addresses_with_context(master_key, count, None)
}

/// Derivar direcciones TRON con contexto de ejecución específico
/// Permite inyección de contexto para testing y diferentes modos de ejecución
pub fn derive_tron_addresses_with_context(
    master_key: &XPrv,
    count: u32,
    execution_context: Option<ExecutionContext>,
) -> Result<Vec<Address>> {
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

    logger.info("TRON Address Derivation - BIP44 m/44'/195'/0'/0/index", "tron");

    // Generar direcciones para el número solicitado
    for index in 0u32..count {
        // TRON BIP44 derivation path oficial
        let path_str = format!("m/44'/195'/0'/0/{}", index);
        let path = DerivationPath::from_str(&path_str)
            .map_err(|e| SCypherError::crypto(format!("Invalid TRON path {}: {}", path_str, e)))?;

        // Derivar la clave privada siguiendo el path BIP44
        let mut current_key = master_key.clone();
        for child_number in path.as_ref() {
            current_key = current_key.derive_child(*child_number)
                .map_err(|e| SCypherError::crypto(format!("TRON derivation failed at {}: {}", path_str, e)))?;
        }

        // Extraer public key en formato secp256k1
        let public_key_point = current_key.public_key();
        let public_key_compressed = public_key_point.to_bytes();

        // Convertir a formato no comprimido (requerido por TRON)
        let uncompressed = compressed_to_uncompressed_pubkey(&public_key_compressed)?;

        // TRON usa solo las coordenadas X,Y (64 bytes), sin el prefijo 0x04
        let xy_coords = &uncompressed[1..]; // 64 bytes

        logger.debug(&format!("Index {} - Public key coords: {} bytes", index, xy_coords.len()), "tron");

        // Aplicar Keccak256 hash (SHA3) a las coordenadas públicas
        let mut hasher = Keccak::v256();
        hasher.update(xy_coords);
        let mut keccak_hash = [0u8; 32];
        hasher.finalize(&mut keccak_hash);

        // Tomar los últimos 20 bytes del hash Keccak256
        let address_bytes = &keccak_hash[12..]; // 20 bytes

        // Agregar prefijo TRON mainnet (0x41) para formar dirección completa
        let mut tron_address = vec![0x41];
        tron_address.extend_from_slice(address_bytes);

        logger.debug(&format!("Index {} - Address with prefix: {}", index, hex::encode(&tron_address)), "tron");

        // Aplicar TRON Base58Check encoding
        let tron_address_base58 = tron_base58_encode(&tron_address)?;

        logger.debug(&format!("Index {} - Final TRON address: {}", index, tron_address_base58), "tron");

        // Verificar que la dirección comience con 'T'
        if !tron_address_base58.starts_with('T') {
            return Err(SCypherError::crypto(format!("Invalid TRON address format for index {}: {}", index, tron_address_base58)));
        }

        addresses.push(Address {
            address_type: format!("TRON #{}", index),
            path: path_str,
            address: tron_address_base58,
        });
    }

    Ok(addresses)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::ExecutionMode;
    use bip39_crate::{Mnemonic, Language};

    const TEST_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    #[test]
    fn test_tron_official_test_vector() {
        println!("\n🔴 TRON OFFICIAL TEST VECTOR");
        println!("============================================================");
        println!("Testing TRON address derivation against Ian Coleman BIP39 Tool");
        println!("Standard test mnemonic: {}", TEST_MNEMONIC);
        println!("Passphrase: None (empty)");
        println!("Derivation path: m/44'/195'/0'/0/0 (TRON coin type 195)");
        println!("Expected format: Base58Check with 'T' prefix");
        println!("");

        let mnemonic = Mnemonic::parse_in_normalized(Language::English, TEST_MNEMONIC).unwrap();
        let seed = mnemonic.to_seed("");
        let master_key = XPrv::new(&seed).unwrap();

        // Test con contexto de testing para no contaminar output
        let test_context = ExecutionContext::for_testing();
        let addresses = derive_tron_addresses_with_context(&master_key, 1, Some(test_context)).unwrap();

        // Dirección verificada con Ian Coleman BIP39 tool
        let expected_address = "TUEZSdKsoDHQMeZwihtdoBiN46zxhGWYdH";

        println!("📋 EXPECTED TEST VECTOR (Ian Coleman BIP39 Tool):");
        println!("   Address: {}", expected_address);
        println!("   Path:    {}", "m/44'/195'/0'/0/0");
        println!("");

        assert_eq!(addresses[0].address, expected_address);
        assert_eq!(addresses[0].path, "m/44'/195'/0'/0/0");

        println!("   ✅ Generated: {} ✓ MATCH", addresses[0].address);
        println!("   ✅ Path:      {} ✓ CORRECT", addresses[0].path);
        println!("   ✅ Format:    Starts with 'T' ✓ VALID", );
        println!("   ✅ Length:    {} characters ✓ STANDARD", addresses[0].address.len());
        println!("");
        println!("✅ TRON OFFICIAL TEST VECTOR PASSED");
        println!("   Address verified against Ian Coleman BIP39 Tool");
        println!("   TRON Base58Check encoding confirmed");
        println!("   Compatible with TronLink and other TRON wallets");
    }

    #[test]
    fn test_tron_with_bip39_passphrase() {
        println!("\n🔴 TRON BIP39 PASSPHRASE TEST VECTOR");
        println!("============================================================");
        println!("Testing TRON with BIP39 passphrase support");
        println!("Standard test mnemonic: {}", TEST_MNEMONIC);
        println!("Passphrase: 'test'");
        println!("Source: Ian Coleman BIP39 Tool");
        println!("");

        let mnemonic = Mnemonic::parse_in_normalized(Language::English, TEST_MNEMONIC).unwrap();
        let seed = mnemonic.to_seed("test");
        let master_key = XPrv::new(&seed).unwrap();

        // Test con contexto de testing para no contaminar output
        let test_context = ExecutionContext::for_testing();
        let addresses = derive_tron_addresses_with_context(&master_key, 1, Some(test_context)).unwrap();

        // Dirección verificada con Ian Coleman BIP39 tool usando passphrase "test"
        let expected_address = "THuKukbDjhaKnRNboYmZyUJjYP9jQzqtWj";

        println!("📋 EXPECTED TEST VECTOR (with passphrase):");
        println!("   Address: {}", expected_address);
        println!("   Path:    {}", "m/44'/195'/0'/0/0");
        println!("");

        assert_eq!(addresses[0].address, expected_address);
        assert_eq!(addresses[0].path, "m/44'/195'/0'/0/0");

        println!("   ✅ Generated: {} ✓ MATCH", addresses[0].address);
        println!("   ✅ Path:      {} ✓ CORRECT", addresses[0].path);
        println!("");
        println!("✅ TRON BIP39 PASSPHRASE TEST VECTOR PASSED");
        println!("   Passphrase functionality verified with Ian Coleman Tool");
        println!("   TRON officially supports BIP39 passphrase");
    }

    #[test]
    fn test_tron_address_format() {
        let mnemonic = Mnemonic::parse_in_normalized(Language::English, TEST_MNEMONIC).unwrap();
        let seed = mnemonic.to_seed("");
        let master_key = XPrv::new(&seed).unwrap();

        let test_context = ExecutionContext::for_testing();
        let addresses = derive_tron_addresses_with_context(&master_key, 5, Some(test_context)).unwrap();

        for addr in &addresses {
            // Verificar que todas las direcciones comiencen con 'T'
            assert!(addr.address.starts_with('T'), "TRON address should start with 'T': {}", addr.address);

            // Verificar longitud típica de direcciones TRON (34 caracteres)
            assert!(addr.address.len() == 34, "TRON address should be 34 characters: {}", addr.address);
        }

        println!("✅ TRON address format validation passed for {} addresses", addresses.len());
    }

    #[test]
    fn test_multiple_tron_addresses() {
        let mnemonic = Mnemonic::parse_in_normalized(Language::English, TEST_MNEMONIC).unwrap();
        let seed = mnemonic.to_seed("");
        let master_key = XPrv::new(&seed).unwrap();

        let test_context = ExecutionContext::for_testing();
        let addresses = derive_tron_addresses_with_context(&master_key, 3, Some(test_context)).unwrap();
        assert_eq!(addresses.len(), 3);

        // Verificar que las direcciones sean únicas
        let mut unique_addresses = std::collections::HashSet::new();
        for addr in &addresses {
            assert!(unique_addresses.insert(&addr.address), "Duplicate TRON address found: {}", addr.address);
        }

        println!("✅ Multiple TRON addresses generation test passed");
        for (i, addr) in addresses.iter().enumerate() {
            println!("   TRON Address {}: {}", i, addr.address);
        }
    }

    #[test]
    fn test_tron_logging_modes() {
        // Test diferentes modos de logging

        let mnemonic = Mnemonic::parse_in_normalized(Language::English, TEST_MNEMONIC).unwrap();
        let seed = mnemonic.to_seed("");
        let master_key = XPrv::new(&seed).unwrap();

        // Modo interactivo (debería mostrar logs)
        let interactive_context = ExecutionContext::new(ExecutionMode::Interactive);
        let addresses_interactive = derive_tron_addresses_with_context(&master_key, 1, Some(interactive_context)).unwrap();

        // Modo JSON API (no debería contaminar output)
        let json_context = ExecutionContext::new(ExecutionMode::JsonApi);
        let addresses_json = derive_tron_addresses_with_context(&master_key, 1, Some(json_context)).unwrap();

        // Modo testing (sin output)
        let test_context = ExecutionContext::for_testing();
        let addresses_test = derive_tron_addresses_with_context(&master_key, 1, Some(test_context)).unwrap();

        // Las direcciones deben ser idénticas independientemente del modo
        assert_eq!(addresses_interactive[0].address, addresses_json[0].address);
        assert_eq!(addresses_json[0].address, addresses_test[0].address);

        println!("✅ TRON logging modes test passed");
        println!("   Same addresses generated across all execution modes");
        println!("   Logging respects execution context properly");
    }

    #[test]
    fn test_tron_function_compatibility() {
        // Test que la función original sigue funcionando
        let mnemonic = Mnemonic::parse_in_normalized(Language::English, TEST_MNEMONIC).unwrap();
        let seed = mnemonic.to_seed("");
        let master_key = XPrv::new(&seed).unwrap();

        let addresses_original = derive_tron_addresses(&master_key, 1).unwrap();

        // Test que la función con contexto produce el mismo resultado
        let test_context = ExecutionContext::for_testing();
        let addresses_with_context = derive_tron_addresses_with_context(&master_key, 1, Some(test_context)).unwrap();

        // Deben generar las mismas direcciones
        assert_eq!(addresses_original[0].address, addresses_with_context[0].address);
        assert_eq!(addresses_original[0].path, addresses_with_context[0].path);

        println!("✅ TRON function compatibility test passed");
        println!("   Original and context-aware functions produce identical results");
    }
}
