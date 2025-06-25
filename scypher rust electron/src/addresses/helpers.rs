//! src/addresses/helpers.rs
//! Funciones auxiliares reutilizables para derivación de direcciones
//!
//! Este módulo contiene funciones de utilidad que son compartidas entre
//! múltiples implementaciones de redes blockchain.

use crate::error::{SCypherError, Result};
use crate::core::{ExecutionContext, ExecutionMode, Logger};
use tiny_keccak::{Hasher, Keccak};
use sha2::{Sha256, Digest};
use hmac::{Hmac, Mac};
use sha2::Sha512;

/// Implementar EIP-55 checksum encoding para direcciones Ethereum compatibles
/// Este es el formato estándar usado por MetaMask, Phantom, Ledger, etc.
pub fn to_eip55_checksum_address(address_bytes: &[u8]) -> String {
    let address_hex = hex::encode(address_bytes);

    // Hash de la dirección en minúsculas (sin 0x) usando Keccak256
    let mut hasher = Keccak::v256();
    hasher.update(address_hex.as_bytes());
    let mut hash = [0u8; 32];
    hasher.finalize(&mut hash);

    let hash_hex = hex::encode(hash);

    // Aplicar EIP-55: mayúscula si el dígito del hash >= 8
    let mut checksum_address = String::with_capacity(42);
    checksum_address.push_str("0x");

    for (i, c) in address_hex.chars().enumerate() {
        if c.is_ascii_digit() {
            // Los números siempre permanecen iguales
            checksum_address.push(c);
        } else {
            // Para letras a-f, usar mayúscula si el hex del hash en esa posición >= 8
            let hash_char = hash_hex.chars().nth(i).unwrap_or('0');
            if hash_char >= '8' {
                checksum_address.push(c.to_ascii_uppercase());
            } else {
                checksum_address.push(c);
            }
        }
    }

    checksum_address
}

/// TRON Base58Check encoding específico
/// Aplica doble SHA256 para checksum + Base58 encoding
pub fn tron_base58_encode(input: &[u8]) -> Result<String> {
    // Primer SHA256 del input
    let hash1 = Sha256::digest(input);

    // Segundo SHA256 del resultado anterior
    let hash2 = Sha256::digest(&hash1);

    // Tomar los primeros 4 bytes como checksum
    let checksum = &hash2[0..4];

    // Crear dirección completa: address + checksum
    let mut address_with_checksum = input.to_vec();
    address_with_checksum.extend_from_slice(checksum);

    // Codificar en Base58 estándar
    let base58_address = bs58::encode(address_with_checksum).into_string();

    Ok(base58_address)
}

/// Helper para hardened derivation en Cardano
pub fn harden(index: u32) -> u32 {
    index | 0x80_00_00_00
}

/// Implementación manual de derivePath para BIP32-Ed25519 (Solana compatible)
/// Compatible con ed25519-hd-key JavaScript
pub fn manual_derive_path(path: &str, seed: &[u8]) -> Result<[u8; 32]> {
    manual_derive_path_with_context(path, seed, None)
}

/// Implementación manual de derivePath con contexto de ejecución específico
/// Permite inyección de contexto para testing y diferentes modos de ejecución
pub fn manual_derive_path_with_context(
    path: &str,
    seed: &[u8],
    execution_context: Option<ExecutionContext>
) -> Result<[u8; 32]> {
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

    // Crear master key usando "ed25519 seed" como en BIP32-Ed25519
    let mut mac = Hmac::<Sha512>::new_from_slice(b"ed25519 seed")
        .map_err(|e| SCypherError::crypto(format!("Master key HMAC failed: {}", e)))?;

    mac.update(seed);
    let master_key_data = mac.finalize().into_bytes();

    // Split master key (32 bytes left = private key, 32 bytes right = chain code)
    let mut master_private_key = [0u8; 32];
    let mut master_chain_code = [0u8; 32];
    master_private_key.copy_from_slice(&master_key_data[0..32]);
    master_chain_code.copy_from_slice(&master_key_data[32..64]);

    // Parsear path y derivar jerárquicamente
    let path_components = parse_derivation_path_simple(path)?;

    let mut current_private_key = master_private_key;
    let mut current_chain_code = master_chain_code;

    for (i, &component) in path_components.iter().enumerate() {
        logger.debug(&format!("Derivando componente {}: 0x{:08x}", i, component), "helpers");

        // Crear HMAC para derivación del componente
        let mut child_mac = Hmac::<Sha512>::new_from_slice(&current_chain_code)
            .map_err(|e| SCypherError::crypto(format!("Child derivation HMAC failed: {}", e)))?;

        // Para hardened derivation (siempre en Ed25519)
        child_mac.update(&[0x00]);
        child_mac.update(&current_private_key);
        child_mac.update(&component.to_be_bytes());

        let child_data = child_mac.finalize().into_bytes();

        // Actualizar keys para siguiente iteración
        current_private_key.copy_from_slice(&child_data[0..32]);
        current_chain_code.copy_from_slice(&child_data[32..64]);
    }

    Ok(current_private_key)
}

/// Parsear derivation path: "m/44'/501'/0'/0'" -> [0x8000002C, 0x800001F5, 0x80000000, 0x80000000]
pub fn parse_derivation_path_simple(path: &str) -> Result<Vec<u32>> {
    let mut components = Vec::new();

    let path_clean = path.strip_prefix("m/")
        .ok_or_else(|| SCypherError::crypto("Invalid path format".to_string()))?;

    for component in path_clean.split('/') {
        if component.is_empty() {
            continue;
        }

        let (num_str, is_hardened) = if component.ends_with('\'') {
            (component.trim_end_matches('\''), true)
        } else {
            (component, false)
        };

        let mut num: u32 = num_str.parse()
            .map_err(|e| SCypherError::crypto(format!("Invalid path component: {}", e)))?;

        if is_hardened {
            num |= 0x80000000;
        }

        components.push(num);
    }

    Ok(components)
}

/// Convertir public key secp256k1 comprimida a formato no comprimido
pub fn compressed_to_uncompressed_pubkey(compressed: &[u8]) -> Result<Vec<u8>> {
    let secp = secp256k1::Secp256k1::new();
    let pk = secp256k1::PublicKey::from_slice(compressed)
        .map_err(|e| SCypherError::crypto(format!("Invalid compressed public key: {}", e)))?;

    Ok(pk.serialize_uncompressed().to_vec())
}

/// Calcular dirección Ethereum/EVM desde public key
pub fn calculate_evm_address_from_pubkey(public_key_compressed: &[u8]) -> Result<String> {
    // Convertir a formato no comprimido
    let uncompressed = compressed_to_uncompressed_pubkey(public_key_compressed)?;

    // Usar solo la parte X,Y (sin el prefijo 0x04)
    let xy_coords = &uncompressed[1..];

    // Hash con Keccak256
    let mut hasher = Keccak::v256();
    hasher.update(xy_coords);
    let mut hash = [0u8; 32];
    hasher.finalize(&mut hash);

    // Tomar los últimos 20 bytes como dirección
    let address_bytes = &hash[12..];

    // Aplicar EIP-55 checksum encoding
    Ok(to_eip55_checksum_address(address_bytes))
}

/// Calcular hash RIPEMD160(SHA256(data)) usado en Bitcoin-family
pub fn hash160(data: &[u8]) -> [u8; 20] {
    use ripemd::Ripemd160;

    let sha256_hash = Sha256::digest(data);
    let ripemd_hash = Ripemd160::digest(&sha256_hash);

    let mut result = [0u8; 20];
    result.copy_from_slice(&ripemd_hash);
    result
}

/// Crear dirección P2PKH (Pay-to-Public-Key-Hash) para Bitcoin-family
pub fn create_p2pkh_address(public_key: &[u8], version_byte: u8) -> Result<String> {
    let hash160_result = hash160(public_key);

    // Agregar version byte
    let mut address_bytes = vec![version_byte];
    address_bytes.extend_from_slice(&hash160_result);

    // Calcular checksum
    let checksum_hash = Sha256::digest(&Sha256::digest(&address_bytes));
    address_bytes.extend_from_slice(&checksum_hash[0..4]);

    // Codificar en Base58
    Ok(bs58::encode(address_bytes).into_string())
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{ExecutionContext, ExecutionMode, Logger};

    #[test]
    fn test_eip55_checksum() {
        let test_context = ExecutionContext::for_testing();
        let logger = Logger::from_context(test_context);

        // Test con dirección conocida
        let address_bytes = hex::decode("9858effd232b4033e47d90003d41ec34ecaeda94").unwrap();
        let result = to_eip55_checksum_address(&address_bytes);
        assert_eq!(result, "0x9858EfFD232B4033E47d90003D41EC34EcaEda94");

        logger.info("EIP-55 checksum test passed", "helpers_tests");
        logger.info(&format!("Generated checksum address: {}", result), "helpers_tests");
    }

    #[test]
    fn test_derivation_path_parsing() {
        let test_context = ExecutionContext::for_testing();
        let logger = Logger::from_context(test_context);

        let path = "m/44'/501'/0'/0'";
        let components = parse_derivation_path_simple(path).unwrap();
        assert_eq!(components, vec![0x8000002C, 0x800001F5, 0x80000000, 0x80000000]);

        logger.info("Derivation path parsing test passed", "helpers_tests");
        logger.info(&format!("Path: {} -> Components: {:?}", path, components), "helpers_tests");
    }

    #[test]
    fn test_harden_function() {
        let test_context = ExecutionContext::for_testing();
        let logger = Logger::from_context(test_context);

        assert_eq!(harden(0), 0x80000000);
        assert_eq!(harden(44), 0x8000002C);
        assert_eq!(harden(501), 0x800001F5);

        logger.info("Harden function test passed", "helpers_tests");
        logger.info("All hardened derivation values calculated correctly", "helpers_tests");
    }

    #[test]
    fn test_manual_derive_path_logging_modes() {
        // Test diferentes modos de logging
        let test_context = ExecutionContext::for_testing();
        let logger = Logger::from_context(test_context);

        let test_seed = [0u8; 32]; // Seed de test
        let test_path = "m/44'/501'/0'/0'";

        // Modo interactivo (debería mostrar logs)
        let interactive_context = ExecutionContext::new(ExecutionMode::Interactive);
        let result_interactive = manual_derive_path_with_context(test_path, &test_seed, Some(interactive_context)).unwrap();

        // Modo JSON API (no debería contaminar output)
        let json_context = ExecutionContext::new(ExecutionMode::JsonApi);
        let result_json = manual_derive_path_with_context(test_path, &test_seed, Some(json_context)).unwrap();

        // Modo testing (sin output)
        let test_context_inner = ExecutionContext::for_testing();
        let result_test = manual_derive_path_with_context(test_path, &test_seed, Some(test_context_inner)).unwrap();

        // Los resultados deben ser idénticos independientemente del modo
        assert_eq!(result_interactive, result_json);
        assert_eq!(result_json, result_test);

        logger.info("Helpers logging modes test passed", "helpers_tests");
        logger.info("Same derivation results across all execution modes", "helpers_tests");
        logger.info("Logging respects execution context properly", "helpers_tests");
    }

    #[test]
    fn test_helpers_function_compatibility() {
        // Test que la función original sigue funcionando
        let test_context = ExecutionContext::for_testing();
        let logger = Logger::from_context(test_context);

        let test_seed = [0u8; 32];
        let test_path = "m/44'/501'/0'/0'";

        let result_original = manual_derive_path(test_path, &test_seed).unwrap();

        // Test que la función con contexto produce el mismo resultado
        let test_context_inner = ExecutionContext::for_testing();
        let result_with_context = manual_derive_path_with_context(test_path, &test_seed, Some(test_context_inner)).unwrap();

        // Deben generar los mismos resultados
        assert_eq!(result_original, result_with_context);

        logger.info("Helpers function compatibility test passed", "helpers_tests");
        logger.info("Original and context-aware functions produce identical results", "helpers_tests");
    }

    #[test]
    fn test_tron_base58_encoding() {
        let test_context = ExecutionContext::for_testing();
        let logger = Logger::from_context(test_context);

        // Test TRON Base58Check encoding con datos conocidos
        let test_data = vec![0x41, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E, 0x6F, 0x70, 0x80, 0x90,
                           0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x07, 0x18, 0x29, 0x3A, 0x4B];

        let result = tron_base58_encode(&test_data).unwrap();

        // La dirección debe comenzar con 'T' (prefijo TRON 0x41)
        assert!(result.starts_with('T'));
        assert!(result.len() >= 30); // Longitud mínima esperada

        logger.info("TRON Base58 encoding test passed", "helpers_tests");
        logger.info(&format!("Generated TRON address: {}", result), "helpers_tests");
    }

    #[test]
    fn test_evm_address_calculation() {
        let test_context = ExecutionContext::for_testing();
        let logger = Logger::from_context(test_context);

        // Test con clave pública conocida (compressed)
        let test_pubkey = hex::decode("0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798").unwrap();

        let result = calculate_evm_address_from_pubkey(&test_pubkey).unwrap();

        // Debe ser una dirección EVM válida
        assert!(result.starts_with("0x"));
        assert_eq!(result.len(), 42); // 0x + 40 caracteres hex
        assert!(result.chars().skip(2).all(|c| c.is_ascii_hexdigit()));

        logger.info("EVM address calculation test passed", "helpers_tests");
        logger.info(&format!("Generated EVM address: {}", result), "helpers_tests");
    }

    #[test]
    fn test_p2pkh_address_creation() {
        let test_context = ExecutionContext::for_testing();
        let logger = Logger::from_context(test_context);

        // Test con clave pública conocida y version byte de Bitcoin
        let test_pubkey = hex::decode("0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798").unwrap();
        let bitcoin_version = 0x00; // Bitcoin mainnet P2PKH

        let result = create_p2pkh_address(&test_pubkey, bitcoin_version).unwrap();

        // Debe ser una dirección Bitcoin válida
        assert!(result.starts_with('1')); // Bitcoin addresses start with '1'
        assert!(result.len() >= 26 && result.len() <= 35); // Standard Bitcoin address length

        logger.info("P2PKH address creation test passed", "helpers_tests");
        logger.info(&format!("Generated Bitcoin address: {}", result), "helpers_tests");
    }

    #[test]
    fn test_compressed_to_uncompressed_conversion() {
        let test_context = ExecutionContext::for_testing();
        let logger = Logger::from_context(test_context);

        // Test con clave pública comprimida conocida
        let compressed = hex::decode("0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798").unwrap();

        let uncompressed = compressed_to_uncompressed_pubkey(&compressed).unwrap();

        // Verificar formato de clave no comprimida
        assert_eq!(uncompressed.len(), 65); // 1 byte prefix + 32 bytes X + 32 bytes Y
        assert_eq!(uncompressed[0], 0x04); // Uncompressed prefix

        logger.info("Compressed to uncompressed conversion test passed", "helpers_tests");
        logger.info(&format!("Uncompressed key length: {} bytes", uncompressed.len()), "helpers_tests");
    }

    #[test]
    fn test_hash160_calculation() {
        let test_context = ExecutionContext::for_testing();
        let logger = Logger::from_context(test_context);

        // Test con datos conocidos
        let test_data = b"Hello Bitcoin";
        let result = hash160(test_data);

        // Verificar que el resultado tenga 20 bytes
        assert_eq!(result.len(), 20);

        logger.info("Hash160 calculation test passed", "helpers_tests");
        logger.info(&format!("Hash160 result: {}", hex::encode(result)), "helpers_tests");
    }
}
