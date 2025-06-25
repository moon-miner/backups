//! src/addresses/mod.rs
//! Coordinador principal para derivación de direcciones multi-blockchain
//!
//! Este módulo orquesta la derivación determinística de direcciones para múltiples
//! redes blockchain desde frases semilla BIP39, con soporte completo para passphrase
//! donde está oficialmente soportado.

use crate::error::{SCypherError, Result};
use crate::core::{ExecutionContext, ExecutionMode};

// Módulos de redes específicas
pub mod bitcoin_family;
pub mod evm_family;
pub mod ergo;
pub mod cardano;
pub mod solana;
pub mod tron;

// Módulos de utilidad
pub mod config_types;
pub mod helpers;

// Tests del módulo completo
#[cfg(test)]
pub mod tests;

// Re-exportar tipos públicos para facilitar uso
pub use config_types::{Address, NetworkConfig, AddressSet, NetworkConfigs};
pub use config_types::{network_supports_passphrase, is_network_supported, SUPPORTED_NETWORKS};

// Importaciones para la función principal
use bip32::XPrv;
use bip39_crate::{Mnemonic, Language};
use std::collections::HashMap;

/// Derivar direcciones para múltiples redes desde una seed phrase
/// Soporta configuración individual por red y cantidad de direcciones
pub fn derive_addresses_with_config(
    seed_phrase: &str,
    passphrase: Option<&str>,
    network_configs: NetworkConfigs,
) -> Result<AddressSet> {
    derive_addresses_with_config_and_context(seed_phrase, passphrase, network_configs, None)
}

/// Derivar direcciones con contexto de ejecución específico
/// Permite inyección de contexto para testing y diferentes modos de ejecución
pub fn derive_addresses_with_config_and_context(
    seed_phrase: &str,
    passphrase: Option<&str>,
    network_configs: NetworkConfigs,
    execution_context: Option<ExecutionContext>,
) -> Result<AddressSet> {
    // Parsear mnemonic BIP39
    let mnemonic = Mnemonic::parse_in_normalized(Language::English, seed_phrase)
        .map_err(|e| SCypherError::crypto(format!("Invalid mnemonic: {}", e)))?;

    // Generar seed con passphrase opcional
    let seed = mnemonic.to_seed(passphrase.unwrap_or(""));

    // Derivar master key para redes BIP32
    let master_key = XPrv::new(&seed)
        .map_err(|e| SCypherError::crypto(format!("Master key derivation failed: {}", e)))?;

    let mut address_set = AddressSet::default();

    // Derivar direcciones para cada red solicitada
    for (network, config) in network_configs {
        // Determinar si usar passphrase según soporte oficial
        let effective_passphrase = if config.use_passphrase && network_supports_passphrase(&network) {
            passphrase
        } else {
            None // No usar passphrase si la red no lo soporta oficialmente
        };

        match network.as_str() {
            "bitcoin" => {
                address_set.bitcoin = bitcoin_family::derive_bitcoin_addresses(&master_key, config.count)?;
            }
            "ethereum" => {
                address_set.ethereum = evm_family::derive_ethereum_addresses(&master_key, config.count)?;
            }
            "ergo" => {
                // Ergo soporta passphrase (verificado con wallet SATERGO)
                address_set.ergo = ergo::derive_ergo_addresses(seed_phrase, effective_passphrase, config.count)?;
            }
            "bsc" => {
                address_set.bsc = evm_family::derive_bsc_addresses(&master_key, config.count)?;
            }
            "polygon" => {
                address_set.polygon = evm_family::derive_polygon_addresses(&master_key, config.count)?;
            }
            "cardano" => {
                // Cardano siempre usa None para passphrase (Yoroi/Daedalus no lo soportan)
                address_set.cardano = cardano::derive_cardano_addresses_with_context(
                    seed_phrase,
                    None,
                    config.count,
                    execution_context.clone()
                )?;
            }
            "dogecoin" => {
                address_set.dogecoin = bitcoin_family::derive_dogecoin_addresses(&master_key, config.count)?;
            }
            "litecoin" => {
                address_set.litecoin = bitcoin_family::derive_litecoin_addresses(&master_key, config.count)?;
            }
            "solana" => {
                // Solana siempre usa None para passphrase (Phantom no lo soporta)
                address_set.solana = solana::derive_solana_from_mnemonic_with_context(
                    seed_phrase,
                    None,
                    config.count,
                    execution_context.clone()
                )?;
            }
            "tron" => {
                address_set.tron = tron::derive_tron_addresses_with_context(
                    &master_key,
                    config.count,
                    execution_context.clone()
                )?;
            }
            _ => return Err(SCypherError::crypto(format!("Unsupported network: {}", network))),
        }
    }

    Ok(address_set)
}

/// Función legacy para compatibilidad hacia atrás
/// Mantiene la interfaz original del código para no romper integración existente
pub fn derive_addresses(
    seed_phrase: &str,
    passphrase: Option<&str>,
    networks: &[String],
) -> Result<AddressSet> {
    // Crear configuración por defecto (3 direcciones cada red)
    let mut network_configs = HashMap::new();
    for network in networks {
        network_configs.insert(network.clone(), NetworkConfig {
            count: 3,
            use_passphrase: true, // Será aplicado solo a redes que lo soporten
        });
    }

    derive_addresses_with_config(seed_phrase, passphrase, network_configs)
}

/// Función de conveniencia para derivar una sola red
pub fn derive_single_network(
    seed_phrase: &str,
    passphrase: Option<&str>,
    network: &str,
    count: u32,
    use_passphrase: bool,
) -> Result<Vec<Address>> {
    let mut network_configs = HashMap::new();
    network_configs.insert(network.to_string(), NetworkConfig {
        count,
        use_passphrase,
    });

    let address_set = derive_addresses_with_config(seed_phrase, passphrase, network_configs)?;

    // Retornar las direcciones de la red solicitada
    match network {
        "bitcoin" => Ok(address_set.bitcoin),
        "ethereum" => Ok(address_set.ethereum),
        "ergo" => Ok(address_set.ergo),
        "bsc" => Ok(address_set.bsc),
        "polygon" => Ok(address_set.polygon),
        "cardano" => Ok(address_set.cardano),
        "dogecoin" => Ok(address_set.dogecoin),
        "litecoin" => Ok(address_set.litecoin),
        "solana" => Ok(address_set.solana),
        "tron" => Ok(address_set.tron),
        _ => Err(SCypherError::crypto(format!("Unsupported network: {}", network))),
    }
}

/// Función de conveniencia para crear configuración rápida
pub fn create_network_config(networks: &[&str], count: u32, use_passphrase: bool) -> NetworkConfigs {
    let mut config = HashMap::new();
    for &network in networks {
        config.insert(network.to_string(), NetworkConfig {
            count,
            use_passphrase,
        });
    }
    config
}

/// Función de conveniencia para crear configuración con todas las redes
pub fn create_all_networks_config(count: u32, use_passphrase: bool) -> NetworkConfigs {
    create_network_config(SUPPORTED_NETWORKS, count, use_passphrase)
}

/// Validar que una lista de redes sea soportada
pub fn validate_networks(networks: &[String]) -> Result<()> {
    for network in networks {
        if !is_network_supported(network) {
            return Err(SCypherError::crypto(format!("Unsupported network: {}", network)));
        }
    }
    Ok(())
}

/// Obtener información sobre qué redes soportan passphrase
pub fn get_passphrase_support_info() -> HashMap<String, bool> {
    let mut support_map = HashMap::new();
    for &network in SUPPORTED_NETWORKS {
        support_map.insert(network.to_string(), network_supports_passphrase(network));
    }
    support_map
}

#[cfg(test)]
mod integration_tests {
    use super::*;
    use crate::core::ExecutionMode;

    const TEST_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    #[test]
    fn test_context_injection_integration() {
        // Test que el contexto se inyecta correctamente en todas las redes

        let mut network_configs = HashMap::new();
        network_configs.insert("cardano".to_string(), NetworkConfig { count: 1, use_passphrase: false });
        network_configs.insert("solana".to_string(), NetworkConfig { count: 1, use_passphrase: false });
        network_configs.insert("tron".to_string(), NetworkConfig { count: 1, use_passphrase: false });

        // Test con contexto de testing
        let test_context = ExecutionContext::for_testing();
        let address_set = derive_addresses_with_config_and_context(
            TEST_MNEMONIC,
            None,
            network_configs.clone(),
            Some(test_context)
        ).unwrap();

        // Verificar que se generaron direcciones para todas las redes
        assert!(!address_set.cardano.is_empty());
        assert!(!address_set.solana.is_empty());
        assert!(!address_set.tron.is_empty());

        println!("✅ Context injection integration test passed");
        println!("   Cardano address: {}", address_set.cardano[0].address);
        println!("   Solana address: {}", address_set.solana[0].address);
        println!("   Tron address: {}", address_set.tron[0].address);
    }

    #[test]
    fn test_execution_modes_consistency() {
        // Test que diferentes modos de ejecución producen las mismas direcciones

        let mut network_configs = HashMap::new();
        network_configs.insert("cardano".to_string(), NetworkConfig { count: 1, use_passphrase: false });
        network_configs.insert("solana".to_string(), NetworkConfig { count: 1, use_passphrase: false });

        // Modo interactivo
        let interactive_context = ExecutionContext::new(ExecutionMode::Interactive);
        let addresses_interactive = derive_addresses_with_config_and_context(
            TEST_MNEMONIC,
            None,
            network_configs.clone(),
            Some(interactive_context)
        ).unwrap();

        // Modo JSON API
        let json_context = ExecutionContext::new(ExecutionMode::JsonApi);
        let addresses_json = derive_addresses_with_config_and_context(
            TEST_MNEMONIC,
            None,
            network_configs.clone(),
            Some(json_context)
        ).unwrap();

        // Modo testing
        let test_context = ExecutionContext::for_testing();
        let addresses_test = derive_addresses_with_config_and_context(
            TEST_MNEMONIC,
            None,
            network_configs,
            Some(test_context)
        ).unwrap();

        // Las direcciones deben ser idénticas independientemente del modo
        assert_eq!(addresses_interactive.cardano[0].address, addresses_json.cardano[0].address);
        assert_eq!(addresses_json.cardano[0].address, addresses_test.cardano[0].address);

        assert_eq!(addresses_interactive.solana[0].address, addresses_json.solana[0].address);
        assert_eq!(addresses_json.solana[0].address, addresses_test.solana[0].address);

        println!("✅ Execution modes consistency test passed");
        println!("   Same addresses generated across all execution modes");
    }

    #[test]
    fn test_backward_compatibility() {
        // Test que las funciones legacy siguen funcionando
        let networks = vec!["cardano".to_string(), "solana".to_string()];

        let address_set_legacy = derive_addresses(TEST_MNEMONIC, None, &networks).unwrap();

        // Crear configuración equivalente
        let mut network_configs = HashMap::new();
        for network in &networks {
            network_configs.insert(network.clone(), NetworkConfig {
                count: 3, // Default de la función legacy
                use_passphrase: true,
            });
        }

        let address_set_new = derive_addresses_with_config(TEST_MNEMONIC, None, network_configs).unwrap();

        // Las direcciones deben ser idénticas
        assert_eq!(address_set_legacy.cardano[0].address, address_set_new.cardano[0].address);
        assert_eq!(address_set_legacy.solana[0].address, address_set_new.solana[0].address);

        println!("✅ Backward compatibility test passed");
        println!("   Legacy and new functions produce identical results");
    }
}
