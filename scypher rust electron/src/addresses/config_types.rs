//! src/addresses/config_types.rs
//! Tipos de datos y configuraciones compartidas para derivación de direcciones
//!
//! Este módulo define las estructuras y enums comunes utilizados por todas las redes
//! para la derivación determinística de direcciones blockchain.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Estructura para una dirección derivada individual
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Address {
    pub address_type: String,
    pub path: String,
    pub address: String,
}

/// Configuración para cada red
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// Cantidad de direcciones a generar
    pub count: u32,
    /// Si usar passphrase (solo para redes que lo soporten oficialmente)
    pub use_passphrase: bool,
}

/// Conjunto completo de direcciones para todas las redes
#[derive(Debug, Serialize, Deserialize)]
pub struct AddressSet {
    pub bitcoin: Vec<Address>,
    pub ethereum: Vec<Address>,
    pub ergo: Vec<Address>,
    pub bsc: Vec<Address>,
    pub polygon: Vec<Address>,
    pub cardano: Vec<Address>,
    pub dogecoin: Vec<Address>,
    pub litecoin: Vec<Address>,
    pub solana: Vec<Address>,
    pub tron: Vec<Address>,
}

impl Default for AddressSet {
    fn default() -> Self {
        Self {
            bitcoin: Vec::new(),
            ethereum: Vec::new(),
            ergo: Vec::new(),
            bsc: Vec::new(),
            polygon: Vec::new(),
            cardano: Vec::new(),
            dogecoin: Vec::new(),
            litecoin: Vec::new(),
            solana: Vec::new(),
            tron: Vec::new(),
        }
    }
}

impl NetworkConfig {
    /// Crear configuración por defecto
    pub fn default() -> Self {
        Self {
            count: 3,
            use_passphrase: true,
        }
    }

    /// Crear configuración con cantidad específica
    pub fn with_count(count: u32) -> Self {
        Self {
            count,
            use_passphrase: true,
        }
    }

    /// Crear configuración sin passphrase
    pub fn without_passphrase(count: u32) -> Self {
        Self {
            count,
            use_passphrase: false,
        }
    }
}

/// Tipo de configuración para múltiples redes
pub type NetworkConfigs = HashMap<String, NetworkConfig>;

/// Información sobre soporte de passphrase por red
pub fn network_supports_passphrase(network: &str) -> bool {
    match network {
        // Redes que oficialmente soportan BIP39 passphrase
        "bitcoin" | "ethereum" | "tron" | "litecoin" | "dogecoin" | "bsc" | "polygon" => true,
        // Ergo soporta passphrase (verificado con wallet SATERGO)
        "ergo" => true,
        // Redes que NO soportan passphrase consistentemente
        "cardano" | "solana" => false,
        _ => false,
    }
}

/// Lista de todas las redes soportadas
pub const SUPPORTED_NETWORKS: &[&str] = &[
    "bitcoin",
    "ethereum",
    "ergo",
    "bsc",
    "polygon",
    "cardano",
    "dogecoin",
    "litecoin",
    "solana",
    "tron",
];

/// Verificar si una red es soportada
pub fn is_network_supported(network: &str) -> bool {
    SUPPORTED_NETWORKS.contains(&network)
}
