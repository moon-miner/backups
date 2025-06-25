// src/error.rs - Sistema de errores completo para SCypher

use std::fmt;
use std::io;
use serde::{Deserialize, Serialize};

/// Tipo Result personalizado para SCypher
pub type Result<T> = std::result::Result<T, SCypherError>;
pub type SCypherResult<T> = std::result::Result<T, SCypherError>;

/// Errores principales de SCypher
#[derive(Debug, Clone, PartialEq)]
pub enum SCypherError {
    // Errores de validación de seed phrases
    InvalidSeedPhrase,
    InvalidWordCount(usize),
    InvalidBip39Word(String),
    InvalidChecksum,

    // Errores de contraseña y autenticación
    InvalidPassword,
    PasswordMismatch,
    PasswordTooShort(usize),

    // Errores de archivos y E/O
    FileError(String),
    IoError(String),

    // Errores criptográficos
    CryptoError(String),
    KeyDerivationFailed,

    // Errores de validación general
    ValidationError(String),

    // Errores de argumentos CLI
    InvalidIterations(String),
    InvalidMemoryCost(String),

    // Errores de red y addresses
    NetworkError(String),
    AddressDerivationFailed(String),

    // Errores de parsing y formato
    ParseError(String),
    FormatError(String),

    // Errores de seguridad
    SecurityError(String),
    MemoryError(String),

    // Errores de configuración
    ConfigError(String),

    // Error de entrada inválida (para compatibilidad con main.rs)
    InvalidInput(String),

    // Error JSON (para compatibilidad con main.rs)
    JsonError(String),

    // Error genérico
    Other(String),
}

impl SCypherError {
    /// Constructor para errores de validación
    pub fn validation(msg: String) -> Self {
        Self::ValidationError(msg)
    }

    /// Constructor para errores de archivo
    pub fn file(msg: String) -> Self {
        Self::FileError(msg)
    }

    /// Constructor para errores criptográficos
    pub fn crypto(msg: String) -> Self {
        Self::CryptoError(msg)
    }

    /// Constructor para errores de red
    pub fn network(msg: String) -> Self {
        Self::NetworkError(msg)
    }

    /// Constructor para errores de parsing
    pub fn parse(msg: String) -> Self {
        Self::ParseError(msg)
    }

    /// Constructor para errores de seguridad
    pub fn security(msg: String) -> Self {
        Self::SecurityError(msg)
    }

    /// Constructor para errores de configuración
    pub fn config(msg: String) -> Self {
        Self::ConfigError(msg)
    }

    /// Verificar si es un error crítico que requiere terminación
    pub fn is_critical(&self) -> bool {
        matches!(self,
            Self::SecurityError(_) |
            Self::MemoryError(_) |
            Self::KeyDerivationFailed
        )
    }

    /// Obtener código de salida apropiado
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::InvalidSeedPhrase |
            Self::InvalidWordCount(_) |
            Self::InvalidBip39Word(_) |
            Self::InvalidChecksum => 2,

            Self::InvalidPassword |
            Self::PasswordMismatch |
            Self::PasswordTooShort(_) => 3,

            Self::FileError(_) |
            Self::IoError(_) => 4,

            Self::CryptoError(_) |
            Self::KeyDerivationFailed => 5,

            Self::SecurityError(_) |
            Self::MemoryError(_) => 6,

            _ => 1,
        }
    }

    /// Obtener categoría de error para logging
    pub fn category(&self) -> &'static str {
        match self {
            Self::InvalidSeedPhrase |
            Self::InvalidWordCount(_) |
            Self::InvalidBip39Word(_) |
            Self::InvalidChecksum => "BIP39_VALIDATION",

            Self::InvalidPassword |
            Self::PasswordMismatch |
            Self::PasswordTooShort(_) => "AUTHENTICATION",

            Self::FileError(_) |
            Self::IoError(_) => "FILE_IO",

            Self::CryptoError(_) |
            Self::KeyDerivationFailed => "CRYPTOGRAPHY",

            Self::NetworkError(_) |
            Self::AddressDerivationFailed(_) => "BLOCKCHAIN",

            Self::SecurityError(_) |
            Self::MemoryError(_) => "SECURITY",

            Self::ValidationError(_) |
            Self::InvalidIterations(_) |
            Self::InvalidMemoryCost(_) |
            Self::InvalidInput(_) => "VALIDATION",

            Self::JsonError(_) => "PARSING",

            Self::ParseError(_) |
            Self::FormatError(_) => "PARSING",

            Self::ConfigError(_) => "CONFIGURATION",

            Self::Other(_) => "GENERAL",
        }
    }

    /// Obtener sugerencia de ayuda para el usuario
    pub fn help_message(&self) -> Option<&'static str> {
        match self {
            Self::InvalidSeedPhrase => Some(
                "Ensure your seed phrase contains 12, 15, 18, 21, or 24 valid BIP39 words"
            ),
            Self::InvalidWordCount(_) => Some(
                "Valid seed phrase lengths are: 12, 15, 18, 21, or 24 words"
            ),
            Self::InvalidPassword => Some(
                "Use a strong password with at least 8 characters"
            ),
            Self::PasswordTooShort(_) => Some(
                "Password must be at least 8 characters long"
            ),
            Self::FileError(_) => Some(
                "Check file path, permissions, and ensure the file exists"
            ),
            Self::CryptoError(_) => Some(
                "Try reducing iterations or memory cost if the operation fails"
            ),
            _ => None,
        }
    }
}

impl fmt::Display for SCypherError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSeedPhrase => {
                write!(f, "Invalid seed phrase format")
            }
            Self::InvalidWordCount(count) => {
                write!(f, "Invalid word count: {} (valid: 12, 15, 18, 21, 24)", count)
            }
            Self::InvalidBip39Word(word) => {
                write!(f, "Invalid BIP39 word: '{}'", word)
            }
            Self::InvalidChecksum => {
                write!(f, "Invalid BIP39 checksum")
            }
            Self::InvalidPassword => {
                write!(f, "Invalid password")
            }
            Self::PasswordMismatch => {
                write!(f, "Password confirmation does not match")
            }
            Self::PasswordTooShort(len) => {
                write!(f, "Password too short: {} characters (minimum: 8)", len)
            }
            Self::FileError(msg) => {
                write!(f, "File error: {}", msg)
            }
            Self::IoError(msg) => {
                write!(f, "I/O error: {}", msg)
            }
            Self::CryptoError(msg) => {
                write!(f, "Cryptographic error: {}", msg)
            }
            Self::KeyDerivationFailed => {
                write!(f, "Key derivation failed")
            }
            Self::ValidationError(msg) => {
                write!(f, "Validation error: {}", msg)
            }
            Self::InvalidIterations(msg) => {
                write!(f, "Invalid iterations: {}", msg)
            }
            Self::InvalidMemoryCost(msg) => {
                write!(f, "Invalid memory cost: {}", msg)
            }
            Self::NetworkError(msg) => {
                write!(f, "Network error: {}", msg)
            }
            Self::AddressDerivationFailed(msg) => {
                write!(f, "Address derivation failed: {}", msg)
            }
            Self::ParseError(msg) => {
                write!(f, "Parse error: {}", msg)
            }
            Self::FormatError(msg) => {
                write!(f, "Format error: {}", msg)
            }
            Self::SecurityError(msg) => {
                write!(f, "Security error: {}", msg)
            }
            Self::MemoryError(msg) => {
                write!(f, "Memory error: {}", msg)
            }
            Self::ConfigError(msg) => {
                write!(f, "Configuration error: {}", msg)
            }
            Self::InvalidInput(msg) => {
                write!(f, "Invalid input: {}", msg)
            }
            Self::JsonError(msg) => {
                write!(f, "JSON error: {}", msg)
            }
            Self::Other(msg) => {
                write!(f, "{}", msg)
            }
        }
    }
}

impl std::error::Error for SCypherError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

/// Implementaciones From para conversión automática de errores estándar
impl From<io::Error> for SCypherError {
    fn from(err: io::Error) -> Self {
        Self::IoError(err.to_string())
    }
}

impl From<std::fmt::Error> for SCypherError {
    fn from(err: std::fmt::Error) -> Self {
        Self::FormatError(err.to_string())
    }
}

impl From<serde_json::Error> for SCypherError {
    fn from(err: serde_json::Error) -> Self {
        Self::ParseError(format!("JSON error: {}", err))
    }
}

/// Macros para crear errores de forma más concisa
#[macro_export]
macro_rules! error_validation {
    ($msg:expr) => {
        $crate::error::SCypherError::validation($msg.to_string())
    };
    ($fmt:expr, $($arg:tt)*) => {
        $crate::error::SCypherError::validation(format!($fmt, $($arg)*))
    };
}

#[macro_export]
macro_rules! error_file {
    ($msg:expr) => {
        $crate::error::SCypherError::file($msg.to_string())
    };
    ($fmt:expr, $($arg:tt)*) => {
        $crate::error::SCypherError::file(format!($fmt, $($arg)*))
    };
}

#[macro_export]
macro_rules! error_crypto {
    ($msg:expr) => {
        $crate::error::SCypherError::crypto($msg.to_string())
    };
    ($fmt:expr, $($arg:tt)*) => {
        $crate::error::SCypherError::crypto(format!($fmt, $($arg)*))
    };
}

#[macro_export]
macro_rules! error_security {
    ($msg:expr) => {
        $crate::error::SCypherError::security($msg.to_string())
    };
    ($fmt:expr, $($arg:tt)*) => {
        $crate::error::SCypherError::security(format!($fmt, $($arg)*))
    };
}

/// Función para manejo consistente de errores críticos
pub fn handle_critical_error(error: &SCypherError) -> ! {
    eprintln!("CRITICAL ERROR [{}]: {}", error.category(), error);

    if let Some(help) = error.help_message() {
        eprintln!("Help: {}", help);
    }

    // Limpiar memoria sensible antes de salir
    // TODO: Implementar cuando tengamos security module
    // crate::security::secure_cleanup();

    std::process::exit(error.exit_code());
}

/// Función para logging de errores no críticos
pub fn log_error(error: &SCypherError) {
    eprintln!("ERROR [{}]: {}", error.category(), error);

    if let Some(help) = error.help_message() {
        eprintln!("Help: {}", help);
    }
}

/// Función para logging de warnings
pub fn log_warning(message: &str) {
    eprintln!("WARNING: {}", message);
}

/// Función para logging de información
pub fn log_info(message: &str) {
    eprintln!("INFO: {}", message);
}

/// Estructura para reporte de errores detallado
#[derive(Debug, Clone)]
pub struct ErrorReport {
    pub error: SCypherError,
    pub timestamp: std::time::SystemTime,
    pub context: String,
    pub operation: String,
}

/// Response structure for API errors
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub success: bool,
    pub error: ErrorInfo,
    pub timestamp: u64,
}

/// Response structure for API success
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuccessResponse<T> {
    pub success: bool,
    pub result: T,
    pub timestamp: u64,
}

/// Error information for API responses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorInfo {
    pub code: String,
    pub message: String,
    pub category: String,
    pub help: Option<String>,
}

impl ErrorReport {
    pub fn new(error: SCypherError, operation: &str) -> Self {
        Self {
            error,
            timestamp: std::time::SystemTime::now(),
            context: String::new(),
            operation: operation.to_string(),
        }
    }

    pub fn with_context(mut self, context: String) -> Self {
        self.context = context;
        self
    }

    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "error": {
                "type": self.error.category(),
                "message": self.error.to_string(),
                "exit_code": self.error.exit_code(),
                "is_critical": self.error.is_critical(),
                "help": self.error.help_message()
            },
            "operation": self.operation,
            "context": self.context,
            "timestamp": self.timestamp.duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default().as_secs()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_creation() {
        let err = SCypherError::validation("test validation".to_string());
        assert_eq!(err.category(), "VALIDATION");
        assert!(!err.is_critical());
        assert_eq!(err.exit_code(), 1);
    }

    #[test]
    fn test_critical_errors() {
        let err = SCypherError::security("test security issue".to_string());
        assert!(err.is_critical());
        assert_eq!(err.exit_code(), 6);
        assert_eq!(err.category(), "SECURITY");
    }

    #[test]
    fn test_error_display() {
        let err = SCypherError::InvalidWordCount(13);
        let display = format!("{}", err);
        assert!(display.contains("Invalid word count: 13"));
        assert!(display.contains("valid: 12, 15, 18, 21, 24"));
    }

    #[test]
    fn test_help_messages() {
        let err = SCypherError::InvalidSeedPhrase;
        assert!(err.help_message().is_some());
        assert!(err.help_message().unwrap().contains("BIP39"));
    }

    #[test]
    fn test_error_macros() {
        let err = error_validation!("Test message");
        assert_eq!(err.category(), "VALIDATION");

        let err = error_file!("File not found: {}", "test.txt");
        assert_eq!(err.category(), "FILE_IO");
    }

    #[test]
    fn test_error_report() {
        let err = SCypherError::InvalidSeedPhrase;
        let report = ErrorReport::new(err, "validate_seed")
            .with_context("Interactive mode".to_string());

        assert_eq!(report.operation, "validate_seed");
        assert_eq!(report.context, "Interactive mode");

        let json = report.to_json();
        assert_eq!(json["operation"], "validate_seed");
        assert_eq!(json["error"]["type"], "BIP39_VALIDATION");
    }

    #[test]
    fn test_io_error_conversion() {
        let io_err = io::Error::new(io::ErrorKind::NotFound, "File not found");
        let scypher_err: SCypherError = io_err.into();

        match scypher_err {
            SCypherError::IoError(_) => {},
            _ => panic!("Expected IoError"),
        }
    }
}
