//! src/core/mod.rs
//! Módulo principal para funcionalidades centrales de SCypher
//!
//! ETAPA B6: Integra conditional compilation para logging profesional
//! con zero overhead en production y full debugging en development.
//!
//! Este módulo proporciona la infraestructura fundamental para:
//! - Gestión de contexto de ejecución
//! - Sistema de logging estructurado con conditional compilation
//! - Separación entre logs técnicos y output de usuario
//! - Compatibilidad con modo JSON para Electron
//! - Production builds optimizados sin logging técnico

pub mod execution_context;
pub mod logger;

// Re-exportar tipos principales para facilitar el uso
pub use execution_context::{ExecutionContext, ExecutionMode, determine_execution_mode};
pub use logger::{LogLevel, Logger, LogMessage, StructuredLogger};

// Re-exportar funciones específicas de B6
pub use logger::{is_dev_logging_enabled, get_build_info, create_logger_from_cli};

/// Versión del módulo core
pub const CORE_VERSION: &str = "1.1.0"; // Incrementado para B6

/// Configuración global del core con soporte para conditional compilation
#[derive(Debug, Clone)]
pub struct CoreConfig {
    /// Habilitar logging detallado
    pub verbose_logging: bool,
    /// Nivel mínimo de log a mostrar
    pub min_log_level: LogLevel,
    /// Contexto de ejecución
    pub execution_mode: ExecutionMode,
}

impl Default for CoreConfig {
    fn default() -> Self {
        Self {
            verbose_logging: false,
            min_log_level: LogLevel::Info,
            execution_mode: ExecutionMode::Interactive,
        }
    }
}

/// Función de conveniencia para crear un logger con configuración estándar
pub fn create_logger(mode: ExecutionMode) -> Logger {
    let config = CoreConfig {
        execution_mode: mode,
        ..Default::default()
    };
    Logger::new(config)
}

/// Función de conveniencia para crear un contexto de ejecución
pub fn create_context(mode: ExecutionMode) -> ExecutionContext {
    ExecutionContext::new(mode)
}

/// Función para crear logger con configuración automática desde argumentos CLI
pub fn create_auto_logger(silent: bool, stdin_mode: bool, format_json: bool, verbose: bool) -> Logger {
    create_logger_from_cli(silent, stdin_mode, format_json, verbose)
}

/// Función para obtener información completa del build (B6)
pub fn get_core_info() -> std::collections::HashMap<String, String> {
    let mut info = get_build_info();
    info.insert("core_version".to_string(), CORE_VERSION.to_string());
    info.insert("conditional_compilation".to_string(), "enabled".to_string());

    // Información sobre features habilitadas
    let mut features: Vec<&str> = Vec::new();

    #[cfg(feature = "dev-logging")]
    features.push("dev-logging");

    #[cfg(feature = "security-testing")]
    features.push("security-testing");

    #[cfg(feature = "async")]
    features.push("async");

    info.insert("enabled_features".to_string(), features.join(","));

    info
}

/// Función para verificar compatibilidad del sistema de logging
pub fn verify_logging_system() -> Result<(), String> {
    // Test básico de creación de logger
    let test_context = ExecutionContext::for_testing();
    let logger = Logger::from_context(test_context);

    // Verificar que los métodos básicos funcionan
    logger.error("Verification test", "core_verification");
    logger.warn("Verification test", "core_verification");

    // Verificar conditional compilation
    #[cfg(feature = "dev-logging")]
    {
        logger.info("Dev logging verification", "core_verification");
        logger.debug("Dev logging verification", "core_verification");
    }

    // Verificar que el buffer funciona
    let logs = logger.get_logs();
    if logs.is_empty() {
        return Err("Logger buffer not working".to_string());
    }

    // Verificar que error y warn están presentes
    let has_error = logs.iter().any(|log| log.level == LogLevel::Error);
    let has_warn = logs.iter().any(|log| log.level == LogLevel::Warn);

    if !has_error || !has_warn {
        return Err("Critical logging levels not working".to_string());
    }

    Ok(())
}

/// Macro para facilitar la creación de loggers con contexto
#[macro_export]
macro_rules! create_contextual_logger {
    ($mode:expr) => {
        $crate::core::create_logger($mode)
    };
    ($silent:expr, $stdin:expr, $json:expr, $verbose:expr) => {
        $crate::core::create_auto_logger($silent, $stdin, $json, $verbose)
    };
}

/// Función para limpiar estado global del core (útil para testing)
pub fn reset_core_state() {
    // En el futuro, aquí se puede agregar limpieza de estado global si es necesario
    // Por ahora, los loggers son independientes y no hay estado global
}

/// Función para obtener métricas de rendimiento del logging system
pub fn get_logging_metrics() -> std::collections::HashMap<String, serde_json::Value> {
    let mut metrics = std::collections::HashMap::new();

    metrics.insert("dev_logging_enabled".to_string(),
        serde_json::Value::Bool(is_dev_logging_enabled()));

    #[cfg(feature = "dev-logging")]
    {
        metrics.insert("logging_overhead".to_string(),
            serde_json::Value::String("full".to_string()));
        metrics.insert("performance_impact".to_string(),
            serde_json::Value::String("development".to_string()));
    }

    #[cfg(not(feature = "dev-logging"))]
    {
        metrics.insert("logging_overhead".to_string(),
            serde_json::Value::String("minimal".to_string()));
        metrics.insert("performance_impact".to_string(),
            serde_json::Value::String("zero".to_string()));
    }

    metrics.insert("critical_logging".to_string(),
        serde_json::Value::String("always_enabled".to_string()));

    metrics
}

/// Función para obtener configuración recomendada según el uso
pub fn get_recommended_config(use_case: &str) -> CoreConfig {
    match use_case {
        "production" | "electron" | "release" => {
            CoreConfig {
                verbose_logging: false,
                min_log_level: LogLevel::Warn, // Solo warnings y errores en production
                execution_mode: ExecutionMode::JsonApi,
            }
        },
        "development" | "debug" | "testing" => {
            CoreConfig {
                verbose_logging: true,
                min_log_level: LogLevel::Debug, // Full logging en development
                execution_mode: ExecutionMode::Interactive,
            }
        },
        "interactive" | "cli" => {
            CoreConfig {
                verbose_logging: false,
                min_log_level: LogLevel::Info,
                execution_mode: ExecutionMode::Interactive,
            }
        },
        "silent" | "script" => {
            CoreConfig {
                verbose_logging: false,
                min_log_level: LogLevel::Error, // Solo errores en scripts
                execution_mode: ExecutionMode::Silent,
            }
        },
        _ => CoreConfig::default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_core_config_default() {
        let config = CoreConfig::default();
        assert!(!config.verbose_logging);
        assert_eq!(config.min_log_level, LogLevel::Info);
        assert_eq!(config.execution_mode, ExecutionMode::Interactive);
    }

    #[test]
    fn test_create_logger() {
        let logger = create_logger(ExecutionMode::JsonApi);
        assert_eq!(logger.get_mode(), ExecutionMode::JsonApi);
    }

    #[test]
    fn test_create_context() {
        let context = create_context(ExecutionMode::Silent);
        assert_eq!(context.get_mode(), ExecutionMode::Silent);
    }

    #[test]
    fn test_version_constant() {
        assert!(!CORE_VERSION.is_empty());
        assert!(CORE_VERSION.contains('.'));
        assert_eq!(CORE_VERSION, "1.1.0");
    }

    #[test]
    fn test_get_core_info() {
        let info = get_core_info();

        assert!(info.contains_key("core_version"));
        assert!(info.contains_key("build_mode"));
        assert!(info.contains_key("dev_logging"));
        assert!(info.contains_key("conditional_compilation"));
        assert!(info.contains_key("enabled_features"));

        assert_eq!(info["core_version"], "1.1.0");
        assert_eq!(info["conditional_compilation"], "enabled");

        #[cfg(feature = "dev-logging")]
        {
            assert_eq!(info["build_mode"], "development");
            assert_eq!(info["dev_logging"], "true");
            assert!(info["enabled_features"].contains("dev-logging"));
        }

        #[cfg(not(feature = "dev-logging"))]
        {
            assert_eq!(info["build_mode"], "production");
            assert_eq!(info["dev_logging"], "false");
            assert!(!info["enabled_features"].contains("dev-logging"));
        }
    }

    #[test]
    fn test_verify_logging_system() {
        let result = verify_logging_system();
        assert!(result.is_ok(), "Logging system verification failed: {:?}", result);
    }

    #[test]
    fn test_create_auto_logger() {
        // Test interactive mode
        let logger = create_auto_logger(false, false, false, false);
        assert_eq!(logger.get_mode(), ExecutionMode::Interactive);

        // Test JSON API mode
        let logger = create_auto_logger(true, false, false, false);
        assert_eq!(logger.get_mode(), ExecutionMode::JsonApi);

        // Test stdin mode
        let logger = create_auto_logger(false, true, false, false);
        assert_eq!(logger.get_mode(), ExecutionMode::Stdin);
    }

    #[test]
    fn test_contextual_logger_macro() {
        // Test basic macro
        let logger = create_contextual_logger!(ExecutionMode::Testing);
        assert_eq!(logger.get_mode(), ExecutionMode::Testing);

        // Test CLI args macro
        let logger = create_contextual_logger!(false, false, true, false);
        assert_eq!(logger.get_mode(), ExecutionMode::JsonApi);
    }

    #[test]
    fn test_get_logging_metrics() {
        let metrics = get_logging_metrics();

        assert!(metrics.contains_key("dev_logging_enabled"));
        assert!(metrics.contains_key("logging_overhead"));
        assert!(metrics.contains_key("performance_impact"));
        assert!(metrics.contains_key("critical_logging"));

        // Verificar valores según build mode
        #[cfg(feature = "dev-logging")]
        {
            assert_eq!(metrics["dev_logging_enabled"], serde_json::Value::Bool(true));
            assert_eq!(metrics["logging_overhead"], serde_json::Value::String("full".to_string()));
            assert_eq!(metrics["performance_impact"], serde_json::Value::String("development".to_string()));
        }

        #[cfg(not(feature = "dev-logging"))]
        {
            assert_eq!(metrics["dev_logging_enabled"], serde_json::Value::Bool(false));
            assert_eq!(metrics["logging_overhead"], serde_json::Value::String("minimal".to_string()));
            assert_eq!(metrics["performance_impact"], serde_json::Value::String("zero".to_string()));
        }

        assert_eq!(metrics["critical_logging"], serde_json::Value::String("always_enabled".to_string()));
    }

    #[test]
    fn test_get_recommended_config() {
        // Test production config
        let prod_config = get_recommended_config("production");
        assert!(!prod_config.verbose_logging);
        assert_eq!(prod_config.min_log_level, LogLevel::Warn);
        assert_eq!(prod_config.execution_mode, ExecutionMode::JsonApi);

        // Test development config
        let dev_config = get_recommended_config("development");
        assert!(dev_config.verbose_logging);
        assert_eq!(dev_config.min_log_level, LogLevel::Debug);
        assert_eq!(dev_config.execution_mode, ExecutionMode::Interactive);

        // Test electron config
        let electron_config = get_recommended_config("electron");
        assert!(!electron_config.verbose_logging);
        assert_eq!(electron_config.min_log_level, LogLevel::Warn);
        assert_eq!(electron_config.execution_mode, ExecutionMode::JsonApi);

        // Test interactive config
        let interactive_config = get_recommended_config("interactive");
        assert!(!interactive_config.verbose_logging);
        assert_eq!(interactive_config.min_log_level, LogLevel::Info);
        assert_eq!(interactive_config.execution_mode, ExecutionMode::Interactive);

        // Test silent config
        let silent_config = get_recommended_config("silent");
        assert!(!silent_config.verbose_logging);
        assert_eq!(silent_config.min_log_level, LogLevel::Error);
        assert_eq!(silent_config.execution_mode, ExecutionMode::Silent);

        // Test default config
        let default_config = get_recommended_config("unknown");
        assert_eq!(default_config.verbose_logging, CoreConfig::default().verbose_logging);
    }

    #[test]
    fn test_reset_core_state() {
        // Test que la función existe y se puede llamar sin problemas
        reset_core_state();
        // No hay estado global actualmente, así que solo verificamos que no falle
    }

    #[test]
    fn test_conditional_compilation_integration() {
        // Test integral de conditional compilation en el módulo core
        let logger = create_logger(ExecutionMode::Testing);

        // Test que error y warn siempre funcionan
        logger.error("Core test error", "core_tests");
        logger.warn("Core test warning", "core_tests");

        // Test conditional logging
        logger.info("Core test info", "core_tests");
        logger.debug("Core test debug", "core_tests");

        let logs = logger.get_logs();

        // Error y warn siempre deben estar presentes
        assert!(logs.iter().any(|log| log.message.contains("Core test error")));
        assert!(logs.iter().any(|log| log.message.contains("Core test warning")));

        #[cfg(feature = "dev-logging")]
        {
            // En dev mode, info y debug también
            assert!(logs.iter().any(|log| log.message.contains("Core test info")));
            assert!(logs.iter().any(|log| log.message.contains("Core test debug")));
        }

        #[cfg(not(feature = "dev-logging"))]
        {
            // En production mode, info y debug no deben estar
            assert!(!logs.iter().any(|log| log.message.contains("Core test info")));
            assert!(!logs.iter().any(|log| log.message.contains("Core test debug")));
        }
    }

    #[test]
    fn test_etapa_b6_core_mod_verification() {
        // Test comprensivo de la implementación B6 en core/mod.rs

        // Verificar versión actualizada
        assert_eq!(CORE_VERSION, "1.1.0");

        // Verificar funciones B6 funcionando
        let core_info = get_core_info();
        assert_eq!(core_info["conditional_compilation"], "enabled");

        let metrics = get_logging_metrics();
        assert!(metrics.contains_key("dev_logging_enabled"));

        // Verificar logging system
        assert!(verify_logging_system().is_ok());

        // Verificar configuraciones recomendadas
        let prod_config = get_recommended_config("production");
        let dev_config = get_recommended_config("development");
        let electron_config = get_recommended_config("electron");

        assert_eq!(prod_config.execution_mode, ExecutionMode::JsonApi);
        assert_eq!(dev_config.execution_mode, ExecutionMode::Interactive);
        assert_eq!(electron_config.execution_mode, ExecutionMode::JsonApi);

        // Verificar macro funcionando
        let logger = create_contextual_logger!(ExecutionMode::Testing);
        assert_eq!(logger.get_mode(), ExecutionMode::Testing);

        // Test integral con conditional compilation
        logger.error("B6 CORE MOD VERIFICATION", "b6_core_verification");
        logger.info("B6 conditional test", "b6_core_verification");

        let logs = logger.get_logs();
        assert!(logs.iter().any(|log| log.message.contains("B6 CORE MOD VERIFICATION")));

        #[cfg(feature = "dev-logging")]
        {
            assert!(logs.iter().any(|log| log.message.contains("B6 conditional test")));
            println!("✅ B6 CORE MOD: Development mode with full logging");
        }

        #[cfg(not(feature = "dev-logging"))]
        {
            assert!(!logs.iter().any(|log| log.message.contains("B6 conditional test")));
            println!("✅ B6 CORE MOD: Production mode with minimal logging");
        }

        println!("✅ ETAPA B6 CORE MODULE IMPLEMENTATION VERIFIED");
        println!("✅ Conditional compilation integrated in core module");
        println!("✅ Helper functions and macros working correctly");
        println!("✅ Recommended configurations available");
        println!("✅ Metrics and build info accessible");
        println!("✅ Logging system verification passed");
    }
}
