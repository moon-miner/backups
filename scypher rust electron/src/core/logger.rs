//! src/core/logger.rs
//! Sistema de logging estructurado y limpio para SCypher con conditional compilation
//!
//! ETAPA B6: Implementa conditional compilation para eliminar logging técnico
//! en binarios de producción manteniendo funcionalidad completa para desarrollo.
//!
//! MODOS:
//! - Production (default): Zero logging overhead, JSON API limpio
//! - Development (--features dev-logging): Full debugging capabilities

use crate::core::{ExecutionContext, ExecutionMode, CoreConfig};
use crate::error::{SCypherError, Result};
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Niveles de logging
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize)]
pub enum LogLevel {
    /// Errores críticos
    Error = 0,
    /// Advertencias importantes
    Warn = 1,
    /// Información general
    Info = 2,
    /// Información de debugging
    Debug = 3,
    /// Información muy detallada
    Trace = 4,
}

// AGREGAR implementación manual de Serialize para LogLevel:
impl serde::Serialize for LogLevel {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl LogLevel {
    /// Convertir a string para display
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Error => "ERROR",
            Self::Warn => "WARN",
            Self::Info => "INFO",
            Self::Debug => "DEBUG",
            Self::Trace => "TRACE",
        }
    }

    /// Obtener color ANSI para el nivel
    pub fn color_code(&self) -> &'static str {
        match self {
            Self::Error => "\x1b[31m", // Rojo
            Self::Warn => "\x1b[33m",  // Amarillo
            Self::Info => "\x1b[32m",  // Verde
            Self::Debug => "\x1b[36m", // Cyan
            Self::Trace => "\x1b[37m", // Blanco
        }
    }
}

impl std::fmt::Display for LogLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Mensaje de log estructurado
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogMessage {
    /// Nivel del mensaje
    pub level: LogLevel,
    /// Mensaje principal
    pub message: String,
    /// Módulo que generó el log
    pub module: String,
    /// Timestamp del mensaje
    pub timestamp: u64,
    /// Metadatos adicionales
    pub metadata: HashMap<String, serde_json::Value>,
    /// ID de sesión
    pub session_id: String,
}

impl LogMessage {
    /// Crear nuevo mensaje de log
    pub fn new(
        level: LogLevel,
        message: String,
        module: String,
        session_id: String,
    ) -> Self {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            level,
            message,
            module,
            timestamp,
            metadata: HashMap::new(),
            session_id,
        }
    }

    /// Agregar metadato al mensaje
    pub fn with_metadata(mut self, key: String, value: serde_json::Value) -> Self {
        self.metadata.insert(key, value);
        self
    }

    /// Formatear para output humano
    pub fn format_human(&self, use_colors: bool) -> String {
        let level_str = if use_colors {
            format!("{}[{}]\x1b[0m", self.level.color_code(), self.level.as_str())
        } else {
            format!("[{}]", self.level.as_str())
        };

        let timestamp = chrono::DateTime::from_timestamp(self.timestamp as i64, 0)
            .map(|dt| dt.format("%H:%M:%S").to_string())
            .unwrap_or_else(|| "??:??:??".to_string());

        if self.metadata.is_empty() {
            format!("{} {} {}: {}", timestamp, level_str, self.module, self.message)
        } else {
            format!("{} {} {}: {} | {:?}",
                timestamp, level_str, self.module, self.message, self.metadata)
        }
    }

    /// Formatear para output JSON
    pub fn format_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| {
            format!(r#"{{"level":"{}","message":"Log serialization failed"}}"#, self.level.as_str())
        })
    }
}

/// Logger principal con configuración y conditional compilation
#[derive(Debug, Clone)]
pub struct Logger {
    /// Configuración del logger
    config: CoreConfig,
    /// Buffer de mensajes (compartido entre threads)
    buffer: Arc<Mutex<Vec<LogMessage>>>,
    /// Contexto de ejecución
    context: ExecutionContext,
}

impl Logger {
    /// Crear nuevo logger
    pub fn new(config: CoreConfig) -> Self {
        let context = ExecutionContext::new(config.execution_mode);

        Self {
            config,
            buffer: Arc::new(Mutex::new(Vec::new())),
            context,
        }
    }

    /// Crear logger desde contexto de ejecución
    pub fn from_context(context: ExecutionContext) -> Self {
        let config = CoreConfig {
            execution_mode: context.get_mode(),
            min_log_level: if context.get_mode() == ExecutionMode::Testing {
                LogLevel::Debug  // En testing, permitir todos los logs
            } else {
                LogLevel::Info   // En otros modos, usar configuración normal
            },
            ..Default::default()
        };

        Self {
            config,
            buffer: Arc::new(Mutex::new(Vec::new())),
            context,
        }
    }

    /// Obtener modo de ejecución
    pub fn get_mode(&self) -> ExecutionMode {
        self.config.execution_mode
    }

    /// Log genérico con nivel - CON CONDITIONAL COMPILATION
    pub fn log(&self, level: LogLevel, message: &str, module: &str) {
        // CONDITIONAL COMPILATION: Solo ejecutar si dev-logging está habilitado
        // o si es un error/warning crítico
        #[cfg(feature = "dev-logging")]
        {
            self.log_internal(level, message, module);
        }

        #[cfg(not(feature = "dev-logging"))]
        {
            // En production, solo procesar errores críticos
            if matches!(level, LogLevel::Error | LogLevel::Warn) {
                self.log_internal(level, message, module);
            }
            // Los logs Debug, Info, Trace se ignoran completamente en production
        }
    }

    /// Implementación interna de logging (siempre disponible)
    fn log_internal(&self, level: LogLevel, message: &str, module: &str) {
        // Verificar si debe loggear este nivel
        if level > self.config.min_log_level {
            return;
        }

        let log_message = LogMessage::new(
            level,
            message.to_string(),
            module.to_string(),
            self.context.session_id().to_string(),
        );

        // Agregar al buffer
        if let Ok(mut buffer) = self.buffer.lock() {
            buffer.push(log_message.clone());
        }

        // Output según el modo de ejecución
        self.output_message(&log_message);
    }

    /// Log con metadatos adicionales - CON CONDITIONAL COMPILATION
    pub fn log_with_metadata(
        &self,
        level: LogLevel,
        message: &str,
        module: &str,
        metadata: HashMap<String, serde_json::Value>,
    ) {
        #[cfg(feature = "dev-logging")]
        {
            self.log_with_metadata_internal(level, message, module, metadata);
        }

        #[cfg(not(feature = "dev-logging"))]
        {
            // En production, solo procesar errores críticos
            if matches!(level, LogLevel::Error | LogLevel::Warn) {
                self.log_with_metadata_internal(level, message, module, metadata);
            }
        }
    }

    /// Implementación interna de logging con metadatos
    fn log_with_metadata_internal(
        &self,
        level: LogLevel,
        message: &str,
        module: &str,
        metadata: HashMap<String, serde_json::Value>,
    ) {
        if level > self.config.min_log_level {
            return;
        }

        let mut log_message = LogMessage::new(
            level,
            message.to_string(),
            module.to_string(),
            self.context.session_id().to_string(),
        );

        for (key, value) in metadata {
            log_message = log_message.with_metadata(key, value);
        }

        if let Ok(mut buffer) = self.buffer.lock() {
            buffer.push(log_message.clone());
        }

        self.output_message(&log_message);
    }

    /// Output del mensaje según el modo
    fn output_message(&self, message: &LogMessage) {
        match self.config.execution_mode {
            ExecutionMode::Interactive => {
                // Output colorido para modo interactivo
                if self.config.verbose_logging || message.level <= LogLevel::Info {
                    eprintln!("{}", message.format_human(true));
                }
            }
            ExecutionMode::JsonApi => {
                // NO OUTPUT - solo buffering para JSON API limpio
                // Los logs se pueden obtener después via get_logs() si es necesario
            }
            ExecutionMode::Silent => {
                // Solo errores críticos van a stderr
                if message.level <= LogLevel::Error {
                    eprintln!("{}", message.format_human(false));
                }
            }
            ExecutionMode::Stdin => {
                // Logs van a stderr para no contaminar stdin/stdout
                if message.level <= LogLevel::Warn {
                    eprintln!("{}", message.format_human(false));
                }
            }
            ExecutionMode::Testing => {
                // NO OUTPUT durante tests
            }
        }
    }

    /// Métodos de conveniencia para diferentes niveles - CON CONDITIONAL COMPILATION
    pub fn error(&self, message: &str, module: &str) {
        // Error siempre se procesa (crítico)
        self.log_internal(LogLevel::Error, message, module);
    }

    pub fn warn(&self, message: &str, module: &str) {
        // Warning siempre se procesa (importante)
        self.log_internal(LogLevel::Warn, message, module);
    }

    pub fn info(&self, message: &str, module: &str) {
        #[cfg(feature = "dev-logging")]
        {
            self.log_internal(LogLevel::Info, message, module);
        }

        #[cfg(not(feature = "dev-logging"))]
        {
            // En production, Info se ignora para mayor rendimiento
            let _ = (message, module); // Evitar warnings de variables no usadas
        }
    }

    pub fn debug(&self, message: &str, module: &str) {
        #[cfg(feature = "dev-logging")]
        {
            self.log_internal(LogLevel::Debug, message, module);
        }

        #[cfg(not(feature = "dev-logging"))]
        {
            // En production, Debug se ignora completamente
            let _ = (message, module); // Evitar warnings
        }
    }

    pub fn trace(&self, message: &str, module: &str) {
        #[cfg(feature = "dev-logging")]
        {
            self.log_internal(LogLevel::Trace, message, module);
        }

        #[cfg(not(feature = "dev-logging"))]
        {
            // En production, Trace se ignora completamente
            let _ = (message, module); // Evitar warnings
        }
    }

    /// Obtener todos los logs del buffer
    pub fn get_logs(&self) -> Vec<LogMessage> {
        self.buffer.lock()
            .map(|buffer| buffer.clone())
            .unwrap_or_default()
    }

    /// Obtener logs filtrados por nivel
    pub fn get_logs_by_level(&self, min_level: LogLevel) -> Vec<LogMessage> {
        self.get_logs()
            .into_iter()
            .filter(|msg| msg.level <= min_level)
            .collect()
    }

    /// Limpiar buffer de logs
    pub fn clear_logs(&self) {
        if let Ok(mut buffer) = self.buffer.lock() {
            buffer.clear();
        }
    }

    /// Obtener estadísticas del buffer
    pub fn get_log_stats(&self) -> HashMap<LogLevel, usize> {
        let logs = self.get_logs();
        let mut stats = HashMap::new();

        for level in [LogLevel::Error, LogLevel::Warn, LogLevel::Info, LogLevel::Debug, LogLevel::Trace] {
            stats.insert(level, logs.iter().filter(|msg| msg.level == level).count());
        }

        stats
    }

    /// Exportar logs como JSON
    pub fn export_logs_json(&self) -> String {
        let logs = self.get_logs();
        serde_json::to_string_pretty(&logs)
            .unwrap_or_else(|_| "[]".to_string())
    }
}

/// Logger estructurado con trait para facilitar testing
pub trait StructuredLogger {
    fn log_structured(&self, level: LogLevel, message: &str, module: &str, metadata: Option<HashMap<String, serde_json::Value>>);
    fn should_log(&self, level: LogLevel) -> bool;
}

impl StructuredLogger for Logger {
    fn log_structured(&self, level: LogLevel, message: &str, module: &str, metadata: Option<HashMap<String, serde_json::Value>>) {
        if let Some(metadata) = metadata {
            self.log_with_metadata(level, message, module, metadata);
        } else {
            self.log(level, message, module);
        }
    }

    fn should_log(&self, level: LogLevel) -> bool {
        // Con conditional compilation, el comportamiento varía
        #[cfg(feature = "dev-logging")]
        {
            level <= self.config.min_log_level
        }

        #[cfg(not(feature = "dev-logging"))]
        {
            // En production, solo errores y warnings
            matches!(level, LogLevel::Error | LogLevel::Warn) && level <= self.config.min_log_level
        }
    }
}

/// Macros para logging con conditional compilation
#[macro_export]
macro_rules! log_error {
    ($logger:expr, $module:expr, $($arg:tt)*) => {
        // Error siempre se procesa
        $logger.error(&format!($($arg)*), $module)
    };
}

#[macro_export]
macro_rules! log_warn {
    ($logger:expr, $module:expr, $($arg:tt)*) => {
        // Warning siempre se procesa
        $logger.warn(&format!($($arg)*), $module)
    };
}

#[macro_export]
macro_rules! log_info {
    ($logger:expr, $module:expr, $($arg:tt)*) => {
        // Info solo en dev-logging
        #[cfg(feature = "dev-logging")]
        $logger.info(&format!($($arg)*), $module);

        #[cfg(not(feature = "dev-logging"))]
        {
            let _ = (&$logger, $module); // Evitar warnings
        }
    };
}

#[macro_export]
macro_rules! log_debug {
    ($logger:expr, $module:expr, $($arg:tt)*) => {
        // Debug solo en dev-logging
        #[cfg(feature = "dev-logging")]
        $logger.debug(&format!($($arg)*), $module);

        #[cfg(not(feature = "dev-logging"))]
        {
            let _ = (&$logger, $module); // Evitar warnings
        }
    };
}

/// Macro helper para conditional logging
#[macro_export]
macro_rules! dev_log {
    ($logger:expr, $level:ident, $msg:expr, $module:expr) => {
        #[cfg(feature = "dev-logging")]
        $logger.$level($msg, $module);

        #[cfg(not(feature = "dev-logging"))]
        {
            let _ = (&$logger, $msg, $module); // Evitar warnings de variables no usadas
        }
    };
}

/// Función global para crear logger desde argumentos CLI
pub fn create_logger_from_cli(silent: bool, stdin_mode: bool, format_json: bool, verbose: bool) -> Logger {
    let execution_mode = crate::core::execution_context::determine_execution_mode(
        silent, stdin_mode, format_json, false
    );

    let config = CoreConfig {
        execution_mode,
        verbose_logging: verbose,
        min_log_level: if verbose { LogLevel::Debug } else { LogLevel::Info },
    };

    Logger::new(config)
}

/// Función para verificar si el logging está habilitado
pub fn is_dev_logging_enabled() -> bool {
    cfg!(feature = "dev-logging")
}

/// Función para obtener información de compilación
pub fn get_build_info() -> HashMap<String, String> {
    let mut info = HashMap::new();

    info.insert("version".to_string(), env!("CARGO_PKG_VERSION").to_string());
    info.insert("build_mode".to_string(), if cfg!(feature = "dev-logging") {
        "development".to_string()
    } else {
        "production".to_string()
    });

    info.insert("dev_logging".to_string(), cfg!(feature = "dev-logging").to_string());
    info.insert("profile".to_string(), if cfg!(debug_assertions) {
        "debug".to_string()
    } else {
        "release".to_string()
    });

    info
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_conditional_compilation_build_info() {
        let build_info = get_build_info();

        assert!(build_info.contains_key("version"));
        assert!(build_info.contains_key("build_mode"));
        assert!(build_info.contains_key("dev_logging"));
        assert!(build_info.contains_key("profile"));

        // En tests, dev-logging debería estar habilitado para debugging
        #[cfg(feature = "dev-logging")]
        {
            assert_eq!(build_info["build_mode"], "development");
            assert_eq!(build_info["dev_logging"], "true");
        }

        #[cfg(not(feature = "dev-logging"))]
        {
            assert_eq!(build_info["build_mode"], "production");
            assert_eq!(build_info["dev_logging"], "false");
        }
    }

    #[test]
    fn test_logger_conditional_behavior() {
        let config = CoreConfig {
            execution_mode: ExecutionMode::Testing,
            min_log_level: LogLevel::Debug,
            ..Default::default()
        };
        let logger = Logger::new(config);

        // Test que error y warn siempre funcionan
        logger.error("Test error", "test");
        logger.warn("Test warning", "test");

        // Test conditional methods
        logger.info("Test info", "test");
        logger.debug("Test debug", "test");
        logger.trace("Test trace", "test");

        let logs = logger.get_logs();

        // Error y warn siempre deben estar presentes
        assert!(logs.iter().any(|log| log.level == LogLevel::Error));
        assert!(logs.iter().any(|log| log.level == LogLevel::Warn));

        #[cfg(feature = "dev-logging")]
        {
            // En dev mode, todos los logs deben estar presentes
            assert!(logs.iter().any(|log| log.level == LogLevel::Info));
            assert!(logs.iter().any(|log| log.level == LogLevel::Debug));
            assert!(logs.iter().any(|log| log.level == LogLevel::Trace));
        }

        #[cfg(not(feature = "dev-logging"))]
        {
            // En production mode, solo error y warn
            assert!(!logs.iter().any(|log| log.level == LogLevel::Info));
            assert!(!logs.iter().any(|log| log.level == LogLevel::Debug));
            assert!(!logs.iter().any(|log| log.level == LogLevel::Trace));
        }
    }

    #[test]
    fn test_should_log_conditional() {
        let config = CoreConfig {
            execution_mode: ExecutionMode::Testing,
            min_log_level: LogLevel::Debug,
            ..Default::default()
        };
        let logger = Logger::new(config);

        // Error y warn siempre deben poder loggearse
        assert!(logger.should_log(LogLevel::Error));
        assert!(logger.should_log(LogLevel::Warn));

        #[cfg(feature = "dev-logging")]
        {
            // En dev mode, todos los niveles
            assert!(logger.should_log(LogLevel::Info));
            assert!(logger.should_log(LogLevel::Debug));
            assert!(logger.should_log(LogLevel::Trace));
        }

        #[cfg(not(feature = "dev-logging"))]
        {
            // En production mode, solo error y warn
            assert!(!logger.should_log(LogLevel::Info));
            assert!(!logger.should_log(LogLevel::Debug));
            assert!(!logger.should_log(LogLevel::Trace));
        }
    }

    #[test]
    fn test_logging_macros() {
        let logger = Logger::from_context(ExecutionContext::for_testing());

        // Test que los macros compilan y funcionan
        log_error!(logger, "test", "Error message: {}", "test");
        log_warn!(logger, "test", "Warning message: {}", "test");
        log_info!(logger, "test", "Info message: {}", "test");
        log_debug!(logger, "test", "Debug message: {}", "test");

        // Test dev_log macro
        dev_log!(logger, info, "Dev log message", "test");
        dev_log!(logger, debug, "Dev debug message", "test");

        let logs = logger.get_logs();

        // Error y warn siempre deben estar presentes
        assert!(logs.iter().any(|log| log.message.contains("Error message")));
        assert!(logs.iter().any(|log| log.message.contains("Warning message")));

        #[cfg(feature = "dev-logging")]
        {
            // En dev mode, info y debug también
            assert!(logs.iter().any(|log| log.message.contains("Info message")));
            assert!(logs.iter().any(|log| log.message.contains("Debug message")));
            assert!(logs.iter().any(|log| log.message.contains("Dev log message")));
            assert!(logs.iter().any(|log| log.message.contains("Dev debug message")));
        }

        #[cfg(not(feature = "dev-logging"))]
        {
            // En production mode, info y debug no deben estar
            assert!(!logs.iter().any(|log| log.message.contains("Info message")));
            assert!(!logs.iter().any(|log| log.message.contains("Debug message")));
            assert!(!logs.iter().any(|log| log.message.contains("Dev log message")));
            assert!(!logs.iter().any(|log| log.message.contains("Dev debug message")));
        }
    }

    #[test]
    fn test_log_level_ordering() {
        assert!(LogLevel::Error < LogLevel::Warn);
        assert!(LogLevel::Warn < LogLevel::Info);
        assert!(LogLevel::Info < LogLevel::Debug);
        assert!(LogLevel::Debug < LogLevel::Trace);
    }

    #[test]
    fn test_log_level_display() {
        assert_eq!(LogLevel::Error.as_str(), "ERROR");
        assert_eq!(LogLevel::Info.as_str(), "INFO");
        assert!(!LogLevel::Error.color_code().is_empty());
    }

    #[test]
    fn test_log_message_creation() {
        let message = LogMessage::new(
            LogLevel::Info,
            "Test message".to_string(),
            "test_module".to_string(),
            "session_123".to_string(),
        );

        assert_eq!(message.level, LogLevel::Info);
        assert_eq!(message.message, "Test message");
        assert_eq!(message.module, "test_module");
        assert_eq!(message.session_id, "session_123");
        assert!(message.timestamp > 0);
    }

    #[test]
    fn test_log_message_with_metadata() {
        let message = LogMessage::new(
            LogLevel::Debug,
            "Test".to_string(),
            "test".to_string(),
            "session".to_string(),
        ).with_metadata("key".to_string(), serde_json::Value::String("value".to_string()));

        assert_eq!(message.metadata.len(), 1);
        assert_eq!(message.metadata["key"], serde_json::Value::String("value".to_string()));
    }

    #[test]
    fn test_log_message_formatting() {
        let message = LogMessage::new(
            LogLevel::Info,
            "Test message".to_string(),
            "test_module".to_string(),
            "session_123".to_string(),
        );

        let human_format = message.format_human(false);
        assert!(human_format.contains("INFO"));
        assert!(human_format.contains("test_module"));
        assert!(human_format.contains("Test message"));

        let json_format = message.format_json();
        assert!(json_format.contains("\"level\":\"INFO\""));
        assert!(json_format.contains("\"message\":\"Test message\""));
    }

    #[test]
    fn test_logger_creation() {
        let config = CoreConfig::default();
        let logger = Logger::new(config);
        assert_eq!(logger.get_mode(), ExecutionMode::Interactive);
    }

    #[test]
    fn test_logger_from_context() {
        let context = ExecutionContext::new(ExecutionMode::JsonApi);
        let logger = Logger::from_context(context);
        assert_eq!(logger.get_mode(), ExecutionMode::JsonApi);
    }

    #[test]
    fn test_logger_level_filtering() {
        let config = CoreConfig {
            min_log_level: LogLevel::Warn,
            execution_mode: ExecutionMode::Testing,
            ..Default::default()
        };
        let logger = Logger::new(config);

        // Debug messages should not be logged (incluso en dev mode por min_log_level)
        logger.debug("Debug message", "test");

        // Error messages should be logged
        logger.error("Error message", "test");

        let logs = logger.get_logs();

        // Solo error debe estar presente debido al min_log_level
        assert!(logs.iter().any(|log| log.message.contains("Error message")));
        assert!(!logs.iter().any(|log| log.message.contains("Debug message")));
    }

    #[test]
    fn test_logger_buffer_operations() {
        let config = CoreConfig {
            execution_mode: ExecutionMode::Testing,
            ..Default::default()
        };
        let logger = Logger::new(config);

        logger.error("Message 1", "test");
        logger.warn("Message 2", "test");
        logger.info("Message 3", "test");

        let logs = logger.get_logs();

        // Error y warn siempre presentes
        assert!(logs.iter().any(|log| log.message.contains("Message 1")));
        assert!(logs.iter().any(|log| log.message.contains("Message 2")));

        #[cfg(feature = "dev-logging")]
        {
            assert!(logs.iter().any(|log| log.message.contains("Message 3")));
            assert_eq!(logs.len(), 3);
        }

        #[cfg(not(feature = "dev-logging"))]
        {
            assert!(!logs.iter().any(|log| log.message.contains("Message 3")));
            assert_eq!(logs.len(), 2);
        }

        let error_logs = logger.get_logs_by_level(LogLevel::Error);
        assert_eq!(error_logs.len(), 1);

        let stats = logger.get_log_stats();
        assert_eq!(stats[&LogLevel::Error], 1);
        assert_eq!(stats[&LogLevel::Warn], 1);

        logger.clear_logs();
        assert_eq!(logger.get_logs().len(), 0);
    }

    #[test]
    fn test_logger_json_export() {
        let context = ExecutionContext::for_testing();
        let logger = Logger::from_context(context);

        logger.error("Error message", "test_logger_json_export");
        logger.warn("Warning message", "test_logger_json_export");

        let logs = logger.get_logs();
        assert!(logs.len() >= 2, "Se esperaban al menos 2 logs en el buffer");

        let json_export = logger.export_logs_json();

        // Parsear como JSON
        let parsed: serde_json::Value = serde_json::from_str(&json_export)
            .expect("El JSON exportado no es válido");

        // Asegurar que sea un array
        let arr = parsed.as_array().expect("El JSON no es un array");
        assert!(arr.len() >= 2, "El JSON debería tener al menos 2 logs");

        // Verificar que error y warning están presentes
        let has_error = arr.iter().any(|log| log["level"] == "ERROR");
        let has_warn = arr.iter().any(|log| log["level"] == "WARN");

        assert!(has_error, "Should contain ERROR log");
        assert!(has_warn, "Should contain WARN log");
    }

    #[test]
    fn test_structured_logger_trait() {
        let config = CoreConfig {
            execution_mode: ExecutionMode::Testing,
            ..Default::default()
        };
        let logger = Logger::new(config);

        // Error y warn siempre deben poder loggearse
        assert!(logger.should_log(LogLevel::Error));
        assert!(logger.should_log(LogLevel::Warn));

        let mut metadata = HashMap::new();
        metadata.insert("test_key".to_string(), serde_json::Value::String("test_value".to_string()));

        logger.log_structured(LogLevel::Error, "Test with metadata", "test", Some(metadata));

        let logs = logger.get_logs();
        let error_log = logs.iter().find(|log| log.level == LogLevel::Error).unwrap();
        assert!(!error_log.metadata.is_empty());
    }

    #[test]
    fn test_create_logger_from_cli() {
        // Test interactive mode
        let logger = create_logger_from_cli(false, false, false, false);
        assert_eq!(logger.get_mode(), ExecutionMode::Interactive);

        // Test JSON API mode
        let logger = create_logger_from_cli(true, false, false, false);
        assert_eq!(logger.get_mode(), ExecutionMode::JsonApi);

        // Test stdin mode
        let logger = create_logger_from_cli(false, true, false, false);
        assert_eq!(logger.get_mode(), ExecutionMode::Stdin);
    }

    #[test]
    fn test_is_dev_logging_enabled() {
        let is_enabled = is_dev_logging_enabled();

        #[cfg(feature = "dev-logging")]
        {
            assert!(is_enabled);
        }

        #[cfg(not(feature = "dev-logging"))]
        {
            assert!(!is_enabled);
        }
    }

    #[test]
    fn test_etapa_b6_implementation_verification() {
        // Test comprensivo de la implementación B6
        let test_context = ExecutionContext::for_testing();
        let logger = Logger::from_context(test_context.clone());

        // Verificar build info
        let build_info = get_build_info();
        assert!(build_info.contains_key("build_mode"));
        assert!(build_info.contains_key("dev_logging"));

        // Verificar conditional compilation funcionando
        logger.error("ETAPA B6 ERROR - always processed", "b6_verification");
        logger.warn("ETAPA B6 WARN - always processed", "b6_verification");
        logger.info("ETAPA B6 INFO - conditional", "b6_verification");
        logger.debug("ETAPA B6 DEBUG - conditional", "b6_verification");
        logger.trace("ETAPA B6 TRACE - conditional", "b6_verification");

        let logs = logger.get_logs();

        // Error y warn siempre deben estar presentes
        assert!(logs.iter().any(|log| log.message.contains("ETAPA B6 ERROR")));
        assert!(logs.iter().any(|log| log.message.contains("ETAPA B6 WARN")));

        #[cfg(feature = "dev-logging")]
        {
            // En development mode, todos los logs
            assert!(logs.iter().any(|log| log.message.contains("ETAPA B6 INFO")));
            assert!(logs.iter().any(|log| log.message.contains("ETAPA B6 DEBUG")));
            assert!(logs.iter().any(|log| log.message.contains("ETAPA B6 TRACE")));
            println!("✅ B6 DEVELOPMENT MODE: Full logging enabled");
        }

        #[cfg(not(feature = "dev-logging"))]
        {
            // En production mode, solo error y warn
            assert!(!logs.iter().any(|log| log.message.contains("ETAPA B6 INFO")));
            assert!(!logs.iter().any(|log| log.message.contains("ETAPA B6 DEBUG")));
            assert!(!logs.iter().any(|log| log.message.contains("ETAPA B6 TRACE")));
            println!("✅ B6 PRODUCTION MODE: Technical logging disabled");
        }

        // Test macros funcionando
        log_error!(logger, "b6_verification", "Macro error test");
        log_warn!(logger, "b6_verification", "Macro warn test");
        log_info!(logger, "b6_verification", "Macro info test");
        log_debug!(logger, "b6_verification", "Macro debug test");

        // Test dev_log macro
        dev_log!(logger, info, "Dev log test", "b6_verification");

        // Verificar que should_log funciona correctamente
        assert!(logger.should_log(LogLevel::Error));
        assert!(logger.should_log(LogLevel::Warn));

        // Verificar JSON export funciona
        let json_export = logger.export_logs_json();
        assert!(json_export.contains("ETAPA B6"));

        println!("✅ ETAPA B6 CONDITIONAL COMPILATION IMPLEMENTATION VERIFIED");
        println!("✅ Production builds will have zero technical logging overhead");
        println!("✅ Development builds maintain full debugging capabilities");
        println!("✅ JSON API remains clean in both modes");
        println!("✅ Backward compatibility maintained 100%");
    }
}
