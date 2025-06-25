//! src/core/execution_context.rs
//! Contexto de ejecución para determinar el comportamiento de logging y output
//!
//! Este módulo proporciona la lógica para determinar cómo debe comportarse
//! la aplicación según el modo de ejecución (interactivo, JSON, silent, etc.)

use crate::error::{SCypherError, Result};
use std::collections::HashMap;
use serde::{Serialize, Deserialize};

/// Modos de ejecución disponibles
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ExecutionMode {
    /// Modo interactivo con menús bonitos y output colorido
    Interactive,
    /// Modo JSON API para integración con Electron
    JsonApi,
    /// Modo silencioso para scripts y automatización
    Silent,
    /// Modo de entrada desde stdin
    Stdin,
    /// Modo de testing (sin output externo)
    Testing,
}

impl ExecutionMode {
    /// Verificar si el modo permite output colorido
    pub fn supports_colors(&self) -> bool {
        matches!(self, Self::Interactive)
    }

    /// Verificar si el modo permite logs de debug
    pub fn allows_debug_logs(&self) -> bool {
        matches!(self, Self::Interactive | Self::Testing)
    }

    /// Verificar si el modo requiere output JSON estricto
    pub fn requires_json_output(&self) -> bool {
        matches!(self, Self::JsonApi)
    }

    /// Verificar si el modo debe suprimir println! de debug
    pub fn should_suppress_debug_prints(&self) -> bool {
    matches!(self, Self::JsonApi | Self::Silent)
    // TODO: Agregar Self::Testing cuando completemos Plan B completo (B2-B6)
    // Final: matches!(self, Self::JsonApi | Self::Silent | Self::Testing)
    }

    /// Obtener prioridad para determinar modo desde flags CLI
    pub fn priority(&self) -> u8 {
        match self {
            Self::JsonApi => 10,    // Máxima prioridad (--silent)
            Self::Silent => 9,      // Alta prioridad
            Self::Stdin => 8,       // Prioridad media (--stdin)
            Self::Testing => 7,     // Prioridad media
            Self::Interactive => 1, // Prioridad baja (default)
        }
    }
}

impl std::fmt::Display for ExecutionMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Interactive => write!(f, "interactive"),
            Self::JsonApi => write!(f, "json-api"),
            Self::Silent => write!(f, "silent"),
            Self::Stdin => write!(f, "stdin"),
            Self::Testing => write!(f, "testing"),
        }
    }
}

/// Contexto de ejecución con metadatos
#[derive(Debug, Clone)]
pub struct ExecutionContext {
    /// Modo de ejecución actual
    mode: ExecutionMode,
    /// Metadatos adicionales del contexto
    metadata: HashMap<String, String>,
    /// Timestamp de creación
    created_at: std::time::SystemTime,
    /// ID único de sesión
    session_id: String,
}

impl ExecutionContext {
    /// Crear nuevo contexto de ejecución
    pub fn new(mode: ExecutionMode) -> Self {
        Self {
            mode,
            metadata: HashMap::new(),
            created_at: std::time::SystemTime::now(),
            session_id: Self::generate_session_id(),
        }
    }

    /// Obtener el modo de ejecución
    pub fn get_mode(&self) -> ExecutionMode {
        self.mode
    }

    /// Cambiar el modo de ejecución
    pub fn set_mode(&mut self, mode: ExecutionMode) {
        self.mode = mode;
    }

    /// Agregar metadato al contexto
    pub fn add_metadata(&mut self, key: String, value: String) {
        self.metadata.insert(key, value);
    }

    /// Obtener metadato del contexto
    pub fn get_metadata(&self, key: &str) -> Option<&String> {
        self.metadata.get(key)
    }

    /// Obtener todos los metadatos
    pub fn get_all_metadata(&self) -> &HashMap<String, String> {
        &self.metadata
    }

    /// Obtener timestamp de creación
    pub fn created_at(&self) -> std::time::SystemTime {
        self.created_at
    }

    /// Obtener ID de sesión
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    /// Verificar si debe mostrar output debug
    pub fn should_show_debug(&self) -> bool {
        self.mode.allows_debug_logs()
    }

    /// Verificar si debe usar colores
    pub fn should_use_colors(&self) -> bool {
        self.mode.supports_colors()
    }

    /// Verificar si debe suprimir println! de debug
    pub fn should_suppress_debug_prints(&self) -> bool {
        self.mode.should_suppress_debug_prints()
    }

    /// Verificar si requiere output JSON
    pub fn requires_json_output(&self) -> bool {
        self.mode.requires_json_output()
    }

    /// Generar ID de sesión único
    fn generate_session_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos(); // Usar nanosegundos en lugar de milisegundos

    // Agregar un componente aleatorio adicional
    let random_part = std::thread::current().id();

    format!("scypher_{}_{:?}", timestamp, random_part)
    }

    /// Crear contexto desde argumentos CLI
    pub fn from_cli_args(
        silent: bool,
        stdin_mode: bool,
        format_json: bool,
    ) -> Self {
        let mode = if silent {
            ExecutionMode::JsonApi
        } else if stdin_mode {
            ExecutionMode::Stdin
        } else if format_json {
            ExecutionMode::JsonApi
        } else {
            ExecutionMode::Interactive
        };

        let mut context = Self::new(mode);

        // Agregar metadatos relevantes
        context.add_metadata("cli_silent".to_string(), silent.to_string());
        context.add_metadata("cli_stdin".to_string(), stdin_mode.to_string());
        context.add_metadata("cli_format_json".to_string(), format_json.to_string());

        context
    }

    /// Crear contexto para testing
    pub fn for_testing() -> Self {
        Self::new(ExecutionMode::Testing)
    }

    /// Serializar contexto para logs estructurados
    pub fn to_log_metadata(&self) -> serde_json::Value {
        serde_json::json!({
            "mode": self.mode.to_string(),
            "session_id": self.session_id,
            "created_at": self.created_at
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            "metadata": self.metadata
        })
    }
}

/// Determinar modo de ejecución desde múltiples flags (con prioridades)
pub fn determine_execution_mode(
    silent: bool,
    stdin_mode: bool,
    format_json: bool,
    is_testing: bool,
) -> ExecutionMode {
    let mut candidates = Vec::new();

    if is_testing {
        candidates.push(ExecutionMode::Testing);
    }
    if silent {
        candidates.push(ExecutionMode::JsonApi);
    }
    if stdin_mode {
        candidates.push(ExecutionMode::Stdin);
    }
    if format_json {
        candidates.push(ExecutionMode::JsonApi);
    }

    // Si no hay flags específicos, usar modo interactivo
    if candidates.is_empty() {
        return ExecutionMode::Interactive;
    }

    // Retornar el modo con mayor prioridad
    candidates
        .into_iter()
        .max_by_key(|mode| mode.priority())
        .unwrap_or(ExecutionMode::Interactive)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_execution_mode_properties() {
        assert!(ExecutionMode::Interactive.supports_colors());
        assert!(!ExecutionMode::JsonApi.supports_colors());

        assert!(ExecutionMode::Interactive.allows_debug_logs());
        assert!(!ExecutionMode::JsonApi.allows_debug_logs());

        assert!(ExecutionMode::JsonApi.requires_json_output());
        assert!(!ExecutionMode::Interactive.requires_json_output());

        assert!(ExecutionMode::JsonApi.should_suppress_debug_prints());
        assert!(!ExecutionMode::Interactive.should_suppress_debug_prints());
    }

    #[test]
    fn test_execution_mode_priority() {
        assert!(ExecutionMode::JsonApi.priority() > ExecutionMode::Interactive.priority());
        assert!(ExecutionMode::Silent.priority() > ExecutionMode::Stdin.priority());
    }

    #[test]
    fn test_execution_context_creation() {
        let context = ExecutionContext::new(ExecutionMode::Interactive);
        assert_eq!(context.get_mode(), ExecutionMode::Interactive);
        assert!(!context.session_id().is_empty());
        assert!(context.get_all_metadata().is_empty());
    }

    #[test]
    fn test_execution_context_metadata() {
        let mut context = ExecutionContext::new(ExecutionMode::JsonApi);
        context.add_metadata("test_key".to_string(), "test_value".to_string());

        assert_eq!(context.get_metadata("test_key"), Some(&"test_value".to_string()));
        assert_eq!(context.get_metadata("nonexistent"), None);
        assert_eq!(context.get_all_metadata().len(), 1);
    }

    #[test]
    fn test_execution_context_from_cli_args() {
        // Test silent mode
        let context = ExecutionContext::from_cli_args(true, false, false);
        assert_eq!(context.get_mode(), ExecutionMode::JsonApi);

        // Test stdin mode
        let context = ExecutionContext::from_cli_args(false, true, false);
        assert_eq!(context.get_mode(), ExecutionMode::Stdin);

        // Test interactive mode
        let context = ExecutionContext::from_cli_args(false, false, false);
        assert_eq!(context.get_mode(), ExecutionMode::Interactive);
    }

    #[test]
    fn test_determine_execution_mode() {
        // Test prioridades
        assert_eq!(
            determine_execution_mode(true, true, false, false),
            ExecutionMode::JsonApi // silent tiene prioridad sobre stdin
        );

        assert_eq!(
            determine_execution_mode(false, true, false, false),
            ExecutionMode::Stdin
        );

        assert_eq!(
            determine_execution_mode(false, false, false, false),
            ExecutionMode::Interactive
        );

        assert_eq!(
            determine_execution_mode(false, false, false, true),
            ExecutionMode::Testing
        );
    }

    #[test]
    fn test_execution_context_serialization() {
        let context = ExecutionContext::new(ExecutionMode::JsonApi);
        let metadata = context.to_log_metadata();

        assert_eq!(metadata["mode"], "json-api");
        assert!(metadata["session_id"].is_string());
        assert!(metadata["created_at"].is_number());
    }

    #[test]
    fn test_session_id_uniqueness() {
        let context1 = ExecutionContext::new(ExecutionMode::Interactive);
        let context2 = ExecutionContext::new(ExecutionMode::Interactive);

        // Los IDs deben ser diferentes
        assert_ne!(context1.session_id(), context2.session_id());
    }
}
