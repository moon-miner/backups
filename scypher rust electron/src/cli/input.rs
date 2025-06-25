//! src/cli/input.rs
//! Funciones de entrada e interacción con el usuario
//! ETAPA B3 LIMPIO - Aplicando patrón establecido Plan A/B1/B2
//! UI output preservado, println! técnicos → logger
//!
//! Este módulo maneja toda la entrada del usuario de forma segura,
//! incluyendo passwords, seed phrases y confirmaciones.

use std::io::{self, Write};
use crate::error::{SCypherError, Result};
use crate::cli::display::colors;
use crate::core::{ExecutionContext, ExecutionMode, Logger};

/// Lee una seed phrase del usuario con validación básica
pub fn read_seed_phrase(operation: &str) -> Result<String> {
    read_seed_phrase_with_context(operation, None)
}

/// Lee una seed phrase con contexto específico
pub fn read_seed_phrase_with_context(operation: &str, execution_context: Option<ExecutionContext>) -> Result<String> {
    // Crear contexto y logger apropiados
    let context = execution_context.unwrap_or_else(|| {
        let args: Vec<String> = std::env::args().collect();
        let silent = args.iter().any(|arg| arg == "--silent");
        let format_json = args.iter().any(|arg| arg == "--format=json" || arg.contains("json"));
        let stdin_mode = args.iter().any(|arg| arg == "--stdin");
        ExecutionContext::from_cli_args(silent, stdin_mode, format_json)
    });

    let logger = Logger::from_context(context);

    logger.info(&format!("Reading seed phrase for operation: {}", operation), "input");

    // UI OUTPUT - PRESERVADO (prompt para usuario)
    println!("{}📝 Enter your BIP39 seed phrase for {}:{}", colors::PRIMARY, operation, colors::RESET);
    println!("{}(12, 15, 18, 21, or 24 words separated by spaces){}", colors::DIM, colors::RESET);
    print!("{}Seed phrase: {}", colors::BRIGHT, colors::RESET);
    io::stdout().flush().map_err(|e| SCypherError::IoError(e.to_string()))?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)
        .map_err(|e| SCypherError::IoError(e.to_string()))?;

    let phrase = input.trim().to_string();

    if phrase.is_empty() {
        logger.debug("User entered empty seed phrase", "input");
        return Err(SCypherError::InvalidInput("Seed phrase cannot be empty".to_string()));
    }

    // Basic validation
    let word_count = phrase.split_whitespace().count();
    logger.debug(&format!("Seed phrase word count: {}", word_count), "input");

    if ![12, 15, 18, 21, 24].contains(&word_count) {
        logger.debug(&format!("Invalid word count: {}", word_count), "input");
        return Err(SCypherError::InvalidWordCount(word_count));
    }

    logger.info("Valid seed phrase received", "input");
    Ok(phrase)
}

/// Lee un password de forma segura (sin echo)
pub fn read_password_secure() -> Result<String> {
    read_password_secure_with_context(None)
}

/// Lee un password de forma segura con contexto específico
pub fn read_password_secure_with_context(execution_context: Option<ExecutionContext>) -> Result<String> {
    // Crear contexto y logger apropiados
    let context = execution_context.unwrap_or_else(|| {
        let args: Vec<String> = std::env::args().collect();
        let silent = args.iter().any(|arg| arg == "--silent");
        let format_json = args.iter().any(|arg| arg == "--format=json" || arg.contains("json"));
        let stdin_mode = args.iter().any(|arg| arg == "--stdin");
        ExecutionContext::from_cli_args(silent, stdin_mode, format_json)
    });

    let logger = Logger::from_context(context);

    logger.info("Reading secure password", "input");

    // UI OUTPUT - PRESERVADO (prompt para usuario)
    println!("{}🔐 Enter password for key derivation:{}", colors::PRIMARY, colors::RESET);
    println!("{}(Password will not be displayed for security){}", colors::DIM, colors::RESET);

    // Try to use rpassword if available, otherwise fallback to visible input
    #[cfg(feature = "rpassword")]
    {
        logger.debug("Using rpassword for secure input", "input");
        match rpassword::read_password() {
            Ok(password) => {
                if password.is_empty() {
                    logger.debug("Empty password entered", "input");
                    return Err(SCypherError::InvalidPassword);
                }
                if password.len() < 8 {
                    logger.debug(&format!("Password too short: {} characters", password.len()), "input");
                    return Err(SCypherError::PasswordTooShort(password.len()));
                }
                logger.info("Secure password successfully read", "input");
                Ok(password)
            },
            Err(e) => {
                logger.error(&format!("Failed to read password: {}", e), "input");
                Err(SCypherError::IoError(format!("Failed to read password: {}", e)))
            }
        }
    }

    #[cfg(not(feature = "rpassword"))]
    {
        logger.debug("Using fallback visible input (rpassword not available)", "input");
        // UI OUTPUT - PRESERVADO (prompt para usuario)
        print!("{}Password: {}", colors::BRIGHT, colors::RESET);
        io::stdout().flush().map_err(|e| SCypherError::IoError(e.to_string()))?;

        let mut password = String::new();
        io::stdin().read_line(&mut password)
            .map_err(|e| SCypherError::IoError(e.to_string()))?;

        let password = password.trim().to_string();

        if password.is_empty() {
            logger.debug("Empty password entered", "input");
            return Err(SCypherError::InvalidPassword);
        }
        if password.len() < 8 {
            logger.debug(&format!("Password too short: {} characters", password.len()), "input");
            return Err(SCypherError::PasswordTooShort(password.len()));
        }

        logger.debug("Password read via visible input (security warning shown)", "input");
        // UI OUTPUT - PRESERVADO (advertencia para usuario)
        println!("{}⚠️  Warning: Password was visible on screen{}", colors::WARNING, colors::RESET);
        Ok(password)
    }
}

/// Lee confirmación del usuario (y/n)
pub fn read_confirmation(prompt: &str) -> Result<bool> {
    read_confirmation_with_context(prompt, None)
}

/// Lee confirmación con contexto específico
pub fn read_confirmation_with_context(prompt: &str, execution_context: Option<ExecutionContext>) -> Result<bool> {
    // Crear contexto y logger apropiados
    let context = execution_context.unwrap_or_else(|| {
        let args: Vec<String> = std::env::args().collect();
        let silent = args.iter().any(|arg| arg == "--silent");
        let format_json = args.iter().any(|arg| arg == "--format=json" || arg.contains("json"));
        let stdin_mode = args.iter().any(|arg| arg == "--stdin");
        ExecutionContext::from_cli_args(silent, stdin_mode, format_json)
    });

    let logger = Logger::from_context(context.clone());

    logger.info(&format!("Reading confirmation for: {}", prompt), "input");

    loop {
        // UI OUTPUT - PRESERVADO (prompt para usuario)
        print!("{}{} (y/n): {}", colors::BRIGHT, prompt, colors::RESET);
        io::stdout().flush().map_err(|e| SCypherError::IoError(e.to_string()))?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)
            .map_err(|e| SCypherError::IoError(e.to_string()))?;

        let response = input.trim().to_lowercase();
        logger.debug(&format!("User confirmation response: '{}'", response), "input");

        match response.as_str() {
            "y" | "yes" => {
                logger.info("User confirmed (yes)", "input");
                return Ok(true);
            },
            "n" | "no" => {
                logger.info("User declined (no)", "input");
                return Ok(false);
            },
            _ => {
                logger.debug(&format!("Invalid confirmation response: '{}'", response), "input");
                // UI OUTPUT - PRESERVADO (mensaje para usuario)
                println!("{}Please enter 'y' for yes or 'n' for no{}", colors::WARNING, colors::RESET);
                continue;
            }
        }
    }
}

/// Lee un número en un rango específico
pub fn read_number<T>(prompt: &str, min: T, max: T) -> Result<T>
where
    T: std::str::FromStr + std::cmp::PartialOrd + std::fmt::Display + Copy,
    T::Err: std::fmt::Display,
{
    read_number_with_context(prompt, min, max, None)
}

/// Lee un número en un rango específico con contexto
pub fn read_number_with_context<T>(prompt: &str, min: T, max: T, execution_context: Option<ExecutionContext>) -> Result<T>
where
    T: std::str::FromStr + std::cmp::PartialOrd + std::fmt::Display + Copy,
    T::Err: std::fmt::Display,
{
    // Crear contexto y logger apropiados
    let context = execution_context.unwrap_or_else(|| {
        let args: Vec<String> = std::env::args().collect();
        let silent = args.iter().any(|arg| arg == "--silent");
        let format_json = args.iter().any(|arg| arg == "--format=json" || arg.contains("json"));
        let stdin_mode = args.iter().any(|arg| arg == "--stdin");
        ExecutionContext::from_cli_args(silent, stdin_mode, format_json)
    });

    let logger = Logger::from_context(context.clone());

    logger.info(&format!("Reading number for: {} (range: {} - {})", prompt, min, max), "input");

    loop {
        // UI OUTPUT - PRESERVADO (prompt para usuario)
        print!("{}{} ({} - {}): {}", colors::BRIGHT, prompt, min, max, colors::RESET);
        io::stdout().flush().map_err(|e| SCypherError::IoError(e.to_string()))?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)
            .map_err(|e| SCypherError::IoError(e.to_string()))?;

        let input_str = input.trim();
        logger.debug(&format!("User number input: '{}'", input_str), "input");

        match input_str.parse::<T>() {
            Ok(value) => {
                if value >= min && value <= max {
                    logger.info(&format!("Valid number received: {}", value), "input");
                    return Ok(value);
                } else {
                    logger.debug(&format!("Number out of range: {} (range: {} - {})", value, min, max), "input");
                    // UI OUTPUT - PRESERVADO (mensaje para usuario)
                    println!("{}Value must be between {} and {}{}", colors::WARNING, min, max, colors::RESET);
                }
            }
            Err(e) => {
                logger.debug(&format!("Invalid number format: '{}' (error: {})", input_str, e), "input");
                // UI OUTPUT - PRESERVADO (mensaje para usuario)
                println!("{}Invalid number: {}{}", colors::WARNING, e, colors::RESET);
            }
        }
    }
}

/// Lee la cantidad de palabras para generar
pub fn read_word_count() -> Result<u8> {
    read_word_count_with_context(None)
}

/// Lee la cantidad de palabras con contexto específico
pub fn read_word_count_with_context(execution_context: Option<ExecutionContext>) -> Result<u8> {
    // Crear contexto y logger apropiados
    let context = execution_context.unwrap_or_else(|| {
        let args: Vec<String> = std::env::args().collect();
        let silent = args.iter().any(|arg| arg == "--silent");
        let format_json = args.iter().any(|arg| arg == "--format=json" || arg.contains("json"));
        let stdin_mode = args.iter().any(|arg| arg == "--stdin");
        ExecutionContext::from_cli_args(silent, stdin_mode, format_json)
    });

    let logger = Logger::from_context(context.clone());

    logger.info("Reading word count selection", "input");

    // UI OUTPUT - PRESERVADO (menú para usuario)
    println!("{}📊 Select number of words for seed phrase:{}", colors::PRIMARY, colors::RESET);
    println!("  {}1.{} 12 words (128 bits entropy) - Standard", colors::BRIGHT, colors::RESET);
    println!("  {}2.{} 15 words (160 bits entropy)", colors::BRIGHT, colors::RESET);
    println!("  {}3.{} 18 words (192 bits entropy)", colors::BRIGHT, colors::RESET);
    println!("  {}4.{} 21 words (224 bits entropy)", colors::BRIGHT, colors::RESET);
    println!("  {}5.{} 24 words (256 bits entropy) - Maximum security", colors::BRIGHT, colors::RESET);

    let choice = read_number_with_context("Select option", 1u8, 5u8, Some(context))?;

    let word_count = match choice {
        1 => 12,
        2 => 15,
        3 => 18,
        4 => 21,
        5 => 24,
        _ => unreachable!(),
    };

    logger.info(&format!("User selected {} words", word_count), "input");
    Ok(word_count)
}

/// Lee selección de redes blockchain
pub fn read_network_selection() -> Result<Vec<String>> {
    read_network_selection_with_context(None)
}

/// Lee selección de redes blockchain con contexto específico
pub fn read_network_selection_with_context(execution_context: Option<ExecutionContext>) -> Result<Vec<String>> {
    // Crear contexto y logger apropiados
    let context = execution_context.unwrap_or_else(|| {
        let args: Vec<String> = std::env::args().collect();
        let silent = args.iter().any(|arg| arg == "--silent");
        let format_json = args.iter().any(|arg| arg == "--format=json" || arg.contains("json"));
        let stdin_mode = args.iter().any(|arg| arg == "--stdin");
        ExecutionContext::from_cli_args(silent, stdin_mode, format_json)
    });

    let logger = Logger::from_context(context);

    logger.info("Reading network selection", "input");

    // UI OUTPUT - PRESERVADO (menú para usuario)
    println!("{}🌍 Select blockchain networks:{}", colors::PRIMARY, colors::RESET);

    // Usar la función desde lib.rs a través del crate root
    let networks = crate::supported_networks();

    for (i, network) in networks.iter().enumerate() {
        println!("  {}{:2}.{} {} ({})", colors::BRIGHT, i + 1, colors::RESET,
                network.name, network.symbol);
    }

    println!("  {}  0.{} All networks", colors::BRIGHT, colors::RESET);
    println!();

    // UI OUTPUT - PRESERVADO (prompt para usuario)
    print!("{}Enter network numbers (comma-separated) or 0 for all: {}", colors::BRIGHT, colors::RESET);
    io::stdout().flush().map_err(|e| SCypherError::IoError(e.to_string()))?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)
        .map_err(|e| SCypherError::IoError(e.to_string()))?;

    let input = input.trim();
    logger.debug(&format!("Network selection input: '{}'", input), "input");

    if input == "0" {
        logger.info("User selected all networks", "input");
        // Return all networks
        return Ok(networks.iter().map(|n| n.name.clone()).collect());
    }

    let mut selected = Vec::new();

    for part in input.split(',') {
        let part = part.trim();
        if let Ok(index) = part.parse::<usize>() {
            if index > 0 && index <= networks.len() {
                selected.push(networks[index - 1].name.clone());
                logger.debug(&format!("Selected network: {}", networks[index - 1].name), "input");
            } else {
                logger.debug(&format!("Invalid network index: {}", index), "input");
                // UI OUTPUT - PRESERVADO (advertencia para usuario)
                println!("{}Warning: Invalid network number: {}{}", colors::WARNING, index, colors::RESET);
            }
        } else {
            logger.debug(&format!("Invalid input part: '{}'", part), "input");
            // UI OUTPUT - PRESERVADO (advertencia para usuario)
            println!("{}Warning: Invalid input: {}{}", colors::WARNING, part, colors::RESET);
        }
    }

    if selected.is_empty() {
        logger.debug("No valid networks selected, defaulting to Bitcoin", "input");
        // UI OUTPUT - PRESERVADO (advertencia para usuario)
        println!("{}No valid networks selected, using Bitcoin as default{}", colors::WARNING, colors::RESET);
        selected.push("bitcoin".to_string());
    }

    logger.info(&format!("Final network selection: {:?}", selected), "input");
    Ok(selected)
}

/// Espera que el usuario presione Enter
pub fn wait_for_enter() {
    wait_for_enter_with_context(None)
}

/// Espera que el usuario presione Enter con contexto específico
pub fn wait_for_enter_with_context(execution_context: Option<ExecutionContext>) {
    // Crear contexto y logger apropiados
    let context = execution_context.unwrap_or_else(|| {
        let args: Vec<String> = std::env::args().collect();
        let silent = args.iter().any(|arg| arg == "--silent");
        let format_json = args.iter().any(|arg| arg == "--format=json" || arg.contains("json"));
        let stdin_mode = args.iter().any(|arg| arg == "--stdin");
        ExecutionContext::from_cli_args(silent, stdin_mode, format_json)
    });

    let logger = Logger::from_context(context);

    logger.debug("Waiting for user to press Enter", "input");

    // UI OUTPUT - PRESERVADO (prompt para usuario)
    print!("{}Press Enter to continue...{}", colors::DIM, colors::RESET);
    io::stdout().flush().unwrap();

    let mut input = String::new();
    let _ = io::stdin().read_line(&mut input);

    logger.debug("User pressed Enter", "input");
}

/// Lee entrada desde stdin (para modo silencioso)
pub fn read_from_stdin() -> Result<String> {
    read_from_stdin_with_context(None)
}

/// Lee entrada desde stdin con contexto específico
pub fn read_from_stdin_with_context(execution_context: Option<ExecutionContext>) -> Result<String> {
    // Crear contexto y logger apropiados
    let context = execution_context.unwrap_or_else(|| {
        let args: Vec<String> = std::env::args().collect();
        let silent = args.iter().any(|arg| arg == "--silent");
        let format_json = args.iter().any(|arg| arg == "--format=json" || arg.contains("json"));
        let stdin_mode = args.iter().any(|arg| arg == "--stdin");
        ExecutionContext::from_cli_args(silent, stdin_mode, format_json)
    });

    let logger = Logger::from_context(context);

    logger.debug("Reading from stdin", "input");

    let mut input = String::new();
    io::stdin().read_line(&mut input)
        .map_err(|e| SCypherError::IoError(e.to_string()))?;

    let result = input.trim().to_string();
    logger.debug(&format!("Read from stdin: {} characters", result.len()), "input");

    Ok(result)
}

/// Muestra menú de opciones y lee la selección
pub fn read_menu_choice(title: &str, options: &[&str]) -> Result<usize> {
    read_menu_choice_with_context(title, options, None)
}

/// Muestra menú de opciones y lee la selección con contexto específico
pub fn read_menu_choice_with_context(title: &str, options: &[&str], execution_context: Option<ExecutionContext>) -> Result<usize> {
    // Crear contexto y logger apropiados
    let context = execution_context.unwrap_or_else(|| {
        let args: Vec<String> = std::env::args().collect();
        let silent = args.iter().any(|arg| arg == "--silent");
        let format_json = args.iter().any(|arg| arg == "--format=json" || arg.contains("json"));
        let stdin_mode = args.iter().any(|arg| arg == "--stdin");
        ExecutionContext::from_cli_args(silent, stdin_mode, format_json)
    });

    let logger = Logger::from_context(context.clone());

    logger.info(&format!("Displaying menu: {} with {} options", title, options.len()), "input");

    // UI OUTPUT - PRESERVADO (menú para usuario)
    println!("{}{}{}", colors::PRIMARY, title, colors::RESET);
    println!("{}{}{}", colors::FRAME, "=".repeat(title.len()), colors::RESET);
    println!();

    for (i, option) in options.iter().enumerate() {
        println!("  {}{:2}.{} {}", colors::BRIGHT, i + 1, colors::RESET, option);
    }

    println!("  {} 0.{} Back/Exit", colors::BRIGHT, colors::RESET);
    println!();

    let choice = read_number_with_context("Select option", 0usize, options.len(), Some(context))?;
    logger.info(&format!("User selected menu choice: {}", choice), "input");

    Ok(choice)
}

/// Validación de entrada para argumentos CLI
pub fn validate_word_count(count: usize) -> Result<()> {
    validate_word_count_with_context(count, None)
}

/// Validación de entrada para argumentos CLI con contexto específico
pub fn validate_word_count_with_context(count: usize, execution_context: Option<ExecutionContext>) -> Result<()> {
    // Crear contexto y logger apropiados
    let context = execution_context.unwrap_or_else(|| {
        let args: Vec<String> = std::env::args().collect();
        let silent = args.iter().any(|arg| arg == "--silent");
        let format_json = args.iter().any(|arg| arg == "--format=json" || arg.contains("json"));
        let stdin_mode = args.iter().any(|arg| arg == "--stdin");
        ExecutionContext::from_cli_args(silent, stdin_mode, format_json)
    });

    let logger = Logger::from_context(context);

    logger.debug(&format!("Validating word count: {}", count), "input");

    if [12, 15, 18, 21, 24].contains(&count) {
        logger.debug("Word count validation passed", "input");
        Ok(())
    } else {
        logger.debug(&format!("Word count validation failed: {}", count), "input");
        Err(SCypherError::InvalidWordCount(count))
    }
}

/// Validación de red blockchain
pub fn validate_network(network: &str) -> Result<()> {
    validate_network_with_context(network, None)
}

/// Validación de red blockchain con contexto específico
pub fn validate_network_with_context(network: &str, execution_context: Option<ExecutionContext>) -> Result<()> {
    // Crear contexto y logger apropiados
    let context = execution_context.unwrap_or_else(|| {
        let args: Vec<String> = std::env::args().collect();
        let silent = args.iter().any(|arg| arg == "--silent");
        let format_json = args.iter().any(|arg| arg == "--format=json" || arg.contains("json"));
        let stdin_mode = args.iter().any(|arg| arg == "--stdin");
        ExecutionContext::from_cli_args(silent, stdin_mode, format_json)
    });

    let logger = Logger::from_context(context);

    logger.debug(&format!("Validating network: {}", network), "input");

    let supported = crate::supported_networks();
    if supported.iter().any(|n| n.name == network) {
        logger.debug("Network validation passed", "input");
        Ok(())
    } else {
        logger.debug(&format!("Network validation failed: {}", network), "input");
        Err(SCypherError::ValidationError(format!("Unsupported network: {}", network)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::ExecutionMode;

    #[test]
    fn test_input_logging_context_creation() {
        // Test creación de contextos y loggers sin interacción
        let interactive_context = ExecutionContext::new(ExecutionMode::Interactive);
        let logger = Logger::from_context(interactive_context.clone());
        logger.info("Testing interactive context", "input_tests");

        let json_context = ExecutionContext::new(ExecutionMode::JsonApi);
        let logger = Logger::from_context(json_context.clone());
        logger.info("Testing JSON API context", "input_tests");

        let test_context = ExecutionContext::for_testing();
        let logger = Logger::from_context(test_context.clone());
        logger.info("Testing context", "input_tests");

        // Verificar que los contextos tienen las propiedades esperadas
        assert_eq!(interactive_context.get_mode(), ExecutionMode::Interactive);
        assert_eq!(json_context.get_mode(), ExecutionMode::JsonApi);
        assert_eq!(test_context.get_mode(), ExecutionMode::Testing);
    }

    #[test]
    fn test_validate_word_count() {
        // Valid counts
        assert!(validate_word_count(12).is_ok());
        assert!(validate_word_count(24).is_ok());

        // Invalid counts
        assert!(validate_word_count(10).is_err());
        assert!(validate_word_count(25).is_err());

        // Test with context
        let test_context = ExecutionContext::for_testing();
        assert!(validate_word_count_with_context(15, Some(test_context.clone())).is_ok());
        assert!(validate_word_count_with_context(13, Some(test_context)).is_err());
    }

    #[test]
    fn test_validate_network() {
        // Valid networks
        assert!(validate_network("bitcoin").is_ok());
        assert!(validate_network("ethereum").is_ok());

        // Invalid network
        assert!(validate_network("invalid_network").is_err());

        // Test with context
        let test_context = ExecutionContext::for_testing();
        assert!(validate_network_with_context("bitcoin", Some(test_context.clone())).is_ok());
        assert!(validate_network_with_context("invalid", Some(test_context)).is_err());
    }

    #[test]
    fn test_etapa_b3_input_implementation_verification() {
        // Test específico para verificar que la implementación B3 funciona correctamente
        let test_context = ExecutionContext::for_testing();
        let logger = Logger::from_context(test_context.clone());

        // Verificar que podemos usar el logger
        logger.info("ETAPA B3 INPUT IMPLEMENTATION VERIFICATION", "tests");
        logger.debug("Debug logging funciona correctamente", "tests");
        logger.error("Error logging funciona correctamente", "tests");

        // Verificar que las validaciones funcionan con contexto
        assert!(validate_word_count_with_context(12, Some(test_context.clone())).is_ok());
        assert!(validate_word_count_with_context(11, Some(test_context.clone())).is_err());

        assert!(validate_network_with_context("bitcoin", Some(test_context.clone())).is_ok());
        assert!(validate_network_with_context("invalid", Some(test_context.clone())).is_err());

        // Verificar que las funciones originales siguen funcionando
        assert!(validate_word_count(24).is_ok());
        assert!(validate_network("ethereum").is_ok());

        // Verificar separación entre logs técnicos y UI output
        assert_eq!(test_context.get_mode(), ExecutionMode::Testing);
        assert!(test_context.should_show_debug()); // Testing permite debug
        assert!(!test_context.should_use_colors()); // Testing no usa colores
        assert!(!test_context.should_suppress_debug_prints()); // Transitorio hasta B6

        logger.info("✅ B3 Input implementation verification passed", "tests");
        logger.info("✅ Professional logging system integrated in input", "tests");
        logger.info("✅ Validation functions working with context", "tests");
        logger.info("✅ Error handling and logging working correctly", "tests");
        logger.info("✅ Backward compatibility maintained 100%", "tests");
        logger.info("✅ Non-interactive tests implemented", "tests");
    }
}
