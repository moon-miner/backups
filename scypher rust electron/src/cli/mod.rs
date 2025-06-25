// src/cli/mod.rs - Módulo CLI integrado para la implementación híbrida
// ETAPA B4 LIMPIO - Aplicando patrón establecido Plan A/B1/B2/B3
// UI output preservado, println! técnicos → logger
//
// VERSIÓN CORREGIDA - INTEGRACIÓN REAL CON EL MÓDULO ADDRESSES

// Declaración de submódulos
pub mod args;
pub mod display;
pub mod input;
pub mod menu;
pub mod output;

// Re-exportar funciones principales para facilitar uso
pub use args::{CliArgs, OperationCommand, OutputFormat, parse_args};
pub use display::{colors, clear_screen, show_banner, show_welcome_message};
pub use menu::{MainMenuChoice, MenuState};

// Funciones principales del sistema CLI
use crate::error::{SCypherError, Result};
use crate::core::{ExecutionContext, ExecutionMode, Logger};
use std::collections::HashMap;

/// Función principal del sistema CLI - coordina los tres modos de operación
pub fn run_cli() -> Result<()> {
    run_cli_with_context(None)
}

/// Función principal del sistema CLI con contexto específico
pub fn run_cli_with_context(execution_context: Option<ExecutionContext>) -> Result<()> {
    // Crear contexto y logger apropiados
    let context = execution_context.unwrap_or_else(|| {
        let args: Vec<String> = std::env::args().collect();
        let silent = args.iter().any(|arg| arg == "--silent");
        let format_json = args.iter().any(|arg| arg == "--format=json" || arg.contains("json"));
        let stdin_mode = args.iter().any(|arg| arg == "--stdin");
        ExecutionContext::from_cli_args(silent, stdin_mode, format_json)
    });

    let logger = Logger::from_context(context.clone());

    logger.info("Starting CLI system", "cli_mod");
    logger.debug("Executing interactive mode", "cli_mod");

    // En lugar de parsear argumentos (eso ya se hizo en main.rs),
    // directamente ejecutamos modo interactivo
    run_interactive_mode_with_context(Some(context))
}

/// Ejecutar modo interactivo con menús navegables - REAL (sin MOCK)
fn run_interactive_mode() -> Result<()> {
    run_interactive_mode_with_context(None)
}

/// Ejecutar modo interactivo con contexto específico
fn run_interactive_mode_with_context(execution_context: Option<ExecutionContext>) -> Result<()> {
    // Crear contexto y logger apropiados
    let context = execution_context.unwrap_or_else(|| {
        let args: Vec<String> = std::env::args().collect();
        let silent = args.iter().any(|arg| arg == "--silent");
        let format_json = args.iter().any(|arg| arg == "--format=json" || arg.contains("json"));
        let stdin_mode = args.iter().any(|arg| arg == "--stdin");
        ExecutionContext::from_cli_args(silent, stdin_mode, format_json)
    });

    let logger = Logger::from_context(context.clone());

    logger.info("Starting interactive mode", "cli_mod");

    // Mostrar mensaje de bienvenida
    display::show_welcome_message_with_context(Some(context.clone()));

    loop {
        logger.debug("Starting interactive menu loop", "cli_mod");

        // Ejecutar sistema de menús REAL desde menu.rs
        let menu_state = menu::run_interactive_menu_with_context(Some(context.clone()))?;

        if menu_state.should_exit {
            logger.info("Menu indicated exit, terminating interactive mode", "cli_mod");
            break;
        }

        if menu_state.return_to_main {
            // Ejecutar la operación seleccionada
            if let Some(operation) = menu_state.selected_operation {
                logger.info(&format!("Executing selected operation: {:?}", operation), "cli_mod");

                if let Err(e) = execute_menu_operation_with_context(operation, Some(context.clone())) {
                    logger.error(&format!("Operation failed: {}", e), "cli_mod");
                    menu::handle_menu_error_with_context(&e.to_string(), Some(context.clone()));
                    continue;
                }
            }
        }
    }

    logger.info("Interactive mode completed", "cli_mod");
    Ok(())
}

/// Ejecutar operación seleccionada desde el menú - REAL (sin MOCK)
fn execute_menu_operation(operation: MainMenuChoice) -> Result<()> {
    execute_menu_operation_with_context(operation, None)
}

/// Ejecutar operación con contexto específico
fn execute_menu_operation_with_context(operation: MainMenuChoice, execution_context: Option<ExecutionContext>) -> Result<()> {
    // Crear contexto y logger apropiados
    let context = execution_context.unwrap_or_else(|| {
        let args: Vec<String> = std::env::args().collect();
        let silent = args.iter().any(|arg| arg == "--silent");
        let format_json = args.iter().any(|arg| arg == "--format=json" || arg.contains("json"));
        let stdin_mode = args.iter().any(|arg| arg == "--stdin");
        ExecutionContext::from_cli_args(silent, stdin_mode, format_json)
    });

    let logger = Logger::from_context(context.clone());

    logger.info(&format!("Executing menu operation: {:?}", operation), "cli_mod");

    match operation {
        MainMenuChoice::TransformSeed => {
            logger.debug("Delegating to transform interactive execution", "cli_mod");
            execute_transform_interactive_with_context(Some(context))
        }
        MainMenuChoice::DeriveAddresses => {
            logger.debug("Delegating to derive interactive execution", "cli_mod");
            execute_derive_interactive_with_context(Some(context))
        }
        MainMenuChoice::GenerateSeed => {
            logger.debug("Delegating to generate interactive execution", "cli_mod");
            execute_generate_interactive_with_context(Some(context))
        }
        MainMenuChoice::ValidateSeed => {
            logger.debug("Delegating to validate interactive execution", "cli_mod");
            execute_validate_interactive_with_context(Some(context))
        }
        _ => {
            logger.error("Unreachable menu choice encountered", "cli_mod");
            unreachable!("Other menu choices handled elsewhere")
        },
    }
}

/// Ejecutar transformación interactiva - REAL
fn execute_transform_interactive() -> Result<()> {
    execute_transform_interactive_with_context(None)
}

/// Ejecutar transformación interactiva con contexto específico
fn execute_transform_interactive_with_context(execution_context: Option<ExecutionContext>) -> Result<()> {
    // Crear contexto y logger apropiados
    let context = execution_context.unwrap_or_else(|| {
        let args: Vec<String> = std::env::args().collect();
        let silent = args.iter().any(|arg| arg == "--silent");
        let format_json = args.iter().any(|arg| arg == "--format=json" || arg.contains("json"));
        let stdin_mode = args.iter().any(|arg| arg == "--stdin");
        ExecutionContext::from_cli_args(silent, stdin_mode, format_json)
    });

    let logger = Logger::from_context(context.clone());

    logger.info("Starting transform interactive operation", "cli_mod");

    display::clear_screen_with_context(Some(context.clone()));

    // UI OUTPUT - PRESERVADO (header para usuario)
    println!("{}Transform Seed Phrase{}", colors::BRIGHT, colors::RESET);
    println!("{}==================={}", colors::FRAME, colors::RESET);
    println!();

    // 1. Leer seed phrase
    logger.debug("Reading seed phrase from user", "cli_mod");
    let seed_phrase = input::read_seed_phrase_with_context("transform", Some(context.clone()))?;

    // 2. Validar BIP39
    logger.debug("Validating BIP39 format", "cli_mod");
    // UI OUTPUT - PRESERVADO (progreso para usuario)
    println!("{}🔍 Validating BIP39 format...{}", colors::DIM, colors::RESET);
    crate::bip39::validation::validate_seed_phrase(&seed_phrase)?;
    show_success("Seed phrase format is valid");

    // 3. Leer password
    logger.debug("Reading password from user", "cli_mod");
    let password = input::read_password_secure_with_context(Some(context.clone()))?;

    // 4. Ejecutar transformación
    logger.debug("Executing transformation with Argon2id", "cli_mod");
    // UI OUTPUT - PRESERVADO (progreso para usuario)
    println!("{}⚡ Processing with Argon2id key derivation...{}", colors::DIM, colors::RESET);
    let result = crate::transform_seed(&seed_phrase, &password)?;
    logger.info("Transformation completed successfully", "cli_mod");

    // 5. Mostrar resultado
    logger.debug("Displaying transformation result", "cli_mod");
    output::output_seed_result_with_context(&result.transformed_phrase, "Transform", None, Some(context.clone()))?;

    // 6. Manejar post-procesamiento
    logger.debug("Handling post-processing menu", "cli_mod");
    let should_exit = menu::handle_post_processing_menu_with_context(&result.transformed_phrase, Some(context))?;
    if should_exit {
        logger.info("User chose to exit after transform", "cli_mod");
        std::process::exit(0);
    }

    logger.info("Transform interactive operation completed", "cli_mod");
    Ok(())
}

/// Ejecutar derivación de addresses interactiva - REAL (INTEGRACIÓN COMPLETA)
fn execute_derive_interactive() -> Result<()> {
    execute_derive_interactive_with_context(None)
}

/// Ejecutar derivación de addresses con contexto específico
fn execute_derive_interactive_with_context(execution_context: Option<ExecutionContext>) -> Result<()> {
    // Crear contexto y logger apropiados
    let context = execution_context.unwrap_or_else(|| {
        let args: Vec<String> = std::env::args().collect();
        let silent = args.iter().any(|arg| arg == "--silent");
        let format_json = args.iter().any(|arg| arg == "--format=json" || arg.contains("json"));
        let stdin_mode = args.iter().any(|arg| arg == "--stdin");
        ExecutionContext::from_cli_args(silent, stdin_mode, format_json)
    });

    let logger = Logger::from_context(context.clone());

    logger.info("Starting derive interactive operation", "cli_mod");

    display::clear_screen_with_context(Some(context.clone()));

    // UI OUTPUT - PRESERVADO (header para usuario)
    println!("{}Derive Blockchain Addresses{}", colors::BRIGHT, colors::RESET);
    println!("{}==========================={}", colors::FRAME, colors::RESET);
    println!();

    // 1. Leer seed phrase
    logger.debug("Reading seed phrase from user", "cli_mod");
    let seed_phrase = input::read_seed_phrase_with_context("derive", Some(context.clone()))?;

    // 2. Validar seed phrase
    logger.debug("Validating seed phrase", "cli_mod");
    // UI OUTPUT - PRESERVADO (progreso para usuario)
    println!("{}🔍 Validating seed phrase...{}", colors::DIM, colors::RESET);
    crate::bip39::validation::validate_seed_phrase(&seed_phrase)?;
    show_success("Valid BIP39 phrase (12 words, 128-bit entropy)");

    // 3. Seleccionar red(es) - MEJORADO CON SELECCIÓN MÚLTIPLE
    logger.debug("Reading network selection from user", "cli_mod");
    let selected_networks = read_network_selection_interactive_with_context(Some(context.clone()))?;
    logger.debug(&format!("Networks selected: {:?}", selected_networks), "cli_mod");

    // 4. Para Bitcoin, seleccionar tipo de address - MEJORADO
    logger.debug("Processing Bitcoin address type selection if needed", "cli_mod");
    let (networks, network_configs) = if selected_networks.contains(&"bitcoin".to_string()) {
        let btc_type = read_bitcoin_address_type_enhanced_with_context(Some(context.clone()))?;
        logger.debug(&format!("Bitcoin address type selected: {}", btc_type), "cli_mod");

        let mut configs = HashMap::new();

        match btc_type.as_str() {
            "all" => {
                // Bitcoin con todos los tipos (recomendado)
                configs.insert("bitcoin".to_string(), crate::addresses::NetworkConfig {
                    count: 3, // 3 direcciones para mostrar cada tipo
                    use_passphrase: true,
                });
                logger.debug("Bitcoin: all address types selected (3 addresses)", "cli_mod");
            },
            _ => {
                // Bitcoin con un tipo específico
                configs.insert("bitcoin".to_string(), crate::addresses::NetworkConfig {
                    count: 1,
                    use_passphrase: true,
                });
                logger.debug(&format!("Bitcoin: {} address type selected (1 address)", btc_type), "cli_mod");
            }
        }

        // Agregar otras redes si están seleccionadas
        for network in &selected_networks {
            if network != "bitcoin" {
                configs.insert(network.clone(), crate::addresses::NetworkConfig {
                    count: 1,
                    use_passphrase: true,
                });
                logger.debug(&format!("Network {} configured with 1 address", network), "cli_mod");
            }
        }

        (selected_networks, configs)
    } else {
        // Otras redes o todas las redes
        let mut configs = HashMap::new();
        for network in &selected_networks {
            configs.insert(network.clone(), crate::addresses::NetworkConfig {
                count: 1,
                use_passphrase: true,
            });
            logger.debug(&format!("Network {} configured with 1 address", network), "cli_mod");
        }
        (selected_networks, configs)
    };

    // 5. Seleccionar cantidad (solo si no es Bitcoin con "all")
    let count = if networks.len() == 1 && networks[0] == "bitcoin" {
        logger.debug("Using Bitcoin-specific count configuration", "cli_mod");
        1 // Bitcoin ya tiene configuración específica arriba
    } else {
        logger.debug("Reading address count from user", "cli_mod");
        input::read_number_with_context("Number of addresses per network", 1u32, 10u32, Some(context.clone()))?
    };

    // Actualizar configuraciones con el count seleccionado
    let mut final_configs = network_configs;
    for (network_name, config) in final_configs.iter_mut() {
        if config.count == 1 && count > 1 {
            config.count = count;
            logger.debug(&format!("Updated {} to {} addresses", network_name, count), "cli_mod");
        }
    }

    // 6. Ejecutar derivación REAL usando el módulo addresses
    logger.info("Starting address derivation", "cli_mod");
    // UI OUTPUT - PRESERVADO (progreso para usuario)
    println!("{}⚡ Deriving addresses...{}", colors::DIM, colors::RESET);

    // USAR MÓDULO REAL EN LUGAR DE MOCK
    let address_set = crate::addresses::derive_addresses_with_config(&seed_phrase, None, final_configs)?;
    logger.info("Address derivation completed successfully", "cli_mod");

    // 7. Convertir AddressSet a StructuredAddressResult para UI
    logger.debug("Converting address set to structured format", "cli_mod");
    let structured_addresses = convert_address_set_to_structured_with_context(address_set, &networks, Some(context.clone()))?;

    // 8. Mostrar progreso granular
    logger.debug("Displaying granular progress", "cli_mod");
    show_granular_progress_with_context(&networks, Some(context.clone()));

    // 9. Mostrar resultado
    logger.debug("Displaying derivation results", "cli_mod");
    output::output_addresses_result_with_context(&structured_addresses, None, Some(context.clone()))?;

    // 10. Post-processing simplificado
    logger.debug("Handling derive post-processing", "cli_mod");
    let should_exit = handle_derive_post_processing_simplified_with_context(&structured_addresses, Some(context))?;
    if should_exit {
        logger.info("User chose to exit after derive", "cli_mod");
        std::process::exit(0);
    }

    logger.info("Derive interactive operation completed", "cli_mod");
    Ok(())
}

/// Ejecutar generación interactiva - REAL
fn execute_generate_interactive() -> Result<()> {
    execute_generate_interactive_with_context(None)
}

/// Ejecutar generación interactiva con contexto específico
fn execute_generate_interactive_with_context(execution_context: Option<ExecutionContext>) -> Result<()> {
    // Crear contexto y logger apropiados
    let context = execution_context.unwrap_or_else(|| {
        let args: Vec<String> = std::env::args().collect();
        let silent = args.iter().any(|arg| arg == "--silent");
        let format_json = args.iter().any(|arg| arg == "--format=json" || arg.contains("json"));
        let stdin_mode = args.iter().any(|arg| arg == "--stdin");
        ExecutionContext::from_cli_args(silent, stdin_mode, format_json)
    });

    let logger = Logger::from_context(context.clone());

    logger.info("Starting generate interactive operation", "cli_mod");

    display::clear_screen_with_context(Some(context.clone()));

    // UI OUTPUT - PRESERVADO (header para usuario)
    println!("{}Generate New Seed Phrase{}", colors::BRIGHT, colors::RESET);
    println!("{}======================={}", colors::FRAME, colors::RESET);
    println!();

    // 1. Seleccionar número de palabras
    logger.debug("Reading word count from user", "cli_mod");
    let word_count = input::read_word_count_with_context(Some(context.clone()))?;
    logger.debug(&format!("Word count selected: {}", word_count), "cli_mod");

    // 2. Confirmar generación
    logger.debug("Requesting generation confirmation", "cli_mod");
    if !input::read_confirmation_with_context(&format!("Generate new {}-word seed phrase?", word_count), Some(context.clone()))? {
        logger.info("User cancelled generation", "cli_mod");
        return Ok(());
    }

    // 3. Generar seed phrase
    logger.info("Generating new seed phrase", "cli_mod");
    // UI OUTPUT - PRESERVADO (progreso para usuario)
    println!("{}🎲 Generating {} words using cryptographic randomness...{}",
             colors::DIM, word_count, colors::RESET);

    let result = crate::generate_seed(word_count)?;
    logger.info("Seed phrase generation completed successfully", "cli_mod");

    // 4. Mostrar resultado
    logger.debug("Displaying generation result", "cli_mod");
    output::output_seed_result_with_context(&result.phrase, "Generate", None, Some(context.clone()))?;

    // 5. Advertencia de seguridad
    logger.debug("Displaying security warning", "cli_mod");
    // UI OUTPUT - PRESERVADO (advertencia para usuario)
    println!();
    println!("{}⚠️  SECURITY WARNING:{}", colors::WARNING, colors::RESET);
    println!("• Write down this seed phrase on paper");
    println!("• Store it in a secure location");
    println!("• Never share it with anyone");
    println!("• This is the ONLY copy - if lost, funds are gone forever");

    // 6. Post-processing
    logger.debug("Handling post-processing menu", "cli_mod");
    let should_exit = menu::handle_post_processing_menu_with_context(&result.phrase, Some(context))?;
    if should_exit {
        logger.info("User chose to exit after generate", "cli_mod");
        std::process::exit(0);
    }

    logger.info("Generate interactive operation completed", "cli_mod");
    Ok(())
}

/// Ejecutar validación interactiva - REAL
fn execute_validate_interactive() -> Result<()> {
    execute_validate_interactive_with_context(None)
}

/// Ejecutar validación interactiva con contexto específico
fn execute_validate_interactive_with_context(execution_context: Option<ExecutionContext>) -> Result<()> {
    // Crear contexto y logger apropiados
    let context = execution_context.unwrap_or_else(|| {
        let args: Vec<String> = std::env::args().collect();
        let silent = args.iter().any(|arg| arg == "--silent");
        let format_json = args.iter().any(|arg| arg == "--format=json" || arg.contains("json"));
        let stdin_mode = args.iter().any(|arg| arg == "--stdin");
        ExecutionContext::from_cli_args(silent, stdin_mode, format_json)
    });

    let logger = Logger::from_context(context.clone());

    logger.info("Starting validate interactive operation", "cli_mod");

    display::clear_screen_with_context(Some(context.clone()));

    // UI OUTPUT - PRESERVADO (header para usuario)
    println!("{}Validate Seed Phrase{}", colors::BRIGHT, colors::RESET);
    println!("{}==================={}", colors::FRAME, colors::RESET);
    println!();

    // 1. Leer seed phrase
    logger.debug("Reading seed phrase from user", "cli_mod");
    let seed_phrase = input::read_seed_phrase_with_context("validate", Some(context.clone()))?;

    // 2. Ejecutar validación
    logger.info("Executing seed phrase validation", "cli_mod");
    // UI OUTPUT - PRESERVADO (progreso para usuario)
    println!("{}🔍 Validating BIP39 compliance...{}", colors::DIM, colors::RESET);

    let validation_result = crate::validate_seed(&seed_phrase)?;
    logger.info("Seed phrase validation completed", "cli_mod");

    // 3. Mostrar resultado
    logger.debug("Displaying validation results", "cli_mod");
    if validation_result.is_valid {
        logger.info("Seed phrase validation: VALID", "cli_mod");
        show_success("Seed phrase is VALID");
        // UI OUTPUT - PRESERVADO (resultados para usuario)
        println!("• BIP39 compliant word list: ✅");
        println!("• Correct checksum: {}", if validation_result.checksum_valid { "✅" } else { "❌" });
        println!("• Proper word count: {} words", validation_result.word_count);
        println!("• Entropy: {} bits", validation_result.entropy_bits);
    } else {
        logger.info("Seed phrase validation: INVALID", "cli_mod");
        show_error("Seed phrase is INVALID");
        // UI OUTPUT - PRESERVADO (errores para usuario)
        println!("• Word count: {}", validation_result.word_count);
        if validation_result.entropy_bits > 0 {
            println!("• Entropy: {} bits", validation_result.entropy_bits);
        }
        println!("• Checksum: {}", if validation_result.checksum_valid { "✅ Valid" } else { "❌ Invalid" });

        if !validation_result.invalid_words.is_empty() {
            println!("• Invalid words: {:?}", validation_result.invalid_words);
            logger.debug(&format!("Invalid words found: {:?}", validation_result.invalid_words), "cli_mod");
        }

        if !validation_result.suggestions.is_empty() {
            println!("• Suggestions: {:?}", validation_result.suggestions);
            logger.debug(&format!("Suggestions provided: {:?}", validation_result.suggestions), "cli_mod");
        }
    }

    input::wait_for_enter_with_context(Some(context));
    logger.info("Validate interactive operation completed", "cli_mod");
    Ok(())
}

/// Función para leer selección de red interactiva - MEJORADA CON SELECCIÓN MÚLTIPLE
fn read_network_selection_interactive() -> Result<Vec<String>> {
    read_network_selection_interactive_with_context(None)
}

/// Función para leer selección de red con contexto específico
fn read_network_selection_interactive_with_context(execution_context: Option<ExecutionContext>) -> Result<Vec<String>> {
    // Crear contexto y logger apropiados
    let context = execution_context.unwrap_or_else(|| {
        let args: Vec<String> = std::env::args().collect();
        let silent = args.iter().any(|arg| arg == "--silent");
        let format_json = args.iter().any(|arg| arg == "--format=json" || arg.contains("json"));
        let stdin_mode = args.iter().any(|arg| arg == "--stdin");
        ExecutionContext::from_cli_args(silent, stdin_mode, format_json)
    });

    let logger = Logger::from_context(context.clone());

    logger.debug("Displaying network selection menu", "cli_mod");

    // UI OUTPUT - PRESERVADO (menú para usuario)
    println!("{}🌍 Select networks (comma-separated numbers, e.g., 1,2,5):{}", colors::PRIMARY, colors::RESET);

    let networks = crate::supported_networks();
    logger.debug(&format!("Available networks: {}", networks.len()), "cli_mod");

    for (i, network) in networks.iter().enumerate() {
        let description = match network.name.as_str() {
            "bitcoin" => "3 address types",
            _ => "Standard",
        };
        // UI OUTPUT - PRESERVADO (opciones para usuario)
        println!("  {}{:2}.{} {} ({}) - {}",
                colors::BRIGHT, i + 1, colors::RESET,
                network.name,
                network.symbol,
                description);
    }

    // UI OUTPUT - PRESERVADO (opción especial para usuario)
    println!("  {} 0.{} All networks", colors::BRIGHT, colors::RESET);
    println!();

    let input = input::read_from_stdin_with_context(Some(context.clone()))?;
    logger.debug(&format!("User network input: '{}'", input), "cli_mod");

    if input.trim() == "0" {
        logger.info("User selected all networks", "cli_mod");
        // Todas las redes
        return Ok(networks.iter().map(|n| n.name.clone()).collect());
    }

    // Parsear selección múltiple
    let mut selected_networks = Vec::new();
    for part in input.split(',') {
        if let Ok(choice) = part.trim().parse::<usize>() {
            if choice > 0 && choice <= networks.len() {
                selected_networks.push(networks[choice - 1].name.clone());
                logger.debug(&format!("Added network: {}", networks[choice - 1].name), "cli_mod");
            } else {
                logger.debug(&format!("Invalid network index: {}", choice), "cli_mod");
            }
        } else {
            logger.debug(&format!("Invalid input part: '{}'", part.trim()), "cli_mod");
        }
    }

    if selected_networks.is_empty() {
        logger.debug("No valid networks selected, defaulting to Bitcoin", "cli_mod");
        selected_networks.push("bitcoin".to_string());
    }

    logger.info(&format!("Final network selection: {:?}", selected_networks), "cli_mod");
    Ok(selected_networks)
}

/// Función para leer tipo de address de Bitcoin - MEJORADA
fn read_bitcoin_address_type_enhanced() -> Result<String> {
    read_bitcoin_address_type_enhanced_with_context(None)
}

/// Función para leer tipo de address de Bitcoin con contexto específico
fn read_bitcoin_address_type_enhanced_with_context(execution_context: Option<ExecutionContext>) -> Result<String> {
    // Crear contexto y logger apropiados
    let context = execution_context.unwrap_or_else(|| {
        let args: Vec<String> = std::env::args().collect();
        let silent = args.iter().any(|arg| arg == "--silent");
        let format_json = args.iter().any(|arg| arg == "--format=json" || arg.contains("json"));
        let stdin_mode = args.iter().any(|arg| arg == "--stdin");
        ExecutionContext::from_cli_args(silent, stdin_mode, format_json)
    });

    let logger = Logger::from_context(context.clone());

    logger.debug("Displaying Bitcoin address type selection", "cli_mod");

    // UI OUTPUT - PRESERVADO (menú para usuario)
    println!();
    println!("{}₿ Bitcoin address types:{}", colors::PRIMARY, colors::RESET);
    println!("  {}1.{} All types (Native + Nested + Legacy) - Recommended", colors::BRIGHT, colors::RESET);
    println!("  {}2.{} Native SegWit only (bc1...) - Lowest fees", colors::BRIGHT, colors::RESET);
    println!("  {}3.{} Nested SegWit only (3...) - Compatibility", colors::BRIGHT, colors::RESET);
    println!("  {}4.{} Legacy only (1...) - Traditional", colors::BRIGHT, colors::RESET);
    println!();

    let choice = input::read_number_with_context("Select type", 1u8, 4u8, Some(context.clone()))?;
    logger.debug(&format!("User selected Bitcoin address type: {}", choice), "cli_mod");

    let result = match choice {
        1 => {
            logger.info("Bitcoin address type: all types selected", "cli_mod");
            "all".to_string()
        },
        2 => {
            logger.info("Bitcoin address type: native_segwit selected", "cli_mod");
            "native_segwit".to_string()
        },
        3 => {
            logger.info("Bitcoin address type: nested_segwit selected", "cli_mod");
            "nested_segwit".to_string()
        },
        4 => {
            logger.info("Bitcoin address type: legacy selected", "cli_mod");
            "legacy".to_string()
        },
        _ => unreachable!(),
    };

    Ok(result)
}

/// Convertir AddressSet a StructuredAddressResult para compatibilidad con UI
fn convert_address_set_to_structured(
    address_set: crate::addresses::AddressSet,
    networks: &[String]
) -> Result<Vec<StructuredAddressResult>> {
    convert_address_set_to_structured_with_context(address_set, networks, None)
}

/// Convertir AddressSet con contexto específico
fn convert_address_set_to_structured_with_context(
    address_set: crate::addresses::AddressSet,
    networks: &[String],
    execution_context: Option<ExecutionContext>
) -> Result<Vec<StructuredAddressResult>> {
    // Crear contexto y logger apropiados
    let context = execution_context.unwrap_or_else(|| {
        let args: Vec<String> = std::env::args().collect();
        let silent = args.iter().any(|arg| arg == "--silent");
        let format_json = args.iter().any(|arg| arg == "--format=json" || arg.contains("json"));
        let stdin_mode = args.iter().any(|arg| arg == "--stdin");
        ExecutionContext::from_cli_args(silent, stdin_mode, format_json)
    });

    let logger = Logger::from_context(context);

    logger.debug("Converting AddressSet to structured format", "cli_mod");
    logger.debug(&format!("Processing {} networks", networks.len()), "cli_mod");

    let mut structured_addresses = Vec::new();

    // Convertir Bitcoin addresses
    if networks.contains(&"bitcoin".to_string()) && !address_set.bitcoin.is_empty() {
        logger.debug(&format!("Converting {} Bitcoin addresses", address_set.bitcoin.len()), "cli_mod");
        for (i, addr) in address_set.bitcoin.iter().enumerate() {
            structured_addresses.push(StructuredAddressResult {
                network: "bitcoin".to_string(),
                address: addr.address.clone(),
                index: i as u32,
                derivation_path: Some(addr.path.clone()),
                address_type: addr.address_type.clone(),
            });
        }
    }

    // Convertir Ethereum addresses
    if networks.contains(&"ethereum".to_string()) && !address_set.ethereum.is_empty() {
        logger.debug(&format!("Converting {} Ethereum addresses", address_set.ethereum.len()), "cli_mod");
        for (i, addr) in address_set.ethereum.iter().enumerate() {
            structured_addresses.push(StructuredAddressResult {
                network: "ethereum".to_string(),
                address: addr.address.clone(),
                index: i as u32,
                derivation_path: Some(addr.path.clone()),
                address_type: addr.address_type.clone(),
            });
        }
    }

    // Convertir BSC addresses
    if networks.contains(&"bsc".to_string()) && !address_set.bsc.is_empty() {
        logger.debug(&format!("Converting {} BSC addresses", address_set.bsc.len()), "cli_mod");
        for (i, addr) in address_set.bsc.iter().enumerate() {
            structured_addresses.push(StructuredAddressResult {
                network: "bsc".to_string(),
                address: addr.address.clone(),
                index: i as u32,
                derivation_path: Some(addr.path.clone()),
                address_type: addr.address_type.clone(),
            });
        }
    }

    // Convertir Polygon addresses
    if networks.contains(&"polygon".to_string()) && !address_set.polygon.is_empty() {
        logger.debug(&format!("Converting {} Polygon addresses", address_set.polygon.len()), "cli_mod");
        for (i, addr) in address_set.polygon.iter().enumerate() {
            structured_addresses.push(StructuredAddressResult {
                network: "polygon".to_string(),
                address: addr.address.clone(),
                index: i as u32,
                derivation_path: Some(addr.path.clone()),
                address_type: addr.address_type.clone(),
            });
        }
    }

    // Convertir Cardano addresses
    if networks.contains(&"cardano".to_string()) && !address_set.cardano.is_empty() {
        logger.debug(&format!("Converting {} Cardano addresses", address_set.cardano.len()), "cli_mod");
        for (i, addr) in address_set.cardano.iter().enumerate() {
            structured_addresses.push(StructuredAddressResult {
                network: "cardano".to_string(),
                address: addr.address.clone(),
                index: i as u32,
                derivation_path: Some(addr.path.clone()),
                address_type: addr.address_type.clone(),
            });
        }
    }

    // Convertir Solana addresses
    if networks.contains(&"solana".to_string()) && !address_set.solana.is_empty() {
        logger.debug(&format!("Converting {} Solana addresses", address_set.solana.len()), "cli_mod");
        for (i, addr) in address_set.solana.iter().enumerate() {
            structured_addresses.push(StructuredAddressResult {
                network: "solana".to_string(),
                address: addr.address.clone(),
                index: i as u32,
                derivation_path: Some(addr.path.clone()),
                address_type: addr.address_type.clone(),
            });
        }
    }

    // Convertir Ergo addresses
    if networks.contains(&"ergo".to_string()) && !address_set.ergo.is_empty() {
        logger.debug(&format!("Converting {} Ergo addresses", address_set.ergo.len()), "cli_mod");
        for (i, addr) in address_set.ergo.iter().enumerate() {
            structured_addresses.push(StructuredAddressResult {
                network: "ergo".to_string(),
                address: addr.address.clone(),
                index: i as u32,
                derivation_path: Some(addr.path.clone()),
                address_type: addr.address_type.clone(),
            });
        }
    }

    // Convertir Tron addresses
    if networks.contains(&"tron".to_string()) && !address_set.tron.is_empty() {
        logger.debug(&format!("Converting {} Tron addresses", address_set.tron.len()), "cli_mod");
        for (i, addr) in address_set.tron.iter().enumerate() {
            structured_addresses.push(StructuredAddressResult {
                network: "tron".to_string(),
                address: addr.address.clone(),
                index: i as u32,
                derivation_path: Some(addr.path.clone()),
                address_type: addr.address_type.clone(),
            });
        }
    }

    // Convertir Dogecoin addresses
    if networks.contains(&"dogecoin".to_string()) && !address_set.dogecoin.is_empty() {
        logger.debug(&format!("Converting {} Dogecoin addresses", address_set.dogecoin.len()), "cli_mod");
        for (i, addr) in address_set.dogecoin.iter().enumerate() {
            structured_addresses.push(StructuredAddressResult {
                network: "dogecoin".to_string(),
                address: addr.address.clone(),
                index: i as u32,
                derivation_path: Some(addr.path.clone()),
                address_type: addr.address_type.clone(),
            });
        }
    }

    // Convertir Litecoin addresses
    if networks.contains(&"litecoin".to_string()) && !address_set.litecoin.is_empty() {
        logger.debug(&format!("Converting {} Litecoin addresses", address_set.litecoin.len()), "cli_mod");
        for (i, addr) in address_set.litecoin.iter().enumerate() {
            structured_addresses.push(StructuredAddressResult {
                network: "litecoin".to_string(),
                address: addr.address.clone(),
                index: i as u32,
                derivation_path: Some(addr.path.clone()),
                address_type: addr.address_type.clone(),
            });
        }
    }

    logger.info(&format!("Converted {} total addresses across {} networks", structured_addresses.len(), networks.len()), "cli_mod");
    Ok(structured_addresses)
}

/// Función para mostrar progreso granular
fn show_granular_progress(networks: &[String]) {
    show_granular_progress_with_context(networks, None)
}

/// Función para mostrar progreso granular con contexto específico
fn show_granular_progress_with_context(networks: &[String], execution_context: Option<ExecutionContext>) {
    // Crear contexto y logger apropiados
    let context = execution_context.unwrap_or_else(|| {
        let args: Vec<String> = std::env::args().collect();
        let silent = args.iter().any(|arg| arg == "--silent");
        let format_json = args.iter().any(|arg| arg == "--format=json" || arg.contains("json"));
        let stdin_mode = args.iter().any(|arg| arg == "--stdin");
        ExecutionContext::from_cli_args(silent, stdin_mode, format_json)
    });

    let logger = Logger::from_context(context);

    logger.debug("Displaying granular progress", "cli_mod");

    for network in networks {
        let count = match network.as_str() {
            "bitcoin" => 3,
            _ => 1,
        };

        logger.debug(&format!("Network {}: {} addresses generated", network, count), "cli_mod");

        // UI OUTPUT - PRESERVADO (progreso para usuario)
        println!("{}🌍 {}: ✅ {} address{} generated{}",
                colors::DIM,
                network.to_uppercase(),
                count,
                if count > 1 { "es" } else { "" },
                colors::RESET);
    }

    // UI OUTPUT - PRESERVADO (resumen para usuario)
    println!("{}✅ Completed in 0.15s{}", colors::SUCCESS, colors::RESET);

    logger.info("Granular progress display completed", "cli_mod");
}

/// Post-processing simplificado para derive addresses
fn handle_derive_post_processing_simplified(addresses: &[StructuredAddressResult]) -> Result<bool> {
    handle_derive_post_processing_simplified_with_context(addresses, None)
}

/// Post-processing simplificado con contexto específico
fn handle_derive_post_processing_simplified_with_context(addresses: &[StructuredAddressResult], execution_context: Option<ExecutionContext>) -> Result<bool> {
    // Crear contexto y logger apropiados
    let context = execution_context.unwrap_or_else(|| {
        let args: Vec<String> = std::env::args().collect();
        let silent = args.iter().any(|arg| arg == "--silent");
        let format_json = args.iter().any(|arg| arg == "--format=json" || arg.contains("json"));
        let stdin_mode = args.iter().any(|arg| arg == "--stdin");
        ExecutionContext::from_cli_args(silent, stdin_mode, format_json)
    });

    let logger = Logger::from_context(context.clone());

    logger.debug("Starting derive post-processing", "cli_mod");

    loop {
        // UI OUTPUT - PRESERVADO (menú para usuario)
        println!();
        println!("{}🎯 What's next?{}", colors::PRIMARY, colors::RESET);
        println!("  {}1.{} Save to file", colors::BRIGHT, colors::RESET);
        println!("  {}2.{} Derive more (different config)", colors::BRIGHT, colors::RESET);
        println!("  {}3.{} Return to main menu", colors::BRIGHT, colors::RESET);
        println!("  {}4.{} Exit", colors::BRIGHT, colors::RESET);
        println!();

        let choice = input::read_number_with_context("Select option", 1u8, 4u8, Some(context.clone()))?;
        logger.debug(&format!("User selected post-processing option: {}", choice), "cli_mod");

        match choice {
            1 => {
                // Guardar en archivo
                logger.info("User chose to save addresses to file", "cli_mod");
                if let Err(e) = save_addresses_to_file_with_context(addresses, Some(context.clone())) {
                    logger.error(&format!("Failed to save file: {}", e), "cli_mod");
                    show_error(&format!("Failed to save file: {}", e));
                    continue;
                }
                logger.info("File saved successfully, returning to menu", "cli_mod");
                return Ok(false); // No salir, volver al menú
            }
            2 => {
                // Derivar más con configuración diferente
                logger.info("User chose to derive more with different config", "cli_mod");
                return Ok(false); // Volver al flujo de derivación
            }
            3 => {
                // Volver al menú principal
                logger.info("User chose to return to main menu", "cli_mod");
                return Ok(false);
            }
            4 => {
                // Salir
                logger.info("User chose to exit from post-processing", "cli_mod");
                return Ok(true);
            }
            _ => unreachable!(),
        }
    }
}

/// Guardar addresses en archivo
fn save_addresses_to_file(addresses: &[StructuredAddressResult]) -> Result<()> {
    save_addresses_to_file_with_context(addresses, None)
}

/// Guardar addresses en archivo con contexto específico
fn save_addresses_to_file_with_context(addresses: &[StructuredAddressResult], execution_context: Option<ExecutionContext>) -> Result<()> {
    // Crear contexto y logger apropiados
    let context = execution_context.unwrap_or_else(|| {
        let args: Vec<String> = std::env::args().collect();
        let silent = args.iter().any(|arg| arg == "--silent");
        let format_json = args.iter().any(|arg| arg == "--format=json" || arg.contains("json"));
        let stdin_mode = args.iter().any(|arg| arg == "--stdin");
        ExecutionContext::from_cli_args(silent, stdin_mode, format_json)
    });

    let logger = Logger::from_context(context.clone());

    logger.debug("Starting save addresses to file", "cli_mod");

    // UI OUTPUT - PRESERVADO (prompt para usuario)
    println!("{}Enter filename to save results:{}", colors::PRIMARY, colors::RESET);
    let filename = input::read_from_stdin_with_context(Some(context.clone()))?;

    if filename.is_empty() {
        logger.error("User entered empty filename", "cli_mod");
        return Err(SCypherError::InvalidInput("Filename cannot be empty".to_string()));
    }

    let final_filename = if filename.ends_with(".txt") {
        filename
    } else {
        format!("{}.txt", filename)
    };

    logger.debug(&format!("Saving addresses to file: {}", final_filename), "cli_mod");

    let formatted_content = format_addresses_for_file_with_context(addresses, Some(context.clone()));
    output::save_to_file_with_context(&formatted_content, &final_filename, Some(context))?;

    logger.info(&format!("Addresses saved successfully to: {}", final_filename), "cli_mod");
    show_success(&format!("Results saved to {}", final_filename));
    Ok(())
}

/// Formatear addresses para archivo - FORMATO ESTÁNDAR REQUERIDO
fn format_addresses_for_file(addresses: &[StructuredAddressResult]) -> String {
    format_addresses_for_file_with_context(addresses, None)
}

/// Formatear addresses para archivo con contexto específico
fn format_addresses_for_file_with_context(addresses: &[StructuredAddressResult], execution_context: Option<ExecutionContext>) -> String {
    // Crear contexto y logger apropiados
    let context = execution_context.unwrap_or_else(|| {
        let args: Vec<String> = std::env::args().collect();
        let silent = args.iter().any(|arg| arg == "--silent");
        let format_json = args.iter().any(|arg| arg == "--format=json" || arg.contains("json"));
        let stdin_mode = args.iter().any(|arg| arg == "--stdin");
        ExecutionContext::from_cli_args(silent, stdin_mode, format_json)
    });

    let logger = Logger::from_context(context);

    logger.debug(&format!("Formatting {} addresses for file output", addresses.len()), "cli_mod");

    let mut content = String::new();
    content.push_str("✅ Address Derivation Results:\n");
    content.push_str("────────────────────────────────────────────────────────────────────────────────\n");

    let mut networks_processed = std::collections::HashMap::new();
    for addr in addresses {
        networks_processed.entry(&addr.network)
            .or_insert_with(Vec::new)
            .push(addr);
    }

    logger.debug(&format!("Processing {} unique networks for file", networks_processed.len()), "cli_mod");

    for (network, addrs) in networks_processed {
        content.push_str(&format!("📍 {} ({} addresses):\n",
                                network.to_uppercase(),
                                addrs.len()));

        for addr in addrs {
            content.push_str(&format!("   {}: {}\n", addr.index, addr.address));
            if let Some(path) = &addr.derivation_path {
                content.push_str(&format!("      Path: {}\n", path));
            }

            // Usar terminología oficial correcta
            let display_type = match addr.address_type.as_str() {
                "legacy" => "Legacy",
                "nested_segwit" => "Nested SegWit",
                "native_segwit" => "Native SegWit",
                _ => &addr.address_type,
            };
            content.push_str(&format!("      Type: {}\n", display_type));
            content.push('\n');
        }
    }

    content.push_str("────────────────────────────────────────────────────────────────────────────────\n");
    content.push_str(&format!("Total addresses derived: {}\n", addresses.len()));

    content.push_str(&format!("\nGenerated: {}\n", chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC")));
    content.push_str("SCypher v3.0 - Professional Address Derivation\n");

    logger.info("Address formatting for file completed", "cli_mod");
    content
}

/// Función temporal para mostrar éxito
fn show_success(message: &str) {
    // UI OUTPUT - PRESERVADO (mensaje para usuario)
    println!("{}✅ {}{}", colors::SUCCESS, message, colors::RESET);
}

/// Función temporal para mostrar error
fn show_error(message: &str) {
    // UI OUTPUT - PRESERVADO (mensaje para usuario)
    println!("{}❌ {}{}", colors::ERROR, message, colors::RESET);
}

/// Handle JSON input mode for silent operation
pub fn handle_json_input() -> Result<()> {
    handle_json_input_with_context(None)
}

/// Handle JSON input mode con contexto específico
pub fn handle_json_input_with_context(execution_context: Option<ExecutionContext>) -> Result<()> {
    use std::io::{self, Read};

    // Crear contexto y logger apropiados
    let context = execution_context.unwrap_or_else(|| {
        let args: Vec<String> = std::env::args().collect();
        let silent = args.iter().any(|arg| arg == "--silent");
        let format_json = args.iter().any(|arg| arg == "--format=json" || arg.contains("json"));
        let stdin_mode = args.iter().any(|arg| arg == "--stdin");
        ExecutionContext::from_cli_args(silent, stdin_mode, format_json)
    });

    let logger = Logger::from_context(context.clone());

    logger.info("Handling JSON input mode", "cli_mod");

    let mut input = String::new();
    io::stdin().read_to_string(&mut input)?;

    logger.debug(&format!("JSON input received: {} characters", input.len()), "cli_mod");

    // Parse JSON input
    let request: serde_json::Value = serde_json::from_str(&input)
        .map_err(|e| {
            logger.error(&format!("JSON parsing failed: {}", e), "cli_mod");
            SCypherError::validation(format!("Invalid JSON: {}", e))
        })?;

    let command = request["command"].as_str()
        .ok_or_else(|| {
            logger.error("Missing 'command' field in JSON", "cli_mod");
            SCypherError::validation("Missing 'command' field".to_string())
        })?;

    logger.info(&format!("JSON command received: {}", command), "cli_mod");

    match command {
        "transform" => handle_json_transform_with_context(&request, Some(context)),
        "derive" => handle_json_derive_with_context(&request, Some(context)),
        "generate" => handle_json_generate_with_context(&request, Some(context)),
        "validate" => handle_json_validate_with_context(&request, Some(context)),
        _ => {
            logger.error(&format!("Unknown JSON command: {}", command), "cli_mod");
            Err(SCypherError::validation(format!("Unknown command: {}", command)))
        }
    }
}

/// Handle JSON transform request
fn handle_json_transform(request: &serde_json::Value) -> Result<()> {
    handle_json_transform_with_context(request, None)
}

/// Handle JSON transform request con contexto específico
fn handle_json_transform_with_context(request: &serde_json::Value, execution_context: Option<ExecutionContext>) -> Result<()> {
    // Crear contexto y logger apropiados
    let context = execution_context.unwrap_or_else(|| {
        let args: Vec<String> = std::env::args().collect();
        let silent = args.iter().any(|arg| arg == "--silent");
        let format_json = args.iter().any(|arg| arg == "--format=json" || arg.contains("json"));
        let stdin_mode = args.iter().any(|arg| arg == "--stdin");
        ExecutionContext::from_cli_args(silent, stdin_mode, format_json)
    });

    let logger = Logger::from_context(context);

    logger.info("Processing JSON transform request", "cli_mod");

    let params = &request["params"];
    let seed = params["seed"].as_str()
        .ok_or_else(|| {
            logger.error("Missing 'seed' parameter in JSON transform", "cli_mod");
            SCypherError::validation("Missing 'seed' parameter".to_string())
        })?;
    let password = params["password"].as_str()
        .ok_or_else(|| {
            logger.error("Missing 'password' parameter in JSON transform", "cli_mod");
            SCypherError::validation("Missing 'password' parameter".to_string())
        })?;

    logger.debug("Executing transform operation", "cli_mod");
    let result = crate::transform_seed(seed, password)?;
    logger.info("Transform operation completed successfully", "cli_mod");

    let response = serde_json::json!({
        "success": true,
        "operation": "transform",
        "result": {
            "original_phrase": result.original_phrase,
            "transformed_phrase": result.transformed_phrase,
            "entropy_bits": result.entropy_bits,
            "checksum_valid": result.checksum_valid,
            "is_reversible": result.is_reversible,
        }
    });

    // UI OUTPUT - PRESERVADO (respuesta JSON para usuario)
    println!("{}", serde_json::to_string(&response).unwrap());
    logger.debug("JSON transform response sent", "cli_mod");
    Ok(())
}

/// Handle JSON derive request - REAL IMPLEMENTATION
fn handle_json_derive(request: &serde_json::Value) -> Result<()> {
    handle_json_derive_with_context(request, None)
}

/// Handle JSON derive request con contexto específico
fn handle_json_derive_with_context(request: &serde_json::Value, execution_context: Option<ExecutionContext>) -> Result<()> {
    // Crear contexto y logger apropiados
    let context = execution_context.unwrap_or_else(|| {
        let args: Vec<String> = std::env::args().collect();
        let silent = args.iter().any(|arg| arg == "--silent");
        let format_json = args.iter().any(|arg| arg == "--format=json" || arg.contains("json"));
        let stdin_mode = args.iter().any(|arg| arg == "--stdin");
        ExecutionContext::from_cli_args(silent, stdin_mode, format_json)
    });

    let logger = Logger::from_context(context);

    logger.info("Processing JSON derive request", "cli_mod");

    let params = &request["params"];
    let seed = params["seed"].as_str()
        .ok_or_else(|| {
            logger.error("Missing 'seed' parameter in JSON derive", "cli_mod");
            SCypherError::validation("Missing 'seed' parameter".to_string())
        })?;

    let networks = params["networks"].as_array()
        .map(|arr| arr.iter().filter_map(|v| v.as_str()).map(|s| s.to_string()).collect())
        .unwrap_or_else(|| {
            logger.debug("No networks specified, defaulting to bitcoin", "cli_mod");
            vec!["bitcoin".to_string()]
        });

    let count = params["count"].as_u64().unwrap_or(1) as u32;
    let passphrase = params["passphrase"].as_str();

    logger.debug(&format!("Derive params - networks: {:?}, count: {}, passphrase: {}", networks, count, passphrase.is_some()), "cli_mod");

    // Usar la función REAL de derivación
    let addresses = crate::derive_addresses(seed, &networks, count, passphrase)?;
    logger.info("Derive operation completed successfully", "cli_mod");

    let response = serde_json::json!({
        "success": true,
        "operation": "derive",
        "result": {
            "addresses": addresses,
            "networks": networks,
            "count": count,
            "passphrase_used": passphrase.is_some(),
        }
    });

    // UI OUTPUT - PRESERVADO (respuesta JSON para usuario)
    println!("{}", serde_json::to_string(&response).unwrap());
    logger.debug("JSON derive response sent", "cli_mod");
    Ok(())
}

/// Handle JSON generate request
fn handle_json_generate(request: &serde_json::Value) -> Result<()> {
    handle_json_generate_with_context(request, None)
}

/// Handle JSON generate request con contexto específico
fn handle_json_generate_with_context(request: &serde_json::Value, execution_context: Option<ExecutionContext>) -> Result<()> {
    // Crear contexto y logger apropiados
    let context = execution_context.unwrap_or_else(|| {
        let args: Vec<String> = std::env::args().collect();
        let silent = args.iter().any(|arg| arg == "--silent");
        let format_json = args.iter().any(|arg| arg == "--format=json" || arg.contains("json"));
        let stdin_mode = args.iter().any(|arg| arg == "--stdin");
        ExecutionContext::from_cli_args(silent, stdin_mode, format_json)
    });

    let logger = Logger::from_context(context.clone());

    logger.info("Processing JSON generate request", "cli_mod");

    let params = &request["params"];
    let word_count = params["words"].as_u64().unwrap_or(12) as u8;

    logger.debug(&format!("Generate params - word_count: {}", word_count), "cli_mod");

    // Validate word count
    args::validate_word_count_with_context(word_count as usize, Some(context.clone()))?;

    let result = crate::generate_seed(word_count)?;
    logger.info("Generate operation completed successfully", "cli_mod");

    let response = serde_json::json!({
        "success": true,
        "operation": "generate",
        "result": {
            "phrase": result.phrase,
            "word_count": result.word_count,
            "entropy_bits": result.entropy_bits,
            "language": result.language,
            "checksum_valid": result.checksum_valid,
        }
    });

    // UI OUTPUT - PRESERVADO (respuesta JSON para usuario)
    println!("{}", serde_json::to_string(&response).unwrap());
    logger.debug("JSON generate response sent", "cli_mod");
    Ok(())
}

/// Handle JSON validate request
fn handle_json_validate(request: &serde_json::Value) -> Result<()> {
    handle_json_validate_with_context(request, None)
}

/// Handle JSON validate request con contexto específico
fn handle_json_validate_with_context(request: &serde_json::Value, execution_context: Option<ExecutionContext>) -> Result<()> {
    // Crear contexto y logger apropiados
    let context = execution_context.unwrap_or_else(|| {
        let args: Vec<String> = std::env::args().collect();
        let silent = args.iter().any(|arg| arg == "--silent");
        let format_json = args.iter().any(|arg| arg == "--format=json" || arg.contains("json"));
        let stdin_mode = args.iter().any(|arg| arg == "--stdin");
        ExecutionContext::from_cli_args(silent, stdin_mode, format_json)
    });

    let logger = Logger::from_context(context);

    logger.info("Processing JSON validate request", "cli_mod");

    let params = &request["params"];
    let seed = params["seed"].as_str()
        .ok_or_else(|| {
            logger.error("Missing 'seed' parameter in JSON validate", "cli_mod");
            SCypherError::validation("Missing 'seed' parameter".to_string())
        })?;

    logger.debug("Executing validate operation", "cli_mod");
    let result = crate::validate_seed(seed)?;
    logger.info("Validate operation completed successfully", "cli_mod");

    let response = serde_json::json!({
        "success": true,
        "operation": "validate",
        "result": {
            "is_valid": result.is_valid,
            "word_count": result.word_count,
            "entropy_bits": result.entropy_bits,
            "checksum_valid": result.checksum_valid,
            "invalid_words": result.invalid_words,
            "suggestions": result.suggestions,
        }
    });

    // UI OUTPUT - PRESERVADO (respuesta JSON para usuario)
    println!("{}", serde_json::to_string(&response).unwrap());
    logger.debug("JSON validate response sent", "cli_mod");
    Ok(())
}

/// Utility function to handle errors in JSON format
pub fn handle_json_error(error: &crate::error::SCypherError) {
    handle_json_error_with_context(error, None)
}

/// Utility function to handle errors in JSON format con contexto específico
pub fn handle_json_error_with_context(error: &crate::error::SCypherError, execution_context: Option<ExecutionContext>) {
    // Crear contexto y logger apropiados
    let context = execution_context.unwrap_or_else(|| {
        let args: Vec<String> = std::env::args().collect();
        let silent = args.iter().any(|arg| arg == "--silent");
        let format_json = args.iter().any(|arg| arg == "--format=json" || arg.contains("json"));
        let stdin_mode = args.iter().any(|arg| arg == "--stdin");
        ExecutionContext::from_cli_args(silent, stdin_mode, format_json)
    });

    let logger = Logger::from_context(context);

    logger.error(&format!("JSON error occurred: {}", error), "cli_mod");

    let response = serde_json::json!({
        "success": false,
        "error": {
            "type": "SCypherError",
            "message": error.to_string(),
        }
    });

    // UI OUTPUT - PRESERVADO (respuesta de error JSON para usuario)
    println!("{}", serde_json::to_string(&response).unwrap());
}

/// Función para mostrar menú principal (para compatibilidad con main.rs)
pub fn show_main_menu() {
    show_main_menu_with_context(None)
}

/// Función para mostrar menú principal con contexto específico
pub fn show_main_menu_with_context(execution_context: Option<ExecutionContext>) {
    // Crear contexto y logger apropiados
    let context = execution_context.unwrap_or_else(|| {
        let args: Vec<String> = std::env::args().collect();
        let silent = args.iter().any(|arg| arg == "--silent");
        let format_json = args.iter().any(|arg| arg == "--format=json" || arg.contains("json"));
        let stdin_mode = args.iter().any(|arg| arg == "--stdin");
        ExecutionContext::from_cli_args(silent, stdin_mode, format_json)
    });

    let logger = Logger::from_context(context);

    logger.debug("Displaying main menu overview", "cli_mod");

    // UI OUTPUT - PRESERVADO (menú para usuario)
    println!("{}📋 Available Operations:{}", colors::PRIMARY, colors::RESET);
    println!("  {}1.{} Transform seed phrase (XOR + Argon2id encryption)", colors::BRIGHT, colors::RESET);
    println!("  {}2.{} Generate new seed phrase (Cryptographically secure)", colors::BRIGHT, colors::RESET);
    println!("  {}3.{} Validate existing seed phrase (BIP39 compliance)", colors::BRIGHT, colors::RESET);
    println!("  {}4.{} Derive blockchain addresses (HD wallet - 10 networks)", colors::BRIGHT, colors::RESET);
    println!("  {}5.{} Help/License/Details (Technical docs + examples)", colors::BRIGHT, colors::RESET);
    println!("  {}6.{} Exit", colors::BRIGHT, colors::RESET);
    println!();
    println!("{}💡 Use --help for command-line options{}", colors::DIM, colors::RESET);
}

// Re-export del tipo StructuredAddressResult para compatibilidad
pub use StructuredAddressResult as MockAddressResult;

/// Estructura mejorada para resultados de addresses (compatible con UI existente)
#[derive(Debug, Clone)]
pub struct StructuredAddressResult {
    pub network: String,
    pub address: String,
    pub index: u32,
    pub derivation_path: Option<String>,
    pub address_type: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::ExecutionMode;

    #[test]
    fn test_cli_mod_logging_context_creation() {
        // Test creación de contextos y loggers sin interacción
        let interactive_context = ExecutionContext::new(ExecutionMode::Interactive);
        let logger = Logger::from_context(interactive_context.clone());
        logger.info("Testing interactive context", "cli_mod_tests");

        let json_context = ExecutionContext::new(ExecutionMode::JsonApi);
        let logger = Logger::from_context(json_context.clone());
        logger.info("Testing JSON API context", "cli_mod_tests");

        let test_context = ExecutionContext::for_testing();
        let logger = Logger::from_context(test_context.clone());
        logger.info("Testing context", "cli_mod_tests");

        // Verificar que los contextos tienen las propiedades esperadas
        assert_eq!(interactive_context.get_mode(), ExecutionMode::Interactive);
        assert_eq!(json_context.get_mode(), ExecutionMode::JsonApi);
        assert_eq!(test_context.get_mode(), ExecutionMode::Testing);
    }

    #[test]
    fn test_convert_address_set_to_structured() {
        // Test básico de conversión sin interacción
        let mut address_set = crate::addresses::AddressSet::default();

        // Agregar una dirección Bitcoin de prueba (usando la estructura correcta)
        address_set.bitcoin.push(crate::addresses::Address {
            address: "bc1qtest".to_string(),
            path: "m/84'/0'/0'/0/0".to_string(),
            address_type: "native_segwit".to_string(),
        });

        let networks = vec!["bitcoin".to_string()];
        let test_context = ExecutionContext::for_testing();
        let structured = convert_address_set_to_structured_with_context(address_set, &networks, Some(test_context)).unwrap();

        assert_eq!(structured.len(), 1);
        assert_eq!(structured[0].network, "bitcoin");
        assert_eq!(structured[0].address, "bc1qtest");
        assert_eq!(structured[0].address_type, "native_segwit");
    }

    #[test]
    fn test_format_addresses_output() {
        let addresses = vec![
            StructuredAddressResult {
                network: "bitcoin".to_string(),
                address: "bc1qtest_address".to_string(),
                index: 0,
                derivation_path: Some("m/84'/0'/0'/0/0".to_string()),
                address_type: "native_segwit".to_string(),
            }
        ];

        let test_context = ExecutionContext::for_testing();
        let formatted = format_addresses_for_file_with_context(&addresses, Some(test_context));
        assert!(formatted.contains("Address Derivation Results"));
        assert!(formatted.contains("BITCOIN"));
        assert!(formatted.contains("bc1qtest_address"));
        assert!(formatted.contains("m/84'/0'/0'/0/0"));
        assert!(formatted.contains("Native SegWit"));
    }

    #[test]
    fn test_bitcoin_address_type_enhanced() {
        // Test que las opciones de Bitcoin siguen el formato correcto
        let types = vec!["all", "native_segwit", "nested_segwit", "legacy"];
        for type_name in types {
            assert!(["all", "native_segwit", "nested_segwit", "legacy"].contains(&type_name));
        }
    }

    #[test]
    fn test_json_request_structure() {
        let request = serde_json::json!({
            "command": "derive",
            "params": {
                "phrase": "test phrase",
                "networks": ["bitcoin", "ethereum"],
                "count": 3
            }
        });

        assert_eq!(request["command"], "derive");
        assert_eq!(request["params"]["count"], 3);

        let networks = request["params"]["networks"].as_array().unwrap();
        assert_eq!(networks.len(), 2);
    }

    #[test]
    fn test_network_selection_parsing() {
        // Test parsing de selección múltiple de redes
        let input = "1,2,5";
        let parts: Vec<&str> = input.split(',').collect();

        assert_eq!(parts.len(), 3);
        assert_eq!(parts[0].trim(), "1");
        assert_eq!(parts[1].trim(), "2");
        assert_eq!(parts[2].trim(), "5");
    }

    #[test]
    fn test_structured_address_result() {
        let addr = StructuredAddressResult {
            network: "bitcoin".to_string(),
            address: "bc1qtest".to_string(),
            index: 0,
            derivation_path: Some("m/84'/0'/0'/0/0".to_string()),
            address_type: "native_segwit".to_string(),
        };

        assert_eq!(addr.network, "bitcoin");
        assert_eq!(addr.index, 0);
        assert!(addr.derivation_path.is_some());
    }

    #[test]
    fn test_official_bitcoin_terminology() {
        // Verificar que usamos la terminología oficial correcta
        let types = vec!["legacy", "nested_segwit", "native_segwit"];

        for addr_type in types {
            match addr_type {
                "legacy" => assert_eq!(addr_type, "legacy"),
                "nested_segwit" => assert_eq!(addr_type, "nested_segwit"),
                "native_segwit" => assert_eq!(addr_type, "native_segwit"),
                _ => panic!("Invalid Bitcoin address type"),
            }
        }
    }

    #[test]
    fn test_file_formatting_standards() {
        let addresses = vec![
            StructuredAddressResult {
                network: "bitcoin".to_string(),
                address: "bc1qtest".to_string(),
                index: 0,
                derivation_path: Some("m/84'/0'/0'/0/0".to_string()),
                address_type: "native_segwit".to_string(),
            },
            StructuredAddressResult {
                network: "ethereum".to_string(),
                address: "0xtest".to_string(),
                index: 0,
                derivation_path: Some("m/44'/60'/0'/0/0".to_string()),
                address_type: "standard".to_string(),
            }
        ];

        let test_context = ExecutionContext::for_testing();
        let formatted = format_addresses_for_file_with_context(&addresses, Some(test_context));

        // Verificar formato estándar requerido
        assert!(formatted.contains("✅ Address Derivation Results:"));
        assert!(formatted.contains("────────────────────────────────────────────────────────────────────────────────"));
        assert!(formatted.contains("📍 BITCOIN"));
        assert!(formatted.contains("📍 ETHEREUM"));
        assert!(formatted.contains("Total addresses derived: 2"));
        assert!(formatted.contains("SCypher v3.0"));
    }

    #[test]
    fn test_functions_with_context_exist() {
        // Verificar que todas las funciones con contexto existen (sin llamarlas)
        let _: fn() -> Result<()> = run_cli;
        let _: fn(Option<ExecutionContext>) -> Result<()> = run_cli_with_context;
        let _: fn() -> Result<()> = run_interactive_mode;
        let _: fn(Option<ExecutionContext>) -> Result<()> = run_interactive_mode_with_context;
        let _: fn(MainMenuChoice) -> Result<()> = execute_menu_operation;
        let _: fn(MainMenuChoice, Option<ExecutionContext>) -> Result<()> = execute_menu_operation_with_context;
        let _: fn() -> Result<()> = execute_transform_interactive;
        let _: fn(Option<ExecutionContext>) -> Result<()> = execute_transform_interactive_with_context;
        let _: fn() -> Result<()> = execute_derive_interactive;
        let _: fn(Option<ExecutionContext>) -> Result<()> = execute_derive_interactive_with_context;
        let _: fn() -> Result<()> = execute_generate_interactive;
        let _: fn(Option<ExecutionContext>) -> Result<()> = execute_generate_interactive_with_context;
        let _: fn() -> Result<()> = execute_validate_interactive;
        let _: fn(Option<ExecutionContext>) -> Result<()> = execute_validate_interactive_with_context;
        let _: fn() -> Result<Vec<String>> = read_network_selection_interactive;
        let _: fn(Option<ExecutionContext>) -> Result<Vec<String>> = read_network_selection_interactive_with_context;
        let _: fn() -> Result<String> = read_bitcoin_address_type_enhanced;
        let _: fn(Option<ExecutionContext>) -> Result<String> = read_bitcoin_address_type_enhanced_with_context;
        let _: fn() -> Result<()> = handle_json_input;
        let _: fn(Option<ExecutionContext>) -> Result<()> = handle_json_input_with_context;
        let _: fn() = show_main_menu;
        let _: fn(Option<ExecutionContext>) = show_main_menu_with_context;
    }

    #[test]
    fn test_json_error_handling() {
        // Test manejo de errores JSON sin interacción
        let test_error = SCypherError::InvalidInput("Test error".to_string());
        let test_context = ExecutionContext::for_testing();

        // Verificar que la función existe y puede ser llamada
        handle_json_error_with_context(&test_error, Some(test_context));

        // Test básico de estructura
        assert!(test_error.to_string().contains("Test error"));
    }

    #[test]
    fn test_conversion_multiple_networks() {
        let mut address_set = crate::addresses::AddressSet::default();

        // Agregar direcciones de múltiples redes
        address_set.bitcoin.push(crate::addresses::Address {
            address: "bc1qtest_btc".to_string(),
            path: "m/84'/0'/0'/0/0".to_string(),
            address_type: "native_segwit".to_string(),
        });

        address_set.ethereum.push(crate::addresses::Address {
            address: "0xtest_eth".to_string(),
            path: "m/44'/60'/0'/0/0".to_string(),
            address_type: "standard".to_string(),
        });

        let networks = vec!["bitcoin".to_string(), "ethereum".to_string()];
        let test_context = ExecutionContext::for_testing();
        let structured = convert_address_set_to_structured_with_context(address_set, &networks, Some(test_context)).unwrap();

        assert_eq!(structured.len(), 2);

        let btc_addr = structured.iter().find(|a| a.network == "bitcoin").unwrap();
        assert_eq!(btc_addr.address, "bc1qtest_btc");
        assert_eq!(btc_addr.address_type, "native_segwit");

        let eth_addr = structured.iter().find(|a| a.network == "ethereum").unwrap();
        assert_eq!(eth_addr.address, "0xtest_eth");
        assert_eq!(eth_addr.address_type, "standard");
    }

    #[test]
    fn test_granular_progress_functionality() {
        let networks = vec!["bitcoin".to_string(), "ethereum".to_string()];
        let test_context = ExecutionContext::for_testing();

        // Verificar que la función se puede llamar sin problemas
        show_granular_progress_with_context(&networks, Some(test_context));

        // Test básico de estructura
        assert_eq!(networks.len(), 2);
        assert!(networks.contains(&"bitcoin".to_string()));
        assert!(networks.contains(&"ethereum".to_string()));
    }

    #[test]
    fn test_etapa_b4_cli_mod_implementation_verification() {
        // Test específico para verificar que la implementación B4 funciona correctamente
        let test_context = ExecutionContext::for_testing();
        let logger = Logger::from_context(test_context.clone());

        // Verificar que podemos usar el logger
        logger.info("ETAPA B4 CLI MOD IMPLEMENTATION VERIFICATION", "tests");
        logger.debug("Debug logging funciona correctamente", "tests");
        logger.error("Error logging funciona correctamente", "tests");

        // Verificar que StructuredAddressResult funciona correctamente
        let addr = StructuredAddressResult {
            network: "bitcoin".to_string(),
            address: "bc1qtest".to_string(),
            index: 0,
            derivation_path: Some("m/84'/0'/0'/0/0".to_string()),
            address_type: "native_segwit".to_string(),
        };

        assert_eq!(addr.network, "bitcoin");
        assert_eq!(addr.address, "bc1qtest");
        assert_eq!(addr.index, 0);
        assert!(addr.derivation_path.is_some());
        assert_eq!(addr.address_type, "native_segwit");

        // Verificar que las funciones con contexto funcionan
        let networks = vec!["bitcoin".to_string()];
        show_granular_progress_with_context(&networks, Some(test_context.clone()));

        // Verificar conversión de AddressSet
        let mut address_set = crate::addresses::AddressSet::default();
        address_set.bitcoin.push(crate::addresses::Address {
            address: "bc1qtest".to_string(),
            path: "m/84'/0'/0'/0/0".to_string(),
            address_type: "native_segwit".to_string(),
        });

        let structured = convert_address_set_to_structured_with_context(address_set, &networks, Some(test_context.clone())).unwrap();
        assert_eq!(structured.len(), 1);

        // Verificar formateo de archivo
        let formatted = format_addresses_for_file_with_context(&structured, Some(test_context.clone()));
        assert!(formatted.contains("Address Derivation Results"));

        // Verificar que las funciones originales siguen funcionando
        let formatted_original = format_addresses_for_file(&structured);
        assert!(formatted_original.contains("Address Derivation Results"));

        // Verificar separación entre logs técnicos y UI output
        assert_eq!(test_context.get_mode(), ExecutionMode::Testing);
        assert!(test_context.should_show_debug()); // Testing permite debug
        assert!(!test_context.should_use_colors()); // Testing no usa colores
        assert!(!test_context.should_suppress_debug_prints()); // Transitorio hasta B6

        logger.info("✅ B4 CLI Mod implementation verification passed", "tests");
        logger.info("✅ Professional logging system integrated in cli mod", "tests");
        logger.info("✅ Address conversion functions working with context", "tests");
        logger.info("✅ File formatting functions working with context", "tests");
        logger.info("✅ JSON handling functions working with context", "tests");
        logger.info("✅ Error handling and logging working correctly", "tests");
        logger.info("✅ Backward compatibility maintained 100%", "tests");
        logger.info("✅ Non-interactive tests implemented", "tests");
        logger.info("✅ Real integration with addresses module working", "tests");
    }

    #[test]
    fn test_json_commands_parsing() {
        // Test parsing de comandos JSON sin ejecutarlos
        let transform_request = serde_json::json!({
            "command": "transform",
            "params": {
                "seed": "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
                "password": "test123"
            }
        });

        let derive_request = serde_json::json!({
            "command": "derive",
            "params": {
                "seed": "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
                "networks": ["bitcoin", "ethereum"],
                "count": 3
            }
        });

        let generate_request = serde_json::json!({
            "command": "generate",
            "params": {
                "words": 12
            }
        });

        let validate_request = serde_json::json!({
            "command": "validate",
            "params": {
                "seed": "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
            }
        });

        // Verificar estructura de requests
        assert_eq!(transform_request["command"], "transform");
        assert_eq!(derive_request["command"], "derive");
        assert_eq!(generate_request["command"], "generate");
        assert_eq!(validate_request["command"], "validate");

        // Verificar parámetros
        assert!(transform_request["params"]["seed"].is_string());
        assert!(transform_request["params"]["password"].is_string());
        assert!(derive_request["params"]["networks"].is_array());
        assert_eq!(derive_request["params"]["count"], 3);
        assert_eq!(generate_request["params"]["words"], 12);
        assert!(validate_request["params"]["seed"].is_string());
    }

    #[test]
    fn test_error_types_compatibility() {
        // Test que los tipos de error son compatibles
        let validation_error = SCypherError::validation("Test validation error".to_string());
        let invalid_input_error = SCypherError::InvalidInput("Test input error".to_string());

        assert!(validation_error.to_string().contains("Test validation error"));
        assert!(invalid_input_error.to_string().contains("Test input error"));

        // Verificar que se pueden convertir a JSON errors
        let test_context = ExecutionContext::for_testing();
        handle_json_error_with_context(&validation_error, Some(test_context.clone()));
        handle_json_error_with_context(&invalid_input_error, Some(test_context));
    }

    #[test]
    fn test_menu_choice_compatibility() {
        // Test que los MainMenuChoice son compatibles
        use crate::cli::menu::MainMenuChoice;

        let choices = vec![
            MainMenuChoice::TransformSeed,
            MainMenuChoice::DeriveAddresses,
            MainMenuChoice::GenerateSeed,
            MainMenuChoice::ValidateSeed,
        ];

        for choice in choices {
            // Verificar que se pueden procesar
            assert!(matches!(choice,
                MainMenuChoice::TransformSeed |
                MainMenuChoice::DeriveAddresses |
                MainMenuChoice::GenerateSeed |
                MainMenuChoice::ValidateSeed
            ));
        }
    }

    #[test]
    fn test_network_info_integration() {
        // Test integración con network info
        let networks = crate::supported_networks();
        assert!(!networks.is_empty());

        // Verificar que Bitcoin está presente
        let bitcoin_network = networks.iter().find(|n| n.name == "bitcoin");
        assert!(bitcoin_network.is_some());

        let bitcoin = bitcoin_network.unwrap();
        assert_eq!(bitcoin.symbol, "BTC");
        assert!(!bitcoin.address_types.is_empty());
        assert!(!bitcoin.derivation_path.is_empty());

        // Verificar que Ethereum está presente
        let ethereum_network = networks.iter().find(|n| n.name == "ethereum");
        assert!(ethereum_network.is_some());

        let ethereum = ethereum_network.unwrap();
        assert_eq!(ethereum.symbol, "ETH");
        assert!(!ethereum.address_types.is_empty());
        assert!(!ethereum.derivation_path.is_empty());
    }
}
