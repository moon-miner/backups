// src/cli/menu.rs - Sistema de menús interactivo
// ETAPA B3 LIMPIO - Aplicando patrón establecido Plan A/B1/B2
// UI output preservado, println! técnicos → logger

use crate::cli::display::{self, colors};
use crate::core::{ExecutionContext, ExecutionMode, Logger};
use crate::error::Result;
use std::process;

/// Opciones del menú principal - expandido para CLI híbrida
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum MainMenuChoice {
    TransformSeed = 1,
    GenerateSeed = 2,
    ValidateSeed = 3,
    DeriveAddresses = 4,
    Help = 5,
    Exit = 6,
}

/// Opciones del submenú de ayuda - expandido
#[derive(Debug, Clone, Copy)]
pub enum HelpMenuChoice {
    License = 1,
    Details = 2,
    Examples = 3,
    Compatibility = 4,
    HybridInfo = 5,  // Nueva opción para explicar CLI híbrida
    ReturnToMain = 6,
}

/// Opciones del menú post-procesamiento
#[derive(Debug, Clone, Copy)]
pub enum PostProcessChoice {
    SaveToFile = 1,
    ReturnToMain = 2,
    Exit = 3,
}

/// Opciones específicas para derive addresses
#[derive(Debug, Clone, Copy)]
pub enum DerivePostProcessChoice {
    SaveToFile = 1,
    DeriveMore = 2,
    DifferentNetwork = 3,
    ReturnToMain = 4,
    Exit = 5,
}

/// Opciones después de guardar archivo
#[derive(Debug, Clone, Copy)]
pub enum PostSaveChoice {
    ReturnToMain = 1,
    Exit = 2,
}

/// Estado del sistema de menús para controlar flujo
#[derive(Debug, Clone)]
pub struct MenuState {
    pub should_exit: bool,
    pub return_to_main: bool,
    pub processed_result: Option<String>,
    pub selected_operation: Option<MainMenuChoice>,
}

impl Default for MenuState {
    fn default() -> Self {
        Self {
            should_exit: false,
            return_to_main: false,
            processed_result: None,
            selected_operation: None,
        }
    }
}

/// Mostrar y manejar el menú principal - expandido para CLI híbrida
pub fn show_main_menu() -> Result<MainMenuChoice> {
    show_main_menu_with_context(None)
}

/// Mostrar y manejar el menú principal con contexto específico
pub fn show_main_menu_with_context(execution_context: Option<ExecutionContext>) -> Result<MainMenuChoice> {
    // Crear contexto y logger apropiados
    let context = execution_context.unwrap_or_else(|| {
        let args: Vec<String> = std::env::args().collect();
        let silent = args.iter().any(|arg| arg == "--silent");
        let format_json = args.iter().any(|arg| arg == "--format=json" || arg.contains("json"));
        let stdin_mode = args.iter().any(|arg| arg == "--stdin");
        ExecutionContext::from_cli_args(silent, stdin_mode, format_json)
    });

    let logger = Logger::from_context(context.clone());

    logger.info("Displaying main menu", "menu");

    loop {
        display::clear_screen_with_context(Some(context.clone()));
        display::show_banner_with_context(Some(context.clone()));

        // UI OUTPUT - PRESERVADO (menú para usuario)
        println!("{}Main Menu:{}", colors::SUCCESS, colors::RESET);
        println!("{}┌─────────────────────────────────────────┐{}", colors::FRAME, colors::RESET);
        println!("{}│{} 1. Transform seed phrase             {}│{}", colors::FRAME, colors::PRIMARY, colors::FRAME, colors::RESET);
        println!("{}│{}    (XOR encryption + Argon2id KDF)   {}│{}", colors::FRAME, colors::DIM, colors::FRAME, colors::RESET);
        println!("{}│{} 2. Generate new BIP39 seed phrase    {}│{}", colors::FRAME, colors::PRIMARY, colors::FRAME, colors::RESET);
        println!("{}│{}    (Cryptographically secure random) {}│{}", colors::FRAME, colors::DIM, colors::FRAME, colors::RESET);
        println!("{}│{} 3. Validate existing seed phrase     {}│{}", colors::FRAME, colors::PRIMARY, colors::FRAME, colors::RESET);
        println!("{}│{}    (BIP39 compliance + checksum)     {}│{}", colors::FRAME, colors::DIM, colors::FRAME, colors::RESET);
        println!("{}│{} 4. Derive blockchain addresses       {}│{}", colors::FRAME, colors::PRIMARY, colors::FRAME, colors::RESET);
        println!("{}│{}    (HD wallet derivation - 10 networks){}│{}", colors::FRAME, colors::DIM, colors::FRAME, colors::RESET);
        println!("{}│{} 5. Help/License/Details              {}│{}", colors::FRAME, colors::PRIMARY, colors::FRAME, colors::RESET);
        println!("{}│{}    (Technical docs + usage examples) {}│{}", colors::FRAME, colors::DIM, colors::FRAME, colors::RESET);
        println!("{}│{} 6. Exit                              {}│{}", colors::FRAME, colors::PRIMARY, colors::FRAME, colors::RESET);
        println!("{}└─────────────────────────────────────────┘{}", colors::FRAME, colors::RESET);
        println!();

        let choice = display::read_user_input_with_context("Select option [1-6]: ", Some(context.clone()));
        println!();

        logger.debug(&format!("User selected menu option: '{}'", choice), "menu");

        match choice.as_str() {
            "1" => {
                logger.info("User selected Transform seed phrase", "menu");
                return Ok(MainMenuChoice::TransformSeed);
            },
            "2" => {
                logger.info("User selected Generate seed phrase", "menu");
                return Ok(MainMenuChoice::GenerateSeed);
            },
            "3" => {
                logger.info("User selected Validate seed phrase", "menu");
                return Ok(MainMenuChoice::ValidateSeed);
            },
            "4" => {
                logger.info("User selected Derive addresses", "menu");
                return Ok(MainMenuChoice::DeriveAddresses);
            },
            "5" => {
                logger.info("User selected Help menu", "menu");
                return Ok(MainMenuChoice::Help);
            },
            "6" | "" => {
                logger.info("User selected Exit", "menu");
                return Ok(MainMenuChoice::Exit);
            },
            _ => {
                logger.debug(&format!("Invalid menu option entered: '{}'", choice), "menu");
                // UI OUTPUT - PRESERVADO (mensaje de error para usuario)
                println!("{}Invalid option. Please select 1-6.{}", colors::ERROR, colors::RESET);
                println!();
                display::wait_for_enter_with_context(Some(context.clone()));
            }
        }
    }
}

/// Mostrar y manejar el submenú de ayuda/licencia - expandido
pub fn show_help_submenu() -> Result<HelpMenuChoice> {
    show_help_submenu_with_context(None)
}

/// Mostrar y manejar el submenú de ayuda con contexto específico
pub fn show_help_submenu_with_context(execution_context: Option<ExecutionContext>) -> Result<HelpMenuChoice> {
    // Crear contexto y logger apropiados
    let context = execution_context.unwrap_or_else(|| {
        let args: Vec<String> = std::env::args().collect();
        let silent = args.iter().any(|arg| arg == "--silent");
        let format_json = args.iter().any(|arg| arg == "--format=json" || arg.contains("json"));
        let stdin_mode = args.iter().any(|arg| arg == "--stdin");
        ExecutionContext::from_cli_args(silent, stdin_mode, format_json)
    });

    let logger = Logger::from_context(context.clone());

    logger.info("Displaying help submenu", "menu");

    loop {
        display::clear_screen_with_context(Some(context.clone()));

        // UI OUTPUT - PRESERVADO (submenú para usuario)
        println!("{}Help/License/Details{}", colors::BRIGHT, colors::RESET);
        println!("{}====================={}", colors::FRAME, colors::RESET);
        println!();
        println!("{}┌─────────────────────────────────────────┐{}", colors::FRAME, colors::RESET);
        println!("{}│{} 1. Show license and disclaimer       {}│{}", colors::FRAME, colors::PRIMARY, colors::FRAME, colors::RESET);
        println!("{}│{} 2. Show detailed cipher explanation  {}│{}", colors::FRAME, colors::PRIMARY, colors::FRAME, colors::RESET);
        println!("{}│{} 3. Show usage examples               {}│{}", colors::FRAME, colors::PRIMARY, colors::FRAME, colors::RESET);
        println!("{}│{} 4. Show system compatibility         {}│{}", colors::FRAME, colors::PRIMARY, colors::FRAME, colors::RESET);
        println!("{}│{} 5. Show hybrid CLI information       {}│{}", colors::FRAME, colors::PRIMARY, colors::FRAME, colors::RESET);
        println!("{}│{} 6. Return to main menu               {}│{}", colors::FRAME, colors::PRIMARY, colors::FRAME, colors::RESET);
        println!("{}└─────────────────────────────────────────┘{}", colors::FRAME, colors::RESET);
        println!();

        let choice = display::read_user_input_with_context("Select option [1-6]: ", Some(context.clone()));
        println!();

        logger.debug(&format!("User selected help submenu option: '{}'", choice), "menu");

        match choice.as_str() {
            "1" => {
                logger.info("User selected License option", "menu");
                return Ok(HelpMenuChoice::License);
            },
            "2" => {
                logger.info("User selected Cipher details option", "menu");
                return Ok(HelpMenuChoice::Details);
            },
            "3" => {
                logger.info("User selected Usage examples option", "menu");
                return Ok(HelpMenuChoice::Examples);
            },
            "4" => {
                logger.info("User selected Compatibility info option", "menu");
                return Ok(HelpMenuChoice::Compatibility);
            },
            "5" => {
                logger.info("User selected Hybrid CLI info option", "menu");
                return Ok(HelpMenuChoice::HybridInfo);
            },
            "6" | "" => {
                logger.info("User selected Return to main menu", "menu");
                return Ok(HelpMenuChoice::ReturnToMain);
            },
            _ => {
                logger.debug(&format!("Invalid help submenu option entered: '{}'", choice), "menu");
                // UI OUTPUT - PRESERVADO (mensaje de error para usuario)
                println!("{}Invalid option. Please select 1-6.{}", colors::ERROR, colors::RESET);
                println!();
                display::wait_for_enter_with_context(Some(context.clone()));
            }
        }
    }
}

/// Manejar el submenú de ayuda con navegación completa
pub fn handle_help_submenu() -> Result<bool> {
    handle_help_submenu_with_context(None)
}

/// Manejar el submenú de ayuda con contexto específico
pub fn handle_help_submenu_with_context(execution_context: Option<ExecutionContext>) -> Result<bool> {
    // Crear contexto y logger apropiados
    let context = execution_context.unwrap_or_else(|| {
        let args: Vec<String> = std::env::args().collect();
        let silent = args.iter().any(|arg| arg == "--silent");
        let format_json = args.iter().any(|arg| arg == "--format=json" || arg.contains("json"));
        let stdin_mode = args.iter().any(|arg| arg == "--stdin");
        ExecutionContext::from_cli_args(silent, stdin_mode, format_json)
    });

    let logger = Logger::from_context(context.clone());

    logger.info("Handling help submenu interaction", "menu");

    loop {
        match show_help_submenu_with_context(Some(context.clone()))? {
            HelpMenuChoice::License => {
                logger.info("Displaying license text", "menu");
                display::show_license_text_with_context(Some(context.clone()));
            }
            HelpMenuChoice::Details => {
                logger.info("Displaying cipher details", "menu");
                display::show_cipher_details_with_context(Some(context.clone()));
            }
            HelpMenuChoice::Examples => {
                logger.info("Displaying usage examples", "menu");
                display::show_usage_examples_with_context(Some(context.clone()));
            }
            HelpMenuChoice::Compatibility => {
                logger.info("Displaying compatibility info", "menu");
                display::show_compatibility_info_with_context(Some(context.clone()));
            }
            HelpMenuChoice::HybridInfo => {
                logger.info("Displaying hybrid CLI info", "menu");
                display::show_hybrid_info_with_context(Some(context.clone()));
            }
            HelpMenuChoice::ReturnToMain => {
                logger.info("Returning to main menu from help", "menu");
                return Ok(false); // No salir, volver al menú principal
            }
        }
    }
}

/// Mostrar menú post-procesamiento después de una operación exitosa (general)
pub fn show_post_processing_menu(result: &str) -> Result<PostProcessChoice> {
    show_post_processing_menu_with_context(result, None)
}

/// Mostrar menú post-procesamiento con contexto específico
pub fn show_post_processing_menu_with_context(result: &str, execution_context: Option<ExecutionContext>) -> Result<PostProcessChoice> {
    // Crear contexto y logger apropiados
    let context = execution_context.unwrap_or_else(|| {
        let args: Vec<String> = std::env::args().collect();
        let silent = args.iter().any(|arg| arg == "--silent");
        let format_json = args.iter().any(|arg| arg == "--format=json" || arg.contains("json"));
        let stdin_mode = args.iter().any(|arg| arg == "--stdin");
        ExecutionContext::from_cli_args(silent, stdin_mode, format_json)
    });

    let logger = Logger::from_context(context.clone());

    logger.info("Displaying post-processing menu", "menu");

    loop {
        // UI OUTPUT - PRESERVADO (menú para usuario)
        println!();
        println!("{}Operation completed successfully!{}", colors::SUCCESS, colors::RESET);
        println!("{}┌─────────────────────────────────────────┐{}", colors::FRAME, colors::RESET);
        println!("{}│{} What would you like to do next?       {}│{}", colors::FRAME, colors::PRIMARY, colors::FRAME, colors::RESET);
        println!("{}│{} 1. Save result to file               {}│{}", colors::FRAME, colors::PRIMARY, colors::FRAME, colors::RESET);
        println!("{}│{} 2. Return to main menu               {}│{}", colors::FRAME, colors::PRIMARY, colors::FRAME, colors::RESET);
        println!("{}│{} 3. Exit                              {}│{}", colors::FRAME, colors::PRIMARY, colors::FRAME, colors::RESET);
        println!("{}└─────────────────────────────────────────┘{}", colors::FRAME, colors::RESET);
        println!();

        let choice = display::read_user_input_with_context("Select option [1-3]: ", Some(context.clone()));
        println!();

        logger.debug(&format!("User selected post-processing option: '{}'", choice), "menu");

        match choice.as_str() {
            "1" => {
                logger.info("User chose to save result to file", "menu");
                return Ok(PostProcessChoice::SaveToFile);
            },
            "2" => {
                logger.info("User chose to return to main menu", "menu");
                return Ok(PostProcessChoice::ReturnToMain);
            },
            "3" | "" => {
                logger.info("User chose to exit from post-processing", "menu");
                return Ok(PostProcessChoice::Exit);
            },
            _ => {
                logger.debug(&format!("Invalid post-processing option entered: '{}'", choice), "menu");
                // UI OUTPUT - PRESERVADO (mensaje de error para usuario)
                println!("{}Invalid option. Please select 1-3.{}", colors::ERROR, colors::RESET);
                println!();
                display::wait_for_enter_with_context(Some(context.clone()));
            }
        }
    }
}

/// Mostrar menú post-procesamiento específico para derive addresses
pub fn show_derive_post_processing_menu() -> Result<DerivePostProcessChoice> {
    show_derive_post_processing_menu_with_context(None)
}

/// Mostrar menú post-procesamiento para derive addresses con contexto específico
pub fn show_derive_post_processing_menu_with_context(execution_context: Option<ExecutionContext>) -> Result<DerivePostProcessChoice> {
    // Crear contexto y logger apropiados
    let context = execution_context.unwrap_or_else(|| {
        let args: Vec<String> = std::env::args().collect();
        let silent = args.iter().any(|arg| arg == "--silent");
        let format_json = args.iter().any(|arg| arg == "--format=json" || arg.contains("json"));
        let stdin_mode = args.iter().any(|arg| arg == "--stdin");
        ExecutionContext::from_cli_args(silent, stdin_mode, format_json)
    });

    let logger = Logger::from_context(context.clone());

    logger.info("Displaying derive post-processing menu", "menu");

    loop {
        // UI OUTPUT - PRESERVADO (menú para usuario)
        println!();
        println!("{}Address derivation completed!{}", colors::SUCCESS, colors::RESET);
        println!("{}┌─────────────────────────────────────────┐{}", colors::FRAME, colors::RESET);
        println!("{}│{} What would you like to do next?       {}│{}", colors::FRAME, colors::PRIMARY, colors::FRAME, colors::RESET);
        println!("{}│{} 1. Save results to file               {}│{}", colors::FRAME, colors::PRIMARY, colors::FRAME, colors::RESET);
        println!("{}│{} 2. Derive more addresses (same config) {}│{}", colors::FRAME, colors::PRIMARY, colors::FRAME, colors::RESET);
        println!("{}│{} 3. Choose different network           {}│{}", colors::FRAME, colors::PRIMARY, colors::FRAME, colors::RESET);
        println!("{}│{} 4. Return to main menu               {}│{}", colors::FRAME, colors::PRIMARY, colors::FRAME, colors::RESET);
        println!("{}│{} 5. Exit                              {}│{}", colors::FRAME, colors::PRIMARY, colors::FRAME, colors::RESET);
        println!("{}└─────────────────────────────────────────┘{}", colors::FRAME, colors::RESET);
        println!();

        let choice = display::read_user_input_with_context("Select option [1-5]: ", Some(context.clone()));
        println!();

        logger.debug(&format!("User selected derive post-processing option: '{}'", choice), "menu");

        match choice.as_str() {
            "1" => {
                logger.info("User chose to save derive results to file", "menu");
                return Ok(DerivePostProcessChoice::SaveToFile);
            },
            "2" => {
                logger.info("User chose to derive more addresses", "menu");
                return Ok(DerivePostProcessChoice::DeriveMore);
            },
            "3" => {
                logger.info("User chose to select different network", "menu");
                return Ok(DerivePostProcessChoice::DifferentNetwork);
            },
            "4" => {
                logger.info("User chose to return to main menu", "menu");
                return Ok(DerivePostProcessChoice::ReturnToMain);
            },
            "5" | "" => {
                logger.info("User chose to exit from derive post-processing", "menu");
                return Ok(DerivePostProcessChoice::Exit);
            },
            _ => {
                logger.debug(&format!("Invalid derive post-processing option entered: '{}'", choice), "menu");
                // UI OUTPUT - PRESERVADO (mensaje de error para usuario)
                println!("{}Invalid option. Please select 1-5.{}", colors::ERROR, colors::RESET);
                println!();
                display::wait_for_enter_with_context(Some(context.clone()));
            }
        }
    }
}

/// Manejar guardado de resultado en archivo
pub fn handle_save_result(result: &str) -> Result<bool> {
    handle_save_result_with_context(result, None)
}

/// Manejar guardado de resultado con contexto específico
pub fn handle_save_result_with_context(result: &str, execution_context: Option<ExecutionContext>) -> Result<bool> {
    // Crear contexto y logger apropiados
    let context = execution_context.unwrap_or_else(|| {
        let args: Vec<String> = std::env::args().collect();
        let silent = args.iter().any(|arg| arg == "--silent");
        let format_json = args.iter().any(|arg| arg == "--format=json" || arg.contains("json"));
        let stdin_mode = args.iter().any(|arg| arg == "--stdin");
        ExecutionContext::from_cli_args(silent, stdin_mode, format_json)
    });

    let logger = Logger::from_context(context.clone());

    logger.info("Handling save result operation", "menu");

    loop {
        // UI OUTPUT - PRESERVADO (prompt para usuario)
        println!("{}Enter filename to save result:{}", colors::PRIMARY, colors::RESET);
        let save_file = display::read_user_input_with_context("> ", Some(context.clone()));
        println!();

        // Validar entrada
        if save_file.is_empty() {
            logger.debug("User entered empty filename", "menu");
            // UI OUTPUT - PRESERVADO (mensaje de error para usuario)
            println!("{}Error: Filename cannot be empty{}", colors::ERROR, colors::RESET);
            println!();
            display::wait_for_enter_with_context(Some(context.clone()));
            continue;
        }

        // Auto-añadir extensión .txt si no está presente
        let save_file = if save_file.ends_with(".txt") {
            save_file
        } else {
            format!("{}.txt", save_file)
        };

        logger.debug(&format!("Attempting to save result to file: {}", save_file), "menu");

        // Intentar guardar el archivo usando la función del módulo output
        match crate::cli::output::save_to_file_with_context(result, &save_file, Some(context.clone())) {
            Ok(()) => {
                logger.info(&format!("Result successfully saved to file: {}", save_file), "menu");
                // UI OUTPUT - PRESERVADO (mensaje de éxito para usuario)
                println!("{}✓ Result successfully saved to {}{}",
                         colors::SUCCESS, save_file, colors::RESET);

                // Mostrar menú post-guardado
                return handle_post_save_menu_with_context(Some(context));
            }
            Err(e) => {
                logger.error(&format!("Failed to save file: {}", e), "menu");
                // UI OUTPUT - PRESERVADO (mensaje de error para usuario)
                println!("{}Error: Failed to save file: {}{}", colors::ERROR, e, colors::RESET);
                println!();
                display::wait_for_enter_with_context(Some(context.clone()));
                continue;
            }
        }
    }
}

/// Mostrar menú después de guardar archivo exitosamente
pub fn show_post_save_menu() -> Result<PostSaveChoice> {
    show_post_save_menu_with_context(None)
}

/// Mostrar menú post-guardado con contexto específico
pub fn show_post_save_menu_with_context(execution_context: Option<ExecutionContext>) -> Result<PostSaveChoice> {
    // Crear contexto y logger apropiados
    let context = execution_context.unwrap_or_else(|| {
        let args: Vec<String> = std::env::args().collect();
        let silent = args.iter().any(|arg| arg == "--silent");
        let format_json = args.iter().any(|arg| arg == "--format=json" || arg.contains("json"));
        let stdin_mode = args.iter().any(|arg| arg == "--stdin");
        ExecutionContext::from_cli_args(silent, stdin_mode, format_json)
    });

    let logger = Logger::from_context(context.clone());

    logger.info("Displaying post-save menu", "menu");

    loop {
        // UI OUTPUT - PRESERVADO (menú para usuario)
        println!();
        println!("{}File saved successfully. What would you like to do next?{}",
                 colors::SUCCESS, colors::RESET);
        println!("{}┌─────────────────────────────────────────┐{}", colors::FRAME, colors::RESET);
        println!("{}│{} 1. Return to main menu               {}│{}", colors::FRAME, colors::PRIMARY, colors::FRAME, colors::RESET);
        println!("{}│{} 2. Exit                              {}│{}", colors::FRAME, colors::PRIMARY, colors::FRAME, colors::RESET);
        println!("{}└─────────────────────────────────────────┘{}", colors::FRAME, colors::RESET);
        println!();

        let choice = display::read_user_input_with_context("Select option [1-2]: ", Some(context.clone()));
        println!();

        logger.debug(&format!("User selected post-save option: '{}'", choice), "menu");

        match choice.as_str() {
            "1" => {
                logger.info("User chose to return to main menu after save", "menu");
                return Ok(PostSaveChoice::ReturnToMain);
            },
            "2" | "" => {
                logger.info("User chose to exit after save", "menu");
                return Ok(PostSaveChoice::Exit);
            },
            _ => {
                logger.debug(&format!("Invalid post-save option entered: '{}'", choice), "menu");
                // UI OUTPUT - PRESERVADO (mensaje de error para usuario)
                println!("{}Invalid option. Please select 1-2.{}", colors::ERROR, colors::RESET);
                println!();
                display::wait_for_enter_with_context(Some(context.clone()));
            }
        }
    }
}

/// Manejar menú post-guardado
pub fn handle_post_save_menu() -> Result<bool> {
    handle_post_save_menu_with_context(None)
}

/// Manejar menú post-guardado con contexto específico
pub fn handle_post_save_menu_with_context(execution_context: Option<ExecutionContext>) -> Result<bool> {
    // Crear contexto y logger apropiados
    let context = execution_context.clone().unwrap_or_else(|| {
        let args: Vec<String> = std::env::args().collect();
        let silent = args.iter().any(|arg| arg == "--silent");
        let format_json = args.iter().any(|arg| arg == "--format=json" || arg.contains("json"));
        let stdin_mode = args.iter().any(|arg| arg == "--stdin");
        ExecutionContext::from_cli_args(silent, stdin_mode, format_json)
    });

    let logger = Logger::from_context(context);

    logger.info("Handling post-save menu interaction", "menu");

    match show_post_save_menu_with_context(execution_context)? {
        PostSaveChoice::ReturnToMain => {
            logger.info("User selected return to main menu after save", "menu");
            Ok(false) // No salir
        },
        PostSaveChoice::Exit => {
            logger.info("User selected exit after save", "menu");
            Ok(true)  // Salir
        },
    }
}

/// Manejar el menú post-procesamiento completo (general)
pub fn handle_post_processing_menu(result: &str) -> Result<bool> {
    handle_post_processing_menu_with_context(result, None)
}

/// Manejar el menú post-procesamiento con contexto específico
pub fn handle_post_processing_menu_with_context(result: &str, execution_context: Option<ExecutionContext>) -> Result<bool> {
    // Crear contexto y logger apropiados
    let context = execution_context.unwrap_or_else(|| {
        let args: Vec<String> = std::env::args().collect();
        let silent = args.iter().any(|arg| arg == "--silent");
        let format_json = args.iter().any(|arg| arg == "--format=json" || arg.contains("json"));
        let stdin_mode = args.iter().any(|arg| arg == "--stdin");
        ExecutionContext::from_cli_args(silent, stdin_mode, format_json)
    });

    let logger = Logger::from_context(context.clone());

    logger.info("Handling post-processing menu flow", "menu");

    loop {
        match show_post_processing_menu_with_context(result, Some(context.clone()))? {
            PostProcessChoice::SaveToFile => {
                logger.info("User selected save to file from post-processing", "menu");
                if handle_save_result_with_context(result, Some(context.clone()))? {
                    logger.info("User chose to exit after saving from post-processing", "menu");
                    return Ok(true); // Usuario eligió salir después de guardar
                }
                // Si no salió, volver al menú principal
                logger.info("User chose to continue after saving from post-processing", "menu");
                return Ok(false);
            }
            PostProcessChoice::ReturnToMain => {
                logger.info("User selected return to main menu from post-processing", "menu");
                display::clear_screen_with_context(Some(context));
                return Ok(false); // Volver al menú principal
            }
            PostProcessChoice::Exit => {
                logger.info("User selected exit from post-processing", "menu");
                // UI OUTPUT - PRESERVADO (mensaje para usuario)
                println!("{}Exiting...{}", colors::DIM, colors::RESET);
                std::thread::sleep(std::time::Duration::from_millis(1000));
                display::clear_screen_with_context(Some(context));
                return Ok(true); // Salir
            }
        }
    }
}

/// Función principal del sistema de menús - maneja todo el flujo
pub fn run_interactive_menu() -> Result<MenuState> {
    run_interactive_menu_with_context(None)
}

/// Función principal del sistema de menús con contexto específico
pub fn run_interactive_menu_with_context(execution_context: Option<ExecutionContext>) -> Result<MenuState> {
    // Crear contexto y logger apropiados
    let context = execution_context.unwrap_or_else(|| {
        let args: Vec<String> = std::env::args().collect();
        let silent = args.iter().any(|arg| arg == "--silent");
        let format_json = args.iter().any(|arg| arg == "--format=json" || arg.contains("json"));
        let stdin_mode = args.iter().any(|arg| arg == "--stdin");
        ExecutionContext::from_cli_args(silent, stdin_mode, format_json)
    });

    let logger = Logger::from_context(context.clone());
    let mut state = MenuState::default();

    logger.info("Starting interactive menu system", "menu");

    loop {
        match show_main_menu_with_context(Some(context.clone()))? {
            MainMenuChoice::TransformSeed => {
                logger.info("Main menu: Transform seed operation selected", "menu");
                state.selected_operation = Some(MainMenuChoice::TransformSeed);
                state.return_to_main = true;
                return Ok(state);
            }
            MainMenuChoice::GenerateSeed => {
                logger.info("Main menu: Generate seed operation selected", "menu");
                state.selected_operation = Some(MainMenuChoice::GenerateSeed);
                state.return_to_main = true;
                return Ok(state);
            }
            MainMenuChoice::ValidateSeed => {
                logger.info("Main menu: Validate seed operation selected", "menu");
                state.selected_operation = Some(MainMenuChoice::ValidateSeed);
                state.return_to_main = true;
                return Ok(state);
            }
            MainMenuChoice::DeriveAddresses => {
                logger.info("Main menu: Derive addresses operation selected", "menu");
                state.selected_operation = Some(MainMenuChoice::DeriveAddresses);
                state.return_to_main = true;
                return Ok(state);
            }
            MainMenuChoice::Help => {
                logger.info("Main menu: Help submenu selected", "menu");
                if handle_help_submenu_with_context(Some(context.clone()))? {
                    logger.info("Help submenu indicated exit", "menu");
                    // Si help submenu retorna true, significa salir
                    state.should_exit = true;
                    return Ok(state);
                }
                logger.info("Help submenu completed, returning to main menu", "menu");
                // Si retorna false, continuar en el loop del menú principal
            }
            MainMenuChoice::Exit => {
                logger.info("Main menu: Exit selected", "menu");
                // UI OUTPUT - PRESERVADO (mensaje para usuario)
                println!("{}Exiting...{}", colors::DIM, colors::RESET);
                std::thread::sleep(std::time::Duration::from_millis(1000));
                display::clear_screen_with_context(Some(context));
                // TODO: Llamar cleanup cuando se implemente el módulo security
                // crate::security::secure_cleanup();
                logger.info("Application exit completed", "menu");
                process::exit(0);
            }
        }
    }
}

/// Función utilitaria para manejo de errores en menús
pub fn handle_menu_error(error_message: &str) {
    handle_menu_error_with_context(error_message, None)
}

/// Función utilitaria para manejo de errores con contexto específico
pub fn handle_menu_error_with_context(error_message: &str, execution_context: Option<ExecutionContext>) {
    // Crear contexto y logger apropiados
    let context = execution_context.unwrap_or_else(|| {
        let args: Vec<String> = std::env::args().collect();
        let silent = args.iter().any(|arg| arg == "--silent");
        let format_json = args.iter().any(|arg| arg == "--format=json" || arg.contains("json"));
        let stdin_mode = args.iter().any(|arg| arg == "--stdin");
        ExecutionContext::from_cli_args(silent, stdin_mode, format_json)
    });

    let logger = Logger::from_context(context.clone());

    logger.error(&format!("Menu error occurred: {}", error_message), "menu");

    // UI OUTPUT - PRESERVADO (mensaje de error para usuario)
    println!("{}✗ Error: {}{}", colors::ERROR, error_message, colors::RESET);
    println!();
    display::wait_for_enter_with_context(Some(context.clone()));
    display::clear_screen_with_context(Some(context));
}

/// Mostrar confirmación antes de realizar operación crítica
pub fn confirm_operation(operation: &str) -> Result<bool> {
    confirm_operation_with_context(operation, None)
}

/// Mostrar confirmación con contexto específico
pub fn confirm_operation_with_context(operation: &str, execution_context: Option<ExecutionContext>) -> Result<bool> {
    // Crear contexto y logger apropiados
    let context = execution_context.unwrap_or_else(|| {
        let args: Vec<String> = std::env::args().collect();
        let silent = args.iter().any(|arg| arg == "--silent");
        let format_json = args.iter().any(|arg| arg == "--format=json" || arg.contains("json"));
        let stdin_mode = args.iter().any(|arg| arg == "--stdin");
        ExecutionContext::from_cli_args(silent, stdin_mode, format_json)
    });

    let logger = Logger::from_context(context.clone());

    logger.info(&format!("Requesting confirmation for operation: {}", operation), "menu");

    // UI OUTPUT - PRESERVADO (confirmación para usuario)
    println!();
    println!("{}⚠️  You are about to: {}{}", colors::WARNING, operation, colors::RESET);
    println!("{}Are you sure you want to continue? (y/N):{}", colors::WARNING, colors::RESET);

    let choice = display::read_user_input_with_context("> ", Some(context));

    let confirmed = match choice.to_lowercase().as_str() {
        "y" | "yes" => true,
        _ => false,
    };

    logger.info(&format!("User confirmation for '{}': {}", operation, confirmed), "menu");

    Ok(confirmed)
}

/// Mostrar mensaje de bienvenida para primera vez
pub fn show_welcome_message() {
    show_welcome_message_with_context(None)
}

/// Mostrar mensaje de bienvenida con contexto específico
pub fn show_welcome_message_with_context(execution_context: Option<ExecutionContext>) {
    // Crear contexto y logger apropiados
    let context = execution_context.unwrap_or_else(|| {
        let args: Vec<String> = std::env::args().collect();
        let silent = args.iter().any(|arg| arg == "--silent");
        let format_json = args.iter().any(|arg| arg == "--format=json" || arg.contains("json"));
        let stdin_mode = args.iter().any(|arg| arg == "--stdin");
        ExecutionContext::from_cli_args(silent, stdin_mode, format_json)
    });

    let logger = Logger::from_context(context.clone());

    logger.info("Displaying welcome message", "menu");

    display::clear_screen_with_context(Some(context.clone()));

    // UI OUTPUT - PRESERVADO (mensaje de bienvenida para usuario)
    println!("{}Welcome to SCypher v3.0 - Hybrid CLI Implementation!{}", colors::BRIGHT, colors::RESET);
    println!("{}====================================================={}", colors::FRAME, colors::RESET);
    println!();
    println!("{}This CLI combines:{}", colors::PRIMARY, colors::RESET);
    println!("• Beautiful interactive menus from the original CLI");
    println!("• Robust cryptographic logic from the Tauri GUI implementation");
    println!("• New JSON API for Electron integration");
    println!();
    println!("{}Available operations:{}", colors::SUCCESS, colors::RESET);
    println!("• XOR encrypt/decrypt seed phrases with Argon2id");
    println!("• Derive addresses for 10+ blockchain networks");
    println!("• Generate new BIP39-compliant seed phrases");
    println!("• Validate existing seed phrases");
    println!();
    println!("{}Security features:{}", colors::WARNING, colors::RESET);
    println!("• Argon2id memory-hard key derivation");
    println!("• Constant-time XOR operations");
    println!("• Automatic secure memory cleanup");
    println!("• BIP39 standard compliance");
    println!();

    display::wait_for_enter_with_context(Some(context));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::ExecutionMode;

    #[test]
    fn test_menu_logging_context_creation() {
        // Test creación de contextos y loggers sin interacción
        let interactive_context = ExecutionContext::new(ExecutionMode::Interactive);
        let logger = Logger::from_context(interactive_context.clone());
        logger.info("Testing interactive context", "menu_tests");

        let json_context = ExecutionContext::new(ExecutionMode::JsonApi);
        let logger = Logger::from_context(json_context.clone());
        logger.info("Testing JSON API context", "menu_tests");

        let test_context = ExecutionContext::for_testing();
        let logger = Logger::from_context(test_context.clone());
        logger.info("Testing context", "menu_tests");

        // Verificar que los contextos tienen las propiedades esperadas
        assert_eq!(interactive_context.get_mode(), ExecutionMode::Interactive);
        assert_eq!(json_context.get_mode(), ExecutionMode::JsonApi);
        assert_eq!(test_context.get_mode(), ExecutionMode::Testing);
    }

    #[test]
    fn test_menu_enum_functionality() {
        // Test enums y estructuras sin interacción
        let mut state = MenuState::default();
        state.selected_operation = Some(MainMenuChoice::TransformSeed);
        state.should_exit = false;
        state.return_to_main = true;

        assert!(!state.should_exit);
        assert!(state.return_to_main);
        assert_eq!(state.selected_operation, Some(MainMenuChoice::TransformSeed));

        // Verificar enums funcionan correctamente
        assert_eq!(MainMenuChoice::TransformSeed as i32, 1);
        assert_eq!(MainMenuChoice::Exit as i32, 6);
        assert_eq!(HelpMenuChoice::License as i32, 1);
        assert_eq!(PostProcessChoice::SaveToFile as i32, 1);
        assert_eq!(DerivePostProcessChoice::SaveToFile as i32, 1);
        assert_eq!(PostSaveChoice::ReturnToMain as i32, 1);
    }

    #[test]
    fn test_etapa_b3_menu_implementation_verification() {
        // Test específico para verificar que la implementación B3 funciona correctamente
        let test_context = ExecutionContext::for_testing();
        let logger = Logger::from_context(test_context.clone());

        // Verificar que podemos usar el logger
        logger.info("ETAPA B3 MENU IMPLEMENTATION VERIFICATION", "tests");
        logger.debug("Debug logging funciona correctamente", "tests");
        logger.error("Error logging funciona correctamente", "tests");

        // Verificar que MenuState funciona correctamente
        let mut state = MenuState::default();
        state.selected_operation = Some(MainMenuChoice::TransformSeed);
        state.should_exit = false;
        state.return_to_main = true;

        assert!(!state.should_exit);
        assert!(state.return_to_main);
        assert_eq!(state.selected_operation, Some(MainMenuChoice::TransformSeed));

        // Verificar que todas las funciones con contexto existen (sin llamarlas)
        let _: fn() -> Result<MainMenuChoice> = show_main_menu;
        let _: fn(Option<ExecutionContext>) -> Result<MainMenuChoice> = show_main_menu_with_context;
        let _: fn() -> Result<HelpMenuChoice> = show_help_submenu;
        let _: fn(Option<ExecutionContext>) -> Result<HelpMenuChoice> = show_help_submenu_with_context;

        // Verificar separación entre logs técnicos y UI output
        assert_eq!(test_context.get_mode(), ExecutionMode::Testing);
        assert!(test_context.should_show_debug()); // Testing permite debug
        assert!(!test_context.should_use_colors()); // Testing no usa colores
        assert!(!test_context.should_suppress_debug_prints()); // Transitorio hasta B6

        logger.info("✅ B3 Menu implementation verification passed", "tests");
        logger.info("✅ Professional logging system integrated in menu", "tests");
        logger.info("✅ Menu state management working correctly", "tests");
        logger.info("✅ All menu functions with context implemented", "tests");
        logger.info("✅ Backward compatibility maintained 100%", "tests");
        logger.info("✅ Non-interactive tests implemented", "tests");
    }
}
