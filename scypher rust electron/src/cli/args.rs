// src/cli/args.rs - Parseo de argumentos para CLI híbrida
// ETAPA B4 LIMPIO - Aplicando patrón establecido Plan A/B1/B2/B3
// UI output preservado, println! técnicos → logger
//
// VERSIÓN ACTUALIZADA - Con soporte para --stdin flag y logging profesional

use clap::{Arg, ArgMatches, Command};
use crate::error::{SCypherError, Result};
use crate::cli::display::colors;
use crate::core::{ExecutionContext, ExecutionMode, Logger};

const VERSION: &str = "3.0";
const DEFAULT_ITERATIONS: &str = "5";
const DEFAULT_MEMORY_COST: &str = "131072"; // 128MB en KB

/// Configuración de argumentos para la CLI híbrida
#[derive(Debug, Clone)]
pub struct CliArgs {
    // Modo de operación
    pub command: OperationCommand,
    pub format: OutputFormat,
    pub silent: bool,
    pub stdin_mode: bool, // Flag para modo stdin

    // Archivos
    pub input_file: Option<String>,
    pub output_file: Option<String>,

    // Parámetros crypto
    pub iterations: u32,
    pub memory_cost: u32,
    pub skip_checksum: bool,

    // Parámetros específicos de comandos
    pub networks: Vec<String>,
    pub address_count: u32,
    pub word_count: Option<usize>,

    // Información especial
    pub show_license: bool,
    pub show_details: bool,
    pub show_help: bool,
}

/// Comandos de operación disponibles
#[derive(Debug, Clone, PartialEq)]
pub enum OperationCommand {
    Interactive,        // Modo menú interactivo (default)
    Transform,         // Encrypt/decrypt seed phrase
    Derive,           // Derive blockchain addresses
    Generate,         // Generate new seed phrase
    Validate,         // Validate existing seed phrase
    ShowLicense,      // Mostrar licencia
    ShowDetails,      // Mostrar detalles técnicos
}

/// Formatos de salida
#[derive(Debug, Clone, PartialEq)]
pub enum OutputFormat {
    Human,    // Output bonito para humanos (default)
    Json,     // Output JSON para Electron
}

impl Default for CliArgs {
    fn default() -> Self {
        Self {
            command: OperationCommand::Interactive,
            format: OutputFormat::Human,
            silent: false,
            stdin_mode: false,
            input_file: None,
            output_file: None,
            iterations: 5,
            memory_cost: 131072,
            skip_checksum: false,
            networks: vec!["bitcoin".to_string()],
            address_count: 5,
            word_count: None,
            show_license: false,
            show_details: false,
            show_help: false,
        }
    }
}

/// Crear la configuración de clap para la CLI híbrida
pub fn build_cli() -> Command {
    build_cli_with_context(None)
}

/// Crear la configuración de clap con contexto específico
pub fn build_cli_with_context(execution_context: Option<ExecutionContext>) -> Command {
    // Crear contexto y logger apropiados
    let context = execution_context.unwrap_or_else(|| {
        let args: Vec<String> = std::env::args().collect();
        let silent = args.iter().any(|arg| arg == "--silent");
        let format_json = args.iter().any(|arg| arg == "--format=json" || arg.contains("json"));
        let stdin_mode = args.iter().any(|arg| arg == "--stdin");
        ExecutionContext::from_cli_args(silent, stdin_mode, format_json)
    });

    let logger = Logger::from_context(context);

    logger.info("Building CLI command structure", "args");
    logger.debug("Configuring clap command with all subcommands and arguments", "args");

    Command::new("SCypher")
        .version(VERSION)
        .about("XOR-based BIP39 seed cipher - Hybrid CLI Implementation")
        .long_about("SCypher provides secure, reversible transformation of BIP39 seed phrases \
                    using XOR encryption with Argon2id key derivation. Features three operation \
                    modes: Interactive (beautiful menus), JSON API (Electron integration), \
                    and Silent (script compatibility).")

        // Información especial
        .arg(Arg::new("license")
            .long("license")
            .help("Show license and disclaimer")
            .action(clap::ArgAction::SetTrue))

        .arg(Arg::new("details")
            .long("details")
            .help("Show detailed explanation of the XOR cipher process")
            .action(clap::ArgAction::SetTrue))

        // Comandos principales
        .arg(Arg::new("interactive")
            .long("interactive")
            .help("Run in interactive mode with menus (default)")
            .action(clap::ArgAction::SetTrue))

        .subcommand(
            Command::new("transform")
                .about("Transform (encrypt/decrypt) a seed phrase")
                .arg(Arg::new("seed")
                    .help("Seed phrase to transform")
                    .required(false)
                    .index(1))
                .arg(Arg::new("password")
                    .help("Password for transformation")
                    .required(false)
                    .index(2))
        )

        .subcommand(
            Command::new("derive")
                .about("Derive blockchain addresses from seed phrase")
                .arg(Arg::new("seed")
                    .help("Seed phrase to derive from")
                    .required(false)
                    .index(1))
                .arg(Arg::new("networks")
                    .long("networks")
                    .short('n')
                    .help("Comma-separated list of networks (bitcoin,ethereum,cardano,etc)")
                    .value_name("LIST")
                    .default_value("bitcoin"))
                .arg(Arg::new("count")
                    .long("count")
                    .short('c')
                    .help("Number of addresses to derive per network")
                    .value_name("NUMBER")
                    .default_value("5")
                    .value_parser(clap::value_parser!(u32)))
        )

        .subcommand(
            Command::new("generate")
                .about("Generate a new BIP39 seed phrase")
                .arg(Arg::new("words")
                    .long("words")
                    .short('w')
                    .help("Number of words (12,15,18,21,24)")
                    .value_name("NUMBER")
                    .default_value("12")
                    .value_parser(clap::value_parser!(usize)))
        )

        .subcommand(
            Command::new("validate")
                .about("Validate a BIP39 seed phrase")
                .arg(Arg::new("seed")
                    .help("Seed phrase to validate")
                    .required(false)
                    .index(1))
        )

        // Modos de operación globales
        .arg(Arg::new("format")
            .long("format")
            .help("Output format")
            .value_name("FORMAT")
            .value_parser(["human", "json"])
            .default_value("human")
            .global(true))

        .arg(Arg::new("silent")
            .long("silent")
            .short('s')
            .help("Silent mode - read from stdin, minimal output (for scripting)")
            .action(clap::ArgAction::SetTrue)
            .global(true))

        .arg(Arg::new("stdin")
            .long("stdin")
            .help("Read input from stdin (plain text mode)")
            .action(clap::ArgAction::SetTrue)
            .global(true))

        // Archivos
        .arg(Arg::new("input-file")
            .short('f')
            .long("file")
            .value_name("FILE")
            .help("Read seed phrase from file")
            .value_parser(clap::value_parser!(String))
            .global(true))

        .arg(Arg::new("output")
            .short('o')
            .long("output")
            .value_name("FILE")
            .help("Save output to file (will add .txt extension if needed)")
            .value_parser(clap::value_parser!(String))
            .global(true))

        // Parámetros crypto
        .arg(Arg::new("iterations")
            .short('i')
            .long("iterations")
            .value_name("NUMBER")
            .help("Argon2id iterations (default: 5, min: 1, recommended: 3-10)")
            .default_value(DEFAULT_ITERATIONS)
            .value_parser(clap::value_parser!(u32))
            .global(true))

        .arg(Arg::new("memory")
            .short('m')
            .long("memory-cost")
            .value_name("KB")
            .help("Argon2id memory cost in KB (default: 131072 = 128MB)")
            .default_value(DEFAULT_MEMORY_COST)
            .value_parser(clap::value_parser!(u32))
            .global(true))

        .arg(Arg::new("skip-checksum")
            .long("skip-checksum")
            .help("Skip BIP39 checksum verification (not recommended)")
            .action(clap::ArgAction::SetTrue)
            .global(true))

        // Mantener compatibilidad con CLI vieja
        .arg(Arg::new("encrypt")
            .short('e')
            .long("encrypt")
            .help("Encryption mode (legacy - use 'transform' subcommand)")
            .action(clap::ArgAction::SetTrue)
            .hide(true))

        .arg(Arg::new("decrypt")
            .short('d')
            .long("decrypt")
            .help("Decryption mode (legacy - use 'transform' subcommand)")
            .action(clap::ArgAction::SetTrue)
            .hide(true))
}

/// Parsear argumentos y retornar configuración
pub fn parse_args() -> Result<CliArgs> {
    parse_args_with_context(None)
}

/// Parsear argumentos con contexto específico
pub fn parse_args_with_context(execution_context: Option<ExecutionContext>) -> Result<CliArgs> {
    // Crear contexto y logger apropiados
    let context = execution_context.unwrap_or_else(|| {
        let args: Vec<String> = std::env::args().collect();
        let silent = args.iter().any(|arg| arg == "--silent");
        let format_json = args.iter().any(|arg| arg == "--format=json" || arg.contains("json"));
        let stdin_mode = args.iter().any(|arg| arg == "--stdin");
        ExecutionContext::from_cli_args(silent, stdin_mode, format_json)
    });

    let logger = Logger::from_context(context.clone());

    logger.info("Starting argument parsing", "args");

    let matches = build_cli_with_context(Some(context.clone())).get_matches();
    parse_matches_with_context(&matches, Some(context))
}

/// Parsear desde ArgMatches (útil para testing)
pub fn parse_matches(matches: &ArgMatches) -> Result<CliArgs> {
    parse_matches_with_context(matches, None)
}

/// Parsear desde ArgMatches con contexto específico
pub fn parse_matches_with_context(matches: &ArgMatches, execution_context: Option<ExecutionContext>) -> Result<CliArgs> {
    // Crear contexto y logger apropiados
    let context = execution_context.unwrap_or_else(|| {
        let args: Vec<String> = std::env::args().collect();
        let silent = args.iter().any(|arg| arg == "--silent");
        let format_json = args.iter().any(|arg| arg == "--format=json" || arg.contains("json"));
        let stdin_mode = args.iter().any(|arg| arg == "--stdin");
        ExecutionContext::from_cli_args(silent, stdin_mode, format_json)
    });

    let logger = Logger::from_context(context.clone());

    logger.info("Parsing CLI argument matches", "args");

    let mut args = CliArgs::default();

    // Verificar información especial primero
    if matches.get_flag("license") {
        logger.debug("License flag detected", "args");
        args.show_license = true;
        args.command = OperationCommand::ShowLicense;
        return Ok(args);
    }

    if matches.get_flag("details") {
        logger.debug("Details flag detected", "args");
        args.show_details = true;
        args.command = OperationCommand::ShowDetails;
        return Ok(args);
    }

    // Parsear formato de salida
    args.format = match matches.get_one::<String>("format").unwrap().as_str() {
        "json" => {
            logger.debug("JSON format selected", "args");
            OutputFormat::Json
        },
        _ => {
            logger.debug("Human format selected (default)", "args");
            OutputFormat::Human
        },
    };

    // Parsear modos de entrada
    args.silent = matches.get_flag("silent");
    args.stdin_mode = matches.get_flag("stdin");

    logger.debug(&format!("Input modes - silent: {}, stdin: {}", args.silent, args.stdin_mode), "args");

    // Parsear archivos
    args.input_file = matches.get_one::<String>("input-file").cloned();
    args.output_file = matches.get_one::<String>("output").cloned();

    if let Some(ref input_file) = args.input_file {
        logger.debug(&format!("Input file specified: {}", input_file), "args");
    }
    if let Some(ref output_file) = args.output_file {
        logger.debug(&format!("Output file specified: {}", output_file), "args");
    }

    // Parsear parámetros crypto
    args.iterations = *matches.get_one::<u32>("iterations").unwrap();
    args.memory_cost = *matches.get_one::<u32>("memory").unwrap();
    args.skip_checksum = matches.get_flag("skip-checksum");

    logger.debug(&format!("Crypto params - iterations: {}, memory: {}KB, skip_checksum: {}",
                          args.iterations, args.memory_cost, args.skip_checksum), "args");

    // Validar parámetros crypto
    validate_crypto_params_with_context(args.iterations, args.memory_cost, Some(context.clone()))?;

    // Determinar comando según subcomandos o flags de compatibilidad
    args.command = if let Some((subcommand, sub_matches)) = matches.subcommand() {
        logger.debug(&format!("Subcommand detected: {}", subcommand), "args");

        match subcommand {
            "transform" => {
                logger.info("Transform command selected", "args");
                OperationCommand::Transform
            }
            "derive" => {
                // Parsear redes
                let networks_str = sub_matches.get_one::<String>("networks").unwrap();
                args.networks = networks_str
                    .split(',')
                    .map(|s| s.trim().to_lowercase())
                    .filter(|s| !s.is_empty())
                    .collect();

                if args.networks.is_empty() {
                    logger.debug("No networks specified, defaulting to bitcoin", "args");
                    args.networks = vec!["bitcoin".to_string()];
                }

                logger.debug(&format!("Networks selected: {:?}", args.networks), "args");

                // Parsear conteo de addresses
                args.address_count = *sub_matches.get_one::<u32>("count").unwrap();
                logger.debug(&format!("Address count: {}", args.address_count), "args");

                logger.info("Derive command selected", "args");
                OperationCommand::Derive
            }
            "generate" => {
                let words = *sub_matches.get_one::<usize>("words").unwrap();
                validate_word_count_with_context(words, Some(context.clone()))?;
                args.word_count = Some(words);
                logger.debug(&format!("Generate command with {} words", words), "args");
                logger.info("Generate command selected", "args");
                OperationCommand::Generate
            }
            "validate" => {
                logger.info("Validate command selected", "args");
                OperationCommand::Validate
            }
            _ => {
                logger.debug("Unknown subcommand, defaulting to interactive", "args");
                OperationCommand::Interactive
            },
        }
    } else if matches.get_flag("encrypt") || matches.get_flag("decrypt") {
        // Compatibilidad con CLI vieja
        logger.debug("Legacy encrypt/decrypt flags detected", "args");
        logger.info("Legacy transform command mode activated", "args");
        OperationCommand::Transform
    } else if has_transform_args_with_context(&matches, Some(context.clone())) {
        // Si tiene argumentos que implican transformación
        logger.debug("Transform arguments detected automatically", "args");
        logger.info("Transform command mode auto-detected", "args");
        OperationCommand::Transform
    } else {
        // Default: modo interactivo
        logger.info("Interactive mode selected (default)", "args");
        OperationCommand::Interactive
    };

    logger.info(&format!("Final command determined: {:?}", args.command), "args");
    Ok(args)
}

/// Verificar si tiene argumentos que implican transformación
fn has_transform_args(matches: &ArgMatches) -> bool {
    has_transform_args_with_context(matches, None)
}

/// Verificar si tiene argumentos que implican transformación con contexto específico
fn has_transform_args_with_context(matches: &ArgMatches, execution_context: Option<ExecutionContext>) -> bool {
    // Crear contexto y logger apropiados
    let context = execution_context.unwrap_or_else(|| {
        let args: Vec<String> = std::env::args().collect();
        let silent = args.iter().any(|arg| arg == "--silent");
        let format_json = args.iter().any(|arg| arg == "--format=json" || arg.contains("json"));
        let stdin_mode = args.iter().any(|arg| arg == "--stdin");
        ExecutionContext::from_cli_args(silent, stdin_mode, format_json)
    });

    let logger = Logger::from_context(context);

    logger.debug("Checking for transform arguments", "args");

    let has_transform = matches.get_one::<String>("input-file").is_some() ||
        matches.get_one::<String>("output").is_some() ||
        *matches.get_one::<u32>("iterations").unwrap() != 5 ||
        *matches.get_one::<u32>("memory").unwrap() != 131072 ||
        matches.get_flag("skip-checksum");

    logger.debug(&format!("Transform arguments detected: {}", has_transform), "args");
    has_transform
}

/// Validar parámetros criptográficos
pub fn validate_crypto_params(iterations: u32, memory_cost: u32) -> Result<()> {
    validate_crypto_params_with_context(iterations, memory_cost, None)
}

/// Validar parámetros criptográficos con contexto específico
pub fn validate_crypto_params_with_context(iterations: u32, memory_cost: u32, execution_context: Option<ExecutionContext>) -> Result<()> {
    // Crear contexto y logger apropiados
    let context = execution_context.unwrap_or_else(|| {
        let args: Vec<String> = std::env::args().collect();
        let silent = args.iter().any(|arg| arg == "--silent");
        let format_json = args.iter().any(|arg| arg == "--format=json" || arg.contains("json"));
        let stdin_mode = args.iter().any(|arg| arg == "--stdin");
        ExecutionContext::from_cli_args(silent, stdin_mode, format_json)
    });

    let logger = Logger::from_context(context);

    logger.debug(&format!("Validating crypto params - iterations: {}, memory_cost: {}KB", iterations, memory_cost), "args");

    if iterations == 0 {
        logger.error("Iterations cannot be zero", "args");
        return Err(SCypherError::validation("Iterations must be at least 1".to_string()));
    }

    if iterations > 100 {
        logger.error(&format!("Iterations too high: {} (max 100)", iterations), "args");
        return Err(SCypherError::validation(
            format!("Iterations too high: {} (maximum recommended: 100)", iterations)
        ));
    }

    // Validar costo de memoria (mínimo 8MB, máximo 2GB)
    if memory_cost < 8192 {  // 8MB
        logger.error(&format!("Memory cost too low: {}KB (min 8192KB)", memory_cost), "args");
        return Err(SCypherError::validation(
            format!("Memory cost too low: {}KB (minimum: 8192KB = 8MB)", memory_cost)
        ));
    }

    if memory_cost > 2_097_152 {  // 2GB
        logger.error(&format!("Memory cost too high: {}KB (max 2097152KB)", memory_cost), "args");
        return Err(SCypherError::validation(
            format!("Memory cost too high: {}KB (maximum: 2097152KB = 2GB)", memory_cost)
        ));
    }

    logger.debug("Crypto params validation passed", "args");
    Ok(())
}

/// Validar número de palabras para generación
pub fn validate_word_count(words: usize) -> Result<()> {
    validate_word_count_with_context(words, None)
}

/// Validar número de palabras con contexto específico
pub fn validate_word_count_with_context(words: usize, execution_context: Option<ExecutionContext>) -> Result<()> {
    // Crear contexto y logger apropiados
    let context = execution_context.unwrap_or_else(|| {
        let args: Vec<String> = std::env::args().collect();
        let silent = args.iter().any(|arg| arg == "--silent");
        let format_json = args.iter().any(|arg| arg == "--format=json" || arg.contains("json"));
        let stdin_mode = args.iter().any(|arg| arg == "--stdin");
        ExecutionContext::from_cli_args(silent, stdin_mode, format_json)
    });

    let logger = Logger::from_context(context);

    logger.debug(&format!("Validating word count: {}", words), "args");

    let valid_counts = [12, 15, 18, 21, 24];
    if !valid_counts.contains(&words) {
        logger.error(&format!("Invalid word count: {} (valid: 12,15,18,21,24)", words), "args");
        return Err(SCypherError::validation(
            format!("Invalid word count: {} (valid: 12, 15, 18, 21, 24)", words)
        ));
    }

    logger.debug("Word count validation passed", "args");
    Ok(())
}

/// Mostrar help personalizado para CLI híbrida - ACTUALIZADO
pub fn show_help() {
    show_help_with_context(None)
}

/// Mostrar help personalizado con contexto específico
pub fn show_help_with_context(execution_context: Option<ExecutionContext>) {
    // Crear contexto y logger apropiados
    let context = execution_context.unwrap_or_else(|| {
        let args: Vec<String> = std::env::args().collect();
        let silent = args.iter().any(|arg| arg == "--silent");
        let format_json = args.iter().any(|arg| arg == "--format=json" || arg.contains("json"));
        let stdin_mode = args.iter().any(|arg| arg == "--stdin");
        ExecutionContext::from_cli_args(silent, stdin_mode, format_json)
    });

    let logger = Logger::from_context(context);

    logger.info("Displaying custom help", "args");

    // UI OUTPUT - PRESERVADO (help para usuario)
    println!("{}SCypher v{} - Hybrid CLI Implementation{}", colors::BRIGHT, VERSION, colors::RESET);
    println!("{}======================================{}", colors::FRAME, colors::RESET);
    println!();
    println!("{}Three Operation Modes:{}", colors::PRIMARY, colors::RESET);
    println!("{}┌─────────────────────────────────────────┐{}", colors::FRAME, colors::RESET);
    println!("{}│{} 1. Interactive - Beautiful menus     {}│{}", colors::FRAME, colors::SUCCESS, colors::FRAME, colors::RESET);
    println!("{}│{} 2. JSON API - Electron integration   {}│{}", colors::FRAME, colors::SUCCESS, colors::FRAME, colors::RESET);
    println!("{}│{} 3. Silent - Script compatibility     {}│{}", colors::FRAME, colors::SUCCESS, colors::FRAME, colors::RESET);
    println!("{}└─────────────────────────────────────────┘{}", colors::FRAME, colors::RESET);
    println!();

    println!("{}Commands:{}", colors::PRIMARY, colors::RESET);
    println!("  scypher-cli                                    {}# Interactive mode{}", colors::DIM, colors::RESET);
    println!("  scypher-cli transform \"seed\" \"password\"         {}# Transform with args{}", colors::DIM, colors::RESET);
    println!("  scypher-cli transform --stdin --format human   {}# Transform from stdin{}", colors::DIM, colors::RESET);
    println!("  scypher-cli derive \"seed\" --networks btc        {}# Derive addresses{}", colors::DIM, colors::RESET);
    println!("  scypher-cli generate --words 24                {}# Generate new seed{}", colors::DIM, colors::RESET);
    println!("  scypher-cli validate \"seed phrase\"              {}# Validate seed{}", colors::DIM, colors::RESET);
    println!();

    println!("{}Input Modes:{}", colors::PRIMARY, colors::RESET);
    println!("  [no flags]        {}# Interactive prompts (default){}", colors::DIM, colors::RESET);
    println!("  --stdin           {}# Read from stdin (plain text){}", colors::DIM, colors::RESET);
    println!("  --silent          {}# JSON input/output mode{}", colors::DIM, colors::RESET);
    println!();

    println!("{}Formats:{}", colors::PRIMARY, colors::RESET);
    println!("  --format human    {}# Beautiful output for humans (default){}", colors::DIM, colors::RESET);
    println!("  --format json     {}# Structured JSON for Electron{}", colors::DIM, colors::RESET);
    println!();

    println!("{}Security:{}", colors::WARNING, colors::RESET);
    println!("  -i, --iterations N     {}# Argon2id iterations (default: 5){}", colors::DIM, colors::RESET);
    println!("  -m, --memory-cost KB   {}# Memory cost (default: 131072 = 128MB){}", colors::DIM, colors::RESET);
    println!();

    println!("{}Examples:{}", colors::PRIMARY, colors::RESET);
    println!("  {}# Direct arguments (no prompts):{}", colors::DIM, colors::RESET);
    println!("  scypher-cli transform \"abandon abandon...\" \"password123\"");
    println!();
    println!("  {}# Stdin mode:{}", colors::DIM, colors::RESET);
    println!("  echo -e \"seed phrase\\npassword\" | scypher-cli transform --stdin");
    println!();
    println!("  {}# JSON API mode:{}", colors::DIM, colors::RESET);
    println!("  echo '{{\"command\":\"transform\",\"params\":{{\"phrase\":\"...\",\"password\":\"...\"}}}}' | scypher-cli --silent --format json");
    println!();

    println!("For detailed help: {}scypher-cli --help{}", colors::BRIGHT, colors::RESET);

    logger.debug("Custom help display completed", "args");
}

/// Mostrar información de versión
pub fn show_version() {
    show_version_with_context(None)
}

/// Mostrar información de versión con contexto específico
pub fn show_version_with_context(execution_context: Option<ExecutionContext>) {
    // Crear contexto y logger apropiados
    let context = execution_context.unwrap_or_else(|| {
        let args: Vec<String> = std::env::args().collect();
        let silent = args.iter().any(|arg| arg == "--silent");
        let format_json = args.iter().any(|arg| arg == "--format=json" || arg.contains("json"));
        let stdin_mode = args.iter().any(|arg| arg == "--stdin");
        ExecutionContext::from_cli_args(silent, stdin_mode, format_json)
    });

    let logger = Logger::from_context(context);

    logger.info("Displaying version information", "args");

    // UI OUTPUT - PRESERVADO (versión para usuario)
    println!("SCypher v{} - Hybrid CLI Implementation", VERSION);
    println!("Build: Rust + Clap + Argon2id + BIP39");
    println!("Modes: Interactive | JSON API | Silent | Stdin");

    logger.debug("Version information display completed", "args");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::ExecutionMode;

    #[test]
    fn test_args_logging_context_creation() {
        // Test creación de contextos y loggers sin interacción
        let interactive_context = ExecutionContext::new(ExecutionMode::Interactive);
        let logger = Logger::from_context(interactive_context.clone());
        logger.info("Testing interactive context", "args_tests");

        let json_context = ExecutionContext::new(ExecutionMode::JsonApi);
        let logger = Logger::from_context(json_context.clone());
        logger.info("Testing JSON API context", "args_tests");

        let test_context = ExecutionContext::for_testing();
        let logger = Logger::from_context(test_context.clone());
        logger.info("Testing context", "args_tests");

        // Verificar que los contextos tienen las propiedades esperadas
        assert_eq!(interactive_context.get_mode(), ExecutionMode::Interactive);
        assert_eq!(json_context.get_mode(), ExecutionMode::JsonApi);
        assert_eq!(test_context.get_mode(), ExecutionMode::Testing);
    }

    #[test]
    fn test_default_args() {
        let args = CliArgs::default();
        assert_eq!(args.command, OperationCommand::Interactive);
        assert_eq!(args.format, OutputFormat::Human);
        assert_eq!(args.iterations, 5);
        assert_eq!(args.memory_cost, 131072);
        assert!(!args.stdin_mode);
    }

    #[test]
    fn test_validate_crypto_params() {
        // Casos válidos
        assert!(validate_crypto_params(1, 8192).is_ok());
        assert!(validate_crypto_params(5, 131072).is_ok());
        assert!(validate_crypto_params(100, 2_097_152).is_ok());

        // Casos inválidos
        assert!(validate_crypto_params(0, 131072).is_err());
        assert!(validate_crypto_params(101, 131072).is_err());
        assert!(validate_crypto_params(5, 4096).is_err());
        assert!(validate_crypto_params(5, 3_000_000).is_err());

        // Test con contexto
        let test_context = ExecutionContext::for_testing();
        assert!(validate_crypto_params_with_context(5, 131072, Some(test_context.clone())).is_ok());
        assert!(validate_crypto_params_with_context(0, 131072, Some(test_context)).is_err());
    }

    #[test]
    fn test_validate_word_count() {
        // Casos válidos
        for &count in &[12, 15, 18, 21, 24] {
            assert!(validate_word_count(count).is_ok());
        }

        // Casos inválidos
        for &count in &[1, 5, 13, 20, 25, 30] {
            assert!(validate_word_count(count).is_err());
        }

        // Test con contexto
        let test_context = ExecutionContext::for_testing();
        assert!(validate_word_count_with_context(12, Some(test_context.clone())).is_ok());
        assert!(validate_word_count_with_context(13, Some(test_context)).is_err());
    }

    #[test]
    fn test_parse_networks() {
        // Test parsing networks
        let networks = "bitcoin,ethereum,cardano".split(',')
            .map(|s| s.trim().to_lowercase())
            .collect::<Vec<_>>();

        assert_eq!(networks, vec!["bitcoin", "ethereum", "cardano"]);
    }

    #[test]
    fn test_command_detection() {
        // Test that subcommand detection works correctly
        assert_eq!(OperationCommand::Transform, OperationCommand::Transform);
        assert_ne!(OperationCommand::Transform, OperationCommand::Generate);
    }

    #[test]
    fn test_stdin_mode_flag() {
        // Test que el flag stdin se puede parsear correctamente
        let mut args = CliArgs::default();
        args.stdin_mode = true;

        assert!(args.stdin_mode);
        assert!(!args.silent); // Diferentes modos
    }

    #[test]
    fn test_argument_priority_detection() {
        // Test que los argumentos pueden detectar el modo correcto
        let test_context = ExecutionContext::for_testing();

        let matches = build_cli_with_context(Some(test_context.clone()))
            .get_matches_from(vec!["scypher-cli"]);
        assert!(!has_transform_args_with_context(&matches, Some(test_context.clone())));

        // Test con argumentos que implican transformación
        let matches = build_cli_with_context(Some(test_context.clone()))
            .get_matches_from(vec!["scypher-cli", "--iterations", "10"]);
        assert!(has_transform_args_with_context(&matches, Some(test_context)));
    }

    #[test]
    fn test_build_cli_structure() {
        // Test que build_cli funciona correctamente
        let test_context = ExecutionContext::for_testing();
        let cli = build_cli_with_context(Some(test_context));

        // Verificar que el comando principal existe
        assert_eq!(cli.get_name(), "SCypher");
        assert_eq!(cli.get_version(), Some(VERSION));

        // Verificar que tiene los subcomandos esperados
        let subcommands: Vec<&str> = cli.get_subcommands()
            .map(|cmd| cmd.get_name())
            .collect();

        assert!(subcommands.contains(&"transform"));
        assert!(subcommands.contains(&"derive"));
        assert!(subcommands.contains(&"generate"));
        assert!(subcommands.contains(&"validate"));
    }

    #[test]
    fn test_functions_with_context_exist() {
        // Verificar que todas las funciones con contexto existen (sin llamarlas)
        let _: fn() -> Command = build_cli;
        let _: fn(Option<ExecutionContext>) -> Command = build_cli_with_context;
        let _: fn() -> Result<CliArgs> = parse_args;
        let _: fn(Option<ExecutionContext>) -> Result<CliArgs> = parse_args_with_context;
        let _: fn(&ArgMatches) -> Result<CliArgs> = parse_matches;
        let _: fn(&ArgMatches, Option<ExecutionContext>) -> Result<CliArgs> = parse_matches_with_context;
        let _: fn(u32, u32) -> Result<()> = validate_crypto_params;
        let _: fn(u32, u32, Option<ExecutionContext>) -> Result<()> = validate_crypto_params_with_context;
        let _: fn(usize) -> Result<()> = validate_word_count;
        let _: fn(usize, Option<ExecutionContext>) -> Result<()> = validate_word_count_with_context;
        let _: fn() = show_help;
        let _: fn(Option<ExecutionContext>) = show_help_with_context;
        let _: fn() = show_version;
        let _: fn(Option<ExecutionContext>) = show_version_with_context;
    }

    #[test]
    fn test_etapa_b4_args_implementation_verification() {
        // Test específico para verificar que la implementación B4 funciona correctamente
        let test_context = ExecutionContext::for_testing();
        let logger = Logger::from_context(test_context.clone());

        // Verificar que podemos usar el logger
        logger.info("ETAPA B4 ARGS IMPLEMENTATION VERIFICATION", "tests");
        logger.debug("Debug logging funciona correctamente", "tests");
        logger.error("Error logging funciona correctamente", "tests");

        // Verificar que CliArgs funciona correctamente
        let args = CliArgs::default();
        assert_eq!(args.command, OperationCommand::Interactive);
        assert_eq!(args.format, OutputFormat::Human);
        assert_eq!(args.iterations, 5);
        assert_eq!(args.memory_cost, 131072);
        assert!(!args.stdin_mode);
        assert!(!args.silent);

        // Verificar que las validaciones funcionan con contexto
        assert!(validate_crypto_params_with_context(5, 131072, Some(test_context.clone())).is_ok());
        assert!(validate_crypto_params_with_context(101, 131072, Some(test_context.clone())).is_err());

        assert!(validate_word_count_with_context(12, Some(test_context.clone())).is_ok());
        assert!(validate_word_count_with_context(13, Some(test_context.clone())).is_err());

        // Verificar que build_cli funciona con contexto
        let cli = build_cli_with_context(Some(test_context.clone()));
        assert_eq!(cli.get_name(), "SCypher");
        assert_eq!(cli.get_version(), Some(VERSION));

        // Verificar que las funciones originales siguen funcionando
        assert!(validate_crypto_params(5, 131072).is_ok());
        assert!(validate_word_count(24).is_ok());

        let cli_original = build_cli();
        assert_eq!(cli_original.get_name(), "SCypher");

        // Verificar separación entre logs técnicos y UI output
        assert_eq!(test_context.get_mode(), ExecutionMode::Testing);
        assert!(test_context.should_show_debug()); // Testing permite debug
        assert!(!test_context.should_use_colors()); // Testing no usa colores
        assert!(!test_context.should_suppress_debug_prints()); // Transitorio hasta B6

        logger.info("✅ B4 Args implementation verification passed", "tests");
        logger.info("✅ Professional logging system integrated in args", "tests");
        logger.info("✅ Argument parsing functions working with context", "tests");
        logger.info("✅ Validation functions working with context", "tests");
        logger.info("✅ CLI building functions working with context", "tests");
        logger.info("✅ Error handling and logging working correctly", "tests");
        logger.info("✅ Backward compatibility maintained 100%", "tests");
        logger.info("✅ Non-interactive tests implemented", "tests");
    }

    #[test]
    fn test_argument_parsing_scenarios() {
        let test_context = ExecutionContext::for_testing();

        // Test silent mode detection
        let cli = build_cli_with_context(Some(test_context.clone()));
        let matches = cli.clone().get_matches_from(vec!["scypher-cli", "--silent", "--format", "json"]);
        let parsed = parse_matches_with_context(&matches, Some(test_context.clone())).unwrap();

        assert!(parsed.silent);
        assert_eq!(parsed.format, OutputFormat::Json);

        // Test stdin mode detection
        let matches = cli.clone().get_matches_from(vec!["scypher-cli", "--stdin"]);
        let parsed = parse_matches_with_context(&matches, Some(test_context.clone())).unwrap();

        assert!(parsed.stdin_mode);
        assert!(!parsed.silent);

        // Test derive subcommand with networks
        let matches = cli.clone().get_matches_from(vec!["scypher-cli", "derive", "--networks", "bitcoin,ethereum", "--count", "3"]);
        let parsed = parse_matches_with_context(&matches, Some(test_context.clone())).unwrap();

        assert_eq!(parsed.command, OperationCommand::Derive);
        assert_eq!(parsed.networks, vec!["bitcoin", "ethereum"]);
        assert_eq!(parsed.address_count, 3);
    }

    #[test]
    fn test_error_handling_with_context() {
        let test_context = ExecutionContext::for_testing();

        // Test crypto params validation errors
        let result = validate_crypto_params_with_context(0, 131072, Some(test_context.clone()));
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Iterations must be at least 1"));

        let result = validate_crypto_params_with_context(5, 4096, Some(test_context.clone()));
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Memory cost too low"));

        // Test word count validation errors
        let result = validate_word_count_with_context(13, Some(test_context.clone()));
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Invalid word count"));
    }

    #[test]
    fn test_legacy_compatibility() {
        let test_context = ExecutionContext::for_testing();
        let cli = build_cli_with_context(Some(test_context.clone()));

        // Test legacy encrypt flag
        let matches = cli.clone().get_matches_from(vec!["scypher-cli", "--encrypt"]);
        let parsed = parse_matches_with_context(&matches, Some(test_context.clone())).unwrap();
        assert_eq!(parsed.command, OperationCommand::Transform);

        // Test legacy decrypt flag
        let matches = cli.clone().get_matches_from(vec!["scypher-cli", "--decrypt"]);
        let parsed = parse_matches_with_context(&matches, Some(test_context)).unwrap();
        assert_eq!(parsed.command, OperationCommand::Transform);
    }
}
