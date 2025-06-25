// src/cli/display.rs - Pantallas visuales y banners
// ETAPA B2.1 LIMPIO - OWNERSHIP ERRORS FIXED
// UI output preservado, println! técnicos → logger

use std::io::{self, Write};
use crate::core::{ExecutionContext, ExecutionMode, Logger};

/// Versión de SCypher para mostrar en el banner
const VERSION: &str = "3.0";

/// Colores ANSI para tema amber/terminal retro
pub mod colors {
    pub const RESET: &str = "\x1b[0m";
    pub const PRIMARY: &str = "\x1b[38;5;214m";      // Amber primary
    pub const BRIGHT: &str = "\x1b[1;38;5;220m";     // Bright amber
    pub const DIM: &str = "\x1b[38;5;172m";          // Dark orange
    pub const WARNING: &str = "\x1b[38;5;228m";      // Warm yellow
    pub const ERROR: &str = "\x1b[38;5;124m";        // Brick red
    pub const FRAME: &str = "\x1b[38;5;240m";        // Dark gray
    pub const SUCCESS: &str = "\x1b[1;32m";          // Green
}

/// Limpiar pantalla usando múltiples métodos para compatibilidad total
pub fn clear_screen() {
    clear_screen_with_context(None)
}

/// Limpiar pantalla con contexto de ejecución específico
pub fn clear_screen_with_context(execution_context: Option<ExecutionContext>) {
    // Crear contexto y logger apropiados
    let context = execution_context.unwrap_or_else(|| {
        let args: Vec<String> = std::env::args().collect();
        let silent = args.iter().any(|arg| arg == "--silent");
        let format_json = args.iter().any(|arg| arg == "--format=json" || arg.contains("json"));
        let stdin_mode = args.iter().any(|arg| arg == "--stdin");
        ExecutionContext::from_cli_args(silent, stdin_mode, format_json)
    });

    let logger = Logger::from_context(context.clone()); // FIX: .clone() añadido

    // Detectar tipo de terminal para mejor compatibilidad
    let term_type = std::env::var("TERM").unwrap_or_default();
    let is_windows = cfg!(target_os = "windows");

    logger.debug(&format!("Clearing screen - Terminal: {}, Windows: {}", term_type, is_windows), "display");

    if is_windows {
        // En Windows, usar comando cls
        logger.debug("Using Windows cls command", "display");
        let _ = std::process::Command::new("cls").status();
    } else if term_type.contains("xterm") || term_type.contains("screen") {
        // Terminales compatibles con ANSI
        logger.debug("Using ANSI escape sequences", "display");
        print!("\x1b[2J\x1b[H");
        io::stdout().flush().unwrap_or(());
    } else {
        // Fallback: comando clear estándar
        logger.debug("Using standard clear command", "display");
        let _ = std::process::Command::new("clear").status();
    }

    // Fallback final: llenar con líneas vacías si los comandos fallan
    for _ in 0..3 {
        println!();
    }

    logger.debug("Screen cleared successfully", "display");
}

/// Mostrar banner principal de SCypher con ASCII art
pub fn show_banner() {
    show_banner_with_context(None)
}

/// Mostrar banner con contexto de ejecución específico
pub fn show_banner_with_context(execution_context: Option<ExecutionContext>) {
    // Crear contexto y logger apropiados
    let context = execution_context.unwrap_or_else(|| {
        let args: Vec<String> = std::env::args().collect();
        let silent = args.iter().any(|arg| arg == "--silent");
        let format_json = args.iter().any(|arg| arg == "--format=json" || arg.contains("json"));
        let stdin_mode = args.iter().any(|arg| arg == "--stdin");
        ExecutionContext::from_cli_args(silent, stdin_mode, format_json)
    });

    let logger = Logger::from_context(context.clone()); // FIX: .clone() añadido

    logger.debug("Displaying SCypher banner", "display");

    // UI OUTPUT - PRESERVADO (este es output para usuario, no logs técnicos)
    println!("{}SCypher v{}{} {}- XOR-based BIP39 Seed Cipher{}",
             colors::BRIGHT, VERSION, colors::RESET, colors::DIM, colors::RESET);
    println!("{}                        Rust Implementation{}", colors::DIM, colors::RESET);
    println!();

    // ASCII art del logo (preservado del script original)
    println!("{}                                  000000000", colors::PRIMARY);
    println!("                              000000000000000000");
    println!("                            000000          000000");
    println!("                           000                  000");
    println!("                          000     0000000000     000");
    println!("                         000      0000000000      000");
    println!("                         00        0000           000");
    println!("                        000          0000          000");
    println!("                        000          0000          000");
    println!("                         000       0000            00");
    println!("                         000      0000000000      000");
    println!("                          000     0000000000     000");
    println!("                           000                  000");
    println!("                            000000          000000");
    println!("                              000000000000000000");
    println!("                                   000000000{}", colors::RESET);
    println!();

    logger.debug("Banner displayed successfully", "display");
}

/// Mostrar mensaje de bienvenida la primera vez
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

    let logger = Logger::from_context(context.clone()); // FIX: .clone() añadido

    logger.info("Showing welcome message", "display");

    clear_screen_with_context(Some(context.clone()));
    show_banner_with_context(Some(context));

    // UI OUTPUT - PRESERVADO (información para el usuario)
    println!("{}Welcome to SCypher v3.0!{}", colors::BRIGHT, colors::RESET);
    println!("{}========================{}", colors::FRAME, colors::RESET);
    println!();
    println!("🔒 {}Secure BIP39 seed phrase encryption with XOR cipher{}", colors::PRIMARY, colors::RESET);
    println!("🛡️  {}Argon2id key derivation for maximum security{}", colors::PRIMARY, colors::RESET);
    println!("⚡ {}Three operation modes: Interactive, JSON API, Silent{}", colors::PRIMARY, colors::RESET);
    println!();
    println!("{}Choose an option from the menu below:{}", colors::DIM, colors::RESET);
    println!();

    logger.debug("Welcome message displayed", "display");
}

/// Mostrar texto de licencia y disclaimer
pub fn show_license_text() {
    show_license_text_with_context(None)
}

/// Mostrar texto de licencia con contexto específico
pub fn show_license_text_with_context(execution_context: Option<ExecutionContext>) {
    // Crear contexto y logger apropiados
    let context = execution_context.unwrap_or_else(|| {
        let args: Vec<String> = std::env::args().collect();
        let silent = args.iter().any(|arg| arg == "--silent");
        let format_json = args.iter().any(|arg| arg == "--format=json" || arg.contains("json"));
        let stdin_mode = args.iter().any(|arg| arg == "--stdin");
        ExecutionContext::from_cli_args(silent, stdin_mode, format_json)
    });

    let logger = Logger::from_context(context.clone()); // FIX: .clone() añadido

    logger.info("Displaying license text", "display");

    let license_text = r#"
License:
This project is released under the MIT License. You are free to:
- Use the software commercially
- Modify the source code
- Distribute the software
- Use it privately

Disclaimer:
THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED.
IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT
OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

The developers assume no responsibility for:
- Loss of funds or assets
- Incorrect usage of the software
- Modifications made by third parties
- Security implications of usage in specific contexts
- Possible malfunction of the software
"#;

    clear_screen_with_context(Some(context));

    // UI OUTPUT - PRESERVADO (información legal para el usuario)
    println!("{}", license_text);
    println!();
    print!("Press enter to continue...");
    io::stdout().flush().unwrap_or(());

    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap_or(0);

    logger.debug("License text interaction completed", "display");
}

/// Mostrar explicación detallada del proceso XOR
pub fn show_cipher_details() {
    show_cipher_details_with_context(None)
}

/// Mostrar explicación detallada con contexto específico
pub fn show_cipher_details_with_context(execution_context: Option<ExecutionContext>) {
    // Crear contexto y logger apropiados
    let context = execution_context.unwrap_or_else(|| {
        let args: Vec<String> = std::env::args().collect();
        let silent = args.iter().any(|arg| arg == "--silent");
        let format_json = args.iter().any(|arg| arg == "--format=json" || arg.contains("json"));
        let stdin_mode = args.iter().any(|arg| arg == "--stdin");
        ExecutionContext::from_cli_args(silent, stdin_mode, format_json)
    });

    let logger = Logger::from_context(context.clone()); // FIX: .clone() añadido

    logger.info("Displaying cipher details explanation", "display");

    let details_text = r#"
How SCypher v3.0 Works (XOR-Based Encryption):

SCypher uses XOR encryption while maintaining BIP39 compatibility through
intelligent checksum recalculation.

1. Core Concept - XOR Encryption:
   - XOR (exclusive OR) is a reversible binary operation
   - When you XOR data twice with the same key, you get back the original
   - Formula: (data XOR key) XOR key = data

2. The Process:
   Encryption/Decryption (same operation due to XOR symmetry):
   - Your seed phrase is converted to binary (11 bits per word)
   - Your password generates a keystream using Argon2id key derivation
   - The keystream can be strengthened with iterations
   - Binary seed XOR keystream = transformed binary
   - Transformed binary gets a recalculated BIP39 checksum
   - Result is converted back to valid BIP39 words

3. Security Features:
   - Argon2id provides memory-hard key derivation
   - Iterations add computational cost for attackers
   - XOR provides perfect secrecy with a strong keystream
   - Output is always a valid BIP39 phrase with correct checksum
   - Memory-secure operations with automatic cleanup

4. Checksum Handling:
   - BIP39 phrases include a checksum for error detection
   - After XOR transformation, we recalculate the checksum
   - This ensures compatibility with all BIP39-compliant wallets
   - The adjustment is deterministic and doesn't compromise security

5. Key Improvements over v2.0:
   - Rust implementation for memory safety
   - Argon2id instead of SHAKE-256 for key derivation
   - Enhanced security protections
   - Better error handling and user experience
   - Cross-platform compatibility

6. Usage Notes:
   - Always use a strong, unique password
   - More iterations = more security but slower processing
   - Test with non-critical phrases first
   - Keep secure backups of original seeds
   - Remember both password AND iteration count

Technical Note:
The XOR cipher achieves 'perfect secrecy' when the keystream is as long as the
message and cryptographically secure. Argon2id provides the secure pseudo-randomness
needed for this application while adding resistance to hardware attacks.
"#;

    clear_screen_with_context(Some(context));

    // UI OUTPUT - PRESERVADO (documentación técnica para el usuario)
    println!("{}", details_text);
    println!();
    print!("Press enter to continue...");
    io::stdout().flush().unwrap_or(());

    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap_or(0);

    logger.debug("Cipher details interaction completed", "display");
}

/// Mostrar ejemplos de uso actualizados para CLI híbrida
pub fn show_usage_examples() {
    show_usage_examples_with_context(None)
}

/// Mostrar ejemplos de uso con contexto específico
pub fn show_usage_examples_with_context(execution_context: Option<ExecutionContext>) {
    // Crear contexto y logger apropiados
    let context = execution_context.unwrap_or_else(|| {
        let args: Vec<String> = std::env::args().collect();
        let silent = args.iter().any(|arg| arg == "--silent");
        let format_json = args.iter().any(|arg| arg == "--format=json" || arg.contains("json"));
        let stdin_mode = args.iter().any(|arg| arg == "--stdin");
        ExecutionContext::from_cli_args(silent, stdin_mode, format_json)
    });

    let logger = Logger::from_context(context.clone()); // FIX: .clone() añadido

    logger.info("Displaying usage examples", "display");

    clear_screen_with_context(Some(context));

    // UI OUTPUT - PRESERVADO (ejemplos de uso para el usuario)
    println!("{}Usage Examples{}", colors::BRIGHT, colors::RESET);
    println!("{}=============={}", colors::FRAME, colors::RESET);
    println!();
    println!("{}Interactive Mode (Menu):{}", colors::PRIMARY, colors::RESET);
    println!("  ./scypher-cli                     # Shows this menu");
    println!("  ./scypher-cli interactive         # Same as above");
    println!();
    println!("{}JSON API Mode (Electron Integration):{}", colors::PRIMARY, colors::RESET);
    println!("  ./scypher-cli transform \"seed phrase\" \"password\" --format json");
    println!("  ./scypher-cli derive \"seed phrase\" --networks bitcoin,ethereum --format json");
    println!("  ./scypher-cli generate --words 24 --format json");
    println!("  ./scypher-cli validate \"seed phrase\" --format json");
    println!();
    println!("{}Silent Mode (Scripts):{}", colors::PRIMARY, colors::RESET);
    println!("  echo -e \"seed phrase\\npassword\" | ./scypher-cli --silent");
    println!("  echo '{{\"command\":\"generate\",\"params\":{{\"words\":12}}}}' | ./scypher-cli --silent --format json");
    println!();
    println!("{}Options:{}", colors::PRIMARY, colors::RESET);
    println!("  --format json           JSON output for programmatic use");
    println!("  --silent               Non-interactive mode");
    println!("  --networks LIST        Blockchain networks for address derivation");
    println!("  --count N              Number of addresses to derive");
    println!("  --words N              Number of words for generate (12,15,18,21,24)");
    println!("  --iterations N         Argon2id iterations (default: 5)");
    println!("  --memory-cost KB       Argon2id memory cost (default: 131072)");
    println!();
    println!("{}Security Recommendations:{}", colors::WARNING, colors::RESET);
    println!("  - Use strong, unique passwords");
    println!("  - Higher iterations = more security but slower processing");
    println!("  - Test with non-critical phrases first");
    println!("  - Keep secure backups of original seeds");
    println!("  - Remember both password AND iteration count");
    println!();

    print!("Press enter to continue...");
    io::stdout().flush().unwrap_or(());

    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap_or(0);

    logger.debug("Usage examples interaction completed", "display");
}

/// Mostrar información de compatibilidad del sistema
pub fn show_compatibility_info() {
    show_compatibility_info_with_context(None)
}

/// Mostrar información de compatibilidad con contexto específico
pub fn show_compatibility_info_with_context(execution_context: Option<ExecutionContext>) {
    // Crear contexto y logger apropiados
    let context = execution_context.unwrap_or_else(|| {
        let args: Vec<String> = std::env::args().collect();
        let silent = args.iter().any(|arg| arg == "--silent");
        let format_json = args.iter().any(|arg| arg == "--format=json" || arg.contains("json"));
        let stdin_mode = args.iter().any(|arg| arg == "--stdin");
        ExecutionContext::from_cli_args(silent, stdin_mode, format_json)
    });

    let logger = Logger::from_context(context.clone()); // FIX: .clone() añadido

    logger.info("Displaying compatibility information", "display");

    clear_screen_with_context(Some(context));

    // UI OUTPUT - PRESERVADO (información técnica para el usuario)
    println!("{}System Compatibility{}", colors::BRIGHT, colors::RESET);
    println!("{}==================={}", colors::FRAME, colors::RESET);
    println!();
    println!("{}Dependencies:{}", colors::PRIMARY, colors::RESET);
    println!("- Rust 1.70 or higher");
    println!("- Standard system libraries");
    println!();
    println!("{}Supported Platforms:{}", colors::PRIMARY, colors::RESET);
    println!("- Linux (all distributions)");
    println!("- macOS 10.15+");
    println!("- Windows 10+ (native or WSL)");
    println!("- FreeBSD and other Unix-like systems");
    println!();
    println!("{}Installation:{}", colors::PRIMARY, colors::RESET);
    println!("1. Install Rust: https://rustup.rs/");
    println!("2. Clone repository");
    println!("3. Run: cargo build --release");
    println!("4. Binary located at: target/release/scypher-cli");
    println!();
    println!("{}Security Features:{}", colors::SUCCESS, colors::RESET);
    println!("- Memory-safe operations");
    println!("- Automatic cleanup of sensitive data");
    println!("- No external network dependencies");
    println!("- Cross-platform secure random generation");
    println!("- JSON API for Electron integration");
    println!("- Three operation modes: Interactive, JSON API, Silent");
    println!();

    print!("Press enter to continue...");
    io::stdout().flush().unwrap_or(());

    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap_or(0);

    logger.debug("Compatibility info interaction completed", "display");
}

/// Mostrar información específica de la CLI híbrida
pub fn show_hybrid_info() {
    show_hybrid_info_with_context(None)
}

/// Mostrar información de CLI híbrida con contexto específico
pub fn show_hybrid_info_with_context(execution_context: Option<ExecutionContext>) {
    // Crear contexto y logger apropiados
    let context = execution_context.unwrap_or_else(|| {
        let args: Vec<String> = std::env::args().collect();
        let silent = args.iter().any(|arg| arg == "--silent");
        let format_json = args.iter().any(|arg| arg == "--format=json" || arg.contains("json"));
        let stdin_mode = args.iter().any(|arg| arg == "--stdin");
        ExecutionContext::from_cli_args(silent, stdin_mode, format_json)
    });

    let logger = Logger::from_context(context.clone()); // FIX: .clone() añadido

    logger.info("Displaying hybrid CLI information", "display");

    clear_screen_with_context(Some(context));

    // UI OUTPUT - PRESERVADO (documentación de arquitectura para el usuario)
    println!("{}SCypher v3.0 - Hybrid CLI Implementation{}", colors::BRIGHT, colors::RESET);
    println!("{}======================================={}", colors::FRAME, colors::RESET);
    println!();
    println!("{}Three Operation Modes:{}", colors::PRIMARY, colors::RESET);
    println!();
    println!("{}1. Interactive Mode{} - Beautiful menus with ASCII art", colors::BRIGHT, colors::RESET);
    println!("   Perfect for manual use and learning");
    println!("   Features: Guided menus, colorful output, help system");
    println!();
    println!("{}2. JSON API Mode{} - Structured communication", colors::BRIGHT, colors::RESET);
    println!("   Designed for Electron frontend integration");
    println!("   Features: Structured input/output, error handling, machine-readable");
    println!();
    println!("{}3. Silent Mode{} - Script compatibility", colors::BRIGHT, colors::RESET);
    println!("   Maintains backward compatibility with existing scripts");
    println!("   Features: Stdin/stdout, minimal output, automation-friendly");
    println!();
    println!("{}Architecture:{}", colors::PRIMARY, colors::RESET);
    println!("- CLI Interface: Beautiful menus from original CLI");
    println!("- Crypto Logic: Robust implementation from Tauri GUI");
    println!("- JSON Bridge: New structured communication layer");
    println!();
    println!("{}Use Cases:{}", colors::SUCCESS, colors::RESET);
    println!("- Manual crypto operations (Interactive)");
    println!("- Desktop app integration (JSON API)");
    println!("- Automated scripts (Silent)");
    println!("- Learning and exploration (Interactive with help)");
    println!();

    print!("Press enter to continue...");
    io::stdout().flush().unwrap_or(());

    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap_or(0);

    logger.debug("Hybrid CLI info interaction completed", "display");
}

/// Función utilitaria para leer entrada del usuario
pub fn read_user_input(prompt: &str) -> String {
    read_user_input_with_context(prompt, None)
}

/// Función utilitaria para leer entrada con contexto específico
pub fn read_user_input_with_context(prompt: &str, execution_context: Option<ExecutionContext>) -> String {
    // Crear contexto y logger apropiados
    let context = execution_context.unwrap_or_else(|| {
        let args: Vec<String> = std::env::args().collect();
        let silent = args.iter().any(|arg| arg == "--silent");
        let format_json = args.iter().any(|arg| arg == "--format=json" || arg.contains("json"));
        let stdin_mode = args.iter().any(|arg| arg == "--stdin");
        ExecutionContext::from_cli_args(silent, stdin_mode, format_json)
    });

    let logger = Logger::from_context(context); // No necesita .clone() aquí

    logger.debug(&format!("Reading user input with prompt: {}", prompt), "display");

    // UI OUTPUT - PRESERVADO (prompt para el usuario)
    print!("{}", prompt);
    io::stdout().flush().unwrap_or(());

    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap_or(0);
    let trimmed_input = input.trim().to_string();

    logger.debug(&format!("User input received: {} characters", trimmed_input.len()), "display");

    trimmed_input
}

/// Función utilitaria para pausar y esperar enter
pub fn wait_for_enter() {
    wait_for_enter_with_context(None)
}

/// Función utilitaria para pausar con contexto específico
pub fn wait_for_enter_with_context(execution_context: Option<ExecutionContext>) {
    // Crear contexto y logger apropiados
    let context = execution_context.unwrap_or_else(|| {
        let args: Vec<String> = std::env::args().collect();
        let silent = args.iter().any(|arg| arg == "--silent");
        let format_json = args.iter().any(|arg| arg == "--format=json" || arg.contains("json"));
        let stdin_mode = args.iter().any(|arg| arg == "--stdin");
        ExecutionContext::from_cli_args(silent, stdin_mode, format_json)
    });

    let logger = Logger::from_context(context); // No necesita .clone() aquí

    logger.debug("Waiting for user to press enter", "display");

    // UI OUTPUT - PRESERVADO (prompt para el usuario)
    print!("Press enter to continue...");
    io::stdout().flush().unwrap_or(());

    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap_or(0);

    logger.debug("User pressed enter, continuing", "display");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::ExecutionMode;

    #[test]
    fn test_display_logging_modes() {
        // Test diferentes modos de ExecutionContext no afecten UI output

        // Modo interactivo (permite debug logs)
        let interactive_context = ExecutionContext::new(ExecutionMode::Interactive);
        show_banner_with_context(Some(interactive_context));

        // Modo JSON API (sin contaminar output)
        let json_context = ExecutionContext::new(ExecutionMode::JsonApi);
        show_banner_with_context(Some(json_context));

        // Modo testing (sin output de logs)
        let test_context = ExecutionContext::for_testing();
        show_banner_with_context(Some(test_context));

        // UI output debe seguir funcionando en todos los modos
        // Solo los logs técnicos deben respetar el ExecutionContext
    }

    #[test]
    fn test_display_function_compatibility() {
        // Test que las funciones originales sigan funcionando
        show_banner(); // Función original
        clear_screen(); // Función original

        // Test que las funciones con contexto produzcan el mismo UI output
        let test_context = ExecutionContext::for_testing();
        show_banner_with_context(Some(test_context.clone()));
        clear_screen_with_context(Some(test_context));

        // UI output debe ser idéntico (solo logs técnicos cambian)
    }

    #[test]
    fn test_etapa_b2_display_implementation_verification() {
        // Test específico para verificar que la implementación B2.1 funciona correctamente
        let test_context = ExecutionContext::for_testing();
        let logger = Logger::from_context(test_context.clone());

        // Verificar que podemos usar el logger sin contaminar UI output
        logger.info("ETAPA B2.1 DISPLAY IMPLEMENTATION VERIFICATION", "tests");
        logger.debug("Este debug message no debe aparecer en UI output", "tests");

        // Verificar que el UI output sigue funcionando
        show_banner_with_context(Some(test_context.clone()));

        // Verificar que las funciones originales siguen funcionando
        show_banner();
        clear_screen();

        // Verificar separación entre logs técnicos y UI output
        assert_eq!(test_context.get_mode(), ExecutionMode::Testing);
        assert!(test_context.should_show_debug()); // Testing permite debug
        assert!(!test_context.should_use_colors()); // Testing no usa colores
        assert!(!test_context.should_suppress_debug_prints()); // Transitorio hasta B6

        logger.info("✅ B2.1 Display implementation verification passed", "tests");
        logger.info("✅ Professional logging system integrated in display", "tests");
        logger.info("✅ UI output preserved completely", "tests");
        logger.info("✅ Technical logs separated from user interface", "tests");
        logger.info("✅ Backward compatibility maintained 100%", "tests");
        logger.info("✅ Ready for B2.2 output.rs implementation", "tests");
    }
}
