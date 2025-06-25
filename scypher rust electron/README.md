# SCypher CLI v3.0 - Hybrid Implementation

🔐 **Secure seed phrase transformation and blockchain address derivation**

## 🎯 Project Status

**Current Phase:** ✅ Phase 1 Complete - Project Setup
**Next Phase:** 🚧 Phase 2 - CLI Interface Migration
**Overall Progress:** 1/6 phases completed (17%)

## 🏗️ Architecture

SCypher CLI combines the best of both worlds:
- 🎨 **Beautiful Interface** from the original CLI (ASCII art, amber colors, interactive menus)
- 🔐 **Robust Crypto Logic** from the Tauri GUI (Argon2id, XOR, BIP39, multi-blockchain)
- 📡 **JSON API** for seamless Electron integration

### Operation Modes

```bash
# 🎨 Interactive Mode - Beautiful ASCII menus
./scypher-cli
./scypher-cli interactive

# 📡 JSON API Mode - For Electron integration
./scypher-cli transform "seed phrase" "password" --format json
./scypher-cli derive "seed phrase" --networks bitcoin,ethereum --format json

# 📜 Silent Mode - Script compatibility
echo -e "seed\npassword" | ./scypher-cli --silent
echo '{"command":"generate","params":{"words":12}}' | ./scypher-cli --silent --format json
```

## 🔧 Features (Planned)

### ✅ Phase 1 Complete - Project Setup
- [x] Modular Rust project structure
- [x] Complete dependency configuration
- [x] Error handling system with JSON support
- [x] CLI argument parsing with clap
- [x] Basic test framework
- [x] Release optimization configuration

### 🚧 Phase 2 - CLI Interface (In Progress)
- [ ] ASCII art banners with amber color theme
- [ ] Interactive menu system with navigation
- [ ] Secure password input with masking
- [ ] Beautiful output formatting
- [ ] File save functionality

### 🔮 Phase 3 - Crypto Logic (Planned)
- [ ] XOR encryption with Argon2id key derivation
- [ ] BIP39 seed phrase validation and generation
- [ ] Checksum calculation and verification
- [ ] Memory-safe operations with zeroize
- [ ] Constant-time cryptographic operations

### 🔮 Phase 4 - Address Derivation (Planned)
- [ ] Bitcoin (Legacy, SegWit, Native SegWit)
- [ ] Ethereum ecosystem (ETH, BSC, Polygon)
- [ ] Additional networks (Cardano, Solana, Ergo, TRON, Dogecoin, Litecoin)
- [ ] HD derivation with BIP44 paths
- [ ] Multiple address formats per network

### 🔮 Phase 5 - JSON Bridge (Planned)
- [ ] Structured JSON input/output
- [ ] Error handling with consistent format
- [ ] Silent mode for programmatic use
- [ ] Electron child_process integration ready

### 🔮 Phase 6 - Testing & Verification (Planned)
- [ ] Security testing (memory safety, crypto correctness)
- [ ] Performance benchmarks
- [ ] Integration testing all modes
- [ ] Final documentation and examples

## 🚀 Quick Start

### Prerequisites
- Rust 1.70+ with Cargo
- Git

### Installation
```bash
git clone <repository>
cd scypher-cli
cargo build --release
```

### Basic Usage
```bash
# Show help
./target/release/scypher-cli --help

# Interactive mode (when implemented)
./target/release/scypher-cli

# Generate seed phrase (when implemented)
./target/release/scypher-cli generate --words 12 --format json
```

## 🛡️ Security Features

### Cryptographic Standards
- **Argon2id** memory-hard key derivation function
- **XOR** symmetric encryption with expanded keystreams
- **BIP39** compliant seed phrase operations
- **Constant-time** operations resistant to timing attacks

### Memory Safety
- **Automatic cleanup** with zeroize on sensitive data
- **Secure allocation** for cryptographic materials
- **Memory locking** on Unix systems (when available)
- **Signal handlers** for emergency cleanup

### Input Validation
- **Zero-trust** input validation
- **JSON schema** validation for API mode
- **BIP39 checksum** verification
- **Network parameter** validation

## 🌍 Supported Networks

| Network | Symbol | Address Types | Status |
|---------|--------|---------------|--------|
| Bitcoin | BTC | Legacy, SegWit, Native SegWit | 🔮 Planned |
| Ethereum | ETH | Standard | 🔮 Planned |
| BSC | BNB | Standard | 🔮 Planned |
| Polygon | MATIC | Standard | 🔮 Planned |
| Cardano | ADA | Shelley | 🔮 Planned |
| Solana | SOL | Standard | 🔮 Planned |
| Ergo | ERG | P2PK | 🔮 Planned |
| TRON | TRX | Standard | 🔮 Planned |
| Dogecoin | DOGE | Legacy | 🔮 Planned |
| Litecoin | LTC | Legacy, SegWit | 🔮 Planned |

## 🧪 Development

### Project Structure
```
scypher-cli/
├── src/
│   ├── main.rs           # 🚪 CLI entry point
│   ├── lib.rs            # 📚 Public API
│   ├── error.rs          # ⚠️ Error handling
│   ├── cli/              # 🎨 Interface (menus, colors, input)
│   ├── crypto/           # 🔐 XOR + Argon2id operations
│   ├── bip39/            # 📝 BIP39 validation + generation
│   ├── addresses/        # 🌍 Multi-blockchain derivation
│   └── security/         # 🛡️ Memory protection
├── tests/                # 🧪 Integration tests
└── target/release/       # 📦 Optimized binary
```

### Running Tests
```bash
# Run all tests
cargo test

# Run specific module tests
cargo test crypto::
cargo test bip39::

# Run with coverage (requires cargo-tarpaulin)
cargo tarpaulin --out html
```

### Phase Verification
```bash
# Verify current phase completion
./verify_phase1.sh

# Check compilation
cargo check
cargo clippy -- -D warnings

# Test basic functionality
./target/debug/scypher-cli --help
```

## 📚 API Documentation

### Command Line Interface
```bash
# Transform seed phrase
scypher-cli transform <phrase> <password> [--format json]

# Derive addresses
scypher-cli derive <phrase> --networks <list> --count <num> [--format json]

# Generate new seed
scypher-cli generate --words <12|15|18|21|24> [--format json]

# Validate seed phrase
scypher-cli validate <phrase> [--format json]

# Interactive mode
scypher-cli interactive
```

### JSON API (For Electron Integration)
```json
// Input (stdin)
{
  "command": "transform|derive|generate|validate",
  "params": { /* command-specific parameters */ },
  "options": { "format": "json", "verbose": false }
}

// Output (stdout)
{
  "success": true|false,
  "result": { /* operation results */ },
  "error": { "code": "ERROR_CODE", "message": "..." },
  "metadata": { "version": "3.0.0", "timestamp": "...", "command": "..." }
}
```

## 🤝 Contributing

This project follows a structured migration approach with 6 phases. Each phase has specific deliverables and verification criteria.

### Migration Status
- ✅ **Phase 1**: Project setup and architecture (Complete)
- 🚧 **Phase 2**: CLI interface migration (In Progress)
- 🔮 **Phase 3**: Crypto logic migration (Planned)
- 🔮 **Phase 4**: Address derivation migration (Planned)
- 🔮 **Phase 5**: JSON bridge implementation (Planned)
- 🔮 **Phase 6**: Testing and verification (Planned)

### Development Guidelines
1. **Preserve exact crypto specifications** from Tauri implementation
2. **Maintain beautiful CLI interface** from original CLI
3. **Ensure JSON API compatibility** for Electron integration
4. **Follow security best practices** for memory and crypto operations
5. **Write comprehensive tests** for each component

## 📄 License

MIT License - see LICENSE file for details.

## 🔗 Links

- **Original Tauri GUI**: Source of robust crypto logic
- **Original CLI**: Source of beautiful interface design
- **Migration Guide**: Detailed implementation roadmap
- **Electron Integration**: Target platform for GUI frontend

---

**Status**: Phase 1 Complete ✅ | **Next**: Phase 2 CLI Interface 🚧
