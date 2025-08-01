# 🌪️ yay-friend

A security-focused wrapper around `yay` that uses AI to analyze PKGBUILD files for **security entropy** - the unpredictability and uncertainty factors that might indicate security risks.

## 🎯 Overview

`yay-friend` acts as your intelligent security companion for the Arch User Repository (AUR). It analyzes packages using **Security Entropy Analysis** - a fuzzy, multi-factor approach that considers how predictable vs chaotic a package's behavior is.

### 🧠 The Security Entropy Concept

**Entropy** = Unpredictability + Uncertainty = Potential Risk

- **🟢 Minimal Entropy**: Predictable, simple repackaging from official sources
- **🟡 Low Entropy**: Minor uncertainty, standard operations  
- **🟠 Moderate Entropy**: Some concerning factors, needs review
- **🔴 High Entropy**: Multiple suspicious factors, high uncertainty
- **⚫ Critical Entropy**: Maximum chaos - compilation + multiple sources + obfuscation

## ✨ Features

- 🌪️ **Security Entropy Analysis** - Multi-factor risk assessment using AI
- 🤖 **Multiple AI Providers** - Claude Code, Qwen, Copilot, Goose support
- 📊 **Comprehensive Analysis** - Source compilation, multiple origins, maintainer trust
- 📝 **Detailed Logging** - Individual JSON files for each evaluation  
- 📡 **Malicious Package Reporting** - Automated threat intelligence sharing
- 🔧 **Developer Tools** - Test commands, configuration management
- 🏗️ **Trust Scoring** - Repository age, maintainer reputation analysis

## 🚀 Installation

### Quick Install (User Scope)
```bash
curl -sSL https://raw.githubusercontent.com/aaronsb/yay-friend/main/install.sh | bash
```

### System-wide Install
```bash
curl -sSL https://raw.githubusercontent.com/aaronsb/yay-friend/main/install.sh | bash -s -- --system
```

### Build from Source
```bash
git clone https://github.com/aaronsb/yay-friend
cd yay-friend
go build -o yay-friend ./cmd/yay-friend
./install.sh --user --build
```

## 📋 Usage

### Basic Analysis
```bash
# Initialize configuration
yay-friend config init

# Test the analysis pipeline
yay-friend test hello

# Analyze a package (no installation)
yay-friend analyze suspicious-package

# Install with analysis (like yay, but safer)
yay-friend -S package-name
```

### Advanced Usage
```bash
# Configure AI provider
yay-friend provider test claude
yay-friend config set default_provider claude

# Check provider status
yay-friend provider list

# View configuration
yay-friend config show

# Skip analysis (emergency bypass)
yay-friend --skip-analysis -S package-name
```

## 🔍 Security Analysis Criteria

### 🌪️ High Entropy Indicators (Suspicious)
- **Source Compilation**: Arbitrary code execution during build
- **Multiple Sources**: Each source multiplies attack surface  
- **Network Requests**: Downloads during build process
- **Code Obfuscation**: Base64, eval, compressed scripts
- **New Maintainers**: Recent accounts with low reputation

### 🛡️ Low Entropy Indicators (Safer)
- **Simple Repackaging**: Just extracting and moving files
- **Official Sources**: Well-known, trusted repositories
- **Established Maintainers**: Long history, good reputation
- **Regular Updates**: Consistent maintenance patterns

## 🏗️ Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   yay-friend    │    │   AI Providers   │    │   Trust Engine  │
│     CLI         │◄───┤  Claude/Qwen/etc │    │  Repo Analysis  │
└─────────────────┘    └──────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Config Mgmt   │    │   Entropy Engine │    │   Evaluation    │
│  ~/.yay-friend  │    │  Security Analysis│    │    Logging     │
└─────────────────┘    └──────────────────┘    └─────────────────┘
```

### Core Components
- **🧠 Entropy Analysis Engine**: Multi-factor security assessment
- **🔌 Provider Interface**: Modular AI backend system
- **📊 Trust Scoring**: Repository and maintainer reputation
- **📝 Evaluation Logging**: Audit trail with individual JSON files
- **📡 Threat Reporting**: Community threat intelligence sharing
- **⚙️ Configuration Management**: User preferences and thresholds

## 📁 Directory Structure

```
~/.yay-friend/
├── config.yaml          # Main configuration
├── evaluations/          # Individual analysis JSON files
├── reports/             # Malicious package reports  
├── providers/           # AI provider configurations
└── cache/              # Temporary analysis data
```

## 🔧 Configuration

### Security Thresholds
```yaml
security_thresholds:
  block_level: 4      # Block CRITICAL entropy packages
  warn_level: 2       # Warn on MODERATE+ entropy  
  auto_proceed: false # Always ask for confirmation
```

### AI Providers
```yaml
default_provider: claude
providers:
  claude: ""     # Uses system claude command
  qwen: ""       # Configuration path
  copilot: ""    # Configuration path  
  goose: ""      # Configuration path
```

## 🧪 Development & Testing

```bash
# Test analysis pipeline
yay-friend test hello

# Test with a compilation package
yay-friend test some-git-package

# Check provider authentication
yay-friend provider test

# View recent evaluations
ls -la ~/.yay-friend/evaluations/
```

## 🤝 Contributing

We welcome contributions! Focus areas:

1. **🔌 New AI Providers**: Implement additional AI backends
2. **🎨 TUI Interface**: Rich terminal interface with colors
3. **🛡️ Sandboxing**: Isolated PKGBUILD analysis environment  
4. **📊 Analytics**: Enhanced trust scoring algorithms
5. **🔍 Detection Rules**: New entropy analysis patterns

### Development Setup
```bash
git clone https://github.com/aaronsb/yay-friend
cd yay-friend
go mod tidy
go build -o yay-friend ./cmd/yay-friend
./yay-friend config init
```

## 📊 Example Analysis Output

```
🧪 Testing analysis pipeline with package: hello
🔑 Authenticating with claude...
📦 Fetching package information for hello...

============================================================
TEST ANALYSIS RESULTS  
============================================================
Package: hello
Provider: claude
Overall Entropy: LOW
Predictability Score: 0.85
Recommendation: PROCEED

Summary:
Simple repackaging from official GNU source with standard build process.

Entropy Factors:
  • Official GNU source (reduces uncertainty)
  • Standard autotools build (predictable)
  • Long-term maintenance history
  • No network requests during build

✅ No security issues found!
```

## 🛡️ Security Philosophy

`yay-friend` doesn't just look for "bad" vs "good" packages. Instead, it analyzes **uncertainty** and **unpredictability** - the entropy that makes it hard to predict what a package will actually do.

**High entropy doesn't mean malicious, but it means "pay attention".**

## 📜 License

MIT License - see [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Inspired by the need for better AUR security practices
- Built on the excellent `yay` AUR helper  
- Powered by AI providers like Claude Code for intelligent analysis
- Community-driven approach to threat intelligence