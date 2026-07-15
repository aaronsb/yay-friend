# 🌪️ yay-friend

A security-focused wrapper around `yay` that uses AI to analyze PKGBUILD files for **security entropy** - the unpredictability and uncertainty factors that might indicate security risks.

## 🎯 Overview

`yay-friend` acts as your intelligent security companion for the Arch User Repository (AUR). It analyzes packages using **Security Entropy Analysis** - a fuzzy, multi-factor approach that considers how predictable vs chaotic a package's behavior is.

### 🧠 The Security Entropy Concept

**Entropy** = Unpredictability + Uncertainty = Potential Risk

- **🟢 Minimal Entropy**: Predictable, simple repackaging from official sources
- **🟢 Low Entropy**: Minor uncertainty, standard operations  
- **🟡 Moderate Entropy**: Some concerning factors, needs review
- **🔴 High Entropy**: Multiple suspicious factors, high uncertainty
- **🔴 Critical Entropy**: Maximum chaos - compilation + multiple sources + obfuscation (bold red)

## 🎬 Demo

![yay-friend Demo](docs/examples/asciinema/demo.gif)

## ✨ Features

- 🌪️ **Security Entropy Analysis** - Multi-factor risk assessment using AI
- 🤖 **Claude Code Powered** - Runs your local Claude Code headless; no API key required (Qwen/Copilot/Goose providers are stubbed for the future — see [#1](https://github.com/aaronsb/yay-friend/issues/1))
- 🔒 **Locked-down analysis** - Isolated Claude call with all tools denied, so untrusted PKGBUILDs can't execute anything
- 📊 **Comprehensive Analysis** - Source compilation, multiple origins, maintainer trust
- ⚡ **Intelligent Caching** - Commit-hash based analysis caching for performance
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

## 🔑 Authentication & Cost

`yay-friend` does **not** talk to any AI API directly. For each package it shells
out to your **locally installed Claude Code** in headless mode (`claude --print`)
and reads back the analysis. This has a few important consequences:

- **It uses your own Claude authentication.** Whatever `claude` is already logged
  into is what gets used — a **Claude Pro/Max subscription** *or* an
  **`ANTHROPIC_API_KEY`**. No API key is required if you're signed in with a
  subscription.
- **It spends your own Claude usage.** Each fresh analysis is one Claude request
  billed to *your* account (results are cached by AUR commit hash, so re-installs
  and unchanged packages cost nothing). On a subscription, programmatic calls draw
  from your plan's usage; if you want fully predictable, metered billing, set an
  `ANTHROPIC_API_KEY` and Claude Code will use that instead.
- **It never touches your credentials.** `yay-friend` only runs the official
  `claude` binary and pipes a prompt to it over stdin. It does not read, extract,
  store, or forward your subscription token or API key — Claude Code manages its
  own auth internally. This is the officially supported
  [headless/programmatic mode](https://code.claude.com/docs/en/headless), the same
  mechanism the Claude Agent SDK is built on.
- **Analysis runs locked down.** The Claude call is isolated: your MCP servers are
  disabled and *all* built-in tools (Bash, file access, web) are denied, so an
  untrusted PKGBUILD can be read and classified but can never cause Claude to
  execute anything on your machine.

> **Prerequisite:** Install and sign in to [Claude Code](https://claude.com/claude-code)
> first (`claude` must be on your `PATH`). Verify with `yay-friend provider test claude`.

## 📋 Usage

### Basic Analysis
```bash
# Initialize configuration
yay-friend config init

# Analyze a package without installing
yay-friend analyze hello

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

### Cache Management
`yay-friend` intelligently caches analysis results using AUR git commit hashes to avoid redundant AI calls for unchanged packages.

```bash
# View cache statistics
yay-friend cache status

# Show cached analyses for a specific package
yay-friend cache show package-name

# Clean expired cache entries (older than 30 days)
yay-friend cache clean --days 30

# Clear all cache entries
yay-friend cache clear

# Clear all cache entries without confirmation
yay-friend cache clear -y
```

#### Cache Benefits
- **⚡ 95%+ faster** for previously analyzed packages (no AI call needed)
- **💰 Cost reduction** - Unchanged packages cost nothing; no repeat Claude usage
- **🔄 Consistency** - Identical analysis results for same package version
- **📱 Offline capability** - Re-analyze previously seen packages offline

The cache uses XDG Base Directory specification:
- Cache location: `${XDG_DATA_HOME:-$HOME/.local/share}/yay-friend/cache/`
- Each package gets its own directory with commit-hash based analysis files

### Prompt Customization
You can customize the AI analysis prompts by editing your configuration file. The prompts use template variables that get replaced with actual package information.

```bash
# Edit your configuration file
$EDITOR ~/.config/yay-friend/config.yaml

# Or reset to defaults by deleting the config (it will be recreated)
rm ~/.config/yay-friend/config.yaml
yay-friend config init
```

#### Available Template Variables
- `{NAME}` - Package name
- `{VERSION}` - Package version  
- `{MAINTAINER}` - Package maintainer
- `{VOTES}` - AUR vote count
- `{POPULARITY}` - AUR popularity score
- `{FIRST_SUBMITTED}` - When first submitted to AUR
- `{LAST_UPDATED}` - When last updated in AUR
- `{DEPENDENCIES}` - Runtime dependencies
- `{MAKE_DEPENDS}` - Build dependencies
- `{PKGBUILD}` - The actual PKGBUILD content

The prompt template is stored in the `prompts.security_analysis` field in your config file.

## 🔍 Example Analysis Output

Here's what a real analysis looks like - notice the **transparency** about what data we collect:

```
🔍 Analyzing hello with claude...

Collected for Analysis:
─────────────────────────
• PKGBUILD: 28 lines of shell script
• Package metadata: hello v2.12.1 by Matthew Sexton <mssxtn@gmail.com

Analyzing with Claude...
Analysis complete.

============================================================
Security Analysis for hello
============================================================
Provider: claude
Analyzed: 2025-07-31 20:26:15
Overall Level: LOW

Summary:
This PKGBUILD represents a low-risk package for the official GNU Hello World program. The primary entropy factors are source compilation (standard for GNU software) and weak MD5 checksums. The package follows standard practices with official sources and clean build processes, though low community engagement raises minor maintenance concerns.

Recommendation: PROCEED

Detailed Findings:
----------------------------------------
1. [MINIMAL] source_analysis
   Single source from official GNU FTP server for well-established GNU Hello World program
   Line: 11
   Context: source=(https://ftp.gnu.org/gnu/hello/$pkgname-$pkgver.tar.gz)
   💡 Source is trustworthy - official GNU software repository. Consider upgrading to SHA256 checksums instead of MD5 for better integrity verification.

2. [LOW] source_analysis
   Uses MD5 checksums instead of stronger SHA256 for integrity verification
   Line: 12
   Context: md5sums=('5cf598783b9541527e17c9b5e525b7eb')
   💡 Upgrade to SHA256 checksums for better cryptographic security: sha256sums=('hash')

3. [LOW] build_process
   Source compilation using standard autotools build process instead of simple repackaging
   Line: 15
   Context: ./configure --prefix=/usr
make
   💡 Build process is standard for GNU software. No additional verification needed - autotools is well-established and secure.

4. [MINIMAL] file_operations
   Clean installation using standard make install with proper DESTDIR usage
   Line: 19
   Context: make DESTDIR="$pkgdir/" install
   💡 File operations are properly contained within package directory. No concerns.

5. [MODERATE] maintainer_trust
   Multiple contributors over time but package has 0 votes and 0.000 popularity in AUR
   Line: 3
   Context: # Maintainer: Matthew Sexton <mssxtn@gmail.com
#contributor: Michał Wojdyła < micwoj9292 at gmail dot com >
#Contributor: leo <leotemplin@yahoo.de>
   💡 Low community engagement despite being official GNU software suggests limited usage. Verify this is needed vs using official repository version.
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

XDG Base Directory compliant:

```
${XDG_CONFIG_HOME:-$HOME/.config}/yay-friend/
├── config.yaml          # Main configuration
├── providers/           # AI provider configurations
└── cache/              # Temporary analysis data

${XDG_DATA_HOME:-$HOME/.local/share}/yay-friend/
├── evaluations/          # Individual analysis JSON files
└── reports/             # Malicious package reports
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
  claude: ""     # Uses your local `claude` command (the only working provider today)
  qwen: ""       # Stub — not yet implemented (see issue #1)
  copilot: ""    # Stub — not yet implemented
  goose: ""      # Stub — not yet implemented
claude:
  model: sonnet  # Model alias passed to `claude --model` (e.g. sonnet, opus).
                 # Pinned so analysis is reproducible instead of drifting with
                 # your interactive default. Defaults to "sonnet" if unset.
```

## 🧪 Development & Testing

```bash
# Analyze packages without installing
yay-friend analyze hello

# Analyze a compilation package
yay-friend analyze some-git-package

# Check provider authentication
yay-friend provider test

# View recent evaluations
ls -la "${XDG_DATA_HOME:-$HOME/.local/share}/yay-friend/evaluations/"
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