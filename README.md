# 🌪️ yay-friend

A security-focused wrapper around `yay` that uses AI to analyze PKGBUILD files for **security entropy** - the unpredictability and uncertainty factors that might indicate security risks.

## Overview

`yay-friend` acts as your intelligent security companion for the Arch User Repository (AUR). It analyzes packages using **Security Entropy Analysis** - a fuzzy, multi-factor approach that considers how predictable vs chaotic a package's behavior is.

### The Security Entropy Concept

**Entropy** = Unpredictability + Uncertainty = Potential Risk

Five levels, shown as a bar that rises with entropy. The bar carries the scale on
its own, so the reading survives `NO_COLOR` and a monochrome terminal:

```
▁ MINIMAL    predictable — simple repackaging from official sources
▃ LOW        minor uncertainty, standard operations
▅ MODERATE   some concerning factors, worth a read
▇ HIGH       multiple suspicious factors, high uncertainty
█ CRITICAL   compilation + multiple sources + obfuscation
```

High entropy is not a verdict of "malicious". It means *pay attention*.

## Demo

![yay-friend Demo](docs/examples/asciinema/demo.gif)

## Features

- **Security Entropy Analysis** - Multi-factor risk assessment using AI
- **Claude Code Powered** - Runs your local Claude Code headless; no API key required (Qwen/Copilot/Goose providers are stubbed for the future — see [#1](https://github.com/aaronsb/yay-friend/issues/1))
- **Locked-down analysis** - Isolated Claude call with built-in tools denied (defense-in-depth), so untrusted PKGBUILDs are read, not executed
- **Comprehensive Analysis** - Source compilation, multiple origins, maintainer trust
- **Intelligent Caching** - Commit-hash based analysis caching for performance
- **Developer Tools** - Test commands, configuration management

## Installation

### From the AUR (recommended)
```bash
# with an existing AUR helper
yay -S yay-friend-git      # or: paru -S yay-friend-git
```
Builds the latest `main` from source. Requires `git` and `yay`; install
[`claude-code`](https://aur.archlinux.org/packages/claude-code) (or have any
`claude` CLI on your `PATH`) for the AI analysis.

### Quick Install (User Scope)
```bash
curl -sSL https://raw.githubusercontent.com/aaronsb/yay-friend/main/install.sh | bash
```

### System-wide Install
```bash
curl -sSL https://raw.githubusercontent.com/aaronsb/yay-friend/main/install.sh | bash -s -- --system
```

### Dependencies

Building needs Go 1.23 or newer. Runtime dependencies are `git`, `yay`, and a
`claude` CLI on `PATH`. The binary links a small set of Go modules:
`mvdan.cc/sh` (parses PKGBUILDs as bash rather than pattern-matching them),
`lipgloss`/`termenv` (terminal rendering), `cobra`, and `yaml.v3`.

### Build from Source
```bash
git clone https://github.com/aaronsb/yay-friend
cd yay-friend
go build -o yay-friend ./cmd/yay-friend
./install.sh --user --build
```

## Authentication & Cost

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
  disabled and the known built-in tools (Bash, file access, web) are denied, so an
  untrusted PKGBUILD is read and classified rather than executed. This is
  defense-in-depth (an enumerated deny-list plus headless permission checks), not
  a hard sandbox — see the `deniedTools` note in `internal/providers/claude.go`.

> **Prerequisite:** Install and sign in to [Claude Code](https://claude.com/claude-code)
> first (`claude` must be on your `PATH`). Verify with `yay-friend provider test claude`.

## Usage

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
- **95%+ faster** for previously analyzed packages (no AI call needed)
- **Cost reduction** - Unchanged packages cost nothing; no repeat Claude usage
- **Consistency** - Identical analysis results for same package version
- **Offline capability** - Re-analyze previously seen packages offline

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

## Example Analysis Output

Note the transparency about what gets collected before anything is sent:

```
:: analyzing hello with claude

── collected for analysis ──────────────────────────────────────────────
  pkgbuild        28 lines of shell
  package         hello 2.12.1
  maintainer      Matthew Sexton <mssxtn@gmail.com>
  runtime deps    glibc
  aur history     submitted 2019-03-02, updated 2026-07-29

:: analyzing with Claude… (4s, receiving)
:: analysis complete (6s)

── hello ───────────────────────────────────────────────────────────────
  entropy         ▃ LOW
  predictability  0.81
  factors         source compilation, weak checksums
  provider        claude
  analyzed        2026-08-03 14:27:02

  Low-risk package for the official GNU Hello World program. Entropy comes
  from source compilation, standard for GNU software, and MD5 checksums.

  recommend       PROCEED

── findings ────────────────────────────────────────────────────────────

  1. ▁ MINIMAL  source_analysis  line 11
     Single source from the official GNU FTP server.
     code source=(https://ftp.gnu.org/gnu/hello/$pkgname-$pkgver.tar.gz)
     do   Trustworthy source. Consider SHA256 over MD5 for integrity.

  2. ▃ LOW  source_analysis  line 12
     Uses MD5 checksums rather than SHA256.
     code md5sums=('5cf598783b9541527e17c9b5e525b7eb')
     do   Upgrade to sha256sums for cryptographic integrity.

  3. ▅ MODERATE  maintainer_trust  line 3
     Multiple contributors over time, but 0 votes and 0.000 popularity.
     why  Low engagement on official GNU software suggests limited usage.
     do   Verify this is needed versus the official repository version.
```

Every line yay-friend speaks is prefixed `::`. That marker is reserved: output
from `yay`, from `pacman`, and from the package's own build is not allowed to
wear it, so you can always tell which lines came from the analyzer.

## Security Analysis Criteria

### High Entropy Indicators (Suspicious)
- **Source Compilation**: Arbitrary code execution during build
- **Multiple Sources**: Each source multiplies attack surface  
- **Network Requests**: Downloads during build process
- **Code Obfuscation**: Base64, eval, compressed scripts
- **New Maintainers**: Recent accounts with low reputation

### Low Entropy Indicators (Safer)
- **Simple Repackaging**: Just extracting and moving files
- **Official Sources**: Well-known, trusted repositories
- **Established Maintainers**: Long history, good reputation
- **Regular Updates**: Consistent maintenance patterns

## Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   yay-friend    │    │   AI Providers   │    │   AUR Fetcher   │
│      CLI        │◄───┤  Claude/Qwen/etc │    │  Metadata/git   │
└─────────────────┘    └──────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Config Mgmt   │    │  Entropy Engine  │    │  Analysis Cache │
│   config.yaml   │    │ Pre-scan + AI    │    │  by commit hash │
└─────────────────┘    └──────────────────┘    └─────────────────┘
```

### Core Components
- **Entropy Analysis Engine**: Multi-factor security assessment
- **Provider Interface**: Modular AI backend system
- **Configuration Management**: User preferences and thresholds

## Directory Structure

XDG Base Directory compliant:

```
${XDG_CONFIG_HOME:-$HOME/.config}/yay-friend/
└── config.yaml          # Main configuration

${XDG_DATA_HOME:-$HOME/.local/share}/yay-friend/
└── cache/               # Analysis results, keyed by AUR commit hash
```

## Configuration

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

> **Note:** `config.yaml` is loaded as an **overlay** on the built-in defaults — set
> only the keys you want to change; anything you omit keeps its default. Change values
> with `yay-friend config set <key> <value>` (dotted keys, e.g. `config set claude.model opus`,
> `config set cache.enabled false`) or by editing the file directly. Invalid values,
> unknown keys, and type mismatches are rejected before anything is written. `config set`
> handles scalar values (strings, ints, bools); to set a list (e.g. `yay.default_flags`),
> edit the file. Note the overlay merges map entries (a partial `providers:` keeps the
> untouched defaults) but replaces lists wholesale.

## Development & Testing

```bash
# Analyze packages without installing
yay-friend analyze hello

# Analyze a compilation package
yay-friend analyze some-git-package

# Check provider authentication
yay-friend provider test

# Inspect the analysis cache
yay-friend cache status
yay-friend cache show hello
```

## Contributing

We welcome contributions! Focus areas:

1. **New AI Providers**: implement additional AI backends
2. **Sandboxing**: isolated PKGBUILD evaluation, so computed metadata can be
   resolved without trusting it — see the notes in `internal/ui` and
   `internal/pkgbuild` for why static analysis alone cannot reach it
3. **Detection Rules**: new entropy analysis patterns
4. **Trust signals**: repository age and maintainer reputation

### Development Setup
```bash
git clone https://github.com/aaronsb/yay-friend
cd yay-friend
go mod tidy
go build -o yay-friend ./cmd/yay-friend
./yay-friend config init
```

## Security Philosophy

`yay-friend` doesn't just look for "bad" vs "good" packages. Instead, it analyzes **uncertainty** and **unpredictability** - the entropy that makes it hard to predict what a package will actually do.

**High entropy doesn't mean malicious, but it means "pay attention".**

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Acknowledgments

- Inspired by the need for better AUR security practices
- Built on the excellent `yay` AUR helper  
- Powered by AI providers like Claude Code for intelligent analysis
- Community-driven approach to threat intelligence