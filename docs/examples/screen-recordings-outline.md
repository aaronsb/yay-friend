# Screen Recording Examples - Outline

## Overview
This document outlines planned screen recordings to demonstrate yay-friend's capabilities using cached package analyses.

## Recording Setup
- Terminal: 120x30 recommended size
- Theme: Dark background with high contrast
- Font: Monospace, 14pt
- Tools: asciinema or terminalizer for recording

## Example Scenarios

### 1. Basic Package Analysis (Safe Package)
**Package**: `hello`
**Duration**: ~15 seconds
**Demonstrates**:
- Simple analysis workflow
- LOW entropy result
- Quick cache hit on second run
- Clear proceed recommendation

**Script**:
```bash
# First run - fresh analysis
yay-friend analyze hello

# Second run - cache hit (instant)
yay-friend analyze hello
```

### 2. Complex Package Analysis (Moderate Risk)
**Package**: `nokiatool-mtk`
**Duration**: ~30 seconds
**Demonstrates**:
- Analysis of hardware interface tool
- HIGH entropy findings
- Multiple security concerns
- Detailed recommendations

**Script**:
```bash
yay-friend analyze nokiatool-mtk
# Show scrolling through findings
# Highlight the gist URL concern
```

### 3. Trusted Maintainer Package
**Package**: `linux-zen`
**Duration**: ~20 seconds
**Demonstrates**:
- Kernel package from core developer
- LOW entropy despite complexity
- Trust indicators
- Build process transparency

**Script**:
```bash
yay-friend analyze linux-zen
# Emphasize maintainer trust
# Show cryptographic verification
```

### 4. Large Binary Repackaging
**Package**: `google-chrome` or `chromium`
**Duration**: ~25 seconds
**Demonstrates**:
- Binary package analysis
- Setuid file detection
- Proprietary software handling
- Clear security boundaries

**Script**:
```bash
yay-friend analyze google-chrome
# Or
yay-friend analyze chromium
```

### 5. Popular AUR Helper
**Package**: `yay-bin`
**Duration**: ~20 seconds
**Demonstrates**:
- Analysis of AUR helper itself
- Binary vs source comparison
- Community trust indicators
- Meta security considerations

**Script**:
```bash
yay-friend analyze yay-bin
```

### 6. Cache Management Demo
**Duration**: ~30 seconds
**Demonstrates**:
- Cache status command
- Cache statistics
- Speed comparison (cached vs fresh)
- Cache cleanup options

**Script**:
```bash
# Show cache status
yay-friend cache status

# Show specific package cache
yay-friend cache show nokiatool-mtk

# Compare timing - fresh analysis
time yay-friend analyze somepackage

# Compare timing - cached analysis  
time yay-friend analyze hello

# Cache statistics
yay-friend cache status
```

### 7. Interactive Installation Flow
**Duration**: ~45 seconds
**Demonstrates**:
- Full workflow from search to install
- Security review before installation
- User decision points
- Integration with yay

**Script**:
```bash
# Search for a package
yay-friend search terminal

# Analyze before installing
yay-friend analyze alacritty

# Proceed with installation (mock or safe package)
yay-friend install alacritty
```

### 8. Batch Analysis (Multiple Packages)
**Duration**: ~40 seconds
**Demonstrates**:
- Analyzing multiple packages
- Cache efficiency
- Summary comparison
- Decision making for multiple installs

**Script**:
```bash
# Analyze multiple packages
for pkg in hello yay-bin linux-zen; do
    echo "=== Analyzing $pkg ==="
    yay-friend analyze $pkg | head -20
    echo
done
```

## Key Points to Highlight

### Visual Elements
- Color-coded entropy levels (🟢 LOW, 🟡 MODERATE, 🔴 HIGH)
- Spinner animation during analysis
- Clear section separators
- Finding enumeration with severity

### Educational Focus
- Show "Collected for Analysis" transparency section
- Highlight entropy factors explanation
- Point out specific security concerns
- Demonstrate cache speed benefits

### User Trust Building
- Show exactly what data is analyzed
- Demonstrate offline capability (cached)
- Show no hidden network requests
- Emphasize local analysis option

## Technical Notes

### Pre-recording Checklist
- [ ] Clear terminal
- [ ] Verify all example packages are cached
- [ ] Set consistent terminal size
- [ ] Disable auto-suggestions/completions
- [ ] Use consistent prompt (minimal)

### Recording Commands
```bash
# Using asciinema
asciinema rec docs/examples/recordings/basic-analysis.cast

# Using terminalizer  
terminalizer record docs/examples/recordings/basic-analysis

# Convert to GIF if needed
asciicast2gif docs/examples/recordings/basic-analysis.cast basic-analysis.gif
```

### Post-processing
- Trim dead time
- Add captions for key moments
- Speed up slow sections (2x for waiting)
- Ensure file size < 10MB for README embedding

## Distribution Plan

### Locations
1. README.md - 1-2 key examples as GIFs
2. docs/examples/ - Full collection
3. GitHub Wiki - Detailed walkthroughs
4. Project website - Interactive demos

### Formats
- GIF - For README/docs (auto-play)
- asciinema - For interactive playback
- MP4 - For presentations/videos
- SVG - For high-quality stills