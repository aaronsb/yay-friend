# yay-friend Examples

This directory contains example demonstrations and screen recordings of yay-friend in action.

## Contents

- `screen-recordings-outline.md` - Planning document for screen recording examples
- `recordings/` - (To be created) Actual screen recordings in various formats

## Quick Examples

### Cached Packages Available for Demo

The following packages have been analyzed and cached, making them ideal for quick demonstrations:

1. **hello** - Simple, safe GNU Hello package (LOW entropy)
2. **nokiatool-mtk** - Hardware tool with security concerns (HIGH entropy)  
3. **linux-zen** - Kernel from trusted maintainer (LOW entropy)
4. **yay-bin** - Popular AUR helper binary (MODERATE entropy)
5. **google-chrome** / **chromium** - Large browser packages

### Running Examples

```bash
# Quick safe package demo
yay-friend analyze hello

# Show cache speed
time yay-friend analyze hello  # Instant from cache

# Complex package with findings
yay-friend analyze nokiatool-mtk

# View cache status
yay-friend cache status
```

## Creating New Examples

See `screen-recordings-outline.md` for the full recording plan and technical setup instructions.