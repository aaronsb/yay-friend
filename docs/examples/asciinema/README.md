# Asciinema Demo Scripts

This directory contains scripts for creating asciinema recordings to demonstrate yay-friend functionality.

## Files

- `setup.sh` - Prepares the environment for recording (pre-caches packages, sets terminal)
- `demo.sh` - Non-interactive demo script that runs through yay-friend features

## Usage

### 1. Prepare Environment

First, run the setup script to prepare your environment:

```bash
./setup.sh
```

This will:
- Install asciinema if needed
- Pre-cache demo packages for instant playback
- Set terminal to consistent size (120x30)
- Configure minimal prompt

### 2. Start Recording

Start an asciinema recording session:

```bash
# For asciinema v2 (recommended for GIF conversion):
asciinema rec --title "yay-friend Demo" --cols 120 --rows 30 demo.cast

# For asciinema v3:
asciinema rec --title "yay-friend Demo" demo.cast
```

Options:
- Add `--idle-time-limit 2` to auto-trim long pauses
- Use `--cols 120 --rows 30` to force terminal size (v2)

### 3. Run Demo

Execute the demo script:

```bash
./demo.sh
```

The script will:
- Type commands with realistic speed
- Show various yay-friend features
- Pause appropriately between sections
- Demonstrate cache benefits

### 4. Stop Recording

When the demo completes, stop recording:
- Press `Ctrl+D` or type `exit`

### 5. Review Recording

Play back your recording locally:

```bash
asciinema play demo.cast
```

### 6. Upload (Optional)

Upload to asciinema.org for sharing:

```bash
asciinema upload demo.cast
```

## Demo Sections

The demo covers:

1. **Getting Started** - Help and available commands
2. **Safe Package Analysis** - GNU Hello (cached, instant)
3. **Security Concerns** - nokiatool-mtk with findings
4. **Trusted Maintainer** - linux-zen kernel package
5. **Cache Management** - Status and speed comparison
6. **Cached Analyses** - Viewing stored analyses
7. **Configuration** - Config management
8. **AI Providers** - Provider status

## Customization

Edit `demo.sh` to:
- Adjust pause durations (`PAUSE_SHORT`, `PAUSE_MEDIUM`, `PAUSE_LONG`)
- Add/remove demo sections
- Change example packages
- Modify typing speed in `type_command()`

## Converting to GIF

To create a GIF from the recording:

```bash
# Install agg (asciinema gif generator)
yay -S agg

# Convert to GIF
agg demo.cast demo.gif
```

Or use asciicast2gif:

```bash
# Install asciicast2gif
npm install -g asciicast2gif

# Convert
asciicast2gif demo.cast demo.gif
```

## Tips

- Run `clear` before starting to ensure clean slate
- Keep recordings under 3 minutes for engagement
- Use consistent terminal theme/colors
- Test the demo script before recording
- Consider multiple short recordings vs one long one