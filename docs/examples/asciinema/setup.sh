#!/bin/bash
# Setup script for asciinema recording session
# This prepares the environment for a clean demo

set -e

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}Setting up environment for yay-friend demo...${NC}"

# 1. Check if asciinema is installed
if ! command -v asciinema &> /dev/null; then
    echo "Installing asciinema..."
    if command -v pacman &> /dev/null; then
        sudo pacman -S --noconfirm asciinema
    elif command -v apt-get &> /dev/null; then
        sudo apt-get install -y asciinema
    else
        echo "Please install asciinema manually"
        exit 1
    fi
fi

# 2. Ensure yay-friend is in PATH
if ! command -v yay-friend &> /dev/null; then
    echo "yay-friend not found in PATH"
    echo "Please ensure yay-friend is installed and in your PATH"
    exit 1
fi

# 3. Clear terminal for clean recording
clear

# 4. Set terminal size for consistency
printf '\e[8;30;120t'  # 30 rows, 120 columns

# 5. Set minimal prompt for cleaner look
export PS1='$ '

# 6. Ensure cache is populated for demo packages
echo -e "${BLUE}Pre-caching demo packages...${NC}"
packages=("hello" "nokiatool-mtk" "linux-zen" "yay-bin")

for pkg in "${packages[@]}"; do
    echo "Analyzing $pkg to populate cache..."
    yay-friend analyze "$pkg" > /dev/null 2>&1 || true
done

# 7. Clear for the actual recording
clear

echo -e "${GREEN}✓ Environment ready for recording${NC}"
echo ""
echo "To start recording, run:"
echo "  asciinema rec --title 'yay-friend Demo' --cols 120 --rows 30 demo.cast"
echo ""
echo "Then run the demo script:"
echo "  ./demo.sh"
echo ""
echo "To stop recording, press Ctrl+D or type 'exit'"