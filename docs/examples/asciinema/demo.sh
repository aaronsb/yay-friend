#!/bin/bash
# Demo script for yay-friend - Non-interactive demonstration
# This script runs through various yay-friend features with pauses

# Configuration
PAUSE_SHORT=2
PAUSE_MEDIUM=3
PAUSE_LONG=5

# Colors for echo statements
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Function to simulate typing
type_command() {
    echo -en "$ "
    for ((i=0; i<${#1}; i++)); do
        echo -n "${1:$i:1}"
        sleep 0.05
    done
    echo
    sleep 0.5
    eval "$1"
}

# Function to show section header
show_section() {
    echo
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}  $1${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    sleep $PAUSE_SHORT
}

# Function to pause with message
pause_with_message() {
    echo
    echo -e "${YELLOW}$1${NC}"
    sleep $2
}

# Clear screen for fresh start
clear

# Title
echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║                   yay-friend Demo                           ║${NC}"
echo -e "${GREEN}║         AI-Powered Security Analysis for AUR Packages       ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
sleep $PAUSE_MEDIUM

# Demo 1: Basic help
show_section "1. Getting Started - Help and Commands"
type_command "yay-friend --help | head -15"
sleep $PAUSE_MEDIUM

# Demo 2: Simple safe package (cached - instant)
show_section "2. Analyzing a Safe Package (GNU Hello)"
pause_with_message "📝 This package is cached, so analysis is instant..." $PAUSE_SHORT
type_command "yay-friend analyze hello"
sleep $PAUSE_LONG

# Demo 3: Complex package with security concerns
show_section "3. Analyzing a Package with Security Concerns"
pause_with_message "⚠️  This hardware tool has elevated entropy factors..." $PAUSE_SHORT
type_command "yay-friend analyze nokiatool-mtk | head -40"
sleep $PAUSE_LONG

# Demo 4: Trusted maintainer package
show_section "4. Kernel Package from Trusted Maintainer"
pause_with_message "🔐 Even complex packages can have LOW entropy with trusted sources..." $PAUSE_SHORT
type_command "yay-friend analyze linux-zen | head -30"
sleep $PAUSE_MEDIUM

# Demo 5: Cache management
show_section "5. Cache Management - Speed Benefits"
pause_with_message "💾 Cached analyses provide instant results..." $PAUSE_SHORT
type_command "yay-friend cache status"
sleep $PAUSE_SHORT

echo
pause_with_message "🚀 Comparing cached vs fresh analysis speed..." $PAUSE_SHORT
echo -e "${YELLOW}First, a cached package (instant):${NC}"
type_command "time yay-friend analyze hello | head -3"
sleep $PAUSE_SHORT

echo
echo -e "${YELLOW}Now clear cache for hello and re-analyze (slower):${NC}"
type_command "rm -rf ~/.local/share/yay-friend/cache/hello/"
type_command "time yay-friend analyze hello --no-spinner | head -3"
sleep $PAUSE_MEDIUM

# Demo 6: Show specific package cache
show_section "6. Viewing Cached Analyses"
type_command "yay-friend cache show nokiatool-mtk"
sleep $PAUSE_MEDIUM

# Demo 7: Configuration
show_section "7. Configuration Management"
type_command "yay-friend config show | head -20"
sleep $PAUSE_MEDIUM

# Demo 8: Provider information
show_section "8. AI Provider Status"
type_command "yay-friend provider list"
sleep $PAUSE_SHORT

# Closing
echo
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}                    Demo Complete!                           ${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo
echo "Key Features Demonstrated:"
echo "  ✓ Instant cached analysis for previously seen packages"
echo "  ✓ Detailed security entropy analysis"
echo "  ✓ Trust indicators (maintainer, votes, popularity)"
echo "  ✓ Clear visual feedback with color-coded severity"
echo "  ✓ Transparent data collection"
echo
echo -e "${BLUE}Learn more at: https://github.com/aaronsb/yay-friend${NC}"
sleep $PAUSE_SHORT