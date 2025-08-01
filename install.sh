#!/bin/bash

# yay-friend installer script
# Supports both user-scoped and system-scoped installation

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
REPO_URL="https://github.com/aaronsb/yay-friend"
BINARY_NAME="yay-friend"
VERSION="latest"

# Function to print colored output
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to detect OS and architecture
detect_platform() {
    OS=$(uname -s | tr '[:upper:]' '[:lower:]')
    ARCH=$(uname -m)
    
    case $ARCH in
        x86_64)
            ARCH="amd64"
            ;;
        aarch64|arm64)
            ARCH="arm64"
            ;;
        armv7l)
            ARCH="arm"
            ;;
        *)
            print_error "Unsupported architecture: $ARCH"
            exit 1
            ;;
    esac
    
    print_info "Detected platform: $OS-$ARCH"
}

# Function to check prerequisites
check_prerequisites() {
    print_info "Checking prerequisites..."
    
    # Check for yay
    if ! command_exists yay; then
        print_error "yay is not installed. Please install yay first."
        print_info "Visit: https://github.com/Jguer/yay#installation"
        exit 1
    fi
    
    # Check for Go (if building from source)
    if [[ "$BUILD_FROM_SOURCE" == "true" ]]; then
        if ! command_exists go; then
            print_error "Go is not installed. Please install Go to build from source."
            exit 1
        fi
    fi
    
    print_success "Prerequisites check passed"
}

# Function to download or build binary
get_binary() {
    if [[ "$BUILD_FROM_SOURCE" == "true" ]]; then
        build_from_source
    else
        download_binary
    fi
}

# Function to build from source
build_from_source() {
    print_info "Building from source..."
    
    TEMP_DIR=$(mktemp -d)
    cd "$TEMP_DIR"
    
    print_info "Cloning repository..."
    git clone "$REPO_URL" .
    
    print_info "Building binary..."
    go build -o "$BINARY_NAME" ./cmd/yay-friend
    
    if [[ ! -f "$BINARY_NAME" ]]; then
        print_error "Failed to build binary"
        exit 1
    fi
    
    print_success "Binary built successfully"
}

# Function to download pre-built binary (placeholder for future releases)
download_binary() {
    print_info "Downloading pre-built binary..."
    print_warning "Pre-built binaries not yet available. Building from source instead."
    BUILD_FROM_SOURCE=true
    build_from_source
}

# Function to install binary
install_binary() {
    local install_dir="$1"
    local needs_sudo="$2"
    
    print_info "Installing to $install_dir..."
    
    if [[ "$needs_sudo" == "true" ]]; then
        sudo cp "$BINARY_NAME" "$install_dir/"
        sudo chmod +x "$install_dir/$BINARY_NAME"
    else
        cp "$BINARY_NAME" "$install_dir/"
        chmod +x "$install_dir/$BINARY_NAME"
    fi
    
    print_success "Binary installed to $install_dir/$BINARY_NAME"
}

# Function to initialize configuration
init_config() {
    print_info "Initializing configuration..."
    
    if [[ -d "$HOME/.yay-friend" ]]; then
        print_warning "Configuration directory already exists at $HOME/.yay-friend"
        read -p "Do you want to reinitialize? [y/N]: " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            print_info "Skipping configuration initialization"
            return
        fi
    fi
    
    "$install_dir/$BINARY_NAME" config init
    print_success "Configuration initialized"
}

# Function to show usage
show_usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --user          Install for current user only (default)"
    echo "  --system        Install system-wide (requires sudo)"
    echo "  --build         Build from source (default)"
    echo "  --download      Download pre-built binary (when available)"
    echo "  --help          Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0                    # User install, build from source"
    echo "  $0 --system          # System install, build from source"
    echo "  $0 --user --download # User install, download binary"
}

# Main installation logic
main() {
    # Default options
    INSTALL_SCOPE="user"
    BUILD_FROM_SOURCE="true"
    
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --user)
                INSTALL_SCOPE="user"
                shift
                ;;
            --system)
                INSTALL_SCOPE="system"
                shift
                ;;
            --build)
                BUILD_FROM_SOURCE="true"
                shift
                ;;
            --download)
                BUILD_FROM_SOURCE="false"
                shift
                ;;
            --help)
                show_usage
                exit 0
                ;;
            *)
                print_error "Unknown option: $1"
                show_usage
                exit 1
                ;;
        esac
    done
    
    print_info "Starting yay-friend installation..."
    print_info "Install scope: $INSTALL_SCOPE"
    print_info "Build method: $([ "$BUILD_FROM_SOURCE" == "true" ] && echo "source" || echo "download")"
    
    # Detect platform
    detect_platform
    
    # Check prerequisites
    check_prerequisites
    
    # Determine install directory
    if [[ "$INSTALL_SCOPE" == "system" ]]; then
        install_dir="/usr/local/bin"
        needs_sudo="true"
        print_info "System installation requires sudo privileges"
    else
        # Create user bin directory if it doesn't exist
        install_dir="$HOME/.local/bin"
        mkdir -p "$install_dir"
        needs_sudo="false"
        
        # Add to PATH if not already there
        if [[ ":$PATH:" != *":$install_dir:"* ]]; then
            print_warning "$install_dir is not in your PATH"
            print_info "Add this line to your shell profile (~/.bashrc, ~/.zshrc, etc.):"
            print_info "export PATH=\"\$HOME/.local/bin:\$PATH\""
        fi
    fi
    
    # Get binary
    get_binary
    
    # Install binary
    install_binary "$install_dir" "$needs_sudo"
    
    # Initialize configuration (only for user installs)
    if [[ "$INSTALL_SCOPE" == "user" ]]; then
        init_config
    fi
    
    # Cleanup
    if [[ -n "$TEMP_DIR" ]] && [[ -d "$TEMP_DIR" ]]; then
        rm -rf "$TEMP_DIR"
    fi
    
    print_success "yay-friend installation completed!"
    print_info "Run 'yay-friend --help' to get started"
    
    if [[ "$INSTALL_SCOPE" == "system" ]]; then
        print_info "For system installations, each user should run 'yay-friend config init' to set up their configuration"
    fi
}

# Run main function
main "$@"