#!/bin/bash
# Build script for yay-friend with version information

set -e

# Get version info
VERSION=${VERSION:-"0.1.0"}
GIT_COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_DATE=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

# Build flags
LDFLAGS="-X github.com/aaronsb/yay-friend/internal/version.Version=${VERSION}"
LDFLAGS="${LDFLAGS} -X github.com/aaronsb/yay-friend/internal/version.GitCommit=${GIT_COMMIT}"
LDFLAGS="${LDFLAGS} -X github.com/aaronsb/yay-friend/internal/version.BuildDate=${BUILD_DATE}"

echo "Building yay-friend..."
echo "  Version: ${VERSION}"
echo "  Commit: ${GIT_COMMIT}"
echo "  Date: ${BUILD_DATE}"

# Build the binary
go build -ldflags "${LDFLAGS}" -o yay-friend cmd/yay-friend/main.go

echo "Build complete: ./yay-friend"