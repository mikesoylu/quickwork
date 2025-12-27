#!/bin/bash
set -e

BUILD_TYPE="Release"
BUILD_DIR="build"
HANDLERS_DIR="handlers"
INSTALL=false

# Parse arguments
for arg in "$@"; do
    case $arg in
        --install)
            INSTALL=true
            ;;
        Debug|Release|RelWithDebInfo|MinSizeRel)
            BUILD_TYPE="$arg"
            ;;
        *)
            echo "Usage: ./build.sh [--install] [Debug|Release]"
            echo "  --install    Link binary to ~/.local/bin/quickw"
            echo "  Debug        Build with debug symbols"
            echo "  Release      Build optimized (default)"
            exit 1
            ;;
    esac
done

mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

cmake .. -DCMAKE_BUILD_TYPE="$BUILD_TYPE"
make -j$(nproc 2>/dev/null || sysctl -n hw.ncpu)

cd ..
rm -rf "$HANDLERS_DIR"

echo "Build complete: $BUILD_DIR/quickwork"

if [ "$INSTALL" = true ]; then
    INSTALL_DIR="$HOME/.local/bin"
    mkdir -p "$INSTALL_DIR"
    
    # Remove existing link/file if present
    rm -f "$INSTALL_DIR/quickw"
    
    # Create symlink
    ln -s "$(pwd)/$BUILD_DIR/quickwork" "$INSTALL_DIR/quickw"
    
    echo "Installed: $INSTALL_DIR/quickw -> $(pwd)/$BUILD_DIR/quickwork"
    
    # Check if ~/.local/bin is in PATH
    if [[ ":$PATH:" != *":$INSTALL_DIR:"* ]]; then
        echo ""
        echo "Note: $INSTALL_DIR is not in your PATH."
        echo "Add this to your shell config (~/.bashrc, ~/.zshrc, etc.):"
        echo "  export PATH=\"\$HOME/.local/bin:\$PATH\""
    fi
fi
