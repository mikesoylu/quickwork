#!/bin/bash
set -e

BUILD_TYPE="${1:-Release}"
BUILD_DIR="build"
HANDLERS_DIR="handlers"

mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

cmake .. -DCMAKE_BUILD_TYPE="$BUILD_TYPE"
make -j$(nproc 2>/dev/null || sysctl -n hw.ncpu)

cd ..
rm -rf "$HANDLERS_DIR"

echo "Build complete: $BUILD_DIR/quickwork"
