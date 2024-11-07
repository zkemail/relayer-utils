#!/bin/bash
set -e

echo "Building for WASM"

# Check if wasm-pack is installed
if ! command -v wasm-pack &> /dev/null; then
    echo "❌ Error: wasm-pack is not installed"
    echo "Please install it with 'cargo install wasm-pack'"
    exit 1
fi

# Get wasm-pack version
WASM_PACK_VERSION=$(wasm-pack --version | sed 's/wasm-pack //')
REQUIRED_VERSION="0.13.0"

# Function to compare versions
version_compare() {
    if [[ $1 == $2 ]]; then
        return 0
    fi
    local IFS=.
    local i ver1=($1) ver2=($2)
    # Fill empty positions with zeros
    for ((i=${#ver1[@]}; i<${#ver2[@]}; i++)); do
        ver1[i]=0
    done
    for ((i=0; i<${#ver1[@]}; i++)); do
        if [[ -z ${ver2[i]} ]]; then
            ver2[i]=0
        fi
        if ((10#${ver1[i]} > 10#${ver2[i]})); then
            return 1
        fi
        if ((10#${ver1[i]} < 10#${ver2[i]})); then
            return 2
        fi
    done
    return 0
}

# Check version
version_compare "$WASM_PACK_VERSION" "$REQUIRED_VERSION"
RESULT=$?

if [ $RESULT -eq 2 ]; then
    echo "❌ Error: wasm-pack version $REQUIRED_VERSION or higher is required"
    echo "Current version: $WASM_PACK_VERSION"
    echo "Please upgrade wasm-pack with 'cargo install wasm-pack --force'"
    exit 1
fi

echo "✅ Using wasm-pack version $WASM_PACK_VERSION"

# Build for Node.js
echo "📦 Building Node.js target..."
wasm-pack build --target bundler --out-dir pkg/node --scope @dimidumo

# Build for web
echo "🌐 Building web target..."
wasm-pack build --target web --out-dir pkg/web --scope @dimidumo

cp README.md pkg/
cp js-wasm-wrapper/index.node.js pkg/
cp js-wasm-wrapper/index.web.js pkg/
cp js-wasm-wrapper/package.json pkg/

# Remove .gitignore files
rm -f pkg/.gitignore pkg/node/.gitignore pkg/web/.gitignore

echo "✨ Build complete!"
