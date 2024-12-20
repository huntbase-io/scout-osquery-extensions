#!/bin/bash

# Ensure the script is run as root (mimicking the given example's behavior)
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root"
   exit 1
fi

# Set the directory for the default Chrome profile
EXT_DIR="$HOME/Library/Application Support/Google/Chrome/Default/Extensions"

# Ensure jq is installed
if ! command -v jq &> /dev/null; then
    echo "jq is not installed. Please install it (e.g., brew install jq) and run again."
    exit 1
fi

# Check if the Chrome Extensions directory exists
if [ ! -d "$EXT_DIR" ]; then
    echo "Chrome Extensions directory not found at: $EXT_DIR"
    exit 1
fi

# Iterate over each extension directory
for EXT_ID in "$EXT_DIR"/*; do
    if [ -d "$EXT_ID" ]; then
        EXT_ID_NAME=$(basename "$EXT_ID")
        
        # Find the latest version directory by sorting versions and selecting the last
        LATEST_VERSION_DIR=$(ls "$EXT_ID" | sort -V | tail -n 1)
        MANIFEST="$EXT_ID/$LATEST_VERSION_DIR/manifest.json"

        if [ -f "$MANIFEST" ]; then
            # Extract name and version from manifest.json
            NAME=$(jq -r '.name // "unknown_name"' "$MANIFEST")
            VERSION=$(jq -r '.version // "unknown_version"' "$MANIFEST")
        else
            NAME="unknown_name"
            VERSION="unknown_version"
        fi

        # Print the extension info in a single row with lowercase field names and underscores
        echo -e "\"name\": \"$NAME\", \"version\": \"$VERSION\", \"extension_id\": \"$EXT_ID_NAME\""
    fi
done
