#!/bin/bash

# Source directory
SRC_DIR="../hls"

# Target directory
TARGET_DIR="./"

# Ensure the source directory exists
if [[ ! -d "$SRC_DIR" ]]; then
    echo "Source directory $SRC_DIR does not exist."
    exit 1
fi

# Find and symlink each *.h file
for file in "$SRC_DIR"/*.cpp; do
    # Skip if no .h files are found
    if [[ ! -e "$file" ]]; then
        echo "No .h files found in $SRC_DIR."
        break
    fi

    # Create a symlink in the target directory
    ln -sf "$file" "$TARGET_DIR"
    echo "Symlinked: $file -> $TARGET_DIR"
done

echo "Symlinking complete."
