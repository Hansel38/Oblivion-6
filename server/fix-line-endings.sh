#!/bin/bash
# Fix line endings for oblivion-start script
# Run this once: bash fix-line-endings.sh

if [ -f "oblivion-start" ]; then
    # Remove carriage returns (^M)
    sed -i 's/\r$//' oblivion-start
    chmod +x oblivion-start
    echo "Fixed line endings for oblivion-start"
else
    echo "Error: oblivion-start not found"
    exit 1
fi

