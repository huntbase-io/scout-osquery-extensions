#!/bin/bash

# Ensure the script is run as root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root"
   exit 1
fi

# Print column names
echo -e "\"device\", \"link_speed\""

# Read the output of networksetup and process each Hardware Port block
networksetup -listallhardwareports | while IFS= read -r line; do
    if [[ "$line" == "Hardware Port:"* ]]; then
        # Extract Hardware Port name (optional, not used in this format)
        hardware_port=$(echo "$line" | awk -F": " '{print $2}')
    elif [[ "$line" == "Device:"* ]]; then
        # Extract Device identifier (e.g., en0, en1)
        device=$(echo "$line" | awk -F": " '{print $2}')
        
        # Retrieve the media status for the device
        link_speed=$(networksetup -getMedia "$device" 2>/dev/null | awk -F": " '{print $2}' | tr '\n' ' ' | sed 's/ $//')
        
        # If link_speed is empty, set it to "unknown"
        if [ -z "$link_speed" ]; then
            link_speed="unknown"
        fi
        
        # Output the device and link speed in a single row with lowercase field names and underscores
        echo -e "\"device\": \"$device\", \"link_speed\": \"$link_speed\""
    fi
done
