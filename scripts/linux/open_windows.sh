#!/bin/bash

# Description:
# This script retrieves and lists all open windows for the current console user on macOS in JSON format.
# It includes details such as application name, window title, window ID, position, size, and visibility status.
# The script must be run as root to access the user's session.

# Function to get the console user
get_console_user() {
    scutil <<< "show State:/Users/ConsoleUser" | awk '/Name :/ && ! /loginwindow/ { print $3 }'
}

# Function to get UID of a user
get_user_uid() {
    local username="$1"
    id -u "$username" 2>/dev/null
}

# Function to execute AppleScript in the user's context and retrieve window info
get_user_windows() {
    local username="$1"
    local uid="$2"

    # Execute AppleScript as the user via launchctl asuser
    windows_json=$(launchctl asuser "$uid" /usr/bin/osascript <<EOF
    -- Initialize JSON array
    set json_output to "[" & return

    tell application "System Events"
        set process_list to every process whose visible is true
        set first_entry to true

        repeat with proc in process_list
            set app_name to name of proc

            try
                -- Get all windows for the current application
                set win_list to every window of proc
                repeat with win in win_list
                    -- Retrieve window properties
                    set win_name to name of win
                    set win_id to id of win
                    set win_bounds to bounds of win -- {x, y, width, height}
                    set is_minimized to minimized of win
                    set is_visible to visible of win

                    -- Extract position and size
                    set pos_x to item 1 of win_bounds
                    set pos_y to item 2 of win_bounds
                    set win_width to item 3 of win_bounds
                    set win_height to item 4 of win_bounds

                    -- Prepare JSON object
                    if first_entry then
                        set first_entry to false
                    else
                        set json_output to json_output & "," & return
                    end if

                    set json_object to "{"
                    set json_object to json_object & "\"application_name\": " & quoted form of app_name & ", "
                    set json_object to json_object & "\"window_title\": " & quoted form of win_name & ", "
                    set json_object to json_object & "\"window_id\": " & win_id & ", "
                    set json_object to json_object & "\"position\": {\"x\": " & pos_x & ", \"y\": " & pos_y & "}, "
                    set json_object to json_object & "\"size\": {\"width\": " & win_width & ", \"height\": " & win_height & "}, "
                    set json_object to json_object & "\"is_minimized\": " & (is_minimized as string) & ", "
                    set json_object to json_object & "\"is_visible\": " & (is_visible as string)
                    set json_object to json_object & "}"

                    set json_output to json_output & json_object
                end repeat
            on error errMsg number errNum
                -- Handle errors silently
            end try
        end repeat
    end tell

    -- Close JSON array
    set json_output to json_output & return & "]"

    -- Return the JSON output
    return json_output
EOF
    )

    # Check if windows_json is empty or contains error
    if [ -z "$windows_json" ]; then
        # Attempt to capture error from osascript
        windows_json="[]"
    fi

    echo "$windows_json"
}

# Initialize the final JSON object
final_json="{\"username\": \"\", \"uid\": 0, \"windows\": []}"

# Get the console user
user=$(get_console_user)

if [ -z "$user" ]; then
    echo "No console user found." >&2
    echo "$final_json"
    exit 1
fi

uid=$(get_user_uid "$user")
if [ -z "$uid" ]; then
    echo "Could not find UID for user: $user" >&2
    echo "$final_json"
    exit 1
fi

echo "Processing user: $user (UID: $uid)" >&2

# Retrieve window information for the user
user_windows=$(get_user_windows "$user" "$uid")

# Check if user_windows is empty or not
if [ "$user_windows" == "[]" ]; then
    echo "No windows found for user: $user" >&2
fi

# Prepare JSON object for the user
# Escape username if necessary
escaped_user=$(printf '%s' "$user" | sed 's/\\/\\\\/g; s/"/\\"/g')

final_json="{\"username\": \"$escaped_user\", \"uid\": $uid, \"windows\": $user_windows}"

# Echo the final JSON output to the console
echo "$final_json"
