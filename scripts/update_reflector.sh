#!/bin/bash
# This script updates the reflector map

if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <reflector_map> <reflector_wiring>"
    exit 1
fi

MAP_NAME=$1
REFLECTOR=$2

# Update the reflector map
update_reflector_map() {
    local map=$1
    local reflector=$2
    for ((i=0; i<26; i++)); do
        char=${reflector:i:1}
        index=$(printf "%d" "'$char")
        index=$((index - 65)) # Convert ASCII to 0-based index
        sudo bpftool map update pinned /sys/fs/bpf/tc/globals/${map} key hex $(printf "%02x 00 00 00" $i) value hex $(printf "%02x" $index)
    done
}

echo "Setting up reflector: $REFLECTOR"
update_reflector_map "$MAP_NAME" "$REFLECTOR"
