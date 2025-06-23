#!/bin/bash
# This script updates rotor maps with proper ring settings

if [ "$#" -ne 4 ]; then
    echo "Usage: $0 <rotor_map_name> <rotor_inv_map_name> <rotor_wiring> <ring_setting>"
    exit 1
fi

MAP_NAME=$1
INV_MAP_NAME=$2
ROTOR=$3
RING_SETTING=$4

# Apply ring setting
apply_ring_setting() {
    local rotor=$1
    local ring_setting=$2
    local offset=$((ring_setting - 1)) # Convert 'A'=1, 'B'=2, etc.
    echo "${rotor:offset}${rotor:0:offset}"
}

# Calculate inverse of a rotor
calculate_inverse() {
    local rotor=$1
    local alphab="ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    local inverse=""

    for ((i=0; i<26; i++)); do
        local char=${alphab:i:1}
        local pos=${rotor%%$char*}
        local index=${#pos}
        local inverse_char=${alphab:index:1}
        inverse="${inverse}${inverse_char}"
    done

    echo "$inverse"
}

# Update a map
update_map() {
    local map=$1
    local rotor=$2
    for ((i=0; i<26; i++)); do
        char=${rotor:i:1}
        index=$(printf "%d" "'$char")
        index=$((index - 65)) # Convert ASCII to 0-based index
        sudo bpftool map update pinned /sys/fs/bpf/tc/globals/${map} key hex $(printf "%02x 00 00 00" $i) value hex $(printf "%02x" $index)
    done
}

# Apply the ring setting
ROTOR_WITH_RING=$(apply_ring_setting "$ROTOR" $RING_SETTING)
ROTOR_INV=$(calculate_inverse "$ROTOR_WITH_RING")

echo "Rotor with ring setting $RING_SETTING: $ROTOR_WITH_RING"
echo "Inverse rotor: $ROTOR_INV"

# Update the maps
update_map $MAP_NAME "$ROTOR_WITH_RING"
update_map $INV_MAP_NAME "$ROTOR_INV"
