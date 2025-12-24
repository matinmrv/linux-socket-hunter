#!/bin/bash

if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root."
    exit 1
fi

echo "Parsing /proc/net/packet and scanning processes..."
echo "---------------------------------------------------------------------"

if [ ! -f "/proc/net/packet" ]; then
    echo "Error: /proc/net/packet not found. Kernel may not support packet sockets."
    exit 1
fi
declare -A packet_inodes
raw_inodes=$(awk 'NR > 1 {print $9}' /proc/net/packet | sort -u)

if [ -z "$raw_inodes" ]; then
    echo "No packet sockets are currently open."
    exit 0
else
    printf "Found inodes:\n${raw_inodes}\nScanning /proc...\n\n"
fi

for inode in $raw_inodes; do
    packet_inodes["$inode"]="not_found"
done


for pid_dir in /proc/[0-9]*; do
    pid="${pid_dir##*/}"

    if [ ! -d "$pid_dir/fd" ]; then
        continue
    fi

    for fd_link in "$pid_dir"/fd/*; do
        if [ -L "$fd_link" ]; then
            target=$(readlink "$fd_link" 2>/dev/null)

            if [[ "$target" =~ ^socket:\[([0-9]+)\]$ ]]; then
                socket_inode="${BASH_REMATCH[1]}"

                if [[ ${packet_inodes[$socket_inode]} ]]; then
                    packet_inodes["$socket_inode"]="found"

                    process_name=$(cat "$pid_dir/comm" 2>/dev/null || echo "Unknown")
                    cmd_line=$(tr '\0' ' ' < "$pid_dir/cmdline" 2>/dev/null)

                    echo "MATCH FOUND:"
                    echo "  PID:          $pid"
                    echo "  Process Name: $process_name"
                    echo "  Command:      $cmd_line"
                    echo "  Inode:        $socket_inode"
                    echo "  FD Path:      $target"
                    echo "---------------------------------------------------------------------"
                fi
            fi
        fi
    done
done

for inode in "${!packet_inodes[@]}"; do
    if [ "${packet_inodes[$inode]}" == "not_found" ]; then
        echo "ALERT: Inode $inode found in /proc/net/packet, but NO process owns it."
        echo "       This could indicate a hidden/malicious process (rootkit)."
        echo "---------------------------------------------------------------------"
    fi
done

echo "Scan complete."
