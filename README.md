# Linux Raw Socket Hunter

A simple tool to find which processes are using raw network sockets.

## Why this is needed
The file `/proc/net/packet` lists active raw sockets, but it only shows the **Inode** number. It doesn't tell you which process is actually using that socket. This script bridges that gap by mapping the Inode back to a **Process ID (PID)**.

## How it works
1. It reads all active socket Inodes from `/proc/net/packet`.
2. It searches through `/proc/[pid]/fd/` to find the matching socket link.
3. It displays the PID, Process Name, and the full Command.
4. **Security Check:** If a socket exists in the kernel but no process owns it in `/proc`, the script alerts you of a potential hidden process (rootkit).



## Usage
The script must be run as **root** to access process information.

```bash
chmod +x socket_hunter.sh
sudo ./socket_hunter.sh
