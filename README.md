# rs-smbclient

An interactive SMB2/3 client written in **pure Rust** no C dependencies, no libsmbclient.
Inspired by Impacket's `smbclient.py`.

## Features

- Interactive shell with command history (REPL)
- Share enumeration via **DCE/RPC NetrShareEnum** (like `smbclient -L`)
- File upload and download
- Create and delete files and directories
- Non-interactive mode for scripting (`-c "command"`)
- 100% Rust SMB2/3 implementation (`smb` crate, no C FFI)

## Installation

```bash
git clone https://github.com/ivancabrera02/rs-smbclient
cd rs-smbclient
cargo build --release
# Binary will be at ./target/release/rs-smbclient
```

**Requirements:** Rust 1.75+ (stable). No system dependencies.

## Usage

```bash
# Connect to a share
smbclient-rs //192.168.1.10/SYSVOL -u "DOMAIN\user" -p "password"

# List all shares on a server (equivalent to smbclient -L)
smbclient-rs //192.168.1.10/IPC$ -u Administrator -p Pass123 -c "shares"

# Run a single command and exit
smbclient-rs //192.168.1.10/share -u user -p pass -c "ls"

# Anonymous session
smbclient-rs //192.168.1.10/IPC$
```

## Commands

| Command | Description |
|---|---|
| `shares` | List all shares on the server (NetrShareEnum via DCE/RPC) |
| `ls [path]` | List files and directories |
| `cd <path>` | Change remote directory (`..` to go up) |
| `pwd` | Print current remote path |
| `get <remote> [local]` | Download a file |
| `put <local> [remote]` | Upload a file |
| `mkdir <path>` | Create a remote directory |
| `rm <file>` | Delete a remote file |
| `rmdir <dir>` | Delete a remote directory |
| `cat <file>` | Print a remote file to stdout |
| `lcd [path]` | Change local working directory |
| `lpwd` | Print local working directory |
| `info` | Show connection info |
| `help` | Show help |
| `exit` | Disconnect and exit |

## How `shares` works

The `shares` command implements the full protocol from scratch:

```
1. Connect to \\HOST\IPC$          administrative share for IPC
2. Open named pipe \srvsvc         Windows Server Service pipe
3. DCE/RPC Bind                    negotiate protocol (SRVSVC UUID v3)
4. NetrShareEnum opnum 15          actual RPC call with Level=1
5. Decode NDR response             parse SHARE_INFO_1 structs
```

Fully implemented by hand in `src/rpc.rs` following the `[MS-RPCE]` and `[MS-SRVS]` Microsoft specifications.

## Project structure

```
src/
├── main.rs   — REPL, commands, SMB connection
└── rpc.rs    — DCE/RPC over named pipe (NetrShareEnum)
```

## Testing locally with Samba

```bash
# Install Samba
sudo apt install samba

# /etc/samba/smb.conf
[global]
  workgroup = WORKGROUP
[test]
  path = /tmp/smb-test
  read only = no
  guest ok = yes

sudo systemctl start smbd
mkdir -p /tmp/smb-test && echo "hello world" > /tmp/smb-test/test.txt

# Connect
./target/release/smbclient-rs //127.0.0.1/test
```

## Dependencies

| Crate | Purpose |
|---|---|
| [`smb`](https://crates.io/crates/smb) | Pure-Rust SMB2/3 implementation |
| `tokio` | Async runtime |
| `clap` | CLI argument parsing |
| `rustyline` | REPL with history |
| `colored` | Colored terminal output |
| `anyhow` | Error handling |

## License

MIT
