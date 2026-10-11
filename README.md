# VoidB WebDAV Plugin (`voidb-plugin-webdav`)

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

Independent process plugin for [VoidB](https://github.com/limmytian/voidb) to connect, inspect, and manage files on WebDAV remote storage servers.

## Features

- **Autonomous Process Architecture**: Runs in an isolated OS process communicating with VoidB via `stdio-jsonrpc`.
- **Tri-Modal Operation**:
  - `test`: Automated connectivity verification.
  - `tui`: Standalone full-screen interactive terminal interface.
  - `serve`: `stdio-jsonrpc` protocol server for AI Agents and automated orchestration.
  - Domain commands: File listing, upload/download, remote folder creation, moving, copying, and sync.
- **Capability Surface**:
  - `probe`: Probe server DAV classes, allowed methods, range requests, and lock capabilities.
  - `list`: List directory contents with bounded results and offset pagination.
  - `stat`: Inspect metadata and headers for a single WebDAV item.
  - `get`: Download bounded base64 file content.
  - `put`: Upload inline content with dry-run support.
  - `delete`: Delete remote files or collections with dry-run support.
  - `mkdir`: Create collections with dry-run support.
  - `copy`: Copy remote items with explicit overwrite and preconditions.
  - `move`: Move remote items with explicit overwrite and preconditions.
  - `sync_plan`: Generate bidirectional sync plans between local folders and remote WebDAV directories.

## Usage & Operational Modes

When installed, `voidb-cli` automatically discovers this plugin and provides seamless transparent dispatch:

### 1. Human Operations (CLI & TUI)

```bash
# Connectivity test
voidb-cli webdav test --profile my-webdav

# Launch standalone interactive fullscreen TUI
voidb-cli webdav tui --profile my-webdav

# File and collection operations
voidb-cli webdav ls /remote/path --profile my-webdav
voidb-cli webdav info /remote/path/file.txt --profile my-webdav
voidb-cli webdav put /remote/path/file.txt ./local.txt --profile my-webdav
voidb-cli webdav get /remote/path/file.txt ./download.txt --profile my-webdav
voidb-cli webdav mkdir /remote/path/new-folder --profile my-webdav
```

### 2. Machine Communication (AI Agents & JSON-RPC)

```bash
# Run the stdio-jsonrpc server directly or via voidb-cli
voidb-cli webdav serve
# Or directly run the binary:
./bin/voidb-plugin-webdav serve
```

## Quick Start

### Installation

Place this plugin directory or a packaged release archive under your VoidB plugins directory (`~/Library/Application Support/voidb/plugins/webdav` on macOS, or `~/.local/share/voidb/plugins/webdav` on Linux):

```bash
mkdir -p "$HOME/Library/Application Support/voidb/plugins/webdav"
cp -r plugin.toml bin schemas "$HOME/Library/Application Support/voidb/plugins/webdav/"
```

Verify discovery via `voidb`:

```bash
voidb-cli plugin list
voidb-cli webdav --help
```

### Development & Build

```bash
cargo build --release
mkdir -p bin
cp target/release/voidb-plugin-webdav bin/
```

## Protocol Specifications

Complies with the [VoidB Process Plugin Protocol](https://github.com/limmytian/voidb/blob/main/docs/quickstart-process-plugin.md) specification (v1.0).

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.

## Optional local SDK development

Release and CI builds resolve SDK/core from the immutable Git revision in Cargo.toml. To test against a sibling `../voidb` checkout, explicitly opt in with `cargo --config .cargo/config.local.example.toml test --all-targets`. Do not commit an active `.cargo/config.toml` path override.
