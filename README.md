# VoidB WebDAV Plugin (`voidb-plugin-webdav`)

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

Independent process plugin for [VoidB](https://github.com/limmytian/voidb) to connect, inspect, and manage files on WebDAV remote storage servers.

## Features

- **Autonomous Process Architecture**: Runs in an isolated OS process communicating with VoidB via `stdio-jsonrpc`.
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
- **Dual Mode**: Can run as a JSON-RPC worker server (`voidb-plugin-webdav serve`) or standalone interactive TUI.

## Quick Start

### Installation

Place this plugin directory or a packaged release archive under your VoidB plugins directory:

```bash
mkdir -p ~/.config/voidb/plugins/webdav
cp -r plugin.toml bin schemas ~/.config/voidb/plugins/webdav/
```

Verify discovery via `voidb`:

```bash
voidb-cli plugin list
voidb-cli plugin describe webdav
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
