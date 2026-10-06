---
name: voidb-plugin-webdav
description: Guide for the VoidB WebDAV plugin. Use when modifying crates/plugins/voidb-plugin-webdav, webdav.* capabilities, WebDAV CLI commands, service/sync operations, standalone WebDAV TUI, auth/TLS config, sync_plan behavior, or fixture smoke checks.
---

# VoidB WebDAV Plugin

## Start Here

Primary crate: `crates/plugins/voidb-plugin-webdav`.

Inspect:

- `src/config.rs` for `WebDavConfig`, auth, TLS verification, and timeout.
- `src/webdav_ops.rs` for low-level WebDAV operations.
- `src/sync_ops.rs` for pull/push/sync planning.
- `src/service/` for commands, events, and service facade.
- `src/capabilities.rs` for `webdav.*` metadata and invocation.
- `src/cli_plugin.rs` for `voidb-cli webdav ...`.
- `src/tui.rs` for standalone WebDAV browser TUI.
- `docs/webdav-release-readiness.md` and `docs/storage-tui-ux-decisions.md`.

## Boundaries

- Keep WebDAV client details inside this plugin crate.
- Treat `put`, `delete`, `mkdir`, copy/move, and sync as policy-sensitive.
- Preserve `sync_plan` as a planning surface; plan-only paths must not write.
- Redact passwords, bearer tokens, URLs with credentials, and server details where policy requires it.
- Keep remote path normalization and traversal behavior explicit.

## CLI And Capabilities

- CLI commands: `ls`, `get`, `put`, `mkdir`, `rm`, `mv`, `cp`, `info`, `test`, `tui`, `pull`, `push`, `sync`.
- Capabilities: `webdav.list`, `webdav.stat`, `webdav.get`, `webdav.put`, `webdav.delete`, `webdav.mkdir`, `webdav.sync_plan`.

## Validation

- Focused gate: `cargo test -p voidb-plugin-webdav`.
- Add `cargo test -p voidb-cli invoke` for capability or generic invoke changes.
- Secret-free smoke: `scripts/release-plugin-smoke.sh --plugin webdav`.
- Fixture gate when feasible: `scripts/webdav-fixture-smoke.sh`.
- Always run `git diff --check`.
