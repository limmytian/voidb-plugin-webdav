//! WebDAV service layer.
//!
//! This module provides `WebDavService`, the service facade for the WebDAV
//! plugin. It follows the RedisService / MySqlService convention:
//!
//! - Background tokio task processes commands asynchronously
//! - `send()` dispatches commands via unbounded mpsc channel (non-blocking)
//! - `poll_event()` drains events via `try_recv()` (non-blocking)
//! - Render notifications fire after every event emission
//!
//! # Connection Lifecycle
//!
//! The service starts by creating a WebDAV client from the config. The
//! background loop processes commands using this persistent client.
//! On `Disconnect` (or sender drop), the loop exits.
//!
//! # ServiceMode
//!
//! `WebDavService` supports two execution modes:
//!
//! - `Channel`: Background tokio task, used by the TUI plugin. Commands are
//!   dispatched via `send()` and results arrive via `poll_event()`.
//! - `Direct`: Synchronous-style async methods called directly, used by the
//!   CLI plugin. No background task is spawned.

pub mod commands;
pub mod events;

pub use commands::WebDavCommand;
pub use events::WebDavEvent;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::Result;
use chrono::Utc;
use reqwest_dav::Client;
use tokio::sync::mpsc;

use crate::config::WebDavConfig;
use crate::sync_ops;
use crate::types::{
    DavEntry, SyncContext, SyncOptions, SyncPlan, SyncResult, WebDavCopyMoveOptions,
    WebDavFeatureProbe, WebDavLock,
};
use crate::webdav_ops;
use voidb_core::{AgentTransferEvent, AgentTransferOperation, AgentTransferPhase, TabManager};

// ---------------------------------------------------------------------------
// ServiceMode
// ---------------------------------------------------------------------------

/// Internal execution mode for `WebDavService`.
enum ServiceMode {
    /// TUI mode: commands routed through a background task via channels.
    Channel {
        cmd_tx: mpsc::UnboundedSender<WebDavCommand>,
        event_rx: mpsc::UnboundedReceiver<WebDavEvent>,
        /// Held to keep the background task alive.
        _task: tokio::task::JoinHandle<()>,
    },
    /// CLI/direct mode: client held inline, operations called directly.
    Direct {
        client: Client,
        cancel_flag: Arc<AtomicBool>,
    },
}

// ---------------------------------------------------------------------------
// WebDavService
// ---------------------------------------------------------------------------

/// WebDAV service facade.
///
/// Owns the command sender and event receiver channels (Channel mode) or the
/// WebDAV client directly (Direct mode). The background task runs on the
/// shared tokio runtime via `runtime.spawn()` when created with `new()`.
///
/// # Send + Sync
///
/// `WebDavService` is `Send` but NOT `Sync` (because `UnboundedReceiver`
/// is `!Sync`). Plugin structs must wrap it in `std::sync::Mutex` to
/// satisfy `Plugin: Send + Sync`. Since `Plugin::update(&mut self)` has
/// exclusive access, the Mutex is never contended.
pub struct WebDavService {
    mode: ServiceMode,
    cancel_flag: Arc<AtomicBool>,
}

impl WebDavService {
    // -----------------------------------------------------------------------
    // Constructors
    // -----------------------------------------------------------------------

    /// Create a new WebDavService with a background processing task (TUI mode).
    ///
    /// The service immediately creates a WebDAV client and lists the root
    /// directory.
    pub fn new(
        config: WebDavConfig,
        cancel_flag: Arc<AtomicBool>,
        tabs: Arc<dyn TabManager>,
        runtime: tokio::runtime::Handle,
    ) -> Self {
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel::<WebDavCommand>();
        let (event_tx, event_rx) = mpsc::unbounded_channel::<WebDavEvent>();

        let task_cancel_flag = Arc::clone(&cancel_flag);
        let task = runtime.spawn(Self::background_task(
            cmd_rx,
            event_tx,
            tabs,
            config,
            task_cancel_flag,
        ));

        Self {
            mode: ServiceMode::Channel {
                cmd_tx,
                event_rx,
                _task: task,
            },
            cancel_flag,
        }
    }

    /// Create a new WebDavService in Direct mode (CLI mode).
    ///
    /// No background task is spawned. Operations are performed via the
    /// direct async methods (`list_dir`, `download`, `upload`, etc.).
    /// Returns an error if the WebDAV client cannot be created.
    pub fn new_direct(config: &WebDavConfig) -> Result<Self> {
        let client = webdav_ops::create_client(config)?;
        let cancel_flag = Arc::new(AtomicBool::new(false));
        Ok(Self {
            mode: ServiceMode::Direct {
                client,
                cancel_flag: Arc::clone(&cancel_flag),
            },
            cancel_flag,
        })
    }

    // -----------------------------------------------------------------------
    // Channel-mode API (TUI)
    // -----------------------------------------------------------------------

    /// Send a command to the background service task (Channel mode only).
    ///
    /// This is non-blocking -- safe to call from the synchronous
    /// `Plugin::update()` context.
    pub fn send(&self, cmd: WebDavCommand) {
        match &cmd {
            WebDavCommand::CancelTransfer => self.cancel_flag.store(true, Ordering::Release),
            WebDavCommand::DownloadFile { .. }
            | WebDavCommand::UploadFile { .. }
            | WebDavCommand::SyncExecute { .. } => {
                self.cancel_flag.store(false, Ordering::Release);
            }
            _ => {}
        }
        match &self.mode {
            ServiceMode::Channel { cmd_tx, .. } => {
                let _ = cmd_tx.send(cmd);
            }
            ServiceMode::Direct { .. } => {
                // Direct mode does not use the command channel.
                // Callers should use the async direct methods instead.
            }
        }
    }

    /// Poll for the next event from the service (Channel mode only).
    ///
    /// Returns `Some(event)` if available, `None` otherwise.
    /// Non-blocking, suitable for calling from `Plugin::update()`.
    pub fn poll_event(&mut self) -> Option<WebDavEvent> {
        match &mut self.mode {
            ServiceMode::Channel { event_rx, .. } => event_rx.try_recv().ok(),
            ServiceMode::Direct { .. } => None,
        }
    }

    // -----------------------------------------------------------------------
    // Direct-mode API (CLI)
    // -----------------------------------------------------------------------

    /// List contents of a remote directory.
    ///
    /// Only available in Direct mode.
    pub async fn list_dir(&self, path: &str) -> Result<Vec<DavEntry>> {
        match &self.mode {
            ServiceMode::Direct { client, .. } => webdav_ops::list_dir(client, path).await,
            ServiceMode::Channel { .. } => {
                anyhow::bail!(
                    "list_dir() requires Direct mode; use send(WebDavCommand::ListDir) for Channel mode"
                )
            }
        }
    }

    /// Download a remote file and return its bytes.
    ///
    /// Only available in Direct mode.
    pub async fn download(&self, remote: &str) -> Result<Vec<u8>> {
        match &self.mode {
            ServiceMode::Direct { client, .. } => webdav_ops::download(client, remote).await,
            ServiceMode::Channel { .. } => {
                anyhow::bail!(
                    "download() requires Direct mode; use send(WebDavCommand::DownloadFile) for Channel mode"
                )
            }
        }
    }

    /// Download a byte range for best-effort resume.
    pub async fn download_range(
        &self,
        remote: &str,
        start: u64,
        end: Option<u64>,
    ) -> Result<(Vec<u8>, Option<u64>)> {
        match &self.mode {
            ServiceMode::Direct { client, .. } => {
                webdav_ops::download_range(client, remote, start, end).await
            }
            ServiceMode::Channel { .. } => anyhow::bail!("download_range() requires Direct mode"),
        }
    }

    /// Upload data to a remote path.
    ///
    /// Only available in Direct mode.
    pub async fn upload(&self, remote: &str, data: Vec<u8>) -> Result<()> {
        match &self.mode {
            ServiceMode::Direct { client, .. } => webdav_ops::upload(client, remote, data).await,
            ServiceMode::Channel { .. } => {
                anyhow::bail!(
                    "upload() requires Direct mode; use send(WebDavCommand::UploadFile) for Channel mode"
                )
            }
        }
    }

    /// Check whether a remote resource exists without treating target errors
    /// as absence.
    pub async fn resource_exists(&self, path: &str) -> Result<bool> {
        match &self.mode {
            ServiceMode::Direct { client, .. } => webdav_ops::resource_exists(client, path).await,
            ServiceMode::Channel { .. } => {
                anyhow::bail!("resource_exists() requires Direct mode")
            }
        }
    }

    /// Create a remote directory.
    ///
    /// Only available in Direct mode.
    pub async fn mkdir(&self, path: &str) -> Result<()> {
        match &self.mode {
            ServiceMode::Direct { client, .. } => webdav_ops::mkdir(client, path).await,
            ServiceMode::Channel { .. } => {
                anyhow::bail!(
                    "mkdir() requires Direct mode; use send(WebDavCommand::CreateDir) for Channel mode"
                )
            }
        }
    }

    /// Delete a remote file or directory.
    ///
    /// Only available in Direct mode.
    pub async fn delete(&self, path: &str) -> Result<()> {
        match &self.mode {
            ServiceMode::Direct { client, .. } => webdav_ops::delete(client, path).await,
            ServiceMode::Channel { .. } => {
                anyhow::bail!(
                    "delete() requires Direct mode; use send(WebDavCommand::DeleteItem) for Channel mode"
                )
            }
        }
    }

    /// Move/rename a remote item.
    ///
    /// Only available in Direct mode.
    pub async fn move_item(&self, from: &str, to: &str) -> Result<()> {
        match &self.mode {
            ServiceMode::Direct { client, .. } => webdav_ops::move_item(client, from, to).await,
            ServiceMode::Channel { .. } => {
                anyhow::bail!(
                    "move_item() requires Direct mode; use send(WebDavCommand::MoveItem) for Channel mode"
                )
            }
        }
    }

    /// Copy a remote item.
    ///
    /// Only available in Direct mode.
    pub async fn copy_item(&self, from: &str, to: &str) -> Result<()> {
        match &self.mode {
            ServiceMode::Direct { client, .. } => webdav_ops::copy_item(client, from, to).await,
            ServiceMode::Channel { .. } => {
                anyhow::bail!(
                    "copy_item() requires Direct mode; use send(WebDavCommand::CopyItem) for Channel mode"
                )
            }
        }
    }

    /// COPY with explicit overwrite, depth, ETag, and lock preconditions.
    pub async fn copy_item_with_options(
        &self,
        from: &str,
        to: &str,
        options: &WebDavCopyMoveOptions,
    ) -> Result<()> {
        match &self.mode {
            ServiceMode::Direct { client, .. } => {
                webdav_ops::copy_item_with_options(client, from, to, options).await
            }
            ServiceMode::Channel { .. } => {
                anyhow::bail!("copy_item_with_options() requires Direct mode")
            }
        }
    }

    /// MOVE with explicit overwrite, ETag, and lock preconditions.
    pub async fn move_item_with_options(
        &self,
        from: &str,
        to: &str,
        options: &WebDavCopyMoveOptions,
    ) -> Result<()> {
        match &self.mode {
            ServiceMode::Direct { client, .. } => {
                webdav_ops::move_item_with_options(client, from, to, options).await
            }
            ServiceMode::Channel { .. } => {
                anyhow::bail!("move_item_with_options() requires Direct mode")
            }
        }
    }

    /// Probe target-supported transfer features.
    pub async fn probe_features(&self, path: &str) -> Result<WebDavFeatureProbe> {
        match &self.mode {
            ServiceMode::Direct { client, .. } => webdav_ops::probe_features(client, path).await,
            ServiceMode::Channel { .. } => anyhow::bail!("probe_features() requires Direct mode"),
        }
    }

    /// Acquire a service-owned lock token.
    pub async fn lock(&self, path: &str, timeout_seconds: u64, owner: &str) -> Result<WebDavLock> {
        match &self.mode {
            ServiceMode::Direct { client, .. } => {
                webdav_ops::lock(client, path, timeout_seconds, owner).await
            }
            ServiceMode::Channel { .. } => anyhow::bail!("lock() requires Direct mode"),
        }
    }

    /// Release a service-owned lock token.
    pub async fn unlock(&self, path: &str, token: &str) -> Result<()> {
        match &self.mode {
            ServiceMode::Direct { client, .. } => webdav_ops::unlock(client, path, token).await,
            ServiceMode::Channel { .. } => anyhow::bail!("unlock() requires Direct mode"),
        }
    }

    /// Get properties of a single remote item (PROPFIND depth 0).
    ///
    /// Only available in Direct mode.
    pub async fn get_properties(&self, path: &str) -> Result<DavEntry> {
        match &self.mode {
            ServiceMode::Direct { client, .. } => webdav_ops::get_properties(client, path).await,
            ServiceMode::Channel { .. } => {
                anyhow::bail!("get_properties() requires Direct mode")
            }
        }
    }

    /// Walk a remote directory tree recursively.
    ///
    /// Only available in Direct mode.
    pub async fn walk_remote_tree(&self, base_path: &str) -> Result<Vec<crate::types::SyncEntry>> {
        match &self.mode {
            ServiceMode::Direct { client, .. } => {
                sync_ops::walk_remote_tree(client, base_path).await
            }
            ServiceMode::Channel { .. } => {
                anyhow::bail!("walk_remote_tree() requires Direct mode")
            }
        }
    }

    /// Execute a sync plan, performing file transfers and deletions.
    ///
    /// Only available in Direct mode. A dummy `SyncContext` is created
    /// internally (events are discarded since there is no UI in CLI mode).
    pub async fn execute_sync(
        &self,
        plan: &SyncPlan,
        remote_base: &str,
        local_base: &str,
    ) -> Result<SyncResult> {
        match &self.mode {
            ServiceMode::Direct {
                client,
                cancel_flag,
            } => {
                let (event_tx, mut event_rx) = mpsc::unbounded_channel();
                // Drain events asynchronously so the channel never blocks.
                tokio::spawn(async move { while event_rx.recv().await.is_some() {} });
                let sync_ctx = SyncContext {
                    event_tx,
                    cancel_flag: cancel_flag.clone(),
                };
                sync_ops::execute_sync_plan(client, plan, remote_base, local_base, &sync_ctx).await
            }
            ServiceMode::Channel { .. } => {
                anyhow::bail!(
                    "execute_sync() requires Direct mode; use send(WebDavCommand::SyncExecute) for Channel mode"
                )
            }
        }
    }

    /// Compute what changes are needed to synchronize two directory trees.
    ///
    /// This is a pure, synchronous operation available in both modes.
    pub fn compute_sync_plan(
        remote_entries: &[crate::types::SyncEntry],
        local_entries: &[crate::types::SyncEntry],
        options: &SyncOptions,
    ) -> SyncPlan {
        sync_ops::compute_sync_plan(remote_entries, local_entries, options)
    }

    /// Format a sync plan as a human-readable string.
    ///
    /// This is a pure, synchronous operation available in both modes.
    pub fn format_sync_plan(plan: &SyncPlan) -> String {
        sync_ops::format_sync_plan(plan)
    }

    /// Return the sync mode implied by the given `SyncMode` variant.
    ///
    /// Exposed here so CLI code does not need to import `sync_ops` directly.
    pub fn walk_local_tree(base_path: &str) -> Result<Vec<crate::types::SyncEntry>> {
        sync_ops::walk_local_tree(base_path)
    }

    // -----------------------------------------------------------------------
    // Background task (Channel mode only)
    // -----------------------------------------------------------------------

    /// Background task that processes commands.
    ///
    /// Absorbed from the former `start_worker()` method in `browser.rs`.
    async fn background_task(
        mut cmd_rx: mpsc::UnboundedReceiver<WebDavCommand>,
        event_tx: mpsc::UnboundedSender<WebDavEvent>,
        tabs: Arc<dyn TabManager>,
        config: WebDavConfig,
        cancel_flag: Arc<AtomicBool>,
    ) {
        let client = match webdav_ops::create_client(&config) {
            Ok(c) => c,
            Err(e) => {
                let _ = event_tx.send(WebDavEvent::Error(format!(
                    "Failed to create WebDAV client: {}",
                    e
                )));
                return;
            }
        };

        while let Some(cmd) = cmd_rx.recv().await {
            match cmd {
                WebDavCommand::Connect => {
                    // Already connected (client created above). Send initial listing.
                    match webdav_ops::list_dir(&client, "/").await {
                        Ok(entries) => {
                            let _ = event_tx.send(WebDavEvent::DirListed {
                                path: "/".to_string(),
                                entries,
                            });
                        }
                        Err(e) => {
                            let _ = event_tx
                                .send(WebDavEvent::Error(format!("List directory failed: {}", e)));
                        }
                    }
                    let _ = tabs.request_render();
                }

                WebDavCommand::Disconnect => {
                    break;
                }

                WebDavCommand::ListDir(path) => {
                    match webdav_ops::list_dir(&client, &path).await {
                        Ok(entries) => {
                            let _ = event_tx.send(WebDavEvent::DirListed { path, entries });
                        }
                        Err(e) => {
                            let _ = event_tx
                                .send(WebDavEvent::Error(format!("List directory failed: {}", e)));
                        }
                    }
                    let _ = tabs.request_render();
                }

                WebDavCommand::DownloadFile { remote, local } => {
                    // Get file size first
                    let total = match webdav_ops::get_properties(&client, &remote).await {
                        Ok(entry) => entry.size,
                        Err(_) => 0,
                    };
                    let transfer_id = tui_transfer_id("download");
                    let _ = event_tx.send(WebDavEvent::transfer_lifecycle(
                        AgentTransferEvent::single_object_snapshot(
                            &transfer_id,
                            AgentTransferOperation::Download,
                            AgentTransferPhase::Transferring,
                            1,
                            0,
                            (total > 0).then_some(total),
                        ),
                    ));

                    match webdav_ops::download(&client, &remote).await {
                        Ok(data) => {
                            if cancel_flag.load(Ordering::Acquire) {
                                let _ = event_tx.send(WebDavEvent::transfer_lifecycle(
                                    AgentTransferEvent::single_object_snapshot(
                                        &transfer_id,
                                        AgentTransferOperation::Download,
                                        AgentTransferPhase::Cancelling,
                                        2,
                                        0,
                                        (total > 0).then_some(total),
                                    ),
                                ));
                                let _ = event_tx.send(WebDavEvent::transfer_lifecycle(
                                    AgentTransferEvent::single_object_snapshot(
                                        transfer_id,
                                        AgentTransferOperation::Download,
                                        AgentTransferPhase::Cancelled,
                                        3,
                                        0,
                                        (total > 0).then_some(total),
                                    ),
                                ));
                                let _ = event_tx.send(WebDavEvent::TransferCancelled);
                                let _ = tabs.request_render();
                                continue;
                            }
                            let _ = event_tx.send(WebDavEvent::DownloadProgress {
                                remote: remote.clone(),
                                transferred: data.len() as u64,
                                total: total.max(data.len() as u64),
                            });
                            if let Err(e) = std::fs::write(&local, &data) {
                                let _ = event_tx.send(WebDavEvent::transfer_lifecycle(
                                    AgentTransferEvent::single_object_snapshot(
                                        transfer_id,
                                        AgentTransferOperation::Download,
                                        AgentTransferPhase::Failed,
                                        2,
                                        data.len() as u64,
                                        Some(total.max(data.len() as u64)),
                                    ),
                                ));
                                let _ = event_tx.send(WebDavEvent::Error(format!(
                                    "Failed to write local file: {}",
                                    e
                                )));
                            } else {
                                let _ = event_tx.send(WebDavEvent::transfer_lifecycle(
                                    AgentTransferEvent::single_object_snapshot(
                                        transfer_id,
                                        AgentTransferOperation::Download,
                                        AgentTransferPhase::Completed,
                                        2,
                                        data.len() as u64,
                                        Some(data.len() as u64),
                                    ),
                                ));
                                let _ =
                                    event_tx.send(WebDavEvent::DownloadComplete { remote, local });
                            }
                        }
                        Err(e) => {
                            let _ = event_tx.send(WebDavEvent::transfer_lifecycle(
                                AgentTransferEvent::single_object_snapshot(
                                    transfer_id,
                                    AgentTransferOperation::Download,
                                    AgentTransferPhase::Failed,
                                    2,
                                    0,
                                    (total > 0).then_some(total),
                                ),
                            ));
                            let _ = event_tx
                                .send(WebDavEvent::Error(format!("Download failed: {}", e)));
                        }
                    }
                    let _ = tabs.request_render();
                }

                WebDavCommand::UploadFile { local, remote_dir } => {
                    let data = match std::fs::read(&local) {
                        Ok(d) => d,
                        Err(e) => {
                            let _ = event_tx.send(WebDavEvent::Error(format!(
                                "Failed to read local file: {}",
                                e
                            )));
                            continue;
                        }
                    };

                    let filename = std::path::Path::new(&local)
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or(&local);
                    let remote_path = if remote_dir.ends_with('/') {
                        format!("{}{}", remote_dir, filename)
                    } else {
                        format!("{}/{}", remote_dir, filename)
                    };

                    let total = data.len() as u64;
                    let transfer_id = tui_transfer_id("upload");
                    let _ = event_tx.send(WebDavEvent::transfer_lifecycle(
                        AgentTransferEvent::single_object_snapshot(
                            &transfer_id,
                            AgentTransferOperation::Upload,
                            AgentTransferPhase::Transferring,
                            1,
                            0,
                            Some(total),
                        ),
                    ));
                    let _ = event_tx.send(WebDavEvent::UploadProgress {
                        local: local.clone(),
                        transferred: 0,
                        total,
                    });
                    if cancel_flag.load(Ordering::Acquire) {
                        let _ = event_tx.send(WebDavEvent::transfer_lifecycle(
                            AgentTransferEvent::single_object_snapshot(
                                &transfer_id,
                                AgentTransferOperation::Upload,
                                AgentTransferPhase::Cancelling,
                                2,
                                0,
                                Some(total),
                            ),
                        ));
                        let _ = event_tx.send(WebDavEvent::transfer_lifecycle(
                            AgentTransferEvent::single_object_snapshot(
                                transfer_id,
                                AgentTransferOperation::Upload,
                                AgentTransferPhase::Cancelled,
                                3,
                                0,
                                Some(total),
                            ),
                        ));
                        let _ = event_tx.send(WebDavEvent::TransferCancelled);
                        let _ = tabs.request_render();
                        continue;
                    }

                    match webdav_ops::upload(&client, &remote_path, data).await {
                        Ok(()) => {
                            if cancel_flag.load(Ordering::Acquire) {
                                let _ = event_tx.send(WebDavEvent::transfer_lifecycle(
                                    AgentTransferEvent::single_object_snapshot(
                                        transfer_id,
                                        AgentTransferOperation::Upload,
                                        AgentTransferPhase::Failed,
                                        2,
                                        0,
                                        Some(total),
                                    ),
                                ));
                                let _ = event_tx.send(WebDavEvent::Error(
                                    "Upload cancellation arrived after the remote request; verify the destination before retrying.".to_string(),
                                ));
                                let _ = tabs.request_render();
                                continue;
                            }
                            let _ = event_tx.send(WebDavEvent::UploadProgress {
                                local: local.clone(),
                                transferred: total,
                                total,
                            });
                            let _ = event_tx.send(WebDavEvent::transfer_lifecycle(
                                AgentTransferEvent::single_object_snapshot(
                                    transfer_id,
                                    AgentTransferOperation::Upload,
                                    AgentTransferPhase::Completed,
                                    2,
                                    total,
                                    Some(total),
                                ),
                            ));
                            let _ = event_tx.send(WebDavEvent::UploadComplete {
                                local,
                                remote: remote_path,
                            });
                            // Auto-refresh remote directory
                            if let Ok(entries) = webdav_ops::list_dir(&client, &remote_dir).await {
                                let _ = event_tx.send(WebDavEvent::DirListed {
                                    path: remote_dir,
                                    entries,
                                });
                            }
                        }
                        Err(e) => {
                            let _ = event_tx.send(WebDavEvent::transfer_lifecycle(
                                AgentTransferEvent::single_object_snapshot(
                                    transfer_id,
                                    AgentTransferOperation::Upload,
                                    AgentTransferPhase::Failed,
                                    2,
                                    0,
                                    Some(total),
                                ),
                            ));
                            let _ =
                                event_tx.send(WebDavEvent::Error(format!("Upload failed: {}", e)));
                        }
                    }
                    let _ = tabs.request_render();
                }

                WebDavCommand::DeleteItem(path) => {
                    match webdav_ops::delete(&client, &path).await {
                        Ok(()) => {
                            let name = path.rsplit('/').next().unwrap_or(&path);
                            let _ = event_tx.send(WebDavEvent::OperationComplete(format!(
                                "Deleted '{}'",
                                name
                            )));
                            // Auto-refresh parent
                            let parent = parent_path(&path);
                            if let Ok(entries) = webdav_ops::list_dir(&client, &parent).await {
                                let _ = event_tx.send(WebDavEvent::DirListed {
                                    path: parent,
                                    entries,
                                });
                            }
                        }
                        Err(e) => {
                            let _ =
                                event_tx.send(WebDavEvent::Error(format!("Delete failed: {}", e)));
                        }
                    }
                    let _ = tabs.request_render();
                }

                WebDavCommand::Rename { old, new_name } => {
                    let parent = parent_path(&old);
                    let new_path = if parent == "/" {
                        format!("/{}", new_name)
                    } else {
                        format!("{}/{}", parent, new_name)
                    };
                    match webdav_ops::move_item(&client, &old, &new_path).await {
                        Ok(()) => {
                            let old_name = old.rsplit('/').next().unwrap_or(&old);
                            let _ = event_tx.send(WebDavEvent::OperationComplete(format!(
                                "Renamed '{}' -> '{}'",
                                old_name, new_name
                            )));
                            if let Ok(entries) = webdav_ops::list_dir(&client, &parent).await {
                                let _ = event_tx.send(WebDavEvent::DirListed {
                                    path: parent,
                                    entries,
                                });
                            }
                        }
                        Err(e) => {
                            let _ =
                                event_tx.send(WebDavEvent::Error(format!("Rename failed: {}", e)));
                        }
                    }
                    let _ = tabs.request_render();
                }

                WebDavCommand::CreateDir(path) => {
                    match webdav_ops::mkdir(&client, &path).await {
                        Ok(()) => {
                            let name = path.rsplit('/').next().unwrap_or(&path);
                            let _ = event_tx.send(WebDavEvent::OperationComplete(format!(
                                "Created directory '{}'",
                                name
                            )));
                            let parent = parent_path(&path);
                            if let Ok(entries) = webdav_ops::list_dir(&client, &parent).await {
                                let _ = event_tx.send(WebDavEvent::DirListed {
                                    path: parent,
                                    entries,
                                });
                            }
                        }
                        Err(e) => {
                            let _ = event_tx.send(WebDavEvent::Error(format!(
                                "Create directory failed: {}",
                                e
                            )));
                        }
                    }
                    let _ = tabs.request_render();
                }

                WebDavCommand::CopyItem { from, to } => {
                    match webdav_ops::copy_item(&client, &from, &to).await {
                        Ok(()) => {
                            let _ = event_tx.send(WebDavEvent::OperationComplete(format!(
                                "Copied '{}' -> '{}'",
                                from, to
                            )));
                            let parent = parent_path(&to);
                            if let Ok(entries) = webdav_ops::list_dir(&client, &parent).await {
                                let _ = event_tx.send(WebDavEvent::DirListed {
                                    path: parent,
                                    entries,
                                });
                            }
                        }
                        Err(e) => {
                            let _ =
                                event_tx.send(WebDavEvent::Error(format!("Copy failed: {}", e)));
                        }
                    }
                    let _ = tabs.request_render();
                }

                WebDavCommand::MoveItem { from, to } => {
                    match webdav_ops::move_item(&client, &from, &to).await {
                        Ok(()) => {
                            let _ = event_tx.send(WebDavEvent::OperationComplete(format!(
                                "Moved '{}' -> '{}'",
                                from, to
                            )));
                            let parent = parent_path(&to);
                            if let Ok(entries) = webdav_ops::list_dir(&client, &parent).await {
                                let _ = event_tx.send(WebDavEvent::DirListed {
                                    path: parent,
                                    entries,
                                });
                            }
                        }
                        Err(e) => {
                            let _ =
                                event_tx.send(WebDavEvent::Error(format!("Move failed: {}", e)));
                        }
                    }
                    let _ = tabs.request_render();
                }

                WebDavCommand::SyncExecute {
                    remote_path,
                    local_path,
                    options,
                } => {
                    let dry_run = options.dry_run;
                    match sync_ops::walk_remote_tree(&client, &remote_path).await {
                        Ok(remote_entries) => {
                            match sync_ops::walk_local_tree(&local_path) {
                                Ok(local_entries) => {
                                    let plan = sync_ops::compute_sync_plan(
                                        &remote_entries,
                                        &local_entries,
                                        &options,
                                    );
                                    if dry_run {
                                        let _ = event_tx.send(WebDavEvent::SyncPlanReady(plan));
                                    } else {
                                        let sync_ctx = SyncContext {
                                            event_tx: event_tx.clone(),
                                            cancel_flag: cancel_flag.clone(),
                                        };
                                        match sync_ops::execute_sync_plan(
                                            &client,
                                            &plan,
                                            &remote_path,
                                            &local_path,
                                            &sync_ctx,
                                        )
                                        .await
                                        {
                                            Ok(result) => {
                                                let _ = event_tx.send(WebDavEvent::SyncComplete {
                                                    downloaded: result.downloaded,
                                                    uploaded: result.uploaded,
                                                    deleted: result.deleted,
                                                });
                                                // Auto-refresh remote dir
                                                if let Ok(entries) =
                                                    webdav_ops::list_dir(&client, &remote_path)
                                                        .await
                                                {
                                                    let _ = event_tx.send(WebDavEvent::DirListed {
                                                        path: remote_path,
                                                        entries,
                                                    });
                                                }
                                            }
                                            Err(e) => {
                                                let _ = event_tx.send(WebDavEvent::Error(format!(
                                                    "Sync failed: {}",
                                                    e
                                                )));
                                            }
                                        }
                                    }
                                }
                                Err(e) => {
                                    let _ = event_tx.send(WebDavEvent::Error(format!(
                                        "Scan local failed: {}",
                                        e
                                    )));
                                }
                            }
                        }
                        Err(e) => {
                            let _ = event_tx
                                .send(WebDavEvent::Error(format!("Scan remote failed: {}", e)));
                        }
                    }
                    let _ = tabs.request_render();
                }

                WebDavCommand::CancelTransfer => {
                    cancel_flag.store(true, Ordering::Relaxed);
                    let _ = event_tx.send(WebDavEvent::TransferCancelled);
                    let _ = tabs.request_render();
                }
            }
        }
    }
}

fn tui_transfer_id(operation: &str) -> String {
    format!("webdav-tui-{operation}-{}", Utc::now().timestamp_micros())
}

/// Get the parent path for a WebDAV path.
/// e.g. "/a/b/c.txt" -> "/a/b", "/a/b/" -> "/a", "/a.txt" -> "/"
fn parent_path(path: &str) -> String {
    let trimmed = path.trim_end_matches('/');
    if let Some(pos) = trimmed.rfind('/') {
        if pos == 0 {
            "/".to_string()
        } else {
            trimmed[..pos].to_string()
        }
    } else {
        "/".to_string()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // === Send/Sync compile-time assertions ===

    fn assert_send<T: Send>() {}

    #[allow(dead_code)]
    fn assert_sync<T: Sync>() {}

    fn assert_send_sync<T: Send + Sync>() {}

    #[test]
    fn service_is_send() {
        assert_send::<WebDavService>();
    }

    #[test]
    fn command_is_send() {
        assert_send::<WebDavCommand>();
    }

    #[test]
    fn event_is_send() {
        assert_send::<WebDavEvent>();
    }

    #[test]
    fn mutex_service_is_send_sync() {
        assert_send_sync::<std::sync::Mutex<WebDavService>>();
    }

    #[test]
    fn parent_path_root_file() {
        assert_eq!(parent_path("/a.txt"), "/");
    }

    #[test]
    fn parent_path_nested() {
        assert_eq!(parent_path("/a/b/c.txt"), "/a/b");
    }

    #[test]
    fn parent_path_trailing_slash() {
        assert_eq!(parent_path("/a/b/"), "/a");
    }
}
