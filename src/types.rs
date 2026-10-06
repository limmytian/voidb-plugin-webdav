//! Shared types for WebDAV operations

use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Instant;

use chrono::{DateTime, Utc};
use voidb_core::AgentTransferEvent;

/// Secret-free result of probing one WebDAV target.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WebDavFeatureProbe {
    pub dav_classes: Vec<String>,
    pub allowed_methods: Vec<String>,
    pub accepts_byte_ranges: bool,
    pub supports_copy: bool,
    pub supports_move: bool,
    pub supports_locks: bool,
    pub supports_partial_upload: bool,
}

/// Explicit COPY/MOVE preconditions retained inside the service layer.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WebDavCopyMoveOptions {
    pub overwrite: bool,
    pub depth_infinity: bool,
    pub if_match: Option<String>,
    pub if_none_match: bool,
    pub lock_token: Option<String>,
}

/// Service-owned WebDAV lock. The token must never be projected directly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebDavLock {
    pub token: String,
    pub timeout_seconds: u64,
}

/// A remote WebDAV entry (file or directory)
#[derive(Debug, Clone)]
pub struct DavEntry {
    /// Display name
    pub name: String,
    /// Full href/path on the server
    pub href: String,
    /// Whether this is a file or directory
    pub entry_type: DavEntryType,
    /// File size in bytes (0 for directories)
    pub size: u64,
    /// Last modified time (ISO 8601 string)
    pub last_modified: Option<String>,
    /// MIME content type
    pub content_type: Option<String>,
    /// ETag header value
    pub etag: Option<String>,
}

/// Type of WebDAV entry
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DavEntryType {
    File,
    Directory,
}

/// Events sent from the background worker back to the UI
pub enum WebDavEvent {
    /// Shared redacted transfer lifecycle for CLI/TUI parity.
    TransferLifecycle(Box<AgentTransferEvent>),
    /// Directory listing completed
    DirListed {
        path: String,
        entries: Vec<DavEntry>,
    },
    /// File download progress
    DownloadProgress {
        remote: String,
        transferred: u64,
        total: u64,
    },
    /// File download completed
    DownloadComplete { remote: String, local: String },
    /// File upload progress
    UploadProgress {
        local: String,
        transferred: u64,
        total: u64,
    },
    /// File upload completed
    UploadComplete { local: String, remote: String },
    /// A mutation operation completed (with message)
    OperationComplete(String),
    /// An error occurred
    Error(String),
    /// Transfer was cancelled
    TransferCancelled,
    /// Sync plan computed (dry-run result)
    SyncPlanReady(SyncPlan),
    /// Sync progress update
    SyncProgress(SyncProgress),
    /// Sync completed
    SyncComplete {
        downloaded: usize,
        uploaded: usize,
        deleted: usize,
    },
}

impl WebDavEvent {
    /// Wrap a shared transfer event without inflating every service event.
    pub fn transfer_lifecycle(event: AgentTransferEvent) -> Self {
        Self::TransferLifecycle(Box::new(event))
    }
}

/// Tracks progress of an active file transfer
pub struct TransferProgress {
    /// Display filename
    pub filename: String,
    /// Bytes transferred so far
    pub transferred: u64,
    /// Total file size
    pub total: u64,
    /// When the transfer started
    pub started_at: Instant,
    /// Whether this is a download (true) or upload (false)
    pub is_download: bool,
}

impl TransferProgress {
    /// Calculate transfer speed in bytes per second
    pub fn speed_bps(&self) -> f64 {
        let elapsed = self.started_at.elapsed().as_secs_f64();
        if elapsed > 0.0 {
            self.transferred as f64 / elapsed
        } else {
            0.0
        }
    }

    /// Calculate estimated time remaining in seconds
    pub fn eta_secs(&self) -> Option<f64> {
        let speed = self.speed_bps();
        if speed > 0.0 && self.total > self.transferred {
            Some((self.total - self.transferred) as f64 / speed)
        } else {
            None
        }
    }

    /// Progress as a fraction 0.0..1.0
    pub fn fraction(&self) -> f64 {
        if self.total > 0 {
            (self.transferred as f64 / self.total as f64).min(1.0)
        } else {
            0.0
        }
    }
}

// ─── Sync types ───────────────────────────────────────────────────────────

/// Sync direction
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncMode {
    /// Remote → Local
    Pull,
    /// Local → Remote
    Push,
    /// Bidirectional (newer wins)
    Sync,
}

impl SyncMode {
    pub fn label(&self) -> &'static str {
        match self {
            SyncMode::Pull => "Pull (Remote \u{2192} Local)",
            SyncMode::Push => "Push (Local \u{2192} Remote)",
            SyncMode::Sync => "Sync (Bidirectional)",
        }
    }

    pub fn next(&self) -> SyncMode {
        match self {
            SyncMode::Pull => SyncMode::Push,
            SyncMode::Push => SyncMode::Sync,
            SyncMode::Sync => SyncMode::Pull,
        }
    }
}

/// Options controlling sync behavior
#[derive(Debug, Clone)]
pub struct SyncOptions {
    pub mode: SyncMode,
    /// Remove files not present in source
    pub delete_extra: bool,
    /// Preview only, no changes
    pub dry_run: bool,
    /// Glob patterns to exclude
    pub exclude: Vec<String>,
}

/// A unified entry for diff comparison (remote or local)
#[derive(Debug, Clone)]
pub struct SyncEntry {
    /// Relative path from sync root (forward slashes)
    pub rel_path: String,
    pub is_dir: bool,
    pub size: u64,
    pub mtime: Option<DateTime<Utc>>,
}

/// What kind of change is needed
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncAction {
    Download,
    Upload,
    DeleteLocal,
    DeleteRemote,
    Conflict,
}

impl SyncAction {
    pub fn icon(&self) -> &'static str {
        match self {
            SyncAction::Download => "\u{2193}",
            SyncAction::Upload => "\u{2191}",
            SyncAction::DeleteLocal => "\u{2715}",
            SyncAction::DeleteRemote => "\u{2715}",
            SyncAction::Conflict => "!",
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            SyncAction::Download => "NEW",
            SyncAction::Upload => "NEW",
            SyncAction::DeleteLocal => "DEL",
            SyncAction::DeleteRemote => "DEL",
            SyncAction::Conflict => "CONFLICT",
        }
    }
}

/// A single change in the sync plan
#[derive(Debug, Clone)]
pub struct SyncChange {
    pub rel_path: String,
    pub action: SyncAction,
    /// Bytes to transfer (0 for deletes)
    pub size: u64,
    pub is_dir: bool,
}

/// The complete diff result
pub struct SyncPlan {
    pub changes: Vec<SyncChange>,
    pub total_transfer_bytes: u64,
}

/// Counts returned after sync execution
pub struct SyncResult {
    pub downloaded: usize,
    pub uploaded: usize,
    pub deleted: usize,
}

/// Progress report during sync execution
pub struct SyncProgress {
    pub total_changes: usize,
    pub completed: usize,
    pub current_file: String,
    pub bytes_transferred: u64,
    pub total_bytes: u64,
}

/// Context needed by the sync worker to send progress and check cancellation
pub struct SyncContext {
    pub event_tx: tokio::sync::mpsc::UnboundedSender<WebDavEvent>,
    pub cancel_flag: Arc<AtomicBool>,
}
