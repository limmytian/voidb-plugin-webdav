//! WebDAV service commands.
//!
//! Commands sent from the UI layer to the WebDAV background service task.

use crate::types::SyncOptions;

/// Commands sent from the UI to the background worker
pub enum WebDavCommand {
    /// Connect to WebDAV server (create client)
    Connect,
    /// Disconnect from WebDAV (stop the worker loop)
    Disconnect,
    /// List directory contents at the given path
    ListDir(String),
    /// Download a remote file to a local path
    DownloadFile { remote: String, local: String },
    /// Upload a local file to a remote directory
    UploadFile { local: String, remote_dir: String },
    /// Delete a remote file or directory
    DeleteItem(String),
    /// Rename/move a remote item
    Rename { old: String, new_name: String },
    /// Create a remote directory
    CreateDir(String),
    /// Copy a remote item
    CopyItem { from: String, to: String },
    /// Move a remote item
    MoveItem { from: String, to: String },
    /// Cancel all active transfers
    CancelTransfer,
    /// Compute or execute a sync plan
    SyncExecute {
        remote_path: String,
        local_path: String,
        options: SyncOptions,
    },
}
