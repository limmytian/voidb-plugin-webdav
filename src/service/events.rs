//! WebDAV service events.
//!
//! Events sent from the WebDAV background service task back to the UI layer.
//! Re-exports from `crate::types` since `SyncContext` also references `WebDavEvent`.

pub use crate::types::WebDavEvent;
