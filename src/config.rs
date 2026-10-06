//! WebDAV connection configuration

use serde::{Deserialize, Serialize};

fn default_timeout() -> u64 {
    30
}

fn default_true() -> bool {
    true
}

/// WebDAV server connection configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebDavConfig {
    /// WebDAV server URL (e.g. https://dav.example.com/remote.php/webdav/)
    pub url: String,

    /// Authentication method
    pub auth: WebDavAuth,

    /// Connection timeout in seconds
    #[serde(default = "default_timeout")]
    pub timeout: u64,

    /// Whether to verify TLS certificates
    #[serde(default = "default_true")]
    pub verify_ssl: bool,
}

/// WebDAV authentication method
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum WebDavAuth {
    /// No authentication
    None,
    /// HTTP Basic authentication
    Basic { username: String, password: String },
    /// HTTP Digest authentication
    Digest { username: String, password: String },
}

impl Default for WebDavConfig {
    fn default() -> Self {
        Self {
            url: String::new(),
            auth: WebDavAuth::None,
            timeout: 30,
            verify_ssl: true,
        }
    }
}
