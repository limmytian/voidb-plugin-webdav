//! WebDAV file management plugin for VoidB

mod agent_session;
mod capabilities;
mod cli_plugin;
pub mod config;
pub mod service;
pub mod sync_ops;
mod transfer_contract;
mod tui;
pub mod types;
pub mod webdav_ops;

pub use agent_session::WebDavAgentSessionFactory;
pub use capabilities::{invoke_webdav_capability, webdav_capabilities};
pub use config::{WebDavAuth, WebDavConfig};
pub use cli_plugin::create_webdav_cli_plugin;
pub use transfer_contract::webdav_transfer_contract;

/// Test a WebDAV connection from a ConnectionConfig
pub async fn test_connection(
    conn: &voidb_core::connection::ConnectionConfig,
) -> anyhow::Result<String> {
    let config: config::WebDavConfig = conn
        .plugin_config
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("Missing plugin_config"))
        .and_then(|v| serde_json::from_value(v.clone()).map_err(Into::into))?;

    let client = webdav_ops::create_client(&config)?;
    let entries = webdav_ops::list_dir(&client, "/").await?;

    Ok(format!(
        "WebDAV connection successful: {} ({} entries in root)",
        config.url,
        entries.len()
    ))
}
