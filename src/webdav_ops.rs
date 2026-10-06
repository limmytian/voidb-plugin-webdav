//! WebDAV operations wrapping reqwest_dav

use anyhow::{Context, Result};
use reqwest_dav::re_exports::reqwest::{Method, StatusCode, Url};
use reqwest_dav::{Auth, Client, ClientBuilder, Depth, list_cmd::ListEntity};

use crate::config::{WebDavAuth, WebDavConfig};
use crate::types::{DavEntry, DavEntryType, WebDavCopyMoveOptions, WebDavFeatureProbe, WebDavLock};

/// Create a reqwest_dav Client from our config
pub fn create_client(config: &WebDavConfig) -> Result<Client> {
    let auth = match &config.auth {
        WebDavAuth::None => Auth::Anonymous,
        WebDavAuth::Basic { username, password } => Auth::Basic(username.clone(), password.clone()),
        WebDavAuth::Digest { username, password } => {
            Auth::Digest(username.clone(), password.clone())
        }
    };

    let http_client = reqwest_dav::re_exports::reqwest::Client::builder()
        .danger_accept_invalid_certs(!config.verify_ssl)
        .timeout(std::time::Duration::from_secs(config.timeout))
        .build()
        .context("Failed to build HTTP client")?;

    ClientBuilder::new()
        .set_host(config.url.clone())
        .set_auth(auth)
        .set_agent(http_client)
        .build()
        .map_err(|e| anyhow::anyhow!("Failed to build WebDAV client: {:?}", e))
}

/// List directory contents
pub async fn list_dir(client: &Client, path: &str) -> Result<Vec<DavEntry>> {
    let entities = client
        .list(path, Depth::Number(1))
        .await
        .map_err(|e| anyhow::anyhow!("Failed to list directory: {:?}", e))?;

    let mut entries = Vec::new();
    for entity in entities {
        let entry = list_entity_to_dav_entry(&entity);
        // Skip the directory itself (parent entry)
        if entry.href.trim_end_matches('/') == path.trim_end_matches('/') {
            continue;
        }
        entries.push(entry);
    }

    // Sort: directories first, then alphabetical
    entries.sort_by(|a, b| match (&a.entry_type, &b.entry_type) {
        (DavEntryType::Directory, DavEntryType::File) => std::cmp::Ordering::Less,
        (DavEntryType::File, DavEntryType::Directory) => std::cmp::Ordering::Greater,
        _ => a.name.to_lowercase().cmp(&b.name.to_lowercase()),
    });

    Ok(entries)
}

/// Download a file and return its contents
pub async fn download(client: &Client, remote: &str) -> Result<Vec<u8>> {
    let response = client
        .get(remote)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to download file: {:?}", e))?;

    let bytes = response
        .bytes()
        .await
        .context("Failed to read response body")?;

    Ok(bytes.to_vec())
}

/// Download a byte range. A server that ignores a non-zero range fails closed.
pub async fn download_range(
    client: &Client,
    remote: &str,
    start: u64,
    end: Option<u64>,
) -> Result<(Vec<u8>, Option<u64>)> {
    let range = end
        .map(|end| format!("bytes={start}-{end}"))
        .unwrap_or_else(|| format!("bytes={start}-"));
    let response = client
        .start_request(Method::GET, remote)
        .await
        .map_err(|error| anyhow::anyhow!("Failed to build ranged GET: {error:?}"))?
        .header("range", range)
        .send()
        .await
        .context("Failed to send ranged GET")?;
    if start > 0 && response.status() != StatusCode::PARTIAL_CONTENT {
        anyhow::bail!(
            "Server did not honor byte-range resume (HTTP {})",
            response.status()
        );
    }
    if !response.status().is_success() {
        anyhow::bail!("Ranged GET failed with HTTP {}", response.status());
    }
    let total = response
        .headers()
        .get("content-range")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.rsplit_once('/'))
        .and_then(|(_, total)| total.parse::<u64>().ok())
        .or_else(|| {
            response
                .content_length()
                .map(|length| length.saturating_add(start))
        });
    let bytes = response
        .bytes()
        .await
        .context("Failed to read ranged GET body")?;
    Ok((bytes.to_vec(), total))
}

/// Upload data to a remote path
pub async fn upload(client: &Client, remote: &str, data: Vec<u8>) -> Result<()> {
    client
        .put(remote, data)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to upload file: {:?}", e))?;

    Ok(())
}

/// Check whether a resource exists without treating authorization, redirect,
/// or endpoint failures as absence.
pub async fn resource_exists(client: &Client, path: &str) -> Result<bool> {
    let response = client
        .start_request(Method::HEAD, path)
        .await
        .map_err(|error| anyhow::anyhow!("Failed to build HEAD request: {error:?}"))?
        .send()
        .await
        .context("Failed to send HEAD request")?;
    match response.status() {
        status if status.is_success() => Ok(true),
        StatusCode::NOT_FOUND => Ok(false),
        status => anyhow::bail!("Resource existence check returned HTTP {status}"),
    }
}

/// Create a directory
pub async fn mkdir(client: &Client, path: &str) -> Result<()> {
    client
        .mkcol(path)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to create directory: {:?}", e))?;

    Ok(())
}

/// Delete a file or directory
pub async fn delete(client: &Client, path: &str) -> Result<()> {
    client
        .delete(path)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to delete: {:?}", e))?;

    Ok(())
}

/// Move/rename a remote item
pub async fn move_item(client: &Client, from: &str, to: &str) -> Result<()> {
    client
        .mv(from, to)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to move: {:?}", e))?;

    Ok(())
}

/// Copy a remote item
pub async fn copy_item(client: &Client, from: &str, to: &str) -> Result<()> {
    client
        .cp(from, to)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to copy: {:?}", e))?;

    Ok(())
}

/// COPY with explicit Destination, Overwrite, Depth, ETag, and lock preconditions.
pub async fn copy_item_with_options(
    client: &Client,
    from: &str,
    to: &str,
    options: &WebDavCopyMoveOptions,
) -> Result<()> {
    copy_or_move(client, Method::from_bytes(b"COPY")?, from, to, options).await
}

/// MOVE with explicit Destination, Overwrite, ETag, and lock preconditions.
pub async fn move_item_with_options(
    client: &Client,
    from: &str,
    to: &str,
    options: &WebDavCopyMoveOptions,
) -> Result<()> {
    copy_or_move(client, Method::from_bytes(b"MOVE")?, from, to, options).await
}

async fn copy_or_move(
    client: &Client,
    method: Method,
    from: &str,
    to: &str,
    options: &WebDavCopyMoveOptions,
) -> Result<()> {
    let base = Url::parse(&client.host).context("Failed to parse WebDAV base URL")?;
    let destination = format!(
        "{}/{}",
        base.path().trim_end_matches('/'),
        to.trim_start_matches('/')
    );
    let mut request = client
        .start_request(method, from)
        .await
        .map_err(|error| anyhow::anyhow!("Failed to build WebDAV transfer request: {error:?}"))?
        .header("destination", destination)
        .header("overwrite", if options.overwrite { "T" } else { "F" });
    // RFC 4918 permits Depth on COPY, but some otherwise interoperable
    // servers reject an explicit `Depth: 0` for file copies. Omitting the
    // header preserves the server default; recursive callers opt into the
    // explicit infinity form.
    if options.depth_infinity {
        request = request.header("depth", "infinity");
    }
    if let Some(etag) = &options.if_match {
        request = request.header("if-match", etag);
    }
    if options.if_none_match {
        request = request.header("if-none-match", "*");
    }
    if let Some(token) = &options.lock_token {
        request = request.header("if", format!("(<{token}>)"));
    }
    let response = request
        .send()
        .await
        .context("Failed to send WebDAV COPY/MOVE")?;
    if !response.status().is_success() {
        anyhow::bail!("WebDAV COPY/MOVE failed with HTTP {}", response.status());
    }
    Ok(())
}

/// Probe advertised WebDAV methods and transfer behavior without mutating state.
pub async fn probe_features(client: &Client, path: &str) -> Result<WebDavFeatureProbe> {
    let response = client
        .start_request(Method::OPTIONS, path)
        .await
        .map_err(|error| anyhow::anyhow!("Failed to build OPTIONS request: {error:?}"))?
        .send()
        .await
        .context("Failed to send OPTIONS request")?;
    if !response.status().is_success() {
        anyhow::bail!("WebDAV OPTIONS failed with HTTP {}", response.status());
    }
    let split = |name: &str| {
        response
            .headers()
            .get(name)
            .and_then(|value| value.to_str().ok())
            .map(|value| {
                value
                    .split(',')
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .map(str::to_string)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default()
    };
    let dav_classes = split("dav");
    let allowed_methods = split("allow")
        .into_iter()
        .map(|method| method.to_ascii_uppercase())
        .collect::<Vec<_>>();
    let accepts_byte_ranges = response
        .headers()
        .get("accept-ranges")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.eq_ignore_ascii_case("bytes"));
    Ok(WebDavFeatureProbe {
        supports_copy: allowed_methods.iter().any(|method| method == "COPY"),
        supports_move: allowed_methods.iter().any(|method| method == "MOVE"),
        supports_locks: allowed_methods.iter().any(|method| method == "LOCK")
            && allowed_methods.iter().any(|method| method == "UNLOCK"),
        supports_partial_upload: allowed_methods
            .iter()
            .any(|method| matches!(method.as_str(), "PATCH" | "PUT-RANGE")),
        dav_classes,
        allowed_methods,
        accepts_byte_ranges,
    })
}

/// Acquire an exclusive write lock. The caller owns and must later release the token.
pub async fn lock(
    client: &Client,
    path: &str,
    timeout_seconds: u64,
    owner: &str,
) -> Result<WebDavLock> {
    let body = format!(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?><D:lockinfo xmlns:D=\"DAV:\"><D:lockscope><D:exclusive/></D:lockscope><D:locktype><D:write/></D:locktype><D:owner><D:href>{}</D:href></D:owner></D:lockinfo>",
        xml_escape(owner)
    );
    let response = client
        .start_request(Method::from_bytes(b"LOCK")?, path)
        .await
        .map_err(|error| anyhow::anyhow!("Failed to build LOCK request: {error:?}"))?
        .header("depth", "0")
        .header("timeout", format!("Second-{timeout_seconds}"))
        .header("content-type", "application/xml; charset=utf-8")
        .body(body)
        .send()
        .await
        .context("Failed to send LOCK request")?;
    if !response.status().is_success() {
        anyhow::bail!("WebDAV LOCK failed with HTTP {}", response.status());
    }
    let token = response
        .headers()
        .get("lock-token")
        .and_then(|value| value.to_str().ok())
        .map(|value| value.trim().trim_matches(['<', '>']).to_string())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow::anyhow!("WebDAV LOCK response omitted Lock-Token"))?;
    Ok(WebDavLock {
        token,
        timeout_seconds,
    })
}

/// Release a previously acquired lock.
pub async fn unlock(client: &Client, path: &str, token: &str) -> Result<()> {
    let response = client
        .start_request(Method::from_bytes(b"UNLOCK")?, path)
        .await
        .map_err(|error| anyhow::anyhow!("Failed to build UNLOCK request: {error:?}"))?
        .header("lock-token", format!("<{token}>"))
        .send()
        .await
        .context("Failed to send UNLOCK request")?;
    if !response.status().is_success() {
        anyhow::bail!("WebDAV UNLOCK failed with HTTP {}", response.status());
    }
    Ok(())
}

fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

/// Get properties of a single item (PROPFIND depth 0)
pub async fn get_properties(client: &Client, path: &str) -> Result<DavEntry> {
    let entities = client
        .list(path, Depth::Number(0))
        .await
        .map_err(|e| anyhow::anyhow!("Failed to get properties: {:?}", e))?;

    entities
        .first()
        .map(list_entity_to_dav_entry)
        .ok_or_else(|| anyhow::anyhow!("No properties returned for path: {}", path))
}

/// Convert a reqwest_dav ListEntity to our DavEntry type
fn list_entity_to_dav_entry(entity: &ListEntity) -> DavEntry {
    match entity {
        ListEntity::File(f) => {
            let name = extract_name_from_href(&f.href);
            DavEntry {
                name,
                href: f.href.clone(),
                entry_type: DavEntryType::File,
                size: f.content_length.max(0) as u64,
                last_modified: Some(f.last_modified.to_rfc3339()),
                content_type: Some(f.content_type.clone()),
                etag: f.tag.clone(),
            }
        }
        ListEntity::Folder(f) => {
            let name = extract_name_from_href(&f.href);
            DavEntry {
                name,
                href: f.href.clone(),
                entry_type: DavEntryType::Directory,
                size: 0,
                last_modified: Some(f.last_modified.to_rfc3339()),
                content_type: None,
                etag: f.tag.clone(),
            }
        }
    }
}

/// Extract the display name from a WebDAV href
/// e.g., "/remote.php/webdav/documents/" -> "documents"
fn extract_name_from_href(href: &str) -> String {
    let trimmed = href.trim_end_matches('/');
    trimmed.rsplit('/').next().unwrap_or(trimmed).to_string()
}
