//! Live WebDAV reliability proof for Agent transfers.
//!
//! The script-facing example stays inside the generated fixture collection.
//! It proves conflict safety, checksum failure, bounded range cancellation and
//! resume, plus provider-aware lock behavior and close-time lock cleanup.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration as StdDuration;

use anyhow::{Context, Result, bail, ensure};
use chrono::{Duration, Utc};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::time::sleep;
use voidb_core::{
    AgentSessionBinding, AgentSessionCallRequest, AgentSessionOpenContext, AgentSessionOpenRequest,
    AgentSessionRef, PluginAgentSession, PluginAgentSessionFactory, PluginSessionError,
    PluginSessionErrorCode, PluginSessionPurpose,
};
use voidb_plugin_webdav::{
    WebDavAgentSessionFactory,
    config::{WebDavAuth, WebDavConfig},
    service::WebDavService,
    types::WebDavCopyMoveOptions,
};

const CHUNK_BYTES: usize = 64 * 1024;
const PAYLOAD_BYTES: usize = 32 * 1024 * 1024;

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> Result<()> {
    let config = config_from_env()?;
    let fixture_root = required_env("VOIDB_WEBDAV_SMOKE_ROOT")?;
    ensure!(
        fixture_root.starts_with("/voidb-smoke/"),
        "refusing WebDAV reliability proof outside a generated fixture root"
    );
    let run_id = std::env::var("VOIDB_FIXTURE_RUN_ID")
        .unwrap_or_else(|_| "webdav-transfer-reliability".into());
    let local_root = prepare_local_root(&run_id)?;
    let payload = deterministic_payload(PAYLOAD_BYTES);
    let checksum = hex::encode(Sha256::digest(&payload));
    std::fs::write(local_root.join("payload.bin"), &payload)
        .with_context(|| format!("write {}", local_root.display()))?;

    let service = WebDavService::new_direct(&config)?;
    let remote_root = join_remote(&fixture_root, "reliability");
    let source = join_remote(&remote_root, "source.bin");
    let destination = join_remote(&remote_root, "destination.bin");
    let moved = join_remote(&remote_root, "moved.bin");
    let payload_path = join_remote(&remote_root, "payload.bin");
    let mismatch_path = join_remote(&remote_root, "checksum-mismatch.bin");
    service.mkdir(&remote_root).await?;
    service.upload(&source, b"source".to_vec()).await?;
    service
        .upload(&destination, b"destination-sentinel".to_vec())
        .await?;

    let conflict_options = WebDavCopyMoveOptions {
        overwrite: false,
        ..Default::default()
    };
    service
        .copy_item_with_options(&source, &destination, &conflict_options)
        .await
        .expect_err("COPY without replacement must reject an existing destination");
    ensure!(
        service.download(&destination).await? == b"destination-sentinel",
        "COPY conflict changed the destination"
    );
    let replace_options = WebDavCopyMoveOptions {
        overwrite: true,
        ..Default::default()
    };
    service
        .copy_item_with_options(&source, &destination, &replace_options)
        .await?;
    service
        .move_item_with_options(&destination, &moved, &conflict_options)
        .await?;
    ensure!(
        !service.resource_exists(&destination).await?,
        "verified MOVE retained its source"
    );
    ensure!(
        service.download(&moved).await? == b"source",
        "verified MOVE changed bytes"
    );
    service.upload(&payload_path, payload.clone()).await?;

    let probe = service.probe_features(&payload_path).await?;
    ensure!(
        probe.supports_copy && probe.supports_move,
        "fixture must advertise COPY and MOVE"
    );

    let mismatch_session = open_session(&config, "checksum-mismatch").await?;
    let mismatch = call_capability(
        mismatch_session.as_ref(),
        "webdav.transfer",
        "webdav-checksum-mismatch",
        json!({
            "operation": "upload",
            "path": mismatch_path,
            "local_root": path_string(&local_root)?,
            "local_path": "payload.bin",
            "expected_sha256": "0".repeat(64),
            "chunk_bytes": CHUNK_BYTES,
        }),
        true,
    )
    .await
    .expect_err("checksum mismatch must fail before remote mutation");
    ensure!(mismatch.code == PluginSessionErrorCode::HealthFailed);
    ensure!(
        !service.resource_exists(&mismatch_path).await?,
        "checksum mismatch created a remote resource"
    );
    mismatch_session
        .close("checksum proof complete".into())
        .await?;

    if probe.accepts_byte_ranges {
        prove_cancel_and_resume(&config, &payload_path, &local_root, &payload, &checksum).await?;
    } else {
        prove_non_resumable_download(&config, &payload_path, &local_root, &payload, &checksum)
            .await?;
    }
    prove_lock_behavior(&config, &source, probe.supports_locks).await?;

    for path in [mismatch_path, payload_path, moved, source] {
        if service.resource_exists(&path).await.unwrap_or(false) {
            let _ = service.delete(&path).await;
        }
    }
    let _ = service.delete(&remote_root).await;
    std::fs::remove_dir_all(&local_root)
        .with_context(|| format!("remove {}", local_root.display()))?;

    println!("webdav transfer reliability fixture passed");
    println!(
        "coverage: conflict, verified move, checksum mismatch, range capability, cancel/resume or fail-closed degradation, lock ownership or unsupported degradation"
    );
    println!(
        "provider quirks: accepts_byte_ranges={} supports_locks={} supports_partial_upload={}",
        probe.accepts_byte_ranges, probe.supports_locks, probe.supports_partial_upload
    );
    Ok(())
}

async fn prove_cancel_and_resume(
    config: &WebDavConfig,
    remote: &str,
    local_root: &Path,
    payload: &[u8],
    checksum: &str,
) -> Result<()> {
    let session = open_session(config, "range-resume").await?;
    let remote = remote.to_string();
    let task_session = session.clone();
    let task_remote = remote.clone();
    let local_root_text = path_string(local_root)?;
    let checksum_text = checksum.to_string();
    let task = tokio::spawn(async move {
        call_capability(
            task_session.as_ref(),
            "webdav.transfer",
            "webdav-range-cancel",
            json!({
                "operation": "download",
                "path": task_remote,
                "local_root": local_root_text,
                "local_path": "resumed.bin",
                "expected_sha256": checksum_text,
                "chunk_bytes": CHUNK_BYTES,
            }),
            true,
        )
        .await
    });

    let mut cancelled = false;
    for sequence in 0..2_000 {
        let status = call_status(session.as_ref(), &format!("webdav-status-{sequence}")).await?;
        if status["event"]["progress"]["chunks_completed"]
            .as_u64()
            .unwrap_or_default()
            >= 1
        {
            session.cancel("webdav-range-cancel").await?;
            cancelled = true;
            break;
        }
        if status["event"]["phase"] == "completed" {
            bail!("ranged download completed before cancellation checkpoint");
        }
        sleep(StdDuration::from_millis(2)).await;
    }
    ensure!(
        cancelled,
        "ranged download never reached a cancellable checkpoint"
    );
    let cancelled_error = task
        .await
        .context("join WebDAV cancellation")?
        .expect_err("cancelled range call should return a structured error");
    ensure!(cancelled_error.code == PluginSessionErrorCode::Cancelled);
    let cancelled_status = call_status(session.as_ref(), "webdav-status-cancelled").await?;
    ensure!(
        cancelled_status["event"]["phase"] == "cancelled"
            && cancelled_status["event"]["cleanup"]["remote_partial"] == "retained_for_resume",
        "cancelled range should retain a scoped checkpoint: {cancelled_status}"
    );
    ensure!(
        !local_root.join("resumed.bin").exists(),
        "cancelled download committed a local destination"
    );
    let resume_token = cancelled_status["event"]["checkpoint"]["token"]
        .as_str()
        .context("cancelled range should expose a resume token")?;
    let resumed = call_capability(
        session.as_ref(),
        "webdav.transfer",
        "webdav-range-resume",
        json!({
            "operation": "download",
            "path": remote,
            "resume_token": resume_token,
            "expected_sha256": checksum,
            "chunk_bytes": CHUNK_BYTES,
        }),
        true,
    )
    .await?;
    ensure!(
        resumed["event"]["phase"] == "completed"
            && resumed["event"]["checksum"]["algorithm"] == "sha256"
            && resumed["event"]["checksum"]["verified"] == true,
        "resumed range should complete with verified SHA-256: {resumed}"
    );
    ensure!(
        std::fs::read(local_root.join("resumed.bin"))? == payload,
        "resumed range changed bytes"
    );
    session.close("range resume proof complete".into()).await?;
    Ok(())
}

async fn prove_non_resumable_download(
    config: &WebDavConfig,
    remote: &str,
    local_root: &Path,
    payload: &[u8],
    checksum: &str,
) -> Result<()> {
    let session = open_session(config, "non-resumable").await?;
    let completed = call_capability(
        session.as_ref(),
        "webdav.transfer",
        "webdav-non-resumable-download",
        json!({
            "operation": "download",
            "path": remote,
            "local_root": path_string(local_root)?,
            "local_path": "non-resumable.bin",
            "expected_sha256": checksum,
            "chunk_bytes": CHUNK_BYTES,
        }),
        true,
    )
    .await?;
    ensure!(
        completed["event"]["phase"] == "completed"
            && completed["event"]["checksum"]["verified"] == true,
        "non-resumable target should still verify a whole transfer: {completed}"
    );
    ensure!(
        std::fs::read(local_root.join("non-resumable.bin"))? == payload,
        "non-resumable whole download changed bytes"
    );
    let unsupported = call_capability(
        session.as_ref(),
        "webdav.transfer",
        "webdav-stale-resume",
        json!({
            "operation": "download",
            "path": remote,
            "resume_token": "webdav-resume-provider-unsupported",
            "expected_sha256": checksum,
            "chunk_bytes": CHUNK_BYTES,
        }),
        true,
    )
    .await
    .expect_err("unadvertised range resume must fail closed");
    ensure!(unsupported.code == PluginSessionErrorCode::Unsupported);
    session
        .close("provider degradation proof complete".into())
        .await?;
    Ok(())
}

async fn prove_lock_behavior(
    config: &WebDavConfig,
    path: &str,
    supports_locks: bool,
) -> Result<()> {
    let owner = open_session(config, "lock-owner").await?;
    if !supports_locks {
        let unsupported = call_capability(
            owner.as_ref(),
            "webdav.lock_acquire",
            "webdav-lock-unsupported",
            json!({ "path": path, "timeout_seconds": 30 }),
            false,
        )
        .await
        .expect_err("unadvertised locks must fail closed");
        ensure!(unsupported.code == PluginSessionErrorCode::Unsupported);
        owner
            .close("unsupported lock proof complete".into())
            .await?;
        return Ok(());
    }

    let acquired = call_capability(
        owner.as_ref(),
        "webdav.lock_acquire",
        "webdav-lock-acquire",
        json!({ "path": path, "timeout_seconds": 30 }),
        false,
    )
    .await?;
    let lock_ref = acquired["lock_ref"]
        .as_str()
        .context("lock acquisition should return an opaque reference")?;
    ensure!(
        !acquired
            .to_string()
            .to_ascii_lowercase()
            .contains("opaquelocktoken"),
        "lock response exposed a target token"
    );

    let stranger = open_session(config, "lock-stranger").await?;
    let stale = call_capability(
        stranger.as_ref(),
        "webdav.lock_release",
        "webdav-lock-stale",
        json!({ "lock_ref": lock_ref }),
        false,
    )
    .await
    .expect_err("another session must not release an owned lock reference");
    ensure!(stale.code == PluginSessionErrorCode::BindingMismatch);
    stranger.close("stale lock proof complete".into()).await?;

    owner
        .close("close must release retained lock".into())
        .await?;
    let successor = open_session(config, "lock-successor").await?;
    let reacquired = call_capability(
        successor.as_ref(),
        "webdav.lock_acquire",
        "webdav-lock-reacquire",
        json!({ "path": path, "timeout_seconds": 30 }),
        false,
    )
    .await?;
    call_capability(
        successor.as_ref(),
        "webdav.lock_release",
        "webdav-lock-release",
        json!({ "lock_ref": reacquired["lock_ref"] }),
        false,
    )
    .await?;
    successor
        .close("lock cleanup proof complete".into())
        .await?;
    Ok(())
}

async fn open_session(config: &WebDavConfig, label: &str) -> Result<Arc<dyn PluginAgentSession>> {
    WebDavAgentSessionFactory::new(config.clone())
        .open(session_context(label))
        .await
        .map_err(|error| anyhow::anyhow!("open WebDAV transfer session: {error}"))
}

fn session_context(label: &str) -> AgentSessionOpenContext {
    let purpose = PluginSessionPurpose::FileTransfer;
    let capabilities = vec![
        "webdav.transfer".into(),
        "webdav.transfer_status".into(),
        "webdav.lock_acquire".into(),
        "webdav.lock_release".into(),
    ];
    AgentSessionOpenContext {
        binding: AgentSessionBinding {
            grant_id: format!("webdav-fixture-{label}-grant"),
            profile_id: "webdav-fixture-profile".into(),
            plugin_id: "webdav".into(),
            purpose: purpose.clone(),
            allowed_capabilities: capabilities.clone(),
            host_generation: 1,
        },
        request: AgentSessionOpenRequest {
            purpose,
            capabilities,
            lease_seconds: 300,
            concurrency: Default::default(),
            destructive_acknowledged: true,
            input: Value::Null,
        },
        lease_expires_at: Utc::now() + Duration::minutes(5),
    }
}

async fn call_capability(
    session: &dyn PluginAgentSession,
    capability: &str,
    call_id: &str,
    input: Value,
    destructive_acknowledged: bool,
) -> std::result::Result<Value, PluginSessionError> {
    session
        .call(AgentSessionCallRequest {
            session: AgentSessionRef::new("webdav-reliability-session", 1),
            call_id: call_id.into(),
            capability: capability.into(),
            input,
            destructive_acknowledged,
            timeout_ms: Some(180_000),
            output_limit_bytes: 128 * 1024,
        })
        .await
        .map(|result| result.output)
}

async fn call_status(session: &dyn PluginAgentSession, call_id: &str) -> Result<Value> {
    call_capability(session, "webdav.transfer_status", call_id, json!({}), false)
        .await
        .map_err(|error| anyhow::anyhow!("read WebDAV transfer status: {error}"))
}

fn deterministic_payload(length: usize) -> Vec<u8> {
    (0..length)
        .map(|index| ((index.wrapping_mul(29).wrapping_add(11)) % 251) as u8)
        .collect()
}

fn prepare_local_root(run_id: &str) -> Result<PathBuf> {
    let root = std::env::temp_dir().join(format!("voidb-webdav-transfer-reliability-{run_id}"));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir(&root).with_context(|| format!("create {}", root.display()))?;
    Ok(root)
}

fn path_string(path: &Path) -> Result<String> {
    path.to_str()
        .map(str::to_string)
        .context("fixture path must be valid UTF-8")
}

fn join_remote(base: &str, child: &str) -> String {
    format!(
        "{}/{}",
        base.trim_end_matches('/'),
        child.trim_start_matches('/')
    )
}

fn config_from_env() -> Result<WebDavConfig> {
    let auth = match required_env("VOIDB_WEBDAV_SMOKE_AUTH")?.as_str() {
        "basic" => WebDavAuth::Basic {
            username: required_env("VOIDB_WEBDAV_SMOKE_USER")?,
            password: required_env("VOIDB_WEBDAV_SMOKE_PASSWORD")?,
        },
        "none" => WebDavAuth::None,
        other => bail!("unsupported fixture WebDAV auth: {other}"),
    };
    Ok(WebDavConfig {
        url: required_env("VOIDB_WEBDAV_SMOKE_URL")?,
        auth,
        timeout: 30,
        verify_ssl: required_env("VOIDB_WEBDAV_SMOKE_VERIFY_SSL")? == "true",
    })
}

fn required_env(name: &str) -> Result<String> {
    std::env::var(name).with_context(|| format!("{name} is required"))
}
