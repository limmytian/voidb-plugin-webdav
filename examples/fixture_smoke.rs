//! WebDAV fixture-backed capability smoke driver.
//!
//! This example is script-facing. It exercises the WebDAV plugin capability
//! surface against a disposable local WebDAV fixture using only the generated
//! scratch collection from the fixture environment.

#![allow(clippy::result_large_err)]

use anyhow::{Context, Result, bail, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use chrono::Utc;
use serde_json::{Value, json};
use std::path::PathBuf;
use voidb_core::{
    ActorRef, ActorType, CapabilityError, CapabilityErrorCategory, CapabilityInvocation,
    CapabilityInvocationResult, InvocationConnectionTarget, InvocationControls, InvocationStatus,
    Pagination, RedactionStatus,
};
use voidb_plugin_webdav::{
    config::{WebDavAuth, WebDavConfig},
    invoke_webdav_capability,
};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let config = config_from_env()?;
    let root = required_env("VOIDB_WEBDAV_SMOKE_ROOT")?;
    let seed_path = required_env("VOIDB_WEBDAV_SMOKE_SEED_PATH")?;
    ensure!(
        root.starts_with("/voidb-smoke/"),
        "refusing WebDAV smoke outside a generated fixture root: {root}"
    );
    ensure!(
        seed_path.starts_with(&format!("{}/", root.trim_end_matches('/'))),
        "refusing WebDAV smoke outside the generated fixture root: {seed_path}"
    );

    let run_id =
        std::env::var("VOIDB_FIXTURE_RUN_ID").unwrap_or_else(|_| "webdav-fixture-smoke".into());
    let run_dir = join_remote(&root, "run");
    let nested_dir = join_remote(&run_dir, "nested");
    let alpha_path = join_remote(&run_dir, "alpha.txt");
    let beta_path = join_remote(&run_dir, "beta.txt");
    let nested_path = join_remote(&nested_dir, "gamma.txt");
    let delete_path = join_remote(&run_dir, "delete-me.txt");
    let missing_path = join_remote(&run_dir, "missing-after-delete.txt");
    let alpha_content = format!("VoidB WebDAV fixture smoke alpha payload for {run_id}");
    let beta_content = format!("VoidB WebDAV fixture smoke beta payload for {run_id}");
    let secret_content = "voidb-webdav-fixture-dry-run-secret";

    let dry_put = invoke_checked(
        &unavailable_config(),
        "put",
        json!({
            "path": alpha_path,
            "content_text": secret_content
        }),
        true,
        None,
        "webdav.put dry-run should not require a live target",
    )
    .await?;
    ensure_succeeded(&dry_put, "webdav.put dry-run")?;
    ensure!(
        dry_put.output["details"]["bytes"].as_u64() == Some(secret_content.len() as u64),
        "webdav.put dry-run should report byte count: {}",
        dry_put.output
    );
    ensure_result_excludes(&dry_put, secret_content, "webdav.put dry-run")?;

    let dry_delete = invoke_checked(
        &unavailable_config(),
        "delete",
        json!({ "path": delete_path }),
        true,
        None,
        "webdav.delete dry-run should not require a live target",
    )
    .await?;
    ensure_succeeded(&dry_delete, "webdav.delete dry-run")?;

    let dry_mkdir = invoke_checked(
        &unavailable_config(),
        "mkdir",
        json!({ "path": run_dir }),
        true,
        None,
        "webdav.mkdir dry-run should not require a live target",
    )
    .await?;
    ensure_succeeded(&dry_mkdir, "webdav.mkdir dry-run")?;

    let root_list = invoke_checked(
        &config,
        "list",
        json!({ "path": root }),
        false,
        Some(Pagination {
            limit: 20,
            cursor: None,
        }),
        "webdav.list fixture root",
    )
    .await?;
    ensure_succeeded(&root_list, "webdav.list fixture root")?;
    ensure_entry_present(&root_list.output, &seed_path)?;

    let seed_stat = invoke_checked(
        &config,
        "stat",
        json!({ "path": seed_path }),
        false,
        None,
        "webdav.stat seed file",
    )
    .await?;
    ensure_succeeded(&seed_stat, "webdav.stat seed file")?;

    let seed_get = invoke_checked(
        &config,
        "get",
        json!({ "path": seed_path, "max_bytes": 8 }),
        false,
        None,
        "webdav.get seed truncated",
    )
    .await?;
    ensure_succeeded(&seed_get, "webdav.get seed truncated")?;
    ensure!(
        seed_get.output["content_truncated"] == true && seed_get.output["bytes_returned"] == 8,
        "webdav.get should enforce max_bytes: {}",
        seed_get.output
    );

    invoke_checked(
        &config,
        "mkdir",
        json!({ "path": run_dir }),
        false,
        None,
        "webdav.mkdir run directory",
    )
    .await?;
    invoke_checked(
        &config,
        "mkdir",
        json!({ "path": nested_dir }),
        false,
        None,
        "webdav.mkdir nested directory",
    )
    .await?;

    for (path, content) in [
        (alpha_path.as_str(), alpha_content.as_str()),
        (beta_path.as_str(), beta_content.as_str()),
        (nested_path.as_str(), "nested fixture payload"),
        (delete_path.as_str(), "delete fixture payload"),
    ] {
        let result = invoke_checked(
            &config,
            "put",
            json!({ "path": path, "content_text": content }),
            false,
            None,
            "webdav.put fixture file",
        )
        .await?;
        ensure_succeeded(&result, "webdav.put fixture file")?;
        ensure_result_excludes_config(&result, &config, "webdav.put fixture file")?;
    }

    let paged = invoke_checked(
        &config,
        "list",
        json!({ "path": run_dir }),
        false,
        Some(Pagination {
            limit: 1,
            cursor: None,
        }),
        "webdav.list paged run directory",
    )
    .await?;
    ensure_succeeded(&paged, "webdav.list paged")?;
    ensure!(
        paged.output["entry_count"].as_u64().unwrap_or_default() <= 1
            && paged.output["truncated"] == true
            && paged.output["next_cursor"].is_string(),
        "webdav.list should honor pagination: {}",
        paged.output
    );

    let full_list = invoke_checked(
        &config,
        "list",
        json!({ "path": run_dir }),
        false,
        Some(Pagination {
            limit: 20,
            cursor: None,
        }),
        "webdav.list full run directory",
    )
    .await?;
    ensure_succeeded(&full_list, "webdav.list full")?;
    ensure_entry_present(&full_list.output, &alpha_path)?;
    ensure_entry_present(&full_list.output, &beta_path)?;
    ensure_entry_present(&full_list.output, &delete_path)?;
    ensure_entry_present(&full_list.output, &nested_dir)?;

    let stat = invoke_checked(
        &config,
        "stat",
        json!({ "path": alpha_path }),
        false,
        None,
        "webdav.stat alpha file",
    )
    .await?;
    ensure_succeeded(&stat, "webdav.stat alpha")?;
    ensure!(
        stat.output["entry"]["size"].as_u64() == Some(alpha_content.len() as u64),
        "webdav.stat should return alpha file size: {}",
        stat.output
    );

    let full_get = invoke_checked(
        &config,
        "get",
        json!({ "path": beta_path }),
        false,
        None,
        "webdav.get beta file",
    )
    .await?;
    ensure_succeeded(&full_get, "webdav.get beta")?;
    let decoded = decode_content(&full_get)?;
    ensure!(
        decoded == beta_content.as_bytes(),
        "webdav.get should return beta file bytes"
    );
    ensure_result_excludes_config(&full_get, &config, "webdav.get beta")?;

    let sync_dir = prepare_sync_dir(&run_id)?;
    let sync_plan = invoke_checked(
        &config,
        "sync_plan",
        json!({
            "remote_path": run_dir,
            "local_root": &sync_dir,
            "local_path": ".",
            "mode": "sync",
            "delete_extra": false
        }),
        false,
        None,
        "webdav.sync_plan dry-run",
    )
    .await?;
    ensure_succeeded(&sync_plan, "webdav.sync_plan")?;
    ensure!(
        sync_plan.output["target"] == "webdav" && sync_plan.output["change_count"].is_number(),
        "webdav.sync_plan should return a dry-run plan: {}",
        sync_plan.output
    );

    let dry_delete_live = invoke_checked(
        &config,
        "delete",
        json!({ "path": delete_path }),
        true,
        None,
        "webdav.delete live dry-run",
    )
    .await?;
    ensure_succeeded(&dry_delete_live, "webdav.delete live dry-run")?;
    invoke_checked(
        &config,
        "stat",
        json!({ "path": delete_path }),
        false,
        None,
        "webdav.stat delete file after dry-run",
    )
    .await?;

    invoke_checked(
        &config,
        "delete",
        json!({ "path": delete_path }),
        false,
        None,
        "webdav.delete fixture file",
    )
    .await?;
    ensure_missing_path_error(
        invoke(&config, "get", json!({ "path": delete_path }), false, None).await,
        &config,
        "webdav.get deleted file",
    )?;
    ensure_missing_path_error(
        invoke(&config, "get", json!({ "path": missing_path }), false, None).await,
        &config,
        "webdav.get missing file",
    )?;

    ensure_failed_auth_redacts(&config, &root).await?;
    cleanup_paths(
        &config,
        [
            nested_path.as_str(),
            nested_dir.as_str(),
            alpha_path.as_str(),
            beta_path.as_str(),
            run_dir.as_str(),
        ],
    )
    .await;
    let _ = std::fs::remove_dir_all(&sync_dir);

    println!("webdav fixture capability smoke passed");
    println!("capabilities: list, stat, get, put, delete, mkdir, sync_plan");
    println!("scratch_root: {root}");
    Ok(())
}

fn config_from_env() -> Result<WebDavConfig> {
    let auth = match required_env("VOIDB_WEBDAV_SMOKE_AUTH")?.as_str() {
        "none" => WebDavAuth::None,
        "basic" => WebDavAuth::Basic {
            username: required_env("VOIDB_WEBDAV_SMOKE_USER")?,
            password: required_env("VOIDB_WEBDAV_SMOKE_PASSWORD")?,
        },
        "digest" => WebDavAuth::Digest {
            username: required_env("VOIDB_WEBDAV_SMOKE_USER")?,
            password: required_env("VOIDB_WEBDAV_SMOKE_PASSWORD")?,
        },
        other => bail!("unsupported WebDAV fixture auth mode: {other}"),
    };

    Ok(WebDavConfig {
        url: required_env("VOIDB_WEBDAV_SMOKE_URL")?,
        auth,
        timeout: 30,
        verify_ssl: required_env("VOIDB_WEBDAV_SMOKE_VERIFY_SSL")?.parse()?,
    })
}

fn unavailable_config() -> WebDavConfig {
    WebDavConfig {
        url: "http://127.0.0.1:0".into(),
        auth: WebDavAuth::None,
        timeout: 1,
        verify_ssl: false,
    }
}

fn required_env(name: &str) -> Result<String> {
    std::env::var(name).with_context(|| format!("{name} is required"))
}

fn join_remote(base: &str, child: &str) -> String {
    format!(
        "{}/{}",
        base.trim_end_matches('/'),
        child.trim_start_matches('/')
    )
}

async fn invoke(
    config: &WebDavConfig,
    capability_id: &str,
    input: Value,
    dry_run: bool,
    page: Option<Pagination>,
) -> std::result::Result<CapabilityInvocationResult, CapabilityError> {
    invoke_webdav_capability(
        config,
        CapabilityInvocation {
            id: format!("webdav-fixture-smoke-{capability_id}"),
            plugin_id: "webdav".into(),
            capability_id: capability_id.into(),
            connection: InvocationConnectionTarget::Stateless,
            input,
            controls: InvocationControls {
                dry_run,
                page,
                ..InvocationControls::default()
            },
            actor: Some(ActorRef {
                id: "agent:webdav-fixture-smoke".into(),
                actor_type: ActorType::Agent,
            }),
            requested_at: Utc::now(),
        },
    )
    .await
}

async fn invoke_checked(
    config: &WebDavConfig,
    capability_id: &str,
    input: Value,
    dry_run: bool,
    page: Option<Pagination>,
    label: &str,
) -> Result<CapabilityInvocationResult> {
    invoke(config, capability_id, input, dry_run, page)
        .await
        .map_err(|error| {
            let error_json = serde_json::to_string(&error).unwrap_or_else(|_| format!("{error:?}"));
            anyhow::anyhow!("{label}: {error_json}")
        })
}

fn ensure_succeeded(result: &CapabilityInvocationResult, label: &str) -> Result<()> {
    ensure!(
        result.status == InvocationStatus::Succeeded,
        "{label} returned non-success status: {:?}",
        result.status
    );
    Ok(())
}

fn ensure_result_excludes(
    result: &CapabilityInvocationResult,
    sample: &str,
    label: &str,
) -> Result<()> {
    let output = serde_json::to_string(&result.output)?;
    let summary = serde_json::to_string(&result.output_summary)?;
    ensure!(
        !output.contains(sample) && !summary.contains(sample),
        "{label} output exposed protected sample"
    );
    Ok(())
}

fn ensure_result_excludes_config(
    result: &CapabilityInvocationResult,
    config: &WebDavConfig,
    label: &str,
) -> Result<()> {
    let output = serde_json::to_string(&result.output)?;
    let summary = serde_json::to_string(&result.output_summary)?;
    for sample in protected_samples(config) {
        ensure!(
            !output.contains(&sample) && !summary.contains(&sample),
            "{label} output exposed WebDAV config material"
        );
    }
    Ok(())
}

fn protected_samples(config: &WebDavConfig) -> Vec<String> {
    let mut samples = vec![config.url.clone()];
    match &config.auth {
        WebDavAuth::None => {}
        WebDavAuth::Basic { username, password } | WebDavAuth::Digest { username, password } => {
            samples.push(username.clone());
            samples.push(password.clone());
        }
    }
    samples
        .into_iter()
        .filter(|sample| !sample.is_empty())
        .collect()
}

fn ensure_entry_present(output: &Value, path: &str) -> Result<()> {
    let entries = output["entries"]
        .as_array()
        .context("webdav.list output should include entries array")?;
    let expected = path.trim_end_matches('/');
    ensure!(
        entries.iter().any(|item| {
            item["href"]
                .as_str()
                .map(|href| href.trim_end_matches('/').ends_with(expected))
                .unwrap_or(false)
        }),
        "webdav.list did not include expected path {path}: {}",
        output
    );
    Ok(())
}

fn decode_content(result: &CapabilityInvocationResult) -> Result<Vec<u8>> {
    let encoded = result.output["content_base64"]
        .as_str()
        .context("webdav.get output should include content_base64")?;
    BASE64.decode(encoded).context("decode webdav.get content")
}

fn prepare_sync_dir(run_id: &str) -> Result<String> {
    let dir = std::env::temp_dir().join(format!("voidb-webdav-fixture-sync-{run_id}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;
    std::fs::write(dir.join("local-only.txt"), b"local fixture sync payload")
        .with_context(|| format!("write {}", dir.display()))?;
    path_string(dir)
}

fn path_string(path: PathBuf) -> Result<String> {
    path.into_os_string()
        .into_string()
        .map_err(|_| anyhow::anyhow!("fixture path is not valid UTF-8"))
}

fn ensure_missing_path_error(
    result: std::result::Result<CapabilityInvocationResult, CapabilityError>,
    config: &WebDavConfig,
    label: &str,
) -> Result<()> {
    match result {
        Ok(result) => bail!(
            "{label}: expected missing path error, got {}",
            result.output
        ),
        Err(error) => {
            ensure!(
                error.category == CapabilityErrorCategory::TargetSystem,
                "{label}: expected target error, got {:?}",
                error.category
            );
            ensure!(
                error.code == "webdav.get_failed",
                "{label}: expected webdav.get_failed, got {}",
                error.code
            );
            ensure_error_excludes_config(&error, config, label)?;
        }
    }
    Ok(())
}

async fn ensure_failed_auth_redacts(config: &WebDavConfig, root: &str) -> Result<()> {
    let mut bad = config.clone();
    match &mut bad.auth {
        WebDavAuth::None => bail!("WebDAV fixture auth redaction requires authentication"),
        WebDavAuth::Basic { password, .. } | WebDavAuth::Digest { password, .. } => {
            password.push_str("-wrong-secret");
        }
    }
    match invoke(&bad, "list", json!({ "path": root }), false, None).await {
        Ok(result) => bail!(
            "expected webdav.list auth failure, got output: {}",
            result.output
        ),
        Err(error) => {
            ensure_error_excludes_config(&error, &bad, "webdav.list bad auth")?;
            ensure_error_excludes_config(&error, config, "webdav.list bad auth")?;
            ensure!(
                matches!(
                    error.redaction,
                    RedactionStatus::Applied | RedactionStatus::NotRequired
                ),
                "target error should report a non-failed redaction state: {:?}",
                error.redaction
            );
        }
    }
    Ok(())
}

fn ensure_error_excludes_config(
    error: &CapabilityError,
    config: &WebDavConfig,
    label: &str,
) -> Result<()> {
    let text = serde_json::to_string(error)?;
    for sample in protected_samples(config) {
        ensure!(
            !text.contains(&sample),
            "{label} error exposed WebDAV config material: {text}"
        );
    }
    Ok(())
}

async fn cleanup_paths<'a>(config: &WebDavConfig, paths: impl IntoIterator<Item = &'a str>) {
    for path in paths {
        let _ = invoke(config, "delete", json!({ "path": path }), false, None).await;
    }
}
