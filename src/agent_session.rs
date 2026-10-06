//! Persistent, cancellable WebDAV transfer and lock sessions for Agent workflows.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use async_trait::async_trait;
use chrono::{Duration, Utc};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;
use voidb_core::{
    AGENT_TRANSFER_PROTOCOL_VERSION, AgentSessionCallRequest, AgentSessionCallResult,
    AgentSessionConcurrency, AgentSessionOpenContext, AgentTransferChecksum,
    AgentTransferChecksumAlgorithm, AgentTransferChecksumScope, AgentTransferChunkState,
    AgentTransferCleanupReport, AgentTransferCleanupState, AgentTransferEvent,
    AgentTransferOperation, AgentTransferPhase, AgentTransferProgress,
    AgentTransferResumeCheckpoint, AgentTransferRetry, LocalPathScope, PluginAgentSession,
    PluginAgentSessionFactory, PluginSessionError, PluginSessionErrorCode, PluginSessionHealth,
    PluginSessionPurpose, RedactionStatus,
};

use crate::config::WebDavConfig;
use crate::service::WebDavService;
use crate::transfer_contract::webdav_transfer_contract;
use crate::types::{DavEntryType, WebDavCopyMoveOptions};

const TRANSFER_CAPABILITY: &str = "webdav.transfer";
const STATUS_CAPABILITY: &str = "webdav.transfer_status";
const LOCK_ACQUIRE_CAPABILITY: &str = "webdav.lock_acquire";
const LOCK_RELEASE_CAPABILITY: &str = "webdav.lock_release";
const DEFAULT_CHUNK_BYTES: usize = 1024 * 1024;
const MIN_CHUNK_BYTES: usize = 64 * 1024;
const MAX_CHUNK_BYTES: usize = 16 * 1024 * 1024;
const MAX_TRANSFER_BYTES: usize = 128 * 1024 * 1024;
const RESUME_TTL_SECONDS: i64 = 60 * 60;

pub struct WebDavAgentSessionFactory {
    config: WebDavConfig,
}

impl WebDavAgentSessionFactory {
    pub fn new(config: WebDavConfig) -> Self {
        Self { config }
    }
}

#[async_trait]
impl PluginAgentSessionFactory for WebDavAgentSessionFactory {
    fn plugin_id(&self) -> &str {
        "webdav"
    }

    async fn open(
        &self,
        context: AgentSessionOpenContext,
    ) -> Result<Arc<dyn PluginAgentSession>, PluginSessionError> {
        validate_open(&context)?;
        webdav_transfer_contract().validate().map_err(|_| {
            error(
                PluginSessionErrorCode::HealthFailed,
                "The WebDAV transfer contract is invalid.",
            )
        })?;
        WebDavService::new_direct(&self.config).map_err(target_error)?;
        let binding_scope = sha256_scope(&[
            &context.binding.grant_id,
            &context.binding.profile_id,
            &context.binding.plugin_id,
        ]);
        Ok(Arc::new(WebDavAgentSession {
            config: self.config.clone(),
            binding_scope,
            state: Mutex::new(WebDavSessionState::default()),
            cancel: AtomicBool::new(false),
            closed: AtomicBool::new(false),
        }))
    }
}

struct WebDavAgentSession {
    config: WebDavConfig,
    binding_scope: String,
    state: Mutex<WebDavSessionState>,
    cancel: AtomicBool,
    closed: AtomicBool,
}

#[derive(Default)]
struct WebDavSessionState {
    active: bool,
    event: Option<AgentTransferEvent>,
    resume: Option<WebDavResumeState>,
    locks: HashMap<String, OwnedLock>,
}

struct WebDavResumeState {
    token: String,
    scope: String,
    path: String,
    local_scope: LocalPathScope,
    local_path: String,
    data: Vec<u8>,
    total: u64,
    etag: Option<String>,
    chunk_bytes: usize,
}

struct OwnedLock {
    path: String,
    token: String,
}

#[async_trait]
impl PluginAgentSession for WebDavAgentSession {
    fn concurrency(&self) -> AgentSessionConcurrency {
        AgentSessionConcurrency::Multiplexed
    }

    async fn call(
        &self,
        request: AgentSessionCallRequest,
    ) -> Result<AgentSessionCallResult, PluginSessionError> {
        if self.closed.load(Ordering::Acquire) {
            return Err(error(
                PluginSessionErrorCode::OwnerUnavailable,
                "The WebDAV transfer session is closed.",
            ));
        }
        match request.capability.as_str() {
            STATUS_CAPABILITY | "transfer_status" => self.status(request).await,
            TRANSFER_CAPABILITY | "transfer" => self.transfer(request).await,
            LOCK_ACQUIRE_CAPABILITY | "lock_acquire" => self.acquire_lock(request).await,
            LOCK_RELEASE_CAPABILITY | "lock_release" => self.release_lock(request).await,
            _ => Err(error(
                PluginSessionErrorCode::PolicyDenied,
                "The WebDAV FileTransfer session accepts only its transfer and lock capability family.",
            )),
        }
    }

    async fn health(&self) -> Result<PluginSessionHealth, PluginSessionError> {
        if self.closed.load(Ordering::Acquire) {
            return Ok(PluginSessionHealth::Closed);
        }
        Ok(if self.state.lock().await.active {
            PluginSessionHealth::Busy
        } else {
            PluginSessionHealth::Ready
        })
    }

    async fn cancel(&self, _call_id: &str) -> Result<(), PluginSessionError> {
        self.cancel.store(true, Ordering::Release);
        Ok(())
    }

    async fn close(&self, _reason: String) -> Result<(), PluginSessionError> {
        self.closed.store(true, Ordering::Release);
        self.cancel.store(true, Ordering::Release);
        let locks = {
            let mut state = self.state.lock().await;
            state.resume = None;
            state
                .locks
                .drain()
                .map(|(_, lock)| lock)
                .collect::<Vec<_>>()
        };
        if let Ok(service) = WebDavService::new_direct(&self.config) {
            for lock in locks {
                let _ = service.unlock(&lock.path, &lock.token).await;
            }
        }
        Ok(())
    }
}

impl WebDavAgentSession {
    async fn status(
        &self,
        request: AgentSessionCallRequest,
    ) -> Result<AgentSessionCallResult, PluginSessionError> {
        let state = self.state.lock().await;
        AgentSessionCallResult::bounded(
            request.call_id,
            json!({ "active": state.active, "event": state.event }),
            request.output_limit_bytes,
        )
    }

    async fn acquire_lock(
        &self,
        request: AgentSessionCallRequest,
    ) -> Result<AgentSessionCallResult, PluginSessionError> {
        let path = required_string(&request.input, "path")?;
        let timeout_seconds = request
            .input
            .get("timeout_seconds")
            .and_then(Value::as_u64)
            .unwrap_or(300);
        if !(30..=3600).contains(&timeout_seconds) {
            return Err(error(
                PluginSessionErrorCode::PolicyDenied,
                "WebDAV lock lifetime must be between 30 and 3600 seconds.",
            ));
        }
        let service = WebDavService::new_direct(&self.config).map_err(target_error)?;
        let probe = service.probe_features(&path).await.map_err(target_error)?;
        if !probe.supports_locks {
            return Err(error(
                PluginSessionErrorCode::Unsupported,
                "The WebDAV server does not advertise LOCK and UNLOCK support.",
            ));
        }
        let owner = format!("urn:voidb:{}", &self.binding_scope[7..23]);
        let lock = service
            .lock(&path, timeout_seconds, &owner)
            .await
            .map_err(target_error)?;
        let lock_ref = lock_ref(&self.binding_scope, &path, &request.call_id);
        self.state.lock().await.locks.insert(
            lock_ref.clone(),
            OwnedLock {
                path,
                token: lock.token,
            },
        );
        AgentSessionCallResult::bounded(
            request.call_id,
            json!({ "lock_ref": lock_ref, "timeout_seconds": timeout_seconds }),
            request.output_limit_bytes,
        )
    }

    async fn release_lock(
        &self,
        request: AgentSessionCallRequest,
    ) -> Result<AgentSessionCallResult, PluginSessionError> {
        let lock_ref = required_string(&request.input, "lock_ref")?;
        let lock = self
            .state
            .lock()
            .await
            .locks
            .remove(&lock_ref)
            .ok_or_else(|| {
                error(
                    PluginSessionErrorCode::BindingMismatch,
                    "The WebDAV lock reference is stale or not owned by this session.",
                )
            })?;
        let service = WebDavService::new_direct(&self.config).map_err(target_error)?;
        if let Err(failure) = service.unlock(&lock.path, &lock.token).await {
            self.state.lock().await.locks.insert(lock_ref, lock);
            return Err(target_error(failure));
        }
        AgentSessionCallResult::bounded(
            request.call_id,
            json!({ "released": true }),
            request.output_limit_bytes,
        )
    }

    async fn transfer(
        &self,
        request: AgentSessionCallRequest,
    ) -> Result<AgentSessionCallResult, PluginSessionError> {
        if !request.destructive_acknowledged {
            return Err(error(
                PluginSessionErrorCode::PolicyDenied,
                "WebDAV transfer requires destructive acknowledgement for local or remote side effects.",
            ));
        }
        let operation = required_string(&request.input, "operation")?;
        let operation_kind = match operation.as_str() {
            "upload" => AgentTransferOperation::Upload,
            "download" => AgentTransferOperation::Download,
            "copy" => AgentTransferOperation::Copy,
            "move" => AgentTransferOperation::Move,
            _ => {
                return Err(error(
                    PluginSessionErrorCode::PolicyDenied,
                    "WebDAV transfer operation must be upload, download, copy, or move.",
                ));
            }
        };
        if matches!(operation.as_str(), "copy" | "move")
            && request.input.get("expected_sha256").is_some()
        {
            return Err(error(
                PluginSessionErrorCode::Unsupported,
                "WebDAV expected_sha256 is supported only for upload and download.",
            ));
        }
        {
            let mut state = self.state.lock().await;
            if state.active {
                return Err(error(
                    PluginSessionErrorCode::PolicyDenied,
                    "Only one WebDAV transfer may be active in a session.",
                ));
            }
            state.active = true;
        }
        self.cancel.store(false, Ordering::Release);
        let result = match operation.as_str() {
            "upload" => self.upload(&request).await,
            "download" => self.download(&request).await,
            "copy" => self.copy_or_move(&request, false).await,
            "move" => self.copy_or_move(&request, true).await,
            _ => unreachable!("operation validated before session activation"),
        };
        self.state.lock().await.active = false;
        match result {
            Ok(event) => AgentSessionCallResult::bounded(
                request.call_id,
                json!({ "event": event }),
                request.output_limit_bytes,
            ),
            Err(failure) => {
                if self.cancel.load(Ordering::Acquire) {
                    Err(error(
                        PluginSessionErrorCode::Cancelled,
                        "The WebDAV transfer was cancelled; query transfer_status for cleanup and resume state.",
                    ))
                } else {
                    self.fail_event(&request.call_id, operation_kind).await;
                    Err(failure)
                }
            }
        }
    }

    async fn upload(
        &self,
        request: &AgentSessionCallRequest,
    ) -> Result<AgentTransferEvent, PluginSessionError> {
        if optional_string(&request.input, "resume_token")?.is_some() {
            return Err(error(
                PluginSessionErrorCode::Unsupported,
                "This WebDAV target has no negotiated partial-upload method; upload resume fails closed.",
            ));
        }
        let path = required_string(&request.input, "path")?;
        let local_root = required_string(&request.input, "local_root")?;
        let local_path = required_string(&request.input, "local_path")?;
        let local_scope = LocalPathScope::new(&local_root).map_err(local_error)?;
        let data = local_scope.read_file(&local_path).map_err(local_error)?;
        enforce_transfer_bound(data.len())?;
        let total = data.len() as u64;
        let expected_sha256 = expected_sha256(&request.input)?;
        let local_checksum = expected_sha256
            .as_deref()
            .map(|expected| verify_sha256(&data, expected))
            .transpose()?;
        let service = WebDavService::new_direct(&self.config).map_err(target_error)?;
        if !request
            .input
            .get("overwrite")
            .and_then(Value::as_bool)
            .unwrap_or(false)
            && service.resource_exists(&path).await.map_err(target_error)?
        {
            return Err(error(
                PluginSessionErrorCode::PolicyDenied,
                "WebDAV upload destination exists; set overwrite only with explicit replacement authorization.",
            ));
        }
        self.set_event(progress_event(
            &request.call_id,
            AgentTransferOperation::Upload,
            AgentTransferPhase::Transferring,
            1,
            0,
            total,
            0,
            1,
            None,
            None,
            false,
        ))
        .await?;
        if self.cancel.load(Ordering::Acquire) {
            let event = cancelled_event(
                &request.call_id,
                AgentTransferOperation::Upload,
                0,
                total,
                None,
                AgentTransferCleanupState::NotApplicable,
            );
            self.set_cancelled_event(event).await?;
            return Err(cancelled());
        }
        service.upload(&path, data).await.map_err(target_error)?;
        let verified = service.get_properties(&path).await.map_err(target_error)?;
        if verified.size != total {
            return Err(target_error_message(
                "WebDAV upload verification detected a size mismatch.",
            ));
        }
        if let Some(expected) = expected_sha256.as_deref() {
            let remote_data = service.download(&path).await.map_err(target_error)?;
            verify_sha256(&remote_data, expected)?;
        }
        let mut event = completed_event(
            &request.call_id,
            AgentTransferOperation::Upload,
            total,
            1,
            verified.etag,
        );
        if local_checksum.is_some() {
            event.checksum = local_checksum;
        }
        self.set_event(event.clone()).await?;
        Ok(event)
    }

    async fn download(
        &self,
        request: &AgentSessionCallRequest,
    ) -> Result<AgentTransferEvent, PluginSessionError> {
        if request
            .input
            .get("overwrite")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            return Err(error(
                PluginSessionErrorCode::Unsupported,
                "WebDAV Agent downloads fail closed on existing local destinations; replacement is not supported.",
            ));
        }
        let path = required_string(&request.input, "path")?;
        let chunk_bytes = chunk_bytes(&request.input)?;
        let resume_token = optional_string(&request.input, "resume_token")?;
        let expected_sha256 = expected_sha256(&request.input)?;
        let service = WebDavService::new_direct(&self.config).map_err(target_error)?;
        let remote = service.get_properties(&path).await.map_err(target_error)?;
        enforce_transfer_bound(remote.size as usize)?;
        let probe = service.probe_features(&path).await.map_err(target_error)?;

        let (local_scope, local_path, mut data, scope, token) = if let Some(token) = resume_token {
            if !probe.accepts_byte_ranges {
                return Err(error(
                    PluginSessionErrorCode::Unsupported,
                    "The WebDAV server no longer advertises byte-range resume.",
                ));
            }
            let resume = { self.state.lock().await.resume.take() };
            match resume {
                Some(resume)
                    if token == resume.token
                        && path == resume.path
                        && remote.size == resume.total
                        && remote.etag == resume.etag
                        && chunk_bytes == resume.chunk_bytes =>
                {
                    (
                        resume.local_scope,
                        resume.local_path,
                        resume.data,
                        resume.scope,
                        resume.token,
                    )
                }
                other => {
                    self.state.lock().await.resume = other;
                    return Err(error(
                        PluginSessionErrorCode::BindingMismatch,
                        "The WebDAV resume token or remote identity is stale.",
                    ));
                }
            }
        } else {
            let local_root = required_string(&request.input, "local_root")?;
            let local_path = required_string(&request.input, "local_path")?;
            let local_scope = LocalPathScope::new(&local_root).map_err(local_error)?;
            local_scope
                .validate_new_file(&local_path)
                .map_err(local_error)?;
            let scope = sha256_scope(&[&self.binding_scope, &path, &local_root, &local_path]);
            let token = resume_token_for(&request.call_id, &scope);
            (local_scope, local_path, Vec::new(), scope, token)
        };
        let total = remote.size;
        self.set_event(progress_event(
            &request.call_id,
            AgentTransferOperation::Download,
            AgentTransferPhase::Transferring,
            u64::from(completed_chunks(data.len(), chunk_bytes)) + 1,
            data.len() as u64,
            total,
            completed_chunks(data.len(), chunk_bytes),
            chunk_count(total as usize, chunk_bytes),
            None,
            None,
            false,
        ))
        .await?;

        if !probe.accepts_byte_ranges {
            if self.cancel.load(Ordering::Acquire) {
                let event = cancelled_event(
                    &request.call_id,
                    AgentTransferOperation::Download,
                    0,
                    total,
                    None,
                    AgentTransferCleanupState::NotApplicable,
                );
                self.set_cancelled_event(event).await?;
                return Err(cancelled());
            }
            data = service.download(&path).await.map_err(target_error)?;
        } else {
            while (data.len() as u64) < total {
                if self.cancel.load(Ordering::Acquire) {
                    let chunks = completed_chunks(data.len(), chunk_bytes);
                    let checkpoint = checkpoint(&token, &scope, data.len() as u64, chunks);
                    self.state.lock().await.resume = Some(WebDavResumeState {
                        token: token.clone(),
                        scope: scope.clone(),
                        path: path.clone(),
                        local_scope,
                        local_path,
                        data,
                        total,
                        etag: remote.etag,
                        chunk_bytes,
                    });
                    let event = cancelled_event(
                        &request.call_id,
                        AgentTransferOperation::Download,
                        checkpoint.completed_bytes,
                        total,
                        Some(checkpoint),
                        AgentTransferCleanupState::RetainedForResume,
                    );
                    self.set_cancelled_event(event).await?;
                    return Err(cancelled());
                }
                let start = data.len() as u64;
                let end = start
                    .saturating_add(chunk_bytes as u64)
                    .min(total)
                    .saturating_sub(1);
                let (chunk, observed_total) =
                    match service.download_range(&path, start, Some(end)).await {
                        Ok(response) => response,
                        Err(_) => {
                            return Err(self
                                .retain_download_failure(
                                    &request.call_id,
                                    token,
                                    scope,
                                    path,
                                    local_scope,
                                    local_path,
                                    data,
                                    total,
                                    remote.etag,
                                    chunk_bytes,
                                )
                                .await);
                        }
                    };
                let expected = end.saturating_sub(start).saturating_add(1);
                if chunk.len() as u64 != expected {
                    return Err(self
                        .retain_download_failure(
                            &request.call_id,
                            token,
                            scope,
                            path,
                            local_scope,
                            local_path,
                            data,
                            total,
                            remote.etag,
                            chunk_bytes,
                        )
                        .await);
                }
                if observed_total.is_some_and(|observed| observed != total) {
                    return Err(error(
                        PluginSessionErrorCode::BindingMismatch,
                        "The WebDAV resource size changed during range transfer.",
                    ));
                }
                data.extend_from_slice(&chunk);
                let chunks = completed_chunks(data.len(), chunk_bytes);
                self.set_event(progress_event(
                    &request.call_id,
                    AgentTransferOperation::Download,
                    AgentTransferPhase::Transferring,
                    u64::from(chunks) + 1,
                    data.len() as u64,
                    total,
                    chunks,
                    chunk_count(total as usize, chunk_bytes),
                    Some((chunks.max(1), start, chunk.len() as u64)),
                    None,
                    false,
                ))
                .await?;
            }
        }
        if data.len() as u64 != total {
            return Err(target_error_message(
                "WebDAV download verification detected a size mismatch.",
            ));
        }
        let verified_checksum = expected_sha256
            .as_deref()
            .map(|expected| verify_sha256(&data, expected))
            .transpose()?;
        local_scope
            .write_new_file(&local_path, &data)
            .map_err(local_error)?;
        self.state.lock().await.resume = None;
        let mut event = completed_event(
            &request.call_id,
            AgentTransferOperation::Download,
            total,
            chunk_count(total as usize, chunk_bytes),
            remote.etag,
        );
        if verified_checksum.is_some() {
            event.checksum = verified_checksum;
        }
        self.set_event(event.clone()).await?;
        Ok(event)
    }

    async fn copy_or_move(
        &self,
        request: &AgentSessionCallRequest,
        move_source: bool,
    ) -> Result<AgentTransferEvent, PluginSessionError> {
        let source = required_string(&request.input, "path")?;
        let destination = required_string(&request.input, "destination")?;
        let depth = optional_string(&request.input, "depth")?.unwrap_or_else(|| "0".to_string());
        if !matches!(depth.as_str(), "0" | "infinity") {
            return Err(error(
                PluginSessionErrorCode::PolicyDenied,
                "WebDAV transfer depth must be 0 or infinity.",
            ));
        }
        let lock_ref = optional_string(&request.input, "lock_ref")?;
        let lock_token = if let Some(lock_ref) = &lock_ref {
            self.state
                .lock()
                .await
                .locks
                .get(lock_ref)
                .map(|lock| lock.token.clone())
                .ok_or_else(|| {
                    error(
                        PluginSessionErrorCode::BindingMismatch,
                        "The WebDAV lock reference is stale or not owned by this session.",
                    )
                })?
                .into()
        } else {
            None
        };
        let service = WebDavService::new_direct(&self.config).map_err(target_error)?;
        let source_info = service
            .get_properties(&source)
            .await
            .map_err(target_error)?;
        let operation = if move_source {
            AgentTransferOperation::Move
        } else {
            AgentTransferOperation::Copy
        };
        self.set_event(progress_event(
            &request.call_id,
            operation,
            AgentTransferPhase::Transferring,
            1,
            0,
            source_info.size,
            0,
            1,
            None,
            None,
            false,
        ))
        .await?;
        if self.cancel.load(Ordering::Acquire) {
            let lock_state = if let Some(lock_ref) = lock_ref {
                self.release_owned_lock(&lock_ref).await?;
                AgentTransferCleanupState::Released
            } else {
                AgentTransferCleanupState::NotApplicable
            };
            let mut event = cancelled_event(
                &request.call_id,
                if move_source {
                    AgentTransferOperation::Move
                } else {
                    AgentTransferOperation::Copy
                },
                0,
                0,
                None,
                AgentTransferCleanupState::NotApplicable,
            );
            if let Some(cleanup) = &mut event.cleanup {
                cleanup.remote_lock = lock_state;
            }
            self.set_cancelled_event(event).await?;
            return Err(cancelled());
        }
        let probe = service
            .probe_features(&source)
            .await
            .map_err(target_error)?;
        if (move_source && !probe.supports_move) || (!move_source && !probe.supports_copy) {
            return Err(error(
                PluginSessionErrorCode::Unsupported,
                "The WebDAV server does not advertise the requested COPY/MOVE method.",
            ));
        }
        let options = WebDavCopyMoveOptions {
            overwrite: request
                .input
                .get("overwrite")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            depth_infinity: depth == "infinity",
            if_match: optional_string(&request.input, "if_match")?,
            if_none_match: request
                .input
                .get("if_none_match")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            lock_token,
        };
        if options.if_match.is_some() && options.if_none_match {
            return Err(error(
                PluginSessionErrorCode::PolicyDenied,
                "WebDAV if_match and if_none_match cannot both be set.",
            ));
        }
        if move_source {
            service
                .move_item_with_options(&source, &destination, &options)
                .await
                .map_err(target_error)?;
        } else {
            service
                .copy_item_with_options(&source, &destination, &options)
                .await
                .map_err(target_error)?;
        }
        let verified = service
            .get_properties(&destination)
            .await
            .map_err(target_error)?;
        if source_info.entry_type == DavEntryType::File && verified.size != source_info.size {
            return Err(target_error_message(
                "WebDAV COPY/MOVE verification detected a size mismatch.",
            ));
        }
        let event = completed_event(
            &request.call_id,
            if move_source {
                AgentTransferOperation::Move
            } else {
                AgentTransferOperation::Copy
            },
            verified.size,
            1,
            verified.etag,
        );
        self.set_event(event.clone()).await?;
        Ok(event)
    }

    async fn release_owned_lock(&self, lock_ref: &str) -> Result<(), PluginSessionError> {
        let lock = self
            .state
            .lock()
            .await
            .locks
            .remove(lock_ref)
            .ok_or_else(|| {
                error(
                    PluginSessionErrorCode::BindingMismatch,
                    "The WebDAV lock reference is stale or not owned by this session.",
                )
            })?;
        let service = WebDavService::new_direct(&self.config).map_err(target_error)?;
        service
            .unlock(&lock.path, &lock.token)
            .await
            .map_err(target_error)
    }

    async fn set_event(&self, event: AgentTransferEvent) -> Result<(), PluginSessionError> {
        let contract = webdav_transfer_contract();
        let mut state = self.state.lock().await;
        let validation = match state
            .event
            .as_ref()
            .filter(|previous| previous.transfer_id == event.transfer_id)
        {
            Some(previous) => event.validate_transition(previous, &contract),
            None => event.validate(&contract),
        };
        validation.map_err(|_| {
            error(
                PluginSessionErrorCode::HealthFailed,
                "WebDAV produced an invalid transfer lifecycle event.",
            )
        })?;
        state.event = Some(event);
        Ok(())
    }

    async fn set_cancelled_event(
        &self,
        mut event: AgentTransferEvent,
    ) -> Result<(), PluginSessionError> {
        let previous = self.state.lock().await.event.clone();
        if let Some(previous) = previous
            && previous.transfer_id == event.transfer_id
            && previous.phase != AgentTransferPhase::Cancelling
        {
            event.progress.bytes_total = previous.progress.bytes_total;
            event.progress.objects_total = previous.progress.objects_total;
            event.progress.chunks_total = previous.progress.chunks_total;
            let mut cancelling = event.clone();
            cancelling.sequence = previous.sequence.saturating_add(1);
            cancelling.observed_at = Utc::now();
            cancelling.phase = AgentTransferPhase::Cancelling;
            cancelling.terminal = false;
            cancelling.cleanup = None;
            self.set_event(cancelling).await?;
            event.sequence = previous.sequence.saturating_add(2);
            event.observed_at = Utc::now();
        }
        self.set_event(event).await
    }

    #[allow(clippy::too_many_arguments)]
    async fn retain_download_failure(
        &self,
        transfer_id: &str,
        token: String,
        scope: String,
        path: String,
        local_scope: LocalPathScope,
        local_path: String,
        data: Vec<u8>,
        total: u64,
        etag: Option<String>,
        chunk_bytes: usize,
    ) -> PluginSessionError {
        let chunks = completed_chunks(data.len(), chunk_bytes);
        let completed = data.len() as u64;
        let checkpoint = checkpoint(&token, &scope, completed, chunks);
        self.state.lock().await.resume = Some(WebDavResumeState {
            token,
            scope,
            path,
            local_scope,
            local_path,
            data,
            total,
            etag,
            chunk_bytes,
        });
        let mut event = progress_event(
            transfer_id,
            AgentTransferOperation::Download,
            AgentTransferPhase::RetryWaiting,
            u64::from(chunks) + 2,
            completed,
            total,
            chunks,
            chunk_count(total as usize, chunk_bytes),
            None,
            Some(checkpoint),
            false,
        );
        event.retry = Some(AgentTransferRetry {
            attempt: 1,
            backoff_ms: 250,
            reason_code: "target_unavailable".into(),
        });
        event.cleanup = Some(AgentTransferCleanupReport {
            local_staging: AgentTransferCleanupState::RetainedForResume,
            remote_partial: AgentTransferCleanupState::NotApplicable,
            remote_lock: AgentTransferCleanupState::NotApplicable,
        });
        match self.set_event(event).await {
            Ok(()) => target_error_message(
                "The WebDAV range request was interrupted; a scoped resume checkpoint was retained.",
            ),
            Err(failure) => failure,
        }
    }

    async fn fail_event(&self, transfer_id: &str, requested_operation: AgentTransferOperation) {
        let previous = self.state.lock().await.event.clone();
        if previous.as_ref().is_some_and(|event| {
            event.operation == requested_operation
                && (event.terminal
                    || (event.phase == AgentTransferPhase::RetryWaiting
                        && event.checkpoint.is_some()))
        }) {
            return;
        }
        let (transfer_id, operation, progress) = previous
            .filter(|event| event.operation == requested_operation && !event.terminal)
            .map(|event| (event.transfer_id, event.operation, event.progress))
            .unwrap_or((
                transfer_id.to_string(),
                requested_operation,
                AgentTransferProgress::default(),
            ));
        let event = AgentTransferEvent {
            protocol_version: AGENT_TRANSFER_PROTOCOL_VERSION,
            transfer_id,
            sequence: 10_000,
            observed_at: Utc::now(),
            operation,
            phase: AgentTransferPhase::Failed,
            progress,
            current_chunk: None,
            checkpoint: None,
            checksum: None,
            retry: None,
            conflict: None,
            cleanup: Some(AgentTransferCleanupReport {
                local_staging: AgentTransferCleanupState::NotApplicable,
                remote_partial: AgentTransferCleanupState::FailedClosed,
                remote_lock: AgentTransferCleanupState::FailedClosed,
            }),
            terminal: true,
            redaction: RedactionStatus::Applied,
        };
        let _ = self.set_event(event).await;
    }
}

fn validate_open(context: &AgentSessionOpenContext) -> Result<(), PluginSessionError> {
    if context.binding.purpose != PluginSessionPurpose::FileTransfer {
        return Err(error(
            PluginSessionErrorCode::Unsupported,
            "WebDAV persistent sessions require the FileTransfer purpose.",
        ));
    }
    if context
        .binding
        .allowed_capabilities
        .iter()
        .any(|capability| {
            !matches!(
                capability.as_str(),
                TRANSFER_CAPABILITY
                    | STATUS_CAPABILITY
                    | LOCK_ACQUIRE_CAPABILITY
                    | LOCK_RELEASE_CAPABILITY
                    | "transfer"
                    | "transfer_status"
                    | "lock_acquire"
                    | "lock_release"
            )
        })
    {
        return Err(error(
            PluginSessionErrorCode::PolicyDenied,
            "WebDAV FileTransfer sessions accept one unmixed transfer and lock family.",
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn progress_event(
    transfer_id: &str,
    operation: AgentTransferOperation,
    phase: AgentTransferPhase,
    sequence: u64,
    bytes_completed: u64,
    bytes_total: u64,
    chunks_completed: u32,
    chunks_total: u32,
    chunk: Option<(u32, u64, u64)>,
    checkpoint: Option<AgentTransferResumeCheckpoint>,
    terminal: bool,
) -> AgentTransferEvent {
    AgentTransferEvent {
        protocol_version: AGENT_TRANSFER_PROTOCOL_VERSION,
        transfer_id: transfer_id.to_string(),
        sequence: sequence.max(1),
        observed_at: Utc::now(),
        operation,
        phase,
        progress: AgentTransferProgress {
            bytes_completed,
            bytes_total: Some(bytes_total),
            objects_completed: u64::from(phase == AgentTransferPhase::Completed),
            objects_total: Some(1),
            chunks_completed,
            chunks_total: Some(chunks_total.max(1)),
        },
        current_chunk: chunk.map(|(index, offset, length)| AgentTransferChunkState {
            index: index.max(1),
            offset,
            length: length.max(1),
            completed: true,
        }),
        checkpoint,
        checksum: None,
        retry: None,
        conflict: None,
        cleanup: terminal.then(clean_cleanup),
        terminal,
        redaction: RedactionStatus::Applied,
    }
}

fn completed_event(
    transfer_id: &str,
    operation: AgentTransferOperation,
    total: u64,
    chunks: u32,
    etag: Option<String>,
) -> AgentTransferEvent {
    let mut event = progress_event(
        transfer_id,
        operation,
        AgentTransferPhase::Completed,
        u64::from(chunks) + 2,
        total,
        total,
        chunks.max(1),
        chunks.max(1),
        None,
        None,
        true,
    );
    event.checksum = etag
        .filter(|value| !value.is_empty())
        .map(|value| AgentTransferChecksum {
            algorithm: AgentTransferChecksumAlgorithm::Etag,
            scope: AgentTransferChecksumScope::Object,
            value,
            verified: true,
        });
    event
}

fn cancelled_event(
    transfer_id: &str,
    operation: AgentTransferOperation,
    completed: u64,
    total: u64,
    checkpoint: Option<AgentTransferResumeCheckpoint>,
    remote_partial: AgentTransferCleanupState,
) -> AgentTransferEvent {
    let chunks = checkpoint
        .as_ref()
        .map(|checkpoint| checkpoint.completed_chunks)
        .unwrap_or(0);
    let mut event = progress_event(
        transfer_id,
        operation,
        AgentTransferPhase::Cancelled,
        u64::from(chunks) + 2,
        completed,
        total,
        chunks,
        chunk_count(total as usize, DEFAULT_CHUNK_BYTES)
            .max(chunks)
            .max(1),
        None,
        checkpoint,
        true,
    );
    event.cleanup = Some(AgentTransferCleanupReport {
        local_staging: AgentTransferCleanupState::NotApplicable,
        remote_partial,
        remote_lock: AgentTransferCleanupState::NotApplicable,
    });
    event
}

fn clean_cleanup() -> AgentTransferCleanupReport {
    AgentTransferCleanupReport {
        local_staging: AgentTransferCleanupState::NotApplicable,
        remote_partial: AgentTransferCleanupState::NotApplicable,
        remote_lock: AgentTransferCleanupState::NotApplicable,
    }
}

fn checkpoint(
    token: &str,
    scope: &str,
    completed_bytes: u64,
    completed_chunks: u32,
) -> AgentTransferResumeCheckpoint {
    AgentTransferResumeCheckpoint {
        token: token.to_string(),
        scope: scope.to_string(),
        completed_bytes,
        completed_chunks,
        expires_at: Utc::now() + Duration::seconds(RESUME_TTL_SECONDS),
    }
}

fn chunk_bytes(input: &Value) -> Result<usize, PluginSessionError> {
    let value = input
        .get("chunk_bytes")
        .and_then(Value::as_u64)
        .unwrap_or(DEFAULT_CHUNK_BYTES as u64);
    let value = usize::try_from(value).map_err(|_| {
        error(
            PluginSessionErrorCode::PolicyDenied,
            "WebDAV transfer chunk size is invalid.",
        )
    })?;
    if !(MIN_CHUNK_BYTES..=MAX_CHUNK_BYTES).contains(&value) {
        return Err(error(
            PluginSessionErrorCode::PolicyDenied,
            "WebDAV transfer chunk size is outside the bounded range.",
        ));
    }
    Ok(value)
}

fn chunk_count(length: usize, chunk_bytes: usize) -> u32 {
    if length == 0 {
        1
    } else {
        u32::try_from(length.div_ceil(chunk_bytes)).unwrap_or(u32::MAX)
    }
}

fn completed_chunks(length: usize, chunk_bytes: usize) -> u32 {
    u32::try_from(length / chunk_bytes).unwrap_or(u32::MAX)
}

fn enforce_transfer_bound(length: usize) -> Result<(), PluginSessionError> {
    if length > MAX_TRANSFER_BYTES {
        return Err(error(
            PluginSessionErrorCode::PolicyDenied,
            "Agent WebDAV transfers are bounded to 128 MiB per session operation.",
        ));
    }
    Ok(())
}

fn required_string(input: &Value, field: &str) -> Result<String, PluginSessionError> {
    input
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(str::to_string)
        .ok_or_else(|| {
            error(
                PluginSessionErrorCode::PolicyDenied,
                format!("WebDAV transfer requires {field}."),
            )
        })
}

fn optional_string(input: &Value, field: &str) -> Result<Option<String>, PluginSessionError> {
    input
        .get(field)
        .filter(|value| !value.is_null())
        .map(|value| {
            value
                .as_str()
                .filter(|value| !value.is_empty() && !value.chars().any(char::is_control))
                .map(str::to_string)
                .ok_or_else(|| {
                    error(
                        PluginSessionErrorCode::PolicyDenied,
                        format!("WebDAV transfer field {field} is invalid."),
                    )
                })
        })
        .transpose()
}

fn expected_sha256(input: &Value) -> Result<Option<String>, PluginSessionError> {
    optional_string(input, "expected_sha256")?
        .map(|value| {
            if value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                Ok(value.to_ascii_lowercase())
            } else {
                Err(error(
                    PluginSessionErrorCode::PolicyDenied,
                    "WebDAV expected_sha256 must contain exactly 64 hexadecimal characters.",
                ))
            }
        })
        .transpose()
}

fn verify_sha256(data: &[u8], expected: &str) -> Result<AgentTransferChecksum, PluginSessionError> {
    let actual = hex::encode(Sha256::digest(data));
    if actual != expected {
        return Err(error(
            PluginSessionErrorCode::HealthFailed,
            "WebDAV SHA-256 verification failed; the transfer was not reported as successful.",
        ));
    }
    Ok(AgentTransferChecksum {
        algorithm: AgentTransferChecksumAlgorithm::Sha256,
        scope: AgentTransferChecksumScope::WholeTransfer,
        value: actual,
        verified: true,
    })
}

fn sha256_scope(parts: &[&str]) -> String {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part.as_bytes());
    }
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

fn resume_token_for(transfer_id: &str, scope: &str) -> String {
    let fingerprint = sha256_scope(&[transfer_id, scope]);
    format!("webdav-resume-{}", &fingerprint[7..39])
}

fn lock_ref(binding_scope: &str, path: &str, call_id: &str) -> String {
    let fingerprint = sha256_scope(&[binding_scope, path, call_id]);
    format!("webdav-lock-{}", &fingerprint[7..39])
}

fn local_error(_error: voidb_core::LocalPathError) -> PluginSessionError {
    error(
        PluginSessionErrorCode::PolicyDenied,
        "The local path is outside the approved scope, changed, linked, or conflicts with an existing destination.",
    )
}

fn target_error(_error: impl std::fmt::Display) -> PluginSessionError {
    target_error_message("The WebDAV target operation failed; target details were withheld.")
}

fn target_error_message(message: &str) -> PluginSessionError {
    error(PluginSessionErrorCode::OwnerUnavailable, message)
}

fn cancelled() -> PluginSessionError {
    error(
        PluginSessionErrorCode::Cancelled,
        "The WebDAV transfer was cancelled.",
    )
}

fn error(code: PluginSessionErrorCode, message: impl Into<String>) -> PluginSessionError {
    PluginSessionError::new(code, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opaque_refs_are_scope_bound() {
        let left = lock_ref(
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "/docs/a",
            "call-1",
        );
        let right = lock_ref(
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "/docs/b",
            "call-1",
        );
        assert_ne!(left, right);
        assert!(!left.contains("/docs"));
    }

    #[test]
    fn chunk_count_is_bounded_and_never_zero() {
        assert_eq!(chunk_count(0, DEFAULT_CHUNK_BYTES), 1);
        assert_eq!(chunk_count(DEFAULT_CHUNK_BYTES + 1, DEFAULT_CHUNK_BYTES), 2);
    }

    #[test]
    fn expected_sha256_detects_mismatch_without_exposing_payload() {
        let expected = hex::encode(Sha256::digest(b"expected"));
        let failure = verify_sha256(b"changed", &expected).unwrap_err();
        assert_eq!(failure.code, PluginSessionErrorCode::HealthFailed);
        assert!(!failure.message.contains("expected"));
        assert!(!failure.message.contains("changed"));
    }

    #[tokio::test]
    async fn interrupted_range_retains_a_scoped_retry_checkpoint() {
        let root = std::env::temp_dir().join(format!(
            "voidb-webdav-range-test-{}-{}",
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        std::fs::create_dir(&root).unwrap();
        let session = WebDavAgentSession {
            config: WebDavConfig::default(),
            binding_scope:
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
            state: Mutex::new(WebDavSessionState::default()),
            cancel: AtomicBool::new(false),
            closed: AtomicBool::new(false),
        };
        session
            .set_event(progress_event(
                "transfer-interrupted",
                AgentTransferOperation::Download,
                AgentTransferPhase::Transferring,
                1,
                0,
                1024,
                0,
                1,
                None,
                None,
                false,
            ))
            .await
            .unwrap();
        let failure = session
            .retain_download_failure(
                "transfer-interrupted",
                "opaque-resume-token".into(),
                session.binding_scope.clone(),
                "/fixture.bin".into(),
                LocalPathScope::new(&root).unwrap(),
                "fixture.bin".into(),
                vec![0; 128],
                1024,
                Some("\"etag\"".into()),
                MIN_CHUNK_BYTES,
            )
            .await;
        assert_eq!(failure.code, PluginSessionErrorCode::OwnerUnavailable);

        {
            let state = session.state.lock().await;
            assert!(state.resume.is_some());
            let event = state.event.as_ref().unwrap();
            assert_eq!(event.phase, AgentTransferPhase::RetryWaiting);
            assert!(event.checkpoint.is_some());
            assert_eq!(
                event.retry.as_ref().map(|retry| retry.reason_code.as_str()),
                Some("target_unavailable")
            );
            assert_eq!(
                event.cleanup.as_ref().map(|cleanup| cleanup.local_staging),
                Some(AgentTransferCleanupState::RetainedForResume)
            );
        }
        drop(session);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn stale_lock_reference_fails_before_target_access() {
        let session = WebDavAgentSession {
            config: WebDavConfig::default(),
            binding_scope:
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
            state: Mutex::new(WebDavSessionState::default()),
            cancel: AtomicBool::new(false),
            closed: AtomicBool::new(false),
        };
        let failure = session
            .release_lock(AgentSessionCallRequest {
                session: voidb_core::AgentSessionRef::new("fixture-session", 1),
                call_id: "stale-lock".into(),
                capability: "webdav.lock_release".into(),
                input: json!({ "lock_ref": "webdav-lock-stale" }),
                destructive_acknowledged: true,
                timeout_ms: Some(1_000),
                output_limit_bytes: 64 * 1024,
            })
            .await
            .unwrap_err();
        assert_eq!(failure.code, PluginSessionErrorCode::BindingMismatch);
    }

    #[tokio::test]
    async fn session_lifecycle_settles_cancellation_and_rejects_terminal_escape() {
        let session = WebDavAgentSession {
            config: WebDavConfig::default(),
            binding_scope:
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
            state: Mutex::new(WebDavSessionState::default()),
            cancel: AtomicBool::new(false),
            closed: AtomicBool::new(false),
        };
        session
            .set_event(progress_event(
                "transfer-1",
                AgentTransferOperation::Download,
                AgentTransferPhase::Transferring,
                1,
                0,
                10,
                0,
                1,
                None,
                None,
                false,
            ))
            .await
            .expect("initial event");
        session
            .set_cancelled_event(cancelled_event(
                "transfer-1",
                AgentTransferOperation::Download,
                0,
                10,
                None,
                AgentTransferCleanupState::NotApplicable,
            ))
            .await
            .expect("settled cancellation");
        let terminal = session.state.lock().await.event.clone().unwrap();
        assert_eq!(terminal.phase, AgentTransferPhase::Cancelled);
        assert!(terminal.terminal);
        assert_eq!(terminal.progress.objects_completed, 0);

        let failure = session
            .set_event(completed_event(
                "transfer-1",
                AgentTransferOperation::Download,
                10,
                1,
                None,
            ))
            .await
            .unwrap_err();
        assert_eq!(failure.code, PluginSessionErrorCode::HealthFailed);
    }
}
