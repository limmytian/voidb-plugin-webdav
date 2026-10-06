#![allow(clippy::result_large_err)]

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use serde_json::{Value, json};
use voidb_core::{
    CapabilityDefinition, CapabilityError, CapabilityErrorCategory, CapabilityInvocation,
    CapabilityInvocationResult, CapabilityRiskLevel, CredentialClass, InvocationOutputPage,
    InvocationStatus, LocalPathError, LocalPathScope, LocalScanLimits, LocalScanReport,
    RedactionStatus, TargetSystemFailure,
};

use crate::config::{WebDavAuth, WebDavConfig};
use crate::service::WebDavService;
use crate::types::{
    DavEntry, DavEntryType, SyncAction, SyncMode, SyncOptions, SyncPlan, WebDavCopyMoveOptions,
};

const PLUGIN_ID: &str = "webdav";
const DEFAULT_PAGE_LIMIT: usize = 100;
const MAX_PAGE_LIMIT: usize = 500;
const DEFAULT_CONTENT_LIMIT_BYTES: usize = 64 * 1024;
const MAX_CONTENT_LIMIT_BYTES: usize = 1024 * 1024;

pub fn webdav_capabilities() -> Vec<CapabilityDefinition> {
    let mut capabilities = vec![
        capability(
            "probe",
            "Probe WebDAV COPY, MOVE, locking, and range-resume support without mutation.",
            json!({
                "type": "object",
                "properties": { "path": { "type": "string", "default": "/" } },
                "additionalProperties": false
            }),
            json!({
                "type": "object",
                "required": [
                    "dav_classes", "allowed_methods", "accepts_byte_ranges",
                    "supports_copy", "supports_move", "supports_locks",
                    "supports_partial_upload"
                ],
                "properties": {
                    "dav_classes": { "type": "array", "items": { "type": "string" } },
                    "allowed_methods": { "type": "array", "items": { "type": "string" } },
                    "accepts_byte_ranges": { "type": "boolean" },
                    "supports_copy": { "type": "boolean" },
                    "supports_move": { "type": "boolean" },
                    "supports_locks": { "type": "boolean" },
                    "supports_partial_upload": { "type": "boolean" }
                },
                "additionalProperties": false
            }),
            vec!["connection.read", "webdav.probe"],
            false,
            false,
            Some(30_000),
        ),
        capability(
            "list",
            "List entries in a WebDAV directory.",
            json!({
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "minLength": 1,
                        "default": "/",
                        "description": "Remote WebDAV directory path. Use InvocationControls.page for offset pagination."
                    }
                },
                "additionalProperties": false
            }),
            json!({
                "type": "object",
                "required": ["path", "entries", "entry_count", "limit", "truncated"],
                "properties": {
                    "path": { "type": "string" },
                    "entries": { "type": "array", "items": entry_schema() },
                    "entry_count": { "type": "integer", "minimum": 0 },
                    "limit": { "type": "integer", "minimum": 1, "maximum": MAX_PAGE_LIMIT },
                    "cursor": { "type": ["string", "null"] },
                    "next_cursor": { "type": ["string", "null"] },
                    "truncated": { "type": "boolean" }
                },
                "additionalProperties": false
            }),
            vec!["connection.read", "webdav.list"],
            false,
            false,
            Some(30_000),
        ),
        capability(
            "stat",
            "Read metadata for one WebDAV item.",
            json!({
                "type": "object",
                "required": ["path"],
                "properties": {
                    "path": { "type": "string", "minLength": 1 }
                },
                "additionalProperties": false
            }),
            json!({
                "type": "object",
                "required": ["entry"],
                "properties": {
                    "entry": entry_schema()
                },
                "additionalProperties": false
            }),
            vec!["connection.read", "webdav.stat"],
            false,
            false,
            Some(30_000),
        ),
        capability(
            "get",
            "Fetch one WebDAV file as bounded base64 content.",
            json!({
                "type": "object",
                "required": ["path"],
                "properties": {
                    "path": { "type": "string", "minLength": 1 },
                    "max_bytes": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": MAX_CONTENT_LIMIT_BYTES,
                        "default": DEFAULT_CONTENT_LIMIT_BYTES
                    }
                },
                "additionalProperties": false
            }),
            json!({
                "type": "object",
                "required": [
                    "path",
                    "content_base64",
                    "bytes_returned",
                    "content_truncated",
                    "byte_limit"
                ],
                "properties": {
                    "path": { "type": "string" },
                    "content_base64": { "type": "string" },
                    "bytes_returned": { "type": "integer", "minimum": 0 },
                    "content_truncated": { "type": "boolean" },
                    "byte_limit": { "type": "integer", "minimum": 1, "maximum": MAX_CONTENT_LIMIT_BYTES }
                },
                "additionalProperties": false
            }),
            vec!["connection.read", "webdav.get"],
            false,
            false,
            Some(30_000),
        ),
        capability(
            "put",
            "Upload one WebDAV file from inline bounded content.",
            json!({
                "type": "object",
                "required": ["path"],
                "oneOf": [
                    {
                        "required": ["content_base64"],
                        "not": { "required": ["content_text"] }
                    },
                    {
                        "required": ["content_text"],
                        "not": { "required": ["content_base64"] }
                    }
                ],
                "properties": {
                    "path": { "type": "string", "minLength": 1 },
                    "content_base64": { "type": "string" },
                    "content_text": { "type": "string" }
                },
                "additionalProperties": false
            }),
            write_output_schema(),
            vec!["connection.write", "webdav.put"],
            true,
            true,
            Some(30_000),
        ),
        capability(
            "delete",
            "Delete one WebDAV file or directory.",
            json!({
                "type": "object",
                "required": ["path"],
                "properties": {
                    "path": { "type": "string", "minLength": 1 }
                },
                "additionalProperties": false
            }),
            write_output_schema(),
            vec!["connection.write", "webdav.delete"],
            true,
            true,
            Some(30_000),
        ),
        capability(
            "mkdir",
            "Create one WebDAV directory.",
            json!({
                "type": "object",
                "required": ["path"],
                "properties": {
                    "path": { "type": "string", "minLength": 1 }
                },
                "additionalProperties": false
            }),
            write_output_schema(),
            vec!["connection.write", "webdav.mkdir"],
            true,
            true,
            Some(30_000),
        ),
        capability(
            "copy",
            "COPY a WebDAV resource with explicit overwrite, depth, and ETag preconditions.",
            copy_move_input_schema(),
            write_output_schema(),
            vec!["connection.write", "webdav.copy"],
            true,
            true,
            Some(60_000),
        ),
        capability(
            "move",
            "MOVE a WebDAV resource with explicit overwrite and ETag preconditions.",
            copy_move_input_schema(),
            write_output_schema(),
            vec!["connection.write", "webdav.move"],
            true,
            true,
            Some(60_000),
        ),
        capability(
            "sync_plan",
            "Compute a local/WebDAV sync plan without applying changes.",
            json!({
                "type": "object",
                "required": ["remote_path", "local_root", "local_path"],
                "properties": {
                    "remote_path": { "type": "string", "minLength": 1 },
                    "local_root": {
                        "type": "string",
                        "minLength": 1,
                        "description": "Human-approved absolute local root; never returned in output."
                    },
                    "local_path": {
                        "type": "string",
                        "minLength": 1,
                        "description": "Directory to scan, relative to local_root."
                    },
                    "disclose_relative_paths": {
                        "type": "boolean",
                        "default": false,
                        "description": "Include approved root-relative names instead of opaque entry references only."
                    },
                    "mode": {
                        "type": "string",
                        "enum": ["pull", "push", "sync"],
                        "default": "sync"
                    },
                    "delete_extra": { "type": "boolean", "default": false },
                    "exclude": {
                        "type": "array",
                        "items": { "type": "string" },
                        "default": []
                    }
                },
                "additionalProperties": false
            }),
            sync_plan_schema(),
            vec!["connection.read", "webdav.sync_plan", "local.scan"],
            false,
            false,
            Some(60_000),
        ),
    ];
    capabilities.extend(webdav_transfer_capabilities());
    capabilities
}

pub async fn invoke_webdav_capability(
    config: &WebDavConfig,
    invocation: CapabilityInvocation,
) -> Result<CapabilityInvocationResult, CapabilityError> {
    if invocation.plugin_id != PLUGIN_ID {
        return Err(validation_error(
            "validation.plugin_mismatch",
            "Invocation plugin_id does not match WebDAV.",
            json!({ "expected": PLUGIN_ID, "actual": invocation.plugin_id }),
        ));
    }

    match invocation.capability_id.as_str() {
        "probe" => invoke_probe(config, invocation).await,
        "list" => invoke_list(config, invocation).await,
        "stat" => invoke_stat(config, invocation).await,
        "get" => invoke_get(config, invocation).await,
        "put" => invoke_put(config, invocation).await,
        "delete" => invoke_delete(config, invocation).await,
        "mkdir" => invoke_mkdir(config, invocation).await,
        "copy" => invoke_copy(config, invocation).await,
        "move" => invoke_move(config, invocation).await,
        "sync_plan" => invoke_sync_plan(config, invocation).await,
        "transfer" | "transfer_status" | "lock_acquire" | "lock_release" => Err(unavailable_error(
            "unavailable.session_required",
            "WebDAV transfer and lock workflows require a persistent FileTransfer session.",
            json!({ "capability_id": invocation.capability_id }),
        )),
        other => Err(unavailable_error(
            "unavailable.capability_not_found",
            "WebDAV capability was not found.",
            json!({ "capability_id": other }),
        )),
    }
}

fn webdav_transfer_capabilities() -> Vec<CapabilityDefinition> {
    let purpose = voidb_core::PluginSessionPurpose::FileTransfer;
    let family = [
        "webdav.transfer",
        "webdav.transfer_status",
        "webdav.lock_acquire",
        "webdav.lock_release",
    ];
    vec![
        CapabilityDefinition {
            plugin_id: PLUGIN_ID.to_string(),
            id: "transfer".to_string(),
            description: "Run a cancellable WebDAV upload, resumable download, COPY, or MOVE inside a plugin-owned session.".to_string(),
            input_schema: json!({
                "type": "object",
                "required": ["operation", "path"],
                "properties": {
                    "operation": { "type": "string", "enum": ["upload", "download", "copy", "move"] },
                    "path": { "type": "string", "minLength": 1 },
                    "destination": { "type": "string", "minLength": 1 },
                    "local_root": { "type": "string", "minLength": 1 },
                    "local_path": { "type": "string", "minLength": 1 },
                    "overwrite": { "type": "boolean", "default": false },
                    "expected_sha256": {
                        "type": "string",
                        "pattern": "^[A-Fa-f0-9]{64}$",
                        "description": "Optional whole-resource SHA-256 required before local commit or reported success."
                    },
                    "depth": { "type": "string", "enum": ["0", "infinity"], "default": "0" },
                    "if_match": { "type": ["string", "null"] },
                    "if_none_match": { "type": "boolean", "default": false },
                    "lock_ref": { "type": ["string", "null"] },
                    "resume_token": { "type": ["string", "null"] },
                    "chunk_bytes": { "type": "integer", "minimum": 65536, "maximum": 16777216 }
                },
                "additionalProperties": false
            }),
            output_schema: transfer_output_schema(false),
            permissions: vec![
                "connection.read".to_string(),
                "connection.write".to_string(),
                "local.read".to_string(),
                "local.write".to_string(),
                "webdav.transfer".to_string(),
            ],
            authorization: webdav_transfer_authorization(),
            risk: CapabilityRiskLevel::Destructive,
            destructive: true,
            streaming: true,
            execution_mode: voidb_core::CapabilityExecutionMode::SessionOnly,
            session_handoff: Some(voidb_core::CapabilitySessionHandoff::new(
                purpose.clone(),
                family,
            )),
            connection_required: true,
            required_secret_classes: Vec::new(),
            supports_dry_run: false,
            default_timeout_ms: Some(15 * 60 * 1_000),
        },
        CapabilityDefinition {
            plugin_id: PLUGIN_ID.to_string(),
            id: "transfer_status".to_string(),
            description: "Read the latest bounded WebDAV transfer lifecycle event without blocking the transfer.".to_string(),
            input_schema: json!({ "type": "object", "additionalProperties": false }),
            output_schema: transfer_output_schema(true),
            permissions: vec!["connection.read".to_string(), "webdav.transfer_status".to_string()],
            authorization: voidb_core::CapabilityAuthorizationMetadata::declared()
                .with_session_purposes(vec![purpose.clone()])
                .with_note("Status exposes only the redacted shared transfer lifecycle."),
            risk: CapabilityRiskLevel::ReadOnly,
            destructive: false,
            streaming: true,
            execution_mode: voidb_core::CapabilityExecutionMode::SessionOnly,
            session_handoff: Some(voidb_core::CapabilitySessionHandoff::new(
                purpose.clone(),
                family,
            )),
            connection_required: true,
            required_secret_classes: Vec::new(),
            supports_dry_run: false,
            default_timeout_ms: Some(5_000),
        },
        CapabilityDefinition {
            plugin_id: PLUGIN_ID.to_string(),
            id: "lock_acquire".to_string(),
            description: "Acquire a bounded WebDAV exclusive write lock retained only inside this session.".to_string(),
            input_schema: json!({
                "type": "object",
                "required": ["path"],
                "properties": {
                    "path": { "type": "string", "minLength": 1 },
                    "timeout_seconds": { "type": "integer", "minimum": 30, "maximum": 3600, "default": 300 }
                },
                "additionalProperties": false
            }),
            output_schema: json!({
                "type": "object",
                "required": ["lock_ref", "timeout_seconds"],
                "properties": {
                    "lock_ref": { "type": "string" },
                    "timeout_seconds": { "type": "integer" }
                },
                "additionalProperties": false
            }),
            permissions: vec!["connection.write".to_string(), "webdav.lock_acquire".to_string()],
            authorization: webdav_lock_authorization("Acquire WebDAV lock"),
            risk: CapabilityRiskLevel::ExternalSideEffect,
            destructive: false,
            streaming: false,
            execution_mode: voidb_core::CapabilityExecutionMode::SessionOnly,
            session_handoff: Some(voidb_core::CapabilitySessionHandoff::new(
                purpose.clone(),
                family,
            )),
            connection_required: true,
            required_secret_classes: Vec::new(),
            supports_dry_run: false,
            default_timeout_ms: Some(30_000),
        },
        CapabilityDefinition {
            plugin_id: PLUGIN_ID.to_string(),
            id: "lock_release".to_string(),
            description: "Release a WebDAV lock owned by this session using its opaque lock reference.".to_string(),
            input_schema: json!({
                "type": "object",
                "required": ["lock_ref"],
                "properties": { "lock_ref": { "type": "string", "minLength": 1 } },
                "additionalProperties": false
            }),
            output_schema: json!({
                "type": "object",
                "required": ["released"],
                "properties": { "released": { "type": "boolean" } },
                "additionalProperties": false
            }),
            permissions: vec!["connection.write".to_string(), "webdav.lock_release".to_string()],
            authorization: voidb_core::CapabilityAuthorizationMetadata::declared()
                .with_interactive_execute()
                .with_session_purposes(vec![purpose.clone()])
                .with_note("Only locks owned by the active session can be released."),
            risk: CapabilityRiskLevel::ExternalSideEffect,
            destructive: false,
            streaming: false,
            execution_mode: voidb_core::CapabilityExecutionMode::SessionOnly,
            session_handoff: Some(voidb_core::CapabilitySessionHandoff::new(purpose, family)),
            connection_required: true,
            required_secret_classes: Vec::new(),
            supports_dry_run: false,
            default_timeout_ms: Some(30_000),
        },
    ]
}

fn transfer_output_schema(status: bool) -> Value {
    let mut event = voidb_core::agent_transfer_event_schema();
    let definitions = event
        .as_object_mut()
        .and_then(|schema| schema.remove("$defs"))
        .unwrap_or_else(|| json!({}));
    if status {
        json!({
            "type": "object",
            "required": ["active", "event"],
            "properties": {
                "active": { "type": "boolean" },
                "event": { "anyOf": [event, { "type": "null" }] }
            },
            "$defs": definitions,
            "additionalProperties": false
        })
    } else {
        json!({
            "type": "object",
            "required": ["event"],
            "properties": { "event": event },
            "$defs": definitions,
            "additionalProperties": false
        })
    }
}

fn webdav_transfer_authorization() -> voidb_core::CapabilityAuthorizationMetadata {
    let fields = vec![
        voidb_core::CapabilityApprovalField::new(
            "/operation",
            "Transfer operation",
            voidb_core::CapabilityApprovalValueType::String,
        )
        .required()
        .with_risk_emphasis(voidb_core::CapabilityApprovalRiskEmphasis::Destructive),
        voidb_core::CapabilityApprovalField::new(
            "/path",
            "Source path",
            voidb_core::CapabilityApprovalValueType::Path,
        )
        .required(),
        voidb_core::CapabilityApprovalField::new(
            "/destination",
            "Destination path",
            voidb_core::CapabilityApprovalValueType::Path,
        )
        .with_risk_emphasis(voidb_core::CapabilityApprovalRiskEmphasis::Destructive),
        voidb_core::CapabilityApprovalField::new(
            "/local_root",
            "Approved local transfer root",
            voidb_core::CapabilityApprovalValueType::Path,
        )
        .with_risk_emphasis(voidb_core::CapabilityApprovalRiskEmphasis::PrivilegeEscalation),
        voidb_core::CapabilityApprovalField::new(
            "/local_path",
            "Relative local transfer path",
            voidb_core::CapabilityApprovalValueType::Path,
        ),
        voidb_core::CapabilityApprovalField::new(
            "/overwrite",
            "Overwrite destination",
            voidb_core::CapabilityApprovalValueType::Boolean,
        )
        .with_risk_emphasis(voidb_core::CapabilityApprovalRiskEmphasis::Destructive),
        voidb_core::CapabilityApprovalField::new(
            "/lock_ref",
            "Session-owned lock reference",
            voidb_core::CapabilityApprovalValueType::ResourceId,
        ),
    ];
    voidb_core::CapabilityAuthorizationMetadata::declared()
        .with_interactive_execute()
        .with_session_purposes(vec![voidb_core::PluginSessionPurpose::FileTransfer])
        .with_note(
            "Remote paths, local scope, overwrite, ETag, range-resume, and lock ownership are revalidated inside the WebDAV session.",
        )
        .with_approval_schema(voidb_core::CapabilityApprovalSchema::v1(fields))
        .without_capability_wide()
}

fn webdav_lock_authorization(label: &str) -> voidb_core::CapabilityAuthorizationMetadata {
    let fields = vec![
        voidb_core::CapabilityApprovalField::new(
            "/path",
            label,
            voidb_core::CapabilityApprovalValueType::Path,
        )
        .required()
        .with_risk_emphasis(voidb_core::CapabilityApprovalRiskEmphasis::PrivilegeEscalation),
        voidb_core::CapabilityApprovalField::new(
            "/timeout_seconds",
            "Lock lifetime",
            voidb_core::CapabilityApprovalValueType::Integer,
        )
        .with_risk_emphasis(voidb_core::CapabilityApprovalRiskEmphasis::PrivilegeEscalation),
    ];
    voidb_core::CapabilityAuthorizationMetadata::declared()
        .with_interactive_execute()
        .with_session_purposes(vec![voidb_core::PluginSessionPurpose::FileTransfer])
        .with_approval_schema(voidb_core::CapabilityApprovalSchema::v1(fields))
        .without_capability_wide()
}

#[allow(clippy::too_many_arguments)]
fn capability(
    id: &str,
    description: &str,
    input_schema: Value,
    output_schema: Value,
    permissions: Vec<&str>,
    destructive: bool,
    supports_dry_run: bool,
    default_timeout_ms: Option<u64>,
) -> CapabilityDefinition {
    CapabilityDefinition {
        plugin_id: PLUGIN_ID.to_string(),
        id: id.to_string(),
        description: description.to_string(),
        input_schema,
        output_schema,
        permissions: permissions.into_iter().map(str::to_string).collect(),
        authorization: webdav_authorization_metadata(id),
        risk: CapabilityRiskLevel::from_destructive(destructive),
        destructive,
        streaming: false,
        execution_mode: voidb_core::CapabilityExecutionMode::Stateless,
        session_handoff: None,
        connection_required: true,
        required_secret_classes: Vec::<CredentialClass>::new(),
        supports_dry_run,
        default_timeout_ms,
    }
}

fn webdav_authorization_metadata(id: &str) -> voidb_core::CapabilityAuthorizationMetadata {
    let (path, required) = match id {
        "list" | "probe" => ("/path", false),
        "stat" | "get" | "put" | "delete" | "mkdir" => ("/path", true),
        "sync_plan" => ("/remote_path", true),
        "copy" | "move" => {
            let fields = vec![
                voidb_core::CapabilityApprovalField::new(
                    "/source",
                    "Source path",
                    voidb_core::CapabilityApprovalValueType::Path,
                )
                .required(),
                voidb_core::CapabilityApprovalField::new(
                    "/destination",
                    "Destination path",
                    voidb_core::CapabilityApprovalValueType::Path,
                )
                .required()
                .with_risk_emphasis(voidb_core::CapabilityApprovalRiskEmphasis::Destructive),
                voidb_core::CapabilityApprovalField::new(
                    "/overwrite",
                    "Overwrite destination",
                    voidb_core::CapabilityApprovalValueType::Boolean,
                )
                .with_risk_emphasis(voidb_core::CapabilityApprovalRiskEmphasis::Destructive),
                voidb_core::CapabilityApprovalField::new(
                    "/depth",
                    "Collection depth",
                    voidb_core::CapabilityApprovalValueType::String,
                )
                .with_risk_emphasis(voidb_core::CapabilityApprovalRiskEmphasis::Destructive),
            ];
            return voidb_core::CapabilityAuthorizationMetadata::declared()
                .with_note(
                    "COPY/MOVE destination, overwrite, depth, ETag, and lock constraints are revalidated by the WebDAV service.",
                )
                .with_approval_schema(voidb_core::CapabilityApprovalSchema::v1(fields));
        }
        _ => {
            return voidb_core::CapabilityAuthorizationMetadata::declared()
                .with_note("Lock and resumable transfer sessions remain deferred.");
        }
    };
    let mut field = voidb_core::CapabilityApprovalField::new(
        path,
        "Remote path or prefix",
        voidb_core::CapabilityApprovalValueType::Path,
    )
    .with_constraint(voidb_core::CapabilityConstraintKind::Prefix);
    if required {
        field = field.required();
    }
    if matches!(id, "put" | "delete" | "mkdir") {
        field = field.with_risk_emphasis(voidb_core::CapabilityApprovalRiskEmphasis::Destructive);
    }
    let mut fields = vec![field];
    if id == "sync_plan" {
        fields.extend([
            voidb_core::CapabilityApprovalField::new(
                "/local_root",
                "Approved local scan root",
                voidb_core::CapabilityApprovalValueType::Path,
            )
            .required()
            .with_risk_emphasis(voidb_core::CapabilityApprovalRiskEmphasis::PrivilegeEscalation),
            voidb_core::CapabilityApprovalField::new(
                "/local_path",
                "Relative local scan path",
                voidb_core::CapabilityApprovalValueType::Path,
            )
            .required(),
            voidb_core::CapabilityApprovalField::new(
                "/disclose_relative_paths",
                "Disclose relative local paths",
                voidb_core::CapabilityApprovalValueType::Boolean,
            )
            .with_risk_emphasis(voidb_core::CapabilityApprovalRiskEmphasis::PrivilegeEscalation),
        ]);
    }
    let metadata = voidb_core::CapabilityAuthorizationMetadata::declared()
        .with_note(
            "Remote path-prefix constraints are revalidated; resumable sessions remain deferred.",
        )
        .with_approval_schema(voidb_core::CapabilityApprovalSchema::v1(fields));
    if id == "sync_plan" {
        metadata.without_capability_wide()
    } else {
        metadata
    }
}

async fn invoke_probe(
    config: &WebDavConfig,
    invocation: CapabilityInvocation,
) -> Result<CapabilityInvocationResult, CapabilityError> {
    let path = optional_string(&invocation.input, "path")?.unwrap_or_else(|| "/".to_string());
    let service = direct_service(config, "webdav.probe_failed")?;
    let probe = service
        .probe_features(&path)
        .await
        .map_err(|error| target_error(config, "webdav.probe_failed", error))?;
    let output = json!({
        "dav_classes": probe.dav_classes,
        "allowed_methods": probe.allowed_methods,
        "accepts_byte_ranges": probe.accepts_byte_ranges,
        "supports_copy": probe.supports_copy,
        "supports_move": probe.supports_move,
        "supports_locks": probe.supports_locks,
        "supports_partial_upload": probe.supports_partial_upload,
    });
    Ok(result(
        invocation.id,
        output.clone(),
        json!({
            "accepts_byte_ranges": output["accepts_byte_ranges"],
            "supports_copy": output["supports_copy"],
            "supports_move": output["supports_move"],
            "supports_locks": output["supports_locks"],
            "supports_partial_upload": output["supports_partial_upload"],
        }),
        None,
    ))
}

async fn invoke_list(
    config: &WebDavConfig,
    invocation: CapabilityInvocation,
) -> Result<CapabilityInvocationResult, CapabilityError> {
    let path = optional_string(&invocation.input, "path")?.unwrap_or_else(|| "/".to_string());
    let page_request = page_request(&invocation)?;
    let service = direct_service(config, "webdav.list_failed")?;
    let entries = service
        .list_dir(&path)
        .await
        .map_err(|e| target_error(config, "webdav.list_failed", e))?;
    let total_count = entries.len();
    let skipped = page_request.offset.min(total_count);
    let output_entries = entries
        .into_iter()
        .skip(skipped)
        .take(page_request.limit)
        .map(entry_output)
        .collect::<Vec<_>>();
    let entry_count = output_entries.len();
    let next_offset = skipped + entry_count;
    let next_cursor = (next_offset < total_count).then(|| next_offset.to_string());
    let truncated = next_cursor.is_some();
    let output = json!({
        "path": path,
        "entries": output_entries,
        "entry_count": entry_count,
        "limit": page_request.limit,
        "cursor": page_request.cursor,
        "next_cursor": next_cursor,
        "truncated": truncated
    });
    let page = output["next_cursor"]
        .as_str()
        .map(|next_cursor| InvocationOutputPage {
            next_cursor: Some(next_cursor.to_string()),
        });
    let summary = json!({
        "entry_count": entry_count,
        "truncated": truncated,
        "next_cursor": output["next_cursor"]
    });

    Ok(result(invocation.id, output, summary, page))
}

async fn invoke_stat(
    config: &WebDavConfig,
    invocation: CapabilityInvocation,
) -> Result<CapabilityInvocationResult, CapabilityError> {
    let path = required_string(&invocation.input, "path")?;
    let service = direct_service(config, "webdav.stat_failed")?;
    let entry = service
        .get_properties(&path)
        .await
        .map_err(|e| target_error(config, "webdav.stat_failed", e))?;
    let output = json!({ "entry": entry_output(entry) });
    let summary = json!({
        "path": output["entry"]["href"],
        "entry_type": output["entry"]["entry_type"],
        "size": output["entry"]["size"]
    });

    Ok(result(invocation.id, output, summary, None))
}

async fn invoke_get(
    config: &WebDavConfig,
    invocation: CapabilityInvocation,
) -> Result<CapabilityInvocationResult, CapabilityError> {
    let path = required_string(&invocation.input, "path")?;
    let byte_limit = content_limit(&invocation.input)?;
    let service = direct_service(config, "webdav.get_failed")?;
    let bytes = service
        .download(&path)
        .await
        .map_err(|e| target_error(config, "webdav.get_failed", e))?;
    let content_truncated = bytes.len() > byte_limit;
    let returned = &bytes[..bytes.len().min(byte_limit)];
    let output = json!({
        "path": path,
        "content_base64": BASE64.encode(returned),
        "bytes_returned": returned.len(),
        "content_truncated": content_truncated,
        "byte_limit": byte_limit
    });
    let summary = json!({
        "path": output["path"],
        "bytes_returned": output["bytes_returned"],
        "content_truncated": content_truncated
    });

    Ok(result(invocation.id, output, summary, None))
}

async fn invoke_put(
    config: &WebDavConfig,
    invocation: CapabilityInvocation,
) -> Result<CapabilityInvocationResult, CapabilityError> {
    let path = required_string(&invocation.input, "path")?;
    let content = content_bytes(&invocation.input)?;
    let details = json!({
        "path": path,
        "bytes": content.len()
    });
    if invocation.controls.dry_run {
        return Ok(dry_run_result(invocation.id, "put", details));
    }

    let service = direct_service(config, "webdav.put_failed")?;
    service
        .upload(&path, content)
        .await
        .map_err(|e| target_error(config, "webdav.put_failed", e))?;

    Ok(write_result(invocation.id, "put", details))
}

async fn invoke_delete(
    config: &WebDavConfig,
    invocation: CapabilityInvocation,
) -> Result<CapabilityInvocationResult, CapabilityError> {
    let path = required_string(&invocation.input, "path")?;
    let details = json!({ "path": path });
    if invocation.controls.dry_run {
        return Ok(dry_run_result(invocation.id, "delete", details));
    }

    let service = direct_service(config, "webdav.delete_failed")?;
    service
        .delete(&path)
        .await
        .map_err(|e| target_error(config, "webdav.delete_failed", e))?;

    Ok(write_result(invocation.id, "delete", details))
}

async fn invoke_mkdir(
    config: &WebDavConfig,
    invocation: CapabilityInvocation,
) -> Result<CapabilityInvocationResult, CapabilityError> {
    let path = required_string(&invocation.input, "path")?;
    let details = json!({ "path": path });
    if invocation.controls.dry_run {
        return Ok(dry_run_result(invocation.id, "mkdir", details));
    }

    let service = direct_service(config, "webdav.mkdir_failed")?;
    service
        .mkdir(&path)
        .await
        .map_err(|e| target_error(config, "webdav.mkdir_failed", e))?;

    Ok(write_result(invocation.id, "mkdir", details))
}

async fn invoke_copy(
    config: &WebDavConfig,
    invocation: CapabilityInvocation,
) -> Result<CapabilityInvocationResult, CapabilityError> {
    invoke_copy_or_move(config, invocation, false).await
}

async fn invoke_move(
    config: &WebDavConfig,
    invocation: CapabilityInvocation,
) -> Result<CapabilityInvocationResult, CapabilityError> {
    invoke_copy_or_move(config, invocation, true).await
}

async fn invoke_copy_or_move(
    config: &WebDavConfig,
    invocation: CapabilityInvocation,
    move_source: bool,
) -> Result<CapabilityInvocationResult, CapabilityError> {
    let source = required_string(&invocation.input, "source")?;
    let destination = required_string(&invocation.input, "destination")?;
    let overwrite = optional_bool(&invocation.input, "overwrite")?.unwrap_or(false);
    let depth = optional_string(&invocation.input, "depth")?.unwrap_or_else(|| "0".to_string());
    if !matches!(depth.as_str(), "0" | "infinity") {
        return Err(validation_error(
            "validation.webdav_depth_invalid",
            "WebDAV depth must be 0 or infinity.",
            json!({ "depth": depth }),
        ));
    }
    let if_match = optional_string(&invocation.input, "if_match")?;
    let if_none_match = optional_bool(&invocation.input, "if_none_match")?.unwrap_or(false);
    if if_match.is_some() && if_none_match {
        return Err(validation_error(
            "validation.webdav_precondition_conflict",
            "if_match and if_none_match cannot both be set.",
            json!({}),
        ));
    }
    let operation = if move_source { "move" } else { "copy" };
    let details = json!({
        "source": source,
        "destination": destination,
        "overwrite": overwrite,
        "depth": depth,
        "if_match": if_match,
        "if_none_match": if_none_match,
    });
    if invocation.controls.dry_run {
        return Ok(dry_run_result(invocation.id, operation, details));
    }
    let options = WebDavCopyMoveOptions {
        overwrite,
        depth_infinity: depth == "infinity",
        if_match,
        if_none_match,
        lock_token: None,
    };
    let service = direct_service(config, &format!("webdav.{operation}_failed"))?;
    let result = if move_source {
        service
            .move_item_with_options(&source, &destination, &options)
            .await
    } else {
        service
            .copy_item_with_options(&source, &destination, &options)
            .await
    };
    result.map_err(|error| target_error(config, &format!("webdav.{operation}_failed"), error))?;
    Ok(write_result(invocation.id, operation, details))
}

async fn invoke_sync_plan(
    config: &WebDavConfig,
    invocation: CapabilityInvocation,
) -> Result<CapabilityInvocationResult, CapabilityError> {
    let remote_path = required_string(&invocation.input, "remote_path")?;
    let local_root = required_string(&invocation.input, "local_root")?;
    let local_path = required_string(&invocation.input, "local_path")?;
    let disclose_relative_paths =
        optional_bool(&invocation.input, "disclose_relative_paths")?.unwrap_or(false);
    let local_scope_id = format!("local-scope:{}", invocation.id);
    let local_scope = LocalPathScope::new(&local_root)
        .map_err(|error| local_path_error(&local_scope_id, error))?;
    let (local_entries, scan_report) = crate::sync_ops::walk_local_tree_scoped(
        &local_scope,
        &local_path,
        LocalScanLimits::default(),
    )
    .map_err(|error| local_path_error(&local_scope_id, error))?;
    let options = SyncOptions {
        mode: sync_mode(&invocation.input)?,
        delete_extra: optional_bool(&invocation.input, "delete_extra")?.unwrap_or(false),
        dry_run: true,
        exclude: optional_string_array(&invocation.input, "exclude")?.unwrap_or_default(),
    };

    let service = direct_service(config, "webdav.sync_plan_failed")?;
    let remote_entries = service
        .walk_remote_tree(&remote_path)
        .await
        .map_err(|e| target_error(config, "webdav.sync_plan_failed", e))?;
    let plan = WebDavService::compute_sync_plan(&remote_entries, &local_entries, &options);
    let output = sync_plan_output(
        "webdav",
        &remote_path,
        &local_scope_id,
        &scan_report,
        disclose_relative_paths,
        &options,
        plan,
    );
    let summary = json!({
        "change_count": output["change_count"],
        "total_transfer_bytes": output["total_transfer_bytes"],
        "mode": output["mode"],
        "delete_extra": output["delete_extra"]
    });

    Ok(result(invocation.id, output, summary, None))
}

fn direct_service(config: &WebDavConfig, code: &str) -> Result<WebDavService, CapabilityError> {
    WebDavService::new_direct(config).map_err(|e| target_error(config, code, e))
}

fn entry_schema() -> Value {
    json!({
        "type": "object",
        "required": ["name", "href", "entry_type", "size"],
        "properties": {
            "name": { "type": "string" },
            "href": { "type": "string" },
            "entry_type": { "type": "string", "enum": ["file", "directory"] },
            "size": { "type": "integer", "minimum": 0 },
            "last_modified": { "type": ["string", "null"] },
            "content_type": { "type": ["string", "null"] },
            "etag": { "type": ["string", "null"] }
        },
        "additionalProperties": false
    })
}

fn copy_move_input_schema() -> Value {
    json!({
        "type": "object",
        "required": ["source", "destination"],
        "properties": {
            "source": { "type": "string", "minLength": 1 },
            "destination": { "type": "string", "minLength": 1 },
            "overwrite": { "type": "boolean", "default": false },
            "depth": { "type": "string", "enum": ["0", "infinity"], "default": "0" },
            "if_match": { "type": ["string", "null"] },
            "if_none_match": { "type": "boolean", "default": false }
        },
        "additionalProperties": false
    })
}

fn write_output_schema() -> Value {
    json!({
        "type": "object",
        "required": ["ok", "operation", "dry_run", "would_execute", "destructive", "details"],
        "properties": write_output_properties(),
        "additionalProperties": false
    })
}

fn write_output_properties() -> Value {
    json!({
        "ok": { "type": "boolean" },
        "operation": { "type": "string" },
        "dry_run": { "type": "boolean" },
        "would_execute": { "type": "boolean" },
        "destructive": { "type": "boolean" },
        "message": { "type": "string" },
        "details": { "type": "object" }
    })
}

fn sync_plan_schema() -> Value {
    json!({
        "type": "object",
        "required": [
            "target",
            "remote_path",
            "local_scope_id",
            "scan",
            "mode",
            "delete_extra",
            "changes",
            "change_count",
            "total_transfer_bytes"
        ],
        "properties": {
            "target": { "type": "string" },
            "remote_path": { "type": "string" },
            "local_scope_id": { "type": "string" },
            "scan": { "type": "object" },
            "mode": { "type": "string", "enum": ["pull", "push", "sync"] },
            "delete_extra": { "type": "boolean" },
            "exclude": { "type": "array", "items": { "type": "string" } },
            "changes": { "type": "array", "items": sync_change_schema() },
            "change_count": { "type": "integer", "minimum": 0 },
            "total_transfer_bytes": { "type": "integer", "minimum": 0 }
        },
        "additionalProperties": false
    })
}

fn sync_change_schema() -> Value {
    json!({
        "type": "object",
        "required": ["entry_ref", "action", "size", "is_dir"],
        "properties": {
            "entry_ref": { "type": "string" },
            "relative_path": { "type": "string" },
            "action": {
                "type": "string",
                "enum": ["download", "upload", "delete_local", "delete_remote", "conflict"]
            },
            "size": { "type": "integer", "minimum": 0 },
            "is_dir": { "type": "boolean" }
        },
        "additionalProperties": false
    })
}

fn entry_output(entry: DavEntry) -> Value {
    json!({
        "name": entry.name,
        "href": entry.href,
        "entry_type": match entry.entry_type {
            DavEntryType::File => "file",
            DavEntryType::Directory => "directory",
        },
        "size": entry.size,
        "last_modified": entry.last_modified,
        "content_type": entry.content_type,
        "etag": entry.etag
    })
}

fn sync_plan_output(
    target: &str,
    remote_path: &str,
    local_scope_id: &str,
    scan_report: &LocalScanReport,
    disclose_relative_paths: bool,
    options: &SyncOptions,
    plan: SyncPlan,
) -> Value {
    let changes = plan
        .changes
        .into_iter()
        .enumerate()
        .map(|(index, change)| {
            let mut output = json!({
                "entry_ref": format!("{local_scope_id}:entry:{}", index + 1),
                "action": sync_action_label(change.action),
                "size": change.size,
                "is_dir": change.is_dir
            });
            if disclose_relative_paths {
                output["relative_path"] = Value::String(change.rel_path);
            }
            output
        })
        .collect::<Vec<_>>();
    let change_count = changes.len();
    json!({
        "target": target,
        "remote_path": remote_path,
        "local_scope_id": local_scope_id,
        "scan": scan_output(scan_report),
        "mode": sync_mode_label(options.mode),
        "delete_extra": options.delete_extra,
        "exclude": options.exclude,
        "changes": changes,
        "change_count": change_count,
        "total_transfer_bytes": plan.total_transfer_bytes
    })
}

fn scan_output(report: &LocalScanReport) -> Value {
    json!({
        "entry_count": report.entries.len(),
        "observed_depth": report.observed_depth,
        "observed_path_bytes": report.observed_path_bytes,
        "limits": {
            "max_depth": report.limits.max_depth,
            "max_entries": report.limits.max_entries,
            "max_path_bytes": report.limits.max_path_bytes,
        }
    })
}

fn sync_action_label(action: SyncAction) -> &'static str {
    match action {
        SyncAction::Download => "download",
        SyncAction::Upload => "upload",
        SyncAction::DeleteLocal => "delete_local",
        SyncAction::DeleteRemote => "delete_remote",
        SyncAction::Conflict => "conflict",
    }
}

fn sync_mode_label(mode: SyncMode) -> &'static str {
    match mode {
        SyncMode::Pull => "pull",
        SyncMode::Push => "push",
        SyncMode::Sync => "sync",
    }
}

fn sync_mode(input: &Value) -> Result<SyncMode, CapabilityError> {
    match optional_string(input, "mode")?.as_deref().unwrap_or("sync") {
        "pull" => Ok(SyncMode::Pull),
        "push" => Ok(SyncMode::Push),
        "sync" => Ok(SyncMode::Sync),
        other => Err(validation_error(
            "validation.sync_mode_invalid",
            "Sync mode must be pull, push, or sync.",
            json!({ "mode": other }),
        )),
    }
}

fn content_limit(input: &Value) -> Result<usize, CapabilityError> {
    let Some(max_bytes) = optional_u64(input, "max_bytes")? else {
        return Ok(DEFAULT_CONTENT_LIMIT_BYTES);
    };
    let max_bytes = usize::try_from(max_bytes).map_err(|_| {
        validation_error(
            "validation.max_bytes_invalid",
            "max_bytes is too large for this platform.",
            json!({ "maximum": MAX_CONTENT_LIMIT_BYTES }),
        )
    })?;
    if max_bytes == 0 || max_bytes > MAX_CONTENT_LIMIT_BYTES {
        return Err(validation_error(
            "validation.max_bytes_invalid",
            "max_bytes must be between 1 and the maximum content limit.",
            json!({ "max_bytes": max_bytes, "maximum": MAX_CONTENT_LIMIT_BYTES }),
        ));
    }
    Ok(max_bytes)
}

fn content_bytes(input: &Value) -> Result<Vec<u8>, CapabilityError> {
    let content_base64 = optional_string(input, "content_base64")?;
    let content_text = optional_string_allow_empty(input, "content_text")?;
    match (content_base64, content_text) {
        (Some(_), Some(_)) => Err(validation_error(
            "validation.content_source_conflict",
            "Provide either content_base64 or content_text, not both.",
            json!({}),
        )),
        (Some(value), None) => BASE64.decode(value).map_err(|error| {
            validation_error(
                "validation.content_base64_invalid",
                "content_base64 could not be decoded.",
                json!({ "message": error.to_string() }),
            )
        }),
        (None, Some(value)) => Ok(value.into_bytes()),
        (None, None) => Err(validation_error(
            "validation.content_source_missing",
            "Provide content_base64 or content_text.",
            json!({}),
        )),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PageRequest {
    offset: usize,
    limit: usize,
    cursor: Option<String>,
}

fn page_request(invocation: &CapabilityInvocation) -> Result<PageRequest, CapabilityError> {
    let limit = invocation
        .controls
        .page
        .as_ref()
        .map(|page| page.limit as usize)
        .unwrap_or(DEFAULT_PAGE_LIMIT);
    if limit == 0 || limit > MAX_PAGE_LIMIT {
        return Err(validation_error(
            "validation.page_limit_invalid",
            "WebDAV list page limit must be between 1 and the maximum page limit.",
            json!({ "limit": limit, "maximum": MAX_PAGE_LIMIT }),
        ));
    }

    let cursor = invocation
        .controls
        .page
        .as_ref()
        .and_then(|page| page.cursor.clone());
    let offset = cursor
        .as_deref()
        .map(parse_offset_cursor)
        .transpose()?
        .unwrap_or(0);

    Ok(PageRequest {
        offset,
        limit,
        cursor,
    })
}

fn parse_offset_cursor(cursor: &str) -> Result<usize, CapabilityError> {
    cursor.parse::<usize>().map_err(|_| {
        validation_error(
            "validation.invalid_cursor",
            "Storage list cursor must be an unsigned offset.",
            json!({ "cursor": cursor }),
        )
    })
}

fn required_string(input: &Value, field: &str) -> Result<String, CapabilityError> {
    match input.get(field) {
        Some(value) if !value.is_string() => Err(validation_error(
            "validation.input_field_invalid",
            "Required input field must be a string.",
            json!({ "field": field }),
        )),
        Some(value) => value
            .as_str()
            .filter(|value| !value.trim().is_empty())
            .map(str::to_string)
            .ok_or_else(|| {
                validation_error(
                    "validation.input_field_required",
                    "Required string input field is missing.",
                    json!({ "field": field }),
                )
            }),
        None => Err(validation_error(
            "validation.input_field_required",
            "Required string input field is missing.",
            json!({ "field": field }),
        )),
    }
}

fn optional_string(input: &Value, field: &str) -> Result<Option<String>, CapabilityError> {
    input
        .get(field)
        .filter(|value| !value.is_null())
        .map(|value| {
            value
                .as_str()
                .filter(|value| !value.trim().is_empty())
                .map(str::to_string)
                .ok_or_else(|| {
                    validation_error(
                        "validation.input_field_invalid",
                        "Optional input field must be a non-empty string.",
                        json!({ "field": field }),
                    )
                })
        })
        .transpose()
}

fn optional_string_allow_empty(
    input: &Value,
    field: &str,
) -> Result<Option<String>, CapabilityError> {
    input
        .get(field)
        .filter(|value| !value.is_null())
        .map(|value| {
            value.as_str().map(str::to_string).ok_or_else(|| {
                validation_error(
                    "validation.input_field_invalid",
                    "Optional input field must be a string.",
                    json!({ "field": field }),
                )
            })
        })
        .transpose()
}

fn optional_string_array(
    input: &Value,
    field: &str,
) -> Result<Option<Vec<String>>, CapabilityError> {
    input
        .get(field)
        .filter(|value| !value.is_null())
        .map(|value| {
            value
                .as_array()
                .ok_or_else(|| {
                    validation_error(
                        "validation.input_field_invalid",
                        "Optional input field must be an array of strings.",
                        json!({ "field": field }),
                    )
                })?
                .iter()
                .map(|item| {
                    item.as_str().map(str::to_string).ok_or_else(|| {
                        validation_error(
                            "validation.input_field_invalid",
                            "Optional array field must contain only strings.",
                            json!({ "field": field }),
                        )
                    })
                })
                .collect()
        })
        .transpose()
}

fn optional_bool(input: &Value, field: &str) -> Result<Option<bool>, CapabilityError> {
    input
        .get(field)
        .filter(|value| !value.is_null())
        .map(|value| {
            value.as_bool().ok_or_else(|| {
                validation_error(
                    "validation.input_field_invalid",
                    "Optional input field must be a boolean.",
                    json!({ "field": field }),
                )
            })
        })
        .transpose()
}

fn optional_u64(input: &Value, field: &str) -> Result<Option<u64>, CapabilityError> {
    input
        .get(field)
        .filter(|value| !value.is_null())
        .map(|value| {
            value.as_u64().ok_or_else(|| {
                validation_error(
                    "validation.input_field_invalid",
                    "Optional input field must be an unsigned integer.",
                    json!({ "field": field }),
                )
            })
        })
        .transpose()
}

fn dry_run_result(
    invocation_id: String,
    operation: &str,
    details: Value,
) -> CapabilityInvocationResult {
    result(
        invocation_id,
        json!({
            "ok": true,
            "dry_run": true,
            "would_execute": true,
            "destructive": true,
            "operation": operation,
            "message": "Dry-run completed; no WebDAV request was sent.",
            "details": details
        }),
        json!({ "dry_run": true, "operation": operation }),
        None,
    )
}

fn write_result(
    invocation_id: String,
    operation: &str,
    details: Value,
) -> CapabilityInvocationResult {
    result(
        invocation_id,
        json!({
            "ok": true,
            "dry_run": false,
            "would_execute": false,
            "destructive": true,
            "operation": operation,
            "message": "WebDAV operation completed.",
            "details": details
        }),
        json!({ "ok": true, "operation": operation }),
        None,
    )
}

fn result(
    invocation_id: String,
    output: Value,
    output_summary: Value,
    page: Option<InvocationOutputPage>,
) -> CapabilityInvocationResult {
    CapabilityInvocationResult {
        invocation_id,
        status: InvocationStatus::Succeeded,
        output,
        output_summary,
        page,
    }
}

fn validation_error(code: &str, message: &str, details: Value) -> CapabilityError {
    capability_error(
        CapabilityErrorCategory::Validation,
        code,
        message,
        details,
        None,
        false,
    )
}

fn unavailable_error(code: &str, message: &str, details: Value) -> CapabilityError {
    capability_error(
        CapabilityErrorCategory::Unavailable,
        code,
        message,
        details,
        None,
        true,
    )
}

fn target_error(config: &WebDavConfig, code: &str, error: anyhow::Error) -> CapabilityError {
    let (message, redaction) = redact_webdav_target_message(error.to_string(), config);
    capability_error_with_redaction(
        CapabilityErrorCategory::TargetSystem,
        code,
        "WebDAV target operation failed.",
        Value::Null,
        Some(TargetSystemFailure {
            system: Some(PLUGIN_ID.to_string()),
            code: None,
            message: Some(message),
        }),
        false,
        redaction,
    )
}

fn local_path_error(local_scope_id: &str, error: LocalPathError) -> CapabilityError {
    capability_error_with_redaction(
        error.category(),
        error.code(),
        error.safe_message(),
        json!({
            "local_scope_id": local_scope_id,
            "access": "scan_directory",
        }),
        None,
        error.retryable(),
        RedactionStatus::Applied,
    )
}

fn redact_webdav_target_message(
    message: String,
    config: &WebDavConfig,
) -> (String, RedactionStatus) {
    let original = message.clone();
    let mut redacted = redact_url_auth(redact_url_auth(message, "http://"), "https://");

    redact_webdav_url(&mut redacted, &config.url);
    match &config.auth {
        WebDavAuth::None => {}
        WebDavAuth::Basic { username, password } | WebDavAuth::Digest { username, password } => {
            redact_value(&mut redacted, username);
            redact_value(&mut redacted, password);
        }
    }

    let status = if redacted != original {
        RedactionStatus::Applied
    } else {
        RedactionStatus::NotRequired
    };
    (redacted, status)
}

fn redact_value(message: &mut String, sensitive: &str) {
    if !sensitive.is_empty() {
        *message = message.replace(sensitive, "<redacted>");
    }
}

fn redact_webdav_url(message: &mut String, url: &str) {
    redact_value(message, url);
    let authority_and_path = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))
        .unwrap_or(url);
    let authority = authority_and_path
        .split('/')
        .next()
        .unwrap_or(authority_and_path);
    redact_value(message, authority);
}

fn redact_url_auth(mut message: String, scheme: &str) -> String {
    let mut search_from = 0;
    while let Some(relative_start) = message[search_from..].find(scheme) {
        let scheme_start = search_from + relative_start;
        let auth_start = scheme_start + scheme.len();
        let tail = &message[auth_start..];
        let slash = tail.find('/');
        let Some(at) = tail.find('@') else {
            search_from = auth_start;
            continue;
        };

        if slash.is_some_and(|slash| slash < at) {
            search_from = auth_start;
            continue;
        }

        let auth_end = auth_start + at;
        message.replace_range(auth_start..auth_end, "<redacted>");
        search_from = auth_start + "<redacted>@".len();
    }
    message
}

fn capability_error(
    category: CapabilityErrorCategory,
    code: &str,
    message: &str,
    details: Value,
    target: Option<TargetSystemFailure>,
    retryable: bool,
) -> CapabilityError {
    capability_error_with_redaction(
        category,
        code,
        message,
        details,
        target,
        retryable,
        RedactionStatus::NotRequired,
    )
}

fn capability_error_with_redaction(
    category: CapabilityErrorCategory,
    code: &str,
    message: &str,
    details: Value,
    target: Option<TargetSystemFailure>,
    retryable: bool,
    redaction: RedactionStatus,
) -> CapabilityError {
    CapabilityError {
        category,
        code: code.to_string(),
        message: message.to_string(),
        details,
        target,
        retryable,
        redaction,
    }
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use serde_json::json;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};
    use voidb_core::{
        CapabilityInvocation, InvocationConnectionTarget, InvocationControls, Pagination,
    };

    use super::*;

    struct LocalFixture(PathBuf);

    impl LocalFixture {
        fn new() -> Self {
            static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock after epoch")
                .as_nanos();
            let sequence = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "voidb-webdav-local-boundary-{}-{nonce}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&path).expect("create WebDAV local fixture");
            Self(path)
        }

        fn display(&self) -> String {
            self.0.to_string_lossy().into_owned()
        }
    }

    impl Drop for LocalFixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn catalog_marks_storage_writes_as_destructive_dry_run() {
        let capabilities = webdav_capabilities();
        for id in ["put", "delete", "mkdir"] {
            let capability = capabilities
                .iter()
                .find(|capability| capability.id == id)
                .expect("capability exists");
            assert!(capability.destructive);
            assert!(capability.supports_dry_run);
            assert!(
                capability
                    .permissions
                    .iter()
                    .any(|permission| permission == &format!("webdav.{}", id))
            );
        }

        let sync_plan = capabilities
            .iter()
            .find(|capability| capability.id == "sync_plan")
            .expect("sync_plan capability exists");
        assert!(!sync_plan.destructive);
        assert!(!sync_plan.supports_dry_run);
        assert!(!sync_plan.authorization.capability_wide_allowed);
        assert_eq!(
            sync_plan.input_schema["required"],
            json!(["remote_path", "local_root", "local_path"])
        );
        assert!(
            sync_plan
                .authorization
                .approval_schema
                .as_ref()
                .unwrap()
                .fields
                .iter()
                .any(|field| field.path == "/local_root" && field.required)
        );
    }

    #[test]
    fn sync_plan_output_withholds_local_paths_by_default() {
        let report = LocalScanReport {
            entries: vec![voidb_core::LocalScanEntry {
                relative_path: "private/name.txt".into(),
                is_dir: false,
                size: 4,
                modified: None,
            }],
            observed_depth: 2,
            observed_path_bytes: 16,
            limits: LocalScanLimits::default(),
        };
        let options = SyncOptions {
            mode: SyncMode::Push,
            delete_extra: false,
            dry_run: true,
            exclude: Vec::new(),
        };
        let plan = SyncPlan {
            changes: vec![crate::types::SyncChange {
                rel_path: "private/name.txt".into(),
                action: SyncAction::Upload,
                size: 4,
                is_dir: false,
            }],
            total_transfer_bytes: 4,
        };

        let output = sync_plan_output(
            "webdav",
            "/remote",
            "local-scope:invoke-test",
            &report,
            false,
            &options,
            plan,
        );
        let encoded = serde_json::to_string(&output).unwrap();
        assert!(!encoded.contains("private/name.txt"));
        assert_eq!(
            output["changes"][0]["entry_ref"],
            "local-scope:invoke-test:entry:1"
        );
        assert!(output["changes"][0]["relative_path"].is_null());
        assert!(output.get("local_path").is_none());
    }

    #[tokio::test]
    async fn local_filesystem_boundary_fixture_rejects_unapproved_webdav_scan_before_connect() {
        let fixture = LocalFixture::new();
        let error = invoke_webdav_capability(
            &WebDavConfig::default(),
            invocation(
                "sync_plan",
                json!({
                    "remote_path": "/remote",
                    "local_root": fixture.display(),
                    "local_path": "../outside",
                }),
            ),
        )
        .await
        .expect_err("traversal must fail before WebDAV access");
        let encoded = serde_json::to_string(&error).unwrap();

        assert_eq!(error.code, "permission.local_path_outside_scope");
        assert_eq!(error.redaction, RedactionStatus::Applied);
        assert!(!encoded.contains(&fixture.display()));
        assert!(!encoded.contains("../outside"));
    }

    #[test]
    fn local_filesystem_boundary_webdav_adapter_enforces_limits_and_policy_metadata() {
        let fixture = LocalFixture::new();
        fs::write(fixture.0.join("one.txt"), b"one").unwrap();
        fs::write(fixture.0.join("two.txt"), b"two").unwrap();
        let scope = LocalPathScope::new(&fixture.0).unwrap();
        assert_eq!(
            crate::sync_ops::walk_local_tree_scoped(
                &scope,
                ".",
                LocalScanLimits {
                    max_entries: 1,
                    ..LocalScanLimits::default()
                },
            )
            .unwrap_err(),
            LocalPathError::ScanLimitExceeded
        );

        let capability = webdav_capabilities()
            .into_iter()
            .find(|capability| capability.id == "sync_plan")
            .unwrap();
        assert!(capability.permissions.contains(&"local.scan".to_string()));
        assert!(!capability.authorization.capability_wide_allowed);
    }

    #[cfg(unix)]
    #[test]
    fn local_filesystem_boundary_webdav_adapter_rejects_symlink_fixture() {
        use std::os::unix::fs::symlink;

        let fixture = LocalFixture::new();
        let outside = LocalFixture::new();
        fs::write(outside.0.join("secret.txt"), b"secret").unwrap();
        symlink(outside.0.join("secret.txt"), fixture.0.join("alias.txt")).unwrap();
        let scope = LocalPathScope::new(&fixture.0).unwrap();

        assert_eq!(
            crate::sync_ops::walk_local_tree_scoped(&scope, ".", LocalScanLimits::default())
                .unwrap_err(),
            LocalPathError::LinkDenied
        );
    }

    #[tokio::test]
    async fn write_dry_runs_do_not_open_webdav_connection() {
        let config = WebDavConfig::default();

        let mut put = invocation(
            "put",
            json!({
                "path": "/agent/probe.txt",
                "content_text": "hello"
            }),
        );
        put.controls.dry_run = true;
        let put_result = invoke_webdav_capability(&config, put).await.unwrap();
        assert_eq!(put_result.output["dry_run"], true);
        assert_eq!(put_result.output["details"]["bytes"], 5);
        assert_eq!(
            put_result.output_summary,
            json!({ "dry_run": true, "operation": "put" })
        );
        let encoded = serde_json::to_string(&put_result).expect("serialize put result");
        assert!(!encoded.contains("hello"));

        let mut delete = invocation("delete", json!({ "path": "/agent/probe.txt" }));
        delete.controls.dry_run = true;
        let delete_result = invoke_webdav_capability(&config, delete).await.unwrap();
        assert_eq!(delete_result.output["operation"], "delete");
        assert_eq!(
            delete_result.output_summary,
            json!({ "dry_run": true, "operation": "delete" })
        );

        let mut mkdir = invocation("mkdir", json!({ "path": "/agent" }));
        mkdir.controls.dry_run = true;
        let mkdir_result = invoke_webdav_capability(&config, mkdir).await.unwrap();
        assert_eq!(mkdir_result.output["details"]["path"], "/agent");
        assert_eq!(
            mkdir_result.output_summary,
            json!({ "dry_run": true, "operation": "mkdir" })
        );
    }

    #[test]
    fn page_cursor_must_be_unsigned_offset() {
        let mut invocation = invocation("list", json!({ "path": "/" }));
        invocation.controls.page = Some(Pagination {
            limit: 10,
            cursor: Some("nope".into()),
        });
        let error = page_request(&invocation).unwrap_err();
        assert_eq!(error.code, "validation.invalid_cursor");
    }

    #[tokio::test]
    async fn transfer_and_lock_family_requires_a_persistent_session() {
        let capabilities = webdav_capabilities();
        for id in [
            "transfer",
            "transfer_status",
            "lock_acquire",
            "lock_release",
        ] {
            let capability = capabilities
                .iter()
                .find(|capability| capability.id == id)
                .expect("session capability");
            assert_eq!(
                capability.execution_mode,
                voidb_core::CapabilityExecutionMode::SessionOnly
            );
            assert_eq!(
                capability.session_handoff.as_ref().unwrap().purpose,
                voidb_core::PluginSessionPurpose::FileTransfer
            );
            if matches!(id, "transfer" | "transfer_status") {
                assert!(capability.output_schema.get("$defs").is_some());
            }
            let error =
                invoke_webdav_capability(&WebDavConfig::default(), invocation(id, json!({})))
                    .await
                    .unwrap_err();
            assert_eq!(error.code, "unavailable.session_required");
        }
    }

    #[test]
    fn target_error_redacts_webdav_credentials_and_url() {
        let config = WebDavConfig {
            url: "http://127.0.0.1:49152".into(),
            auth: WebDavAuth::Basic {
                username: "voidb-user".into(),
                password: "voidb-secret".into(),
            },
            timeout: 30,
            verify_ssl: false,
        };
        let error = target_error(
            &config,
            "webdav.list_failed",
            anyhow::anyhow!(
                "request failed for http://voidb-user:voidb-secret@127.0.0.1:49152/voidb-smoke with user voidb-user and password voidb-secret"
            ),
        );
        let encoded = serde_json::to_string(&error).expect("serialize error");

        assert_eq!(error.redaction, RedactionStatus::Applied);
        assert!(encoded.contains("<redacted>"));
        assert!(!encoded.contains("127.0.0.1:49152"));
        assert!(!encoded.contains("voidb-user"));
        assert!(!encoded.contains("voidb-secret"));
    }

    fn invocation(capability_id: &str, input: Value) -> CapabilityInvocation {
        CapabilityInvocation {
            id: "invoke-test".into(),
            plugin_id: PLUGIN_ID.into(),
            capability_id: capability_id.into(),
            connection: InvocationConnectionTarget::Stateless,
            input,
            controls: InvocationControls::default(),
            actor: None,
            requested_at: Utc::now(),
        }
    }
}
