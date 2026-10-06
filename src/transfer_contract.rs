//! Driver-free mapping from WebDAV semantics to the shared transfer lifecycle.

use voidb_core::{
    AGENT_TRANSFER_PROTOCOL_VERSION, AgentTransferChecksumAlgorithm, AgentTransferChunkMode,
    AgentTransferChunkPolicy, AgentTransferCleanupAction, AgentTransferCleanupPolicy,
    AgentTransferConflictPolicy, AgentTransferContract, AgentTransferLocalAccess,
    AgentTransferLocalPathPolicy, AgentTransferOperation, AgentTransferPrecondition,
    AgentTransferResumeMode, AgentTransferResumePolicy, AgentTransferRetryPolicy,
    MAX_AGENT_TRANSFER_CHUNKS,
};

/// Required WebDAV transfer behavior shared by future Agent sessions, CLI
/// streams, and the plugin-owned TUI.
///
/// Returning this descriptor does not advertise an executable capability. The
/// capability expansion slice must attach it only after the WebDAV service owns
/// range negotiation, lock lifetime, cancellation, resume binding, and cleanup.
pub fn webdav_transfer_contract() -> AgentTransferContract {
    AgentTransferContract {
        protocol_version: AGENT_TRANSFER_PROTOCOL_VERSION,
        target_kind: "webdav_resource".into(),
        operations: vec![
            AgentTransferOperation::Upload,
            AgentTransferOperation::Download,
            AgentTransferOperation::Copy,
            AgentTransferOperation::Move,
        ],
        chunking: AgentTransferChunkPolicy {
            modes: vec![
                AgentTransferChunkMode::Single,
                AgentTransferChunkMode::ByteRange,
            ],
            max_chunks: MAX_AGENT_TRANSFER_CHUNKS,
            max_parallel_chunks: 8,
        },
        checksums: vec![
            AgentTransferChecksumAlgorithm::Sha256,
            AgentTransferChecksumAlgorithm::Etag,
            AgentTransferChecksumAlgorithm::WebdavDigest,
        ],
        conflicts: vec![
            AgentTransferConflictPolicy::Fail,
            AgentTransferConflictPolicy::Skip,
            AgentTransferConflictPolicy::Replace,
        ],
        preconditions: vec![
            AgentTransferPrecondition::SourceMatch,
            AgentTransferPrecondition::DestinationAbsent,
            AgentTransferPrecondition::DestinationMatch,
            AgentTransferPrecondition::LockToken,
        ],
        retry: AgentTransferRetryPolicy {
            max_retries: 4,
            initial_backoff_ms: 250,
            max_backoff_ms: 30_000,
        },
        resume: AgentTransferResumePolicy {
            mode: AgentTransferResumeMode::BestEffort,
            max_token_bytes: 8 * 1024,
            token_ttl_seconds: 60 * 60,
            require_scope_fingerprint: true,
        },
        local_path: AgentTransferLocalPathPolicy {
            access: vec![
                AgentTransferLocalAccess::ReadFile,
                AgentTransferLocalAccess::CreateFile,
                AgentTransferLocalAccess::ReplaceFile,
                AgentTransferLocalAccess::ResumeTransfer,
            ],
            disclose_absolute_paths: false,
        },
        cleanup: AgentTransferCleanupPolicy {
            on_cancel: vec![
                AgentTransferCleanupAction::RemoveLocalStaging,
                AgentTransferCleanupAction::AbortRemotePartial,
                AgentTransferCleanupAction::ReleaseRemoteLock,
            ],
            on_failure: vec![
                AgentTransferCleanupAction::RemoveLocalStaging,
                AgentTransferCleanupAction::RetainBoundCheckpoint,
                AgentTransferCleanupAction::ReleaseRemoteLock,
            ],
            timeout_ms: 30_000,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_webdav_to_the_shared_transfer_contract() {
        let contract = webdav_transfer_contract();
        contract.validate().expect("valid WebDAV transfer contract");
        assert!(
            contract
                .preconditions
                .contains(&AgentTransferPrecondition::LockToken)
        );
        assert_eq!(contract.resume.mode, AgentTransferResumeMode::BestEffort);
        assert!(
            contract
                .cleanup
                .on_cancel
                .contains(&AgentTransferCleanupAction::ReleaseRemoteLock)
        );
        assert!(!contract.local_path.disclose_absolute_paths);
    }
}
