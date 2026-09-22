use std::{
    fs,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tauri::{State, ipc::InvokeBody};
use zeroize::Zeroizing;

use crate::{
    crypto::{Argon2Profile, MasterPassword, fill_random},
    vault::{
        AttachmentId, ItemDraft, ItemKind, ItemSummary, MAX_ATTACHMENT_BYTES, MAX_ATTACHMENT_COUNT,
        RecordId, TransferError, TransferObserver, UnlockedVault, VaultAttachment, VaultError,
        VaultItem, VaultRepository, cleanup_stale_import_artifacts, export_vault, import_vault,
        validate_attachment_input,
    },
};

#[cfg(target_os = "macos")]
use crate::file_panel::{self, PanelOutcome};

const VAULT_DIRECTORY_NAME: &str = "vault";
const VAULT_FILE_NAME: &str = "aeterna-vault.sqlite3";
const UPLOAD_HEADER: &str = "x-aeterna-upload-id";
const UPLOAD_TTL: Duration = Duration::from_secs(300);
const TRANSFER_TTL: Duration = Duration::from_secs(300);
const DEVELOPMENT_ARGON2_PROFILE: Argon2Profile = Argon2Profile::new(262_144, 2, 1);

pub(crate) struct VaultAppState {
    path: PathBuf,
    inner: Mutex<AppStateInner>,
}

struct AppStateInner {
    session: SessionState,
    pending_upload: Option<PendingUpload>,
    selection: Option<FileSelection>,
    transfer: Option<TransferOperation>,
    session_epoch: u64,
}

enum SessionState {
    Uninitialized,
    Locked(VaultRepository),
    Unlocked {
        repository: VaultRepository,
        vault: Arc<UnlockedVault>,
    },
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum TransferKind {
    Export,
    Import,
}

struct FileSelection {
    id: [u8; 16],
    kind: TransferKind,
    path: PathBuf,
    session_epoch: u64,
    expires_at: Instant,
}

struct TransferOperation {
    id: [u8; 16],
    kind: TransferKind,
    reporter: TransferReporter,
    handle: Option<JoinHandle<()>>,
}

#[derive(Clone)]
struct TransferReporter {
    cancel: Arc<AtomicBool>,
    progress: Arc<Mutex<TransferProgress>>,
}

struct TransferProgress {
    state: &'static str,
    phase: &'static str,
    bytes: u64,
    entries: u64,
    cancellable: bool,
    error: Option<TransferError>,
    terminal_at: Option<Instant>,
}

impl TransferReporter {
    fn new() -> Self {
        Self {
            cancel: Arc::new(AtomicBool::new(false)),
            progress: Arc::new(Mutex::new(TransferProgress {
                state: "running",
                phase: "preparing",
                bytes: 0,
                entries: 0,
                cancellable: true,
                error: None,
                terminal_at: None,
            })),
        }
    }

    fn finish(&self, result: Result<(), TransferError>) {
        let Ok(mut progress) = self.progress.lock() else {
            return;
        };
        progress.cancellable = false;
        progress.terminal_at = Some(Instant::now());
        match result {
            Ok(()) => {
                progress.state = "completed";
                progress.phase = "completed";
            }
            Err(TransferError::Cancelled) => {
                progress.state = "cancelled";
                progress.phase = "cancelled";
                progress.error = Some(TransferError::Cancelled);
            }
            Err(error) => {
                progress.state = "failed";
                progress.phase = "failed";
                progress.error = Some(error);
            }
        }
    }
}

impl TransferObserver for TransferReporter {
    fn update(&self, phase: &'static str, bytes: u64, entries: u64, cancellable: bool) {
        let Ok(mut progress) = self.progress.lock() else {
            return;
        };
        if progress.terminal_at.is_some() {
            return;
        }
        progress.phase = phase;
        progress.bytes = progress.bytes.max(bytes);
        progress.entries = progress.entries.max(entries);
        progress.cancellable = cancellable;
        if phase == "cancelling" {
            progress.state = "cancelling";
        }
    }

    fn is_cancelled(&self) -> bool {
        self.cancel.load(Ordering::Acquire)
    }
}

struct PendingUpload {
    upload_id: [u8; 16],
    item_id: RecordId,
    expected_revision: u64,
    operation: UploadOperation,
    filename: Zeroizing<String>,
    media_type: Zeroizing<String>,
    byte_length: usize,
    expires_at: Instant,
}

enum UploadOperation {
    Add,
    Replace(AttachmentId),
}

impl core::fmt::Debug for VaultAppState {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("VaultAppState([REDACTED])")
    }
}

impl VaultAppState {
    pub(crate) fn load(app_local_data_directory: &Path) -> Result<Self, VaultError> {
        let path = app_local_data_directory
            .join(VAULT_DIRECTORY_NAME)
            .join(VAULT_FILE_NAME);
        cleanup_stale_import_artifacts(&path);
        let session = if path.try_exists().map_err(|_| VaultError::Io)? {
            SessionState::Locked(VaultRepository::open(&path)?)
        } else {
            SessionState::Uninitialized
        };
        Ok(Self {
            path,
            inner: Mutex::new(AppStateInner {
                session,
                pending_upload: None,
                selection: None,
                transfer: None,
                session_epoch: 0,
            }),
        })
    }

    fn lock(&self) -> Result<MutexGuard<'_, AppStateInner>, IpcError> {
        self.inner
            .lock()
            .map_err(|_| IpcError::from(VaultError::Internal))
    }
}

#[derive(Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct IpcError {
    code: &'static str,
}

impl From<VaultError> for IpcError {
    fn from(error: VaultError) -> Self {
        Self { code: error.code() }
    }
}

impl From<TransferError> for IpcError {
    fn from(error: TransferError) -> Self {
        Self { code: error.code() }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EmptyRequest {}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PasswordRequest {
    password: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ItemIdRequest {
    item_id: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ItemMutationRequest {
    item_id: String,
    expected_revision: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ItemDraftRequest {
    kind: ItemKindRequest,
    title: String,
    category: String,
    contact_explanation: String,
    body: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct UpdateItemRequest {
    item_id: String,
    expected_revision: String,
    kind: ItemKindRequest,
    title: String,
    category: String,
    contact_explanation: String,
    body: String,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
enum ItemKindRequest {
    Note,
    Instruction,
}

impl From<ItemKindRequest> for ItemKind {
    fn from(value: ItemKindRequest) -> Self {
        match value {
            ItemKindRequest::Note => Self::Note,
            ItemKindRequest::Instruction => Self::Instruction,
        }
    }
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
enum UploadOperationRequest {
    Add,
    Replace,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PrepareAttachmentRequest {
    item_id: String,
    expected_revision: String,
    operation: UploadOperationRequest,
    attachment_id: Option<String>,
    filename: String,
    media_type: String,
    byte_length: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct UploadIdRequest {
    upload_id: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SelectionIdRequest {
    selection_id: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ImportStartRequest {
    selection_id: String,
    password: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct OperationIdRequest {
    operation_id: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AttachmentRequest {
    item_id: String,
    attachment_id: String,
    expected_revision: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct StatusResponse {
    state: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DeleteResponse {
    deleted: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CancelResponse {
    cancelled: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PrepareAttachmentResponse {
    upload_id: String,
    expires_in_seconds: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase", tag = "outcome")]
pub(crate) enum SelectionResponse {
    #[serde(rename = "selected")]
    Selected {
        #[serde(rename = "selectionId")]
        selection_id: String,
    },
    #[serde(rename = "cancelled")]
    Cancelled,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct StartTransferResponse {
    operation_id: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct TransferStatusResponse {
    kind: &'static str,
    state: &'static str,
    phase: &'static str,
    bytes_processed: String,
    entries_processed: String,
    cancellable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    error_code: Option<&'static str>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CancelTransferResponse {
    state: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ItemListResponse {
    items: Vec<ItemSummaryResponse>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ItemResponseEnvelope {
    item: VaultItemResponse,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ItemSummaryResponse {
    item_id: String,
    revision: String,
    kind: &'static str,
    title: String,
    category: String,
    attachment_count: usize,
    created_at_ms: String,
    updated_at_ms: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct VaultItemResponse {
    item_id: String,
    revision: String,
    kind: &'static str,
    title: String,
    category: String,
    contact_explanation: String,
    body: String,
    attachments: Vec<AttachmentResponse>,
    created_at_ms: String,
    updated_at_ms: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AttachmentResponse {
    attachment_id: String,
    filename: String,
    media_type: String,
    byte_length: String,
}

#[tauri::command]
pub(crate) fn vault_status(
    request: tauri::ipc::Request<'_>,
    state: State<'_, VaultAppState>,
) -> Result<StatusResponse, IpcError> {
    vault_status_impl(request.body(), state.inner())
}

fn vault_status_impl(body: &InvokeBody, state: &VaultAppState) -> Result<StatusResponse, IpcError> {
    parse_json::<EmptyRequest>(body)?;
    let mut inner = state.lock()?;
    reconcile_transfer(&mut inner, &state.path)?;
    clear_expired_selection(&mut inner);
    Ok(StatusResponse {
        state: state_name(&inner.session),
    })
}

#[tauri::command]
pub(crate) fn vault_initialize(
    request: tauri::ipc::Request<'_>,
    state: State<'_, VaultAppState>,
) -> Result<StatusResponse, IpcError> {
    vault_initialize_impl(request.body(), state.inner())
}

fn vault_initialize_impl(
    body: &InvokeBody,
    state: &VaultAppState,
) -> Result<StatusResponse, IpcError> {
    let request = parse_json::<PasswordRequest>(body)?;
    let password = MasterPassword::new(request.password.into_bytes()).map_err(VaultError::from)?;
    let mut inner = state.lock()?;
    prepare_new_transfer(&mut inner, &state.path)?;
    if !matches!(inner.session, SessionState::Uninitialized) {
        return Err(VaultError::AlreadyInitialized.into());
    }
    ensure_vault_directory(&state.path)?;
    let bootstrap = VaultRepository::initialize(&state.path, &password, DEVELOPMENT_ARGON2_PROFILE)
        .map_err(|error| {
            if error == VaultError::AlreadyExists {
                IpcError::from(VaultError::AlreadyInitialized)
            } else {
                IpcError::from(error)
            }
        })?;
    let (repository, recovery_material) = bootstrap.into_parts();
    drop(recovery_material);
    let vault = Arc::new(repository.unlock(&password)?);
    inner.session = SessionState::Unlocked { repository, vault };
    inner.pending_upload = None;
    inner.selection = None;
    inner.session_epoch = inner.session_epoch.wrapping_add(1);
    Ok(StatusResponse { state: "unlocked" })
}

#[tauri::command]
pub(crate) fn vault_unlock(
    request: tauri::ipc::Request<'_>,
    state: State<'_, VaultAppState>,
) -> Result<StatusResponse, IpcError> {
    vault_unlock_impl(request.body(), state.inner())
}

fn vault_unlock_impl(body: &InvokeBody, state: &VaultAppState) -> Result<StatusResponse, IpcError> {
    let request = parse_json::<PasswordRequest>(body)?;
    let password = MasterPassword::new(request.password.into_bytes()).map_err(VaultError::from)?;
    let mut inner = state.lock()?;
    let repository = match &inner.session {
        SessionState::Uninitialized => return Err(VaultError::Uninitialized.into()),
        SessionState::Locked(repository) => repository.clone(),
        SessionState::Unlocked { .. } => return Err(VaultError::InvalidInput.into()),
    };
    let vault = Arc::new(repository.unlock(&password)?);
    inner.session = SessionState::Unlocked { repository, vault };
    inner.pending_upload = None;
    inner.selection = None;
    inner.session_epoch = inner.session_epoch.wrapping_add(1);
    Ok(StatusResponse { state: "unlocked" })
}

#[tauri::command]
pub(crate) fn vault_lock(
    request: tauri::ipc::Request<'_>,
    state: State<'_, VaultAppState>,
) -> Result<StatusResponse, IpcError> {
    vault_lock_impl(request.body(), state.inner())
}

fn vault_lock_impl(body: &InvokeBody, state: &VaultAppState) -> Result<StatusResponse, IpcError> {
    parse_json::<EmptyRequest>(body)?;
    let mut inner = state.lock()?;
    let replacement = match &inner.session {
        SessionState::Uninitialized => return Err(VaultError::Uninitialized.into()),
        SessionState::Locked(_) => None,
        SessionState::Unlocked { repository, .. } => Some(repository.clone()),
    };
    if let Some(repository) = replacement {
        inner.session = SessionState::Locked(repository);
        inner.pending_upload = None;
        inner.selection = None;
        inner.session_epoch = inner.session_epoch.wrapping_add(1);
        let handle = if let Some(transfer) = inner.transfer.as_mut() {
            if transfer.kind == TransferKind::Export {
                transfer.reporter.cancel.store(true, Ordering::Release);
                transfer.reporter.update("cancelling", 0, 0, false);
                transfer.handle.take()
            } else {
                None
            }
        } else {
            None
        };
        if let Some(handle) = handle {
            drop(inner);
            let _ = handle.join();
            return Ok(StatusResponse { state: "locked" });
        }
    } else {
        inner.pending_upload = None;
        inner.selection = None;
        inner.session_epoch = inner.session_epoch.wrapping_add(1);
    }
    Ok(StatusResponse { state: "locked" })
}

#[tauri::command]
pub(crate) fn vault_list_items(
    request: tauri::ipc::Request<'_>,
    state: State<'_, VaultAppState>,
) -> Result<ItemListResponse, IpcError> {
    vault_list_items_impl(request.body(), state.inner())
}

fn vault_list_items_impl(
    body: &InvokeBody,
    state: &VaultAppState,
) -> Result<ItemListResponse, IpcError> {
    parse_json::<EmptyRequest>(body)?;
    let inner = state.lock()?;
    let vault = unlocked(&inner.session)?;
    let items = vault
        .list_items()?
        .into_iter()
        .map(summary_response)
        .collect();
    Ok(ItemListResponse { items })
}

#[tauri::command]
pub(crate) fn vault_get_item(
    request: tauri::ipc::Request<'_>,
    state: State<'_, VaultAppState>,
) -> Result<ItemResponseEnvelope, IpcError> {
    vault_get_item_impl(request.body(), state.inner())
}

fn vault_get_item_impl(
    body: &InvokeBody,
    state: &VaultAppState,
) -> Result<ItemResponseEnvelope, IpcError> {
    let request = parse_json::<ItemIdRequest>(body)?;
    let item_id = parse_record_id(&request.item_id)?;
    let inner = state.lock()?;
    let item = unlocked(&inner.session)?.get_item(item_id)?;
    Ok(ItemResponseEnvelope {
        item: item_response(&item),
    })
}

#[tauri::command]
pub(crate) fn vault_create_item(
    request: tauri::ipc::Request<'_>,
    state: State<'_, VaultAppState>,
) -> Result<ItemResponseEnvelope, IpcError> {
    vault_create_item_impl(request.body(), state.inner())
}

fn vault_create_item_impl(
    body: &InvokeBody,
    state: &VaultAppState,
) -> Result<ItemResponseEnvelope, IpcError> {
    let request = parse_json::<ItemDraftRequest>(body)?;
    let draft = draft_from_request(
        request.kind,
        request.title,
        request.category,
        request.contact_explanation,
        request.body,
    )?;
    let inner = state.lock()?;
    let item = unlocked(&inner.session)?.create_item(draft)?;
    Ok(ItemResponseEnvelope {
        item: item_response(&item),
    })
}

#[tauri::command]
pub(crate) fn vault_update_item(
    request: tauri::ipc::Request<'_>,
    state: State<'_, VaultAppState>,
) -> Result<ItemResponseEnvelope, IpcError> {
    vault_update_item_impl(request.body(), state.inner())
}

fn vault_update_item_impl(
    body: &InvokeBody,
    state: &VaultAppState,
) -> Result<ItemResponseEnvelope, IpcError> {
    let request = parse_json::<UpdateItemRequest>(body)?;
    let item_id = parse_record_id(&request.item_id)?;
    let expected_revision = parse_positive_decimal(&request.expected_revision)?;
    let draft = draft_from_request(
        request.kind,
        request.title,
        request.category,
        request.contact_explanation,
        request.body,
    )?;
    let inner = state.lock()?;
    let item = unlocked(&inner.session)?.update_item(item_id, expected_revision, draft)?;
    Ok(ItemResponseEnvelope {
        item: item_response(&item),
    })
}

#[tauri::command]
pub(crate) fn vault_delete_item(
    request: tauri::ipc::Request<'_>,
    state: State<'_, VaultAppState>,
) -> Result<DeleteResponse, IpcError> {
    vault_delete_item_impl(request.body(), state.inner())
}

fn vault_delete_item_impl(
    body: &InvokeBody,
    state: &VaultAppState,
) -> Result<DeleteResponse, IpcError> {
    let request = parse_json::<ItemMutationRequest>(body)?;
    let item_id = parse_record_id(&request.item_id)?;
    let expected_revision = parse_positive_decimal(&request.expected_revision)?;
    let inner = state.lock()?;
    unlocked(&inner.session)?.delete_item(item_id, expected_revision)?;
    Ok(DeleteResponse { deleted: true })
}

#[tauri::command]
pub(crate) fn vault_prepare_attachment(
    request: tauri::ipc::Request<'_>,
    state: State<'_, VaultAppState>,
) -> Result<PrepareAttachmentResponse, IpcError> {
    vault_prepare_attachment_impl(request.body(), state.inner())
}

fn vault_prepare_attachment_impl(
    body: &InvokeBody,
    state: &VaultAppState,
) -> Result<PrepareAttachmentResponse, IpcError> {
    let request = parse_json::<PrepareAttachmentRequest>(body)?;
    let item_id = parse_record_id(&request.item_id)?;
    let expected_revision = parse_positive_decimal(&request.expected_revision)?;
    let byte_length = parse_nonnegative_decimal_usize(&request.byte_length)?;
    validate_attachment_input(
        &request.filename,
        &request.media_type,
        byte_length,
        VaultError::InvalidInput,
    )?;
    let operation = match (request.operation, request.attachment_id) {
        (UploadOperationRequest::Add, None) => UploadOperation::Add,
        (UploadOperationRequest::Replace, Some(value)) => {
            UploadOperation::Replace(parse_attachment_id(&value)?)
        }
        _ => return Err(invalid_request()),
    };

    let mut inner = state.lock()?;
    clear_expired_upload(&mut inner);
    if inner.pending_upload.is_some() {
        return Err(VaultError::UploadPending.into());
    }
    let vault = unlocked(&inner.session)?;
    let item = vault.get_item(item_id)?;
    if item.revision != expected_revision {
        return Err(VaultError::Conflict.into());
    }
    validate_prepared_operation(&item, &operation, byte_length)?;

    let mut upload_id = [0_u8; 16];
    fill_random(&mut upload_id).map_err(VaultError::from)?;
    inner.pending_upload = Some(PendingUpload {
        upload_id,
        item_id,
        expected_revision,
        operation,
        filename: Zeroizing::new(request.filename),
        media_type: Zeroizing::new(request.media_type),
        byte_length,
        expires_at: Instant::now() + UPLOAD_TTL,
    });
    Ok(PrepareAttachmentResponse {
        upload_id: encode_hex(upload_id),
        expires_in_seconds: UPLOAD_TTL.as_secs(),
    })
}

#[tauri::command]
pub(crate) fn vault_commit_attachment(
    request: tauri::ipc::Request<'_>,
    state: State<'_, VaultAppState>,
) -> Result<ItemResponseEnvelope, IpcError> {
    vault_commit_attachment_impl(request.body(), request.headers(), state.inner())
}

fn vault_commit_attachment_impl(
    body: &InvokeBody,
    headers: &tauri::http::HeaderMap,
    state: &VaultAppState,
) -> Result<ItemResponseEnvelope, IpcError> {
    let supplied_upload_id = headers
        .get(UPLOAD_HEADER)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(invalid_request)
        .and_then(parse_hex_id);

    let mut inner = state.lock()?;
    clear_expired_upload(&mut inner);
    unlocked(&inner.session)?;
    let pending = inner
        .pending_upload
        .take()
        .ok_or_else(|| IpcError::from(VaultError::UploadNotFound))?;
    let upload_id = supplied_upload_id?;
    if pending.upload_id != upload_id {
        return Err(VaultError::UploadNotFound.into());
    }
    let InvokeBody::Raw(content) = body else {
        return Err(invalid_request());
    };
    if content.len() != pending.byte_length {
        return Err(invalid_request());
    }
    if content.len() > MAX_ATTACHMENT_BYTES {
        return Err(VaultError::AttachmentTooLarge.into());
    }
    let vault = unlocked(&inner.session)?;
    let item = match pending.operation {
        UploadOperation::Add => vault.add_attachment(
            pending.item_id,
            pending.expected_revision,
            take_zeroizing_string(pending.filename),
            take_zeroizing_string(pending.media_type),
            content.to_vec(),
        )?,
        UploadOperation::Replace(attachment_id) => vault.replace_attachment(
            pending.item_id,
            pending.expected_revision,
            attachment_id,
            take_zeroizing_string(pending.filename),
            take_zeroizing_string(pending.media_type),
            content.to_vec(),
        )?,
    };
    Ok(ItemResponseEnvelope {
        item: item_response(&item),
    })
}

#[tauri::command]
pub(crate) fn vault_cancel_attachment(
    request: tauri::ipc::Request<'_>,
    state: State<'_, VaultAppState>,
) -> Result<CancelResponse, IpcError> {
    vault_cancel_attachment_impl(request.body(), state.inner())
}

fn vault_cancel_attachment_impl(
    body: &InvokeBody,
    state: &VaultAppState,
) -> Result<CancelResponse, IpcError> {
    let request = parse_json::<UploadIdRequest>(body)?;
    let upload_id = parse_hex_id(&request.upload_id)?;
    let mut inner = state.lock()?;
    unlocked(&inner.session)?;
    clear_expired_upload(&mut inner);
    let matching = inner
        .pending_upload
        .as_ref()
        .is_some_and(|pending| pending.upload_id == upload_id);
    if !matching {
        return Err(VaultError::UploadNotFound.into());
    }
    inner.pending_upload = None;
    Ok(CancelResponse { cancelled: true })
}

#[tauri::command]
pub(crate) fn vault_read_attachment(
    request: tauri::ipc::Request<'_>,
    state: State<'_, VaultAppState>,
) -> Result<tauri::ipc::Response, IpcError> {
    vault_read_attachment_impl(request.body(), state.inner()).map(tauri::ipc::Response::new)
}

fn vault_read_attachment_impl(
    body: &InvokeBody,
    state: &VaultAppState,
) -> Result<Vec<u8>, IpcError> {
    let request = parse_json::<AttachmentRequest>(body)?;
    let item_id = parse_record_id(&request.item_id)?;
    let attachment_id = parse_attachment_id(&request.attachment_id)?;
    let expected_revision = parse_positive_decimal(&request.expected_revision)?;
    let inner = state.lock()?;
    let content =
        unlocked(&inner.session)?.read_attachment(item_id, expected_revision, attachment_id)?;
    Ok(content.to_vec())
}

#[tauri::command]
pub(crate) fn vault_remove_attachment(
    request: tauri::ipc::Request<'_>,
    state: State<'_, VaultAppState>,
) -> Result<ItemResponseEnvelope, IpcError> {
    vault_remove_attachment_impl(request.body(), state.inner())
}

fn vault_remove_attachment_impl(
    body: &InvokeBody,
    state: &VaultAppState,
) -> Result<ItemResponseEnvelope, IpcError> {
    let request = parse_json::<AttachmentRequest>(body)?;
    let item_id = parse_record_id(&request.item_id)?;
    let attachment_id = parse_attachment_id(&request.attachment_id)?;
    let expected_revision = parse_positive_decimal(&request.expected_revision)?;
    let inner = state.lock()?;
    let item =
        unlocked(&inner.session)?.remove_attachment(item_id, expected_revision, attachment_id)?;
    Ok(ItemResponseEnvelope {
        item: item_response(&item),
    })
}

#[tauri::command]
pub(crate) fn vault_export_choose(
    request: tauri::ipc::Request<'_>,
    state: State<'_, VaultAppState>,
) -> Result<SelectionResponse, IpcError> {
    parse_json::<EmptyRequest>(request.body())?;
    choose_file(state.inner(), TransferKind::Export)
}

#[tauri::command]
pub(crate) fn vault_import_choose(
    request: tauri::ipc::Request<'_>,
    state: State<'_, VaultAppState>,
) -> Result<SelectionResponse, IpcError> {
    parse_json::<EmptyRequest>(request.body())?;
    choose_file(state.inner(), TransferKind::Import)
}

#[tauri::command]
pub(crate) fn vault_export_start(
    request: tauri::ipc::Request<'_>,
    state: State<'_, VaultAppState>,
) -> Result<StartTransferResponse, IpcError> {
    vault_export_start_impl(request.body(), state.inner())
}

fn vault_export_start_impl(
    body: &InvokeBody,
    state: &VaultAppState,
) -> Result<StartTransferResponse, IpcError> {
    let request = parse_json::<SelectionIdRequest>(body)?;
    let selection_id = parse_hex_id(&request.selection_id)?;
    let mut inner = state.lock()?;
    prepare_new_transfer(&mut inner, &state.path)?;
    let selection = consume_selection(&mut inner, selection_id, TransferKind::Export)?;
    let vault = match &inner.session {
        SessionState::Unlocked { vault, .. } => Arc::clone(vault),
        SessionState::Locked(_) => return Err(VaultError::Locked.into()),
        SessionState::Uninitialized => return Err(VaultError::Uninitialized.into()),
    };
    if selection.session_epoch != inner.session_epoch {
        return Err(IpcError {
            code: "vault_selection_not_found",
        });
    }
    let operation_id = random_identifier()?;
    let reporter = TransferReporter::new();
    let worker_reporter = reporter.clone();
    let path = selection.path;
    let handle = thread::Builder::new()
        .name("aeterna-export".to_owned())
        .spawn(move || {
            let result = export_vault(&vault, &path, &worker_reporter);
            worker_reporter.finish(result);
        })
        .map_err(|_| IpcError::from(VaultError::Io))?;
    inner.transfer = Some(TransferOperation {
        id: operation_id,
        kind: TransferKind::Export,
        reporter,
        handle: Some(handle),
    });
    Ok(StartTransferResponse {
        operation_id: encode_hex(operation_id),
    })
}

#[tauri::command]
pub(crate) fn vault_import_start(
    request: tauri::ipc::Request<'_>,
    state: State<'_, VaultAppState>,
) -> Result<StartTransferResponse, IpcError> {
    vault_import_start_impl(request.body(), state.inner())
}

fn vault_import_start_impl(
    body: &InvokeBody,
    state: &VaultAppState,
) -> Result<StartTransferResponse, IpcError> {
    let request = parse_json::<ImportStartRequest>(body)?;
    let selection_id = parse_hex_id(&request.selection_id)?;
    let password = MasterPassword::new(request.password.into_bytes()).map_err(VaultError::from)?;
    let mut inner = state.lock()?;
    prepare_new_transfer(&mut inner, &state.path)?;
    if !matches!(inner.session, SessionState::Uninitialized) {
        return Err(VaultError::AlreadyInitialized.into());
    }
    let selection = consume_selection(&mut inner, selection_id, TransferKind::Import)?;
    if selection.session_epoch != inner.session_epoch {
        return Err(IpcError {
            code: "vault_selection_not_found",
        });
    }
    ensure_vault_directory(&state.path)?;
    let operation_id = random_identifier()?;
    let reporter = TransferReporter::new();
    let worker_reporter = reporter.clone();
    let path = selection.path;
    let target = state.path.clone();
    let handle = thread::Builder::new()
        .name("aeterna-import".to_owned())
        .spawn(move || {
            let result = import_vault(&path, &target, &password, &worker_reporter);
            worker_reporter.finish(result);
        })
        .map_err(|_| IpcError::from(VaultError::Io))?;
    inner.transfer = Some(TransferOperation {
        id: operation_id,
        kind: TransferKind::Import,
        reporter,
        handle: Some(handle),
    });
    Ok(StartTransferResponse {
        operation_id: encode_hex(operation_id),
    })
}

#[tauri::command]
pub(crate) fn vault_transfer_status(
    request: tauri::ipc::Request<'_>,
    state: State<'_, VaultAppState>,
) -> Result<TransferStatusResponse, IpcError> {
    vault_transfer_status_impl(request.body(), state.inner())
}

fn vault_transfer_status_impl(
    body: &InvokeBody,
    state: &VaultAppState,
) -> Result<TransferStatusResponse, IpcError> {
    let request = parse_json::<OperationIdRequest>(body)?;
    let operation_id = parse_hex_id(&request.operation_id)?;
    let mut inner = state.lock()?;
    reconcile_transfer(&mut inner, &state.path)?;
    let transfer = inner.transfer.as_ref().ok_or(IpcError {
        code: "vault_operation_not_found",
    })?;
    if transfer.id != operation_id {
        return Err(IpcError {
            code: "vault_operation_not_found",
        });
    }
    let progress = transfer
        .reporter
        .progress
        .lock()
        .map_err(|_| IpcError::from(VaultError::Internal))?;
    Ok(TransferStatusResponse {
        kind: transfer_kind_name(transfer.kind),
        state: progress.state,
        phase: progress.phase,
        bytes_processed: progress.bytes.to_string(),
        entries_processed: progress.entries.to_string(),
        cancellable: progress.cancellable,
        error_code: progress.error.map(TransferError::code),
    })
}

#[tauri::command]
pub(crate) fn vault_transfer_cancel(
    request: tauri::ipc::Request<'_>,
    state: State<'_, VaultAppState>,
) -> Result<CancelTransferResponse, IpcError> {
    vault_transfer_cancel_impl(request.body(), state.inner())
}

fn vault_transfer_cancel_impl(
    body: &InvokeBody,
    state: &VaultAppState,
) -> Result<CancelTransferResponse, IpcError> {
    let request = parse_json::<OperationIdRequest>(body)?;
    let operation_id = parse_hex_id(&request.operation_id)?;
    let mut inner = state.lock()?;
    reconcile_transfer(&mut inner, &state.path)?;
    let transfer = inner.transfer.as_mut().ok_or(IpcError {
        code: "vault_operation_not_found",
    })?;
    if transfer.id != operation_id {
        return Err(IpcError {
            code: "vault_operation_not_found",
        });
    }
    {
        let progress = transfer
            .reporter
            .progress
            .lock()
            .map_err(|_| IpcError::from(VaultError::Internal))?;
        if !progress.cancellable || progress.terminal_at.is_some() {
            return Err(IpcError {
                code: "vault_operation_not_cancellable",
            });
        }
    }
    transfer.reporter.cancel.store(true, Ordering::Release);
    transfer.reporter.update("cancelling", 0, 0, false);
    Ok(CancelTransferResponse {
        state: "cancelling",
    })
}

fn choose_file(state: &VaultAppState, kind: TransferKind) -> Result<SelectionResponse, IpcError> {
    let epoch = {
        let mut inner = state.lock()?;
        prepare_new_transfer(&mut inner, &state.path)?;
        match (kind, &inner.session) {
            (TransferKind::Export, SessionState::Unlocked { .. })
            | (TransferKind::Import, SessionState::Uninitialized) => {}
            (TransferKind::Export, SessionState::Locked(_)) => {
                return Err(VaultError::Locked.into());
            }
            (TransferKind::Export, SessionState::Uninitialized) => {
                return Err(VaultError::Uninitialized.into());
            }
            (TransferKind::Import, _) => return Err(VaultError::AlreadyInitialized.into()),
        }
        inner.selection = None;
        inner.session_epoch
    };

    #[cfg(target_os = "macos")]
    let outcome = match kind {
        TransferKind::Export => file_panel::choose_export(),
        TransferKind::Import => file_panel::choose_import(),
    }
    .map_err(|_| IpcError {
        code: "vault_path_rejected",
    })?;
    #[cfg(not(target_os = "macos"))]
    let outcome: Result<(), IpcError> = Err(IpcError {
        code: "vault_platform_unsupported",
    });

    #[cfg(not(target_os = "macos"))]
    {
        let _ = outcome?;
        unreachable!()
    }
    #[cfg(target_os = "macos")]
    match outcome {
        PanelOutcome::Cancelled => Ok(SelectionResponse::Cancelled),
        PanelOutcome::Selected(path) => {
            let id = random_identifier()?;
            let mut inner = state.lock()?;
            if inner.session_epoch != epoch || inner.transfer.is_some() {
                return Err(IpcError {
                    code: "vault_selection_not_found",
                });
            }
            inner.selection = Some(FileSelection {
                id,
                kind,
                path,
                session_epoch: epoch,
                expires_at: Instant::now() + TRANSFER_TTL,
            });
            Ok(SelectionResponse::Selected {
                selection_id: encode_hex(id),
            })
        }
    }
}

fn consume_selection(
    inner: &mut AppStateInner,
    selection_id: [u8; 16],
    kind: TransferKind,
) -> Result<FileSelection, IpcError> {
    clear_expired_selection(inner);
    let matches = inner
        .selection
        .as_ref()
        .is_some_and(|selection| selection.id == selection_id);
    if !matches {
        return Err(IpcError {
            code: "vault_selection_not_found",
        });
    }
    let selection = inner.selection.take().ok_or(IpcError {
        code: "vault_selection_not_found",
    })?;
    if selection.kind != kind || selection.expires_at <= Instant::now() {
        return Err(IpcError {
            code: "vault_selection_not_found",
        });
    }
    Ok(selection)
}

fn prepare_new_transfer(inner: &mut AppStateInner, path: &Path) -> Result<(), IpcError> {
    reconcile_transfer(inner, path)?;
    let terminal = inner.transfer.as_ref().is_some_and(|transfer| {
        transfer
            .reporter
            .progress
            .lock()
            .is_ok_and(|progress| progress.terminal_at.is_some())
    });
    if terminal
        && let Some(mut transfer) = inner.transfer.take()
        && let Some(handle) = transfer.handle.take()
    {
        let _ = handle.join();
    }
    if inner.transfer.is_some() {
        return Err(IpcError {
            code: "vault_operation_in_progress",
        });
    }
    Ok(())
}

fn reconcile_transfer(inner: &mut AppStateInner, path: &Path) -> Result<(), IpcError> {
    let completed_import = inner.transfer.as_ref().is_some_and(|transfer| {
        transfer.kind == TransferKind::Import
            && transfer
                .reporter
                .progress
                .lock()
                .is_ok_and(|progress| progress.state == "completed")
    });
    if completed_import && matches!(inner.session, SessionState::Uninitialized) {
        inner.session = SessionState::Locked(VaultRepository::open(path)?);
        inner.session_epoch = inner.session_epoch.wrapping_add(1);
        inner.selection = None;
    }
    let expired = inner.transfer.as_ref().is_some_and(|transfer| {
        transfer.reporter.progress.lock().is_ok_and(|progress| {
            progress
                .terminal_at
                .is_some_and(|finished| finished + TRANSFER_TTL <= Instant::now())
        })
    });
    if expired {
        if let Some(mut transfer) = inner.transfer.take()
            && let Some(handle) = transfer.handle.take()
        {
            let _ = handle.join();
        }
        return Ok(());
    }
    let Some(transfer) = inner.transfer.as_mut() else {
        return Ok(());
    };
    if transfer
        .handle
        .as_ref()
        .is_some_and(JoinHandle::is_finished)
        && let Some(handle) = transfer.handle.take()
    {
        let _ = handle.join();
    }
    Ok(())
}

fn clear_expired_selection(inner: &mut AppStateInner) {
    if inner
        .selection
        .as_ref()
        .is_some_and(|selection| selection.expires_at <= Instant::now())
    {
        inner.selection = None;
    }
}

fn random_identifier() -> Result<[u8; 16], IpcError> {
    let mut value = [0_u8; 16];
    fill_random(&mut value).map_err(VaultError::from)?;
    Ok(value)
}

const fn transfer_kind_name(kind: TransferKind) -> &'static str {
    match kind {
        TransferKind::Export => "export",
        TransferKind::Import => "import",
    }
}

fn parse_json<T: DeserializeOwned>(body: &InvokeBody) -> Result<T, IpcError> {
    let InvokeBody::Json(value) = body else {
        return Err(invalid_request());
    };
    T::deserialize(value).map_err(|_| invalid_request())
}

fn state_name(state: &SessionState) -> &'static str {
    match state {
        SessionState::Uninitialized => "uninitialized",
        SessionState::Locked(_) => "locked",
        SessionState::Unlocked { .. } => "unlocked",
    }
}

fn unlocked(state: &SessionState) -> Result<&UnlockedVault, IpcError> {
    match state {
        SessionState::Uninitialized => Err(VaultError::Uninitialized.into()),
        SessionState::Locked(_) => Err(VaultError::Locked.into()),
        SessionState::Unlocked { vault, .. } => Ok(vault),
    }
}

fn draft_from_request(
    kind: ItemKindRequest,
    title: String,
    category: String,
    contact_explanation: String,
    body: String,
) -> Result<ItemDraft, IpcError> {
    ItemDraft::new(kind.into(), title, category, contact_explanation, body).map_err(Into::into)
}

fn validate_prepared_operation(
    item: &VaultItem,
    operation: &UploadOperation,
    byte_length: usize,
) -> Result<(), IpcError> {
    let prior_length = match operation {
        UploadOperation::Add => {
            if item.attachments.len() >= MAX_ATTACHMENT_COUNT {
                return Err(VaultError::InvalidInput.into());
            }
            0
        }
        UploadOperation::Replace(attachment_id) => item
            .attachments
            .iter()
            .find(|attachment| attachment.id == *attachment_id)
            .map(|attachment| attachment.content().len())
            .ok_or_else(|| IpcError::from(VaultError::AttachmentNotFound))?,
    };
    let existing = item
        .attachments
        .iter()
        .try_fold(0_usize, |total, attachment| {
            total.checked_add(attachment.content().len())
        })
        .ok_or_else(|| IpcError::from(VaultError::AttachmentTooLarge))?;
    let next = existing
        .checked_sub(prior_length)
        .and_then(|value| value.checked_add(byte_length))
        .ok_or_else(|| IpcError::from(VaultError::AttachmentTooLarge))?;
    if next > MAX_ATTACHMENT_BYTES {
        return Err(VaultError::AttachmentTooLarge.into());
    }
    Ok(())
}

fn clear_expired_upload(inner: &mut AppStateInner) {
    if inner
        .pending_upload
        .as_ref()
        .is_some_and(|pending| Instant::now() >= pending.expires_at)
    {
        inner.pending_upload = None;
    }
}

fn ensure_vault_directory(path: &Path) -> Result<(), IpcError> {
    let directory = path
        .parent()
        .ok_or_else(|| IpcError::from(VaultError::Io))?;
    let app_directory = directory
        .parent()
        .ok_or_else(|| IpcError::from(VaultError::Io))?;
    fs::create_dir_all(app_directory).map_err(VaultError::from)?;

    match fs::symlink_metadata(directory) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(VaultError::Io.into());
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let mut builder = fs::DirBuilder::new();
            #[cfg(unix)]
            builder.mode(0o700);
            builder.create(directory).map_err(VaultError::from)?;
        }
        Err(error) => return Err(VaultError::from(error).into()),
    }
    #[cfg(unix)]
    fs::set_permissions(directory, fs::Permissions::from_mode(0o700)).map_err(VaultError::from)?;
    Ok(())
}

fn summary_response(item: ItemSummary) -> ItemSummaryResponse {
    ItemSummaryResponse {
        item_id: encode_hex(item.id.as_bytes()),
        revision: item.revision.to_string(),
        kind: item.kind.code(),
        title: take_zeroizing_string(item.title),
        category: take_zeroizing_string(item.category),
        attachment_count: item.attachment_count,
        created_at_ms: item.created_at_ms.to_string(),
        updated_at_ms: item.updated_at_ms.to_string(),
    }
}

fn item_response(item: &VaultItem) -> VaultItemResponse {
    VaultItemResponse {
        item_id: encode_hex(item.id.as_bytes()),
        revision: item.revision.to_string(),
        kind: item.kind.code(),
        title: item.title.to_string(),
        category: item.category.to_string(),
        contact_explanation: item.contact_explanation.to_string(),
        body: item.body.to_string(),
        attachments: item.attachments.iter().map(attachment_response).collect(),
        created_at_ms: item.created_at_ms.to_string(),
        updated_at_ms: item.updated_at_ms.to_string(),
    }
}

fn attachment_response(attachment: &VaultAttachment) -> AttachmentResponse {
    AttachmentResponse {
        attachment_id: encode_hex(attachment.id.as_bytes()),
        filename: attachment.filename.to_string(),
        media_type: attachment.media_type.to_string(),
        byte_length: attachment.content().len().to_string(),
    }
}

fn take_zeroizing_string(mut value: Zeroizing<String>) -> String {
    std::mem::take(&mut *value)
}

fn parse_record_id(value: &str) -> Result<RecordId, IpcError> {
    parse_hex_id(value).map(RecordId::from_bytes)
}

fn parse_attachment_id(value: &str) -> Result<AttachmentId, IpcError> {
    parse_hex_id(value).map(AttachmentId::from_bytes)
}

fn parse_hex_id(value: &str) -> Result<[u8; 16], IpcError> {
    if value.len() != 32
        || value
            .bytes()
            .any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte))
    {
        return Err(invalid_request());
    }
    let mut output = [0_u8; 16];
    let (pairs, remainder) = value.as_bytes().as_chunks::<2>();
    if !remainder.is_empty() {
        return Err(invalid_request());
    }
    for (index, pair) in pairs.iter().enumerate() {
        output[index] = (hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?;
    }
    Ok(output)
}

fn hex_nibble(value: u8) -> Result<u8, IpcError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(invalid_request()),
    }
}

fn encode_hex(value: [u8; 16]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(32);
    for byte in value {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn parse_positive_decimal(value: &str) -> Result<u64, IpcError> {
    let parsed = parse_canonical_decimal(value)?;
    if parsed == 0 {
        return Err(invalid_request());
    }
    Ok(parsed)
}

fn parse_nonnegative_decimal_usize(value: &str) -> Result<usize, IpcError> {
    let parsed = parse_canonical_decimal(value)?;
    usize::try_from(parsed).map_err(|_| invalid_request())
}

fn parse_canonical_decimal(value: &str) -> Result<u64, IpcError> {
    if value.is_empty()
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(invalid_request());
    }
    value.parse().map_err(|_| invalid_request())
}

fn invalid_request() -> IpcError {
    IpcError {
        code: "ipc_invalid_request",
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use serde::Serialize;
    use serde_json::{Value, json};
    use tauri::http::{HeaderMap, HeaderValue};

    use super::*;

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let mut random = [0_u8; 16];
            assert!(getrandom::fill(&mut random).is_ok());
            let root = match fs::canonicalize(std::env::temp_dir()) {
                Ok(value) => value,
                Err(_) => panic!("temporary directory should resolve"),
            };
            let encoded = random
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            let path = root.join(format!("aeterna-i06-ipc-{encoded}"));
            assert!(fs::create_dir(&path).is_ok());
            Self(path)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn test_state(app_local_data_directory: &Path) -> VaultAppState {
        match VaultAppState::load(app_local_data_directory) {
            Ok(value) => value,
            Err(error) => panic!("test state load failed: {error}"),
        }
    }

    fn json_body(value: Value) -> InvokeBody {
        InvokeBody::Json(value)
    }

    fn json_result<T: Serialize>(result: Result<T, IpcError>) -> Result<Value, Value> {
        match result {
            Ok(value) => {
                serde_json::to_value(value).map_err(|_| json!({ "code": "test_encode_failed" }))
            }
            Err(error) => Err(json!({ "code": error.code })),
        }
    }

    fn upload_headers(upload_id: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        let value = match HeaderValue::from_str(upload_id) {
            Ok(value) => value,
            Err(error) => panic!("test header failed: {error}"),
        };
        headers.insert(UPLOAD_HEADER, value);
        headers
    }

    fn invalid_upload_headers() -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(UPLOAD_HEADER, HeaderValue::from_static("INVALID"));
        headers
    }

    fn expire_pending_upload(state: &VaultAppState) {
        let mut inner = match state.lock() {
            Ok(value) => value,
            Err(error) => panic!("test state lock failed: {error:?}"),
        };
        let pending = match inner.pending_upload.as_mut() {
            Some(value) => value,
            None => panic!("test pending upload is missing"),
        };
        pending.expires_at = Instant::now();
    }

    fn assert_error<T>(result: Result<T, IpcError>, code: &'static str) {
        assert_eq!(result.err(), Some(IpcError { code }));
    }

    fn string_field<'a>(value: &'a Value, pointer: &str) -> &'a str {
        match value.pointer(pointer).and_then(Value::as_str) {
            Some(value) => value,
            None => panic!("test response field is missing"),
        }
    }

    #[test]
    fn identifier_and_decimal_encodings_are_canonical() {
        let bytes = [0xab; 16];
        let encoded = encode_hex(bytes);
        assert_eq!(encoded, "abababababababababababababababab");
        assert_eq!(parse_hex_id(&encoded), Ok(bytes));
        for invalid in [
            "ABABABABABABABABABABABABABABABAB",
            "0xabababababababababababababababab",
            "abab",
            "gggggggggggggggggggggggggggggggg",
        ] {
            assert!(parse_hex_id(invalid).is_err());
        }
        assert_eq!(parse_positive_decimal("1"), Ok(1));
        assert_eq!(parse_nonnegative_decimal_usize("0"), Ok(0));
        for invalid in ["", "00", "01", "-1", "+1", "1.0"] {
            assert!(parse_canonical_decimal(invalid).is_err());
        }
    }

    #[test]
    fn strict_request_schemas_reject_missing_extra_and_wrong_types() {
        let valid = serde_json::from_str::<ItemDraftRequest>(
            r#"{"kind":"note","title":"Synthetic","category":"","contactExplanation":"","body":""}"#,
        );
        assert!(valid.is_ok());
        assert!(
            serde_json::from_str::<ItemDraftRequest>(
                r#"{"kind":"note","title":"Synthetic","category":"","contactExplanation":"","body":"","extra":true}"#,
            )
            .is_err()
        );
        assert!(
            serde_json::from_str::<ItemDraftRequest>(
                r#"{"kind":"note","title":1,"category":"","contactExplanation":"","body":""}"#,
            )
            .is_err()
        );
        assert!(
            serde_json::from_str::<ItemDraftRequest>(
                r#"{"kind":"note","category":"","contactExplanation":"","body":""}"#,
            )
            .is_err()
        );
        assert!(
            serde_json::from_str::<SelectionIdRequest>(
                r#"{"selectionId":"11111111111111111111111111111111"}"#
            )
            .is_ok()
        );
        assert!(
            serde_json::from_str::<SelectionIdRequest>(
                r#"{"selectionId":"11111111111111111111111111111111","path":"/tmp/secret"}"#
            )
            .is_err()
        );
        assert!(
            serde_json::from_str::<ImportStartRequest>(
                r#"{"selectionId":"11111111111111111111111111111111","password":"synthetic"}"#
            )
            .is_ok()
        );
        assert!(
            serde_json::from_str::<ImportStartRequest>(
                r#"{"selectionId":"11111111111111111111111111111111","password":"synthetic","bytes":[1]}"#
            )
            .is_err()
        );
        assert!(
            serde_json::from_str::<OperationIdRequest>(
                r#"{"operationId":"11111111111111111111111111111111","extra":true}"#
            )
            .is_err()
        );
    }

    #[test]
    fn transfer_tokens_are_typed_expiring_one_shot_and_progress_is_monotonic() {
        let selection_id = [0x11; 16];
        let mut inner = AppStateInner {
            session: SessionState::Uninitialized,
            pending_upload: None,
            selection: Some(FileSelection {
                id: selection_id,
                kind: TransferKind::Import,
                path: PathBuf::from("/not/exposed.aeterna-vault"),
                session_epoch: 7,
                expires_at: Instant::now() + Duration::from_secs(60),
            }),
            transfer: None,
            session_epoch: 7,
        };
        assert_error(
            consume_selection(&mut inner, [0x22; 16], TransferKind::Import),
            "vault_selection_not_found",
        );
        let consumed = consume_selection(&mut inner, selection_id, TransferKind::Import)
            .unwrap_or_else(|error| panic!("selection consume failed: {error:?}"));
        assert_eq!(consumed.session_epoch, 7);
        assert_error(
            consume_selection(&mut inner, selection_id, TransferKind::Import),
            "vault_selection_not_found",
        );

        inner.selection = Some(FileSelection {
            id: selection_id,
            kind: TransferKind::Export,
            path: PathBuf::from("/not/exposed.aeterna-vault"),
            session_epoch: 7,
            expires_at: Instant::now(),
        });
        assert_error(
            consume_selection(&mut inner, selection_id, TransferKind::Export),
            "vault_selection_not_found",
        );

        let reporter = TransferReporter::new();
        reporter.update("writing", 100, 5, true);
        reporter.update("writing", 10, 2, true);
        let progress = reporter
            .progress
            .lock()
            .unwrap_or_else(|_| panic!("progress lock failed"));
        assert_eq!(progress.bytes, 100);
        assert_eq!(progress.entries, 5);
        drop(progress);
        reporter.finish(Err(TransferError::Cancelled));
        reporter.update("writing", 500, 50, true);
        let progress = reporter
            .progress
            .lock()
            .unwrap_or_else(|_| panic!("progress lock failed"));
        assert_eq!(progress.state, "cancelled");
        assert_eq!(progress.bytes, 100);
        assert!(!progress.cancellable);
    }

    #[test]
    fn app_state_debug_and_ipc_errors_are_redacted_and_fixed() {
        let state = VaultAppState {
            path: PathBuf::from("/sensitive/aeterna-vault.sqlite3"),
            inner: Mutex::new(AppStateInner {
                session: SessionState::Uninitialized,
                pending_upload: None,
                selection: None,
                transfer: None,
                session_epoch: 0,
            }),
        };
        assert_eq!(format!("{state:?}"), "VaultAppState([REDACTED])");
        let serialized = serde_json::to_string(&IpcError::from(VaultError::Locked));
        assert!(matches!(
            serialized.as_deref(),
            Ok(r#"{"code":"vault_locked"}"#)
        ));
        let selected = serde_json::to_value(SelectionResponse::Selected {
            selection_id: "11111111111111111111111111111111".to_owned(),
        })
        .unwrap_or(serde_json::Value::Null);
        assert_eq!(
            selected,
            json!({
                "outcome": "selected",
                "selectionId": "11111111111111111111111111111111",
            })
        );
        let cancelled =
            serde_json::to_value(SelectionResponse::Cancelled).unwrap_or(serde_json::Value::Null);
        assert_eq!(cancelled, json!({ "outcome": "cancelled" }));
    }

    #[test]
    fn ipc_handlers_enforce_shapes_sessions_raw_transfer_and_replay() {
        let directory = TestDirectory::new();
        let state = test_state(&directory.0);

        assert_eq!(
            json_result(vault_status_impl(&json_body(json!({})), &state)),
            Ok(json!({ "state": "uninitialized" }))
        );
        assert_error(
            vault_export_start_impl(
                &json_body(json!({
                    "selectionId": "11111111111111111111111111111111",
                    "path": "/tmp/secret",
                })),
                &state,
            ),
            "ipc_invalid_request",
        );
        assert_error(
            vault_import_start_impl(
                &json_body(json!({
                    "selectionId": "11111111111111111111111111111111",
                    "password": "synthetic-password",
                    "packageBytes": [1, 2, 3],
                })),
                &state,
            ),
            "ipc_invalid_request",
        );
        assert_error(
            vault_transfer_status_impl(&InvokeBody::Raw(vec![1, 2, 3]), &state),
            "ipc_invalid_request",
        );
        assert_eq!(
            json_result(vault_status_impl(
                &json_body(json!({ "extra": true })),
                &state,
            )),
            Err(json!({ "code": "ipc_invalid_request" }))
        );
        assert_eq!(
            json_result(vault_list_items_impl(&json_body(json!({})), &state)),
            Err(json!({ "code": "vault_uninitialized" }))
        );
        assert_eq!(
            json_result(vault_initialize_impl(
                &json_body(json!({ "password": "synthetic-password" })),
                &state,
            )),
            Ok(json!({ "state": "unlocked" }))
        );

        let created = match json_result(vault_create_item_impl(
            &json_body(json!({
                "kind": "note",
                "title": "Synthetic IPC item",
                "category": "Synthetic",
                "contactExplanation": "",
                "body": "Synthetic body",
            })),
            &state,
        )) {
            Ok(value) => value,
            Err(error) => panic!("test item create failed: {error}"),
        };
        let item_id = string_field(&created, "/item/itemId").to_owned();
        let revision = string_field(&created, "/item/revision").to_owned();
        assert_eq!(revision, "1");

        let prepare_body = || {
            json_body(json!({
                "itemId": item_id.clone(),
                "expectedRevision": revision.clone(),
                "operation": "add",
                "filename": "synthetic.bin",
                "mediaType": "application/octet-stream",
                "byteLength": "3",
            }))
        };

        let prepared = match json_result(vault_prepare_attachment_impl(&prepare_body(), &state)) {
            Ok(value) => value,
            Err(error) => panic!("test missing-header prepare failed: {error}"),
        };
        let upload_id = string_field(&prepared, "/uploadId").to_owned();
        assert_error(
            vault_commit_attachment_impl(
                &InvokeBody::Raw(vec![1, 2, 3]),
                &HeaderMap::new(),
                &state,
            ),
            "ipc_invalid_request",
        );
        assert_error(
            vault_commit_attachment_impl(
                &InvokeBody::Raw(vec![1, 2, 3]),
                &upload_headers(&upload_id),
                &state,
            ),
            "vault_upload_not_found",
        );

        let prepared = match json_result(vault_prepare_attachment_impl(&prepare_body(), &state)) {
            Ok(value) => value,
            Err(error) => panic!("test invalid-header prepare failed: {error}"),
        };
        let upload_id = string_field(&prepared, "/uploadId").to_owned();
        assert_error(
            vault_commit_attachment_impl(
                &InvokeBody::Raw(vec![1, 2, 3]),
                &invalid_upload_headers(),
                &state,
            ),
            "ipc_invalid_request",
        );
        assert_error(
            vault_commit_attachment_impl(
                &InvokeBody::Raw(vec![1, 2, 3]),
                &upload_headers(&upload_id),
                &state,
            ),
            "vault_upload_not_found",
        );

        let prepared = match json_result(vault_prepare_attachment_impl(&prepare_body(), &state)) {
            Ok(value) => value,
            Err(error) => panic!("test cancellation prepare failed: {error}"),
        };
        let upload_id = string_field(&prepared, "/uploadId").to_owned();
        assert_eq!(
            json_result(vault_cancel_attachment_impl(
                &json_body(json!({ "uploadId": upload_id.clone() })),
                &state,
            )),
            Ok(json!({ "cancelled": true }))
        );
        assert_error(
            vault_commit_attachment_impl(
                &InvokeBody::Raw(vec![1, 2, 3]),
                &upload_headers(&upload_id),
                &state,
            ),
            "vault_upload_not_found",
        );

        let prepared = match json_result(vault_prepare_attachment_impl(&prepare_body(), &state)) {
            Ok(value) => value,
            Err(error) => panic!("test expiration prepare failed: {error}"),
        };
        let upload_id = string_field(&prepared, "/uploadId").to_owned();
        expire_pending_upload(&state);
        assert_error(
            vault_commit_attachment_impl(
                &InvokeBody::Raw(vec![1, 2, 3]),
                &upload_headers(&upload_id),
                &state,
            ),
            "vault_upload_not_found",
        );

        let prepared = match json_result(vault_prepare_attachment_impl(&prepare_body(), &state)) {
            Ok(value) => value,
            Err(error) => panic!("test attachment prepare failed: {error}"),
        };
        let upload_id = string_field(&prepared, "/uploadId").to_owned();
        assert_error(
            vault_commit_attachment_impl(
                &json_body(json!({})),
                &upload_headers(&upload_id),
                &state,
            ),
            "ipc_invalid_request",
        );
        assert_error(
            vault_commit_attachment_impl(
                &InvokeBody::Raw(vec![1, 2, 3]),
                &upload_headers(&upload_id),
                &state,
            ),
            "vault_upload_not_found",
        );

        let prepared = match json_result(vault_prepare_attachment_impl(&prepare_body(), &state)) {
            Ok(value) => value,
            Err(error) => panic!("test attachment reprepare failed: {error}"),
        };
        let upload_id = string_field(&prepared, "/uploadId").to_owned();
        assert_error(
            vault_commit_attachment_impl(
                &InvokeBody::Raw(vec![1, 2]),
                &upload_headers(&upload_id),
                &state,
            ),
            "ipc_invalid_request",
        );
        assert_error(
            vault_commit_attachment_impl(
                &InvokeBody::Raw(vec![1, 2, 3]),
                &upload_headers(&upload_id),
                &state,
            ),
            "vault_upload_not_found",
        );

        let prepared = match json_result(vault_prepare_attachment_impl(&prepare_body(), &state)) {
            Ok(value) => value,
            Err(error) => panic!("test final attachment prepare failed: {error}"),
        };
        let upload_id = string_field(&prepared, "/uploadId").to_owned();
        let committed = match json_result(vault_commit_attachment_impl(
            &InvokeBody::Raw(vec![1, 2, 3]),
            &upload_headers(&upload_id),
            &state,
        )) {
            Ok(value) => value,
            Err(error) => panic!("test attachment commit failed: {error}"),
        };
        let next_revision = string_field(&committed, "/item/revision").to_owned();
        let attachment_id = string_field(&committed, "/item/attachments/0/attachmentId").to_owned();
        assert_eq!(next_revision, "2");
        assert_error(
            vault_commit_attachment_impl(
                &InvokeBody::Raw(vec![1, 2, 3]),
                &upload_headers(&upload_id),
                &state,
            ),
            "vault_upload_not_found",
        );

        let raw_read = vault_read_attachment_impl(
            &json_body(json!({
                "itemId": item_id.clone(),
                "attachmentId": attachment_id.clone(),
                "expectedRevision": next_revision.clone(),
            })),
            &state,
        );
        assert_eq!(raw_read, Ok(vec![1, 2, 3]));

        let transfer_reporter = TransferReporter::new();
        let worker_reporter = transfer_reporter.clone();
        let transfer_worker = thread::spawn(move || {
            while !worker_reporter.cancel.load(Ordering::Acquire) {
                thread::yield_now();
            }
            worker_reporter.finish(Err(TransferError::Cancelled));
        });
        {
            let mut inner = state
                .lock()
                .unwrap_or_else(|error| panic!("test state lock failed: {error:?}"));
            inner.transfer = Some(TransferOperation {
                id: [0x44; 16],
                kind: TransferKind::Export,
                reporter: transfer_reporter,
                handle: Some(transfer_worker),
            });
        }
        assert_eq!(
            json_result(vault_lock_impl(&json_body(json!({})), &state)),
            Ok(json!({ "state": "locked" }))
        );
        {
            let inner = state
                .lock()
                .unwrap_or_else(|error| panic!("test state lock failed: {error:?}"));
            assert!(matches!(inner.session, SessionState::Locked(_)));
            let transfer = inner
                .transfer
                .as_ref()
                .unwrap_or_else(|| panic!("cancelled export status is retained"));
            assert!(transfer.handle.is_none());
            let progress = transfer
                .reporter
                .progress
                .lock()
                .unwrap_or_else(|_| panic!("progress lock failed"));
            assert_eq!(progress.state, "cancelled");
            assert!(!progress.cancellable);
        }
        assert_error(
            vault_list_items_impl(&json_body(json!({})), &state),
            "vault_locked",
        );
        assert_error(
            vault_get_item_impl(&json_body(json!({ "itemId": item_id.clone() })), &state),
            "vault_locked",
        );
        assert_error(
            vault_create_item_impl(
                &json_body(json!({
                    "kind": "note",
                    "title": "Locked",
                    "category": "",
                    "contactExplanation": "",
                    "body": "",
                })),
                &state,
            ),
            "vault_locked",
        );
        assert_error(
            vault_update_item_impl(
                &json_body(json!({
                    "itemId": item_id.clone(),
                    "expectedRevision": next_revision.clone(),
                    "kind": "note",
                    "title": "Locked",
                    "category": "",
                    "contactExplanation": "",
                    "body": "",
                })),
                &state,
            ),
            "vault_locked",
        );
        assert_error(
            vault_delete_item_impl(
                &json_body(json!({
                    "itemId": item_id.clone(),
                    "expectedRevision": next_revision.clone(),
                })),
                &state,
            ),
            "vault_locked",
        );
        assert_error(
            vault_prepare_attachment_impl(
                &json_body(json!({
                    "itemId": item_id.clone(),
                    "expectedRevision": next_revision.clone(),
                    "operation": "add",
                    "filename": "locked.bin",
                    "mediaType": "",
                    "byteLength": "0",
                })),
                &state,
            ),
            "vault_locked",
        );
        assert_error(
            vault_cancel_attachment_impl(
                &json_body(json!({
                    "uploadId": "11111111111111111111111111111111",
                })),
                &state,
            ),
            "vault_locked",
        );
        assert_error(
            vault_read_attachment_impl(
                &json_body(json!({
                    "itemId": item_id.clone(),
                    "attachmentId": attachment_id.clone(),
                    "expectedRevision": next_revision.clone(),
                })),
                &state,
            ),
            "vault_locked",
        );
        assert_error(
            vault_remove_attachment_impl(
                &json_body(json!({
                    "itemId": item_id,
                    "attachmentId": attachment_id,
                    "expectedRevision": next_revision,
                })),
                &state,
            ),
            "vault_locked",
        );
        assert_error(
            vault_commit_attachment_impl(
                &InvokeBody::Raw(Vec::new()),
                &upload_headers("11111111111111111111111111111111"),
                &state,
            ),
            "vault_locked",
        );

        drop(state);
        let restarted = test_state(&directory.0);
        assert_eq!(
            json_result(vault_status_impl(&json_body(json!({})), &restarted)),
            Ok(json!({ "state": "locked" }))
        );
        assert_eq!(
            json_result(vault_unlock_impl(
                &json_body(json!({ "password": "wrong-synthetic-password" })),
                &restarted,
            )),
            Err(json!({ "code": "crypto_authentication_failed" }))
        );
        assert_eq!(
            json_result(vault_unlock_impl(
                &json_body(json!({ "password": "synthetic-password" })),
                &restarted,
            )),
            Ok(json!({ "state": "unlocked" }))
        );
    }
}
