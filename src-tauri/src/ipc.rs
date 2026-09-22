use std::{
    fs,
    path::{Path, PathBuf},
    sync::{Mutex, MutexGuard},
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
        RecordId, UnlockedVault, VaultAttachment, VaultError, VaultItem, VaultRepository,
        validate_attachment_input,
    },
};

const VAULT_DIRECTORY_NAME: &str = "vault";
const VAULT_FILE_NAME: &str = "aeterna-vault.sqlite3";
const UPLOAD_HEADER: &str = "x-aeterna-upload-id";
const UPLOAD_TTL: Duration = Duration::from_secs(300);
const DEVELOPMENT_ARGON2_PROFILE: Argon2Profile = Argon2Profile::new(262_144, 2, 1);

pub(crate) struct VaultAppState {
    path: PathBuf,
    inner: Mutex<AppStateInner>,
}

struct AppStateInner {
    session: SessionState,
    pending_upload: Option<PendingUpload>,
}

enum SessionState {
    Uninitialized,
    Locked(VaultRepository),
    Unlocked {
        repository: VaultRepository,
        vault: UnlockedVault,
    },
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
    let inner = state.lock()?;
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
    let vault = repository.unlock(&password)?;
    inner.session = SessionState::Unlocked { repository, vault };
    inner.pending_upload = None;
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
    let vault = repository.unlock(&password)?;
    inner.session = SessionState::Unlocked { repository, vault };
    inner.pending_upload = None;
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
    }
    inner.pending_upload = None;
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
    }

    #[test]
    fn app_state_debug_and_ipc_errors_are_redacted_and_fixed() {
        let state = VaultAppState {
            path: PathBuf::from("/sensitive/aeterna-vault.sqlite3"),
            inner: Mutex::new(AppStateInner {
                session: SessionState::Uninitialized,
                pending_upload: None,
            }),
        };
        assert_eq!(format!("{state:?}"), "VaultAppState([REDACTED])");
        let serialized = serde_json::to_string(&IpcError::from(VaultError::Locked));
        assert!(matches!(
            serialized.as_deref(),
            Ok(r#"{"code":"vault_locked"}"#)
        ));
    }

    #[test]
    fn ipc_handlers_enforce_shapes_sessions_raw_transfer_and_replay() {
        let directory = TestDirectory::new();
        let state = test_state(&directory.0);

        assert_eq!(
            json_result(vault_status_impl(&json_body(json!({})), &state)),
            Ok(json!({ "state": "uninitialized" }))
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

        assert_eq!(
            json_result(vault_lock_impl(&json_body(json!({})), &state)),
            Ok(json!({ "state": "locked" }))
        );
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
