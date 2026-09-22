import { invoke } from "@tauri-apps/api/core";

export const MAX_ATTACHMENT_BYTES = 786_432;

export type VaultState = "uninitialized" | "locked" | "unlocked";
export type ItemKind = "note" | "instruction";

export interface ItemDraft {
  kind: ItemKind;
  title: string;
  category: string;
  contactExplanation: string;
  body: string;
}

export interface AttachmentDescriptor {
  attachmentId: string;
  filename: string;
  mediaType: string;
  byteLength: string;
}

export interface ItemSummary {
  itemId: string;
  revision: string;
  kind: ItemKind;
  title: string;
  category: string;
  attachmentCount: number;
  createdAtMs: string;
  updatedAtMs: string;
}

export interface VaultItem extends ItemDraft {
  itemId: string;
  revision: string;
  attachments: AttachmentDescriptor[];
  createdAtMs: string;
  updatedAtMs: string;
}

export class VaultIpcError extends Error {
  readonly code: string;

  constructor(code: string) {
    super(code);
    this.name = "VaultIpcError";
    this.code = code;
  }
}

export async function getVaultStatus(): Promise<VaultState> {
  const response = await invokeSafely("vault_status", {});
  if (!isRecord(response) || !isVaultState(response.state)) {
    throw new VaultIpcError("ipc_invalid_response");
  }
  return response.state;
}

export async function initializeVault(password: string): Promise<void> {
  await expectStateResponse("vault_initialize", { password }, "unlocked");
}

export async function unlockVault(password: string): Promise<void> {
  await expectStateResponse("vault_unlock", { password }, "unlocked");
}

export async function lockVault(): Promise<void> {
  await expectStateResponse("vault_lock", {}, "locked");
}

export async function listItems(): Promise<ItemSummary[]> {
  const response = await invokeSafely("vault_list_items", {});
  if (
    !isRecord(response) ||
    !Array.isArray(response.items) ||
    !response.items.every(isItemSummary)
  ) {
    throw new VaultIpcError("ipc_invalid_response");
  }
  return response.items;
}

export async function getItem(itemId: string): Promise<VaultItem> {
  return invokeForItem("vault_get_item", { itemId });
}

export async function createItem(draft: ItemDraft): Promise<VaultItem> {
  return invokeForItem("vault_create_item", { ...draft });
}

export async function updateItem(
  itemId: string,
  expectedRevision: string,
  draft: ItemDraft,
): Promise<VaultItem> {
  return invokeForItem("vault_update_item", {
    itemId,
    expectedRevision,
    ...draft,
  });
}

export async function deleteItem(
  itemId: string,
  expectedRevision: string,
): Promise<void> {
  const response = await invokeSafely("vault_delete_item", {
    itemId,
    expectedRevision,
  });
  if (!isRecord(response) || response.deleted !== true) {
    throw new VaultIpcError("ipc_invalid_response");
  }
}

interface PrepareAttachmentRequest {
  itemId: string;
  expectedRevision: string;
  operation: "add" | "replace";
  attachmentId?: string;
  filename: string;
  mediaType: string;
  byteLength: string;
}

export async function prepareAttachment(
  request: PrepareAttachmentRequest,
): Promise<string> {
  const response = await invokeSafely("vault_prepare_attachment", {
    ...request,
  });
  if (
    !isRecord(response) ||
    !isCanonicalId(response.uploadId) ||
    response.expiresInSeconds !== 300
  ) {
    throw new VaultIpcError("ipc_invalid_response");
  }
  return response.uploadId;
}

export async function commitAttachment(
  uploadId: string,
  bytes: Uint8Array,
): Promise<VaultItem> {
  try {
    const response = await invoke<unknown>("vault_commit_attachment", bytes, {
      headers: { "x-aeterna-upload-id": uploadId },
    });
    return parseItemEnvelope(response);
  } catch (error) {
    throw normalizeInvokeError(error);
  }
}

export async function cancelAttachment(uploadId: string): Promise<void> {
  const response = await invokeSafely("vault_cancel_attachment", { uploadId });
  if (!isRecord(response) || response.cancelled !== true) {
    throw new VaultIpcError("ipc_invalid_response");
  }
}

export async function readAttachment(
  itemId: string,
  attachmentId: string,
  expectedRevision: string,
): Promise<Uint8Array> {
  try {
    const response = await invoke<ArrayBuffer>("vault_read_attachment", {
      itemId,
      attachmentId,
      expectedRevision,
    });
    if (!(response instanceof ArrayBuffer)) {
      throw new VaultIpcError("ipc_invalid_response");
    }
    return new Uint8Array(response);
  } catch (error) {
    throw normalizeInvokeError(error);
  }
}

export async function removeAttachment(
  itemId: string,
  attachmentId: string,
  expectedRevision: string,
): Promise<VaultItem> {
  return invokeForItem("vault_remove_attachment", {
    itemId,
    attachmentId,
    expectedRevision,
  });
}

async function expectStateResponse(
  command: string,
  request: Record<string, unknown>,
  expectedState: VaultState,
): Promise<void> {
  const response = await invokeSafely(command, request);
  if (!isRecord(response) || response.state !== expectedState) {
    throw new VaultIpcError("ipc_invalid_response");
  }
}

async function invokeForItem(
  command: string,
  request: Record<string, unknown>,
): Promise<VaultItem> {
  return parseItemEnvelope(await invokeSafely(command, request));
}

async function invokeSafely(
  command: string,
  request: Record<string, unknown>,
): Promise<unknown> {
  try {
    return await invoke<unknown>(command, request);
  } catch (error) {
    throw normalizeInvokeError(error);
  }
}

function parseItemEnvelope(value: unknown): VaultItem {
  if (!isRecord(value) || !isVaultItem(value.item)) {
    throw new VaultIpcError("ipc_invalid_response");
  }
  return value.item;
}

function normalizeInvokeError(error: unknown): VaultIpcError {
  if (
    isRecord(error) &&
    typeof error.code === "string" &&
    /^[a-z][a-z0-9_]{2,63}$/.test(error.code)
  ) {
    return new VaultIpcError(error.code);
  }
  return new VaultIpcError("ipc_unavailable");
}

function isVaultState(value: unknown): value is VaultState {
  return (
    value === "uninitialized" || value === "locked" || value === "unlocked"
  );
}

function isItemKind(value: unknown): value is ItemKind {
  return value === "note" || value === "instruction";
}

function isItemSummary(value: unknown): value is ItemSummary {
  if (!isRecord(value)) {
    return false;
  }
  return (
    isCanonicalId(value.itemId) &&
    isPositiveDecimal(value.revision) &&
    isItemKind(value.kind) &&
    typeof value.title === "string" &&
    typeof value.category === "string" &&
    Number.isSafeInteger(value.attachmentCount) &&
    Number(value.attachmentCount) >= 0 &&
    isNonnegativeDecimal(value.createdAtMs) &&
    isNonnegativeDecimal(value.updatedAtMs)
  );
}

function isVaultItem(value: unknown): value is VaultItem {
  if (!isRecord(value) || !isItemSummary({ ...value, attachmentCount: 0 })) {
    return false;
  }
  return (
    typeof value.contactExplanation === "string" &&
    typeof value.body === "string" &&
    Array.isArray(value.attachments) &&
    value.attachments.every(isAttachmentDescriptor)
  );
}

function isAttachmentDescriptor(value: unknown): value is AttachmentDescriptor {
  if (!isRecord(value)) {
    return false;
  }
  return (
    isCanonicalId(value.attachmentId) &&
    typeof value.filename === "string" &&
    typeof value.mediaType === "string" &&
    isNonnegativeDecimal(value.byteLength)
  );
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function isCanonicalId(value: unknown): value is string {
  return typeof value === "string" && /^[0-9a-f]{32}$/.test(value);
}

function isPositiveDecimal(value: unknown): value is string {
  return typeof value === "string" && /^[1-9][0-9]*$/.test(value);
}

function isNonnegativeDecimal(value: unknown): value is string {
  return typeof value === "string" && /^(0|[1-9][0-9]*)$/.test(value);
}
