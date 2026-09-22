import { beforeEach, describe, expect, it, vi } from "vitest";

import {
  cancelTransfer,
  chooseVaultExport,
  commitAttachment,
  getTransferStatus,
  getVaultStatus,
  listItems,
  readAttachment,
  startVaultImport,
} from "./ipc";

const { invokeMock } = vi.hoisted(() => ({
  invokeMock:
    vi.fn<
      (
        command: string,
        args?: Record<string, unknown> | Uint8Array,
        options?: { headers?: Record<string, string> },
      ) => Promise<unknown>
    >(),
}));

vi.mock("@tauri-apps/api/core", () => ({ invoke: invokeMock }));

describe("I07 typed IPC client", () => {
  beforeEach(() => invokeMock.mockReset());

  it("sends strict top-level request bodies", async () => {
    invokeMock.mockResolvedValue({ state: "locked" });
    await expect(getVaultStatus()).resolves.toBe("locked");
    expect(invokeMock).toHaveBeenCalledWith("vault_status", {});
  });

  it("rejects malformed native responses", async () => {
    invokeMock.mockResolvedValue({ items: [{ itemId: "not-canonical" }] });
    await expect(listItems()).rejects.toMatchObject({
      code: "ipc_invalid_response",
    });
  });

  it("preserves only structured machine-readable errors", async () => {
    invokeMock
      .mockRejectedValueOnce({ code: "vault_locked", detail: "ignored" })
      .mockRejectedValueOnce("sensitive framework detail");
    await expect(getVaultStatus()).rejects.toMatchObject({
      code: "vault_locked",
    });
    const unavailable = await getVaultStatus().catch((error: unknown) => error);
    expect((unavailable as { code?: unknown }).code).toBe("ipc_unavailable");
    expect((unavailable as { message?: unknown }).message).not.toBe(
      "sensitive framework detail",
    );
  });

  it("uses raw binary request and response bodies for attachments", async () => {
    const item = {
      itemId: "11111111111111111111111111111111",
      revision: "2",
      kind: "note",
      title: "Synthetic",
      category: "",
      contactExplanation: "",
      body: "",
      attachments: [],
      createdAtMs: "1",
      updatedAtMs: "2",
    };
    const uploaded = new Uint8Array([1, 2, 3]);
    invokeMock.mockResolvedValueOnce({ item });
    await expect(
      commitAttachment("22222222222222222222222222222222", uploaded),
    ).resolves.toEqual(item);
    expect(invokeMock).toHaveBeenCalledWith(
      "vault_commit_attachment",
      uploaded,
      {
        headers: { "x-aeterna-upload-id": "22222222222222222222222222222222" },
      },
    );

    const downloaded = new Uint8Array([4, 5, 6]).buffer;
    invokeMock.mockResolvedValueOnce(downloaded);
    await expect(
      readAttachment(
        "11111111111111111111111111111111",
        "33333333333333333333333333333333",
        "2",
      ),
    ).resolves.toEqual(new Uint8Array([4, 5, 6]));
  });

  it("keeps package paths and bytes out of typed transfer IPC", async () => {
    const selectionId = "44444444444444444444444444444444";
    const operationId = "55555555555555555555555555555555";
    invokeMock
      .mockResolvedValueOnce({ outcome: "selected", selectionId })
      .mockResolvedValueOnce({ operationId })
      .mockResolvedValueOnce({
        kind: "import",
        state: "running",
        phase: "authenticating",
        bytesProcessed: "1161",
        entriesProcessed: "7",
        cancellable: true,
      })
      .mockResolvedValueOnce({ state: "cancelling" });

    await expect(chooseVaultExport()).resolves.toEqual({
      outcome: "selected",
      selectionId,
    });
    await expect(
      startVaultImport(selectionId, "synthetic-password"),
    ).resolves.toBe(operationId);
    await expect(getTransferStatus(operationId)).resolves.toMatchObject({
      kind: "import",
      phase: "authenticating",
    });
    await expect(cancelTransfer(operationId)).resolves.toBeUndefined();

    expect(invokeMock).toHaveBeenNthCalledWith(1, "vault_export_choose", {});
    expect(invokeMock).toHaveBeenNthCalledWith(2, "vault_import_start", {
      selectionId,
      password: "synthetic-password",
    });
    expect(JSON.stringify(invokeMock.mock.calls)).not.toContain(
      ".aeterna-vault",
    );
  });

  it("rejects malformed transfer progress and selection responses", async () => {
    invokeMock
      .mockResolvedValueOnce({
        outcome: "selected",
        selectionId: "/tmp/secret",
      })
      .mockResolvedValueOnce({
        kind: "export",
        state: "running",
        phase: "unknown",
        bytesProcessed: "01",
        entriesProcessed: "0",
        cancellable: true,
      });
    await expect(chooseVaultExport()).rejects.toMatchObject({
      code: "ipc_invalid_response",
    });
    await expect(
      getTransferStatus("55555555555555555555555555555555"),
    ).rejects.toMatchObject({ code: "ipc_invalid_response" });
  });
});
