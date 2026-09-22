import { beforeEach, describe, expect, it, vi } from "vitest";

import {
  commitAttachment,
  getVaultStatus,
  listItems,
  readAttachment,
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

describe("I06 typed IPC client", () => {
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
});
