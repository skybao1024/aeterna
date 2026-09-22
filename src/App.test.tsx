import {
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { I18nextProvider } from "react-i18next";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { App } from "./App";
import {
  createI18n,
  DEFAULT_LOCALE,
  LOCALE_STORAGE_KEY,
  resolveSavedLocale,
} from "./i18n";

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

const ITEM_ID = "11111111111111111111111111111111";
const ATTACHMENT_ID = "22222222222222222222222222222222";

const item = {
  itemId: ITEM_ID,
  revision: "1",
  kind: "note",
  title: "Synthetic title",
  category: "Synthetic category",
  contactExplanation: "",
  body: "Synthetic body",
  attachments: [],
  createdAtMs: "1700000000000",
  updatedAtMs: "1700000000000",
};

const summary = {
  itemId: ITEM_ID,
  revision: "1",
  kind: "note",
  title: "Synthetic title",
  category: "Synthetic category",
  attachmentCount: 0,
  createdAtMs: "1700000000000",
  updatedAtMs: "1700000000000",
};

function renderApplication() {
  const instance = createI18n(window.localStorage);
  render(
    <I18nextProvider i18n={instance}>
      <App />
    </I18nextProvider>,
  );
  return instance;
}

function resolved(value: unknown): Promise<unknown> {
  return Promise.resolve(value);
}

describe("I06 local vault workflow", () => {
  beforeEach(() => {
    window.localStorage.clear();
    invokeMock.mockReset();
  });

  it("shows the truthful recovery-less initialization warning and initializes", async () => {
    const user = userEvent.setup();
    invokeMock.mockImplementation((command) => {
      if (command === "vault_status")
        return resolved({ state: "uninitialized" });
      if (command === "vault_initialize")
        return resolved({ state: "unlocked" });
      if (command === "vault_list_items") return resolved({ items: [] });
      throw new Error("unexpected command");
    });

    renderApplication();

    expect(
      await screen.findByRole("heading", { name: "Create a local vault" }),
    ).toBeInTheDocument();
    expect(
      screen.getByText(
        /recovery, account binding, backup, and export are not available/i,
      ),
    ).toBeInTheDocument();

    await user.type(
      screen.getByLabelText("Master password"),
      "synthetic-password",
    );
    await user.type(
      screen.getByLabelText("Confirm master password"),
      "synthetic-password",
    );
    await user.click(
      screen.getByRole("button", { name: "Create local vault" }),
    );

    await screen.findByRole("heading", { name: "Vault items" });
    expect(invokeMock).toHaveBeenCalledWith("vault_initialize", {
      password: "synthetic-password",
    });
    expect(Object.keys(window.localStorage)).toEqual([]);
  });

  it("creates a note with the keyboard save shortcut through typed IPC", async () => {
    const user = userEvent.setup();
    invokeMock.mockImplementation((command) => {
      if (command === "vault_status") return resolved({ state: "unlocked" });
      if (command === "vault_list_items") return resolved({ items: [] });
      if (command === "vault_create_item") return resolved({ item });
      throw new Error("unexpected command");
    });
    renderApplication();

    await user.click(await screen.findByRole("button", { name: "New item" }));
    await user.type(screen.getByLabelText("Title"), "Synthetic title");
    await user.type(screen.getByLabelText("Category"), "Synthetic category");
    await user.type(screen.getByLabelText("Body"), "Synthetic body");
    await user.keyboard("{Control>}s{/Control}");

    await waitFor(() => {
      expect(invokeMock).toHaveBeenCalledWith("vault_create_item", {
        kind: "note",
        title: "Synthetic title",
        category: "Synthetic category",
        contactExplanation: "",
        body: "Synthetic body",
      });
    });
    expect(
      screen.queryByText("Save this item before adding attachments."),
    ).not.toBeInTheDocument();
  });

  it("guards unsaved locale changes with an accessible confirmation", async () => {
    const user = userEvent.setup();
    invokeMock.mockImplementation((command) => {
      if (command === "vault_status") return resolved({ state: "unlocked" });
      if (command === "vault_list_items") return resolved({ items: [] });
      throw new Error("unexpected command");
    });
    renderApplication();

    await user.click(await screen.findByRole("button", { name: "New item" }));
    await user.type(screen.getByLabelText("Title"), "Unsaved synthetic title");
    await user.click(
      screen.getByRole("button", {
        name: "Language: Switch to Simplified Chinese",
      }),
    );

    const dialog = screen.getByRole("alertdialog");
    expect(dialog).toHaveAccessibleName("Discard unsaved changes?");
    expect(screen.getByRole("button", { name: "Cancel" })).toHaveFocus();
    await user.click(screen.getByRole("button", { name: "Discard changes" }));
    expect(await screen.findByText("保险箱项目")).toBeInTheDocument();
    expect(window.localStorage.getItem(LOCALE_STORAGE_KEY)).toBe("zh-CN");
  });

  it("can save from the unsaved-change dialog before continuing", async () => {
    const user = userEvent.setup();
    invokeMock.mockImplementation((command) => {
      if (command === "vault_status") return resolved({ state: "unlocked" });
      if (command === "vault_list_items") return resolved({ items: [] });
      if (command === "vault_create_item") return resolved({ item });
      throw new Error("unexpected command");
    });
    renderApplication();

    await user.click(await screen.findByRole("button", { name: "New item" }));
    await user.type(screen.getByLabelText("Title"), "Synthetic title");
    const localeButton = screen.getByRole("button", {
      name: "Language: Switch to Simplified Chinese",
    });
    await user.click(localeButton);
    const dialog = screen.getByRole("alertdialog");
    await user.click(within(dialog).getByRole("button", { name: "Save" }));

    await waitFor(() => {
      expect(invokeMock).toHaveBeenCalledWith("vault_create_item", {
        kind: "note",
        title: "Synthetic title",
        category: "",
        contactExplanation: "",
        body: "",
      });
    });
    expect(await screen.findByText("保险箱项目")).toBeInTheDocument();
  });

  it("returns focus on cancellation and ignores a late item response after lock", async () => {
    const user = userEvent.setup();
    let resolveItem: ((value: unknown) => void) | undefined;
    const pendingItem = new Promise<unknown>((resolve) => {
      resolveItem = resolve;
    });
    invokeMock.mockImplementation((command) => {
      if (command === "vault_status") return resolved({ state: "unlocked" });
      if (command === "vault_list_items") return resolved({ items: [summary] });
      if (command === "vault_get_item") return pendingItem;
      if (command === "vault_lock") return resolved({ state: "locked" });
      throw new Error("unexpected command");
    });
    renderApplication();

    await user.click(await screen.findByRole("button", { name: "New item" }));
    await user.type(screen.getByLabelText("Title"), "Unsaved");
    const localeButton = screen.getByRole("button", {
      name: "Language: Switch to Simplified Chinese",
    });
    await user.click(localeButton);
    await user.click(screen.getByRole("button", { name: "Cancel" }));
    await waitFor(() => expect(localeButton).toHaveFocus());
    await user.click(screen.getByRole("button", { name: /Synthetic title/ }));
    await user.click(screen.getByRole("button", { name: "Discard changes" }));
    await user.click(screen.getByRole("button", { name: "Lock" }));
    expect(
      await screen.findByRole("heading", { name: "Unlock your local vault" }),
    ).toBeInTheDocument();
    resolveItem?.({ item });
    await waitFor(() => {
      expect(screen.queryByDisplayValue("Synthetic title")).toBeNull();
    });
  });

  it("requires destructive confirmation before deleting an item", async () => {
    const user = userEvent.setup();
    invokeMock.mockImplementation((command) => {
      if (command === "vault_status") return resolved({ state: "unlocked" });
      if (command === "vault_list_items") return resolved({ items: [summary] });
      if (command === "vault_get_item") return resolved({ item });
      if (command === "vault_delete_item") return resolved({ deleted: true });
      throw new Error("unexpected command");
    });
    renderApplication();

    await user.click(
      await screen.findByRole("button", { name: /Synthetic title/ }),
    );
    await user.click(await screen.findByRole("button", { name: "Delete" }));
    expect(screen.getByRole("alertdialog")).toHaveAccessibleName(
      "Delete this encrypted item?",
    );
    await user.click(screen.getByRole("button", { name: "Delete item" }));

    await waitFor(() => {
      expect(invokeMock).toHaveBeenCalledWith("vault_delete_item", {
        itemId: ITEM_ID,
        expectedRevision: "1",
      });
    });
  });

  it("uploads a selected file through prepare and raw commit without browser storage", async () => {
    const user = userEvent.setup();
    const updatedItem = {
      ...item,
      revision: "2",
      attachments: [
        {
          attachmentId: ATTACHMENT_ID,
          filename: "synthetic.txt",
          mediaType: "text/plain",
          byteLength: "9",
        },
      ],
      updatedAtMs: "1700000000001",
    };
    invokeMock.mockImplementation((command) => {
      if (command === "vault_status") return resolved({ state: "unlocked" });
      if (command === "vault_list_items") return resolved({ items: [summary] });
      if (command === "vault_get_item") return resolved({ item });
      if (command === "vault_prepare_attachment") {
        return resolved({
          uploadId: "33333333333333333333333333333333",
          expiresInSeconds: 300,
        });
      }
      if (command === "vault_commit_attachment") {
        return resolved({ item: updatedItem });
      }
      throw new Error("unexpected command");
    });
    renderApplication();
    await user.click(
      await screen.findByRole("button", { name: /Synthetic title/ }),
    );
    await user.click(
      await screen.findByRole("button", { name: "Add attachment" }),
    );

    const file = new File(["synthetic"], "synthetic.txt", {
      type: "text/plain",
    });
    Object.defineProperty(file, "arrayBuffer", {
      value: () =>
        Promise.resolve(new TextEncoder().encode("synthetic").buffer),
    });
    fireEvent.change(screen.getByLabelText("Choose an attachment file"), {
      target: { files: [file] },
    });

    await waitFor(() => {
      expect(invokeMock).toHaveBeenCalledWith(
        "vault_commit_attachment",
        expect.any(Uint8Array),
        {
          headers: {
            "x-aeterna-upload-id": "33333333333333333333333333333333",
          },
        },
      );
    });
    expect(Object.keys(window.localStorage)).toEqual([]);
  });

  it("restores supported locale preferences only", () => {
    expect(resolveSavedLocale(null)).toBe(DEFAULT_LOCALE);
    expect(resolveSavedLocale("fr-FR")).toBe(DEFAULT_LOCALE);
    window.localStorage.setItem(LOCALE_STORAGE_KEY, "zh-CN");
    invokeMock.mockResolvedValue({ state: "locked" });
    renderApplication();
    expect(screen.getByText("I06 本地开发预览")).toBeInTheDocument();
  });
});
