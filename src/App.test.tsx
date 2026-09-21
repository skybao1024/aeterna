import { act, render, screen, waitFor } from "@testing-library/react";
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
      (command: string, args?: Record<string, unknown>) => Promise<unknown>
    >(),
}));

vi.mock("@tauri-apps/api/core", () => ({ invoke: invokeMock }));

function renderApplication() {
  const instance = createI18n(window.localStorage);
  render(
    <I18nextProvider i18n={instance}>
      <App />
    </I18nextProvider>,
  );
  return instance;
}

describe("desktop foundation shell", () => {
  beforeEach(() => {
    window.localStorage.clear();
    invokeMock.mockResolvedValue({
      status: "ready",
      displayName: "Contributor",
    });
  });

  it("renders the baseline shell in English and invokes typed IPC", async () => {
    renderApplication();

    expect(
      screen.getByRole("heading", {
        name: "A quiet foundation for work that must endure.",
      }),
    ).toBeInTheDocument();

    await waitFor(() => {
      expect(
        screen.getByText("Native IPC is ready for Contributor."),
      ).toBeInTheDocument();
    });
    expect(invokeMock).toHaveBeenCalledWith("check_desktop_foundation", {
      request: { displayName: "Contributor" },
    });
  });

  it("switches to Simplified Chinese and persists the preference", async () => {
    const user = userEvent.setup();
    renderApplication();

    await user.click(
      screen.getByRole("button", {
        name: "Language: Switch to Simplified Chinese",
      }),
    );

    expect(
      screen.getByRole("heading", {
        name: "为必须经得起时间考验的工作打下安静的基础。",
      }),
    ).toBeInTheDocument();
    expect(window.localStorage.getItem(LOCALE_STORAGE_KEY)).toBe("zh-CN");
  });

  it("restores a supported saved locale", () => {
    window.localStorage.setItem(LOCALE_STORAGE_KEY, "zh-CN");
    renderApplication();

    expect(screen.getByText("简体中文")).toBeInTheDocument();
  });

  it("falls back to English for missing and unsupported saved locales", () => {
    expect(resolveSavedLocale(null)).toBe(DEFAULT_LOCALE);
    expect(resolveSavedLocale("fr-FR")).toBe(DEFAULT_LOCALE);
  });

  it("shows a localized safe message when native IPC is unavailable", async () => {
    invokeMock.mockRejectedValue(new Error("synthetic failure"));
    renderApplication();

    await act(async () => {
      await Promise.resolve();
    });

    expect(
      await screen.findByText("Native IPC is unavailable in this environment."),
    ).toBeInTheDocument();
  });
});
