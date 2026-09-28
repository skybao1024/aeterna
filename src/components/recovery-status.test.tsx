import { render, screen } from "@testing-library/react";
import { I18nextProvider } from "react-i18next";
import { describe, expect, it } from "vitest";

import { createI18n } from "../i18n";
import { RecoveryStatusPanel } from "./recovery-status";

function renderPanel(
  state: Parameters<typeof RecoveryStatusPanel>[0]["state"],
) {
  const storage = { getItem: () => "en" };
  render(
    <I18nextProvider i18n={createI18n(storage)}>
      <RecoveryStatusPanel state={state} />
    </I18nextProvider>,
  );
}

describe("RecoveryStatusPanel", () => {
  it("shows incomplete devices instead of reporting full protection", () => {
    renderPanel({
      kind: "partial",
      devices: [
        { deviceId: "device-a", label: "MacBook", state: "complete" },
        { deviceId: "device-b", label: "Mac mini", state: "pending" },
      ],
    });

    expect(screen.getByText(/not all devices are protected/i)).toBeVisible();
    expect(screen.getByText("Mac mini")).toBeVisible();
    expect(screen.getByText("Pending")).toBeVisible();
    expect(screen.queryByText(/^Protected$/)).not.toBeInTheDocument();
  });

  it("makes post-compromise rekey a blocking state", () => {
    renderPanel({ kind: "rekey_required" });

    expect(screen.getByText(/must be re-encrypted/i)).toBeVisible();
  });
});
