import { describe, expect, it } from "vitest";

import capability from "../src-tauri/capabilities/main-foundation.json";
import tauriConfig from "../src-tauri/tauri.conf.json";

describe("Tauri security baseline", () => {
  it("grants the main window only the approved vault and lifecycle surface", () => {
    expect(tauriConfig.identifier).toBe("dev.aeterna.desktop.foundation");
    expect(tauriConfig.app.security.capabilities).toEqual(["main-foundation"]);
    expect(capability.windows).toEqual(["main"]);
    expect(capability.permissions).toEqual([
      "allow-vault-status",
      "allow-vault-initialize",
      "allow-vault-unlock",
      "allow-vault-lock",
      "allow-vault-list-items",
      "allow-vault-get-item",
      "allow-vault-create-item",
      "allow-vault-update-item",
      "allow-vault-delete-item",
      "allow-vault-prepare-attachment",
      "allow-vault-commit-attachment",
      "allow-vault-cancel-attachment",
      "allow-vault-read-attachment",
      "allow-vault-remove-attachment",
      "allow-vault-export-choose",
      "allow-vault-export-start",
      "allow-vault-import-choose",
      "allow-vault-import-start",
      "allow-vault-transfer-status",
      "allow-vault-transfer-cancel",
      "allow-lifecycle-status",
      "allow-lifecycle-set-autostart",
      "allow-lifecycle-request-notification-permission",
      "allow-lifecycle-set-locale",
      "allow-lifecycle-reset-health-state",
      "core:event:allow-listen",
      "core:event:allow-unlisten",
    ]);
    expect(tauriConfig.app.security.assetProtocol).toEqual({
      enable: false,
      scope: [],
    });
  });

  it("keeps remote origins out of the production CSP", () => {
    const productionCsp = Object.values(tauriConfig.app.security.csp).join(" ");

    expect(tauriConfig.app.security.csp["connect-src"]).toBe(
      "'self' ipc: http://ipc.localhost",
    );
    expect(productionCsp.match(/https?:\/\/[^\s]+/gu)).toEqual([
      "http://ipc.localhost",
    ]);
    expect(productionCsp).not.toMatch(/wss?:\/\//u);
    for (const directive of [
      "object-src",
      "frame-src",
      "child-src",
      "worker-src",
      "media-src",
      "manifest-src",
    ] as const) {
      expect(tauriConfig.app.security.csp[directive]).toBe("'none'");
    }
  });

  it("starts the macOS 15 lifecycle window hidden", () => {
    expect(tauriConfig.app.windows[0]?.visible).toBe(false);
    expect(tauriConfig.bundle.macOS.minimumSystemVersion).toBe("15.0");
  });
});
