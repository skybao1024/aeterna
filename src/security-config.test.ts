import { describe, expect, it } from "vitest";

import capability from "../src-tauri/capabilities/main-foundation.json";
import tauriConfig from "../src-tauri/tauri.conf.json";

describe("Tauri security baseline", () => {
  it("grants the main window only the narrow foundation command", () => {
    expect(tauriConfig.identifier).toBe("dev.aeterna.desktop.foundation");
    expect(tauriConfig.app.security.capabilities).toEqual(["main-foundation"]);
    expect(capability.windows).toEqual(["main"]);
    expect(capability.permissions).toEqual(["allow-check-desktop-foundation"]);
    expect(tauriConfig.app.security.assetProtocol).toEqual({
      enable: false,
      scope: [],
    });
  });

  it("keeps remote origins out of the production CSP", () => {
    const productionCsp = Object.values(tauriConfig.app.security.csp).join(" ");

    expect(tauriConfig.app.security.csp["connect-src"]).toBe(
      "ipc: http://ipc.localhost",
    );
    expect(productionCsp.match(/https?:\/\/[^\s]+/gu)).toEqual([
      "http://ipc.localhost",
    ]);
    expect(productionCsp).not.toMatch(/wss?:\/\//u);
    expect(tauriConfig.app.security.csp["object-src"]).toBe("'none'");
    expect(tauriConfig.app.security.csp["frame-src"]).toBe("'none'");
  });
});
