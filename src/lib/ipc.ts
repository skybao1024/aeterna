import { invoke } from "@tauri-apps/api/core";

export interface FoundationRequest {
  displayName: string;
}

export interface FoundationResponse {
  status: "ready";
  displayName: string;
}

function isFoundationResponse(value: unknown): value is FoundationResponse {
  if (typeof value !== "object" || value === null) {
    return false;
  }

  const response = value as Record<string, unknown>;
  return (
    response.status === "ready" && typeof response.displayName === "string"
  );
}

export async function checkDesktopFoundation(
  request: FoundationRequest,
): Promise<FoundationResponse> {
  const response = await invoke<unknown>("check_desktop_foundation", {
    request,
  });
  if (!isFoundationResponse(response)) {
    throw new Error("The native foundation response is invalid.");
  }
  return response;
}
