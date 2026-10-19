import { apiUrl } from "@/lib/common/webPath";

export interface StartupAuthentication {
  required: boolean;
  authenticated: boolean;
  setup_required: boolean;
  provider?: "password" | "oidc";
  tenant_id?: string;
}

export async function checkStartupAuthentication(signal?: AbortSignal): Promise<StartupAuthentication> {
  const response = await fetch(apiUrl("/api/auth/check"), { credentials: "same-origin", signal });
  if (!response.ok) throw new Error("AUTH_CHECK_FAILED");
  const result: unknown = await response.json();
  if (!result || typeof result !== "object" || !("required" in result) || !("authenticated" in result) || typeof result.required !== "boolean" || typeof result.authenticated !== "boolean") {
    throw new Error("AUTH_CHECK_FAILED");
  }
  return {
    required: result.required,
    authenticated: result.authenticated,
    setup_required: "setup_required" in result && result.setup_required === true,
    ...("provider" in result && result.provider === "oidc" ? { provider: "oidc" as const } : {}),
    ...("tenant_id" in result && typeof result.tenant_id === "string" ? { tenant_id: result.tenant_id } : {}),
  };
}

export async function logoutWeb(): Promise<void> {
  const response = await fetch(apiUrl("/api/auth/logout"), {
    method: "POST",
    credentials: "same-origin",
  });
  if (!response.ok) {
    throw new Error("AUTH_LOGOUT_FAILED");
  }
}
