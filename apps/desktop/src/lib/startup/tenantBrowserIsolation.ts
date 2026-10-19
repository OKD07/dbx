const OWNER_KEY = "dbx-browser-tenant-owner";
const DATABASES = ["dbx-app-state", "dbx-tab-runtime-cache", "dbx-nacos-replace-history"];

function deleteDatabase(name: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.deleteDatabase(name);
    request.onsuccess = () => resolve();
    request.onerror = () => reject(request.error ?? new Error("TENANT_BROWSER_ISOLATION_FAILED"));
    request.onblocked = () => reject(new Error("TENANT_BROWSER_STORAGE_BLOCKED"));
  });
}

/** Clear origin-wide browser caches before any tenant's business modules load. */
export async function ensureTenantBrowserIsolation(tenantId: string): Promise<void> {
  if (!/^[0-9a-f]{64}$/.test(tenantId)) throw new Error("TENANT_ID_INVALID");
  if (localStorage.getItem(OWNER_KEY) === tenantId) return;
  localStorage.clear();
  if (typeof indexedDB !== "undefined") {
    for (const name of DATABASES) await deleteDatabase(name);
  }
  localStorage.setItem(OWNER_KEY, tenantId);
}

/** A different account signing in from another tab invalidates this tab's view. */
export function reloadOnTenantSwitch(tenantId: string): () => void {
  const listener = (event: StorageEvent) => {
    if (event.storageArea === localStorage && (event.key === null || event.key === OWNER_KEY) && event.newValue !== tenantId) {
      window.location.reload();
    }
  };
  window.addEventListener("storage", listener);
  return () => window.removeEventListener("storage", listener);
}
