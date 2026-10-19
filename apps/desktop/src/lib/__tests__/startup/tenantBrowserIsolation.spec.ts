// @vitest-environment happy-dom
import { afterEach, describe, expect, it, vi } from "vitest";
import { ensureTenantBrowserIsolation } from "@/lib/startup/tenantBrowserIsolation";

const alice = "a".repeat(64);
const bob = "b".repeat(64);

afterEach(() => {
  localStorage.clear();
  vi.unstubAllGlobals();
});

describe("tenant browser isolation", () => {
  it("removes browser data before granting a different account access", async () => {
    const deleted: string[] = [];
    vi.stubGlobal("indexedDB", {
      deleteDatabase(name: string) {
        deleted.push(name);
        const request: { onsuccess?: () => void } = {};
        queueMicrotask(() => request.onsuccess?.());
        return request;
      },
    });
    localStorage.setItem("old-account-query", "SELECT secret");
    await ensureTenantBrowserIsolation(alice);
    expect(localStorage.getItem("old-account-query")).toBeNull();
    expect(deleted).toEqual(["dbx-app-state", "dbx-tab-runtime-cache", "dbx-nacos-replace-history"]);
    await ensureTenantBrowserIsolation(alice);
    expect(deleted).toHaveLength(3);
    localStorage.setItem("old-account-query", "SELECT secret");
    await ensureTenantBrowserIsolation(bob);
    expect(localStorage.getItem("old-account-query")).toBeNull();
    expect(deleted).toHaveLength(6);
  });

  it("refuses access when another tab prevents database removal", async () => {
    vi.stubGlobal("indexedDB", {
      deleteDatabase() {
        const request: { onblocked?: () => void } = {};
        queueMicrotask(() => request.onblocked?.());
        return request;
      },
    });
    await expect(ensureTenantBrowserIsolation(alice)).rejects.toThrow("TENANT_BROWSER_STORAGE_BLOCKED");
    expect(localStorage.getItem("dbx-browser-tenant-owner")).toBeNull();
  });
});
