/**
 * tests for frontend/src/lib/api.js
 *
 * Runner : Jest (CRA default)
 * Mocks  : axios, @/lib/supabase
 */

import axios from "axios";

// ── Axios mock ────────────────────────────────────────────────────────────────
// Must be declared before the module under test is imported so Jest can hoist
// the factory.  We expose a shared `mockInstance` so individual tests can
// inspect / override method implementations.

const mockGet    = jest.fn();
const mockPost   = jest.fn();
const mockPatch  = jest.fn();
const mockDelete = jest.fn();

const mockResponseInterceptorUse = jest.fn();

const mockAxiosInstance = {
  get:    mockGet,
  post:   mockPost,
  patch:  mockPatch,
  delete: mockDelete,
  interceptors: {
    request:  { use: jest.fn() },
    response: { use: mockResponseInterceptorUse },
  },
};

jest.mock("axios", () => {
  const actual = jest.requireActual("axios");
  return {
    ...actual,
    create: jest.fn(() => mockAxiosInstance),
  };
});

// ── Supabase mock ─────────────────────────────────────────────────────────────
const mockSignOut = jest.fn(() => Promise.resolve({ error: null }));

jest.mock("@/lib/supabase", () => ({
  supabase: {
    auth: {
      signOut: mockSignOut,
    },
  },
}));

// ── Module under test ─────────────────────────────────────────────────────────
// Import AFTER mocks are set up.
import {
  API_BASE,
  auth,
  audit,
  dashboard,
  events,
  health,
  integrations,
  paymentMethods,
  payments,
  policies,
  prompts,
  tools,
} from "@/lib/api";

// ── Helpers ───────────────────────────────────────────────────────────────────

/** Extract the success/error handlers registered with the response interceptor. */
function getInterceptorHandlers() {
  // mockResponseInterceptorUse is called exactly once during module init.
  const [onFulfilled, onRejected] = mockResponseInterceptorUse.mock.calls[0];
  return { onFulfilled, onRejected };
}

// ── Setup / teardown ──────────────────────────────────────────────────────────

beforeEach(() => {
  jest.clearAllMocks();
  delete window.location;
  window.location = { href: "" };
});

// =============================================================================
// axios.create — base URL construction
// =============================================================================

describe("axios.create", () => {
  it("calls axios.create exactly once during module initialisation", () => {
    expect(axios.create).toHaveBeenCalledTimes(1);
  });

  it("passes baseURL equal to API_BASE", () => {
    const [config] = axios.create.mock.calls[0];
    expect(config.baseURL).toBe(API_BASE);
  });

  it("sets a timeout", () => {
    const [config] = axios.create.mock.calls[0];
    expect(typeof config.timeout).toBe("number");
    expect(config.timeout).toBeGreaterThan(0);
  });
});

// =============================================================================
// API_BASE construction
// =============================================================================

describe("API_BASE", () => {
  it("ends with /api", () => {
    expect(API_BASE.endsWith("/api")).toBe(true);
  });

  it("is a non-empty string", () => {
    expect(typeof API_BASE).toBe("string");
    expect(API_BASE.length).toBeGreaterThan(0);
  });

  it("is derived from REACT_APP_BACKEND_URL when set", () => {
    const backendUrl =
      process.env.REACT_APP_BACKEND_URL || "http://127.0.0.1:8000";
    expect(API_BASE).toBe(`${backendUrl}/api`);
  });
});

// =============================================================================
// 401 response interceptor
// =============================================================================

describe("401 response interceptor", () => {
  it("registers exactly one response interceptor", () => {
    expect(mockResponseInterceptorUse).toHaveBeenCalledTimes(1);
  });

  it("passes a fulfillment handler that returns the response unchanged", async () => {
    const { onFulfilled } = getInterceptorHandlers();
    const fakeRes = { status: 200, data: {} };
    const result = await onFulfilled(fakeRes);
    expect(result).toBe(fakeRes);
  });

  it("calls supabase.auth.signOut() on a 401 error", async () => {
    const { onRejected } = getInterceptorHandlers();
    const error401 = { response: { status: 401 } };
    await onRejected(error401).catch(() => {});
    expect(mockSignOut).toHaveBeenCalledTimes(1);
  });

  it("sets window.location.href to '/' on a 401 error", async () => {
    const { onRejected } = getInterceptorHandlers();
    const error401 = { response: { status: 401 } };
    await onRejected(error401).catch(() => {});
    expect(window.location.href).toBe("/");
  });

  it("rejects the promise so callers receive the error after 401 handling", async () => {
    const { onRejected } = getInterceptorHandlers();
    const error401 = { response: { status: 401 } };
    await expect(onRejected(error401)).rejects.toEqual(error401);
  });

  it("does NOT call supabase.auth.signOut() for non-401 errors", async () => {
    const { onRejected } = getInterceptorHandlers();
    const error403 = { response: { status: 403 } };
    await onRejected(error403).catch(() => {});
    expect(mockSignOut).not.toHaveBeenCalled();
  });

  it("does NOT redirect for non-401 errors", async () => {
    const { onRejected } = getInterceptorHandlers();
    const error500 = { response: { status: 500 } };
    await onRejected(error500).catch(() => {});
    expect(window.location.href).toBe("");
  });

  it("does NOT call supabase.auth.signOut() when error has no response", async () => {
    const { onRejected } = getInterceptorHandlers();
    const networkError = new Error("Network Error");
    await onRejected(networkError).catch(() => {});
    expect(mockSignOut).not.toHaveBeenCalled();
  });

  it("does NOT redirect when error has no response", async () => {
    const { onRejected } = getInterceptorHandlers();
    const networkError = new Error("Network Error");
    await onRejected(networkError).catch(() => {});
    expect(window.location.href).toBe("");
  });
});

// =============================================================================
// paymentMethods.list
// =============================================================================

describe("paymentMethods.list", () => {
  it("calls api.get with the correct URL for a plain orgId", () => {
    mockGet.mockResolvedValueOnce({ data: {} });
    paymentMethods.list("org-001");
    expect(mockGet).toHaveBeenCalledWith(
      "/ui/billing/payment-methods?organizationid=org-001",
    );
  });

  it("URL-encodes the orgId", () => {
    mockGet.mockResolvedValueOnce({ data: {} });
    paymentMethods.list("org/special chars&more");
    const [url] = mockGet.mock.calls[0];
    expect(url).toContain(
      `organizationid=${encodeURIComponent("org/special chars&more")}`,
    );
  });

  it("returns the axios promise", () => {
    const fakePromise = Promise.resolve({ data: [] });
    mockGet.mockReturnValueOnce(fakePromise);
    const result = paymentMethods.list("org-001");
    expect(result).toBe(fakePromise);
  });

  it("calls api.get exactly once per invocation", () => {
    mockGet.mockResolvedValueOnce({ data: {} });
    paymentMethods.list("org-001");
    expect(mockGet).toHaveBeenCalledTimes(1);
  });
});

// =============================================================================
// paymentMethods.setDefault
// =============================================================================

describe("paymentMethods.setDefault", () => {
  it("calls api.patch with the correct URL for plain ids", () => {
    mockPatch.mockResolvedValueOnce({ data: {} });
    paymentMethods.setDefault("pm-001", "org-001");
    expect(mockPatch).toHaveBeenCalledWith(
      "/ui/billing/payment-methods/pm-001/default?organizationid=org-001",
    );
  });

  it("URL-encodes the methodId", () => {
    mockPatch.mockResolvedValueOnce({ data: {} });
    paymentMethods.setDefault("pm/001 x", "org-001");
    const [url] = mockPatch.mock.calls[0];
    expect(url).toContain(
      `/ui/billing/payment-methods/${encodeURIComponent("pm/001 x")}/default`,
    );
  });

  it("URL-encodes the orgId", () => {
    mockPatch.mockResolvedValueOnce({ data: {} });
    paymentMethods.setDefault("pm-001", "org/001 x");
    const [url] = mockPatch.mock.calls[0];
    expect(url).toContain(
      `organizationid=${encodeURIComponent("org/001 x")}`,
    );
  });

  it("URL-encodes both methodId and orgId independently", () => {
    mockPatch.mockResolvedValueOnce({ data: {} });
    paymentMethods.setDefault("pm/a b", "org/c d");
    const [url] = mockPatch.mock.calls[0];
    expect(url).toBe(
      `/ui/billing/payment-methods/${encodeURIComponent("pm/a b")}/default?organizationid=${encodeURIComponent("org/c d")}`,
    );
  });

  it("returns the axios promise", () => {
    const fakePromise = Promise.resolve({ data: {} });
    mockPatch.mockReturnValueOnce(fakePromise);
    const result = paymentMethods.setDefault("pm-001", "org-001");
    expect(result).toBe(fakePromise);
  });

  it("uses PATCH, not GET or DELETE", () => {
    mockPatch.mockResolvedValueOnce({ data: {} });
    paymentMethods.setDefault("pm-001", "org-001");
    expect(mockPatch).toHaveBeenCalledTimes(1);
    expect(mockGet).not.toHaveBeenCalled();
    expect(mockDelete).not.toHaveBeenCalled();
  });
});

// =============================================================================
// paymentMethods.delete
// =============================================================================

describe("paymentMethods.delete", () => {
  it("calls api.delete with the correct URL for plain ids", () => {
    mockDelete.mockResolvedValueOnce({ data: {} });
    paymentMethods.delete("pm-001", "org-001");
    expect(mockDelete).toHaveBeenCalledWith(
      "/ui/billing/payment-methods/pm-001?organizationid=org-001",
    );
  });

  it("URL-encodes the methodId", () => {
    mockDelete.mockResolvedValueOnce({ data: {} });
    paymentMethods.delete("pm/001 x", "org-001");
    const [url] = mockDelete.mock.calls[0];
    expect(url).toContain(
      `/ui/billing/payment-methods/${encodeURIComponent("pm/001 x")}`,
    );
  });

  it("URL-encodes the orgId", () => {
    mockDelete.mockResolvedValueOnce({ data: {} });
    paymentMethods.delete("pm-001", "org/001 x");
    const [url] = mockDelete.mock.calls[0];
    expect(url).toContain(
      `organizationid=${encodeURIComponent("org/001 x")}`,
    );
  });

  it("URL-encodes both methodId and orgId independently", () => {
    mockDelete.mockResolvedValueOnce({ data: {} });
    paymentMethods.delete("pm/a b", "org/c d");
    const [url] = mockDelete.mock.calls[0];
    expect(url).toBe(
      `/ui/billing/payment-methods/${encodeURIComponent("pm/a b")}?organizationid=${encodeURIComponent("org/c d")}`,
    );
  });

  it("returns the axios promise", () => {
    const fakePromise = Promise.resolve({ data: {} });
    mockDelete.mockReturnValueOnce(fakePromise);
    const result = paymentMethods.delete("pm-001", "org-001");
    expect(result).toBe(fakePromise);
  });

  it("uses DELETE, not GET or PATCH", () => {
    mockDelete.mockResolvedValueOnce({ data: {} });
    paymentMethods.delete("pm-001", "org-001");
    expect(mockDelete).toHaveBeenCalledTimes(1);
    expect(mockGet).not.toHaveBeenCalled();
    expect(mockPatch).not.toHaveBeenCalled();
  });
});

// =============================================================================
// payments.createCheckout
// =============================================================================

describe("payments.createCheckout", () => {
  it("calls api.post with /payments/create-checkout", () => {
    mockPost.mockResolvedValueOnce({ data: {} });
    const payload = { plan: "starter", quantity: 1 };
    payments.createCheckout(payload);
    expect(mockPost).toHaveBeenCalledWith("/payments/create-checkout", payload);
  });

  it("forwards the payload untouched", () => {
    mockPost.mockResolvedValueOnce({ data: {} });
    const payload = { plan: "enterprise", organizationid: "org-99" };
    payments.createCheckout(payload);
    const [, sentPayload] = mockPost.mock.calls[0];
    expect(sentPayload).toEqual(payload);
  });

  it("returns the axios promise", () => {
    const fakePromise = Promise.resolve({ data: { url: "https://stripe.example" } });
    mockPost.mockReturnValueOnce(fakePromise);
    expect(payments.createCheckout({})).toBe(fakePromise);
  });

  it("uses POST, not GET", () => {
    mockPost.mockResolvedValueOnce({ data: {} });
    payments.createCheckout({});
    expect(mockPost).toHaveBeenCalledTimes(1);
    expect(mockGet).not.toHaveBeenCalled();
  });
});

// =============================================================================
// payments.getStatus
// =============================================================================

describe("payments.getStatus", () => {
  it("calls api.get with the correct URL including sessionId", () => {
    mockGet.mockResolvedValueOnce({ data: {} });
    payments.getStatus("cs_test_abc123");
    expect(mockGet).toHaveBeenCalledWith("/payments/status/cs_test_abc123");
  });

  it("interpolates the sessionId directly into the path", () => {
    mockGet.mockResolvedValueOnce({ data: {} });
    payments.getStatus("cs_live_xyz789");
    const [url] = mockGet.mock.calls[0];
    expect(url).toBe("/payments/status/cs_live_xyz789");
  });

  it("returns the axios promise", () => {
    const fakePromise = Promise.resolve({ data: { status: "complete" } });
    mockGet.mockReturnValueOnce(fakePromise);
    expect(payments.getStatus("cs_test_abc")).toBe(fakePromise);
  });

  it("uses GET, not POST or PATCH", () => {
    mockGet.mockResolvedValueOnce({ data: {} });
    payments.getStatus("cs_test_abc");
    expect(mockGet).toHaveBeenCalledTimes(1);
    expect(mockPost).not.toHaveBeenCalled();
    expect(mockPatch).not.toHaveBeenCalled();
  });
});

// =============================================================================
// Smoke tests — other exported call shapes
// =============================================================================

describe("health.check", () => {
  it("calls api.get('/')", () => {
    mockGet.mockResolvedValueOnce({ data: {} });
    health.check();
    expect(mockGet).toHaveBeenCalledWith("/");
  });
});

describe("auth.me", () => {
  it("calls api.get('/auth/me')", () => {
    mockGet.mockResolvedValueOnce({ data: {} });
    auth.me();
    expect(mockGet).toHaveBeenCalledWith("/auth/me");
  });
});

describe("dashboard.get", () => {
  it("calls api.get('/dashboard')", () => {
    mockGet.mockResolvedValueOnce({ data: {} });
    dashboard.get();
    expect(mockGet).toHaveBeenCalledWith("/dashboard");
  });
});

describe("events.simulate", () => {
  it("calls api.post('/events/simulate')", () => {
    mockPost.mockResolvedValueOnce({ data: {} });
    events.simulate();
    expect(mockPost).toHaveBeenCalledWith("/events/simulate");
  });
});

describe("integrations.getToken", () => {
  it("calls api.get('/integrations/token')", () => {
    mockGet.mockResolvedValueOnce({ data: {} });
    integrations.getToken();
    expect(mockGet).toHaveBeenCalledWith("/integrations/token");
  });
});

describe("prompts.inspect", () => {
  it("calls api.post('/inspect', payload)", () => {
    mockPost.mockResolvedValueOnce({ data: {} });
    const payload = { prompt: "test" };
    prompts.inspect(payload);
    expect(mockPost).toHaveBeenCalledWith("/inspect", payload);
  });
});

describe("audit.getLogs", () => {
  it("calls api.get('/audit/logs', { params })", () => {
    mockGet.mockResolvedValueOnce({ data: [] });
    const params = { page: 1, limit: 50 };
    audit.getLogs(params);
    expect(mockGet).toHaveBeenCalledWith("/audit/logs", { params });
  });
});

describe("tools.inspect", () => {
  it("calls api.post('/tools/inspect', payload)", () => {
    mockPost.mockResolvedValueOnce({ data: {} });
    const payload = { tool: "bash", args: [] };
    tools.inspect(payload);
    expect(mockPost).toHaveBeenCalledWith("/tools/inspect", payload);
  });
});

describe("policies", () => {
  it("list() calls api.get('/policies')", () => {
    mockGet.mockResolvedValueOnce({ data: [] });
    policies.list();
    expect(mockGet).toHaveBeenCalledWith("/policies");
  });

  it("get(id) calls api.get('/policies/<id>')", () => {
    mockGet.mockResolvedValueOnce({ data: {} });
    policies.get("pol-001");
    expect(mockGet).toHaveBeenCalledWith("/policies/pol-001");
  });

  it("create(payload) calls api.post('/policies', payload)", () => {
    mockPost.mockResolvedValueOnce({ data: {} });
    const payload = { name: "deny-all" };
    policies.create(payload);
    expect(mockPost).toHaveBeenCalledWith("/policies", payload);
  });

  it("update(id, payload) calls api.put('/policies/<id>', payload)", () => {
    const mockPut = jest.fn().mockResolvedValueOnce({ data: {} });
    mockAxiosInstance.put = mockPut;
    const payload = { name: "allow-safe" };
    policies.update("pol-001", payload);
    expect(mockPut).toHaveBeenCalledWith("/policies/pol-001", payload);
  });

  it("delete(id) calls api.delete('/policies/<id>')", () => {
    mockDelete.mockResolvedValueOnce({ data: {} });
    policies.delete("pol-001");
    expect(mockDelete).toHaveBeenCalledWith("/policies/pol-001");
  });
});
