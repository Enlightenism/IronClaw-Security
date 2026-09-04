jest.mock("axios", () => {
  const mockAxiosInstance = {
    get: jest.fn(),
    post: jest.fn(),
    patch: jest.fn(),
    delete: jest.fn(),
    put: jest.fn(),
    interceptors: {
      request: { use: jest.fn() },
      response: { use: jest.fn() },
    },
  };

  return {
    __esModule: true,
    default: { create: jest.fn(() => mockAxiosInstance) },
  };
});

jest.mock("@/lib/supabase", () => ({
  supabase: {
    auth: {
      getSession: jest.fn(() =>
        Promise.resolve({
          data: { session: null },
        }),
      ),
      signOut: jest.fn(() => Promise.resolve({ error: null })),
    },
  },
}));

import axios from "axios";
import { supabase } from "@/lib/supabase";
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

// ── Capture everything at import time, before clearMocks wipes history ──────
const mockAxiosInstance = axios.create.mock.results[0].value;
const mockGet = mockAxiosInstance.get;
const mockPost = mockAxiosInstance.post;
const mockPatch = mockAxiosInstance.patch;
const mockDelete = mockAxiosInstance.delete;
const mockPut = mockAxiosInstance.put;
const mockRequestInterceptorUse = mockAxiosInstance.interceptors.request.use;
const mockResponseInterceptorUse = mockAxiosInstance.interceptors.response.use;
const mockGetSession = supabase.auth.getSession;
const mockSignOut = supabase.auth.signOut;

const axiosCreateCallCount = axios.create.mock.calls.length;
const axiosCreateConfig = axios.create.mock.calls[0]?.[0];
const requestInterceptorCallCount = mockRequestInterceptorUse.mock.calls.length;
const responseInterceptorCallCount =
  mockResponseInterceptorUse.mock.calls.length;
const [, capturedRequestHandler] = [
  null,
  mockRequestInterceptorUse.mock.calls[0]?.[0],
];
const [capturedOnFulfilled, capturedOnRejected] =
  mockResponseInterceptorUse.mock.calls[0] || [];

beforeEach(() => {
  mockGet.mockClear();
  mockPost.mockClear();
  mockPatch.mockClear();
  mockDelete.mockClear();
  mockPut.mockClear();
  mockGetSession.mockClear();
  mockSignOut.mockClear();
  mockGetSession.mockResolvedValue({
    data: { session: null },
  });
});

describe("axios.create", () => {
  it("calls axios.create exactly once during module initialisation", () => {
    expect(axiosCreateCallCount).toBe(1);
  });

  it("passes baseURL equal to API_BASE", () => {
    expect(axiosCreateConfig.baseURL).toBe(API_BASE);
  });

  it("sets the expected timeout", () => {
    expect(axiosCreateConfig.timeout).toBe(15000);
  });
});

describe("API_BASE", () => {
  it("ends with /api", () => {
    expect(API_BASE.endsWith("/api")).toBe(true);
  });

  it("is derived from REACT_APP_API_BASE_URL when set or localhost fallback otherwise", () => {
    const backendUrl =
      process.env.REACT_APP_API_BASE_URL || "http://127.0.0.1:8000";
    expect(API_BASE).toBe(`${backendUrl}/api`);
  });
});

describe("request interceptor", () => {
  const originalLocalStorage = global.localStorage;

  beforeEach(() => {
    Object.defineProperty(global, "localStorage", {
      value: {
        getItem: jest.fn(() => null),
      },
      configurable: true,
      writable: true,
    });
  });

  afterEach(() => {
    Object.defineProperty(global, "localStorage", {
      value: originalLocalStorage,
      configurable: true,
      writable: true,
    });
  });

  it("registers exactly one request interceptor", () => {
    expect(requestInterceptorCallCount).toBe(1);
  });

  it("adds Authorization and X-Org-Id headers from the active Supabase session", async () => {
    mockGetSession.mockResolvedValueOnce({
      data: {
        session: {
          access_token: "token-123",
          user: {
            id: "user-1",
            user_metadata: { org_id: "org-123" },
            app_metadata: {},
          },
        },
      },
    });

    const config = { headers: {} };
    const result = await capturedRequestHandler(config);

    expect(result.headers.Authorization).toBe("Bearer token-123");
    expect(result.headers["X-Org-Id"]).toBe("org-123");
  });

  it("falls back to localStorage token and org id when session is unavailable", async () => {
    global.localStorage.getItem = jest.fn((key) => {
      if (key === "ironclaw.auth.token") return "stored-token";
      if (key === "ironclaw.auth.orgId") return "stored-org";
      return null;
    });

    mockGetSession.mockResolvedValueOnce({
      data: { session: null },
    });

    const config = { headers: {} };
    const result = await capturedRequestHandler(config);

    expect(result.headers.Authorization).toBe("Bearer stored-token");
    expect(result.headers["X-Org-Id"]).toBe("stored-org");
  });

  it("removes auth headers when neither session nor storage values exist", async () => {
    global.localStorage.getItem = jest.fn(() => null);

    const config = {
      headers: {
        Authorization: "Bearer old-token",
        "X-Org-Id": "old-org",
      },
    };

    const result = await capturedRequestHandler(config);

    expect(result.headers.Authorization).toBeUndefined();
    expect(result.headers["X-Org-Id"]).toBeUndefined();
  });

  it("does not set X-API-Key from static platform env values", async () => {
    process.env.REACT_APP_IRONCLAW_API_KEY = "ic_platform_static_key";
    process.env.REACT_APP_PLATFORM_API_KEY = "platform-api-legacy";
    global.localStorage.getItem = jest.fn(() => null);

    const config = { headers: { "X-API-Key": "old-static-key" } };
    const result = await capturedRequestHandler(config);

    expect(result.headers["X-API-Key"]).toBeUndefined();

    delete process.env.REACT_APP_IRONCLAW_API_KEY;
    delete process.env.REACT_APP_PLATFORM_API_KEY;
  });
});

describe("401 response interceptor", () => {
  const originalHref = window.location.href;

  afterEach(() => {
    window.history.pushState(null, "", originalHref);
  });

  it("registers exactly one response interceptor", () => {
    expect(responseInterceptorCallCount).toBe(1);
  });

  it("passes a fulfillment handler that returns the response unchanged", async () => {
    const fakeRes = { status: 200, data: {} };
    const result = await capturedOnFulfilled(fakeRes);
    expect(result).toBe(fakeRes);
  });

  it("calls supabase.auth.getSession() on a 401 error", async () => {
    const error401 = { response: { status: 401 } };
    await capturedOnRejected(error401).catch(() => {});
    expect(mockGetSession).toHaveBeenCalledTimes(1);
  });

  it("calls supabase.auth.signOut() on a 401 error only when no active session exists", async () => {
    mockGetSession.mockResolvedValueOnce({
      data: { session: null },
    });

    const error401 = { response: { status: 401 } };
    await capturedOnRejected(error401).catch(() => {});
    expect(mockSignOut).toHaveBeenCalledTimes(1);
  });

  it("redirects to / on a 401 error only when no active session exists", async () => {
    mockGetSession.mockResolvedValueOnce({
      data: { session: null },
    });

    const error401 = { response: { status: 401 } };
    await capturedOnRejected(error401).catch(() => {});
    expect(window.location.pathname).toBe("/");
  });

  it("does NOT call supabase.auth.signOut() on a 401 error when an active session still exists", async () => {
    mockGetSession.mockResolvedValueOnce({
      data: {
        session: {
          access_token: "token-123",
          user: { id: "user-1", user_metadata: {}, app_metadata: {} },
        },
      },
    });

    const error401 = { response: { status: 401 } };
    await capturedOnRejected(error401).catch(() => {});
    expect(mockSignOut).not.toHaveBeenCalled();
  });

  it("does NOT redirect on a 401 error when an active session still exists", async () => {
    mockGetSession.mockResolvedValueOnce({
      data: {
        session: {
          access_token: "token-123",
          user: { id: "user-1", user_metadata: {}, app_metadata: {} },
        },
      },
    });

    const error401 = { response: { status: 401 } };
    await capturedOnRejected(error401).catch(() => {});
    expect(window.location.href).toBe(originalHref);
  });

  it("rejects the promise so callers receive the error after 401 handling", async () => {
    const error401 = { response: { status: 401 } };
    await expect(capturedOnRejected(error401)).rejects.toEqual(error401);
  });

  it("does NOT call supabase.auth.signOut() for non-401 errors", async () => {
    const error403 = { response: { status: 403 } };
    await capturedOnRejected(error403).catch(() => {});
    expect(mockSignOut).not.toHaveBeenCalled();
  });

  it("does NOT redirect for non-401 errors", async () => {
    const error500 = { response: { status: 500 } };
    await capturedOnRejected(error500).catch(() => {});
    expect(window.location.href).toBe(originalHref);
  });

  it("does NOT call supabase.auth.signOut() when error has no response", async () => {
    const networkError = new Error("Network Error");
    await capturedOnRejected(networkError).catch(() => {});
    expect(mockSignOut).not.toHaveBeenCalled();
  });

  it("does NOT redirect when error has no response", async () => {
    const networkError = new Error("Network Error");
    await capturedOnRejected(networkError).catch(() => {});
    expect(window.location.href).toBe(originalHref);
  });
});

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
  it("calls api.get('/dashboard/overview')", () => {
    mockGet.mockResolvedValueOnce({ data: {} });
    dashboard.get();
    expect(mockGet).toHaveBeenCalledWith("/dashboard/overview");
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

describe("payments.createCheckout", () => {
  it("calls api.post with /billing/checkout/sessions", () => {
    mockPost.mockResolvedValueOnce({ data: {} });
    const payload = { plan: "starter", quantity: 1 };
    payments.createCheckout(payload);
    expect(mockPost).toHaveBeenCalledWith(
      "/billing/checkout/sessions",
      payload,
    );
  });

  it("removes raw card values and carries saved Stripe payment metadata without leaking PAN data", () => {
    mockPost.mockResolvedValueOnce({ data: {} });
    const payload = {
      packageId: "pkg5000",
      organizationId: "org-001",
      paymentMethod: {
        id: "pm_saved_123",
        customer: "cus_123",
        card: {
          number: "4242424242424242",
          last4: "4242",
          brand: "Visa",
        },
      },
      customer: { id: "cus_123" },
      card: { number: "4242424242424242", cvc: "123" },
    };

    payments.createCheckout(payload);

    const [, sentPayload] = mockPost.mock.calls.at(-1);
    expect(sentPayload.card).toBeUndefined();
    expect(sentPayload.customer).toBeUndefined();
    expect(sentPayload.paymentMethod).toBeUndefined();
    expect(sentPayload.paymentMethodId).toBe("pm_saved_123");
    expect(sentPayload.customerId).toBe("cus_123");
    expect(JSON.stringify(sentPayload)).not.toContain("4242424242424242");
  });
});

describe("payments.getStatus", () => {
  it("calls api.get with the correct URL including sessionId", () => {
    mockGet.mockResolvedValueOnce({ data: {} });
    payments.getStatus("cs_test_abc123");
    expect(mockGet).toHaveBeenCalledWith(
      "/billing/checkout/sessions/cs_test_abc123",
    );
  });
});

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
});

describe("paymentMethods.setDefault", () => {
  it("calls api.patch with the correct URL for plain ids", () => {
    mockPatch.mockResolvedValueOnce({ data: {} });
    paymentMethods.setDefault("pm-001", "org-001");
    expect(mockPatch).toHaveBeenCalledWith(
      "/ui/billing/payment-methods/pm-001/default?organizationid=org-001",
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
});

describe("paymentMethods.delete", () => {
  it("calls api.delete with the correct URL for plain ids", () => {
    mockDelete.mockResolvedValueOnce({ data: {} });
    paymentMethods.delete("pm-001", "org-001");
    expect(mockDelete).toHaveBeenCalledWith(
      "/ui/billing/payment-methods/pm-001?organizationid=org-001",
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
  it("list() calls api.get('/policy/status')", () => {
    mockGet.mockResolvedValueOnce({ data: {} });
    policies.list();
    expect(mockGet).toHaveBeenCalledWith("/policy/status");
  });

  it("get() calls the policy status endpoint", () => {
    mockGet.mockResolvedValueOnce({ data: {} });
    policies.get("pol-001");
    expect(mockGet).toHaveBeenCalledWith("/policy/status");
  });

  it("create(payload) posts the normalized policy contract to /policy/create", () => {
    mockPost.mockResolvedValueOnce({ data: {} });
    const payload = {
      name: "deny-all",
      action: "block",
      pattern: "suspicious",
      priority: 12,
      policy_type: "tool_abuse",
    };

    policies.create(payload);

    expect(mockPost).toHaveBeenCalledWith(
      "/policy/create",
      expect.objectContaining({
        name: "deny-all",
        enforcement_mode: "block",
        rules: [
          expect.objectContaining({
            name: "deny-all",
            pattern: "suspicious",
            enforcement_mode: "block",
            categories: ["tool_abuse"],
          }),
        ],
      }),
    );
  });

  it("update(id, payload) calls the policy update endpoint with the backend payload contract", () => {
    mockPatch.mockResolvedValueOnce({ data: {} });
    const payload = { name: "allow-safe", action: "allow", pattern: "safe" };
    policies.update("pol-001", payload);
    expect(mockPatch).toHaveBeenCalledWith(
      "/policy/update",
      expect.objectContaining({
        id: "pol-001",
        name: "allow-safe",
        enforcement_mode: "allow",
      }),
    );
  });

  it("delete(id) resets the policy engine via the supported backend route", () => {
    mockDelete.mockResolvedValueOnce({ data: {} });
    policies.delete("pol-001");
    expect(mockDelete).toHaveBeenCalledWith("/policy/reset");
  });
});
