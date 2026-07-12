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
const mockSignOut = supabase.auth.signOut;

const axiosCreateCallCount = axios.create.mock.calls.length;
const axiosCreateConfig = axios.create.mock.calls[0]?.[0];
const responseInterceptorCallCount = mockResponseInterceptorUse.mock.calls.length;
const [capturedOnFulfilled, capturedOnRejected] =
  mockResponseInterceptorUse.mock.calls[0] || [];

beforeEach(() => {
  mockGet.mockClear();
  mockPost.mockClear();
  mockPatch.mockClear();
  mockDelete.mockClear();
  mockPut.mockClear();
  mockSignOut.mockClear();
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

  it("is derived from REACT_APP_BACKEND_URL when set or localhost fallback otherwise", () => {
    const backendUrl =
      process.env.REACT_APP_BACKEND_URL || "http://127.0.0.1:8000";
    expect(API_BASE).toBe(`${backendUrl}/api`);
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

  it("calls supabase.auth.signOut() on a 401 error", async () => {
    const error401 = { response: { status: 401 } };
    await capturedOnRejected(error401).catch(() => {});
    expect(mockSignOut).toHaveBeenCalledTimes(1);
  });

  it("redirects to / on a 401 error", async () => {
    const error401 = { response: { status: 401 } };
    await capturedOnRejected(error401).catch(() => {});
    expect(window.location.pathname).toBe("/");
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

describe("payments.createCheckout", () => {
  it("calls api.post with /payments/create-checkout", () => {
    mockPost.mockResolvedValueOnce({ data: {} });
    const payload = { plan: "starter", quantity: 1 };
    payments.createCheckout(payload);
    expect(mockPost).toHaveBeenCalledWith("/payments/create-checkout", payload);
  });
});

describe("payments.getStatus", () => {
  it("calls api.get with the correct URL including sessionId", () => {
    mockGet.mockResolvedValueOnce({ data: {} });
    payments.getStatus("cs_test_abc123");
    expect(mockGet).toHaveBeenCalledWith("/payments/status/cs_test_abc123");
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
    mockPut.mockResolvedValueOnce({ data: {} });
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
