/* global process */
import axios from "axios";
import { supabase } from "@/lib/supabase";

const RAW_BACKEND_URL =
  process.env.REACT_APP_API_BASE_URL || "http://127.0.0.1:8000";

const BACKEND_URL = RAW_BACKEND_URL.replace(/\/+$/, "");

export const API_BASE = `${BACKEND_URL}/api`;

const AUTH_TOKEN_STORAGE_KEY = "ironclaw.auth.token";
const AUTH_ORG_ID_STORAGE_KEY = "ironclaw.auth.orgId";

const api = axios.create({
  baseURL: API_BASE,
  timeout: 15000,
});

const getStoredToken = () => {
  try {
    return localStorage.getItem(AUTH_TOKEN_STORAGE_KEY) || "";
  } catch {
    return "";
  }
};

const getStoredOrgId = () => {
  try {
    return localStorage.getItem(AUTH_ORG_ID_STORAGE_KEY) || "";
  } catch {
    return "";
  }
};

const getOrgIdFromSession = (session) => {
  const user = session?.user;
  if (!user) return "";

  const userMeta = user.user_metadata ?? {};
  const appMeta = user.app_metadata ?? {};

  return (
    userMeta.org_id ||
    userMeta.organization_id ||
    userMeta.orgId ||
    appMeta.org_id ||
    appMeta.organization_id ||
    appMeta.orgId ||
    user.id ||
    ""
  );
};

const shouldBypassUnauthorizedRedirect = async () => {
  try {
    const {
      data: { session },
    } = await supabase.auth.getSession();

    return Boolean(session?.access_token);
  } catch {
    return false;
  }
};

api.interceptors.request.use(async (config) => {
  let accessToken = "";
  let orgId = "";

  try {
    const {
      data: { session },
    } = await supabase.auth.getSession();

    accessToken = session?.access_token || "";
    orgId = getOrgIdFromSession(session);
  } catch {
    accessToken = "";
    orgId = "";
  }

  if (!accessToken) {
    accessToken = getStoredToken();
  }

  if (!orgId) {
    orgId = getStoredOrgId();
  }

  config.headers = config.headers ?? {};

  if (accessToken) {
    config.headers.Authorization = `Bearer ${accessToken}`;
  } else {
    delete config.headers.Authorization;
  }

  if (orgId) {
    config.headers["X-Org-Id"] = orgId;
  } else {
    delete config.headers["X-Org-Id"];
  }

  delete config.headers["X-API-Key"];

  return config;
});

api.interceptors.response.use(
  (res) => res,
  async (error) => {
    if (error?.response?.status === 422) {
      const detail = error?.response?.data?.detail;
      const errors = Array.isArray(detail) ? detail : detail?.errors || [];
      const method = error?.config?.method?.toUpperCase?.() || "REQUEST";
      const url = error?.config?.url || "";
      const keys = error?.config?.data
        ? Object.keys(JSON.parse(error.config.data || "{}"))
        : [];

      // eslint-disable-next-line no-console
      console.warn(
        `[422 Validation] ${method} ${url} keys=${JSON.stringify(keys)} errors=`,
        errors,
      );
    }

    if (
      error?.response?.status === 401 &&
      error.config &&
      !error.config.__retried
    ) {
      try {
        const {
          data: { session },
        } = await supabase.auth.getSession();

        const newToken = session?.access_token;
        if (newToken) {
          const originalAuth = error.config.headers?.Authorization || "";
          const expectedAuth = `Bearer ${newToken}`;

          if (originalAuth !== expectedAuth) {
            api.defaults.headers.common.Authorization = expectedAuth;
            error.config.headers.Authorization = expectedAuth;
            error.config.__retried = true;
            return api.request(error.config);
          }
        }
      } catch {
        // Fall through to sign-out behavior
      }
    }

    if (error?.response?.status === 401) {
      const hasActiveSession = await shouldBypassUnauthorizedRedirect();

      if (!hasActiveSession) {
        await supabase.auth.signOut();
        window.location.href = "/";
      }
    }

    return Promise.reject(error);
  },
);

const withOrgId = (orgId) => `organizationid=${encodeURIComponent(orgId)}`;

export const health = {
  check: () => api.get("/"),
};

export const auth = {
  me: () => api.get("/auth/me"),
};

export const dashboard = {
  get: () => api.get("/dashboard/overview"),
};

export const events = {
  simulate: () => api.post("/events/simulate"),
};

export const integrations = {
  getToken: () => api.get("/integrations/token"),
};

export const payments = {
  createCheckout: (payload) => api.post("/billing/checkout/sessions", payload),
  getStatus: (sessionId) =>
    api.get(`/billing/checkout/sessions/${encodeURIComponent(sessionId)}`),
};

export const paymentMethods = {
  list: (orgId) => api.get(`/ui/billing/payment-methods?${withOrgId(orgId)}`),

  setDefault: (methodId, orgId) =>
    api.patch(
      `/ui/billing/payment-methods/${encodeURIComponent(methodId)}/default?${withOrgId(orgId)}`,
    ),

  delete: (methodId, orgId) =>
    api.delete(
      `/ui/billing/payment-methods/${encodeURIComponent(methodId)}?${withOrgId(orgId)}`,
    ),

  setDefaultFallback: (methodId, orgId) =>
    api.post(
      `/billing/payment-methods/${encodeURIComponent(methodId)}/set-default?${withOrgId(orgId)}`,
    ),

  detachFallback: (methodId, orgId) =>
    api.post(
      `/billing/payment-methods/${encodeURIComponent(methodId)}/detach?${withOrgId(orgId)}`,
    ),
};

export const prompts = {
  inspect: (payload) => api.post("/inspect", payload),
};

export const audit = {
  getLogs: (params) => api.get("/audit/logs", { params }),
};

const normalizePolicyRequest = (payload = {}) => {
  const action = payload.action || "block";
  const policyType = payload.policy_type || "custom";

  return {
    name: payload.name || "Custom policy",
    version: payload.version || "1.0.0",
    rules: [
      {
        rule_id:
          payload.rule_id ||
          `rule-${Date.now()}-${Math.random().toString(16).slice(2, 8)}`,
        name: payload.name || "Custom policy rule",
        description: payload.description || "",
        scope: "global_",
        severity: "medium",
        enforcement_mode: action,
        pattern: payload.pattern || "",
        categories: [policyType],
        enabled: payload.enabled ?? true,
        tags: [],
        metadata: {
          policy_type: policyType,
          priority: payload.priority ?? 50,
        },
      },
    ],
    heuristic_threshold: payload.heuristic_threshold ?? 50,
    unicode_normalization_enabled:
      payload.unicode_normalization_enabled ?? true,
    enforcement_mode: action,
    scope: payload.scope || "global_",
    metadata: {
      description: payload.description || "",
      policy_type: policyType,
      priority: payload.priority ?? 50,
    },
  };
};

export const policies = {
  list: () => api.get("/policy/status"),
  get: () => api.get("/policy/status"),
  create: (payload) =>
    api.post("/policy/create", normalizePolicyRequest(payload)),
  update: (id, payload) =>
    api.patch(`/policy/update`, {
      ...normalizePolicyRequest(payload),
      id,
    }),
  delete: (id) => {
    if (id) {
      return api.delete("/policy/reset");
    }
    return api.delete("/policy/reset");
  },
};

export const tools = {
  inspect: (payload) => api.post("/tools/inspect", payload),
};

export default api;
