/* global process */
import axios from "axios";
import { supabase } from "@/lib/supabase";

const RAW_BACKEND_URL =
  process.env.REACT_APP_API_BASE_URL || "http://127.0.0.1:8000";

const BACKEND_URL = RAW_BACKEND_URL.replace(/\/+$/, "");

export const API_BASE = `${BACKEND_URL}/api`;

const AUTH_TOKEN_STORAGE_KEY = "ironclaw.auth.token";
const AUTH_ORG_ID_STORAGE_KEY = "ironclaw.auth.orgId";
const AUTH_API_KEY_STORAGE_KEY = "ironclaw.auth.apiKey";

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

const getStoredApiKey = () => {
  try {
    return localStorage.getItem(AUTH_API_KEY_STORAGE_KEY) || "";
  } catch {
    return "";
  }
};

const getConfiguredApiKey = () =>
  process.env.REACT_APP_API_KEY ||
  process.env.REACT_APP_PLATFORM_API_KEY ||
  process.env.REACT_APP_INTERNAL_PLATFORM_API_KEY ||
  "";

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
  let apiKey = "";

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

  apiKey = getConfiguredApiKey() || getStoredApiKey();

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

  if (apiKey) {
    config.headers["X-API-Key"] = apiKey;
  } else {
    delete config.headers["X-API-Key"];
  }

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

export const policies = {
  list: () => api.get("/policies"),
  get: (id) => api.get(`/policies/${encodeURIComponent(id)}`),
  create: (payload) => api.post("/policies", payload),
  update: (id, payload) =>
    api.put(`/policies/${encodeURIComponent(id)}`, payload),
  delete: (id) => api.delete(`/policies/${encodeURIComponent(id)}`),
};

export const tools = {
  inspect: (payload) => api.post("/tools/inspect", payload),
};

export default api;
