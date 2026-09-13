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

const sanitizeCheckoutPayload = (payload = {}) => {
  const safePayload = { ...payload };

  if (safePayload.card) {
    delete safePayload.card;
  }

  if (safePayload.customer) {
    delete safePayload.customer;
  }

  if (
    safePayload.paymentMethod &&
    typeof safePayload.paymentMethod === "object"
  ) {
    const candidate = safePayload.paymentMethod;
    const savedMethodId =
      candidate?.id ||
      candidate?.payment_method_id ||
      candidate?.paymentMethodId;

    if (savedMethodId) {
      safePayload.paymentMethodId = savedMethodId;
    }

    if (candidate?.customer) {
      safePayload.customerId = candidate.customer;
    }
  }

  delete safePayload.paymentMethod;
  delete safePayload.cardNumber;
  delete safePayload.pan;
  delete safePayload.last4_raw;

  return safePayload;
};

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

const getPaymentStatusValue = (value) => {
  if (typeof value === "string") {
    return value.trim().toLowerCase();
  }
  return value;
};

const getInstallKeyFromResponse = (response = {}) => {
  const fulfilled =
    response?.payment_status === "paid" || response?.status === "paid";

  if (!fulfilled) {
    return null;
  }

  const candidates = [
    response?.install_key,
    response?.installKey,
    response?.generated_install_key,
    response?.generatedInstallKey,
    response?.key,
    response?.data?.install_key,
    response?.data?.installKey,
    response?.data?.generated_install_key,
    response?.data?.generatedInstallKey,
  ];

  for (const candidate of candidates) {
    if (typeof candidate === "string" && candidate.trim()) {
      return candidate.trim();
    }
  }

  return null;
};

export const payments = {
  createCheckout: (payload) =>
    api.post("/billing/checkout/sessions", sanitizeCheckoutPayload(payload)),
  getStatus: (sessionId) =>
    api.get(`/billing/checkout/sessions/${encodeURIComponent(sessionId)}`),
  getState: (response = {}) => {
    const paymentStatus = getPaymentStatusValue(
      response?.payment_status ?? response?.status ?? response?.state,
    );

    if (paymentStatus === "paid" || response?.paid === true) return "fulfilled";
    if (
      paymentStatus === "pending" ||
      paymentStatus === "open" ||
      paymentStatus === "requires_payment_method" ||
      paymentStatus === "incomplete" ||
      response?.checkout_url ||
      response?.url
    ) {
      return "pending";
    }

    return "unknown";
  },
  isPending: (response = {}) => payments.getState(response) === "pending",
  isFulfilled: (response = {}) => payments.getState(response) === "fulfilled",
  getInstallKey: (response = {}) => getInstallKeyFromResponse(response),
};

export const paymentMethods = {
  list: (orgId) => api.get(`/ui/billing/payment-methods?${withOrgId(orgId)}`),

  attach: (paymentMethodId, orgId, options = {}) => {
    const payload = {
      paymentMethodId: String(paymentMethodId || "").trim(),
      setAsDefault: Boolean(options.setAsDefault),
      ...(orgId ? { organizationid: String(orgId) } : {}),
    };

    return api.post("/ui/billing/payment-methods", payload);
  },

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

export const audit = {
  getLogs: (params) => api.get("/audit/logs", { params }),
};

export const tools = {
  inspect: (payload) => api.post("/tools/inspect", payload),
};

export default api;
