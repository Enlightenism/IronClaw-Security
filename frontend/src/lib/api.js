/* global process */
import axios from "axios";
import { supabase } from "@/lib/supabase";

const RAW_BACKEND_URL =
  process.env.REACT_APP_API_BASE_URL || "http://127.0.0.1:8000";

const BACKEND_URL = RAW_BACKEND_URL.replace(/\/+$/, "");

export const API_BASE = `${BACKEND_URL}/api`;

const api = axios.create({
  baseURL: API_BASE,
  timeout: 15000,
});

api.interceptors.response.use(
  (res) => res,
  async (error) => {
    if (error?.response?.status === 401) {
      await supabase.auth.signOut();
      window.location.href = "/";
    }
    return Promise.reject(error);
  },
);

const withOrgId = (orgId) =>
  `organizationid=${encodeURIComponent(orgId)}`;

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
  list: (orgId) =>
    api.get(`/ui/billing/payment-methods?${withOrgId(orgId)}`),

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
