/* global process */
import axios from "axios";
import { supabase } from "@/lib/supabase";

const BACKEND_URL =
  process.env.REACT_APP_BACKEND_URL || "http://127.0.0.1:8000";

export const API_BASE = `${BACKEND_URL}/api`;

const api = axios.create({
  baseURL: API_BASE,
  timeout: 15000,
});

// ── Response: handle 401 globally ────────────────────────────────────────────
// Authorization header is kept current by AuthContext.syncAxiosToken via
// supabase.auth.onAuthStateChange — no request interceptor needed.
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

// ── Health ────────────────────────────────────────────────────────────────────
export const health = {
  check: () => api.get("/"),
};

// ── Auth ──────────────────────────────────────────────────────────────────────
// signup/signin removed — handled by Supabase Auth directly in AuthContext.
// me() retained for backend session/user validation.
export const auth = {
  me: () => api.get("/auth/me"),
};

// ── Dashboard ─────────────────────────────────────────────────────────────────
export const dashboard = {
  get: () => api.get("/dashboard"),
};

// ── Events ────────────────────────────────────────────────────────────────────
export const events = {
  simulate: () => api.post("/events/simulate"),
};

// ── Integrations ──────────────────────────────────────────────────────────────
export const integrations = {
  getToken: () => api.get("/integrations/token"),
};

// ── Payments ──────────────────────────────────────────────────────────────────
export const payments = {
  createCheckout: (payload) => api.post("/payments/create-checkout", payload),
  getStatus: (sessionId) => api.get(`/payments/status/${sessionId}`),
};

// ── Prompts ───────────────────────────────────────────────────────────────────
export const prompts = {
  inspect: (payload) => api.post("/inspect", payload),
};

// ── Audit ─────────────────────────────────────────────────────────────────────
export const audit = {
  getLogs: (params) => api.get("/audit/logs", { params }),
};

// ── Policies ──────────────────────────────────────────────────────────────────
export const policies = {
  list: () => api.get("/policies"),
  get: (id) => api.get(`/policies/${id}`),
  create: (payload) => api.post("/policies", payload),
  update: (id, payload) => api.put(`/policies/${id}`, payload),
  delete: (id) => api.delete(`/policies/${id}`),
};

// ── Tools ─────────────────────────────────────────────────────────────────────
export const tools = {
  inspect: (payload) => api.post("/tools/inspect", payload),
};

export default api;
