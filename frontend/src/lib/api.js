/* global process */
import axios from "axios";

const BACKEND_URL =
  process.env.REACT_APP_BACKEND_URL || "http://127.0.0.1:8000";

export const API_BASE = `${BACKEND_URL}/api`;
export const TOKEN_KEY = "ironclaw_token";

const api = axios.create({
  baseURL: API_BASE,
  timeout: 15000,
});

// ── Request: inject auth token ────────────────────────────────────────────────
api.interceptors.request.use((config) => {
  const token = localStorage.getItem(TOKEN_KEY);
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// ── Response: handle 401 globally ────────────────────────────────────────────
api.interceptors.response.use(
  (res) => res,
  (error) => {
    if (error?.response?.status === 401) {
      localStorage.removeItem(TOKEN_KEY);
      if (
        !window.location.pathname.includes("/signin") &&
        !window.location.pathname.includes("/signup")
      ) {
        window.location.href = "/signin";
      }
    }
    return Promise.reject(error);
  },
);

// ── Health ────────────────────────────────────────────────────────────────────
export const health = {
  check: () => api.get("/"),
};

// ── Auth ──────────────────────────────────────────────────────────────────────
export const auth = {
  signup: (payload) => api.post("/auth/signup", payload),
  signin: (payload) => api.post("/auth/signin", payload),
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
