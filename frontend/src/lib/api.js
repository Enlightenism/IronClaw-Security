import axios from "axios";

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;
export const API_BASE = `${BACKEND_URL}/api`;
export const TOKEN_KEY = "ironclaw_token";

const api = axios.create({ baseURL: API_BASE });

api.interceptors.request.use((config) => {
  const token = localStorage.getItem(TOKEN_KEY);
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

api.interceptors.response.use(
  (res) => res,
  (error) => {
    if (error?.response?.status === 401) {
      localStorage.removeItem(TOKEN_KEY);
    }
    return Promise.reject(error);
  }
);

// ── Health ────────────────────────────────────────────────────────────────────
export const health = {
  check: () => api.get("/health"),
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
  list:   ()             => api.get("/policies"),
  get:    (id)           => api.get(`/policies/${id}`),
  create: (payload)      => api.post("/policies", payload),
  update: (id, payload)  => api.put(`/policies/${id}`, payload),
  delete: (id)           => api.delete(`/policies/${id}`),
};

// ── Tools ─────────────────────────────────────────────────────────────────────
export const tools = {
  inspect: (payload) => api.post("/tools/inspect", payload),
};

export default api;