/* global process */
import { createClient } from "@supabase/supabase-js";

const SUPABASE_URL = process.env.REACT_APP_SUPABASE_URL;
const SUPABASE_ANON_KEY = process.env.REACT_APP_SUPABASE_ANON_KEY;
const COOKIE_CONSENT_STORAGE_KEY = "ironclaw.cookie-consent";

const consentAllowsSessionStorage = () => {
  try {
    return localStorage.getItem(COOKIE_CONSENT_STORAGE_KEY) === "accepted";
  } catch {
    return false;
  }
};

const authStorage = {
  getItem: (key) =>
    consentAllowsSessionStorage() ? localStorage.getItem(key) : null,
  setItem: (key, value) => {
    if (consentAllowsSessionStorage()) {
      localStorage.setItem(key, value);
    }
  },
  removeItem: (key) => {
    localStorage.removeItem(key);
  },
};

if (!SUPABASE_URL || !SUPABASE_ANON_KEY) {
  throw new Error(
    "Missing REACT_APP_SUPABASE_URL or REACT_APP_SUPABASE_ANON_KEY in environment.",
  );
}

export const supabase = createClient(SUPABASE_URL, SUPABASE_ANON_KEY, {
  auth: {
    autoRefreshToken: true,
    persistSession: true,
    detectSessionInUrl: true,
    storage: authStorage,
  },
});
