import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
} from "react";
import { supabase } from "@/lib/supabase";
import api from "@/lib/api";

const AuthContext = createContext(null);
const AUTH_TOKEN_STORAGE_KEY = "ironclaw.auth.token";
const AUTH_ORG_ID_STORAGE_KEY = "ironclaw.auth.orgId";

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

const syncAxiosToken = (session) => {
  const accessToken =
    session?.access_token || session?.provider_token || session?.id_token || "";
  const orgId = getOrgIdFromSession(session);

  if (accessToken) {
    api.defaults.headers.common["Authorization"] = `Bearer ${accessToken}`;
    localStorage.setItem(AUTH_TOKEN_STORAGE_KEY, accessToken);

    if (orgId) {
      api.defaults.headers.common["X-Org-Id"] = orgId;
      localStorage.setItem(AUTH_ORG_ID_STORAGE_KEY, orgId);
    } else {
      delete api.defaults.headers.common["X-Org-Id"];
      localStorage.removeItem(AUTH_ORG_ID_STORAGE_KEY);
    }
  } else {
    delete api.defaults.headers.common["Authorization"];
    delete api.defaults.headers.common["X-Org-Id"];
    localStorage.removeItem(AUTH_TOKEN_STORAGE_KEY);
    localStorage.removeItem(AUTH_ORG_ID_STORAGE_KEY);
  }
};

const ensureSharedCounterRegistry = () => {
  if (typeof globalThis === "undefined") {
    return null;
  }

  const store = globalThis.__IC_COUNTERS__ || {};
  const existingRegistry = store.__controllers;
  const nextRegistry = new Map();

  if (existingRegistry instanceof Map) {
    for (const [key, value] of existingRegistry.entries()) {
      if (key && value !== undefined) {
        nextRegistry.set(key, value);
      }
    }
  } else if (existingRegistry && typeof existingRegistry === "object") {
    Object.entries(existingRegistry).forEach(([key, value]) => {
      if (key && value !== undefined) {
        nextRegistry.set(key, value);
      }
    });
  }

  Object.keys(store).forEach((key) => {
    if (key === "__controllers" || key === "__appMounted") {
      return;
    }

    if (!nextRegistry.has(key)) {
      delete store[key];
    }
  });

  for (const [key, value] of nextRegistry.entries()) {
    store[key] = value;
  }

  store.__controllers = nextRegistry;
  globalThis.__IC_COUNTERS__ = store;
  return nextRegistry;
};

export const ensureFrontEndHasFreshSession = async () => {
  try {
    const {
      data: { session },
    } = await supabase.auth.getSession();

    if (session?.access_token) {
      syncAxiosToken(session);
      return true;
    }

    return false;
  } catch {
    return false;
  }
};

export const AuthProvider = ({ children }) => {
  const [cachedAuthApplied] = useState(() => {
    const cachedToken = localStorage.getItem(AUTH_TOKEN_STORAGE_KEY);
    const cachedOrgId = localStorage.getItem(AUTH_ORG_ID_STORAGE_KEY);

    if (cachedToken) {
      api.defaults.headers.common["Authorization"] = `Bearer ${cachedToken}`;
    }

    if (cachedOrgId) {
      api.defaults.headers.common["X-Org-Id"] = cachedOrgId;
    }

    return Boolean(cachedToken || cachedOrgId);
  });

  useEffect(() => {
    ensureSharedCounterRegistry();
  }, []);

  const [user, setUser] = useState(null);
  const [session, setSession] = useState(null);
  const [loading, setLoading] = useState(!cachedAuthApplied);

  useEffect(() => {
    let isMounted = true;

    const applySession = (nextSession) => {
      if (!isMounted) return;
      ensureSharedCounterRegistry();
      setSession(nextSession ?? null);
      setUser(nextSession?.user ?? null);
      syncAxiosToken(nextSession ?? null);
      setLoading(false);
    };

    supabase.auth.getSession().then(({ data: { session: s } }) => {
      applySession(s);
    });

    const {
      data: { subscription },
    } = supabase.auth.onAuthStateChange((_event, s) => {
      applySession(s);
    });

    return () => {
      isMounted = false;
      subscription.unsubscribe();
    };
  }, []);

  const authenticate = useCallback(async (email, password) => {
    ensureSharedCounterRegistry();
    setLoading(true);

    const { data, error } = await supabase.auth.signInWithPassword({
      email,
      password,
    });

    if (error) {
      setLoading(false);
      throw error;
    }

    const nextSession = data?.session ?? null;
    const nextUser = data?.user ?? nextSession?.user ?? null;

    setSession(nextSession);
    setUser(nextUser);
    syncAxiosToken(nextSession);
    setLoading(false);

    return data;
  }, []);

  const register = useCallback(async (email, password) => {
    ensureSharedCounterRegistry();
    setLoading(true);

    const { data, error } = await supabase.auth.signUp({
      email,
      password,
    });

    if (error) {
      setLoading(false);
      throw error;
    }

    const nextSession = data?.session ?? null;
    const nextUser = data?.user ?? nextSession?.user ?? null;

    setSession(nextSession);
    setUser(nextUser);
    syncAxiosToken(nextSession);
    setLoading(false);

    return data;
  }, []);

  const logout = useCallback(async () => {
    ensureSharedCounterRegistry();
    setSession(null);
    setUser(null);
    syncAxiosToken(null);
    setLoading(false);
    await supabase.auth.signOut();
  }, []);

  const refreshUser = useCallback(async () => {
    ensureSharedCounterRegistry();

    const {
      data: { user: refreshedUser },
    } = await supabase.auth.getUser();

    setUser(refreshedUser ?? null);

    const {
      data: { session: refreshedSession },
    } = await supabase.auth.getSession();

    setSession(refreshedSession ?? null);
    syncAxiosToken(refreshedSession ?? null);
  }, []);

  const value = useMemo(
    () => ({
      user,
      session,
      loading,
      authenticate,
      register,
      logout,
      refreshUser,
      ensureFrontEndHasFreshSession,
    }),
    [user, session, loading, authenticate, register, logout, refreshUser],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};

export const useAuth = () => {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within AuthProvider");
  return ctx;
};
