import { createContext, useContext, useEffect, useState } from "react";
import { supabase } from "@/lib/supabase";
import api from "@/lib/api";

const AuthContext = createContext(null);
const AUTH_TOKEN_STORAGE_KEY = "ironclaw.auth.token";

// Keep the Axios interceptor fed with the current Supabase JWT.
// Called whenever the session changes (sign-in, token refresh, sign-out).
const syncAxiosToken = (session) => {
  const accessToken = session?.access_token;

  if (accessToken) {
    api.defaults.headers.common["Authorization"] = `Bearer ${accessToken}`;
    localStorage.setItem(AUTH_TOKEN_STORAGE_KEY, accessToken);
  } else {
    delete api.defaults.headers.common["Authorization"];
    localStorage.removeItem(AUTH_TOKEN_STORAGE_KEY);
  }
};

export const AuthProvider = ({ children }) => {
  const [cachedTokenApplied] = useState(() => {
    const cachedToken = localStorage.getItem(AUTH_TOKEN_STORAGE_KEY);
    if (cachedToken) {
      api.defaults.headers.common["Authorization"] = `Bearer ${cachedToken}`;
      return true;
    }
    return false;
  });

  const [user, setUser] = useState(null);
  const [session, setSession] = useState(null);
  const [loading, setLoading] = useState(!cachedTokenApplied);

  useEffect(() => {
    let isMounted = true;

    // Hydrate from the persisted session on first mount.
    supabase.auth.getSession().then(({ data: { session: s } }) => {
      if (!isMounted) return;
      setSession(s);
      setUser(s?.user ?? null);
      syncAxiosToken(s);
      setLoading(false);
    });

    // Subscribe to all future auth state changes.
    const {
      data: { subscription },
    } = supabase.auth.onAuthStateChange((_event, s) => {
      if (!isMounted) return;
      setSession(s);
      setUser(s?.user ?? null);
      syncAxiosToken(s);
      setLoading(false);
    });

    return () => {
      isMounted = false;
      subscription.unsubscribe();
    };
  }, []);

  // Supabase sign-in with email + password.
  const authenticate = async (email, password) => {
    const { data, error } = await supabase.auth.signInWithPassword({
      email,
      password,
    });
    if (error) throw error;

    const nextSession = data?.session ?? null;
    const nextUser = data?.user ?? nextSession?.user ?? null;

    setSession(nextSession);
    setUser(nextUser);
    syncAxiosToken(nextSession);
    setLoading(false);

    return data;
  };

  // Supabase sign-up.
  const register = async (email, password) => {
    const { data, error } = await supabase.auth.signUp({ email, password });
    if (error) throw error;

    const nextSession = data?.session ?? null;
    const nextUser = data?.user ?? nextSession?.user ?? null;

    setSession(nextSession);
    setUser(nextUser);
    syncAxiosToken(nextSession);
    setLoading(false);

    return data;
  };

  // Supabase sign-out — clears session, Axios header is cleaned in onAuthStateChange.
  const logout = async () => {
    setSession(null);
    setUser(null);
    syncAxiosToken(null);
    setLoading(false);
    await supabase.auth.signOut();
  };

  // Force-refresh user profile from Supabase (e.g. after metadata update).
  const refreshUser = async () => {
    const {
      data: { user: u },
    } = await supabase.auth.getUser();
    setUser(u ?? null);
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        session,
        loading,
        authenticate,
        register,
        logout,
        refreshUser,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within AuthProvider");
  return ctx;
};
