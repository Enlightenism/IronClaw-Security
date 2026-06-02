import { createContext, useContext, useEffect, useState } from "react";
import { supabase } from "@/lib/supabase";
import api from "@/lib/api";

const AuthContext = createContext(null);

// Keep the Axios interceptor fed with the current Supabase JWT.
// Called whenever the session changes (sign-in, token refresh, sign-out).
const syncAxiosToken = (session) => {
  if (session?.access_token) {
    api.defaults.headers.common["Authorization"] =
      `Bearer ${session.access_token}`;
  } else {
    delete api.defaults.headers.common["Authorization"];
  }
};

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [session, setSession] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    // Hydrate from the persisted session on first mount.
    supabase.auth.getSession().then(({ data: { session: s } }) => {
      setSession(s);
      setUser(s?.user ?? null);
      syncAxiosToken(s);
      setLoading(false);
    });

    // Subscribe to all future auth state changes.
    const {
      data: { subscription },
    } = supabase.auth.onAuthStateChange((_event, s) => {
      setSession(s);
      setUser(s?.user ?? null);
      syncAxiosToken(s);
    });

    return () => subscription.unsubscribe();
  }, []);

  // Supabase sign-in with email + password.
  const authenticate = async (email, password) => {
    const { data, error } = await supabase.auth.signInWithPassword({
      email,
      password,
    });
    if (error) throw error;
    return data;
  };

  // Supabase sign-up.
  const register = async (email, password) => {
    const { data, error } = await supabase.auth.signUp({ email, password });
    if (error) throw error;
    return data;
  };

  // Supabase sign-out — clears session, Axios header is cleaned in onAuthStateChange.
  const logout = async () => {
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
