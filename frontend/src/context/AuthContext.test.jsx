import React from "react";
import { render, screen, waitFor, act, fireEvent } from "@testing-library/react";
import { AuthProvider, useAuth } from "@/context/AuthContext";
import { supabase } from "@/lib/supabase";
import api from "@/lib/api";

jest.mock("@/lib/api", () => ({
  __esModule: true,
  default: {
    defaults: {
      headers: {
        common: {},
      },
    },
  },
}));

jest.mock("@/lib/supabase", () => ({
  supabase: {
    auth: {
      getSession: jest.fn(),
      onAuthStateChange: jest.fn(),
      signInWithPassword: jest.fn(),
      signUp: jest.fn(),
      signOut: jest.fn(),
      getUser: jest.fn(),
    },
  },
}));

const TestConsumer = () => {
  const {
    user,
    session,
    loading,
    authenticate,
    register,
    logout,
    refreshUser,
  } = useAuth();

  const [lastError, setLastError] = React.useState("");

  const handleAuthenticate = async () => {
    try {
      await authenticate("user@example.com", "password123");
      setLastError("");
    } catch (error) {
      setLastError(error.message);
    }
  };

  const handleRegister = async () => {
    try {
      await register("new@example.com", "password123");
      setLastError("");
    } catch (error) {
      setLastError(error.message);
    }
  };

  const handleLogout = async () => {
    try {
      await logout();
      setLastError("");
    } catch (error) {
      setLastError(error.message);
    }
  };

  const handleRefreshUser = async () => {
    try {
      await refreshUser();
      setLastError("");
    } catch (error) {
      setLastError(error.message);
    }
  };

  return (
    <div>
      <div data-testid="loading">{String(loading)}</div>
      <div data-testid="user">{user?.email ?? "null"}</div>
      <div data-testid="session">{session?.access_token ?? "null"}</div>
      <div data-testid="error">{lastError || "none"}</div>
      <button onClick={handleAuthenticate}>authenticate</button>
      <button onClick={handleRegister}>register</button>
      <button onClick={handleLogout}>logout</button>
      <button onClick={handleRefreshUser}>refreshUser</button>
    </div>
  );
};

const renderWithProvider = () =>
  render(
    <AuthProvider>
      <TestConsumer />
    </AuthProvider>,
  );

const mockSubscription = {
  unsubscribe: jest.fn(),
};

const makeSession = (overrides = {}) => ({
  access_token: "token-123",
  user: {
    id: "user-1",
    email: "user@example.com",
  },
  ...overrides,
});

describe("AuthContext", () => {
  let authStateChangeHandler;
  let localStorageStore;

  beforeEach(() => {
    jest.clearAllMocks();

    authStateChangeHandler = null;
    localStorageStore = {};

    api.defaults.headers.common = {};

    Object.defineProperty(window, "localStorage", {
      value: {
        getItem: jest.fn((key) => localStorageStore[key] ?? null),
        setItem: jest.fn((key, value) => {
          localStorageStore[key] = String(value);
        }),
        removeItem: jest.fn((key) => {
          delete localStorageStore[key];
        }),
      },
      configurable: true,
    });

    supabase.auth.getSession.mockResolvedValue({
      data: { session: null },
    });

    supabase.auth.onAuthStateChange.mockImplementation((handler) => {
      authStateChangeHandler = handler;
      return {
        data: {
          subscription: mockSubscription,
        },
      };
    });

    supabase.auth.signInWithPassword.mockResolvedValue({
      data: { user: null, session: null },
      error: null,
    });

    supabase.auth.signUp.mockResolvedValue({
      data: { user: null, session: null },
      error: null,
    });

    supabase.auth.signOut.mockResolvedValue({ error: null });

    supabase.auth.getUser.mockResolvedValue({
      data: { user: null },
    });
  });

  it("hydrates from getSession on mount and clears loading", async () => {
    const session = makeSession();

    supabase.auth.getSession.mockResolvedValue({
      data: { session },
    });

    renderWithProvider();

    expect(screen.getByTestId("loading")).toHaveTextContent("true");

    await waitFor(() =>
      expect(screen.getByTestId("loading")).toHaveTextContent("false"),
    );

    expect(screen.getByTestId("user")).toHaveTextContent("user@example.com");
    expect(screen.getByTestId("session")).toHaveTextContent("token-123");
    expect(api.defaults.headers.common["Authorization"]).toBe("Bearer token-123");
    expect(window.localStorage.setItem).toHaveBeenCalledWith(
      "ironclaw.auth.token",
      "token-123",
    );
  });

  it("starts with loading false when a cached token exists and applies it immediately", async () => {
    localStorageStore["ironclaw.auth.token"] = "cached-token";

    renderWithProvider();

    expect(screen.getByTestId("loading")).toHaveTextContent("false");
    expect(api.defaults.headers.common["Authorization"]).toBe(
      "Bearer cached-token",
    );

    await waitFor(() =>
      expect(supabase.auth.getSession).toHaveBeenCalledTimes(1),
    );
  });

  it("subscribes to auth state changes and updates state from the callback", async () => {
    renderWithProvider();

    await waitFor(() =>
      expect(supabase.auth.onAuthStateChange).toHaveBeenCalledTimes(1),
    );

    const nextSession = makeSession({
      access_token: "token-456",
      user: { id: "user-2", email: "changed@example.com" },
    });

    await act(async () => {
      authStateChangeHandler("SIGNED_IN", nextSession);
    });

    expect(screen.getByTestId("user")).toHaveTextContent("changed@example.com");
    expect(screen.getByTestId("session")).toHaveTextContent("token-456");
    expect(api.defaults.headers.common["Authorization"]).toBe("Bearer token-456");
    expect(window.localStorage.setItem).toHaveBeenCalledWith(
      "ironclaw.auth.token",
      "token-456",
    );
  });

  it("cleans up the auth subscription on unmount", async () => {
    const { unmount } = renderWithProvider();

    await waitFor(() =>
      expect(supabase.auth.onAuthStateChange).toHaveBeenCalledTimes(1),
    );

    unmount();

    expect(mockSubscription.unsubscribe).toHaveBeenCalledTimes(1);
  });

  it("authenticate sets optimistic auth state immediately from Supabase response", async () => {
    const session = makeSession({
      access_token: "login-token",
      user: { id: "user-3", email: "login@example.com" },
    });

    supabase.auth.signInWithPassword.mockResolvedValue({
      data: {
        user: session.user,
        session,
      },
      error: null,
    });

    renderWithProvider();

    await waitFor(() =>
      expect(screen.getByTestId("loading")).toHaveTextContent("false"),
    );

    await act(async () => {
      fireEvent.click(screen.getByText("authenticate"));
    });

    expect(supabase.auth.signInWithPassword).toHaveBeenCalledWith({
      email: "user@example.com",
      password: "password123",
    });
    expect(screen.getByTestId("user")).toHaveTextContent("login@example.com");
    expect(screen.getByTestId("session")).toHaveTextContent("login-token");
    expect(api.defaults.headers.common["Authorization"]).toBe(
      "Bearer login-token",
    );
    expect(window.localStorage.setItem).toHaveBeenCalledWith(
      "ironclaw.auth.token",
      "login-token",
    );
    expect(screen.getByTestId("error")).toHaveTextContent("none");
  });

  it("authenticate surfaces Supabase errors without crashing the test", async () => {
    const error = new Error("invalid login");

    supabase.auth.signInWithPassword.mockResolvedValue({
      data: { user: null, session: null },
      error,
    });

    renderWithProvider();

    await waitFor(() =>
      expect(screen.getByTestId("loading")).toHaveTextContent("false"),
    );

    await act(async () => {
      fireEvent.click(screen.getByText("authenticate"));
    });

    expect(screen.getByTestId("error")).toHaveTextContent("invalid login");
  });

  it("register sets optimistic auth state immediately from Supabase response", async () => {
    const session = makeSession({
      access_token: "signup-token",
      user: { id: "user-4", email: "new@example.com" },
    });

    supabase.auth.signUp.mockResolvedValue({
      data: {
        user: session.user,
        session,
      },
      error: null,
    });

    renderWithProvider();

    await waitFor(() =>
      expect(screen.getByTestId("loading")).toHaveTextContent("false"),
    );

    await act(async () => {
      fireEvent.click(screen.getByText("register"));
    });

    expect(supabase.auth.signUp).toHaveBeenCalledWith({
      email: "new@example.com",
      password: "password123",
    });
    expect(screen.getByTestId("user")).toHaveTextContent("new@example.com");
    expect(screen.getByTestId("session")).toHaveTextContent("signup-token");
    expect(api.defaults.headers.common["Authorization"]).toBe(
      "Bearer signup-token",
    );
    expect(window.localStorage.setItem).toHaveBeenCalledWith(
      "ironclaw.auth.token",
      "signup-token",
    );
    expect(screen.getByTestId("error")).toHaveTextContent("none");
  });

  it("register surfaces Supabase errors without crashing the test", async () => {
    const error = new Error("signup failed");

    supabase.auth.signUp.mockResolvedValue({
      data: { user: null, session: null },
      error,
    });

    renderWithProvider();

    await waitFor(() =>
      expect(screen.getByTestId("loading")).toHaveTextContent("false"),
    );

    await act(async () => {
      fireEvent.click(screen.getByText("register"));
    });

    expect(screen.getByTestId("error")).toHaveTextContent("signup failed");
  });

  it("logout clears local state, axios auth header, and cached token before signOut resolves", async () => {
    const session = makeSession();

    supabase.auth.getSession.mockResolvedValue({
      data: { session },
    });

    let resolveSignOut;
    supabase.auth.signOut.mockImplementation(
      () =>
        new Promise((resolve) => {
          resolveSignOut = resolve;
        }),
    );

    renderWithProvider();

    await waitFor(() =>
      expect(screen.getByTestId("user")).toHaveTextContent("user@example.com"),
    );

    await act(async () => {
      fireEvent.click(screen.getByText("logout"));
    });

    expect(screen.getByTestId("user")).toHaveTextContent("null");
    expect(screen.getByTestId("session")).toHaveTextContent("null");
    expect(screen.getByTestId("loading")).toHaveTextContent("false");
    expect(api.defaults.headers.common["Authorization"]).toBeUndefined();
    expect(window.localStorage.removeItem).toHaveBeenCalledWith(
      "ironclaw.auth.token",
    );
    expect(supabase.auth.signOut).toHaveBeenCalledTimes(1);

    await act(async () => {
      resolveSignOut({ error: null });
    });
  });

  it("refreshUser refreshes only the user value", async () => {
    const session = makeSession();

    supabase.auth.getSession.mockResolvedValue({
      data: { session },
    });

    supabase.auth.getUser.mockResolvedValue({
      data: {
        user: {
          id: "user-99",
          email: "refreshed@example.com",
        },
      },
    });

    renderWithProvider();

    await waitFor(() =>
      expect(screen.getByTestId("user")).toHaveTextContent("user@example.com"),
    );

    await act(async () => {
      fireEvent.click(screen.getByText("refreshUser"));
    });

    expect(supabase.auth.getUser).toHaveBeenCalledTimes(1);
    expect(screen.getByTestId("user")).toHaveTextContent(
      "refreshed@example.com",
    );
    expect(screen.getByTestId("session")).toHaveTextContent("token-123");
  });

  it("removes the cached token and axios header when auth state changes to signed out", async () => {
    const session = makeSession();

    supabase.auth.getSession.mockResolvedValue({
      data: { session },
    });

    renderWithProvider();

    await waitFor(() =>
      expect(screen.getByTestId("session")).toHaveTextContent("token-123"),
    );

    await act(async () => {
      authStateChangeHandler("SIGNED_OUT", null);
    });

    expect(screen.getByTestId("user")).toHaveTextContent("null");
    expect(screen.getByTestId("session")).toHaveTextContent("null");
    expect(api.defaults.headers.common["Authorization"]).toBeUndefined();
    expect(window.localStorage.removeItem).toHaveBeenCalledWith(
      "ironclaw.auth.token",
    );
  });

  it("throws when useAuth is used outside AuthProvider", () => {
    const OutsideConsumer = () => {
      useAuth();
      return null;
    };

    expect(() => render(<OutsideConsumer />)).toThrow(
      "useAuth must be used within AuthProvider",
    );
  });
});
