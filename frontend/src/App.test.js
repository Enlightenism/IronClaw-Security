import React from "react";
import { render, screen, waitFor } from "@testing-library/react";
import App from "@/App";

const mockUseAuth = jest.fn();

jest.mock("sonner", () => ({
  Toaster: () => <div data-testid="toaster" />,
}));

jest.mock("@/context/AuthContext", () => ({
  __esModule: true,
  AuthProvider: ({ children }) => (
    <div data-testid="auth-provider">{children}</div>
  ),
  useAuth: () => mockUseAuth(),
}));

jest.mock("@/pages/Landing", () => ({
  __esModule: true,
  default: () => <div>Landing Page</div>,
}));

jest.mock("@/pages/Dashboard", () => ({
  __esModule: true,
  default: () => <div>Dashboard Page</div>,
}));

jest.mock("@/pages/Privacy", () => ({
  __esModule: true,
  default: () => <div>Privacy Page</div>,
}));

jest.mock("@/pages/Terms", () => ({
  __esModule: true,
  default: () => <div>Terms Page</div>,
}));

jest.mock("@/pages/NotFound", () => ({
  __esModule: true,
  default: () => <div>Not Found Page</div>,
}));

const renderAppAtRoute = (
  route,
  authState = { user: null, session: null, loading: false },
) => {
  window.history.pushState({}, "", route);
  mockUseAuth.mockReturnValue(authState);
  return render(<App />);
};

describe("App", () => {
  beforeEach(() => {
    jest.clearAllMocks();
    globalThis.__IC_COUNTERS__ = {};
    window.history.pushState({}, "", "/");
    mockUseAuth.mockReturnValue({ user: null, session: null, loading: false });
  });

  it("initializes the shared counter registry once without discarding valid controller state", async () => {
    const existingRegistry = new Map([["ic_threats_blocked", { value: 732 }]]);
    globalThis.__IC_COUNTERS__ = {
      __controllers: existingRegistry,
      ic_threats_blocked: { value: 732, updatedAt: Date.now() },
    };

    renderAppAtRoute("/");

    await waitFor(() => {
      expect(globalThis.__IC_COUNTERS__).toBeTruthy();
      expect(globalThis.__IC_COUNTERS__.__appMounted).toBe(true);
      expect(globalThis.__IC_COUNTERS__.__controllers).toBeInstanceOf(Map);
      expect(
        globalThis.__IC_COUNTERS__.__controllers.has("ic_threats_blocked"),
      ).toBe(true);
      expect(globalThis.__IC_COUNTERS__.ic_threats_blocked).toMatchObject({
        value: 732,
      });
    });

    expect(await screen.findByText("Landing Page")).toBeInTheDocument();
  });

  it("rehydrates stale object registries into a Map without dropping controller entries", async () => {
    globalThis.__IC_COUNTERS__ = {
      __controllers: {
        ic_threats_blocked: { value: 732, updatedAt: Date.now() },
        ic_engineers_protected: { value: 344, updatedAt: Date.now() },
      },
    };

    renderAppAtRoute("/");

    await waitFor(() => {
      expect(globalThis.__IC_COUNTERS__.__controllers).toBeInstanceOf(Map);
      expect(
        globalThis.__IC_COUNTERS__.__controllers.has("ic_threats_blocked"),
      ).toBe(true);
      expect(
        globalThis.__IC_COUNTERS__.__controllers.has("ic_engineers_protected"),
      ).toBe(true);
    });
  });

  it("preserves valid top-level counter values during app bootstrap", async () => {
    globalThis.__IC_COUNTERS__ = {
      __controllers: new Map([["ic_threats_blocked", { value: 732 }]]),
      ic_threats_blocked: { value: 732, updatedAt: Date.now() },
      ic_engineers_protected: { value: 9999, updatedAt: Date.now() },
    };

    renderAppAtRoute("/");

    await waitFor(() => {
      expect(globalThis.__IC_COUNTERS__.__controllers).toBeInstanceOf(Map);
      expect(
        globalThis.__IC_COUNTERS__.__controllers.has("ic_threats_blocked"),
      ).toBe(true);
      expect(globalThis.__IC_COUNTERS__.ic_threats_blocked).toMatchObject({
        value: 732,
      });
      expect(globalThis.__IC_COUNTERS__.ic_engineers_protected).toMatchObject({
        value: 9999,
      });
    });
  });

  it("renders the landing page on /", async () => {
    renderAppAtRoute("/");

    expect(await screen.findByText("Landing Page")).toBeInTheDocument();
    expect(screen.getByTestId("auth-provider")).toBeInTheDocument();
    expect(screen.getByTestId("toaster")).toBeInTheDocument();
  });

  it("renders the dashboard page for an authenticated user", async () => {
    renderAppAtRoute("/dashboard", {
      user: { id: "user-1" },
      session: null,
      loading: false,
    });

    expect(await screen.findByText("Dashboard Page")).toBeInTheDocument();
  });

  it("renders the dashboard page when session exists during auth rehydration", async () => {
    renderAppAtRoute("/dashboard", {
      user: null,
      session: { access_token: "token-123" },
      loading: false,
    });

    expect(await screen.findByText("Dashboard Page")).toBeInTheDocument();
  });

  it("redirects unauthenticated users from /dashboard to /", async () => {
    renderAppAtRoute("/dashboard", {
      user: null,
      session: null,
      loading: false,
    });

    expect(await screen.findByText("Landing Page")).toBeInTheDocument();
    await waitFor(() => expect(window.location.pathname).toBe("/"));
  });

  it("renders nothing for private routes while auth is loading", async () => {
    const { container } = renderAppAtRoute("/dashboard", {
      user: null,
      session: null,
      loading: true,
    });

    await waitFor(() => {
      expect(screen.queryByText("Dashboard Page")).not.toBeInTheDocument();
      expect(screen.queryByText("Landing Page")).not.toBeInTheDocument();
    });

    expect(container).toBeInTheDocument();
  });

  it("renders the privacy page on /privacy", async () => {
    renderAppAtRoute("/privacy");

    expect(await screen.findByText("Privacy Page")).toBeInTheDocument();
  });

  it("renders the terms page on /terms", async () => {
    renderAppAtRoute("/terms");

    expect(await screen.findByText("Terms Page")).toBeInTheDocument();
  });

  it("renders the not found page for unknown routes", async () => {
    renderAppAtRoute("/does-not-exist");

    expect(await screen.findByText("Not Found Page")).toBeInTheDocument();
  });
});
