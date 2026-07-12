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

jest.mock("@/pages/PromptInspector", () => ({
  __esModule: true,
  default: () => <div>Prompt Inspector Page</div>,
}));

jest.mock("@/pages/PolicyManager", () => ({
  __esModule: true,
  default: () => <div>Policy Manager Page</div>,
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

const renderAppAtRoute = (route, authState = { user: null, loading: false }) => {
  window.history.pushState({}, "", route);
  mockUseAuth.mockReturnValue(authState);
  return render(<App />);
};

describe("App", () => {
  beforeEach(() => {
    jest.clearAllMocks();
    window.history.pushState({}, "", "/");
    mockUseAuth.mockReturnValue({ user: null, loading: false });
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
      loading: false,
    });

    expect(await screen.findByText("Dashboard Page")).toBeInTheDocument();
  });

  it("redirects unauthenticated users from /dashboard to /", async () => {
    renderAppAtRoute("/dashboard", {
      user: null,
      loading: false,
    });

    expect(await screen.findByText("Landing Page")).toBeInTheDocument();
    await waitFor(() => expect(window.location.pathname).toBe("/"));
  });

  it("renders nothing for private routes while auth is loading", async () => {
    const { container } = renderAppAtRoute("/dashboard", {
      user: null,
      loading: true,
    });

    await waitFor(() => {
      expect(screen.queryByText("Dashboard Page")).not.toBeInTheDocument();
      expect(screen.queryByText("Landing Page")).not.toBeInTheDocument();
    });

    expect(container).toBeInTheDocument();
  });

  it("renders the prompt inspector page for an authenticated user", async () => {
    renderAppAtRoute("/inspector", {
      user: { id: "user-1" },
      loading: false,
    });

    expect(await screen.findByText("Prompt Inspector Page")).toBeInTheDocument();
  });

  it("renders the policy manager page for an authenticated user", async () => {
    renderAppAtRoute("/policies", {
      user: { id: "user-1" },
      loading: false,
    });

    expect(await screen.findByText("Policy Manager Page")).toBeInTheDocument();
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
