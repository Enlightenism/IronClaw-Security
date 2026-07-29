import {
  render,
  screen,
  fireEvent,
  waitFor,
  act,
} from "@testing-library/react";
import Landing from "@/pages/Landing";
import { useAuth } from "@/context/AuthContext";
import { MemoryRouter } from "react-router-dom";

const mockNavigate = jest.fn();
const mockUseAuth = useAuth;

jest.mock("framer-motion", () => {
  const React = require("react");

  const createMotionComponent = (tagName) => {
    const MotionComponent = ({ children, ...props }) => {
      const filteredProps = { ...props };

      delete filteredProps.variants;
      delete filteredProps.initial;
      delete filteredProps.animate;
      delete filteredProps.custom;
      delete filteredProps.whileInView;
      delete filteredProps.viewport;
      delete filteredProps.transition;
      delete filteredProps.exit;

      return React.createElement(tagName, filteredProps, children);
    };

    MotionComponent.displayName = `MockMotion${tagName.toUpperCase()}`;
    return MotionComponent;
  };

  return {
    motion: {
      div: createMotionComponent("div"),
      h1: createMotionComponent("h1"),
      h2: createMotionComponent("h2"),
      h3: createMotionComponent("h3"),
      p: createMotionComponent("p"),
      section: createMotionComponent("section"),
      span: createMotionComponent("span"),
      button: createMotionComponent("button"),
    },
  };
});

jest.mock("@/hooks/useCountUp", () => ({
  useCountUp: (value) => value,
}));

jest.mock("@/components/AuthModal", () => {
  const MockAuthModal = (props) => (
    <div
      data-testid="auth-modal"
      data-open={props.open ? "true" : "false"}
      data-mode={props.initialMode}
    />
  );

  MockAuthModal.displayName = "MockAuthModal";

  return MockAuthModal;
});

jest.mock("@/components/ParticleField", () => {
  const MockParticleField = () => <div data-testid="particle-field" />;

  MockParticleField.displayName = "MockParticleField";

  return MockParticleField;
});

jest.mock("@/context/AuthContext", () => ({
  useAuth: jest.fn(),
}));

jest.mock("react-router-dom", () => {
  const actual = jest.requireActual("react-router-dom");

  const MockMemoryRouter = ({ children, future }) => (
    <actual.MemoryRouter
      future={{
        v7_startTransition: true,
        v7_relativeSplatPath: true,
        ...(future || {}),
      }}
    >
      {children}
    </actual.MemoryRouter>
  );

  MockMemoryRouter.displayName = "MockMemoryRouter";

  return {
    ...actual,
    useNavigate: () => mockNavigate,
    MemoryRouter: MockMemoryRouter,
  };
});

const flushPromises = async () => {
  await act(async () => {
    await Promise.resolve();
  });
};

const renderLanding = async (authState = { user: null }) => {
  mockUseAuth.mockReturnValue(authState);

  let result;
  await act(async () => {
    result = render(
      <MemoryRouter>
        <Landing />
      </MemoryRouter>,
    );
  });

  await flushPromises();
  return result;
};

describe("Landing", () => {
  beforeEach(() => {
    jest.clearAllMocks();

    Object.defineProperty(window, "localStorage", {
      value: {
        getItem: jest.fn(() => null),
        setItem: jest.fn(),
        removeItem: jest.fn(),
        clear: jest.fn(),
      },
      configurable: true,
    });

    window.requestIdleCallback = jest.fn((cb) => {
      const result = cb({ didTimeout: false, timeRemaining: () => 50 });
      return result ?? 1;
    });

    window.cancelIdleCallback = jest.fn();
  });

  it("renders hero content on first paint", async () => {
    await renderLanding();

    expect(screen.getByTestId("brand-logo")).toBeInTheDocument();
    expect(screen.getByText(/Complete Cyber Security/i)).toBeInTheDocument();
    expect(screen.getByTestId("hero-signin-btn")).toBeInTheDocument();
    expect(screen.getByTestId("hero-signup-btn")).toBeInTheDocument();
    expect(screen.getByTestId("threat-counter")).toBeInTheDocument();
    expect(screen.getByTestId("user-counter")).toBeInTheDocument();
  });

  it("opens signin auth modal when signin is clicked and no user exists", async () => {
    await renderLanding({ user: null });

    await act(async () => {
      fireEvent.click(screen.getByTestId("hero-signin-btn"));
    });

    await waitFor(() => {
      expect(screen.getByTestId("auth-modal")).toHaveAttribute(
        "data-open",
        "true",
      );
      expect(screen.getByTestId("auth-modal")).toHaveAttribute(
        "data-mode",
        "signin",
      );
    });
  });

  it("opens signup auth modal when signup is clicked and no user exists", async () => {
    await renderLanding({ user: null });

    await act(async () => {
      fireEvent.click(screen.getByTestId("hero-signup-btn"));
    });

    await waitFor(() => {
      expect(screen.getByTestId("auth-modal")).toHaveAttribute(
        "data-open",
        "true",
      );
      expect(screen.getByTestId("auth-modal")).toHaveAttribute(
        "data-mode",
        "signup",
      );
    });
  });

  it("navigates authenticated users to dashboard instead of opening modal", async () => {
    await renderLanding({ user: { id: "user-1" } });

    await act(async () => {
      fireEvent.click(screen.getByTestId("nav-signin-btn"));
    });

    expect(mockNavigate).toHaveBeenCalledWith("/dashboard");
    expect(screen.getByTestId("auth-modal")).toHaveAttribute(
      "data-open",
      "false",
    );
  });

  it("lazy-loads ParticleField after idle callback", async () => {
    await renderLanding();

    await waitFor(() => {
      expect(window.requestIdleCallback).toHaveBeenCalled();
      expect(screen.getByTestId("particle-field")).toBeInTheDocument();
    });
  });

  it("does not render below-fold sections on first paint", async () => {
    await renderLanding();

    expect(screen.queryByTestId("credits-section")).not.toBeInTheDocument();
    expect(
      screen.queryByTestId("footer-getstarted-btn"),
    ).not.toBeInTheDocument();
    expect(screen.queryByTestId("feature-card-0")).not.toBeInTheDocument();
  });

  it("reveals below-fold sections after first scroll", async () => {
    await renderLanding();

    await act(async () => {
      fireEvent.scroll(window);
    });

    await waitFor(() => {
      expect(screen.getByTestId("credits-section")).toBeInTheDocument();
      expect(screen.getByTestId("footer-getstarted-btn")).toBeInTheDocument();
      expect(screen.getByTestId("feature-card-0")).toBeInTheDocument();
      expect(screen.getByTestId("feature-card-13")).toBeInTheDocument();
    });
  });

  it("reveals below-fold sections when auth is opened before scrolling", async () => {
    await renderLanding();

    await act(async () => {
      fireEvent.click(screen.getByTestId("nav-signup-btn"));
    });

    await waitFor(() => {
      expect(screen.getByTestId("credits-section")).toBeInTheDocument();
      expect(screen.getByTestId("feature-card-0")).toBeInTheDocument();
      expect(screen.getByTestId("auth-modal")).toHaveAttribute(
        "data-open",
        "true",
      );
      expect(screen.getByTestId("auth-modal")).toHaveAttribute(
        "data-mode",
        "signup",
      );
    });
  });

  it("renders footer links after below-fold content is revealed", async () => {
    await renderLanding();

    await act(async () => {
      fireEvent.scroll(window);
    });

    await waitFor(() => {
      expect(screen.getByTestId("footer-privacy-link")).toBeInTheDocument();
      expect(screen.getByTestId("footer-terms-link")).toBeInTheDocument();
      expect(screen.getByTestId("powered-by")).toBeInTheDocument();
    });
  });
});
