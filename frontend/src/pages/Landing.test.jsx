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
      ul: createMotionComponent("ul"),
      li: createMotionComponent("li"),
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
    globalThis.__IC_COUNTERS__ = {};

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

  it("starts each landing counter from the canonical baseline values", async () => {
    await renderLanding();

    expect(screen.getByTestId("threat-counter")).toHaveTextContent("5,344");
    expect(screen.getByTestId("user-counter")).toHaveTextContent("1,087");
  });

  it("keeps the counters monotonic with the required small increments", async () => {
    jest.useFakeTimers();
    jest.spyOn(Math, "random").mockReturnValue(0.25);

    try {
      await renderLanding();

      const threatCounter = screen.getByTestId("threat-counter");
      const userCounter = screen.getByTestId("user-counter");

      const beforeThreat = Number(threatCounter.textContent.replace(/,/g, ""));
      const beforeUsers = Number(userCounter.textContent.replace(/,/g, ""));

      act(() => {
        jest.advanceTimersByTime(20000);
      });

      const afterThreat = Number(threatCounter.textContent.replace(/,/g, ""));
      const afterUsers = Number(userCounter.textContent.replace(/,/g, ""));

      expect(afterThreat).toBeGreaterThanOrEqual(beforeThreat);
      expect(afterThreat - beforeThreat).toBeGreaterThanOrEqual(2);
      expect(afterThreat - beforeThreat).toBeLessThanOrEqual(3);

      expect(afterUsers).toBeGreaterThanOrEqual(beforeUsers);
      expect(afterUsers - beforeUsers).toBe(1);
    } finally {
      jest.restoreAllMocks();
      jest.useRealTimers();
    }
  });

  it("ignores stale lower persisted values so the counter never moves backward", async () => {
    const staleValue = 5000;
    const staleSnapshot = JSON.stringify({
      value: staleValue,
      updatedAt: Date.now(),
    });
    const originalGetItem = window.localStorage.getItem;
    const originalSetItem = window.localStorage.setItem;
    globalThis.__IC_COUNTERS__ = {};

    window.localStorage.getItem = jest.fn((key) => {
      if (key === "ic_threats_blocked") {
        return staleSnapshot;
      }
      return null;
    });
    window.localStorage.setItem = jest.fn((key, value) => {
      if (key === "ic_threats_blocked") {
        const parsed = JSON.parse(value);
        if (Number(parsed.value) > staleValue) {
          return originalSetItem.call(window.localStorage, key, value);
        }
      }
      return undefined;
    });

    try {
      await renderLanding();
      expect(screen.getByTestId("threat-counter")).toHaveTextContent("5,344");
    } finally {
      window.localStorage.getItem = originalGetItem;
      window.localStorage.setItem = originalSetItem;
    }
  });

  it("keeps the counters moving forward-only across rerenders and timer ticks", async () => {
    jest.useFakeTimers();
    jest.spyOn(Math, "random").mockReturnValue(0.25);

    try {
      const { rerender } = await renderLanding();

      const threatCounter = screen.getByTestId("threat-counter");
      const userCounter = screen.getByTestId("user-counter");

      const beforeThreat = Number(threatCounter.textContent.replace(/,/g, ""));
      const beforeUsers = Number(userCounter.textContent.replace(/,/g, ""));

      rerender(
        <MemoryRouter>
          <Landing />
        </MemoryRouter>,
      );

      act(() => {
        jest.advanceTimersByTime(20000);
      });

      const afterThreat = Number(threatCounter.textContent.replace(/,/g, ""));
      const afterUsers = Number(userCounter.textContent.replace(/,/g, ""));

      expect(afterThreat).toBeGreaterThanOrEqual(beforeThreat);
      expect(afterThreat - beforeThreat).toBeGreaterThanOrEqual(2);
      expect(afterThreat - beforeThreat).toBeLessThanOrEqual(3);
      expect(afterUsers).toBeGreaterThanOrEqual(beforeUsers);
      expect(afterUsers - beforeUsers).toBe(1);
    } finally {
      jest.restoreAllMocks();
      jest.useRealTimers();
    }
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

  it("renders below-fold sections on first paint", async () => {
    await renderLanding();

    expect(screen.getByTestId("credits-section")).toBeInTheDocument();
    expect(screen.getByTestId("footer-getstarted-btn")).toBeInTheDocument();
    expect(screen.getByTestId("feature-card-0")).toBeInTheDocument();
    expect(screen.getByTestId("feature-card-13")).toBeInTheDocument();
  });

  it("keeps below-fold sections visible without requiring scroll", async () => {
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
