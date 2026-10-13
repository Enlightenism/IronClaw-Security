import {
  render,
  screen,
  fireEvent,
  waitFor,
  act,
} from "@testing-library/react";
import Landing from "@/pages/Landing";
import { useAuth } from "@/context/AuthContext";
import {
  computeCounterValue,
  LANDING_COUNTER_FALLBACKS,
  resetLandingCounters,
  syncLandingCounters,
  useLandingCounter,
} from "@/lib/landingCounters";
import { supabase } from "@/lib/supabase";
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
  const MockParticleField = (props) => (
    <div
      data-testid="particle-field"
      data-paused={props.paused ? "true" : "false"}
    />
  );

  MockParticleField.displayName = "MockParticleField";

  return MockParticleField;
});

jest.mock("@/context/AuthContext", () => ({
  useAuth: jest.fn(),
}));

jest.mock("@/lib/supabase", () => ({
  supabase: { rpc: jest.fn() },
}));

jest.mock("@/lib/landingCounters", () => ({
  ...jest.requireActual("@/lib/landingCounters"),
  useLandingCounter: jest.fn(),
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

const START_MS = Date.UTC(2026, 9, 13, 6, 0, 0);
const HOUR_MS = 60 * 60 * 1000;
const MIN_KEY_PREFIX = "ironclaw:landing-counter-min:";

const formatCount = (value) => value.toLocaleString();
const parseCount = (text) => Number(text.replace(/,/g, ""));

const readCounters = () => ({
  threat: screen.getByTestId("threat-counter").textContent,
  users: screen.getByTestId("user-counter").textContent,
});

const expectedFormula = (nowMs) => ({
  threat: formatCount(
    computeCounterValue(LANDING_COUNTER_FALLBACKS.threats_blocked, nowMs),
  ),
  users: formatCount(
    computeCounterValue(LANDING_COUNTER_FALLBACKS.engineers_protected, nowMs),
  ),
});

const buildServerRow = (counterKey, value, nowMs) => {
  const config = LANDING_COUNTER_FALLBACKS[counterKey];

  return {
    counter_key: counterKey,
    value,
    server_time: new Date(nowMs).toISOString(),
    anchor_value: config.anchorValue,
    anchor_at: new Date(config.anchorAtMs).toISOString(),
    tick_seconds: config.tickMs / 1000,
    step_min: config.stepMin,
    step_max: config.stepMax,
    seed: config.seed,
  };
};

const installMemoryStorage = (initial = {}) => {
  const entries = new Map(Object.entries(initial));

  Object.defineProperty(window, "localStorage", {
    value: {
      getItem: jest.fn((key) => (entries.has(key) ? entries.get(key) : null)),
      setItem: jest.fn((key, value) => {
        entries.set(key, String(value));
      }),
      removeItem: jest.fn((key) => {
        entries.delete(key);
      }),
      clear: jest.fn(() => entries.clear()),
    },
    configurable: true,
  });

  return entries;
};

const freezeTimeAt = (nowMs) => {
  jest.useFakeTimers();
  jest.setSystemTime(new Date(nowMs));
};

describe("Landing", () => {
  beforeEach(() => {
    jest.clearAllMocks();
    resetLandingCounters();

    useLandingCounter.mockImplementation(
      jest.requireActual("@/lib/landingCounters").useLandingCounter,
    );
    supabase.rpc.mockResolvedValue({ data: [], error: null });

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
    window.requestAnimationFrame = jest.fn((callback) => {
      const id = Math.random() * 10000;
      window.__queuedRaf = window.__queuedRaf || [];
      window.__queuedRaf.push(callback);
      return id;
    });
    window.cancelAnimationFrame = jest.fn();
  });

  afterEach(() => {
    resetLandingCounters();
    jest.useRealTimers();
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

  it("shows the server value for each counter key", async () => {
    const nowMs = START_MS + HOUR_MS;
    freezeTimeAt(nowMs);
    installMemoryStorage();
    supabase.rpc.mockResolvedValue({
      data: [
        buildServerRow("threats_blocked", 987654, nowMs),
        buildServerRow("engineers_protected", 456789, nowMs),
      ],
      error: null,
    });

    await renderLanding();
    await act(async () => {
      await syncLandingCounters();
    });

    expect(supabase.rpc).toHaveBeenCalledWith("get_landing_counters");
    expect(useLandingCounter).toHaveBeenCalledWith("threats_blocked");
    expect(useLandingCounter).toHaveBeenCalledWith("engineers_protected");
    expect(readCounters()).toEqual({
      threat: formatCount(987654),
      users: formatCount(456789),
    });
  });

  it("shows the local formula value when the counter request fails", async () => {
    const nowMs = START_MS + 5 * HOUR_MS;
    freezeTimeAt(nowMs);
    installMemoryStorage();
    supabase.rpc.mockRejectedValue(new Error("offline"));

    await renderLanding();
    await act(async () => {
      await syncLandingCounters();
    });

    const shown = readCounters();

    expect(supabase.rpc).toHaveBeenCalledWith("get_landing_counters");
    expect(shown).toEqual(expectedFormula(nowMs));
    expect(parseCount(shown.threat)).toBeGreaterThan(732);
    expect(parseCount(shown.users)).toBeGreaterThan(344);
  });

  it("never displays less than the saved minimum", async () => {
    const nowMs = START_MS + HOUR_MS;
    const savedThreat = 7654321;
    const savedUsers = 1234567;
    freezeTimeAt(nowMs);
    installMemoryStorage({
      [`${MIN_KEY_PREFIX}threats_blocked`]: String(savedThreat),
      [`${MIN_KEY_PREFIX}engineers_protected`]: String(savedUsers),
    });
    const lowerServerState = expectedFormula(nowMs);
    supabase.rpc.mockResolvedValue({
      data: [
        buildServerRow(
          "threats_blocked",
          parseCount(lowerServerState.threat),
          nowMs,
        ),
        buildServerRow(
          "engineers_protected",
          parseCount(lowerServerState.users),
          nowMs,
        ),
      ],
      error: null,
    });

    await renderLanding();

    expect(readCounters()).toEqual({
      threat: formatCount(savedThreat),
      users: formatCount(savedUsers),
    });

    await act(async () => {
      await syncLandingCounters();
    });
    act(() => {
      jest.advanceTimersByTime(10 * 60 * 1000);
    });

    expect(readCounters()).toEqual({
      threat: formatCount(savedThreat),
      users: formatCount(savedUsers),
    });
  });

  it("shows the same value on two fresh devices at the same time", async () => {
    const nowMs = START_MS + 3 * HOUR_MS + 123456;
    freezeTimeAt(nowMs);
    installMemoryStorage();
    supabase.rpc.mockRejectedValue(new Error("offline"));

    const deviceA = await renderLanding();
    const shownByA = readCounters();
    deviceA.unmount();

    resetLandingCounters();
    installMemoryStorage();

    await renderLanding();
    const shownByB = readCounters();

    expect(shownByB).toEqual(shownByA);
    expect(shownByA).toEqual(expectedFormula(nowMs));
  });

  it("never falls back to 732 or 344 after the start time, even after 24 hours away", async () => {
    installMemoryStorage();
    freezeTimeAt(START_MS + HOUR_MS);
    supabase.rpc.mockRejectedValue(new Error("offline"));

    const firstVisit = await renderLanding();
    const before = readCounters();
    firstVisit.unmount();
    resetLandingCounters();

    const returnMs = START_MS + 31 * HOUR_MS;
    jest.setSystemTime(new Date(returnMs));

    await renderLanding();
    const after = readCounters();

    expect(after).toEqual(expectedFormula(returnMs));
    expect(parseCount(after.threat)).toBeGreaterThan(parseCount(before.threat));
    expect(parseCount(after.users)).toBeGreaterThan(parseCount(before.users));
    expect(parseCount(after.threat)).toBeGreaterThan(732);
    expect(parseCount(after.users)).toBeGreaterThan(344);
    expect(after.threat).not.toBe(formatCount(732));
    expect(after.users).not.toBe(formatCount(344));
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

  it("pauses the background particle field while the auth modal is open", async () => {
    await renderLanding({ user: null });

    await waitFor(() => {
      expect(screen.getByTestId("particle-field")).toBeInTheDocument();
    });

    expect(screen.getByTestId("particle-field")).toHaveAttribute(
      "data-paused",
      "false",
    );

    await act(async () => {
      fireEvent.click(screen.getByTestId("hero-signin-btn"));
    });

    await waitFor(() => {
      expect(screen.getByTestId("auth-modal")).toHaveAttribute(
        "data-open",
        "true",
      );
      expect(screen.getByTestId("particle-field")).toHaveAttribute(
        "data-paused",
        "true",
      );
    });
  });

  it("throttles feature-card hover glow updates to animation frames", async () => {
    await renderLanding();

    const featureCard = screen.getByTestId("feature-card-0");
    featureCard.getBoundingClientRect = jest.fn(() => ({
      left: 20,
      top: 30,
      width: 200,
      height: 180,
    }));

    fireEvent.mouseMove(featureCard, {
      clientX: 100,
      clientY: 140,
    });
    fireEvent.mouseMove(featureCard, {
      clientX: 125,
      clientY: 165,
    });

    expect(window.requestAnimationFrame).toHaveBeenCalledTimes(1);

    const queuedFrame = window.__queuedRaf[0];
    queuedFrame();

    expect(featureCard.style.getPropertyValue("--mx")).toBe("80px");
    expect(featureCard.style.getPropertyValue("--my")).toBe("110px");
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
