import { render, cleanup, screen } from "@testing-library/react";
import ParticleField from "./ParticleField";

describe("ParticleField", () => {
  let context;

  beforeEach(() => {
    jest.clearAllMocks();

    Object.defineProperty(window, "matchMedia", {
      value: jest.fn().mockImplementation((query) => ({
        matches: false,
        media: query,
        addListener: jest.fn(),
        removeListener: jest.fn(),
        addEventListener: jest.fn(),
        removeEventListener: jest.fn(),
        dispatchEvent: jest.fn(),
      })),
      configurable: true,
    });

    Object.defineProperty(window, "requestAnimationFrame", {
      value: jest.fn((callback) => {
        if (typeof callback === "function") {
          return callback.length + 1;
        }
        return 1;
      }),
      configurable: true,
    });

    Object.defineProperty(window, "cancelAnimationFrame", {
      value: jest.fn(),
      configurable: true,
    });

    Object.defineProperty(window, "visualViewport", {
      value: {
        addEventListener: jest.fn(),
        removeEventListener: jest.fn(),
      },
      configurable: true,
    });

    Object.defineProperty(document, "hidden", {
      value: false,
      configurable: true,
    });

    Object.defineProperty(HTMLCanvasElement.prototype, "offsetWidth", {
      configurable: true,
      get: () => 960,
    });

    Object.defineProperty(HTMLCanvasElement.prototype, "offsetHeight", {
      configurable: true,
      get: () => 540,
    });

    Object.defineProperty(HTMLCanvasElement.prototype, "clientWidth", {
      configurable: true,
      get: () => 960,
    });

    Object.defineProperty(HTMLCanvasElement.prototype, "clientHeight", {
      configurable: true,
      get: () => 540,
    });

    const createRadialGradient = jest.fn(() => ({
      addColorStop: jest.fn(),
    }));

    context = {
      clearRect: jest.fn(),
      beginPath: jest.fn(),
      arc: jest.fn(),
      fill: jest.fn(),
      moveTo: jest.fn(),
      lineTo: jest.fn(),
      stroke: jest.fn(),
      setTransform: jest.fn(),
      createRadialGradient,
      fillStyle: "",
      strokeStyle: "",
      lineWidth: 0,
    };

    HTMLCanvasElement.prototype.getContext = jest.fn(() => context);
  });

  afterEach(() => {
    cleanup();
  });

  it("caps animation updates near 30fps", () => {
    render(<ParticleField density={50} />);

    const beforeCount = context.clearRect.mock.calls.length;
    const rafCallback = window.requestAnimationFrame.mock.calls.at(-1)[0];

    rafCallback(16);
    rafCallback(32);
    rafCallback(60);

    expect(context.clearRect.mock.calls.length - beforeCount).toBe(1);
  });

  it("reflows the canvas on resize and keeps the animation stable across mobile and desktop sizes", () => {
    render(<ParticleField density={50} />);

    const canvas = screen.getByTestId("particle-field");
    const originalWidth = canvas.width;
    const originalHeight = canvas.height;

    Object.defineProperty(canvas, "getBoundingClientRect", {
      configurable: true,
      value: () => ({ width: 420, height: 760 }),
    });
    Object.defineProperty(window, "devicePixelRatio", {
      configurable: true,
      value: 2,
    });

    window.dispatchEvent(new Event("resize"));

    expect(canvas.width).not.toBe(originalWidth);
    expect(canvas.height).not.toBe(originalHeight);
    expect(canvas.width).toBe(Math.round(420 * 1.5));
    expect(canvas.height).toBe(Math.round(760 * 1.5));
    expect(context.setTransform).toHaveBeenCalled();
  });

  it("pauses while the document is hidden and resumes when visible again", () => {
    render(<ParticleField density={50} />);

    const initialRafCalls = window.requestAnimationFrame.mock.calls.length;

    Object.defineProperty(document, "hidden", {
      value: true,
      configurable: true,
    });
    document.dispatchEvent(new Event("visibilitychange"));

    expect(window.cancelAnimationFrame).toHaveBeenCalled();

    Object.defineProperty(document, "hidden", {
      value: false,
      configurable: true,
    });
    document.dispatchEvent(new Event("visibilitychange"));

    expect(window.requestAnimationFrame.mock.calls.length).toBeGreaterThan(
      initialRafCalls,
    );
  });

  it("registers pointer-based interaction handlers for touch and mouse input", () => {
    const addEventListenerSpy = jest.spyOn(window, "addEventListener");

    render(<ParticleField density={50} />);

    expect(addEventListenerSpy).toHaveBeenCalledWith(
      "pointermove",
      expect.any(Function),
    );
    expect(addEventListenerSpy).toHaveBeenCalledWith(
      "pointerdown",
      expect.any(Function),
    );
    expect(addEventListenerSpy).toHaveBeenCalledWith(
      "pointerup",
      expect.any(Function),
    );
    expect(addEventListenerSpy).toHaveBeenCalledWith(
      "pointercancel",
      expect.any(Function),
    );
  });

  it("registers passive raw touch listeners so scroll-cancelled pointer gestures still track finger position on mobile", () => {
    const addEventListenerSpy = jest.spyOn(window, "addEventListener");

    render(<ParticleField density={50} />);

    expect(addEventListenerSpy).toHaveBeenCalledWith(
      "touchstart",
      expect.any(Function),
      { passive: true },
    );
    expect(addEventListenerSpy).toHaveBeenCalledWith(
      "touchmove",
      expect.any(Function),
      { passive: true },
    );
    expect(addEventListenerSpy).toHaveBeenCalledWith(
      "touchend",
      expect.any(Function),
      { passive: true },
    );
    expect(addEventListenerSpy).toHaveBeenCalledWith(
      "touchcancel",
      expect.any(Function),
      { passive: true },
    );
  });

  it("keeps the attraction point active at the last touched location after the finger lifts (sticky touch)", () => {
    const addEventListenerSpy = jest.spyOn(window, "addEventListener");

    render(<ParticleField density={50} />);

    const rafCallback = window.requestAnimationFrame.mock.calls.at(-1)[0];
    const pointerDownHandler = addEventListenerSpy.mock.calls.find(
      ([type]) => type === "pointerdown",
    )[1];
    const pointerUpHandler = addEventListenerSpy.mock.calls.find(
      ([type]) => type === "pointerup",
    )[1];

    context.createRadialGradient.mockClear();
    rafCallback(1000);
    rafCallback(1040);
    const baselineGradientCalls = context.createRadialGradient.mock.calls.length;

    pointerDownHandler({ clientX: 100, clientY: 100, pointerType: "touch" });

    context.createRadialGradient.mockClear();
    rafCallback(1080);
    const activeTouchGradientCalls =
      context.createRadialGradient.mock.calls.length;

    expect(activeTouchGradientCalls).toBe(baselineGradientCalls + 1);

    pointerUpHandler({ pointerType: "touch" });

    context.createRadialGradient.mockClear();
    rafCallback(1120);
    const afterReleaseGradientCalls =
      context.createRadialGradient.mock.calls.length;

    expect(afterReleaseGradientCalls).toBe(activeTouchGradientCalls);
  });

  it("moves the sticky attraction point to a new location when a fresh touch begins elsewhere", () => {
    const addEventListenerSpy = jest.spyOn(window, "addEventListener");

    render(<ParticleField density={50} />);

    const rafCallback = window.requestAnimationFrame.mock.calls.at(-1)[0];
    const pointerDownHandler = addEventListenerSpy.mock.calls.find(
      ([type]) => type === "pointerdown",
    )[1];
    const pointerUpHandler = addEventListenerSpy.mock.calls.find(
      ([type]) => type === "pointerup",
    )[1];

    pointerDownHandler({ clientX: 100, clientY: 100, pointerType: "touch" });
    pointerUpHandler({ pointerType: "touch" });

    context.createRadialGradient.mockClear();
    rafCallback(2000);
    rafCallback(2040);
    const stickyCallCount = context.createRadialGradient.mock.calls.length;

    pointerDownHandler({ clientX: 500, clientY: 300, pointerType: "touch" });

    context.createRadialGradient.mockClear();
    rafCallback(2080);
    const movedCallCount = context.createRadialGradient.mock.calls.length;

    expect(movedCallCount).toBe(stickyCallCount);
  });

  it("respects reduced motion and subscribes to viewport resizing on mobile layouts", () => {
    window.matchMedia.mockImplementation((query) => ({
      matches: query === "(prefers-reduced-motion: reduce)",
      media: query,
      addListener: jest.fn(),
      removeListener: jest.fn(),
      addEventListener: jest.fn(),
      removeEventListener: jest.fn(),
      dispatchEvent: jest.fn(),
    }));

    render(<ParticleField density={50} />);

    expect(window.matchMedia).toHaveBeenCalledWith(
      "(prefers-reduced-motion: reduce)",
    );
    expect(window.visualViewport.addEventListener).toHaveBeenCalledWith(
      "resize",
      expect.any(Function),
    );
    expect(window.visualViewport.addEventListener).toHaveBeenCalledWith(
      "scroll",
      expect.any(Function),
    );
  });
});
