import { render, cleanup } from "@testing-library/react";
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

  it("checks for reduced motion before running expensive visual passes", () => {
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
  });
});
