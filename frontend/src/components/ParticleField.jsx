import { useEffect, useRef } from "react";

const clamp = (value, min, max) => Math.min(Math.max(value, min), max);

const ParticleField = ({ density = 180, paused = false }) => {
  const canvasRef = useRef(null);
  const rafRef = useRef(null);
  const lastFrameTimeRef = useRef(0);
  const attractionStrength = 1.25;

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    let width = 0;
    let height = 0;
    let stars = [];
    let t = 0;
    let isPaused = document.hidden || paused;
    const pointer = { x: -9999, y: -9999, active: false };
    const frameInterval = 1000 / 30;
    const palette = [
      "255, 215, 0",
      "229, 228, 226",
      "56, 189, 248",
      "255, 255, 255",
    ];

    const prefersReducedMotion = () => {
      if (typeof window === "undefined" || !window.matchMedia) {
        return false;
      }
      return window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    };

    const getCanvasMetrics = () => {
      const rect = canvas.getBoundingClientRect();
      const nextWidth = Math.max(
        0,
        rect.width || canvas.clientWidth || canvas.offsetWidth || 0,
      );
      const nextHeight = Math.max(
        0,
        rect.height || canvas.clientHeight || canvas.offsetHeight || 0,
      );

      return { width: nextWidth, height: nextHeight };
    };

    const getParticleCount = () => {
      const normalizedDensity = Number.isFinite(Number(density))
        ? Number(density)
        : 180;
      const baseDensity = clamp(normalizedDensity, 18, 220);
      const viewportFactor = width < 480 ? 0.7 : width < 1024 ? 0.9 : 1;
      const availableCores =
        typeof navigator !== "undefined" && navigator.hardwareConcurrency
          ? navigator.hardwareConcurrency
          : 4;
      const hardwareFactor = clamp(availableCores / 6, 0.72, 1.25);
      const areaFactor = clamp((width * height) / 180000, 0.5, 1.5);

      return Math.max(
        18,
        Math.min(
          baseDensity,
          Math.round(
            (baseDensity * viewportFactor * areaFactor) / hardwareFactor,
          ),
        ),
      );
    };

    const drawSparkle = (x, y, r, alpha, color) => {
      const grad = ctx.createRadialGradient(x, y, 0, x, y, r * 4);
      grad.addColorStop(0, `rgba(${color}, ${alpha * 0.9})`);
      grad.addColorStop(1, `rgba(${color}, 0)`);
      ctx.fillStyle = grad;
      ctx.beginPath();
      ctx.arc(x, y, r * 4, 0, Math.PI * 2);
      ctx.fill();

      ctx.strokeStyle = `rgba(${color}, ${alpha})`;
      ctx.lineWidth = 0.9;
      ctx.beginPath();
      ctx.moveTo(x - r * 2.4, y);
      ctx.lineTo(x + r * 2.4, y);
      ctx.moveTo(x, y - r * 2.4);
      ctx.lineTo(x, y + r * 2.4);
      ctx.stroke();

      ctx.fillStyle = `rgba(${color}, ${Math.min(1, alpha + 0.2)})`;
      ctx.beginPath();
      ctx.arc(x, y, r * 0.9, 0, Math.PI * 2);
      ctx.fill();
    };

    const renderConstellation = () => {
      if (prefersReducedMotion() || stars.length < 2) {
        return;
      }

      const bucketSize = 86;
      const buckets = new Map();

      stars.forEach((star, index) => {
        const bucketKey = `${Math.floor(star.x / bucketSize)}:${Math.floor(
          star.y / bucketSize,
        )}`;
        const bucketEntries = buckets.get(bucketKey) ?? [];
        bucketEntries.push(index);
        buckets.set(bucketKey, bucketEntries);
      });

      const neighborOffsets = [
        [0, 0],
        [1, 0],
        [-1, 0],
        [0, 1],
        [0, -1],
        [1, 1],
        [1, -1],
        [-1, 1],
        [-1, -1],
      ];
      const checkedPairs = new Set();

      for (const [key, indices] of buckets.entries()) {
        const [gridX, gridY] = key.split(":").map(Number);

        for (const [offsetX, offsetY] of neighborOffsets) {
          const neighborKey = `${gridX + offsetX}:${gridY + offsetY}`;
          const neighborIndices = buckets.get(neighborKey);
          if (!neighborIndices || neighborKey === key) {
            continue;
          }

          for (const leftIndex of indices) {
            const leftStar = stars[leftIndex];

            for (const rightIndex of neighborIndices) {
              if (rightIndex <= leftIndex) {
                continue;
              }

              const pairKey =
                leftIndex < rightIndex
                  ? `${leftIndex}:${rightIndex}`
                  : `${rightIndex}:${leftIndex}`;
              if (checkedPairs.has(pairKey)) {
                continue;
              }
              checkedPairs.add(pairKey);

              const rightStar = stars[rightIndex];
              const dx = leftStar.x - rightStar.x;
              const dy = leftStar.y - rightStar.y;
              const distSq = dx * dx + dy * dy;
              if (distSq < 12100) {
                const distance = Math.sqrt(distSq);
                const alpha = 0.08 * (1 - distance / 110);
                ctx.beginPath();
                ctx.strokeStyle = `rgba(${leftStar.c}, ${Math.max(0, alpha)})`;
                ctx.lineWidth = 0.5;
                ctx.moveTo(leftStar.x, leftStar.y);
                ctx.lineTo(rightStar.x, rightStar.y);
                ctx.stroke();
              }
            }
          }
        }
      }
    };

    const getPointerPoint = (event) => {
      const source = event?.touches?.[0] ?? event?.changedTouches?.[0] ?? event;

      if (
        !source ||
        typeof source.clientX !== "number" ||
        typeof source.clientY !== "number"
      ) {
        return null;
      }

      return {
        x: source.clientX,
        y: source.clientY,
      };
    };

    const updatePointerPosition = (event) => {
      const point = getPointerPoint(event);
      if (!point) {
        return;
      }

      const rect = canvas.getBoundingClientRect();
      const nextX = point.x - rect.left;
      const nextY = point.y - rect.top;

      pointer.x = nextX;
      pointer.y = nextY;
      pointer.active =
        nextX >= 0 && nextX <= width && nextY >= 0 && nextY <= height;
    };

    const clearPointer = () => {
      pointer.x = -9999;
      pointer.y = -9999;
      pointer.active = false;
    };

    const renderPointerAttraction = () => {
      if (prefersReducedMotion() || !pointer.active || stars.length === 0) {
        return;
      }

      const halo = ctx.createRadialGradient(
        pointer.x,
        pointer.y,
        0,
        pointer.x,
        pointer.y,
        120,
      );
      halo.addColorStop(0, "rgba(255,215,0,0.18)");
      halo.addColorStop(1, "rgba(255,215,0,0)");
      ctx.fillStyle = halo;
      ctx.beginPath();
      ctx.arc(pointer.x, pointer.y, 120, 0, Math.PI * 2);
      ctx.fill();

      for (const star of stars) {
        const dx = star.x - pointer.x;
        const dy = star.y - pointer.y;
        const distance = Math.sqrt(dx * dx + dy * dy);

        if (distance < 230 && distance > 0) {
          const alpha = 0.5 * (1 - distance / 230);
          ctx.beginPath();
          ctx.strokeStyle = `rgba(255, 215, 0, ${alpha})`;
          ctx.lineWidth = 0.9;
          ctx.moveTo(star.x, star.y);
          ctx.lineTo(pointer.x, pointer.y);
          ctx.stroke();

          star.x -= (dx / distance) * attractionStrength;
          star.y -= (dy / distance) * attractionStrength;
        }
      }
    };

    const resize = () => {
      const metrics = getCanvasMetrics();
      if (
        metrics.width === width &&
        metrics.height === height &&
        stars.length > 0
      ) {
        return;
      }
      width = metrics.width;
      height = metrics.height;
      if (!width || !height) {
        return;
      }

      const dpr = Math.min(window.devicePixelRatio || 1, 1.5);
      canvas.width = Math.round(width * dpr);
      canvas.height = Math.round(height * dpr);
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);

      const count = getParticleCount();
      stars = Array.from({ length: count }).map(() => ({
        x: Math.random() * width,
        y: Math.random() * height,
        vx: (Math.random() - 0.5) * 0.22,
        vy: (Math.random() - 0.5) * 0.22,
        r: Math.random() * 1.1 + 0.5,
        c: palette[Math.floor(Math.random() * palette.length)],
        phase: Math.random() * Math.PI * 2,
        speed: 0.6 + Math.random() * 1.2,
      }));
    };

    const renderFrame = () => {
      t += 0.016;
      ctx.clearRect(0, 0, width, height);

      for (const star of stars) {
        star.x += star.vx;
        star.y += star.vy;
        if (star.x < 0) star.x = width;
        if (star.x > width) star.x = 0;
        if (star.y < 0) star.y = height;
        if (star.y > height) star.y = 0;

        const twinkle =
          0.35 + 0.5 * (0.5 + 0.5 * Math.sin(t * star.speed + star.phase));
        drawSparkle(star.x, star.y, star.r, twinkle, star.c);
      }

      renderConstellation();
      renderPointerAttraction();
    };

    const stopLoop = () => {
      if (rafRef.current !== null) {
        window.cancelAnimationFrame(rafRef.current);
      }
      rafRef.current = null;
    };

    const startLoop = () => {
      if (
        prefersReducedMotion() ||
        paused ||
        document.hidden ||
        rafRef.current !== null
      ) {
        return;
      }
      lastFrameTimeRef.current = 0;
      rafRef.current = window.requestAnimationFrame(tick);
    };

    const tick = (timestamp) => {
      if (isPaused || paused || document.hidden) {
        return;
      }

      if (lastFrameTimeRef.current === 0) {
        lastFrameTimeRef.current = timestamp;
      }

      const delta = timestamp - lastFrameTimeRef.current;
      if (delta >= frameInterval) {
        lastFrameTimeRef.current = timestamp;
        renderFrame();
      }

      rafRef.current = window.requestAnimationFrame(tick);
    };

    const onPointerMove = (event) => {
      if (paused || document.hidden) {
        return;
      }

      updatePointerPosition(event);
    };

    const onPointerDown = (event) => {
      if (paused || document.hidden) {
        return;
      }

      updatePointerPosition(event);
    };

    const onPointerLeave = () => {
      clearPointer();
    };

    const onPointerRelease = (event) => {
      if (event?.pointerType === "touch") {
        return;
      }
      clearPointer();
    };

    const onTouchTrack = (event) => {
      if (paused || document.hidden) {
        return;
      }

      updatePointerPosition(event);
    };

    const onTouchRelease = () => {};

    const handleVisibilityChange = () => {
      isPaused = document.hidden || paused || prefersReducedMotion();
      if (isPaused) {
        clearPointer();
        stopLoop();
        return;
      }

      resize();
      renderFrame();
      startLoop();
    };

    const handleViewportResize = () => {
      resize();
      if (prefersReducedMotion() || paused || document.hidden) {
        renderFrame();
        return;
      }
      startLoop();
    };

    resize();
    renderFrame();
    if (!paused && !document.hidden && !prefersReducedMotion()) {
      startLoop();
    }
    window.addEventListener("resize", handleViewportResize);
    window.visualViewport?.addEventListener("resize", handleViewportResize);
    window.visualViewport?.addEventListener("scroll", handleViewportResize);
    window.addEventListener("pointermove", onPointerMove);
    window.addEventListener("pointerdown", onPointerDown);
    window.addEventListener("pointerup", onPointerRelease);
    window.addEventListener("pointercancel", onPointerRelease);
    canvas.addEventListener("pointerleave", onPointerLeave);
    document.addEventListener("visibilitychange", handleVisibilityChange);
    window.addEventListener("touchstart", onTouchTrack, { passive: true });
    window.addEventListener("touchmove", onTouchTrack, { passive: true });
    window.addEventListener("touchend", onTouchRelease, { passive: true });
    window.addEventListener("touchcancel", onTouchRelease, { passive: true });

    return () => {
      isPaused = true;
      clearPointer();
      stopLoop();
      window.removeEventListener("resize", handleViewportResize);
      window.visualViewport?.removeEventListener(
        "resize",
        handleViewportResize,
      );
      window.visualViewport?.removeEventListener(
        "scroll",
        handleViewportResize,
      );
      window.removeEventListener("pointermove", onPointerMove);
      window.removeEventListener("pointerdown", onPointerDown);
      window.removeEventListener("pointerup", onPointerRelease);
      window.removeEventListener("pointercancel", onPointerRelease);
      canvas.removeEventListener("pointerleave", onPointerLeave);
      document.removeEventListener("visibilitychange", handleVisibilityChange);
      window.removeEventListener("touchstart", onTouchTrack);
      window.removeEventListener("touchmove", onTouchTrack);
      window.removeEventListener("touchend", onTouchRelease);
      window.removeEventListener("touchcancel", onTouchRelease);
    };
  }, [density, paused]);

  return (
    <canvas
      ref={canvasRef}
      data-testid="particle-field"
      className="absolute inset-0 h-full w-full"
      style={{ pointerEvents: "none", background: "transparent" }}
    />
  );
};

export default ParticleField;
