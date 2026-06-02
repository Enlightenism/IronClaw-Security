import { useEffect, useRef } from "react";

/**
 * Animated deep-space starfield.
 * - Twinkling star sprites (4-point sparkle) in gold / platinum / sky.
 * - Drifting motion with soft parallax.
 * - Faint constellation lines between nearby stars.
 * - Multiple bright gold lines that reach out and follow the cursor.
 */
const ParticleField = ({ density = 90 }) => {
  const canvasRef = useRef(null);
  const rafRef = useRef();

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    let width = 0;
    let height = 0;
    const dpr = Math.min(window.devicePixelRatio || 1, 2);
    let stars = [];
    let t = 0;
    const mouse = { x: -9999, y: -9999, active: false };

    const palette = [
      "255, 215, 0", // gold
      "229, 228, 226", // platinum
      "56, 189, 248", // sky
      "255, 255, 255", // white
    ];

    const drawSparkle = (x, y, r, alpha, color) => {
      // soft glow
      const grad = ctx.createRadialGradient(x, y, 0, x, y, r * 4);
      grad.addColorStop(0, `rgba(${color}, ${alpha * 0.9})`);
      grad.addColorStop(1, `rgba(${color}, 0)`);
      ctx.fillStyle = grad;
      ctx.beginPath();
      ctx.arc(x, y, r * 4, 0, Math.PI * 2);
      ctx.fill();

      // 4-point cross sparkle
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

    const resize = () => {
      width = canvas.offsetWidth;
      height = canvas.offsetHeight;
      canvas.width = width * dpr;
      canvas.height = height * dpr;
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      const count = Math.min(density, Math.floor((width * height) / 13000));
      stars = Array.from({ length: count }).map(() => ({
        x: Math.random() * width,
        y: Math.random() * height,
        vx: (Math.random() - 0.5) * 0.22,
        vy: (Math.random() - 0.5) * 0.22,
        r: Math.random() * 1.1 + 0.5,
        c: palette[Math.floor(Math.random() * palette.length)],
        phase: Math.random() * Math.PI * 2,
        speed: 0.6 + Math.random() * 1.6, // twinkle speed
      }));
    };

    const draw = () => {
      t += 0.016;
      ctx.clearRect(0, 0, width, height);

      for (let i = 0; i < stars.length; i++) {
        const s = stars[i];
        s.x += s.vx;
        s.y += s.vy;
        if (s.x < 0) s.x = width;
        if (s.x > width) s.x = 0;
        if (s.y < 0) s.y = height;
        if (s.y > height) s.y = 0;

        // twinkle: oscillate alpha
        const twinkle =
          0.35 + 0.5 * (0.5 + 0.5 * Math.sin(t * s.speed + s.phase));
        drawSparkle(s.x, s.y, s.r, twinkle, s.c);

        // faint constellation lines between nearby stars
        for (let j = i + 1; j < stars.length; j++) {
          const q = stars[j];
          const dx = s.x - q.x;
          const dy = s.y - q.y;
          const dist = dx * dx + dy * dy;
          if (dist < 12100) {
            const d = Math.sqrt(dist);
            ctx.beginPath();
            ctx.strokeStyle = `rgba(${s.c}, ${0.08 * (1 - d / 110)})`;
            ctx.lineWidth = 0.5;
            ctx.moveTo(s.x, s.y);
            ctx.lineTo(q.x, q.y);
            ctx.stroke();
          }
        }
      }

      // bright gold lines reaching out to the cursor (many of them)
      if (mouse.active) {
        // halo around cursor
        const cg = ctx.createRadialGradient(
          mouse.x,
          mouse.y,
          0,
          mouse.x,
          mouse.y,
          90,
        );
        cg.addColorStop(0, "rgba(255,215,0,0.10)");
        cg.addColorStop(1, "rgba(255,215,0,0)");
        ctx.fillStyle = cg;
        ctx.beginPath();
        ctx.arc(mouse.x, mouse.y, 90, 0, Math.PI * 2);
        ctx.fill();

        for (let i = 0; i < stars.length; i++) {
          const s = stars[i];
          const dx = s.x - mouse.x;
          const dy = s.y - mouse.y;
          const dist = Math.sqrt(dx * dx + dy * dy);
          if (dist < 230) {
            const a = 0.5 * (1 - dist / 230);
            ctx.beginPath();
            ctx.strokeStyle = `rgba(255, 215, 0, ${a})`;
            ctx.lineWidth = 0.9;
            ctx.moveTo(s.x, s.y);
            ctx.lineTo(mouse.x, mouse.y);
            ctx.stroke();
            // gentle pull toward cursor for a magnetic feel
            s.x -= (dx / dist) * 0.25;
            s.y -= (dy / dist) * 0.25;
          }
        }
      }

      rafRef.current = requestAnimationFrame(draw);
    };

    const onMove = (e) => {
      const rect = canvas.getBoundingClientRect();
      mouse.x = e.clientX - rect.left;
      mouse.y = e.clientY - rect.top;
      mouse.active = mouse.y >= 0 && mouse.y <= height;
    };
    const onLeave = () => {
      mouse.active = false;
    };

    resize();
    draw();
    window.addEventListener("resize", resize);
    window.addEventListener("mousemove", onMove);
    window.addEventListener("mouseout", onLeave);

    return () => {
      cancelAnimationFrame(rafRef.current);
      window.removeEventListener("resize", resize);
      window.removeEventListener("mousemove", onMove);
      window.removeEventListener("mouseout", onLeave);
    };
  }, [density]);

  return (
    <canvas
      ref={canvasRef}
      data-testid="particle-field"
      className="absolute inset-0 h-full w-full"
      style={{ pointerEvents: "none" }}
    />
  );
};

export default ParticleField;
