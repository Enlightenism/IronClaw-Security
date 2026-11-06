from __future__ import annotations

import logging
import textwrap
from typing import Annotated

from fastapi import APIRouter, Form, Request, Response, status
from fastapi.responses import HTMLResponse, RedirectResponse

from frontend.auth_context import (
    CurrentUser,
    OptionalUser,
    set_session_cookie,
    validate_api_key_login,
)

_log = logging.getLogger(__name__)

router = APIRouter(tags=["auth"])

# ── Login page HTML (self-contained — no base.html shell) ─────────────────────

_LOGIN_HTML = textwrap.dedent(
    """\
<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta http-equiv="Content-Security-Policy"
        content="default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' https://fonts.googleapis.com https://fonts.gstatic.com; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self';">
  <title>IronClaw Security — Sign In</title>
  <link rel="icon" href="/favicon.ico" sizes="32x32">
  <link rel="icon" href="/favicon-96x96.png" type="image/png" sizes="96x96">
  <link rel="apple-touch-icon" href="/apple-touch-icon.png" sizes="180x180">
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=Orbitron:wght@400;600;700;900&display=swap" rel="stylesheet">
  <style>
    /* ── Reset ────────────────────────────────────────────────────────────── */
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    html {
      -webkit-font-smoothing: antialiased;
      -moz-osx-font-smoothing: grayscale;
      text-rendering: optimizeLegibility;
      height: 100%;
    }
    body {
      min-height: 100dvh;
      font-family: 'Inter', 'Helvetica Neue', system-ui, sans-serif;
      background: #030508;
      color: #e8e6e0;
      overflow-x: hidden;
      display: flex;
      align-items: center;
      justify-content: center;
    }

    /* ── Design tokens ────────────────────────────────────────────────────── */
    :root {
      --gold-1:       #ffd700;
      --gold-2:       #ffec6e;
      --gold-3:       #c9a227;
      --gold-4:       #8b6914;
      --gold-glow:    rgba(255,215,0,0.18);
      --gold-glow-lg: rgba(255,215,0,0.08);
      --plat-1:       #e8e6e8;
      --plat-2:       #d0cdd4;
      --plat-3:       #a09bad;
      --sky-1:        #7dd3fc;
      --sky-2:        #38bdf8;
      --sky-3:        #0ea5e9;
      --sky-glow:     rgba(56,189,248,0.15);
      --black-1:      #030508;
      --black-2:      #080c14;
      --black-3:      #0d1220;
      --black-4:      #111827;
      --black-5:      #1a2235;
      --glass-bg:     rgba(8,12,20,0.72);
      --glass-border: rgba(255,215,0,0.12);
      --glass-border-active: rgba(255,215,0,0.45);
      --error-color:  #f87171;
      --error-bg:     rgba(248,113,113,0.08);
      --radius-card:  1.25rem;
      --radius-input: 0.625rem;
      --transition:   220ms cubic-bezier(0.16,1,0.3,1);
    }

    /* ── Background — deep animated starfield + grid ─────────────────────── */
    .ic-login-bg {
      position: fixed;
      inset: 0;
      z-index: 0;
      background:
        radial-gradient(ellipse 80% 60% at 50% -10%, rgba(255,215,0,0.06) 0%, transparent 70%),
        radial-gradient(ellipse 60% 40% at 80% 100%, rgba(56,189,248,0.05) 0%, transparent 60%),
        radial-gradient(ellipse 40% 60% at 10% 50%, rgba(201,162,39,0.04) 0%, transparent 60%),
        #030508;
      overflow: hidden;
    }

    /* Animated grid lines */
    .ic-login-bg::before {
      content: '';
      position: absolute;
      inset: 0;
      background-image:
        linear-gradient(rgba(255,215,0,0.03) 1px, transparent 1px),
        linear-gradient(90deg, rgba(255,215,0,0.03) 1px, transparent 1px);
      background-size: 60px 60px;
      animation: gridPan 25s linear infinite;
    }

    /* Scan line sweep */
    .ic-login-bg::after {
      content: '';
      position: absolute;
      inset: 0;
      background: linear-gradient(
        180deg,
        transparent 0%,
        rgba(255,215,0,0.015) 50%,
        transparent 100%
      );
      background-size: 100% 200%;
      animation: scanSweep 6s ease-in-out infinite;
    }

    @keyframes gridPan {
      0%   { transform: translateY(0); }
      100% { transform: translateY(60px); }
    }

    @keyframes scanSweep {
      0%, 100% { background-position: 0 -100%; }
      50%       { background-position: 0 100%; }
    }

    /* Floating orbs */
    .ic-orb {
      position: absolute;
      border-radius: 50%;
      filter: blur(80px);
      pointer-events: none;
      animation: orbFloat linear infinite;
    }
    .ic-orb--gold {
      width: 500px; height: 500px;
      background: radial-gradient(circle, rgba(255,215,0,0.07) 0%, transparent 70%);
      top: -120px; left: -100px;
      animation-duration: 20s;
    }
    .ic-orb--sky {
      width: 400px; height: 400px;
      background: radial-gradient(circle, rgba(56,189,248,0.06) 0%, transparent 70%);
      bottom: -80px; right: -80px;
      animation-duration: 28s;
      animation-direction: reverse;
    }
    .ic-orb--plat {
      width: 300px; height: 300px;
      background: radial-gradient(circle, rgba(208,205,212,0.04) 0%, transparent 70%);
      top: 40%; right: 10%;
      animation-duration: 35s;
    }

    @keyframes orbFloat {
      0%   { transform: translate(0, 0) scale(1); }
      33%  { transform: translate(30px, -20px) scale(1.05); }
      66%  { transform: translate(-20px, 30px) scale(0.97); }
      100% { transform: translate(0, 0) scale(1); }
    }

    /* Particle canvas */
    #ic-particle-canvas {
      position: absolute;
      inset: 0;
      pointer-events: none;
    }

    /* ── Main layout ──────────────────────────────────────────────────────── */
    .ic-login-wrap {
      position: relative;
      z-index: 10;
      display: flex;
      align-items: center;
      justify-content: center;
      min-height: 100dvh;
      width: 100%;
      padding: 2rem 1rem;
    }

    .ic-login-card {
      width: 100%;
      max-width: 440px;
      background: var(--glass-bg);
      border: 1px solid var(--glass-border);
      border-radius: var(--radius-card);
      padding: 2.75rem 2.5rem 2.5rem;
      backdrop-filter: blur(24px) saturate(1.4);
      -webkit-backdrop-filter: blur(24px) saturate(1.4);
      box-shadow:
        0 0 0 1px rgba(255,215,0,0.05),
        0 4px 24px rgba(0,0,0,0.6),
        0 24px 80px rgba(0,0,0,0.4),
        inset 0 1px 0 rgba(255,215,0,0.07);
      animation: cardReveal 0.7s cubic-bezier(0.16,1,0.3,1) both;
      position: relative;
      overflow: hidden;
    }

    /* Gold shimmer edge on card */
    .ic-login-card::before {
      content: '';
      position: absolute;
      top: 0; left: 0; right: 0;
      height: 1px;
      background: linear-gradient(
        90deg,
        transparent 0%,
        rgba(255,215,0,0.6) 30%,
        var(--gold-1) 50%,
        rgba(255,215,0,0.6) 70%,
        transparent 100%
      );
      animation: shimmerEdge 3s ease-in-out infinite;
    }

    /* Platinum corner accent bottom-right */
    .ic-login-card::after {
      content: '';
      position: absolute;
      bottom: 0; right: 0;
      width: 80px; height: 80px;
      background: radial-gradient(circle at bottom right, rgba(208,205,212,0.06), transparent 70%);
      border-radius: 0 0 var(--radius-card) 0;
      pointer-events: none;
    }

    @keyframes cardReveal {
      0%   { opacity: 0; transform: translateY(24px) scale(0.97); }
      100% { opacity: 1; transform: translateY(0) scale(1); }
    }

    @keyframes shimmerEdge {
      0%, 100% { opacity: 0.6; background-position: -200% 0; }
      50%       { opacity: 1;   background-position: 200% 0; }
    }

    /* ── Brand section ────────────────────────────────────────────────────── */
    .ic-brand {
      display: flex;
      flex-direction: column;
      align-items: center;
      gap: 0.75rem;
      margin-bottom: 2.25rem;
    }

    .ic-brand__claw-wrap {
      position: relative;
      width: 72px;
      height: 72px;
    }

    .ic-brand__claw-glow {
      position: absolute;
      inset: -12px;
      border-radius: 50%;
      background: radial-gradient(circle, rgba(255,215,0,0.2) 0%, transparent 70%);
      animation: pulseGlow 2.5s ease-in-out infinite;
    }

    @keyframes pulseGlow {
      0%, 100% { opacity: 0.6; transform: scale(1); }
      50%       { opacity: 1;   transform: scale(1.1); }
    }

    .ic-brand__claw-svg {
      position: relative;
      z-index: 1;
      filter: drop-shadow(0 0 12px rgba(255,215,0,0.5));
      animation: shieldRotate 8s ease-in-out infinite;
    }

    @keyframes shieldRotate {
      0%, 100% { filter: drop-shadow(0 0 10px rgba(255,215,0,0.4)); }
      50%       { filter: drop-shadow(0 0 20px rgba(255,215,0,0.7)) drop-shadow(0 0 40px rgba(255,215,0,0.2)); }
    }

    .ic-brand__name {
      font-family: 'Orbitron', 'Inter', sans-serif;
      font-size: 1.6rem;
      font-weight: 900;
      letter-spacing: 0.12em;
      text-transform: uppercase;
      background: linear-gradient(
        135deg,
        var(--plat-2) 0%,
        var(--gold-1) 35%,
        var(--plat-1) 55%,
        var(--gold-2) 75%,
        var(--plat-3) 100%
      );
      background-size: 200% auto;
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      background-clip: text;
      animation: goldShimmer 4s linear infinite;
    }

    @keyframes goldShimmer {
      0%   { background-position: 0% center; }
      100% { background-position: 200% center; }
    }

    .ic-brand__tagline {
      font-size: 0.7rem;
      font-weight: 500;
      letter-spacing: 0.22em;
      text-transform: uppercase;
      color: var(--plat-3);
      opacity: 0.8;
    }

    /* ── Status badge (animated) ──────────────────────────────────────────── */
    .ic-status-badge {
      display: inline-flex;
      align-items: center;
      gap: 0.375rem;
      padding: 0.25rem 0.75rem;
      border-radius: 9999px;
      border: 1px solid rgba(56,189,248,0.2);
      background: rgba(56,189,248,0.05);
      font-size: 0.65rem;
      font-weight: 600;
      letter-spacing: 0.16em;
      text-transform: uppercase;
      color: var(--sky-1);
      margin-bottom: 0.5rem;
    }

    .ic-status-dot {
      width: 6px;
      height: 6px;
      border-radius: 50%;
      background: var(--sky-2);
      animation: blinkDot 1.8s ease-in-out infinite;
      flex-shrink: 0;
    }

    @keyframes blinkDot {
      0%, 100% { opacity: 1; box-shadow: 0 0 4px var(--sky-2); }
      50%       { opacity: 0.35; box-shadow: none; }
    }

    /* ── Form section ─────────────────────────────────────────────────────── */
    .ic-form-group {
      margin-bottom: 1.25rem;
    }

    .ic-form-label {
      display: block;
      font-size: 0.7rem;
      font-weight: 600;
      letter-spacing: 0.14em;
      text-transform: uppercase;
      color: var(--plat-3);
      margin-bottom: 0.5rem;
    }

    .ic-input-wrap {
      position: relative;
    }

    .ic-input-icon {
      position: absolute;
      left: 0.875rem;
      top: 50%;
      transform: translateY(-50%);
      color: var(--gold-4);
      pointer-events: none;
      transition: color var(--transition);
    }

    .ic-form-input {
      width: 100%;
      padding: 0.75rem 1rem 0.75rem 2.75rem;
      border-radius: var(--radius-input);
      border: 1px solid rgba(255,215,0,0.1);
      background: rgba(8,12,20,0.6);
      color: var(--plat-1);
      font-size: 0.9rem;
      font-family: inherit;
      outline: none;
      transition:
        border-color var(--transition),
        box-shadow var(--transition),
        background var(--transition);
      -webkit-text-fill-color: var(--plat-1);
    }

    .ic-form-input::placeholder {
      color: rgba(160,155,173,0.45);
    }

    .ic-form-input:-webkit-autofill,
    .ic-form-input:-webkit-autofill:hover,
    .ic-form-input:-webkit-autofill:focus {
      -webkit-box-shadow: 0 0 0 1000px rgba(8,12,20,0.9) inset;
      -webkit-text-fill-color: var(--plat-1);
      border-color: rgba(255,215,0,0.25);
      transition: background-color 5000s ease-in-out 0s;
    }

    .ic-form-input:focus {
      border-color: rgba(255,215,0,0.4);
      background: rgba(8,12,20,0.8);
      box-shadow:
        0 0 0 3px rgba(255,215,0,0.08),
        0 0 20px rgba(255,215,0,0.06);
    }

    .ic-form-input:focus + .ic-input-focus-ring {
      opacity: 1;
    }

    /* Eye toggle for password */
    .ic-eye-toggle {
      position: absolute;
      right: 0.875rem;
      top: 50%;
      transform: translateY(-50%);
      background: none;
      border: none;
      color: var(--plat-3);
      cursor: pointer;
      padding: 0.25rem;
      border-radius: 4px;
      display: flex;
      align-items: center;
      justify-content: center;
      transition: color var(--transition);
    }

    .ic-eye-toggle:hover { color: var(--gold-2); }

    /* ── Error message ────────────────────────────────────────────────────── */
    .ic-login-error {
      display: flex;
      align-items: center;
      gap: 0.5rem;
      padding: 0.75rem 1rem;
      border-radius: var(--radius-input);
      border: 1px solid rgba(248,113,113,0.3);
      background: var(--error-bg);
      color: var(--error-color);
      font-size: 0.8rem;
      font-weight: 500;
      margin-bottom: 1.25rem;
      animation: shakeError 0.4s cubic-bezier(0.36,0.07,0.19,0.97);
    }

    @keyframes shakeError {
      0%, 100% { transform: translateX(0); }
      20%       { transform: translateX(-6px); }
      40%       { transform: translateX(6px); }
      60%       { transform: translateX(-4px); }
      80%       { transform: translateX(4px); }
    }

    /* ── Submit button ────────────────────────────────────────────────────── */
    .ic-btn-submit {
      width: 100%;
      padding: 0.875rem 1.5rem;
      border-radius: var(--radius-input);
      border: 1px solid rgba(255,215,0,0.35);
      background: linear-gradient(
        135deg,
        rgba(255,215,0,0.12) 0%,
        rgba(201,162,39,0.18) 50%,
        rgba(255,215,0,0.1) 100%
      );
      color: var(--gold-1);
      font-family: 'Orbitron', 'Inter', sans-serif;
      font-size: 0.78rem;
      font-weight: 700;
      letter-spacing: 0.18em;
      text-transform: uppercase;
      cursor: pointer;
      position: relative;
      overflow: hidden;
      transition:
        border-color var(--transition),
        box-shadow var(--transition),
        background var(--transition),
        transform var(--transition);
      margin-top: 0.5rem;
    }

    .ic-btn-submit::before {
      content: '';
      position: absolute;
      inset: 0;
      background: linear-gradient(
        90deg,
        transparent 0%,
        rgba(255,215,0,0.15) 50%,
        transparent 100%
      );
      background-size: 200% 100%;
      animation: btnShimmer 2.5s linear infinite;
      pointer-events: none;
    }

    @keyframes btnShimmer {
      0%   { background-position: -200% 0; }
      100% { background-position: 200% 0; }
    }

    .ic-btn-submit:hover {
      border-color: rgba(255,215,0,0.65);
      background: linear-gradient(
        135deg,
        rgba(255,215,0,0.2) 0%,
        rgba(201,162,39,0.28) 50%,
        rgba(255,215,0,0.18) 100%
      );
      box-shadow:
        0 0 20px rgba(255,215,0,0.2),
        0 0 40px rgba(255,215,0,0.08);
      transform: translateY(-1px);
    }

    .ic-btn-submit:active {
      transform: translateY(0);
      box-shadow: none;
    }

    .ic-btn-submit:disabled {
      opacity: 0.5;
      cursor: not-allowed;
      transform: none;
    }

    /* Spinner inside button */
    .ic-btn-spinner {
      display: none;
      width: 16px;
      height: 16px;
      border: 2px solid rgba(255,215,0,0.3);
      border-top-color: var(--gold-1);
      border-radius: 50%;
      animation: spin 0.7s linear infinite;
      margin: 0 auto;
    }

    @keyframes spin {
      to { transform: rotate(360deg); }
    }

    .ic-btn-submit.ic-loading .ic-btn-text { display: none; }
    .ic-btn-submit.ic-loading .ic-btn-spinner { display: block; }

    /* ── Divider ──────────────────────────────────────────────────────────── */
    .ic-divider {
      display: flex;
      align-items: center;
      gap: 0.75rem;
      margin: 1.5rem 0 1.25rem;
      color: rgba(160,155,173,0.35);
      font-size: 0.65rem;
      letter-spacing: 0.1em;
      text-transform: uppercase;
    }

    .ic-divider::before,
    .ic-divider::after {
      content: '';
      flex: 1;
      height: 1px;
      background: linear-gradient(90deg, transparent, rgba(255,215,0,0.12), transparent);
    }

    /* ── Security info strip ──────────────────────────────────────────────── */
    .ic-security-strip {
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 0.5rem;
      margin-top: 1.75rem;
      color: rgba(160,155,173,0.4);
      font-size: 0.65rem;
      letter-spacing: 0.08em;
    }

    .ic-security-strip svg {
      color: rgba(255,215,0,0.35);
      flex-shrink: 0;
    }

    /* ── Sparkling gold particles (CSS) ──────────────────────────────────── */
    .ic-spark {
      position: fixed;
      pointer-events: none;
      border-radius: 50%;
      z-index: 5;
      animation: sparkLife linear forwards;
    }

    @keyframes sparkLife {
      0%   { opacity: 0; transform: translate(0, 0) scale(0); }
      15%  { opacity: 1; transform: translate(var(--sx), var(--sy)) scale(1); }
      85%  { opacity: 0.6; }
      100% { opacity: 0; transform: translate(var(--ex), var(--ey)) scale(0.2); }
    }

    /* ── Scanning line animation on input focus ───────────────────────────── */
    .ic-input-scan {
      position: absolute;
      left: 0; right: 0;
      bottom: 0;
      height: 2px;
      background: linear-gradient(90deg, transparent, var(--gold-1), transparent);
      background-size: 200% 100%;
      transform: scaleX(0);
      transform-origin: left;
      transition: transform 0.3s var(--transition);
      border-radius: 0 0 var(--radius-input) var(--radius-input);
    }

    .ic-form-input:focus ~ .ic-input-scan {
      transform: scaleX(1);
      animation: scanLine 1.5s linear infinite;
    }

    @keyframes scanLine {
      0%   { background-position: -200% 0; }
      100% { background-position: 200% 0; }
    }

    /* ── Platinum corner accents ──────────────────────────────────────────── */
    .ic-corner {
      position: absolute;
      width: 16px;
      height: 16px;
      opacity: 0.45;
    }
    .ic-corner--tl { top: 12px; left: 12px; border-top: 1.5px solid var(--plat-2); border-left: 1.5px solid var(--plat-2); }
    .ic-corner--tr { top: 12px; right: 12px; border-top: 1.5px solid var(--plat-2); border-right: 1.5px solid var(--plat-2); }
    .ic-corner--bl { bottom: 12px; left: 12px; border-bottom: 1.5px solid var(--plat-2); border-left: 1.5px solid var(--plat-2); }
    .ic-corner--br { bottom: 12px; right: 12px; border-bottom: 1.5px solid var(--plat-2); border-right: 1.5px solid var(--plat-2); }

    /* ── Focus ring accessible ────────────────────────────────────────────── */
    :focus-visible {
      outline: 2px solid rgba(255,215,0,0.5);
      outline-offset: 2px;
      border-radius: 4px;
    }

    /* ── Reduced motion ───────────────────────────────────────────────────── */
    @media (prefers-reduced-motion: reduce) {
      *, *::before, *::after {
        animation-duration: 0.01ms !important;
        animation-iteration-count: 1 !important;
        transition-duration: 0.01ms !important;
      }
    }

    /* ── Mobile ───────────────────────────────────────────────────────────── */
    @media (max-width: 480px) {
      .ic-login-card {
        padding: 2rem 1.5rem 1.75rem;
        border-radius: 1rem;
      }
      .ic-brand__name { font-size: 1.35rem; }
    }
  </style>
</head>
<body>

  <!-- Background layers -->
  <div class="ic-login-bg">
    <div class="ic-orb ic-orb--gold"></div>
    <div class="ic-orb ic-orb--sky"></div>
    <div class="ic-orb ic-orb--plat"></div>
    <canvas id="ic-particle-canvas"></canvas>
  </div>

  <!-- Login card -->
  <div class="ic-login-wrap">
    <div class="ic-login-card" role="main">

      <!-- Corner accents -->
      <div class="ic-corner ic-corner--tl" aria-hidden="true"></div>
      <div class="ic-corner ic-corner--tr" aria-hidden="true"></div>
      <div class="ic-corner ic-corner--bl" aria-hidden="true"></div>
      <div class="ic-corner ic-corner--br" aria-hidden="true"></div>

      <!-- Brand -->
      <div class="ic-brand">
        <div class="ic-status-badge">
          <span class="ic-status-dot" aria-hidden="true"></span>
          System Active
        </div>
        <div class="ic-brand__claw-wrap">
          <div class="ic-brand__claw-glow" aria-hidden="true"></div>
          <svg class="ic-brand__claw-svg" width="72" height="72" viewBox="0 0 72 72" fill="none" aria-hidden="true" focusable="false">
            <defs>
              <linearGradient id="shieldGold" x1="0" y1="0" x2="72" y2="72" gradientUnits="userSpaceOnUse">
                <stop offset="0%" stop-color="#ffd700"/>
                <stop offset="40%" stop-color="#fff4b0"/>
                <stop offset="70%" stop-color="#c9a227"/>
                <stop offset="100%" stop-color="#ffd700"/>
              </linearGradient>
              <linearGradient id="shieldPlat" x1="72" y1="0" x2="0" y2="72" gradientUnits="userSpaceOnUse">
                <stop offset="0%" stop-color="#e8e6e8" stop-opacity="0.3"/>
                <stop offset="100%" stop-color="#a09bad" stop-opacity="0.1"/>
              </linearGradient>
              <filter id="shieldGlow">
                <feGaussianBlur in="SourceGraphic" stdDeviation="2.5" result="blur"/>
                <feComposite in="SourceGraphic" in2="blur" operator="over"/>
              </filter>
            </defs>
            <!-- Shield body -->
            <path d="M36 8 L16 18 L16 34 C16 48 36 58 36 58 C36 58 56 48 56 34 L56 18 Z"
                  fill="url(#shieldPlat)"
                  stroke="url(#shieldGold)"
                  stroke-width="1.8"
                  stroke-linejoin="round"
                  filter="url(#shieldGlow)"/>
            <!-- Claw mark -->
            <path d="M26 28 C26 28 30 32 36 36 C42 32 46 28 46 28"
                  stroke="url(#shieldGold)" stroke-width="2" stroke-linecap="round" fill="none" opacity="0.5"/>
            <!-- Check mark -->
            <path d="M27 36 L33 42 L46 29"
                  stroke="url(#shieldGold)"
                  stroke-width="2.2"
                  stroke-linecap="round"
                  stroke-linejoin="round"
                  fill="none"/>
            <!-- Scan lines inside shield -->
            <line x1="24" y1="31" x2="48" y2="31" stroke="rgba(255,215,0,0.15)" stroke-width="0.8"/>
            <line x1="22" y1="37" x2="50" y2="37" stroke="rgba(255,215,0,0.1)" stroke-width="0.8"/>
            <line x1="24" y1="43" x2="48" y2="43" stroke="rgba(255,215,0,0.08)" stroke-width="0.8"/>
          </svg>
        </div>
        <div class="ic-brand__name">IronClaw</div>
        <div class="ic-brand__tagline">Security Intelligence Platform</div>
      </div>

      <!-- Error message -->
      {ERROR_BLOCK}

      <!-- Login form -->
      <form
        method="POST"
        action="/login{NEXT_QUERY}"
        id="ic-login-form"
        novalidate
        autocomplete="on"
      >
        <input type="hidden" name="next" value="{NEXT_VALUE}">

        <div class="ic-form-group">
          <label class="ic-form-label" for="ic-api-key">Access Key</label>
          <div class="ic-input-wrap">
            <svg class="ic-input-icon" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
              <path d="M21 2L19 4M11 12A5 5 0 1 0 6 7a5 5 0 0 0 5 5zm0 0l3 3m0 0l3 3m-3-3l3-3m-3 3l-3 3"/>
            </svg>
            <input
              class="ic-form-input"
              type="password"
              id="ic-api-key"
              name="api_key"
              placeholder="Enter your API access key"
              autocomplete="current-password"
              spellcheck="false"
              required
              aria-required="true"
              aria-label="API access key"
            >
            <button
              type="button"
              class="ic-eye-toggle"
              id="ic-eye-toggle"
              aria-label="Show access key"
              title="Toggle visibility"
            >
              <svg id="ic-eye-icon" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/>
                <circle cx="12" cy="12" r="3"/>
              </svg>
            </button>
            <div class="ic-input-scan" aria-hidden="true"></div>
          </div>
        </div>

        <button
          type="submit"
          class="ic-btn-submit"
          id="ic-submit-btn"
          aria-label="Authenticate and access IronClaw dashboard"
        >
          <span class="ic-btn-text">Authenticate</span>
          <div class="ic-btn-spinner" role="status" aria-label="Authenticating..."></div>
        </button>
      </form>

      <div class="ic-divider" aria-hidden="true">Protected Access</div>

      <!-- Security strip -->
      <div class="ic-security-strip" aria-label="Security information">
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
          <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
          <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
        </svg>
        HMAC-signed session &nbsp;·&nbsp; HttpOnly cookie &nbsp;·&nbsp; TLS enforced
      </div>

    </div>
  </div>

  <script>
    (function () {
      'use strict';

      // ── Eye toggle ─────────────────────────────────────────────────────────
      var input     = document.getElementById('ic-api-key');
      var eyeBtn    = document.getElementById('ic-eye-toggle');
      var eyeIcon   = document.getElementById('ic-eye-icon');

      var EYE_OPEN   = '<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/>';
      var EYE_CLOSED = '<path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/>';

      if (eyeBtn && input) {
        eyeBtn.addEventListener('click', function () {
          var visible = input.type === 'text';
          input.type = visible ? 'password' : 'text';
          eyeIcon.innerHTML = visible ? EYE_OPEN : EYE_CLOSED;
          eyeBtn.setAttribute('aria-label', visible ? 'Show access key' : 'Hide access key');
        });
      }

      // ── Form submit — loading state ────────────────────────────────────────
      var form    = document.getElementById('ic-login-form');
      var submitBtn = document.getElementById('ic-submit-btn');

      if (form && submitBtn) {
        form.addEventListener('submit', function (e) {
          var key = input ? input.value.trim() : '';
          if (!key) {
            e.preventDefault();
            input && input.focus();
            return;
          }
          submitBtn.classList.add('ic-loading');
          submitBtn.disabled = true;
        });
      }

      // ── Particle canvas ────────────────────────────────────────────────────
      var canvas = document.getElementById('ic-particle-canvas');
      if (!canvas) return;
      var ctx = canvas.getContext('2d');
      var W, H, particles = [];

      function resize() {
        W = canvas.width  = window.innerWidth;
        H = canvas.height = window.innerHeight;
      }

      resize();
      window.addEventListener('resize', resize);

      var PARTICLE_COUNT = 55;

      function rand(min, max) { return min + Math.random() * (max - min); }

      function mkParticle() {
        var type = Math.random();
        return {
          x: rand(0, W),
          y: rand(0, H),
          r: rand(0.4, type < 0.6 ? 1.2 : 2.2),
          hue: type < 0.55 ? rand(42, 52) : type < 0.8 ? rand(195, 215) : rand(0, 360),
          sat: type < 0.55 ? rand(80, 100) : type < 0.8 ? rand(5, 20) : rand(60, 90),
          lum: type < 0.55 ? rand(65, 85) : type < 0.8 ? rand(75, 90) : rand(55, 75),
          alpha: rand(0.3, 0.9),
          vx: rand(-0.15, 0.15),
          vy: rand(-0.25, -0.05),
          life: rand(0, 1),
          lifeSpeed: rand(0.0015, 0.004),
          twinkle: rand(0, Math.PI * 2),
          twinkleSpeed: rand(0.01, 0.04),
        };
      }

      for (var i = 0; i < PARTICLE_COUNT; i++) { particles.push(mkParticle()); }

      function drawParticles() {
        ctx.clearRect(0, 0, W, H);
        for (var j = 0; j < particles.length; j++) {
          var p = particles[j];
          p.life += p.lifeSpeed;
          p.twinkle += p.twinkleSpeed;
          p.x += p.vx;
          p.y += p.vy;

          if (p.y < -5 || p.x < -5 || p.x > W + 5 || p.life > 1) {
            particles[j] = mkParticle();
            particles[j].y = H + 5;
            continue;
          }

          var fadeAlpha = p.alpha * Math.sin(Math.PI * p.life) * (0.7 + 0.3 * Math.sin(p.twinkle));
          if (fadeAlpha <= 0) continue;

          ctx.save();
          ctx.globalAlpha = fadeAlpha;

          if (p.r > 1.5) {
            var spikes = 4, outerR = p.r, innerR = p.r * 0.4;
            ctx.fillStyle = 'hsl(' + p.hue + ',' + p.sat + '%,' + p.lum + '%)';
            ctx.beginPath();
            for (var s = 0; s < spikes * 2; s++) {
              var angle = (s * Math.PI) / spikes + p.twinkle * 0.5;
              var radius = s % 2 === 0 ? outerR : innerR;
              if (s === 0) ctx.moveTo(p.x + radius * Math.cos(angle), p.y + radius * Math.sin(angle));
              else ctx.lineTo(p.x + radius * Math.cos(angle), p.y + radius * Math.sin(angle));
            }
            ctx.closePath();
            ctx.fill();

            ctx.shadowBlur = 8;
            ctx.shadowColor = 'hsl(' + p.hue + ',' + p.sat + '%,' + p.lum + '%)';
            ctx.fill();
          } else {
            ctx.fillStyle = 'hsl(' + p.hue + ',' + p.sat + '%,' + p.lum + '%)';
            ctx.shadowBlur = 4;
            ctx.shadowColor = 'hsl(' + p.hue + ',' + p.sat + '%,' + p.lum + '%)';
            ctx.beginPath();
            ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
            ctx.fill();
          }

          ctx.restore();
        }
        requestAnimationFrame(drawParticles);
      }

      var prefersReduced = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
      if (!prefersReduced) {
        requestAnimationFrame(drawParticles);
      }

      // ── Input — focus glow burst ───────────────────────────────────────────
      var keyInput = document.getElementById('ic-api-key');
      if (keyInput) {
        keyInput.addEventListener('focus', function () {
          spawnGoldSparks(6);
        });
      }

      function spawnGoldSparks(count) {
        if (prefersReduced) return;
        var rect = document.querySelector('.ic-login-card');
        if (!rect) return;
        var box = rect.getBoundingClientRect();
        var cx  = box.left + box.width / 2;
        var cy  = box.top + box.height / 2;

        for (var k = 0; k < count; k++) {
          (function(idx) {
            setTimeout(function () {
              var spark = document.createElement('div');
              spark.className = 'ic-spark';
              var size = rand(2, 5);
              var angle = rand(0, Math.PI * 2);
              var dist1 = rand(40, 80);
              var dist2 = rand(80, 160);
              var dur   = rand(900, 1600);
              spark.style.cssText = [
                'width:' + size + 'px',
                'height:' + size + 'px',
                'left:' + (cx + rand(-60,60)) + 'px',
                'top:' + (cy + rand(-80,80)) + 'px',
                'background:hsl(' + rand(42,55) + ',100%,' + rand(65,85) + '%)',
                'box-shadow:0 0 ' + (size*2) + 'px hsl(48,100%,70%)',
                '--sx:' + (Math.cos(angle)*dist1*0.3) + 'px',
                '--sy:' + (Math.sin(angle)*dist1*0.3) + 'px',
                '--ex:' + (Math.cos(angle)*dist2) + 'px',
                '--ey:' + (Math.sin(angle)*dist2) + 'px',
                'animation-duration:' + dur + 'ms',
              ].join(';');
              document.body.appendChild(spark);
              setTimeout(function () { spark.remove(); }, dur + 100);
            }, idx * 80);
          })(k);
        }
      }

    }());
  </script>

</body>
</html>
"""
)

# ── Route handlers ────────────────────────────────────────────────────────────


@router.get("/login", response_class=HTMLResponse)
async def login_get(
    request: Request,
    current_user: OptionalUser,
) -> HTMLResponse | RedirectResponse:
    """
    Render the login page.
    If the user is already authenticated, redirect straight to /dashboard.
    """
    if current_user is not None:
        next_path = request.query_params.get("next", "/dashboard")
        if not next_path.startswith("/") or next_path.startswith("//"):
            next_path = "/dashboard"
        return RedirectResponse(url=next_path, status_code=status.HTTP_303_SEE_OTHER)

    html = _render_login_html(error=None, next_value="")
    return HTMLResponse(content=html)


@router.post("/login", response_class=HTMLResponse)
async def login_post(
    request: Request,
    response: Response,
    api_key: Annotated[str, Form()] = "",
    next: Annotated[str, Form()] = "",
) -> HTMLResponse | RedirectResponse:
    """
    Validate the submitted API key.
    On success: write session cookie and redirect to ?next or /dashboard.
    On failure: re-render form with an error message.
    """
    next_path = next.strip() if next.strip() else "/dashboard"
    if not next_path.startswith("/") or next_path.startswith("//"):
        next_path = "/dashboard"

    user: CurrentUser | None = validate_api_key_login(api_key)

    if user is None:
        _log.warning(
            "login: authentication failed — ip=%s path=%s",
            request.client.host if request.client else "unknown",
            request.url.path,
        )
        html = _render_login_html(
            error="Invalid access key. Verify your credentials and try again.",
            next_value=next_path,
        )
        return HTMLResponse(content=html, status_code=status.HTTP_401_UNAUTHORIZED)

    _log.info(
        "login: authentication succeeded — user=%s roles=%s ip=%s",
        user.username,
        user.roles,
        request.client.host if request.client else "unknown",
    )

    redirect = RedirectResponse(url=next_path, status_code=status.HTTP_303_SEE_OTHER)
    set_session_cookie(redirect, user)
    return redirect


# ── HTML renderer ─────────────────────────────────────────────────────────────


def _render_login_html(*, error: str | None, next_value: str) -> str:
    """Inject dynamic values into the static login HTML template."""
    if error:
        error_block = (
            '<div class="ic-login-error" role="alert" aria-live="assertive">'
            '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" '
            'stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">'
            '<circle cx="12" cy="12" r="10"/>'
            '<line x1="12" y1="8" x2="12" y2="12"/>'
            '<line x1="12" y1="16" x2="12.01" y2="16"/>'
            "</svg>"
            f"<span>{_escape_html(error)}</span>"
            "</div>"
        )
    else:
        error_block = ""

    next_query = f"?next={_escape_html(next_value)}" if next_value and next_value != "/dashboard" else ""

    return _LOGIN_HTML.replace("{ERROR_BLOCK}", error_block).replace("{NEXT_QUERY}", next_query).replace("{NEXT_VALUE}", _escape_html(next_value))


def _escape_html(value: str) -> str:
    return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;").replace("'", "&#x27;")
