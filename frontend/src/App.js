import "@/App.css";
import { lazy, Suspense, useEffect, useRef } from "react";
import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import { Toaster } from "sonner";
import { AuthProvider } from "@/context/AuthContext";
import { useAuth } from "@/context/AuthContext";

const Landing = lazy(() => import("@/pages/Landing"));
const Dashboard = lazy(() => import("@/pages/Dashboard"));
const Privacy = lazy(() => import("@/pages/Privacy"));
const Terms = lazy(() => import("@/pages/Terms"));
const NotFound = lazy(() => import("@/pages/NotFound"));

const isCounterSnapshot = (value) =>
  Boolean(
    value &&
    typeof value === "object" &&
    Number.isFinite(Number(value.value)) &&
    Number.isFinite(Number(value.updatedAt)),
  );

const isCounterController = (value) =>
  Boolean(
    value &&
    typeof value === "object" &&
    typeof value.getValue === "function" &&
    typeof value.subscribe === "function",
  );

const normalizeCounterEntry = (value) => {
  if (isCounterController(value)) {
    return value;
  }

  if (isCounterSnapshot(value)) {
    return {
      getValue: () => Number(value.value),
      subscribe: () => () => undefined,
    };
  }

  return null;
};

const CounterProvider = ({ children }) => {
  const mountedRef = useRef(false);

  useEffect(() => {
    if (mountedRef.current) {
      return;
    }

    mountedRef.current = true;
    const store = globalThis.__IC_COUNTERS__ || {};
    const existingRegistry = store.__controllers;
    const nextRegistry = new Map();

    if (existingRegistry instanceof Map) {
      for (const [key, value] of existingRegistry.entries()) {
        const normalized = normalizeCounterEntry(value);
        if (key && normalized) {
          nextRegistry.set(key, normalized);
        }
      }
    } else if (existingRegistry && typeof existingRegistry === "object") {
      Object.entries(existingRegistry).forEach(([key, value]) => {
        const normalized = normalizeCounterEntry(value);
        if (key && normalized) {
          nextRegistry.set(key, normalized);
        }
      });
    }

    Object.entries(store).forEach(([key, value]) => {
      if (key === "__controllers" || key === "__appMounted") {
        return;
      }

      const normalized = normalizeCounterEntry(value);
      if (normalized && !nextRegistry.has(key)) {
        nextRegistry.set(key, normalized);
      }

      if (key && !normalized && isCounterSnapshot(value)) {
        delete store[key];
      }
    });

    store.__controllers = nextRegistry;
    store.__appMounted = true;
    globalThis.__IC_COUNTERS__ = store;
  }, []);

  return children;
};

const PrivateRoute = ({ children }) => {
  const { user, session, loading } = useAuth();

  if (loading) {
    return (
      <div
        role="status"
        aria-live="polite"
        className="flex min-h-screen items-center justify-center bg-[#050607] text-[#BFC1C2]"
      >
        <span className="font-tech text-xs uppercase tracking-[0.28em] text-[#FFD700]">
          Loading
        </span>
      </div>
    );
  }

  return user || session ? children : <Navigate to="/" replace />;
};

const RouteFallback = () => (
  <div
    role="status"
    aria-live="polite"
    className="flex min-h-screen items-center justify-center bg-[#050607] text-[#BFC1C2]"
  >
    <span className="font-tech text-xs uppercase tracking-[0.28em] text-[#FFD700]">
      Loading
    </span>
  </div>
);

function App() {
  return (
    <div className="App">
      <BrowserRouter
        future={{
          v7_startTransition: true,
          v7_relativeSplatPath: true,
        }}
      >
        <CounterProvider>
          <AuthProvider>
            <Suspense fallback={<RouteFallback />}>
              <Routes>
                <Route path="/" element={<Landing />} />
                <Route
                  path="/dashboard"
                  element={
                    <PrivateRoute>
                      <Dashboard />
                    </PrivateRoute>
                  }
                />
                <Route path="/privacy" element={<Privacy />} />
                <Route path="/terms" element={<Terms />} />
                <Route path="*" element={<NotFound />} />
              </Routes>
            </Suspense>

            <Toaster
              theme="dark"
              position="top-right"
              toastOptions={{
                style: {
                  background: "rgba(10,11,13,0.9)",
                  border: "1px solid rgba(255,255,255,0.12)",
                  color: "#fff",
                  backdropFilter: "blur(12px)",
                },
              }}
            />
          </AuthProvider>
        </CounterProvider>
      </BrowserRouter>
    </div>
  );
}

export default App;
