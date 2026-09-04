import "@/App.css";
import { lazy, Suspense, useEffect, useRef } from "react";
import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import { Toaster } from "sonner";
import { AuthProvider } from "@/context/AuthContext";
import { useAuth } from "@/context/AuthContext";

const Landing = lazy(() => import("@/pages/Landing"));
const Dashboard = lazy(() => import("@/pages/Dashboard"));
const PromptInspector = lazy(() => import("@/pages/PromptInspector"));
const PolicyManager = lazy(() => import("@/pages/PolicyManager"));
const Privacy = lazy(() => import("@/pages/Privacy"));
const Terms = lazy(() => import("@/pages/Terms"));
const NotFound = lazy(() => import("@/pages/NotFound"));

const CounterProvider = ({ children }) => {
  const mountedRef = useRef(false);

  useEffect(() => {
    if (mountedRef.current) {
      return;
    }

    mountedRef.current = true;
    globalThis.__IC_COUNTERS__ = globalThis.__IC_COUNTERS__ || {};
    globalThis.__IC_COUNTERS__.__controllers =
      globalThis.__IC_COUNTERS__.__controllers || new Map();
    globalThis.__IC_COUNTERS__.__appMounted = true;
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
                <Route
                  path="/inspector"
                  element={
                    <PrivateRoute>
                      <PromptInspector />
                    </PrivateRoute>
                  }
                />
                <Route
                  path="/policies"
                  element={
                    <PrivateRoute>
                      <PolicyManager />
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
