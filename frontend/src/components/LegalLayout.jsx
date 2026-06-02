import { Link } from "react-router-dom";
import { ShieldCheck, ArrowLeft } from "lucide-react";

const LegalLayout = ({ title, updated, children, testid }) => {
  return (
    <div className="min-h-screen bg-[#050607] text-white">
      <nav className="sticky top-0 z-40 border-b border-white/10 bg-[#050607]/80 backdrop-blur-xl">
        <div className="mx-auto flex max-w-4xl items-center justify-between px-6 py-4">
          <Link
            to="/"
            className="flex items-center gap-2.5"
            data-testid="legal-logo"
          >
            <div className="flex h-9 w-9 items-center justify-center rounded-lg border border-[#FFD700]/30 bg-[#C9A84C]/10">
              <ShieldCheck className="text-[#FFD700]" size={20} />
            </div>
            <span className="font-tech text-base font-bold tracking-tight">
              IRONCLAW<span className="metal-gold-text">-SECURITY</span>
            </span>
          </Link>
          <Link
            to="/"
            data-testid="legal-back-btn"
            className="flex items-center gap-2 rounded-lg border border-white/15 px-4 py-2 text-sm text-[#BFC1C2] transition hover:border-white/40 hover:text-white"
          >
            <ArrowLeft size={15} /> Back home
          </Link>
        </div>
      </nav>

      <main className="mx-auto max-w-4xl px-6 py-14" data-testid={testid}>
        <h1 className="text-3xl font-bold tracking-tight sm:text-4xl">
          <span className="metal-gold-text">{title}</span>
        </h1>
        <p className="mt-2 font-tech text-xs uppercase tracking-widest text-[#737373]">
          Last updated: {updated}
        </p>

        <div className="legal-body mt-10 space-y-8 text-[#BFC1C2]">
          {children}
        </div>

        <div className="mt-14 border-t border-white/10 pt-8 text-center text-xs text-[#737373]">
          <p className="font-tech">
            &copy; 2026{" "}
            <span className="metal-gold-text">IronClaw-Security</span>. All
            rights reserved.
          </p>
        </div>
      </main>
    </div>
  );
};

export const Section = ({ heading, children }) => (
  <section>
    <h2 className="mb-3 text-lg font-semibold text-white">{heading}</h2>
    <div className="space-y-3 text-sm leading-relaxed">{children}</div>
  </section>
);

export default LegalLayout;
