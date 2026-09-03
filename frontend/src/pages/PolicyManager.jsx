import { useEffect, useState, useCallback, useRef } from "react";
import { useNavigate } from "react-router-dom";
import {
  LogOut,
  Loader2,
  Plus,
  Pencil,
  Trash2,
  RefreshCw,
  X,
  Save,
  ShieldAlert,
  ToggleLeft,
  ToggleRight,
  ArrowLeft,
} from "lucide-react";
import { toast } from "sonner";
import { useAuth } from "@/context/AuthContext";
import { policies } from "@/lib/api";

// ── Policy field constants ────────────────────────────────────────────────────
const POLICY_ACTIONS = ["allow", "warn", "quarantine", "block"];
const POLICY_TYPES = [
  "prompt_injection",
  "data_exfiltration",
  "tool_abuse",
  "trust_escalation",
  "content_filter",
  "rate_limit",
  "custom",
];

const EMPTY_FORM = {
  name: "",
  description: "",
  policy_type: "custom",
  action: "block",
  pattern: "",
  enabled: true,
  priority: 50,
};

// ── Action badge colors ───────────────────────────────────────────────────────
const actionStyle = (action) => {
  switch (action) {
    case "allow":
      return {
        dot: "bg-[#22C55E]",
        text: "text-[#22C55E]",
        border: "border-[#22C55E]/30",
        bg: "bg-[#22C55E]/10",
      };
    case "warn":
      return {
        dot: "bg-[#FFD700]",
        text: "text-[#FFD700]",
        border: "border-[#FFD700]/30",
        bg: "bg-[#FFD700]/10",
      };
    case "quarantine":
      return {
        dot: "bg-[#F97316]",
        text: "text-[#F97316]",
        border: "border-[#F97316]/30",
        bg: "bg-[#F97316]/10",
      };
    case "block":
      return {
        dot: "bg-[#EF4444]",
        text: "text-[#EF4444]",
        border: "border-[#EF4444]/30",
        bg: "bg-[#EF4444]/10",
      };
    default:
      return {
        dot: "bg-white/40",
        text: "text-white/60",
        border: "border-white/20",
        bg: "bg-white/5",
      };
  }
};

// ── useEscapeKey ──────────────────────────────────────────────────────────────
const useEscapeKey = (handler) => {
  useEffect(() => {
    const onKey = (e) => {
      if (e.key === "Escape") handler();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [handler]);
};

// ── ActionBadge ───────────────────────────────────────────────────────────────
const ActionBadge = ({ action }) => {
  const s = actionStyle(action);
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 font-tech text-[10px] font-semibold uppercase tracking-wider ${s.bg} ${s.border} ${s.text}`}
    >
      <span className={`h-1.5 w-1.5 rounded-full ${s.dot}`} />
      {action}
    </span>
  );
};

// ── PolicyFormModal ───────────────────────────────────────────────────────────
const PolicyFormModal = ({ mode, initial, onSave, onClose, saving }) => {
  const [form, setForm] = useState(initial ?? EMPTY_FORM);
  const firstRef = useRef(null);

  useEffect(() => {
    firstRef.current?.focus();
  }, []);
  useEscapeKey(onClose);

  const set = useCallback(
    (field, value) => setForm((prev) => ({ ...prev, [field]: value })),
    [],
  );

  const handleSubmit = (e) => {
    e.preventDefault();
    if (!form.name.trim()) {
      toast.error("Policy name is required.");
      return;
    }
    if (!form.pattern.trim()) {
      toast.error("Pattern / rule is required.");
      return;
    }
    onSave(form);
  };

  const inputCls =
    "w-full rounded-xl border border-white/10 bg-white/5 px-4 py-2.5 font-tech text-sm text-white placeholder-[#3a3a3a] outline-none transition focus:border-[#FFD700]/40 focus:bg-white/[0.07] disabled:opacity-50";
  const labelCls =
    "block mb-1.5 text-xs uppercase tracking-widest text-[#BFC1C2]";

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm px-4"
      role="dialog"
      aria-modal="true"
      aria-label={mode === "create" ? "Create policy" : "Edit policy"}
    >
      <div className="relative w-full max-w-xl rounded-2xl border border-white/10 bg-[#0d0f11] p-6 shadow-2xl">
        <div className="mb-5 flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <div className="flex h-8 w-8 items-center justify-center rounded-lg border border-[#FFD700]/30 bg-[#C9A84C]/10">
              <ShieldAlert size={16} className="text-[#FFD700]" />
            </div>
            <span className="font-tech text-base font-semibold">
              {mode === "create" ? "New Policy" : "Edit Policy"}
            </span>
          </div>
          <button
            onClick={onClose}
            className="rounded-lg p-1 text-[#BFC1C2] transition hover:bg-white/10 hover:text-white"
            aria-label="Close modal"
          >
            <X size={18} />
          </button>
        </div>

        <form onSubmit={handleSubmit} className="flex flex-col gap-4">
          <div>
            <label className={labelCls}>Policy Name *</label>
            <input
              ref={firstRef}
              type="text"
              className={inputCls}
              placeholder="e.g. Block Prompt Injection Patterns"
              value={form.name}
              onChange={(e) => set("name", e.target.value)}
              maxLength={120}
              required
            />
          </div>

          <div>
            <label className={labelCls}>
              Description{" "}
              <span className="normal-case tracking-normal text-[#737373]">
                (optional)
              </span>
            </label>
            <textarea
              className={`${inputCls} resize-none`}
              rows={2}
              placeholder="What does this policy enforce?"
              value={form.description}
              onChange={(e) => set("description", e.target.value)}
              maxLength={500}
            />
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className={labelCls}>Policy Type</label>
              <select
                className={inputCls}
                value={form.policy_type}
                onChange={(e) => set("policy_type", e.target.value)}
              >
                {POLICY_TYPES.map((t) => (
                  <option key={t} value={t} className="bg-[#0d0f11]">
                    {t.replace(/_/g, " ")}
                  </option>
                ))}
              </select>
            </div>
            <div>
              <label className={labelCls}>Action</label>
              <select
                className={inputCls}
                value={form.action}
                onChange={(e) => set("action", e.target.value)}
              >
                {POLICY_ACTIONS.map((a) => (
                  <option key={a} value={a} className="bg-[#0d0f11]">
                    {a.charAt(0).toUpperCase() + a.slice(1)}
                  </option>
                ))}
              </select>
            </div>
          </div>

          <div>
            <label className={labelCls}>Pattern / Rule *</label>
            <textarea
              className={`${inputCls} resize-none`}
              rows={3}
              placeholder="Regex, keyword list, or rule expression enforced by this policy…"
              value={form.pattern}
              onChange={(e) => set("pattern", e.target.value)}
              required
            />
          </div>

          <div className="grid grid-cols-2 gap-4 items-end">
            <div>
              <label className={labelCls}>
                Priority{" "}
                <span className="normal-case tracking-normal text-[#737373]">
                  (1&#8211;100, lower = higher priority)
                </span>
              </label>
              <input
                type="number"
                min={1}
                max={100}
                className={inputCls}
                value={form.priority}
                onChange={(e) =>
                  set(
                    "priority",
                    Math.min(100, Math.max(1, Number(e.target.value) || 50)),
                  )
                }
              />
            </div>
            <div className="flex items-center gap-3 pb-1">
              <span className="text-xs uppercase tracking-widest text-[#BFC1C2]">
                Enabled
              </span>
              <button
                type="button"
                onClick={() => set("enabled", !form.enabled)}
                aria-label={form.enabled ? "Disable policy" : "Enable policy"}
                className="transition hover:opacity-80"
              >
                {form.enabled ? (
                  <ToggleRight size={28} className="text-[#22C55E]" />
                ) : (
                  <ToggleLeft size={28} className="text-[#737373]" />
                )}
              </button>
              <span
                className={`font-tech text-xs font-semibold ${form.enabled ? "text-[#22C55E]" : "text-[#737373]"}`}
              >
                {form.enabled ? "On" : "Off"}
              </span>
            </div>
          </div>

          <div className="mt-2 flex items-center justify-end gap-3 border-t border-white/8 pt-4">
            <button
              type="button"
              onClick={onClose}
              className="rounded-xl border border-white/15 px-5 py-2.5 text-sm text-[#BFC1C2] transition hover:border-white/30 hover:text-white"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={saving}
              className="btn-shimmer flex items-center gap-2 rounded-xl border border-[#FFD700]/30 bg-[#C9A84C]/15 px-6 py-2.5 text-sm font-semibold text-[#FFD700] transition hover:border-[#FFD700]/60 hover:bg-[#C9A84C]/25 disabled:cursor-not-allowed disabled:opacity-50"
            >
              {saving ? (
                <Loader2 size={15} className="animate-spin" />
              ) : (
                <Save size={15} />
              )}
              {mode === "create" ? "Create Policy" : "Save Changes"}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};

// ── DeleteConfirmModal ────────────────────────────────────────────────────────
const DeleteConfirmModal = ({ policy, onConfirm, onClose, deleting }) => {
  useEscapeKey(onClose);

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm px-4"
      role="dialog"
      aria-modal="true"
      aria-label="Confirm delete policy"
    >
      <div className="w-full max-w-md rounded-2xl border border-[#EF4444]/20 bg-[#0d0f11] p-6 shadow-2xl">
        <div className="mb-4 flex items-center gap-3">
          <div className="flex h-9 w-9 items-center justify-center rounded-full border border-[#EF4444]/30 bg-[#EF4444]/10">
            <Trash2 size={18} className="text-[#EF4444]" />
          </div>
          <span className="font-tech font-semibold">Delete Policy</span>
        </div>
        <p className="mb-1 text-sm text-[#BFC1C2]">
          Permanently delete{" "}
          <span className="font-tech font-semibold text-white">
            &quot;{policy.name}&quot;
          </span>
          ?
        </p>
        <p className="text-xs text-[#737373]">
          This action cannot be undone and will immediately remove the policy
          from IronClaw&apos;s enforcement layer.
        </p>
        <div className="mt-6 flex justify-end gap-3">
          <button
            onClick={onClose}
            className="rounded-xl border border-white/15 px-5 py-2.5 text-sm text-[#BFC1C2] transition hover:border-white/30 hover:text-white"
          >
            Cancel
          </button>
          <button
            onClick={onConfirm}
            disabled={deleting}
            className="flex items-center gap-2 rounded-xl border border-[#EF4444]/40 bg-[#EF4444]/10 px-6 py-2.5 text-sm font-semibold text-[#EF4444] transition hover:border-[#EF4444]/70 hover:bg-[#EF4444]/20 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {deleting ? (
              <Loader2 size={15} className="animate-spin" />
            ) : (
              <Trash2 size={15} />
            )}
            Delete
          </button>
        </div>
      </div>
    </div>
  );
};

// ── normalizePolicyList ───────────────────────────────────────────────────────
const normalizePolicyList = (data) =>
  Array.isArray(data)
    ? data
    : (data?.policies ?? data?.items ?? data?.results ?? []);

// ── PolicyManager (main page) ─────────────────────────────────────────────────
const PolicyManager = () => {
  const { user, logout } = useAuth();
  const navigate = useNavigate();

  const [policyList, setPolicyList] = useState([]);
  const [fetching, setFetching] = useState(false);
  const [modal, setModal] = useState(null);
  const [deleteTarget, setDeleteTarget] = useState(null);
  const [saving, setSaving] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [searchQuery, setSearchQuery] = useState("");
  const [filterAction, setFilterAction] = useState("all");
  const [filterEnabled, setFilterEnabled] = useState("all");

  const fetchPolicies = useCallback(async () => {
    setFetching(true);
    try {
      const { data } = await policies.list();
      setPolicyList(normalizePolicyList(data));
    } catch {
      toast.error("Failed to load policies.");
    } finally {
      setFetching(false);
    }
  }, []);

  useEffect(() => {
    if (user) fetchPolicies();
  }, [user, fetchPolicies]);

  const handleCreate = useCallback(async (formData) => {
    setSaving(true);
    try {
      const { data } = await policies.create(formData);
      setPolicyList((prev) => [data, ...prev]);
      toast.success("Policy created.");
      setModal(null);
    } catch (err) {
      toast.error(err?.response?.data?.detail || "Failed to create policy.");
    } finally {
      setSaving(false);
    }
  }, []);

  const handleUpdate = useCallback(
    async (formData) => {
      if (!modal?.policy?.id) return;
      setSaving(true);
      try {
        const { data } = await policies.update(modal.policy.id, formData);
        setPolicyList((prev) =>
          prev.map((p) => (p.id === modal.policy.id ? data : p)),
        );
        toast.success("Policy updated.");
        setModal(null);
      } catch (err) {
        toast.error(err?.response?.data?.detail || "Failed to update policy.");
      } finally {
        setSaving(false);
      }
    },
    [modal?.policy?.id],
  );

  const handleDelete = useCallback(async () => {
    if (!deleteTarget?.id) return;
    setDeleting(true);
    try {
      await policies.delete(deleteTarget.id);
      setPolicyList((prev) => prev.filter((p) => p.id !== deleteTarget.id));
      toast.success("Policy deleted.");
      setDeleteTarget(null);
    } catch (err) {
      toast.error(err?.response?.data?.detail || "Failed to delete policy.");
    } finally {
      setDeleting(false);
    }
  }, [deleteTarget?.id]);

  const handleToggleEnabled = useCallback(async (policy) => {
    const next = !policy.enabled;
    setPolicyList((prev) =>
      prev.map((p) => (p.id === policy.id ? { ...p, enabled: next } : p)),
    );
    try {
      const { data } = await policies.update(policy.id, {
        ...policy,
        enabled: next,
      });
      setPolicyList((prev) => prev.map((p) => (p.id === policy.id ? data : p)));
      toast.success(next ? "Policy enabled." : "Policy disabled.");
    } catch (err) {
      setPolicyList((prev) =>
        prev.map((p) =>
          p.id === policy.id ? { ...p, enabled: policy.enabled } : p,
        ),
      );
      toast.error(err?.response?.data?.detail || "Failed to toggle policy.");
    }
  }, []);

  const handleSignOut = useCallback(() => {
    logout();
    navigate("/");
  }, [logout, navigate]);

  const visiblePolicies = policyList.filter((p) => {
    const q = searchQuery.toLowerCase();
    const matchSearch =
      !q ||
      (p.name ?? "").toLowerCase().includes(q) ||
      (p.description ?? "").toLowerCase().includes(q) ||
      (p.policy_type ?? "").toLowerCase().includes(q) ||
      (p.pattern ?? "").toLowerCase().includes(q);
    const matchAction = filterAction === "all" || p.action === filterAction;
    const matchEnabled =
      filterEnabled === "all" ||
      (filterEnabled === "enabled" && p.enabled) ||
      (filterEnabled === "disabled" && !p.enabled);
    return matchSearch && matchAction && matchEnabled;
  });

  const clearFilters = useCallback(() => {
    setSearchQuery("");
    setFilterAction("all");
    setFilterEnabled("all");
  }, []);

  const hasActiveFilters =
    searchQuery || filterAction !== "all" || filterEnabled !== "all";

  const handleModalSave = useCallback(
    (formData) => {
      if (modal?.mode === "create") handleCreate(formData);
      else handleUpdate(formData);
    },
    [modal?.mode, handleCreate, handleUpdate],
  );

  const closeModal = useCallback(() => {
    if (!saving) setModal(null);
  }, [saving]);

  const closeDelete = useCallback(() => {
    if (!deleting) setDeleteTarget(null);
  }, [deleting]);

  const editInitial =
    modal?.mode === "edit"
      ? {
          name: modal.policy.name ?? "",
          description: modal.policy.description ?? "",
          policy_type: modal.policy.policy_type ?? "custom",
          action: modal.policy.action ?? "block",
          pattern: modal.policy.pattern ?? "",
          enabled: modal.policy.enabled ?? true,
          priority: modal.policy.priority ?? 50,
        }
      : EMPTY_FORM;

  return (
    <div className="min-h-screen bg-[#050607] text-white">
      <nav className="sticky top-0 z-40 border-b border-white/10 bg-[#050607]/80 backdrop-blur-xl">
        <div className="mx-auto flex max-w-7xl items-center justify-between gap-3 px-6 py-4">
          <div className="flex items-center gap-3">
            <button
              onClick={() => navigate("/dashboard")}
              className="inline-flex items-center gap-2 rounded-lg border border-white/10 bg-white/5 px-3 py-2 text-sm text-[#BFC1C2] transition hover:border-[#FFD700]/50 hover:text-white"
              data-testid="policy-back-btn"
              aria-label="Back to dashboard"
            >
              <ArrowLeft size={16} />
              Back
            </button>
            <button
              onClick={() => navigate("/dashboard")}
              className="flex items-center gap-2.5"
              data-testid="policy-manager-logo"
              aria-label="Back to Control Room"
            >
              <img
                src="/images/Golden%20Knight%20Logo128.png"
                alt="IronClaw-Security"
                className="brand-logo-image"
                loading="eager"
                decoding="async"
              />
              <span className="font-tech text-lg font-bold tracking-tight">
                IRONCLAW<span className="metal-gold-text">-SECURITY</span>
              </span>
            </button>
          </div>
          <div className="flex items-center gap-4">
            <span className="font-tech hidden text-sm text-[#BFC1C2] sm:block">
              {user?.email}
            </span>
            <button
              onClick={handleSignOut}
              data-testid="policy-manager-signout-btn"
              className="flex items-center gap-2 rounded-lg border border-white/15 px-4 py-2 text-sm text-white/90 transition hover:border-[#EF4444]/50 hover:text-[#EF4444]"
            >
              <LogOut size={16} /> Sign Out
            </button>
          </div>
        </div>
      </nav>

      <main className="mx-auto max-w-7xl px-6 py-8">
        <div className="mb-7 flex flex-col gap-4 sm:flex-row sm:items-end sm:justify-between">
          <div>
            <h1 className="text-2xl font-semibold tracking-tight sm:text-3xl">
              Policy Manager
            </h1>
            <p className="mt-1 text-sm text-[#BFC1C2]">
              Define, enable, and enforce security policies across
              IronClaw&apos;s inspection and verdict layer.
            </p>
          </div>
          <div className="flex items-center gap-3 shrink-0">
            <button
              onClick={fetchPolicies}
              disabled={fetching}
              data-testid="policy-refresh-btn"
              className="flex items-center gap-2 rounded-lg border border-white/15 px-4 py-2 text-sm text-[#BFC1C2] transition hover:text-white disabled:opacity-50"
              aria-label="Refresh policies"
            >
              <RefreshCw size={15} className={fetching ? "animate-spin" : ""} />
              Refresh
            </button>
            <button
              onClick={() => setModal({ mode: "create" })}
              data-testid="create-policy-btn"
              className="btn-shimmer flex items-center gap-2 rounded-lg border border-[#FFD700]/30 bg-[#C9A84C]/15 px-4 py-2 text-sm font-semibold text-[#FFD700] transition hover:border-[#FFD700]/60 hover:bg-[#C9A84C]/25"
            >
              <Plus size={16} /> New Policy
            </button>
          </div>
        </div>

        <div className="mb-5 flex flex-wrap items-center gap-3 rounded-xl border border-white/8 bg-white/[0.03] px-4 py-3">
          <div className="relative flex-1 min-w-[180px]">
            <input
              type="text"
              className="w-full rounded-lg border border-white/10 bg-white/5 px-3 py-2 font-tech text-sm text-white placeholder-[#3a3a3a] outline-none transition focus:border-[#FFD700]/40 focus:bg-white/[0.07]"
              placeholder="Search policies…"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              data-testid="policy-search-input"
            />
          </div>

          <select
            className="rounded-lg border border-white/10 bg-[#0d0f11] px-3 py-2 font-tech text-sm text-white outline-none transition focus:border-[#FFD700]/40"
            value={filterAction}
            onChange={(e) => setFilterAction(e.target.value)}
            data-testid="policy-action-filter"
          >
            <option value="all" className="bg-[#0d0f11]">
              All actions
            </option>
            {POLICY_ACTIONS.map((a) => (
              <option key={a} value={a} className="bg-[#0d0f11]">
                {a.charAt(0).toUpperCase() + a.slice(1)}
              </option>
            ))}
          </select>

          <select
            className="rounded-lg border border-white/10 bg-[#0d0f11] px-3 py-2 font-tech text-sm text-white outline-none transition focus:border-[#FFD700]/40"
            value={filterEnabled}
            onChange={(e) => setFilterEnabled(e.target.value)}
            data-testid="policy-enabled-filter"
          >
            <option value="all" className="bg-[#0d0f11]">
              All statuses
            </option>
            <option value="enabled" className="bg-[#0d0f11]">
              Enabled
            </option>
            <option value="disabled" className="bg-[#0d0f11]">
              Disabled
            </option>
          </select>

          {hasActiveFilters && (
            <button
              onClick={clearFilters}
              className="flex items-center gap-1.5 rounded-lg border border-white/15 px-3 py-2 text-xs text-[#BFC1C2] transition hover:border-white/30 hover:text-white"
            >
              <X size={13} /> Clear
            </button>
          )}

          <span className="ml-auto font-tech text-xs text-[#737373]">
            {visiblePolicies.length} / {policyList.length} policies
          </span>
        </div>

        {fetching && policyList.length === 0 ? (
          <div className="flex items-center justify-center py-24 text-[#737373] gap-2">
            <Loader2 className="animate-spin h-5 w-5" />
            <span className="font-tech text-sm">Loading policies…</span>
          </div>
        ) : visiblePolicies.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-24 text-[#737373] gap-3">
            <div className="flex h-14 w-14 items-center justify-center rounded-full border border-white/8 bg-white/[0.03]">
              <ShieldAlert size={26} className="text-[#737373]" />
            </div>
            <p className="font-tech text-sm">
              {policyList.length === 0
                ? "No policies yet. Create your first enforcement policy."
                : "No policies match your current filters."}
            </p>
            {policyList.length === 0 && (
              <button
                onClick={() => setModal({ mode: "create" })}
                className="btn-shimmer mt-1 flex items-center gap-2 rounded-lg border border-[#FFD700]/30 bg-[#C9A84C]/15 px-5 py-2.5 text-sm font-semibold text-[#FFD700] transition hover:border-[#FFD700]/60 hover:bg-[#C9A84C]/25"
              >
                <Plus size={15} /> New Policy
              </button>
            )}
          </div>
        ) : (
          <div className="flex flex-col gap-3" data-testid="policy-list">
            {visiblePolicies.map((policy) => (
              <div
                key={policy.id}
                data-testid={`policy-row-${policy.id}`}
                className={`glass-platinum group relative rounded-xl border p-4 transition ${
                  policy.enabled
                    ? "border-white/10 hover:border-white/20"
                    : "border-white/5 opacity-60 hover:opacity-80"
                }`}
              >
                <div className="flex flex-wrap items-start justify-between gap-3">
                  <div className="flex-1 min-w-0">
                    <div className="flex flex-wrap items-center gap-2 mb-1">
                      <span className="font-tech text-sm font-semibold text-white truncate">
                        {policy.name}
                      </span>
                      <ActionBadge action={policy.action} />
                      <span className="rounded-full border border-white/12 bg-white/5 px-2 py-0.5 font-tech text-[10px] text-[#BFC1C2]">
                        {(policy.policy_type ?? "custom").replace(/_/g, " ")}
                      </span>
                      <span className="font-tech text-[10px] text-[#737373]">
                        priority {policy.priority ?? "—"}
                      </span>
                    </div>
                    {policy.description && (
                      <p className="mt-0.5 text-xs text-[#BFC1C2] line-clamp-1">
                        {policy.description}
                      </p>
                    )}
                    {policy.pattern && (
                      <p className="mt-1.5 rounded-lg border border-white/8 bg-black/30 px-3 py-1.5 font-tech text-[11px] text-[#BFC1C2] break-all line-clamp-2">
                        {policy.pattern}
                      </p>
                    )}
                  </div>

                  <div className="flex items-center gap-2 shrink-0">
                    <button
                      onClick={() => handleToggleEnabled(policy)}
                      aria-label={
                        policy.enabled ? "Disable policy" : "Enable policy"
                      }
                      className="transition hover:opacity-80"
                      data-testid={`toggle-policy-${policy.id}`}
                    >
                      {policy.enabled ? (
                        <ToggleRight size={24} className="text-[#22C55E]" />
                      ) : (
                        <ToggleLeft size={24} className="text-[#737373]" />
                      )}
                    </button>
                    <button
                      onClick={() => setModal({ mode: "edit", policy })}
                      aria-label="Edit policy"
                      data-testid={`edit-policy-${policy.id}`}
                      className="rounded-lg border border-white/10 p-2 text-[#BFC1C2] transition hover:border-[#FFD700]/40 hover:bg-[#C9A84C]/10 hover:text-[#FFD700]"
                    >
                      <Pencil size={15} />
                    </button>
                    <button
                      onClick={() => setDeleteTarget(policy)}
                      aria-label="Delete policy"
                      data-testid={`delete-policy-${policy.id}`}
                      className="rounded-lg border border-white/10 p-2 text-[#BFC1C2] transition hover:border-[#EF4444]/40 hover:bg-[#EF4444]/10 hover:text-[#EF4444]"
                    >
                      <Trash2 size={15} />
                    </button>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </main>

      {modal && (
        <PolicyFormModal
          mode={modal.mode}
          initial={editInitial}
          onSave={handleModalSave}
          onClose={closeModal}
          saving={saving}
        />
      )}

      {deleteTarget && (
        <DeleteConfirmModal
          policy={deleteTarget}
          onConfirm={handleDelete}
          onClose={closeDelete}
          deleting={deleting}
        />
      )}
    </div>
  );
};

export default PolicyManager;
