import { useEffect, useState, useCallback } from "react";
import { useNavigate } from "react-router-dom";
import { Loader2, RefreshCw, Filter, X } from "lucide-react";
import { toast } from "sonner";
import { useAuth } from "@/context/AuthContext";
import { audit } from "@/lib/api";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

const VERDICTS = ["allow", "block"];
const PAGE_SIZE = 20;

// Legacy values remain styled for historical audit rows, not new filters.
const verdictVariant = (verdict) => {
  switch (verdict) {
    case "allow":
      return "secondary";
    case "warn":
      return "outline";
    case "quarantine":
      return "outline";
    case "block":
      return "destructive";
    default:
      return "outline";
  }
};

const verdictClass = (verdict) => {
  switch (verdict) {
    case "allow":
      return "text-green-600 border-green-400";
    case "warn":
      return "text-yellow-600 border-yellow-400";
    case "quarantine":
      return "text-orange-600 border-orange-400";
    case "block":
      return "text-red-600 border-red-400";
    default:
      return "";
  }
};

const AuditLog = () => {
  const { user, loading } = useAuth();
  const navigate = useNavigate();

  const [logs, setLogs] = useState([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [fetching, setFetching] = useState(false);

  const [verdict, setVerdict] = useState("all");
  const [agent, setAgent] = useState("");
  const [dateFrom, setDateFrom] = useState("");
  const [dateTo, setDateTo] = useState("");

  useEffect(() => {
    if (!loading && !user) navigate("/");
  }, [loading, user, navigate]);

  const buildParams = useCallback(
    (overridePage) => {
      const params = {
        page: overridePage ?? page,
        limit: PAGE_SIZE,
      };
      if (verdict && verdict !== "all") params.verdict = verdict;
      if (agent.trim()) params.agent = agent.trim();
      if (dateFrom) params.from = dateFrom;
      if (dateTo) params.to = dateTo;
      return params;
    },
    [page, verdict, agent, dateFrom, dateTo],
  );

  const fetchLogs = useCallback(
    async (overridePage) => {
      setFetching(true);
      try {
        const { data } = await audit.getLogs(buildParams(overridePage));
        setLogs(data.logs ?? data.items ?? data.results ?? []);
        setTotal(data.total ?? 0);
      } catch {
        toast.error("Failed to load audit logs.");
      } finally {
        setFetching(false);
      }
    },
    [buildParams],
  );

  useEffect(() => {
    if (user) fetchLogs(page);
  }, [user]); // eslint-disable-line react-hooks/exhaustive-deps

  const handleApplyFilters = () => {
    setPage(1);
    fetchLogs(1);
  };

  const handleClearFilters = () => {
    setVerdict("all");
    setAgent("");
    setDateFrom("");
    setDateTo("");
    setPage(1);
  };

  const handlePageChange = (next) => {
    setPage(next);
    fetchLogs(next);
  };

  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));

  return (
    <div className="min-h-screen bg-background text-foreground">
      <header className="sticky top-0 z-10 flex items-center justify-between border-b bg-background/80 backdrop-blur px-6 py-3">
        <div className="flex items-center gap-2">
          <span className="text-lg font-semibold tracking-tight">
            Audit Log
          </span>
          {total > 0 && (
            <Badge variant="secondary" className="text-xs">
              {total.toLocaleString()} entries
            </Badge>
          )}
        </div>
        <Button
          variant="ghost"
          size="sm"
          disabled={fetching}
          onClick={() => fetchLogs(page)}
          aria-label="Refresh audit logs"
        >
          <RefreshCw className={fetching ? "animate-spin" : ""} />
          Refresh
        </Button>
      </header>

      <main className="mx-auto max-w-7xl px-6 py-6 space-y-4">
        <section className="flex flex-wrap items-end gap-3 rounded-lg border bg-card p-4">
          <div className="flex items-center gap-1 text-sm text-muted-foreground">
            <Filter className="h-4 w-4" />
            Filters
          </div>

          <div className="flex flex-col gap-1">
            <label className="text-xs text-muted-foreground">Verdict</label>
            <Select value={verdict} onValueChange={setVerdict}>
              <SelectTrigger className="w-36">
                <SelectValue placeholder="All verdicts" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All verdicts</SelectItem>
                {VERDICTS.map((v) => (
                  <SelectItem key={v} value={v}>
                    {v.charAt(0).toUpperCase() + v.slice(1)}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          <div className="flex flex-col gap-1">
            <label className="text-xs text-muted-foreground">Agent</label>
            <Input
              className="w-44"
              placeholder="Agent ID or name"
              value={agent}
              onChange={(e) => setAgent(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && handleApplyFilters()}
            />
          </div>

          <div className="flex flex-col gap-1">
            <label className="text-xs text-muted-foreground">From</label>
            <Input
              type="date"
              className="w-36"
              value={dateFrom}
              onChange={(e) => setDateFrom(e.target.value)}
            />
          </div>

          <div className="flex flex-col gap-1">
            <label className="text-xs text-muted-foreground">To</label>
            <Input
              type="date"
              className="w-36"
              value={dateTo}
              onChange={(e) => setDateTo(e.target.value)}
            />
          </div>

          <div className="flex gap-2 ml-auto">
            <Button variant="outline" size="sm" onClick={handleClearFilters}>
              <X className="h-3.5 w-3.5" />
              Clear
            </Button>
            <Button size="sm" onClick={handleApplyFilters} disabled={fetching}>
              {fetching ? (
                <Loader2 className="animate-spin" />
              ) : (
                <Filter className="h-3.5 w-3.5" />
              )}
              Apply
            </Button>
          </div>
        </section>

        <div className="rounded-lg border bg-card overflow-hidden">
          {fetching && logs.length === 0 ? (
            <div className="flex items-center justify-center py-20 text-muted-foreground gap-2">
              <Loader2 className="animate-spin h-5 w-5" />
              Loading audit logs…
            </div>
          ) : logs.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-20 text-muted-foreground gap-2">
              <span className="text-4xl">🗂️</span>
              <p className="text-sm">
                No audit log entries match the current filters.
              </p>
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-[180px]">Timestamp</TableHead>
                  <TableHead>Agent</TableHead>
                  <TableHead>Event Type</TableHead>
                  <TableHead>Input Preview</TableHead>
                  <TableHead className="w-[110px]">Verdict</TableHead>
                  <TableHead>Reason</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {logs.map((log) => (
                  <TableRow key={log.id ?? log.log_id ?? log._id}>
                    <TableCell className="text-xs text-muted-foreground tabular-nums whitespace-nowrap">
                      {log.created_at
                        ? new Date(log.created_at).toLocaleString()
                        : log.timestamp
                          ? new Date(log.timestamp).toLocaleString()
                          : "—"}
                    </TableCell>
                    <TableCell className="text-xs font-mono max-w-[160px] truncate">
                      {log.agent_id ?? log.agent ?? "—"}
                    </TableCell>
                    <TableCell className="text-xs">
                      {log.event_type ?? log.type ?? "—"}
                    </TableCell>
                    <TableCell className="text-xs max-w-[280px] truncate text-muted-foreground">
                      {log.input_preview ?? log.prompt ?? log.content ?? "—"}
                    </TableCell>
                    <TableCell>
                      <Badge
                        variant={verdictVariant(log.verdict)}
                        className={`capitalize text-xs ${verdictClass(log.verdict)}`}
                      >
                        {log.verdict ?? "—"}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-xs max-w-[240px] truncate text-muted-foreground">
                      {log.reason ?? log.reasoning ?? "—"}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </div>

        {totalPages > 1 && (
          <div className="flex items-center justify-between text-sm text-muted-foreground">
            <span>
              Page {page} of {totalPages} · {total.toLocaleString()} total
            </span>
            <div className="flex gap-2">
              <Button
                variant="outline"
                size="sm"
                disabled={page <= 1 || fetching}
                onClick={() => handlePageChange(page - 1)}
              >
                Previous
              </Button>
              <Button
                variant="outline"
                size="sm"
                disabled={page >= totalPages || fetching}
                onClick={() => handlePageChange(page + 1)}
              >
                Next
              </Button>
            </div>
          </div>
        )}
      </main>
    </div>
  );
};

export default AuditLog;
