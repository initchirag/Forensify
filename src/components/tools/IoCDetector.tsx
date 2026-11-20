import { useState, useCallback } from "react";
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, PieChart, Pie, Cell } from "recharts";
import { extractIoCs, detectIoAs, severityBg, type IoC, type IoA } from "@/utils/forensics";
import { readArtifactText } from "@/utils/analyzer";

const SEV_COLORS: Record<string, string> = {
  critical: "#ef4444", high: "#f97316", medium: "#eab308", low: "#22c55e",
};
const SEV_ORDER = ["critical", "high", "medium", "low"];

interface Result {
  filename: string;
  iocs: IoC[];
  ioas: IoA[];
}

const TooltipStyle = { background: "var(--card)", border: "1px solid var(--border)", borderRadius: 4, fontSize: 12 };

export default function IoCDetector() {
  const [isDragging, setIsDragging] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState<Result | null>(null);
  const [activeTab, setActiveTab] = useState<"ioc" | "ioa">("ioc");
  const [filterSev, setFilterSev] = useState("all");
  const [filterType, setFilterType] = useState("all");

  const analyze = useCallback(async (file: File) => {
    setLoading(true);
    setError("");
    try {
      const text = await readArtifactText(file);
      if (text === null) {
        setResult(null);
        setError("This artifact looks binary. Local IoC and technique rules currently scan readable text and log files only.");
        return;
      }
      setResult({ filename: file.name, iocs: extractIoCs(text), ioas: detectIoAs(text) });
    } catch (reason) {
      setResult(null);
      setError(reason instanceof Error ? reason.message : "The artifact could not be scanned.");
    } finally {
      setLoading(false);
    }
  }, []);

  const onDrop = (e: React.DragEvent) => {
    e.preventDefault(); setIsDragging(false);
    if (e.dataTransfer.files[0]) analyze(e.dataTransfer.files[0]);
  };

  const iocSevData = SEV_ORDER.map((s) => ({
    name: s[0].toUpperCase() + s.slice(1),
    count: result?.iocs.filter((i) => i.severity === s).length || 0,
    fill: SEV_COLORS[s],
  })).filter((d) => d.count > 0);

  const iocTypeData = result
    ? Object.entries(result.iocs.reduce<Record<string, number>>((a, i) => { a[i.type] = (a[i.type] || 0) + 1; return a; }, {}))
        .map(([name, count]) => ({ name, count })).sort((a, b) => b.count - a.count)
    : [];

  const iocTypes = result ? [...new Set(result.iocs.map((i) => i.type))] : [];

  const filteredIoCs = result?.iocs.filter((i) =>
    (filterSev === "all" || i.severity === filterSev) && (filterType === "all" || i.type === filterType)
  ) || [];

  const filteredIoAs = result?.ioas.filter((a) => filterSev === "all" || a.severity === filterSev) || [];

  const criticalCount = [...(result?.iocs || []), ...(result?.ioas || [])].filter((x) => x.severity === "critical").length;

  return (
    <div className="space-y-6">
      <div className="space-y-1">
        <h2 className="text-lg font-bold tracking-tight">Threat Detection</h2>
        <p className="text-sm" style={{ color: "var(--muted-foreground)" }}>
          Apply local text and log pattern rules to identify candidate indicators and map technique matches to MITRE ATT&CK. No reputation feed is queried.
        </p>
      </div>
      {error && <div role="alert" className="rounded p-3 text-sm" style={{ color: "#ef4444", border: "1px solid rgba(239,68,68,0.3)", background: "rgba(239,68,68,0.06)" }}>{error}</div>}

      <div
        className="rounded cursor-pointer transition-colors"
        style={{
          border: `2px dashed ${isDragging ? "var(--primary)" : "var(--border)"}`,
          background: isDragging ? "rgba(34,197,94,0.04)" : "var(--card)",
        }}
        onDragOver={(e) => { e.preventDefault(); setIsDragging(true); }}
        onDragLeave={() => setIsDragging(false)}
        onDrop={onDrop}
        onClick={() => document.getElementById("ioc-input")?.click()}
      >
        <input id="ioc-input" type="file" accept=".txt,.log,.csv,.json,.xml,.yaml,.yml,.md,.ps1" className="hidden" onChange={(e) => { if (e.target.files?.[0]) analyze(e.target.files[0]); e.target.value = ""; }} />
        <div className="flex flex-col items-center justify-center py-12 gap-2 select-none">
          <div className="text-sm font-medium">{loading ? "Scanning for threats…" : "Drop a log, text, or data file"}</div>
          <div className="text-xs" style={{ color: "var(--muted-foreground)" }}>
            Candidate extraction uses local heuristics; binary file strings and live reputation are not checked
          </div>
        </div>
      </div>

      {result && (
        <>
          {/* Summary bar */}
          <div className="rounded p-4 flex items-center gap-6" style={{ background: criticalCount > 0 ? "rgba(239,68,68,0.06)" : "var(--card)", border: `1px solid ${criticalCount > 0 ? "rgba(239,68,68,0.25)" : "var(--border)"}` }}>
            <div>
              <div className="font-mono font-black text-2xl" style={{ color: criticalCount > 0 ? "#ef4444" : "var(--foreground)" }}>{criticalCount}</div>
              <div className="text-xs" style={{ color: "var(--muted-foreground)" }}>Critical findings</div>
            </div>
            <div className="h-10 w-px" style={{ background: "var(--border)" }} />
            {[
              { l: "Indicators of Compromise", v: result.iocs.length },
              { l: "Attack Techniques", v: result.ioas.length },
              { l: "High severity", v: [...result.iocs, ...result.ioas].filter((x) => x.severity === "high").length },
            ].map((s) => (
              <div key={s.l}>
                <div className="font-mono font-bold text-base">{s.v}</div>
                <div className="text-xs" style={{ color: "var(--muted-foreground)" }}>{s.l}</div>
              </div>
            ))}
            <div className="ml-auto text-xs font-mono" style={{ color: "var(--muted-foreground)" }}>{result.filename}</div>
          </div>

          {/* Charts */}
          {(iocSevData.length > 0 || iocTypeData.length > 0) && (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="rounded p-4" style={{ border: "1px solid var(--border)", background: "var(--card)" }}>
                <div className="text-xs font-mono uppercase tracking-widest mb-4" style={{ color: "var(--muted-foreground)" }}>IoC Severity Distribution</div>
                <ResponsiveContainer width="100%" height={170}>
                  <PieChart>
                    <Pie data={iocSevData} dataKey="count" nameKey="name" cx="50%" cy="50%" outerRadius={62} innerRadius={30}>
                      {iocSevData.map((d, i) => <Cell key={i} fill={d.fill} />)}
                    </Pie>
                    <Tooltip contentStyle={TooltipStyle} />
                  </PieChart>
                </ResponsiveContainer>
                <div className="flex gap-3 flex-wrap mt-2">
                  {iocSevData.map((d) => (
                    <div key={d.name} className="flex items-center gap-1.5">
                      <div className="w-2 h-2 rounded-full" style={{ background: d.fill }} />
                      <span className="text-xs" style={{ color: "var(--muted-foreground)" }}>{d.name}: {d.count}</span>
                    </div>
                  ))}
                </div>
              </div>
              <div className="rounded p-4" style={{ border: "1px solid var(--border)", background: "var(--card)" }}>
                <div className="text-xs font-mono uppercase tracking-widest mb-4" style={{ color: "var(--muted-foreground)" }}>IoC by Type</div>
                <ResponsiveContainer width="100%" height={170}>
                  <BarChart data={iocTypeData.slice(0, 7)} layout="vertical">
                    <XAxis type="number" tick={{ fontSize: 10, fill: "var(--muted-foreground)" }} stroke="var(--border)" />
                    <YAxis type="category" dataKey="name" tick={{ fontSize: 9, fill: "var(--muted-foreground)" }} width={110} stroke="var(--border)" />
                    <Tooltip contentStyle={TooltipStyle} />
                    <Bar dataKey="count" fill="var(--primary)" radius={[0, 2, 2, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </div>
          )}

          {/* Tabs */}
          <div className="rounded overflow-hidden" style={{ border: "1px solid var(--border)", background: "var(--card)" }}>
            <div className="flex items-center" style={{ borderBottom: "1px solid var(--border)" }}>
              {(["ioc", "ioa"] as const).map((tab) => (
                <button
                  key={tab}
                  className="px-5 py-3 text-xs font-medium transition-colors"
                  style={{
                    borderBottom: `2px solid ${activeTab === tab ? "var(--primary)" : "transparent"}`,
                    color: activeTab === tab ? "var(--foreground)" : "var(--muted-foreground)",
                    marginBottom: -1,
                  }}
                  onClick={() => setActiveTab(tab)}
                >
                  {tab === "ioc" ? `Indicators of Compromise (${result.iocs.length})` : `Attack Techniques (${result.ioas.length})`}
                </button>
              ))}
              <div className="ml-auto flex items-center gap-2 px-3">
                {activeTab === "ioc" && (
                  <select className="text-xs rounded px-2 py-1" style={{ background: "var(--muted)", border: "1px solid var(--border)", color: "var(--muted-foreground)" }} value={filterType} onChange={(e) => setFilterType(e.target.value)}>
                    <option value="all">All types</option>
                    {iocTypes.map((t) => <option key={t} value={t}>{t}</option>)}
                  </select>
                )}
                <select className="text-xs rounded px-2 py-1" style={{ background: "var(--muted)", border: "1px solid var(--border)", color: "var(--muted-foreground)" }} value={filterSev} onChange={(e) => setFilterSev(e.target.value)}>
                  <option value="all">All severities</option>
                  {SEV_ORDER.map((s) => <option key={s} value={s}>{s[0].toUpperCase() + s.slice(1)}</option>)}
                </select>
              </div>
            </div>

            {activeTab === "ioc" && (
              <div className="divide-y max-h-96 overflow-y-auto" style={{ borderColor: "var(--border)" }}>
                {filteredIoCs.length === 0
                  ? <div className="px-5 py-8 text-sm text-center" style={{ color: "var(--muted-foreground)" }}>No indicators match current filters</div>
                  : filteredIoCs.map((ioc, i) => (
                    <div key={i} className="flex items-start gap-3 px-5 py-3" style={{ borderBottom: "1px solid var(--border)" }}>
                      <span className={`text-xs px-2 py-0.5 rounded border font-mono shrink-0 mt-0.5 ${severityBg(ioc.severity)}`}>{ioc.severity.slice(0, 4).toUpperCase()}</span>
                      <div className="min-w-0 flex-1">
                        <div className="text-xs font-mono" style={{ color: "var(--muted-foreground)" }}>{ioc.type}</div>
                        <div className="text-xs font-mono break-all mt-0.5">{ioc.value}</div>
                        <div className="text-xs mt-0.5" style={{ color: "var(--muted-foreground)" }}>{ioc.description}{ioc.confidence ? ` — ${ioc.confidence}% confidence` : ""}</div>
                      </div>
                    </div>
                  ))}
              </div>
            )}

            {activeTab === "ioa" && (
              <div className="divide-y max-h-96 overflow-y-auto" style={{ borderColor: "var(--border)" }}>
                {filteredIoAs.length === 0
                  ? <div className="px-5 py-8 text-sm text-center" style={{ color: "var(--muted-foreground)" }}>No attack techniques detected</div>
                  : filteredIoAs.map((ioa, i) => (
                    <div key={i} className="flex items-start gap-3 px-5 py-3" style={{ borderBottom: "1px solid var(--border)" }}>
                      <span className={`text-xs px-2 py-0.5 rounded border font-mono shrink-0 mt-0.5 ${severityBg(ioa.severity)}`}>{ioa.severity.slice(0, 4).toUpperCase()}</span>
                      <div className="min-w-0 flex-1">
                        <div className="flex items-center gap-2 flex-wrap">
                          <span className="text-xs font-bold">{ioa.technique}</span>
                          <span className="font-mono text-xs" style={{ color: "var(--primary)" }}>{ioa.mitreId}</span>
                          <span className="text-xs px-1.5 py-px rounded" style={{ background: "var(--muted)", color: "var(--muted-foreground)" }}>{ioa.tactic}</span>
                        </div>
                        <div className="text-xs mt-0.5" style={{ color: "var(--muted-foreground)" }}>
                          Evidence: {ioa.evidence.slice(0, 3).map((e) => `"${e.trim().slice(0, 40)}"`).join(", ")} · {ioa.confidence}% confidence
                        </div>
                      </div>
                    </div>
                  ))}
              </div>
            )}
          </div>
        </>
      )}
    </div>
  );
}
