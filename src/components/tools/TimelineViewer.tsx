import { useState, useCallback } from "react";
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer } from "recharts";
import { buildTimeline, severityBg, severityColor, type ForensicTimelineEntry } from "@/utils/forensics";
import { readArtifactText } from "@/utils/analyzer";

const CATEGORIES = ["All", "Critical Event", "Suspicious Activity", "Attack Technique", "Reconnaissance", "Process Execution", "Persistence", "Registry Activity", "Authentication", "File Access", "Network", "General"];
const SEV_OPTS = ["all", "critical", "high", "medium", "low", "info"];
const TooltipStyle = { background: "var(--card)", border: "1px solid var(--border)", borderRadius: 4, fontSize: 12 };

export default function TimelineViewer() {
  const [isDragging, setIsDragging] = useState(false);
  const [timeline, setTimeline] = useState<ForensicTimelineEntry[]>([]);
  const [filename, setFilename] = useState("");
  const [filterCat, setFilterCat] = useState("All");
  const [filterSev, setFilterSev] = useState("all");
  const [loading, setLoading] = useState(false);
  const [search, setSearch] = useState("");
  const [error, setError] = useState("");

  const process = useCallback(async (file: File) => {
    setLoading(true);
    setError("");
    try {
      const text = await readArtifactText(file);
      if (text === null) {
        setTimeline([]);
        setFilename(file.name);
        setError("This artifact looks binary. Timeline reconstruction currently parses readable text and log files only.");
        return;
      }
      setTimeline(buildTimeline(text, file.name));
      setFilename(file.name);
    } catch (reason) {
      setTimeline([]);
      setError(reason instanceof Error ? reason.message : "The artifact could not be parsed.");
    } finally {
      setLoading(false);
    }
  }, []);

  const onDrop = (e: React.DragEvent) => {
    e.preventDefault(); setIsDragging(false);
    if (e.dataTransfer.files[0]) process(e.dataTransfer.files[0]);
  };

  const filtered = timeline.filter((t) =>
    (filterCat === "All" || t.category === filterCat) &&
    (filterSev === "all" || t.severity === filterSev) &&
    (!search || t.event.toLowerCase().includes(search.toLowerCase()) || t.category.toLowerCase().includes(search.toLowerCase()))
  );

  const hourlyData = Array.from({ length: 24 }, (_, h) => ({
    hour: `${String(h).padStart(2, "0")}h`,
    events: timeline.filter((t) => { const m = t.timestamp.match(/(\d{2}):\d{2}:\d{2}/); return m && parseInt(m[1]) === h; }).length,
  })).filter((d) => d.events > 0);

  const catData = CATEGORIES.slice(1).map((c) => ({
    name: c.replace(" Event", "").replace(" Activity", ""),
    count: timeline.filter((t) => t.category === c).length,
  })).filter((d) => d.count > 0);

  return (
    <div className="space-y-6">
      <div className="space-y-1">
        <h2 className="text-lg font-bold tracking-tight">Timeline Reconstruction</h2>
        <p className="text-sm" style={{ color: "var(--muted-foreground)" }}>
          Parse timestamped text and log lines into a chronological view. Categories and severities are assigned by local rules, not an event-log engine.
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
        onClick={() => document.getElementById("tl-input")?.click()}
      >
        <input id="tl-input" type="file" accept=".log,.txt,.csv" className="hidden"
          onChange={(e) => { if (e.target.files?.[0]) process(e.target.files[0]); e.target.value = ""; }} />
        <div className="flex flex-col items-center justify-center py-12 gap-2 select-none">
          <div className="text-sm font-medium">{loading ? "Building timeline…" : "Drop a log or CSV file"}</div>
          <div className="text-xs" style={{ color: "var(--muted-foreground)" }}>Parses several common timestamp shapes in readable text logs; event semantics are heuristic</div>
        </div>
      </div>

      {timeline.length > 0 && (
        <>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            {[
              { label: "Total Events", val: timeline.length, cls: "" },
              { label: "Critical", val: timeline.filter((t) => t.severity === "critical").length, cls: "text-red-400" },
              { label: "High", val: timeline.filter((t) => t.severity === "high").length, cls: "text-orange-400" },
              { label: "Categories", val: new Set(timeline.map((t) => t.category)).size, cls: "" },
            ].map((s) => (
              <div key={s.label} className="rounded p-4" style={{ border: "1px solid var(--border)", background: "var(--card)" }}>
                <div className={`text-2xl font-bold font-mono ${s.cls}`}>{s.val}</div>
                <div className="text-xs mt-1 uppercase tracking-wider" style={{ color: "var(--muted-foreground)" }}>{s.label}</div>
              </div>
            ))}
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="rounded p-4" style={{ border: "1px solid var(--border)", background: "var(--card)" }}>
              <div className="text-xs font-mono uppercase tracking-widest mb-4" style={{ color: "var(--muted-foreground)" }}>Activity by Hour</div>
              <ResponsiveContainer width="100%" height={150}>
                <BarChart data={hourlyData}>
                  <XAxis dataKey="hour" tick={{ fontSize: 9, fill: "var(--muted-foreground)" }} stroke="var(--border)" />
                  <YAxis tick={{ fontSize: 9, fill: "var(--muted-foreground)" }} stroke="var(--border)" />
                  <Tooltip contentStyle={TooltipStyle} />
                  <Bar dataKey="events" fill="var(--primary)" radius={[2, 2, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
            <div className="rounded p-4" style={{ border: "1px solid var(--border)", background: "var(--card)" }}>
              <div className="text-xs font-mono uppercase tracking-widest mb-4" style={{ color: "var(--muted-foreground)" }}>Events by Category</div>
              <ResponsiveContainer width="100%" height={150}>
                <BarChart data={catData} layout="vertical">
                  <XAxis type="number" tick={{ fontSize: 9, fill: "var(--muted-foreground)" }} stroke="var(--border)" />
                  <YAxis type="category" dataKey="name" tick={{ fontSize: 9, fill: "var(--muted-foreground)" }} width={110} stroke="var(--border)" />
                  <Tooltip contentStyle={TooltipStyle} />
                  <Bar dataKey="count" fill="#3b82f6" radius={[0, 2, 2, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>

          <div className="rounded overflow-hidden" style={{ border: "1px solid var(--border)", background: "var(--card)" }}>
            <div className="flex items-center gap-2 px-4 py-3 flex-wrap" style={{ borderBottom: "1px solid var(--border)" }}>
              <span className="font-mono text-xs" style={{ color: "var(--muted-foreground)" }}>{filename}</span>
              <div className="ml-auto flex items-center gap-2 flex-wrap">
                <input
                  className="text-xs rounded px-2 py-1 font-mono"
                  style={{ background: "var(--muted)", border: "1px solid var(--border)", color: "var(--foreground)", width: 160 }}
                  placeholder="Search events…"
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                />
                <select className="text-xs rounded px-2 py-1" style={{ background: "var(--muted)", border: "1px solid var(--border)", color: "var(--muted-foreground)" }} value={filterCat} onChange={(e) => setFilterCat(e.target.value)}>
                  {CATEGORIES.map((c) => <option key={c} value={c}>{c}</option>)}
                </select>
                <select className="text-xs rounded px-2 py-1" style={{ background: "var(--muted)", border: "1px solid var(--border)", color: "var(--muted-foreground)" }} value={filterSev} onChange={(e) => setFilterSev(e.target.value)}>
                  {SEV_OPTS.map((s) => <option key={s} value={s}>{s === "all" ? "All severities" : s[0].toUpperCase() + s.slice(1)}</option>)}
                </select>
                <span className="font-mono text-xs" style={{ color: "var(--muted-foreground)" }}>{filtered.length} events</span>
              </div>
            </div>

            <div className="max-h-[500px] overflow-y-auto">
              {filtered.length === 0
                ? <div className="px-5 py-8 text-sm text-center" style={{ color: "var(--muted-foreground)" }}>No events match current filters</div>
                : filtered.map((entry, i) => (
                  <div
                    key={i}
                    className="flex items-start gap-3 px-5 py-2.5 transition-colors"
                    style={{ borderBottom: "1px solid var(--border)" }}
                  >
                    <div className="font-mono text-xs w-40 shrink-0 pt-0.5" style={{ color: "var(--muted-foreground)" }}>{entry.timestamp}</div>
                    <div style={{ width: 3, minWidth: 3, alignSelf: "stretch", background: severityColor(entry.severity), borderRadius: 2, opacity: 0.7 }} />
                    <div className="min-w-0 flex-1">
                      <div className="text-xs font-mono mb-0.5" style={{ color: "var(--muted-foreground)" }}>{entry.category}</div>
                      <div className="text-xs break-all leading-relaxed">{entry.event.slice(0, 240)}</div>
                    </div>
                  </div>
                ))}
            </div>
          </div>
        </>
      )}
    </div>
  );
}
