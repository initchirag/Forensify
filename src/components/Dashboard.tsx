import { useCallback, useRef, useState } from "react";
import { Area, AreaChart, Bar, BarChart, CartesianGrid, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { analyzeArtifact, type ArtifactAnalysis } from "@/utils/analyzer";
import { severityBg, severityColor } from "@/utils/forensics";

const severityOrder = ["critical", "high", "medium", "low"] as const;
const chartTooltip = {
  contentStyle: { background: "var(--card)", border: "1px solid var(--border)", borderRadius: 8, color: "var(--foreground)", fontSize: 12 },
  cursor: { fill: "var(--muted)", opacity: 0.6 },
};

function riskLabel(score: number): string {
  if (score >= 70) return "High signal";
  if (score >= 40) return "Review";
  if (score >= 20) return "Low signal";
  return "No signals";
}

function StatCard({ label, value, note, accent }: { label: string; value: string | number; note: string; accent?: string }) {
  return (
    <div className="rounded-xl p-4 sm:p-5" style={{ background: "var(--card)", border: "1px solid var(--border)" }}>
      <div className="text-xs font-medium" style={{ color: "var(--muted-foreground)" }}>{label}</div>
      <div className="font-mono text-2xl sm:text-3xl font-semibold mt-3 tracking-tight" style={{ color: accent || "var(--foreground)" }}>{value}</div>
      <div className="text-xs mt-1.5" style={{ color: "var(--muted-foreground)" }}>{note}</div>
    </div>
  );
}

function FindingsChart({ analysis }: { analysis: ArtifactAnalysis }) {
  const findings = [...analysis.iocs, ...analysis.ioas];
  const counts = severityOrder.map((severity) => ({
    severity,
    count: findings.filter((finding) => finding.severity === severity).length,
    color: severityColor(severity),
  }));

  return (
    <div className="rounded-xl p-5" style={{ background: "var(--card)", border: "1px solid var(--border)" }}>
      <div className="flex items-start justify-between gap-3 mb-5">
        <div>
          <h3 className="text-sm font-semibold">Finding distribution</h3>
          <p className="text-xs mt-1" style={{ color: "var(--muted-foreground)" }}>Rule-based matches by heuristic severity</p>
        </div>
        <span className="text-xs font-mono px-2 py-1 rounded-md" style={{ color: "var(--muted-foreground)", background: "var(--muted)" }}>
          {findings.length} total
        </span>
      </div>
      <ResponsiveContainer width="100%" height={190}>
        <BarChart data={counts} margin={{ top: 8, right: 4, left: -22, bottom: 0 }}>
          <CartesianGrid vertical={false} stroke="var(--border)" strokeDasharray="3 4" />
          <XAxis dataKey="severity" tick={{ fontSize: 10, fill: "var(--muted-foreground)" }} tickFormatter={(value: string) => value[0].toUpperCase() + value.slice(1)} axisLine={false} tickLine={false} />
          <YAxis allowDecimals={false} width={34} tick={{ fontSize: 10, fill: "var(--muted-foreground)" }} axisLine={false} tickLine={false} />
          <Tooltip {...chartTooltip} />
          <Bar dataKey="count" name="Matched findings" radius={[4, 4, 0, 0]}>
            {counts.map((entry) => <Cell key={entry.severity} fill={entry.color} />)}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
      <p className="text-[11px] leading-relaxed mt-5 pt-4" style={{ borderTop: "1px solid var(--border)", color: "var(--muted-foreground)" }}>
        Heuristic severity is not a malware verdict. There is no threat-feed or reputation lookup.
      </p>
    </div>
  );
}

function ActivityChart({ analysis }: { analysis: ArtifactAnalysis }) {
  const grouped = new Map<string, { label: string; order: string; events: number }>();
  for (const entry of analysis.timeline) {
    const match = entry.timestamp.match(/^(?:(\d{4}-\d{2}-\d{2})[T\s])?(\d{2}):/);
    if (!match) continue;
    const day = match[1];
    const hour = match[2];
    const key = day ? `${day} ${hour}` : `hour ${hour}`;
    const label = day ? `${day.slice(5)} ${hour}:00` : `${hour}:00`;
    const bucket = grouped.get(key) || { label, order: key, events: 0 };
    bucket.events++;
    grouped.set(key, bucket);
  }
  const data = [...grouped.values()].sort((a, b) => a.order.localeCompare(b.order));

  return (
    <div className="rounded-xl p-5" style={{ background: "var(--card)", border: "1px solid var(--border)" }}>
      <div className="mb-5">
        <h3 className="text-sm font-semibold">Timeline activity</h3>
        <p className="text-xs mt-1" style={{ color: "var(--muted-foreground)" }}>Timestamped lines grouped by hour</p>
      </div>
      {data.length === 0 ? (
        <div className="h-[190px] flex items-center justify-center text-xs" style={{ color: "var(--muted-foreground)" }}>No timestamped events in this artifact.</div>
      ) : (
        <ResponsiveContainer width="100%" height={190}>
          <AreaChart data={data} margin={{ top: 8, right: 6, left: -22, bottom: 0 }}>
            <defs>
              <linearGradient id="activityFill" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="var(--primary)" stopOpacity={0.28} />
                <stop offset="95%" stopColor="var(--primary)" stopOpacity={0.01} />
              </linearGradient>
            </defs>
            <CartesianGrid vertical={false} stroke="var(--border)" strokeDasharray="3 4" />
            <XAxis dataKey="label" tick={{ fontSize: 9, fill: "var(--muted-foreground)" }} axisLine={false} tickLine={false} />
            <YAxis allowDecimals={false} width={34} tick={{ fontSize: 10, fill: "var(--muted-foreground)" }} axisLine={false} tickLine={false} />
            <Tooltip {...chartTooltip} />
            <Area type="monotone" dataKey="events" name="Events" stroke="var(--primary)" strokeWidth={2} fill="url(#activityFill)" />
          </AreaChart>
        </ResponsiveContainer>
      )}
    </div>
  );
}

function EvidenceList({ analysis }: { analysis: ArtifactAnalysis }) {
  const findings = [
    ...analysis.ioas.map((item) => ({
      title: item.technique,
      detail: `${item.mitreId} · ${item.tactic}`,
      severity: item.severity,
      confidence: item.confidence,
      evidence: item.evidence[0] || "Matched a local pattern",
      kind: "ATT&CK technique",
    })),
    ...analysis.iocs.map((item) => ({
      title: item.value,
      detail: item.description,
      severity: item.severity,
      confidence: item.confidence || 0,
      evidence: item.evidence?.[0] || "Matched in text content",
      kind: item.type,
    })),
  ].sort((a, b) => {
    const order = { critical: 0, high: 1, medium: 2, low: 3 };
    return order[a.severity] - order[b.severity] || b.confidence - a.confidence;
  });

  return (
    <div className="rounded-xl overflow-hidden max-h-[560px] flex flex-col" style={{ background: "var(--card)", border: "1px solid var(--border)" }}>
      <div className="flex items-center justify-between gap-3 p-5" style={{ borderBottom: "1px solid var(--border)" }}>
        <div>
          <h3 className="text-sm font-semibold">Evidence highlights</h3>
          <p className="text-xs mt-1" style={{ color: "var(--muted-foreground)" }}>Matched content and the rule that surfaced it</p>
        </div>
        <span className="text-xs font-mono shrink-0" style={{ color: "var(--muted-foreground)" }}>{findings.length} matches</span>
      </div>
      {findings.length === 0 ? (
        <div className="p-6 text-sm" style={{ color: "var(--muted-foreground)" }}>No local rules matched this artifact. This is not a clean-file verdict.</div>
      ) : <div className="overflow-y-auto">{findings.map((finding, index) => (
        <div key={`${finding.kind}-${finding.title}-${index}`} className="flex items-start gap-3 p-4 sm:px-5" style={{ borderBottom: index < findings.length - 1 ? "1px solid var(--border)" : undefined }}>
          <span className={`text-[10px] font-mono px-2 py-1 rounded-md border uppercase shrink-0 ${severityBg(finding.severity)}`}>{finding.severity}</span>
          <div className="min-w-0 flex-1">
            <div className="text-sm font-medium break-all">{finding.title}</div>
            <div className="text-xs mt-1" style={{ color: "var(--muted-foreground)" }}>{finding.kind} · {finding.detail}</div>
            <div className="font-mono text-[11px] mt-2 break-all" style={{ color: "var(--muted-foreground)" }}>{finding.evidence}</div>
          </div>
          <span className="font-mono text-xs shrink-0" style={{ color: "var(--muted-foreground)" }}>{finding.confidence}%</span>
        </div>
      ))}</div>}
    </div>
  );
}

function ArtifactDetails({ analysis }: { analysis: ArtifactAnalysis }) {
  const details = [
    ["Detected format", analysis.detectedType === "unknown" ? "No signature identified" : analysis.detectedType],
    ["Browser MIME", analysis.reportedType],
    ["File extension", analysis.extension ? `.${analysis.extension}` : "None"],
    ["File size", analysis.formattedSize],
    ["Last modified", analysis.lastModified],
    ["Shannon entropy", `${analysis.entropy.toFixed(2)} bits / byte`],
    ["Text lines", analysis.isText ? analysis.lineCount.toLocaleString() : "Not scanned as text"],
  ];

  return (
    <div className="rounded-xl p-5" style={{ background: "var(--card)", border: "1px solid var(--border)" }}>
      <div className="mb-4">
        <h3 className="text-sm font-semibold">Artifact profile</h3>
        <p className="text-xs mt-1" style={{ color: "var(--muted-foreground)" }}>Properties measured from the selected file and browser metadata</p>
      </div>
      <dl className="space-y-3">
        {details.map(([label, value]) => (
          <div key={label} className="flex items-start justify-between gap-4 text-xs">
            <dt className="shrink-0" style={{ color: "var(--muted-foreground)" }}>{label}</dt>
            <dd className="text-right break-all font-mono">{value}</dd>
          </div>
        ))}
      </dl>
      <p className="text-[11px] leading-relaxed mt-4 pt-4" style={{ borderTop: "1px solid var(--border)", color: "var(--muted-foreground)" }}>
        Entropy is a compression/encryption clue only; the score is not a malware classifier. Last-modified time comes from the file supplied by the browser.
      </p>
    </div>
  );
}

function Hashes({ analysis }: { analysis: ArtifactAnalysis }) {
  return (
    <div className="rounded-xl overflow-hidden" style={{ background: "var(--card)", border: "1px solid var(--border)" }}>
      <div className="p-5" style={{ borderBottom: "1px solid var(--border)" }}>
        <h3 className="text-sm font-semibold">Cryptographic fingerprints</h3>
        <p className="text-xs mt-1" style={{ color: "var(--muted-foreground)" }}>Computed from the exact uploaded bytes</p>
      </div>
      {Object.entries(analysis.hashes).map(([algorithm, value], index, all) => (
        <div key={algorithm} className="grid grid-cols-[64px_1fr] gap-3 p-4 sm:px-5" style={{ borderBottom: index < all.length - 1 ? "1px solid var(--border)" : undefined }}>
          <span className="text-xs font-mono uppercase" style={{ color: "var(--muted-foreground)" }}>{algorithm}</span>
          <code className="text-[11px] break-all leading-relaxed">{value}</code>
        </div>
      ))}
    </div>
  );
}

export default function Dashboard() {
  const [analysis, setAnalysis] = useState<ArtifactAnalysis | null>(null);
  const [busy, setBusy] = useState(false);
  const [dragging, setDragging] = useState(false);
  const [error, setError] = useState("");
  const fileInput = useRef<HTMLInputElement>(null);

  const analyze = useCallback(async (file: File) => {
    setError("");
    setAnalysis(null);
    setBusy(true);
    try {
      setAnalysis(await analyzeArtifact(file));
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "The file could not be analyzed.");
    } finally {
      setBusy(false);
    }
  }, []);

  const loadExample = async () => {
    setError("");
    setBusy(true);
    try {
      const response = await fetch("/samples/system_events.csv");
      if (!response.ok) throw new Error(`Could not load example artifact (${response.status}).`);
      const file = new File([await response.blob()], "system_events.csv", { type: "text/csv" });
      setAnalysis(await analyzeArtifact(file));
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "The example artifact could not be analyzed.");
    } finally {
      setBusy(false);
    }
  };

  const findings = analysis ? [...analysis.iocs, ...analysis.ioas] : [];
  const highestSeverity = findings.some((item) => item.severity === "critical")
    ? "#ef4444"
    : findings.some((item) => item.severity === "high")
      ? "#f97316"
      : "var(--foreground)";

  return (
    <div className="space-y-7 sm:space-y-8">
      <div className="flex flex-col sm:flex-row sm:items-end justify-between gap-4">
        <div>
          <div className="text-xs font-mono uppercase tracking-[0.18em] mb-2" style={{ color: "var(--primary)" }}>Forensic workspace / overview</div>
          <h1 className="text-2xl sm:text-3xl font-semibold tracking-tight">Artifact overview</h1>
          <p className="text-sm mt-2 max-w-2xl leading-relaxed" style={{ color: "var(--muted-foreground)" }}>
            Hash, profile, and scan one file in your browser. Results are derived from the bytes and local rules—no files are uploaded to a server.
          </p>
        </div>
        {analysis && (
          <button onClick={() => fileInput.current?.click()} className="text-xs font-semibold px-4 py-2.5 rounded-lg shrink-0" style={{ background: "var(--primary)", color: "var(--primary-foreground)" }}>
            Analyze another file
          </button>
        )}
      </div>

      <input ref={fileInput} type="file" className="hidden" aria-label="Select an artifact to analyze" onChange={(event) => {
        const file = event.target.files?.[0];
        if (file) void analyze(file);
        event.target.value = "";
      }} />
      {!analysis && (
        <div
          role="button"
          tabIndex={0}
          onClick={() => !busy && fileInput.current?.click()}
          onKeyDown={(event) => {
            if (!busy && (event.key === "Enter" || event.key === " ")) {
              event.preventDefault();
              fileInput.current?.click();
            }
          }}
          onDragOver={(event) => { event.preventDefault(); setDragging(true); }}
          onDragLeave={() => setDragging(false)}
          onDrop={(event) => {
            event.preventDefault();
            setDragging(false);
            const file = event.dataTransfer.files[0];
            if (file) void analyze(file);
          }}
          className="rounded-2xl p-8 sm:p-12 text-center cursor-pointer transition-colors"
          style={{ border: `1px dashed ${dragging ? "var(--primary)" : "var(--border)"}`, background: dragging ? "rgba(34,197,94,0.06)" : "var(--card)" }}
        >
          <div className="mx-auto w-12 h-12 rounded-xl flex items-center justify-center font-mono text-xl" style={{ background: "var(--muted)", color: "var(--primary)" }}>↑</div>
          <h2 className="text-base font-semibold mt-4">{busy ? "Analyzing artifact…" : "Drop an evidence file to begin"}</h2>
          <p className="text-xs mt-2" style={{ color: "var(--muted-foreground)" }}>
            {busy ? "Calculating hashes and deriving local findings from the file contents" : "Files stay in this browser session; hashes are computed from the original bytes"}
          </p>
          {!busy && <span className="inline-block text-xs font-semibold mt-5 px-4 py-2 rounded-lg" style={{ background: "var(--primary)", color: "var(--primary-foreground)" }}>Choose a file</span>}
          <div className="mt-5 flex flex-wrap justify-center gap-2">
            {["MD5 + SHA-1/256/512", "Format signatures", "Entropy", "IoC / ATT&CK patterns"].map((item) => (
              <span key={item} className="text-[11px] px-2.5 py-1 rounded-full" style={{ background: "var(--muted)", color: "var(--muted-foreground)" }}>{item}</span>
            ))}
          </div>
        </div>
      )}
      {error && <div role="alert" className="rounded-lg p-3 text-sm" style={{ color: "#ef4444", border: "1px solid rgba(239,68,68,0.3)", background: "rgba(239,68,68,0.06)" }}>{error}</div>}

      {!analysis && !busy && (
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 rounded-xl p-4 sm:px-5" style={{ background: "var(--card)", border: "1px solid var(--border)" }}>
          <div>
            <div className="text-sm font-medium">Want to inspect a fixture first?</div>
            <div className="text-xs mt-1" style={{ color: "var(--muted-foreground)" }}>Load a bundled, synthetic Windows event log to see how detections are derived.</div>
          </div>
          <button onClick={() => void loadExample()} className="text-xs font-semibold px-3 py-2 rounded-lg shrink-0" style={{ border: "1px solid var(--border)", color: "var(--foreground)" }}>Analyze example</button>
        </div>
      )}

      {analysis && (
        <>
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 rounded-xl p-4 sm:px-5" style={{ background: "var(--card)", border: "1px solid var(--border)" }}>
            <div className="min-w-0">
              <div className="text-xs" style={{ color: "var(--muted-foreground)" }}>Analyzed artifact</div>
              <div className="text-sm font-semibold mt-1 break-all">{analysis.filename}</div>
              <div className="text-xs mt-1" style={{ color: "var(--muted-foreground)" }}>{analysis.formattedSize} · Finished in {analysis.durationMs} ms · {new Date(analysis.analyzedAt).toLocaleString()}</div>
            </div>
            <span className="text-[11px] font-medium px-2.5 py-1.5 rounded-full shrink-0" style={{ background: "var(--muted)", color: "var(--muted-foreground)" }}>Private session</span>
          </div>

          <div className="grid grid-cols-2 xl:grid-cols-4 gap-3">
            <StatCard label="Heuristic risk score" value={`${analysis.riskScore}/100`} note={riskLabel(analysis.riskScore)} accent={highestSeverity} />
            <StatCard label="Indicators" value={analysis.iocs.length} note="Contextual candidates" />
            <StatCard label="ATT&CK patterns" value={analysis.ioas.length} note="Rule matches, not confirmation" />
            <StatCard label="Timeline events" value={analysis.timeline.length} note={analysis.isText ? "Timestamped lines parsed" : "Text log not detected"} />
          </div>

          <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
            <FindingsChart analysis={analysis} />
            <ActivityChart analysis={analysis} />
          </div>
          <div className="grid grid-cols-1 xl:grid-cols-[0.8fr_1.2fr] gap-4">
            <ArtifactDetails analysis={analysis} />
            <EvidenceList analysis={analysis} />
          </div>

          {analysis.timeline.length > 0 && (
            <div className="rounded-xl overflow-hidden" style={{ background: "var(--card)", border: "1px solid var(--border)" }}>
              <div className="flex items-center justify-between p-5" style={{ borderBottom: "1px solid var(--border)" }}>
                <div>
                  <h3 className="text-sm font-semibold">Timeline preview</h3>
                  <p className="text-xs mt-1" style={{ color: "var(--muted-foreground)" }}>Timestamped lines sorted by their parsed timestamp</p>
                </div>
                <span className="text-xs font-mono" style={{ color: "var(--muted-foreground)" }}>{analysis.timeline.length} events</span>
              </div>
              {analysis.timeline.slice(0, 4).map((entry, index) => (
                <div key={`${entry.timestamp}-${index}`} className="grid grid-cols-[auto_1fr] gap-3 p-4 sm:px-5" style={{ borderBottom: index < Math.min(analysis.timeline.length, 4) - 1 ? "1px solid var(--border)" : undefined }}>
                  <span className={`text-[10px] font-mono px-2 py-1 rounded-md border uppercase h-fit ${severityBg(entry.severity)}`}>{entry.severity}</span>
                  <div className="min-w-0">
                    <div className="flex flex-wrap gap-x-3 gap-y-1 text-[11px] font-mono" style={{ color: "var(--muted-foreground)" }}>
                      <span>{entry.timestamp}</span><span>{entry.category}</span>
                    </div>
                    <div className="text-xs mt-1 break-all">{entry.event}</div>
                  </div>
                </div>
              ))}
            </div>
          )}
          <Hashes analysis={analysis} />
          {analysis.isText && analysis.textPreview && (
            <details className="rounded-xl p-5" style={{ background: "var(--card)", border: "1px solid var(--border)" }}>
              <summary className="text-sm font-semibold cursor-pointer">View text preview</summary>
              <pre className="text-xs font-mono mt-4 p-4 rounded-lg overflow-auto max-h-72 whitespace-pre-wrap break-all" style={{ background: "var(--muted)", color: "var(--muted-foreground)" }}>{analysis.textPreview}</pre>
            </details>
          )}
        </>
      )}
    </div>
  );
}
