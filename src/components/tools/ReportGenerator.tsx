import { useState, useCallback } from "react";
import {
  ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip, PieChart, Pie, Cell,
} from "recharts";
import { formatFileSize } from "@/utils/crypto";
import { severityBg } from "@/utils/forensics";
import { analyzeArtifact } from "@/utils/analyzer";
import { downloadReportZip, type ReportData } from "@/utils/report";

const SEV_COLORS: Record<string, string> = {
  critical: "#ef4444", high: "#f97316", medium: "#eab308", low: "#22c55e",
};
const PIE_COLORS = ["#22c55e", "#3b82f6", "#f97316", "#a855f7", "#ec4899", "#eab308", "#06b6d4"];
const TooltipStyle = { background: "var(--card)", border: "1px solid var(--border)", borderRadius: 4, fontSize: 12 };

export default function ReportGenerator() {
  const [isDragging, setIsDragging] = useState(false);
  const [loading, setLoading] = useState(false);
  const [report, setReport] = useState<ReportData | null>(null);
  const [downloading, setDownloading] = useState(false);
  const [error, setError] = useState("");

  const analyze = useCallback(async (file: File) => {
    setLoading(true);
    setError("");
    try {
      const analysis = await analyzeArtifact(file);
      setReport({
        filename: analysis.filename,
        fileSize: analysis.size,
        fileType: analysis.reportedType,
        analysisDate: analysis.analyzedAt,
        md5: analysis.hashes.md5,
        sha1: analysis.hashes.sha1,
        sha256: analysis.hashes.sha256,
        sha512: analysis.hashes.sha512,
        iocs: analysis.iocs,
        ioas: analysis.ioas,
        timeline: analysis.timeline,
        riskScore: analysis.riskScore,
      });
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "The file could not be analyzed.");
    } finally {
      setLoading(false);
    }
  }, []);

  const onDrop = (e: React.DragEvent) => {
    e.preventDefault(); setIsDragging(false);
    if (e.dataTransfer.files[0]) analyze(e.dataTransfer.files[0]);
  };

  const handleDownload = async () => {
    if (!report) return;
    setDownloading(true);
    setError("");
    try {
      await downloadReportZip(report);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "The report archive could not be created.");
    } finally {
      setDownloading(false);
    }
  };

  const riskLevel = !report ? "" : report.riskScore >= 70 ? "HIGH SIGNAL" : report.riskScore >= 40 ? "REVIEW" : report.riskScore >= 20 ? "LOW SIGNAL" : "NO SIGNAL";
  const riskColorMap: Record<string, string> = { "HIGH SIGNAL": "#ef4444", REVIEW: "#f97316", "LOW SIGNAL": "#eab308", "NO SIGNAL": "#22c55e" };
  const riskColor = riskColorMap[riskLevel] || "var(--foreground)";

  const sevBreakdown = ["critical", "high", "medium", "low"].map((s) => ({
    name: s[0].toUpperCase() + s.slice(1),
    ioc: report?.iocs.filter((i) => i.severity === s).length || 0,
    ioa: report?.ioas.filter((a) => a.severity === s).length || 0,
    fill: SEV_COLORS[s],
  }));

  const iocTypePie = report
    ? Object.entries(report.iocs.reduce<Record<string, number>>((a, i) => { a[i.type] = (a[i.type] || 0) + 1; return a; }, {}))
        .map(([name, value]) => ({ name, value }))
    : [];

  const mitreData = report
    ? Object.entries(report.ioas.reduce<Record<string, number>>((counts, item) => {
        counts[item.tactic] = (counts[item.tactic] || 0) + 1;
        return counts;
      }, {})).map(([tactic, count]) => ({ tactic, count }))
    : [];

  return (
    <div className="space-y-6">
      <div className="space-y-1">
        <h2 className="text-lg font-bold tracking-tight">Report Generator</h2>
        <p className="text-sm" style={{ color: "var(--muted-foreground)" }}>
          Artifact triage with a heuristic signal score, measured findings, and a downloadable ZIP package.
        </p>
      </div>
      {error && <div role="alert" className="rounded p-3 text-sm" style={{ color: "#ef4444", border: "1px solid rgba(239,68,68,0.3)", background: "rgba(239,68,68,0.06)" }}>{error}</div>}

      <div
        className="rounded cursor-pointer transition-colors relative"
        style={{
          border: `2px dashed ${isDragging ? "var(--primary)" : "var(--border)"}`,
          background: isDragging ? "rgba(34,197,94,0.04)" : "var(--card)",
        }}
        onDragOver={(e) => { e.preventDefault(); setIsDragging(true); }}
        onDragLeave={() => setIsDragging(false)}
        onDrop={onDrop}
        onClick={() => !loading && document.getElementById("report-input")?.click()}
      >
        <input id="report-input" type="file" className="hidden" onChange={(e) => { if (e.target.files?.[0]) analyze(e.target.files[0]); e.target.value = ""; }} />
        <div className="flex flex-col items-center justify-center py-14 gap-3 select-none">
          {loading ? (
            <>
              <div className="text-sm font-medium">Analyzing artifact…</div>
              <div className="text-xs" style={{ color: "var(--muted-foreground)" }}>Hashing the file and applying local text-analysis rules</div>
            </>
          ) : (
            <>
              <div className="text-sm font-medium">Drop any file for artifact triage</div>
              <div className="text-xs" style={{ color: "var(--muted-foreground)" }}>
                Generates a heuristic score, finding breakdowns, and downloadable ZIP report package
              </div>
            </>
          )}
        </div>
      </div>

      {report && (
        <>
          {/* Action bar */}
          <div className="flex items-center justify-between rounded p-4" style={{ border: "1px solid var(--border)", background: "var(--card)" }}>
            <div>
              <div className="font-mono font-bold text-sm">{report.filename}</div>
              <div className="text-xs mt-0.5" style={{ color: "var(--muted-foreground)" }}>
                {formatFileSize(report.fileSize)} · Analyzed {new Date(report.analysisDate).toLocaleString()}
              </div>
            </div>
            <button
              onClick={handleDownload}
              disabled={downloading}
              className="font-bold text-xs px-5 py-2.5 rounded transition-all disabled:opacity-50"
              style={{ background: "var(--primary)", color: "var(--primary-foreground)" }}
            >
              {downloading ? "Packaging…" : "Download ZIP Report"}
            </button>
          </div>

          {/* KPIs */}
          <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
            <div className="rounded p-4 col-span-2 md:col-span-1" style={{ border: "1px solid var(--border)", background: "var(--card)" }}>
              <div className="font-black font-mono text-5xl leading-none" style={{ color: riskColor }}>{report.riskScore}</div>
              <div className="text-xs mt-2 uppercase tracking-wider" style={{ color: "var(--muted-foreground)" }}>Heuristic Score</div>
              <div className="font-mono font-bold text-xs mt-1" style={{ color: riskColor }}>{riskLevel}</div>
              <div className="text-[10px] mt-2 leading-relaxed" style={{ color: "var(--muted-foreground)" }}>Not a malware probability or verdict.</div>
            </div>
            {[
              { l: "IoCs", v: report.iocs.length },
              { l: "IoAs", v: report.ioas.length },
              { l: "Timeline Events", v: report.timeline.length },
              { l: "Critical", v: [...report.iocs, ...report.ioas].filter((x) => x.severity === "critical").length },
            ].map((s) => (
              <div key={s.l} className="rounded p-4" style={{ border: "1px solid var(--border)", background: "var(--card)" }}>
                <div className="font-bold font-mono text-2xl">{s.v}</div>
                <div className="text-xs mt-1 uppercase tracking-wider" style={{ color: "var(--muted-foreground)" }}>{s.l}</div>
              </div>
            ))}
          </div>

          {/* Hashes */}
          <div className="rounded overflow-hidden" style={{ border: "1px solid var(--border)", background: "var(--card)" }}>
            <div className="px-5 py-3" style={{ borderBottom: "1px solid var(--border)" }}>
              <span className="text-xs font-mono uppercase tracking-widest" style={{ color: "var(--muted-foreground)" }}>Cryptographic Hashes</span>
            </div>
            {[["MD5", report.md5], ["SHA-1", report.sha1], ["SHA-256", report.sha256], ["SHA-512", report.sha512]].map(([label, hash]) => (
              <div key={label} className="flex items-start gap-4 px-5 py-3" style={{ borderBottom: "1px solid var(--border)" }}>
                <span className="font-mono text-xs w-14 shrink-0 pt-px" style={{ color: "var(--muted-foreground)" }}>{label}</span>
                <span className="font-mono text-xs break-all" style={{ color: "var(--primary)" }}>{hash}</span>
              </div>
            ))}
          </div>

          {/* Charts row */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="rounded p-4" style={{ border: "1px solid var(--border)", background: "var(--card)" }}>
              <div className="text-xs font-mono uppercase tracking-widest mb-4" style={{ color: "var(--muted-foreground)" }}>Severity Breakdown</div>
              <ResponsiveContainer width="100%" height={160}>
                <BarChart data={sevBreakdown}>
                  <XAxis dataKey="name" tick={{ fontSize: 10, fill: "var(--muted-foreground)" }} stroke="var(--border)" />
                  <YAxis tick={{ fontSize: 9, fill: "var(--muted-foreground)" }} stroke="var(--border)" />
                  <Tooltip contentStyle={TooltipStyle} />
                  <Bar dataKey="ioc" name="IoC" fill="#22c55e" radius={[2, 2, 0, 0]} />
                  <Bar dataKey="ioa" name="IoA" fill="#3b82f6" radius={[2, 2, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
            <div className="rounded p-4" style={{ border: "1px solid var(--border)", background: "var(--card)" }}>
              <div className="text-xs font-mono uppercase tracking-widest mb-4" style={{ color: "var(--muted-foreground)" }}>IoC Type Distribution</div>
              <ResponsiveContainer width="100%" height={160}>
                <PieChart>
                  <Pie data={iocTypePie} dataKey="value" nameKey="name" cx="50%" cy="50%" outerRadius={60} innerRadius={28}>
                    {iocTypePie.map((_, i) => <Cell key={i} fill={PIE_COLORS[i % PIE_COLORS.length]} />)}
                  </Pie>
                  <Tooltip contentStyle={TooltipStyle} />
                </PieChart>
              </ResponsiveContainer>
            </div>
          </div>

          {/* MITRE Radar */}
          <div className="rounded p-4" style={{ border: "1px solid var(--border)", background: "var(--card)" }}>
            <div className="text-xs font-mono uppercase tracking-widest mb-4" style={{ color: "var(--muted-foreground)" }}>ATT&CK pattern matches by tactic</div>
            {mitreData.length === 0
              ? <div className="text-sm py-12 text-center" style={{ color: "var(--muted-foreground)" }}>No ATT&CK patterns matched.</div>
              : <ResponsiveContainer width="100%" height={260}>
                  <BarChart data={mitreData} layout="vertical">
                    <XAxis type="number" allowDecimals={false} tick={{ fontSize: 9, fill: "var(--muted-foreground)" }} stroke="var(--border)" />
                    <YAxis type="category" dataKey="tactic" width={120} tick={{ fontSize: 9, fill: "var(--muted-foreground)" }} stroke="var(--border)" />
                    <Tooltip contentStyle={TooltipStyle} />
                    <Bar dataKey="count" name="Matched rules" fill="var(--primary)" radius={[0, 3, 3, 0]} />
                  </BarChart>
                </ResponsiveContainer>}
          </div>

          {/* IoA table */}
          <div className="rounded overflow-hidden" style={{ border: "1px solid var(--border)", background: "var(--card)" }}>
            <div className="px-5 py-3" style={{ borderBottom: "1px solid var(--border)" }}>
              <span className="text-xs font-mono uppercase tracking-widest" style={{ color: "var(--muted-foreground)" }}>Detected Attack Techniques</span>
            </div>
            <div className="divide-y" style={{ borderColor: "var(--border)" }}>
              {report.ioas.length === 0
                ? <div className="px-5 py-6 text-sm" style={{ color: "var(--muted-foreground)" }}>No attack techniques detected in this artifact.</div>
                : report.ioas.map((ioa, i) => (
                  <div key={i} className="flex items-center gap-3 px-5 py-3" style={{ borderBottom: "1px solid var(--border)" }}>
                    <span className={`text-xs px-2 py-0.5 rounded border font-mono shrink-0 ${severityBg(ioa.severity)}`}>{ioa.severity.slice(0, 4).toUpperCase()}</span>
                    <div className="flex-1">
                      <span className="text-xs font-bold">{ioa.technique}</span>
                      <span className="text-xs ml-2" style={{ color: "var(--muted-foreground)" }}>{ioa.tactic}</span>
                    </div>
                    <span className="font-mono text-xs shrink-0" style={{ color: "var(--primary)" }}>{ioa.mitreId}</span>
                    <span className="font-mono text-xs shrink-0" style={{ color: "var(--muted-foreground)" }}>{ioa.confidence}%</span>
                  </div>
                ))}
            </div>
          </div>
        </>
      )}
    </div>
  );
}
