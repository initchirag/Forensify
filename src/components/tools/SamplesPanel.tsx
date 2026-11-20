import { useState } from "react";
import type { CSSProperties } from "react";
import JSZip from "jszip";
import { saveAs } from "file-saver";

interface Sample {
  name: string;
  path: string;
  description: string;
  tags: string[];
  bestFor: string;
}

const SAMPLES: Sample[] = [
  {
    name: "system_events.csv",
    path: "/samples/system_events.csv",
    description: "Synthetic Windows-style event rows for exercising timestamp parsing and local pattern rules. Not collected from a real endpoint.",
    tags: ["IoC", "IoA", "Timeline"],
    bestFor: "Indicators, timeline",
  },
  {
    name: "malware_indicators.txt",
    path: "/samples/malware_indicators.txt",
    description: "A fictional threat-report fixture containing illustrative hashes, addresses, domains, and technique references. It is not a live or verified threat-intelligence feed.",
    tags: ["IoC", "Hash", "Metadata"],
    bestFor: "Indicators, hashes",
  },
  {
    name: "memory_dump_excerpt.txt",
    path: "/samples/memory_dump_excerpt.txt",
    description: "Synthetic text excerpt formatted like memory-analysis output. It is not a real memory image and does not run a memory-forensics engine.",
    tags: ["IoC", "IoA", "Metadata"],
    bestFor: "Indicators, reports",
  },
];

const TAG_STYLE: Record<string, CSSProperties> = {
  IoC: { color: "#ef4444", borderColor: "rgba(239,68,68,0.25)", background: "rgba(239,68,68,0.07)" },
  IoA: { color: "#f97316", borderColor: "rgba(249,115,22,0.25)", background: "rgba(249,115,22,0.07)" },
  Hash: { color: "#3b82f6", borderColor: "rgba(59,130,246,0.25)", background: "rgba(59,130,246,0.07)" },
  Timeline: { color: "#a855f7", borderColor: "rgba(168,85,247,0.25)", background: "rgba(168,85,247,0.07)" },
  Metadata: { color: "#22c55e", borderColor: "rgba(34,197,94,0.25)", background: "rgba(34,197,94,0.07)" },
};

const WORKFLOW = [
  ["File hashes", "Select any fixture to compute MD5, SHA-1, SHA-256, and SHA-512."],
  ["Artifact profile", "Inspect byte entropy, browser metadata, signatures, and readable text structure."],
  ["Indicators", "Try malware_indicators.txt to review local candidate indicators and pattern matches."],
  ["Timeline", "Try system_events.csv to parse timestamped rows into a rule-labeled timeline."],
  ["Reports", "Analyze a fixture to export measured findings in a ZIP report."],
];

export default function SamplesPanel() {
  const [downloading, setDownloading] = useState(false);
  const [error, setError] = useState("");

  const download = async (sample: Sample) => {
    setError("");
    try {
      const response = await fetch(sample.path);
      if (!response.ok) throw new Error(`Could not download ${sample.name} (${response.status}).`);
      saveAs(await response.blob(), sample.name);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : `Could not download ${sample.name}.`);
    }
  };

  const downloadAll = async () => {
    setError("");
    setDownloading(true);
    try {
      const archive = new JSZip();
      await Promise.all(SAMPLES.map(async (sample) => {
        const response = await fetch(sample.path);
        if (!response.ok) throw new Error(`Could not download ${sample.name} (${response.status}).`);
        archive.file(sample.name, await response.blob());
      }));
      const blob = await archive.generateAsync({ type: "blob" });
      saveAs(blob, "forensify-example-artifacts.zip");
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "The example archive could not be created.");
    } finally {
      setDownloading(false);
    }
  };

  return (
    <div className="space-y-6">
      <div className="space-y-1">
        <h2 className="text-xl font-semibold tracking-tight">Example artifacts</h2>
        <p className="text-sm" style={{ color: "var(--muted-foreground)" }}>
          Synthetic fixtures for testing the parsers. These are examples, not real evidence or verified threat intelligence.
        </p>
      </div>
      {error && <div role="alert" className="rounded-lg p-3 text-sm" style={{ color: "#ef4444", border: "1px solid rgba(239,68,68,0.3)", background: "rgba(239,68,68,0.06)" }}>{error}</div>}

      <div className="rounded-xl p-4 sm:px-5 flex flex-col sm:flex-row sm:items-center justify-between gap-4" style={{ border: "1px solid var(--border)", background: "var(--card)" }}>
        <div>
          <div className="font-semibold text-sm">{SAMPLES.length} bundled fixtures</div>
          <div className="text-xs mt-1" style={{ color: "var(--muted-foreground)" }}>Download one file or collect all three in a ZIP archive.</div>
        </div>
        <button
          type="button"
          onClick={() => void downloadAll()}
          disabled={downloading}
          className="font-semibold text-xs px-4 py-2.5 rounded-lg transition-opacity hover:opacity-90 disabled:opacity-60"
          style={{ background: "var(--primary)", color: "var(--primary-foreground)" }}
        >
          {downloading ? "Preparing archive…" : "Download all"}
        </button>
      </div>

      <div className="space-y-3">
        {SAMPLES.map((sample, index) => (
          <article key={sample.name} className="rounded-xl p-4 sm:p-5 flex flex-col sm:flex-row sm:items-start gap-4" style={{ border: "1px solid var(--border)", background: "var(--card)" }}>
            <span className="font-mono text-xs mt-0.5" style={{ color: "var(--muted-foreground)" }}>{String(index + 1).padStart(2, "0")}</span>
            <div className="min-w-0 flex-1">
              <div className="flex items-center gap-2 flex-wrap">
                <h3 className="font-mono font-semibold text-sm">{sample.name}</h3>
                <span className="text-[10px] font-medium tracking-wide px-2 py-1 rounded-full" style={{ color: "var(--muted-foreground)", background: "var(--muted)" }}>SYNTHETIC</span>
              </div>
              <p className="text-xs mt-2 leading-relaxed" style={{ color: "var(--muted-foreground)" }}>{sample.description}</p>
              <div className="flex items-center gap-2 mt-3 flex-wrap">
                {sample.tags.map((tag) => (
                  <span key={tag} className="text-[10px] px-2 py-1 rounded-full border font-mono" style={TAG_STYLE[tag]}>{tag}</span>
                ))}
                <span className="text-[11px]" style={{ color: "var(--muted-foreground)" }}>Useful for {sample.bestFor}</span>
              </div>
            </div>
            <button
              type="button"
              onClick={() => void download(sample)}
              disabled={downloading}
              className="self-start shrink-0 text-xs font-medium px-3 py-2 rounded-lg disabled:opacity-60"
              style={{ border: "1px solid var(--border)", color: "var(--foreground)" }}
            >
              Download
            </button>
          </article>
        ))}
      </div>

      <section className="rounded-xl p-5 sm:p-6" style={{ border: "1px solid var(--border)", background: "var(--card)" }}>
        <h3 className="text-xs font-mono uppercase tracking-widest" style={{ color: "var(--muted-foreground)" }}>Suggested workflow</h3>
        <ol className="mt-4 grid sm:grid-cols-2 gap-4">
          {WORKFLOW.map(([title, description], index) => (
            <li key={title} className="flex items-start gap-3 text-xs">
              <span className="font-mono font-semibold shrink-0" style={{ color: "var(--primary)" }}>{String(index + 1).padStart(2, "0")}</span>
              <span>
                <strong className="font-semibold" style={{ color: "var(--foreground)" }}>{title}: </strong>
                <span style={{ color: "var(--muted-foreground)" }}>{description}</span>
              </span>
            </li>
          ))}
        </ol>
      </section>
    </div>
  );
}
