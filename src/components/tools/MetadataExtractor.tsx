import { useState, useCallback } from "react";
import { formatFileSize } from "@/utils/crypto";
import { profileArtifact } from "@/utils/analyzer";

interface MetaField { label: string; value: string; mono?: boolean }

interface FileMetadata {
  filename: string;
  extension: string;
  size: number;
  type: string;
  lastModified: Date;
  fields: MetaField[];
  textPreview?: string;
}

function guessCategory(type: string, ext: string): string {
  if (type.startsWith("image/")) return "Image";
  if (type.startsWith("video/")) return "Video";
  if (type.startsWith("audio/")) return "Audio";
  if (type.includes("pdf")) return "PDF Document";
  if (type.includes("word") || ext === "docx" || ext === "doc") return "Word Document";
  if (type.includes("excel") || ext === "xlsx" || ext === "csv") return "Spreadsheet";
  if (type.includes("zip") || type.includes("tar") || ext === "gz" || ext === "7z") return "Archive";
  if (type.startsWith("text/") || ["log", "txt", "md", "json", "xml", "yaml", "yml"].includes(ext)) return "Text / Log";
  return "Binary / Unknown";
}

function entropyRisk(entropy: number): string {
  if (entropy > 7.2) return "High; may indicate compression or encryption";
  if (entropy > 6.5) return "Elevated; may indicate compressed or binary data";
  return "Lower; more byte values are repeated";
}

async function extractMeta(file: File): Promise<FileMetadata> {
  const ext = file.name.split(".").pop()?.toLowerCase() || "";
  const profile = await profileArtifact(file);
  const actualType = profile.detectedType !== "unknown" ? profile.detectedType : file.type;
  const category = guessCategory(actualType, ext);
  const fields: MetaField[] = [
    { label: "Filename", value: file.name, mono: true },
    { label: "Extension", value: ext ? `.${ext}` : "—", mono: true },
    { label: "Browser MIME Type", value: file.type || "unknown", mono: true },
    { label: "Detected Signature", value: profile.detectedType, mono: true },
    { label: "Category", value: category },
    { label: "Size (formatted)", value: formatFileSize(file.size) },
    { label: "Size (bytes)", value: file.size.toLocaleString(), mono: true },
    { label: "Last Modified (UTC)", value: new Date(file.lastModified).toISOString(), mono: true },
    { label: "Last Modified (local)", value: new Date(file.lastModified).toLocaleString() },
    { label: "Byte entropy", value: `${profile.entropy.toFixed(4)} bits/byte — ${entropyRisk(profile.entropy)}`, mono: true },
  ];

  const textPreview = profile.isText ? profile.text.slice(0, 8192) : undefined;
  if (profile.isText) {
    const text = profile.text;
    const lines = text.split("\n");
    const avgLineLen = lines.reduce((s, l) => s + l.length, 0) / Math.max(lines.length, 1);
    fields.push(
      { label: "Text lines", value: profile.lineCount.toLocaleString() },
      { label: "Avg. line length", value: `${avgLineLen.toFixed(1)} chars` },
      { label: "First line", value: lines[0]?.slice(0, 250) || "—", mono: true }
    );
  }

  if (actualType.startsWith("image/")) {
    const url = URL.createObjectURL(file);
    await new Promise<void>((resolve) => {
      const img = new Image();
      img.onload = () => {
        fields.push({ label: "Image dimensions", value: `${img.width} × ${img.height} px` });
        URL.revokeObjectURL(url);
        resolve();
      };
      img.onerror = () => { URL.revokeObjectURL(url); resolve(); };
      img.src = url;
    });
  }

  return { filename: file.name, extension: ext, size: file.size, type: actualType, lastModified: new Date(file.lastModified), fields, textPreview };
}

export default function MetadataExtractor() {
  const [isDragging, setIsDragging] = useState(false);
  const [results, setResults] = useState<FileMetadata[]>([]);
  const [loading, setLoading] = useState(false);
  const [expanded, setExpanded] = useState<number | null>(null);
  const [error, setError] = useState("");

  const processFiles = useCallback(async (files: File[]) => {
    if (files.length === 0) return;
    setLoading(true);
    setError("");
    try {
      const metadata = await Promise.all(files.map(extractMeta));
      setResults((previous) => [...metadata, ...previous]);
      setExpanded(0);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "The file metadata could not be read.");
    } finally {
      setLoading(false);
    }
  }, []);

  const onDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    void processFiles(Array.from(e.dataTransfer.files));
  };

  return (
    <div className="space-y-6">
      <div className="space-y-1">
        <h2 className="text-lg font-bold tracking-tight">Metadata Extraction</h2>
        <p className="text-sm" style={{ color: "var(--muted-foreground)" }}>
          Inspect browser-provided file properties, recognized format signatures, full-file byte entropy, and readable text structure.
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
        onClick={() => document.getElementById("meta-input")?.click()}
      >
        <input id="meta-input" type="file" multiple className="hidden" onChange={(e) => { void processFiles(Array.from(e.target.files || [])); e.target.value = ""; }} />
        <div className="flex flex-col items-center justify-center py-14 gap-2 select-none">
          <div className="text-sm font-medium">{loading ? "Extracting metadata…" : "Drop any file to inspect"}</div>
          <div className="text-xs" style={{ color: "var(--muted-foreground)" }}>Text, image, log, JSON, CSV — entropy analysis included</div>
        </div>
      </div>

      {results.map((meta, idx) => (
        <div key={idx} className="rounded overflow-hidden" style={{ border: "1px solid var(--border)", background: "var(--card)" }}>
          <button
            className="w-full flex items-center justify-between px-5 py-4 transition-colors text-left"
            style={{ borderBottom: expanded === idx ? "1px solid var(--border)" : undefined }}
            onClick={() => setExpanded(expanded === idx ? null : idx)}
          >
            <div>
              <div className="font-mono font-bold text-sm">{meta.filename}</div>
              <div className="text-xs mt-0.5" style={{ color: "var(--muted-foreground)" }}>
                {formatFileSize(meta.size)} · {meta.type || "unknown type"}
              </div>
            </div>
            <span className="font-mono text-lg" style={{ color: "var(--muted-foreground)" }}>{expanded === idx ? "−" : "+"}</span>
          </button>

          {expanded === idx && (
            <>
              <div>
                {meta.fields.map((f, fi) => (
                  <div
                    key={fi}
                    className="flex items-start gap-4 px-5 py-2.5"
                    style={{ borderBottom: "1px solid var(--border)" }}
                  >
                    <span className="text-xs w-44 shrink-0 pt-px" style={{ color: "var(--muted-foreground)" }}>{f.label}</span>
                    <span className={`text-xs break-all ${f.mono ? "font-mono" : ""}`}>{f.value}</span>
                  </div>
                ))}
              </div>
              {meta.textPreview && (
                <div className="px-5 py-4">
                  <div className="text-xs font-mono uppercase tracking-widest mb-3" style={{ color: "var(--muted-foreground)" }}>Content Preview</div>
                  <pre
                    className="text-xs font-mono p-4 rounded overflow-auto max-h-52 whitespace-pre-wrap"
                    style={{ background: "var(--muted)", border: "1px solid var(--border)" }}
                  >
                    {meta.textPreview.slice(0, 1200)}
                  </pre>
                </div>
              )}
            </>
          )}
        </div>
      ))}
    </div>
  );
}
