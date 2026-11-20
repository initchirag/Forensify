import { useState, useCallback } from "react";
import { computeMD5, computeSHA, formatFileSize } from "@/utils/crypto";

interface HashResult {
  md5: string;
  sha1: string;
  sha256: string;
  sha512: string;
  filename: string;
  size: number;
  type: string;
  lastModified: string;
}

const ALGORITHMS = ["MD5", "SHA-1", "SHA-256", "SHA-512"] as const;

export default function HashAnalyzer() {
  const [isDragging, setIsDragging] = useState(false);
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState<HashResult[]>([]);
  const [copied, setCopied] = useState<string | null>(null);
  const [error, setError] = useState("");

  const copy = (val: string, key: string) => {
    navigator.clipboard.writeText(val);
    setCopied(key);
    setTimeout(() => setCopied(null), 1600);
  };

  const analyzeFiles = useCallback(async (files: File[]) => {
    if (files.length === 0) return;
    setLoading(true);
    setError("");
    try {
      const outcomes = await Promise.all(files.map(async (file) => {
        try {
          const [md5, sha1, sha256, sha512] = await Promise.all([
            computeMD5(file),
            computeSHA(file, "SHA-1"),
            computeSHA(file, "SHA-256"),
            computeSHA(file, "SHA-512"),
          ]);
          return {
            success: true as const,
            result: {
              md5, sha1, sha256, sha512,
              filename: file.name,
              size: file.size,
              type: file.type || "application/octet-stream",
              lastModified: new Date(file.lastModified).toISOString(),
            } satisfies HashResult,
          };
        } catch (reason) {
          return { success: false as const, error: `${file.name}: ${reason instanceof Error ? reason.message : "hashing failed"}` };
        }
      }));
      const completed: HashResult[] = [];
      const failures: string[] = [];
      outcomes.forEach((outcome) => {
        if (outcome.success) completed.push(outcome.result);
        else failures.push(outcome.error);
      });
      if (completed.length > 0) setResults((previous) => [...completed, ...previous]);
      if (failures.length > 0) setError(failures.join("; "));
    } finally {
      setLoading(false);
    }
  }, []);

  const onDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault();
      setIsDragging(false);
      void analyzeFiles(Array.from(e.dataTransfer.files));
    },
    [analyzeFiles]
  );

  const onInput = (e: React.ChangeEvent<HTMLInputElement>) => {
    void analyzeFiles(Array.from(e.target.files || []));
    e.target.value = "";
  };

  const hashes = (r: HashResult) => [
    { label: "MD5", value: r.md5 },
    { label: "SHA-1", value: r.sha1 },
    { label: "SHA-256", value: r.sha256 },
    { label: "SHA-512", value: r.sha512 },
  ];

  return (
    <div className="space-y-6">
      <div className="space-y-1">
        <h2 className="text-lg font-bold tracking-tight">File Hashing</h2>
        <p className="text-sm" style={{ color: "var(--muted-foreground)" }}>
          Compute MD5, SHA-1, SHA-256 and SHA-512 digests for file integrity verification and threat hunting.
        </p>
      </div>

      <div
        className="relative rounded cursor-pointer transition-colors"
        style={{
          border: `2px dashed ${isDragging ? "var(--primary)" : "var(--border)"}`,
          background: isDragging ? "rgba(34,197,94,0.04)" : "var(--card)",
        }}
        onDragOver={(e) => { e.preventDefault(); setIsDragging(true); }}
        onDragLeave={() => setIsDragging(false)}
        onDrop={onDrop}
        onClick={() => document.getElementById("hash-input")?.click()}
      >
        <input id="hash-input" type="file" multiple className="hidden" onChange={onInput} />
        <div className="flex flex-col items-center justify-center py-14 gap-2 select-none">
          <div className="text-sm font-medium">
            {loading ? "Computing hashes…" : "Drop files here or click to select"}
          </div>
          <div className="text-xs" style={{ color: "var(--muted-foreground)" }}>
            {loading ? "Processing the original file bytes locally" : "Any file type · Processed entirely in your browser"}
          </div>
          <div className="flex gap-2 mt-3">
            {ALGORITHMS.map((a) => (
              <span key={a} className="font-mono text-xs px-2 py-0.5 rounded" style={{ background: "var(--muted)", color: "var(--muted-foreground)", border: "1px solid var(--border)" }}>{a}</span>
            ))}
          </div>
        </div>
      </div>
      {error && <div role="alert" className="rounded p-3 text-sm" style={{ color: "#ef4444", border: "1px solid rgba(239,68,68,0.3)", background: "rgba(239,68,68,0.06)" }}>{error}</div>}

      {results.map((r, i) => (
        <div key={i} className="rounded overflow-hidden" style={{ border: "1px solid var(--border)", background: "var(--card)" }}>
          <div className="px-5 py-3.5" style={{ borderBottom: "1px solid var(--border)" }}>
            <div className="font-mono font-bold text-sm">{r.filename}</div>
            <div className="text-xs mt-0.5" style={{ color: "var(--muted-foreground)" }}>
              {formatFileSize(r.size)} · {r.type} · {new Date(r.lastModified).toLocaleString()}
            </div>
          </div>
          <div>
            {hashes(r).map(({ label, value }) => {
              const key = `${i}-${label}`;
              return (
                <div key={label} className="flex items-start gap-4 px-5 py-3" style={{ borderBottom: "1px solid var(--border)" }}>
                  <span className="font-mono text-xs w-14 shrink-0 pt-px" style={{ color: "var(--muted-foreground)" }}>{label}</span>
                  <span className="font-mono text-xs break-all flex-1">{value}</span>
                  <button
                    className="shrink-0 font-mono text-xs px-2 py-0.5 rounded transition-colors"
                    style={{
                      border: "1px solid var(--border)",
                      color: copied === key ? "var(--primary)" : "var(--muted-foreground)",
                    }}
                    onClick={(e) => { e.stopPropagation(); copy(value, key); }}
                  >
                    {copied === key ? "Copied" : "Copy"}
                  </button>
                </div>
              );
            })}
            <div className="px-5 py-3 flex gap-3">
              <button
                className="font-mono text-xs px-3 py-1.5 rounded transition-colors"
                style={{ border: "1px solid var(--border)", color: "var(--muted-foreground)" }}
                onClick={() => {
                  const text = hashes(r).map(({ label, value }) => `${label}:\t${value}`).join("\n");
                  navigator.clipboard.writeText(text);
                }}
              >
                Copy all hashes
              </button>
              <button
                className="font-mono text-xs px-3 py-1.5 rounded transition-colors"
                style={{ border: "1px solid var(--border)", color: "var(--muted-foreground)" }}
                onClick={() => setResults((prev) => prev.filter((_, idx) => idx !== i))}
              >
                Remove
              </button>
            </div>
          </div>
        </div>
      ))}

      {results.length === 0 && (
        <div className="rounded p-4" style={{ border: "1px solid var(--border)", background: "var(--card)" }}>
          <p className="text-xs" style={{ color: "var(--muted-foreground)" }}>
            Download sample files from the <strong style={{ color: "var(--foreground)" }}>Sample Files</strong> tab, then drag them here to test hash computation.
          </p>
        </div>
      )}
    </div>
  );
}
