import JSZip from "jszip";
import { saveAs } from "file-saver";
import type { IoC, IoA, ForensicTimelineEntry } from "./forensics";

export interface ReportData {
  filename: string;
  fileSize: number;
  fileType: string;
  analysisDate: string;
  md5: string;
  sha1: string;
  sha256: string;
  sha512: string;
  iocs: IoC[];
  ioas: IoA[];
  timeline: ForensicTimelineEntry[];
  riskScore: number;
}

export function computeRiskScore(iocs: IoC[], ioas: IoA[]): number {
  const weights = { critical: 35, high: 22, medium: 12, low: 4 };
  const uniqueIoCs = new Map(iocs.map((ioc) => [`${ioc.type}:${ioc.value.toLowerCase()}`, ioc]));
  const uniqueIoAs = new Map(ioas.map((ioa) => [ioa.mitreId, ioa]));
  const weight = [
    ...uniqueIoCs.values(),
    ...uniqueIoAs.values(),
  ].reduce((total, finding) => {
    const confidence = finding.confidence ?? 25;
    return total + weights[finding.severity] * confidence / 100;
  }, 0);

  return Math.round(100 * (1 - Math.exp(-weight / 45)));
}

function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, (char) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;",
  })[char] ?? char);
}

function buildHtmlReport(data: ReportData): string {
  const severityCount = (items: (IoC | IoA)[], sev: string) =>
    items.filter((i) => i.severity === sev).length;

  const iocRows = data.iocs
    .map((i) => `<tr><td>${escapeHtml(i.type)}</td><td style="word-break:break-all;max-width:300px">${escapeHtml(i.value)}</td><td><span class="badge ${escapeHtml(i.severity)}">${escapeHtml(i.severity.toUpperCase())}</span></td><td>${escapeHtml(i.description)}</td></tr>`)
    .join("");

  const ioaRows = data.ioas
    .map((a) => `<tr><td>${escapeHtml(a.technique)}</td><td>${escapeHtml(a.mitreId)}</td><td><span class="badge ${escapeHtml(a.severity)}">${escapeHtml(a.severity.toUpperCase())}</span></td><td>${escapeHtml(a.evidence.join("; "))}</td></tr>`)
    .join("");

  const timelineRows = data.timeline
    .slice(0, 50)
    .map((t) => `<tr><td>${escapeHtml(t.timestamp)}</td><td><span class="badge ${escapeHtml(t.severity)}">${escapeHtml(t.severity.toUpperCase())}</span></td><td>${escapeHtml(t.category)}</td><td style="max-width:400px;word-break:break-all">${escapeHtml(t.event.slice(0, 120))}</td></tr>`)
    .join("");

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Forensify Report — ${escapeHtml(data.filename)}</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: 'Courier New', monospace; background: #0a0a0a; color: #e5e5e5; padding: 40px; }
  h1 { font-size: 28px; font-weight: 700; letter-spacing: -0.5px; margin-bottom: 4px; }
  h2 { font-size: 14px; font-weight: 400; color: #737373; margin-bottom: 32px; }
  h3 { font-size: 12px; font-weight: 700; text-transform: uppercase; letter-spacing: 2px; color: #737373; margin-bottom: 12px; margin-top: 32px; border-bottom: 1px solid #262626; padding-bottom: 8px; }
  .logo { font-size: 32px; font-weight: 900; letter-spacing: -2px; margin-bottom: 2px; }
  .logo span { color: #22c55e; }
  .grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 24px; }
  .card { background: #141414; border: 1px solid #262626; border-radius: 4px; padding: 16px; }
  .card-val { font-size: 28px; font-weight: 700; }
  .card-label { font-size: 11px; color: #737373; text-transform: uppercase; letter-spacing: 1px; margin-top: 4px; }
  .risk-score { font-size: 48px; font-weight: 900; }
  .risk-critical { color: #ef4444; }
  .risk-high { color: #f97316; }
  .risk-medium { color: #eab308; }
  .risk-low { color: #22c55e; }
  table { width: 100%; border-collapse: collapse; font-size: 12px; }
  th { text-align: left; padding: 8px 12px; background: #141414; color: #737373; font-weight: 600; text-transform: uppercase; letter-spacing: 1px; border-bottom: 1px solid #262626; }
  td { padding: 8px 12px; border-bottom: 1px solid #1a1a1a; vertical-align: top; }
  tr:hover td { background: #111; }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 2px; font-size: 10px; font-weight: 700; letter-spacing: 1px; }
  .badge.critical { background: rgba(239,68,68,0.15); color: #ef4444; }
  .badge.high { background: rgba(249,115,22,0.15); color: #f97316; }
  .badge.medium { background: rgba(234,179,8,0.15); color: #eab308; }
  .badge.low { background: rgba(34,197,94,0.15); color: #22c55e; }
  .badge.info { background: rgba(59,130,246,0.15); color: #3b82f6; }
  .meta { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-bottom: 24px; }
  .meta-row { display: flex; gap: 8px; }
  .meta-label { color: #737373; min-width: 80px; font-size: 12px; }
  .meta-val { font-size: 12px; word-break: break-all; }
  .hash { font-size: 11px; color: #737373; word-break: break-all; margin-top: 4px; }
  footer { margin-top: 40px; border-top: 1px solid #262626; padding-top: 16px; font-size: 11px; color: #525252; }
</style>
</head>
<body>
<div class="logo">FORENS<span>IFY</span></div>
<h1>Forensic Analysis Report</h1>
<h2>Generated: ${escapeHtml(data.analysisDate)} | File: ${escapeHtml(data.filename)}</h2>

<h3>File Metadata</h3>
<div class="meta">
  <div><div class="meta-row"><span class="meta-label">Filename</span><span class="meta-val">${escapeHtml(data.filename)}</span></div>
  <div class="meta-row"><span class="meta-label">Size</span><span class="meta-val">${data.fileSize} bytes</span></div>
  <div class="meta-row"><span class="meta-label">Type</span><span class="meta-val">${escapeHtml(data.fileType || "Unknown")}</span></div></div>
  <div><div class="hash">MD5: ${escapeHtml(data.md5)}</div>
  <div class="hash">SHA1: ${escapeHtml(data.sha1)}</div>
  <div class="hash">SHA256: ${escapeHtml(data.sha256)}</div>
  <div class="hash">SHA512: ${escapeHtml(data.sha512)}</div></div>
</div>

<h3>Risk Assessment</h3>
<div class="grid">
  <div class="card"><div class="card-val risk-score ${data.riskScore >= 70 ? "risk-critical" : data.riskScore >= 40 ? "risk-high" : data.riskScore >= 20 ? "risk-medium" : "risk-low"}">${data.riskScore}</div><div class="card-label">Heuristic Signal Score / 100</div></div>
  <div class="card"><div class="card-val">${data.iocs.length}</div><div class="card-label">Indicators of Compromise</div></div>
  <div class="card"><div class="card-val">${data.ioas.length}</div><div class="card-label">Indicators of Attack</div></div>
  <div class="card"><div class="card-val">${severityCount([...data.iocs, ...data.ioas], "critical")}</div><div class="card-label">Critical Findings</div></div>
</div>

<h3>Indicators of Compromise (IoC)</h3>
<table><thead><tr><th>Type</th><th>Value</th><th>Severity</th><th>Description</th></tr></thead>
<tbody>${iocRows || "<tr><td colspan='4' style='color:#525252'>No indicators detected</td></tr>"}</tbody></table>

<h3>Indicators of Attack (IoA) — MITRE ATT&CK</h3>
<table><thead><tr><th>Technique</th><th>MITRE ID</th><th>Severity</th><th>Evidence</th></tr></thead>
<tbody>${ioaRows || "<tr><td colspan='4' style='color:#525252'>No attack techniques detected</td></tr>"}</tbody></table>

<h3>Forensic Timeline (top 50 events)</h3>
<table><thead><tr><th>Timestamp</th><th>Severity</th><th>Category</th><th>Event</th></tr></thead>
<tbody>${timelineRows || "<tr><td colspan='4' style='color:#525252'>No timeline events extracted</td></tr>"}</tbody></table>

<footer>Forensify Digital Forensics Platform | Report ID: ${Math.random().toString(36).slice(2, 10).toUpperCase()} | For investigative purposes only</footer>
</body>
</html>`;
}

function buildJsonReport(data: ReportData): string {
  return JSON.stringify(
    {
      reportMetadata: {
        tool: "Forensify",
        version: "1.0.0",
        generatedAt: data.analysisDate,
        reportId: Math.random().toString(36).slice(2, 10).toUpperCase(),
      },
      fileInfo: {
        filename: data.filename,
        fileSize: data.fileSize,
        fileType: data.fileType,
        hashes: { md5: data.md5, sha1: data.sha1, sha256: data.sha256, sha512: data.sha512 },
      },
      riskAssessment: {
        score: data.riskScore,
        level: data.riskScore >= 70 ? "HIGH SIGNAL" : data.riskScore >= 40 ? "REVIEW" : data.riskScore >= 20 ? "LOW SIGNAL" : "NO SIGNAL",
        totalIoCs: data.iocs.length,
        totalIoAs: data.ioas.length,
      },
      indicators: { ioc: data.iocs, ioa: data.ioas },
      timeline: data.timeline,
    },
    null,
    2
  );
}

export async function downloadReportZip(data: ReportData) {
  const zip = new JSZip();
  const folder = zip.folder("forensify-report")!;

  folder.file("report.html", buildHtmlReport(data));
  folder.file("report.json", buildJsonReport(data));

  const csvValue = (value: string) => `"${value.replace(/"/g, '""')}"`;
  const csvRows = ["Type,Value,Severity,Description", ...data.iocs.map((i) => [i.type, i.value, i.severity, i.description].map(csvValue).join(","))];
  folder.file("indicators_of_compromise.csv", csvRows.join("\n"));

  const ioaCsv = ["Technique,MITRE_ID,Severity,Evidence", ...data.ioas.map((a) => [a.technique, a.mitreId, a.severity, a.evidence.join("; ")].map(csvValue).join(","))];
  folder.file("indicators_of_attack.csv", ioaCsv.join("\n"));

  const tlCsv = ["Timestamp,Severity,Category,Event,Source", ...data.timeline.map((t) => [t.timestamp, t.severity, t.category, t.event, t.source].map(csvValue).join(","))];
  folder.file("forensic_timeline.csv", tlCsv.join("\n"));

  folder.file("hashes.txt", `File: ${data.filename}\nMD5:    ${data.md5}\nSHA1:   ${data.sha1}\nSHA256: ${data.sha256}\nSHA512: ${data.sha512}\n`);

  const readme = `FORENSIFY ANALYSIS REPORT
========================
File: ${data.filename}
Date: ${data.analysisDate}
Heuristic Signal Score: ${data.riskScore}/100

Contents:
- report.html                  Full visual report (open in browser)
- report.json                  Machine-readable JSON report
- indicators_of_compromise.csv IoC list
- indicators_of_attack.csv     IoA / MITRE ATT&CK mappings
- forensic_timeline.csv        Event timeline
- hashes.txt                   Cryptographic file hashes
`;
  folder.file("README.txt", readme);

  const blob = await zip.generateAsync({ type: "blob" });
  saveAs(blob, `forensify-report-${data.filename.replace(/[^a-z0-9]/gi, "_")}-${Date.now()}.zip`);
}
