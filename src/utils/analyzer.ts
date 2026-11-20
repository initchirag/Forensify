import { computeMD5Bytes, computeSHABytes, formatFileSize } from "@/utils/crypto";
import { buildTimeline, detectIoAs, extractIoCs, type ForensicTimelineEntry, type IoA, type IoC } from "@/utils/forensics";
import { computeRiskScore } from "@/utils/report";

const MAX_TEXT_PREVIEW = 1800;

export interface ArtifactAnalysis {
  filename: string;
  size: number;
  formattedSize: string;
  reportedType: string;
  detectedType: string;
  extension: string;
  lastModified: string;
  analyzedAt: string;
  durationMs: number;
  hashes: { md5: string; sha1: string; sha256: string; sha512: string };
  entropy: number;
  isText: boolean;
  textPreview: string;
  lineCount: number;
  iocs: IoC[];
  ioas: IoA[];
  timeline: ForensicTimelineEntry[];
  riskScore: number;
}

export interface ArtifactContentProfile {
  detectedType: string;
  isText: boolean;
  text: string;
  entropy: number;
  lineCount: number;
}

function detectFileType(bytes: Uint8Array): string {
  const startsWith = (...signature: number[]) => signature.every((byte, index) => bytes[index] === byte);
  if (startsWith(0x25, 0x50, 0x44, 0x46, 0x2d)) return "application/pdf";
  if (startsWith(0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a)) return "image/png";
  if (startsWith(0xff, 0xd8, 0xff)) return "image/jpeg";
  if (startsWith(0x47, 0x49, 0x46, 0x38)) return "image/gif";
  if (startsWith(0x42, 0x4d)) return "image/bmp";
  if (startsWith(0x50, 0x4b, 0x03, 0x04) || startsWith(0x50, 0x4b, 0x05, 0x06)) return "application/zip";
  if (startsWith(0x1f, 0x8b)) return "application/gzip";
  if (startsWith(0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c)) return "application/x-7z-compressed";
  if (startsWith(0x4d, 0x5a)) return "application/vnd.microsoft.portable-executable";
  if (startsWith(0x7f, 0x45, 0x4c, 0x46)) return "application/x-elf";
  return "unknown";
}

function isLikelyText(bytes: Uint8Array): boolean {
  const sampleSize = Math.min(bytes.length, 8192);
  if (sampleSize === 0) return true;
  let controlBytes = 0;
  for (let i = 0; i < sampleSize; i++) {
    const byte = bytes[Math.floor(i * bytes.length / sampleSize)];
    if (byte === 0 || (byte < 0x20 && byte !== 0x09 && byte !== 0x0a && byte !== 0x0d && byte !== 0x0c)) {
      controlBytes++;
    }
  }
  return controlBytes / sampleSize < 0.01;
}

export async function readArtifactText(file: File): Promise<string | null> {
  const profile = await profileArtifact(file);
  return profile.isText ? profile.text : null;
}

export async function profileArtifact(file: File): Promise<ArtifactContentProfile> {
  const bytes = new Uint8Array(await file.arrayBuffer());
  const detectedType = detectFileType(bytes);
  const isText = detectedType === "unknown" && isLikelyText(bytes);
  const text = isText ? new TextDecoder().decode(bytes) : "";

  return {
    detectedType,
    isText,
    text,
    entropy: calculateEntropy(bytes),
    lineCount: isText && text.length > 0 ? text.split(/\r\n|\r|\n/).length : 0,
  };
}

function calculateEntropy(bytes: Uint8Array): number {
  if (bytes.length === 0) return 0;
  const counts = new Uint32Array(256);
  for (const byte of bytes) counts[byte]++;
  let entropy = 0;
  for (const count of counts) {
    if (count === 0) continue;
    const probability = count / bytes.length;
    entropy -= probability * Math.log2(probability);
  }
  return entropy;
}

export async function analyzeArtifact(file: File): Promise<ArtifactAnalysis> {
  const startedAt = performance.now();
  const buffer = await file.arrayBuffer();
  const bytes = new Uint8Array(buffer);
  const reportedType = file.type || "unknown";
  const detectedType = detectFileType(bytes);
  const isText = detectedType === "unknown" && isLikelyText(bytes);
  const text = isText ? new TextDecoder().decode(bytes) : "";

  const [sha1, sha256, sha512] = await Promise.all([
    computeSHABytes(bytes, "SHA-1"),
    computeSHABytes(bytes, "SHA-256"),
    computeSHABytes(bytes, "SHA-512"),
  ]);
  const iocs = isText ? extractIoCs(text) : [];
  const ioas = isText ? detectIoAs(text) : [];
  const timeline = isText ? buildTimeline(text, file.name) : [];
  const extension = file.name.includes(".") ? file.name.split(".").pop()?.toLowerCase() || "" : "";

  return {
    filename: file.name,
    size: file.size,
    formattedSize: formatFileSize(file.size),
    reportedType,
    detectedType,
    extension,
    lastModified: Number.isFinite(file.lastModified) ? new Date(file.lastModified).toISOString() : "Unavailable",
    analyzedAt: new Date().toISOString(),
    durationMs: Math.round(performance.now() - startedAt),
    hashes: { md5: computeMD5Bytes(bytes), sha1, sha256, sha512 },
    entropy: calculateEntropy(bytes),
    isText,
    textPreview: text.slice(0, MAX_TEXT_PREVIEW),
    lineCount: isText && text.length > 0 ? text.split(/\r\n|\r|\n/).length : 0,
    iocs,
    ioas,
    timeline,
    riskScore: computeRiskScore(iocs, ioas),
  };
}
