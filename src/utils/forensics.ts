export interface IoC {
  type: string;
  value: string;
  severity: "critical" | "high" | "medium" | "low";
  description: string;
  mitreId?: string;
  confidence?: number;
  evidence?: string[];
}

export interface IoA {
  technique: string;
  mitreId: string;
  tactic: string;
  description: string;
  evidence: string[];
  severity: "critical" | "high" | "medium" | "low";
  confidence: number;
}

export interface ForensicTimelineEntry {
  timestamp: string;
  event: string;
  category: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  source: string;
  raw?: string;
}

// Regex patterns
const RE_IPV4 = /\b((?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?))\b/g;
const RE_DOMAIN = /\b([a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z]{2,})+)\b/g;
const RE_URL = /https?:\/\/[^\s"'<>)\]]{8,}/g;
const RE_MD5 = /\b([a-fA-F0-9]{32})\b/g;
const RE_SHA1 = /\b([a-fA-F0-9]{40})\b/g;
const RE_SHA256 = /\b([a-fA-F0-9]{64})\b/g;
const RE_CVE = /\b(CVE-\d{4}-\d{4,7})\b/gi;
const RE_REG = /\b(HK(?:LM|CU|CR|U|CC)\\[^\s"'\n]{4,})\b/g;
const RE_EMAIL = /\b([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})\b/g;
const RE_BASE64 = /\b([A-Za-z0-9+/]{48,}={0,2})\b/g;
const RE_MUTEX = /Global\\{[0-9A-F\-]{8,}}/gi;
const RE_FILEPATH = /[A-Za-z]:\\(?:[^\\<>"|?*\n]{1,260}\\)*[^\\<>"|?*\n]{1,260}/g;

// MITRE ATT&CK mapped attack patterns — ordered by severity
const ATTACK_RULES: {
  pattern: RegExp;
  technique: string;
  tactic: string;
  mitreId: string;
  severity: "critical" | "high" | "medium" | "low";
  confidence: number;
}[] = [
  { pattern: /mimikatz|sekurlsa::|lsass.*dump|procdump.*lsass|wce\.exe/gi, technique: "OS Credential Dumping", tactic: "Credential Access", mitreId: "T1003", severity: "critical", confidence: 95 },
  { pattern: /cobalt.?strike|beacon|cs\.exe|teamserver/gi, technique: "Remote Access Tools (Cobalt Strike)", tactic: "Command and Control", mitreId: "T1219", severity: "critical", confidence: 90 },
  { pattern: /vssadmin.*delete|wbadmin.*delete|bcdedit.*no|shadow.*delete|recover.*disable/gi, technique: "Inhibit System Recovery", tactic: "Impact", mitreId: "T1490", severity: "critical", confidence: 90 },
  { pattern: /wevtutil.*cl|clear.*eventlog|Remove-EventLog|1102.*Security/gi, technique: "Indicator Removal (Log Clearing)", tactic: "Defense Evasion", mitreId: "T1070.001", severity: "critical", confidence: 88 },
  { pattern: /\/c2\/|beacon.*GET|POST.*\/upload.*[0-9]{7}/gi, technique: "Exfiltration Over C2 Channel", tactic: "Exfiltration", mitreId: "T1041", severity: "critical", confidence: 85 },
  { pattern: /meterpreter|reverse.?shell|bind.?shell|nc\s+-[el]|ncat\s+-[el]/gi, technique: "Command Shell / Reverse Shell", tactic: "Execution", mitreId: "T1059", severity: "critical", confidence: 90 },
  { pattern: /powershell.*-enc[odedcommand]?|-EncodedCommand|invoke-expression.*\[convert\]/gi, technique: "PowerShell Obfuscated Execution", tactic: "Execution", mitreId: "T1059.001", severity: "high", confidence: 85 },
  { pattern: /net\s+user.*\/add|useradd\s|adduser\s|New-LocalUser/gi, technique: "Create Account", tactic: "Persistence", mitreId: "T1136", severity: "high", confidence: 88 },
  { pattern: /psexec|wmic.*\/node.*process|schtasks.*\/create|at\s+\d{2}:/gi, technique: "Remote Service Execution", tactic: "Lateral Movement", mitreId: "T1021", severity: "high", confidence: 82 },
  { pattern: /lateral.?movement|LATERAL_MOVEMENT|smb.*sweep|psexec.*\\\\|wmiexec/gi, technique: "Lateral Movement via SMB/WMI", tactic: "Lateral Movement", mitreId: "T1021.002", severity: "high", confidence: 85 },
  { pattern: /net.*localgroup.*admin|Add-LocalGroupMember.*Admin|4732.*Admin/gi, technique: "Account Manipulation (Admin Group)", tactic: "Privilege Escalation", mitreId: "T1098", severity: "high", confidence: 90 },
  { pattern: /HKLM.*CurrentVersion.*Run|HKCU.*Run|schtasks.*\/ru\s+system/gi, technique: "Boot or Logon Autostart Execution", tactic: "Persistence", mitreId: "T1547", severity: "high", confidence: 80 },
  { pattern: /union\s+select|'\s*or\s*'1'\s*=\s*'1|--\s*$|\/\*.*\*\/|sqlmap/gi, technique: "Exploit Public-Facing App (SQLi)", tactic: "Initial Access", mitreId: "T1190", severity: "high", confidence: 88 },
  { pattern: /<script[\s>]|onerror\s*=|javascript:|onload\s*=|XSS|document\.cookie/gi, technique: "Cross-Site Scripting (XSS)", tactic: "Initial Access", mitreId: "T1059.007", severity: "high", confidence: 82 },
  { pattern: /\.\.\/\.\.\/|%2e%2e%2f|\.\.\\\.\.\\|path.*traversal/gi, technique: "Path Traversal", tactic: "Discovery", mitreId: "T1083", severity: "high", confidence: 85 },
  { pattern: /brute.?force|FAIL=auth.*ATTEMPT=[5-9]|failed.*logon.*\d{3,}|password.*spray/gi, technique: "Brute Force / Credential Stuffing", tactic: "Credential Access", mitreId: "T1110", severity: "high", confidence: 80 },
  { pattern: /nmap|PORTSCAN|SYN.*SYN.*SYN.*SYN|masscan|zmap/gi, technique: "Network Service Scanning", tactic: "Discovery", mitreId: "T1046", severity: "medium", confidence: 78 },
  { pattern: /whoami|systeminfo|ipconfig|net\s+view|arp\s+-a|tasklist|hostname/gi, technique: "System Information Discovery", tactic: "Discovery", mitreId: "T1082", severity: "medium", confidence: 70 },
  { pattern: /\.env|config\.php|\.git\/config|wp-config|database\.yml|credentials\.xml/gi, technique: "Credentials In Files", tactic: "Credential Access", mitreId: "T1552", severity: "high", confidence: 75 },
  { pattern: /\(\)\s*\{\s*:;/gi, technique: "ShellShock Exploit (CVE-2014-6271)", tactic: "Initial Access", mitreId: "T1190", severity: "critical", confidence: 95 },
  { pattern: /wget.*\/tmp|curl.*\|.*sh|chmod.*\+x.*\/tmp/gi, technique: "Ingress Tool Transfer", tactic: "Command and Control", mitreId: "T1105", severity: "high", confidence: 82 },
  { pattern: /base64\s+(?:--decode|-d)|frombase64string|(?:-enc(?:odedcommand)?\s+[a-z0-9+/=]{12,})/gi, technique: "Obfuscated Files / Encoded Payload", tactic: "Defense Evasion", mitreId: "T1027", severity: "medium", confidence: 65 },
  { pattern: /4688.*powershell|4688.*cmd\.exe.*\/c|4688.*wscript|4688.*cscript/gi, technique: "Process Creation (Suspicious)", tactic: "Execution", mitreId: "T1059", severity: "medium", confidence: 72 },
  { pattern: /new\s+service|7045.*service|sc\s+create/gi, technique: "Create or Modify System Process", tactic: "Persistence", mitreId: "T1543", severity: "high", confidence: 80 },
];

export function extractIoCs(content: string): IoC[] {
  const seen = new Set<string>();
  const iocs: IoC[] = [];
  const evidenceAt = (index: number) => {
    const lineStart = content.lastIndexOf("\n", index - 1) + 1;
    const lineEnd = content.indexOf("\n", index);
    const line = content.slice(lineStart, lineEnd < 0 ? content.length : lineEnd).trim();
    return [`Line ${content.slice(0, lineStart).split("\n").length}: ${line.slice(0, 180)}`];
  };

  const add = (ioc: IoC, index: number) => {
    const k = `${ioc.type}:${ioc.value}`;
    if (!seen.has(k)) {
      seen.add(k);
      iocs.push({ ...ioc, evidence: evidenceAt(index) });
    }
  };

  // IPs
  for (const m of content.matchAll(RE_IPV4)) {
    const ip = m[1];
    const [a, b] = ip.split(".").map(Number);
    const isPrivateOrSpecial =
      a === 0 || a === 10 || a === 127 || a >= 224 ||
      (a === 100 && b >= 64 && b <= 127) ||
      (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      (a === 192 && b === 0 && (ip.split(".")[2] === "0" || ip.split(".")[2] === "2")) ||
      (a === 198 && (b === 18 || b === 19 || (b === 51 && ip.split(".")[2] === "100"))) ||
      (a === 203 && b === 0 && ip.split(".")[2] === "113");
    if (isPrivateOrSpecial) continue;
    add({
      type: "IP Address",
      value: ip,
      severity: "low",
      description: "External address observed; no reputation lookup was performed",
      confidence: 20,
    }, m.index ?? 0);
  }

  // URLs first so suspicious paths can be retained as a single indicator.
  for (const m of content.matchAll(RE_URL)) {
    const url = m[0].replace(/[.,;:!?]+$/, "");
    if (url.length > 200) continue;
    let hostname = "";
    try {
      hostname = new URL(url).hostname;
    } catch {
      continue;
    }
    if (/\/c2\/|beacon|shell\.php|malware|exploit/i.test(url)) {
      add({
        type: "Suspicious URL",
        value: url,
        severity: "medium",
        description: `URL path matches a local heuristic; host ${hostname} was not reputation-checked`,
        confidence: 55,
      }, m.index ?? 0);
    }
  }

  // Domains
  for (const m of content.matchAll(RE_DOMAIN)) {
    const d = m[1].toLowerCase();
    if (/^\d+\.\d+\.\d+\.\d+$/.test(d)) continue;
    if (d.split(".").length < 2) continue;
    const suspTLD = /\.(ru|xyz|tk|ml|ga|cf|pw|cc|su|to)$/.test(d);
    const suspPattern = /(?:windows|microsoft|security|update).*(?:cdn|alert|login|support)|(?:cdn|alert|login|support).*(?:windows|microsoft|security|update)/i.test(d);
    if (suspPattern) add({
      type: "Domain",
      value: d,
      severity: "medium",
      description: "Name resembles a trusted-service lure; heuristic only, not a reputation match",
      confidence: 55,
    }, m.index ?? 0);
    else if (suspTLD) add({
      type: "Domain",
      value: d,
      severity: "low",
      description: "Domain uses a TLD selected by a local heuristic; this alone does not establish maliciousness",
      confidence: 25,
    }, m.index ?? 0);
  }

  // Hashes — SHA256 first, then SHA1, then MD5 to avoid overlaps
  const sha256s: string[] = [];
  for (const m of content.matchAll(RE_SHA256)) {
    sha256s.push(m[1]);
    add({ type: "SHA-256 Hash", value: m[1], severity: "low", description: "Hash found in text; no reputation lookup was performed", confidence: 15 }, m.index ?? 0);
  }
  const sha1s: string[] = [];
  for (const m of content.matchAll(RE_SHA1)) {
    if (sha256s.some((s: string) => s.toLowerCase().includes(m[1].toLowerCase()))) continue;
    sha1s.push(m[1]);
    add({ type: "SHA-1 Hash", value: m[1], severity: "low", description: "Hash found in text; no reputation lookup was performed", confidence: 15 }, m.index ?? 0);
  }
  for (const m of content.matchAll(RE_MD5)) {
    if (sha256s.some((s) => s.toLowerCase().includes(m[1].toLowerCase())) || sha1s.some((s) => s.toLowerCase() === m[1].toLowerCase())) continue;
    add({ type: "MD5 Hash", value: m[1], severity: "low", description: "Hash found in text; no reputation lookup was performed", confidence: 15 }, m.index ?? 0);
  }

  // CVEs
  for (const m of content.matchAll(RE_CVE)) {
    add({ type: "CVE", value: m[1].toUpperCase(), severity: "low", description: "Vulnerability identifier reference; exploitability was not assessed", confidence: 20 }, m.index ?? 0);
  }

  // Registry keys
  for (const m of content.matchAll(RE_REG)) {
    const isPersistence = /Run|RunOnce|Services|Startup/i.test(m[1]);
    add({ type: "Registry Key", value: m[1], severity: isPersistence ? "medium" : "low", description: isPersistence ? "Persistence-related registry location; surrounding context is required" : "Registry key reference", confidence: isPersistence ? 55 : 20 }, m.index ?? 0);
  }

  // Mutexes
  for (const m of content.matchAll(RE_MUTEX)) {
    add({ type: "Mutex", value: m[0], severity: "low", description: "Named mutex reference; no reputation lookup was performed", confidence: 20 }, m.index ?? 0);
  }

  // Suspicious file paths
  for (const m of content.matchAll(RE_FILEPATH)) {
    const p = m[0];
    if (/\\temp\\|\\tmp\\|\\appdata\\local\\temp|\\\$recycle/i.test(p)) {
      add({ type: "Suspicious File Path", value: p, severity: "medium", description: "Path uses a user-writable temporary location; execution was not confirmed", confidence: 50 }, m.index ?? 0);
    }
  }

  // Base64 blobs (large ones only)
  for (const m of content.matchAll(RE_BASE64)) {
    if (m[1].length > 80) {
      add({ type: "Base64 Candidate", value: m[1].slice(0, 80) + "…", severity: "low", description: "Long Base64-like string; content was not decoded or executed", confidence: 25 }, m.index ?? 0);
    }
  }

  return iocs.sort((a, b) => {
    const o = { critical: 0, high: 1, medium: 2, low: 3 };
    return o[a.severity] - o[b.severity];
  });
}

export function detectIoAs(content: string): IoA[] {
  const found = new Map<string, IoA>();
  for (const rule of ATTACK_RULES) {
    const matches: RegExpMatchArray[] = [];
    for (const match of content.matchAll(rule.pattern)) {
      matches.push(match);
      if (matches.length === 4) break;
    }
    if (matches.length === 0) continue;
    if (!found.has(rule.mitreId)) {
      found.set(rule.mitreId, {
        technique: rule.technique,
        mitreId: rule.mitreId,
        tactic: rule.tactic,
        description: `${rule.tactic} technique detected in artifact`,
        evidence: [...new Set(matches.slice(0, 4).map((match) => {
          const index = match.index ?? 0;
          const lineStart = content.lastIndexOf("\n", index - 1) + 1;
          const lineEnd = content.indexOf("\n", index);
          const line = content.slice(lineStart, lineEnd < 0 ? content.length : lineEnd).trim();
          const lineNumber = content.slice(0, lineStart).split("\n").length;
          return `Line ${lineNumber}: ${line.slice(0, 180)}`;
        }))],
        severity: rule.severity,
        confidence: rule.confidence,
      });
    }
  }
  const result = Array.from(found.values());
  result.sort((a, b) => {
    const o = { critical: 0, high: 1, medium: 2, low: 3 };
    return o[a.severity] - o[b.severity] || b.confidence - a.confidence;
  });
  return result;
}

export function buildTimeline(content: string, filename: string): ForensicTimelineEntry[] {
  const entries: ForensicTimelineEntry[] = [];
  const lines = content.split("\n").filter((l) => l.trim().length > 10);

  // Multiple timestamp format parsers
  const parsers: { re: RegExp; extract: (m: RegExpMatchArray) => string }[] = [
    { re: /(\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2})/, extract: (m) => m[1] },
    { re: /\[(\d{2}\/\w{3}\/\d{4}:\d{2}:\d{2}:\d{2})/, extract: (m) => m[1] },
    { re: /^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})/, extract: (m) => m[1] },
    { re: /(\d{2}\/\d{2}\/\d{4}\s+\d{2}:\d{2}:\d{2})/, extract: (m) => m[1] },
  ];

  for (const line of lines) {
    let timestamp = "";
    for (const p of parsers) {
      const m = line.match(p.re);
      if (m) { timestamp = p.extract(m); break; }
    }
    if (!timestamp) continue;

    let severity: ForensicTimelineEntry["severity"] = "info";
    let category = "General";

    if (/mimikatz|vssadmin.*delete|wevtutil.*cl|1102.*cleared|shellshock|shellcode/i.test(line)) {
      severity = "critical"; category = "Critical Event";
    } else if (/cobalt|meterpreter|reverse.*shell|psexec.*\\\\|lateral/i.test(line)) {
      severity = "critical"; category = "Attack Technique";
    } else if (/FAIL=auth|failed.*logon|4625|4688.*suspicious|warning|exploit|sqlmap|xss/i.test(line)) {
      severity = "high"; category = "Suspicious Activity";
    } else if (/PORTSCAN|SWEEP|nmap|masscan|scan/i.test(line)) {
      severity = "medium"; category = "Reconnaissance";
    } else if (/4688|new.*process|process.*created/i.test(line)) {
      severity = "medium"; category = "Process Execution";
    } else if (/success|4624|logged.*on|authenticated|200\s/i.test(line)) {
      severity = "low"; category = "Authentication";
    } else if (/4698|schtasks|service.*install|7045/i.test(line)) {
      severity = "high"; category = "Persistence";
    } else if (/4657|registry.*modified|HKLM|HKCU/i.test(line)) {
      severity = "high"; category = "Registry Activity";
    } else if (/4663|file.*access|read.*file|write.*file/i.test(line)) {
      severity = "low"; category = "File Access";
    } else if (/connect|ESTABLISHED|TCP|UDP/i.test(line)) {
      severity = "info"; category = "Network";
    }

    entries.push({ timestamp, event: line.trim().slice(0, 250), category, severity, source: filename });
  }

  return entries.sort((a, b) => a.timestamp.localeCompare(b.timestamp));
}

export function severityColor(sev: string): string {
  return ({ critical: "#ef4444", high: "#f97316", medium: "#eab308", low: "#22c55e", info: "#525252" } as Record<string, string>)[sev] ?? "#525252";
}

export function severityBg(sev: string): string {
  return ({
    critical: "bg-red-500/10 text-red-400 border-red-500/20",
    high: "bg-orange-500/10 text-orange-400 border-orange-500/20",
    medium: "bg-yellow-500/10 text-yellow-400 border-yellow-500/20",
    low: "bg-green-500/10 text-green-400 border-green-500/20",
    info: "bg-neutral-500/10 text-neutral-400 border-neutral-500/20",
  } as Record<string, string>)[sev] ?? "bg-neutral-500/10 text-neutral-400 border-neutral-500/20";
}
