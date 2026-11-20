interface LandingPageProps {
  onEnter: () => void;
  theme: "dark" | "light";
  onToggleTheme: () => void;
}

const FEATURES = [
  {
    number: "01",
    title: "File integrity",
    description: "Calculate MD5, SHA-1, SHA-256, and SHA-512 digests directly from uploaded bytes.",
  },
  {
    number: "02",
    title: "Artifact profile",
    description: "Inspect file signatures, browser metadata, byte entropy, and readable text structure.",
  },
  {
    number: "03",
    title: "Indicator review",
    description: "Surface text-based IoC candidates and ATT&CK pattern matches with line-level evidence.",
  },
  {
    number: "04",
    title: "Event timeline",
    description: "Review timestamped log lines in sequence with rule-based category and severity labels.",
  },
  {
    number: "05",
    title: "Exportable reports",
    description: "Package the analysis results as HTML, JSON, and CSV for further review.",
  },
  {
    number: "06",
    title: "Privacy by default",
    description: "Files are handled in your browser. The app does not connect to a reputation feed.",
  },
];

function ThemeButton({ theme, onToggleTheme }: Pick<LandingPageProps, "theme" | "onToggleTheme">) {
  const label = theme === "dark" ? "Switch to light appearance" : "Switch to dark appearance";
  return (
    <button
      type="button"
      aria-label={label}
      title={label}
      onClick={onToggleTheme}
      className="w-10 h-10 rounded-lg flex items-center justify-center transition-colors hover:bg-[var(--muted)]"
      style={{ color: "var(--muted-foreground)", border: "1px solid var(--border)" }}
    >
      {theme === "dark" ? (
        <svg aria-hidden="true" viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round">
          <circle cx="12" cy="12" r="4" /><path d="M12 2v2m0 16v2M4.93 4.93l1.42 1.42m11.3 11.3 1.42 1.42M2 12h2m16 0h2M4.93 19.07l1.42-1.42m11.3-11.3 1.42-1.42" />
        </svg>
      ) : (
        <svg aria-hidden="true" viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round">
          <path d="M20.5 14.2A8.5 8.5 0 0 1 9.8 3.5 8.5 8.5 0 1 0 20.5 14.2Z" />
        </svg>
      )}
    </button>
  );
}

export default function LandingPage({ onEnter, theme, onToggleTheme }: LandingPageProps) {
  return (
    <div className="min-h-screen flex flex-col">
      <header className="shrink-0" style={{ borderBottom: "1px solid var(--border)" }}>
        <div className="max-w-[1480px] h-[68px] mx-auto px-4 sm:px-6 lg:px-10 flex items-center justify-between gap-6">
          <a href="#" className="text-[15px] sm:text-base font-semibold tracking-tight" style={{ color: "var(--foreground)" }}>forensify.com</a>
          <nav aria-label="Page navigation" className="hidden sm:flex items-center gap-7 ml-auto mr-2">
            <a href="#capabilities" className="text-xs transition-colors hover:text-[var(--foreground)]" style={{ color: "var(--muted-foreground)" }}>Capabilities</a>
            <a href="#approach" className="text-xs transition-colors hover:text-[var(--foreground)]" style={{ color: "var(--muted-foreground)" }}>Approach</a>
          </nav>
          <ThemeButton theme={theme} onToggleTheme={onToggleTheme} />
        </div>
      </header>

      <main className="flex-1">
        <section className="max-w-[1480px] mx-auto px-4 pt-16 pb-16 sm:px-6 sm:pt-24 sm:pb-24 lg:px-10 lg:pt-28">
          <div className="grid lg:grid-cols-[1.05fr_0.95fr] items-center gap-12 lg:gap-20">
            <div className="max-w-2xl">
              <div className="inline-flex items-center gap-2 text-[11px] font-medium tracking-wide px-3 py-1.5 rounded-full" style={{ color: "var(--primary)", border: "1px solid var(--border)", background: "var(--card)" }}>
                <span className="w-1.5 h-1.5 rounded-full" style={{ background: "var(--primary)" }} />
                Digital forensic triage
              </div>
              <h1 className="mt-7 text-4xl sm:text-5xl lg:text-[64px] leading-[1.08] font-semibold tracking-[-0.045em]">
                Investigate artifacts with clarity.
              </h1>
              <p className="mt-6 max-w-xl text-sm sm:text-base leading-7" style={{ color: "var(--muted-foreground)" }}>
                A focused workspace for file integrity, artifact profiling, text-based indicator review, and event timelines. Your files stay in the browser.
              </p>
              <div className="mt-9 flex flex-wrap items-center gap-3">
                <button
                  type="button"
                  onClick={onEnter}
                  className="px-5 py-3 rounded-lg text-sm font-semibold transition-opacity hover:opacity-90"
                  style={{ background: "var(--primary)", color: "var(--primary-foreground)" }}
                >
                  Open platform <span aria-hidden="true" className="ml-2">→</span>
                </button>
                <a href="#capabilities" className="px-5 py-3 rounded-lg text-sm font-medium transition-colors hover:bg-[var(--muted)]" style={{ color: "var(--foreground)", border: "1px solid var(--border)" }}>
                  Explore capabilities
                </a>
              </div>
              <p className="mt-5 text-xs" style={{ color: "var(--muted-foreground)" }}>No account required · No third-party reputation lookups</p>
            </div>

            <div className="relative">
              <div className="absolute -inset-6 rounded-[32px] opacity-40 blur-3xl pointer-events-none" style={{ background: "radial-gradient(circle, rgba(80,200,178,0.16), transparent 68%)" }} />
              <div className="relative rounded-2xl p-5 sm:p-7" style={{ background: "var(--card)", border: "1px solid var(--border)", boxShadow: "0 24px 80px rgba(0,0,0,0.16)" }}>
                <div className="flex items-center justify-between pb-5" style={{ borderBottom: "1px solid var(--border)" }}>
                  <div>
                    <div className="text-sm font-semibold">Investigation workflow</div>
                    <div className="text-xs mt-1" style={{ color: "var(--muted-foreground)" }}>A clear path from file to evidence</div>
                  </div>
                  <span className="text-[10px] uppercase tracking-wider px-2.5 py-1 rounded-full" style={{ color: "var(--primary)", background: "var(--muted)" }}>Browser-based</span>
                </div>
                <div className="pt-6 space-y-3">
                  {[
                    ["01", "Select an artifact", "Choose a file or load a bundled example"],
                    ["02", "Review measured data", "Hashes, signatures, entropy, and rule matches"],
                    ["03", "Export your findings", "Download structured report files"],
                  ].map(([number, title, description], index) => (
                    <div key={number} className="flex items-start gap-4 rounded-xl p-4" style={{ background: "var(--background)", border: "1px solid var(--border)" }}>
                      <span className="font-mono text-xs mt-0.5" style={{ color: "var(--primary)" }}>{number}</span>
                      <div className="min-w-0 flex-1">
                        <div className="text-sm font-medium">{title}</div>
                        <div className="text-xs mt-1 leading-relaxed" style={{ color: "var(--muted-foreground)" }}>{description}</div>
                      </div>
                      <span className="text-xs mt-0.5" style={{ color: index === 0 ? "var(--primary)" : "var(--muted-foreground)" }}>{index === 0 ? "Start" : "→"}</span>
                    </div>
                  ))}
                </div>
                <div className="flex items-center gap-2 pt-5 mt-5 text-xs" style={{ borderTop: "1px solid var(--border)", color: "var(--muted-foreground)" }}>
                  <svg aria-hidden="true" viewBox="0 0 20 20" width="15" height="15" fill="none" stroke="var(--primary)" strokeWidth="1.5">
                    <path d="M10 2.5 4 5v4.3c0 3.4 2.5 6.4 6 8.2 3.5-1.8 6-4.8 6-8.2V5l-6-2.5Z" /><path d="m7.5 9.7 1.7 1.7 3.5-3.6" />
                  </svg>
                  Files are processed in this browser session.
                </div>
              </div>
            </div>
          </div>
        </section>

        <section id="capabilities" className="scroll-mt-20" style={{ borderTop: "1px solid var(--border)", borderBottom: "1px solid var(--border)", background: "var(--card)" }}>
          <div className="max-w-[1480px] mx-auto px-4 py-16 sm:px-6 sm:py-20 lg:px-10">
            <div className="flex flex-col sm:flex-row sm:items-end justify-between gap-4 mb-9">
              <div>
                <div className="text-[11px] font-mono uppercase tracking-[0.16em]" style={{ color: "var(--primary)" }}>Capabilities</div>
                <h2 className="mt-3 text-2xl sm:text-3xl font-semibold tracking-tight">Tools for evidence review</h2>
              </div>
              <p className="max-w-md text-sm leading-6" style={{ color: "var(--muted-foreground)" }}>Analysis is transparent and rules-based. Findings need analyst validation; they are not a malware verdict.</p>
            </div>
            <div className="grid sm:grid-cols-2 xl:grid-cols-3 gap-3">
              {FEATURES.map((feature) => (
                <article key={feature.number} className="rounded-xl p-5 sm:p-6 transition-colors hover:border-[var(--primary)]" style={{ background: "var(--background)", border: "1px solid var(--border)" }}>
                  <div className="font-mono text-[11px]" style={{ color: "var(--primary)" }}>{feature.number}</div>
                  <h3 className="mt-4 text-sm font-semibold">{feature.title}</h3>
                  <p className="mt-2 text-xs leading-6" style={{ color: "var(--muted-foreground)" }}>{feature.description}</p>
                </article>
              ))}
            </div>
          </div>
        </section>

        <section id="approach" className="scroll-mt-20 max-w-[1480px] mx-auto px-4 py-14 sm:px-6 sm:py-16 lg:px-10">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-5">
            <div>
              <h2 className="text-lg font-semibold">Built for quick, careful triage.</h2>
              <p className="text-xs mt-2 leading-5" style={{ color: "var(--muted-foreground)" }}>
                Text detections use local heuristics. There is no live threat feed, YARA engine, or native event-log parser.
              </p>
            </div>
            <button type="button" onClick={onEnter} className="shrink-0 px-4 py-2.5 rounded-lg text-xs font-semibold" style={{ color: "var(--foreground)", border: "1px solid var(--border)" }}>
              Continue to platform <span aria-hidden="true" className="ml-2">→</span>
            </button>
          </div>
        </section>
      </main>

      <footer className="py-5 px-4 sm:px-6 lg:px-10" style={{ borderTop: "1px solid var(--border)" }}>
        <div className="max-w-[1480px] mx-auto flex flex-col sm:flex-row gap-2 sm:items-center justify-between text-[11px]" style={{ color: "var(--muted-foreground)" }}>
          <span>forensify.com</span>
          <span>Browser-based forensic triage · Heuristic results require review</span>
        </div>
      </footer>
    </div>
  );
}
