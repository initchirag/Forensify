import { lazy, Suspense, useState } from "react";
import LandingPage from "@/components/LandingPage";

const Dashboard = lazy(() => import("@/components/Dashboard"));
const HashAnalyzer = lazy(() => import("@/components/tools/HashAnalyzer"));
const MetadataExtractor = lazy(() => import("@/components/tools/MetadataExtractor"));
const IoCDetector = lazy(() => import("@/components/tools/IoCDetector"));
const TimelineViewer = lazy(() => import("@/components/tools/TimelineViewer"));
const ReportGenerator = lazy(() => import("@/components/tools/ReportGenerator"));
const SamplesPanel = lazy(() => import("@/components/tools/SamplesPanel"));

type Tab = "overview" | "ioc" | "timeline" | "report" | "hash" | "metadata" | "samples";
type Theme = "dark" | "light";

const TABS: { id: Tab; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "ioc", label: "Indicators" },
  { id: "timeline", label: "Timeline" },
  { id: "report", label: "Reports" },
  { id: "hash", label: "Hashes" },
  { id: "metadata", label: "Metadata" },
  { id: "samples", label: "Examples" },
];

function ThemeToggle({ theme, onToggle }: { theme: Theme; onToggle: () => void }) {
  const label = theme === "dark" ? "Switch to light appearance" : "Switch to dark appearance";
  return (
    <button
      type="button"
      aria-label={label}
      title={label}
      onClick={onToggle}
      className="w-10 h-10 shrink-0 rounded-lg flex items-center justify-center transition-colors hover:bg-[var(--muted)]"
      style={{ border: "1px solid var(--border)", color: "var(--muted-foreground)" }}
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

export default function App() {
  const [theme, setTheme] = useState<Theme>("dark");
  const [page, setPage] = useState<"landing" | "platform">("landing");
  const [activeTab, setActiveTab] = useState<Tab>("overview");
  const toggleTheme = () => setTheme((current) => current === "dark" ? "light" : "dark");

  if (page === "landing") {
    return (
      <div className={`${theme === "light" ? "light" : ""} min-h-full`} style={{ background: "var(--background)", color: "var(--foreground)" }}>
        <LandingPage theme={theme} onToggleTheme={toggleTheme} onEnter={() => setPage("platform")} />
      </div>
    );
  }

  return (
    <div className={`${theme === "light" ? "light" : ""} h-full flex flex-col`} style={{ background: "var(--background)", color: "var(--foreground)" }}>
      <header className="sticky top-0 z-30 shrink-0" style={{ background: "var(--background)", borderBottom: "1px solid var(--border)" }}>
        <div className="max-w-[1480px] mx-auto h-[68px] px-4 sm:px-6 flex items-center gap-4">
          <button
            type="button"
            onClick={() => setActiveTab("overview")}
            className="shrink-0 text-[15px] sm:text-base font-semibold tracking-tight"
            style={{ color: "var(--foreground)" }}
          >
            forensify.com
          </button>
          <nav aria-label="Forensic tools" className="flex-1 min-w-0 h-full flex items-stretch justify-center gap-0.5 overflow-x-auto hide-scrollbar">
            {TABS.map((tab) => (
              <button
                type="button"
                key={tab.id}
                aria-current={activeTab === tab.id ? "page" : undefined}
                onClick={() => setActiveTab(tab.id)}
                className="relative shrink-0 px-2.5 sm:px-3.5 text-xs sm:text-[13px] transition-colors"
                style={{
                  color: activeTab === tab.id ? "var(--foreground)" : "var(--muted-foreground)",
                  borderBottom: activeTab === tab.id ? "2px solid var(--primary)" : "2px solid transparent",
                }}
              >
                {tab.label}
              </button>
            ))}
          </nav>
          <ThemeToggle theme={theme} onToggle={toggleTheme} />
        </div>
      </header>

      <main className="flex-1 min-h-0 overflow-y-auto">
        <div className="max-w-[1480px] mx-auto px-4 py-6 sm:px-6 sm:py-9 lg:px-10">
          <Suspense fallback={<div className="py-16 text-center text-sm" style={{ color: "var(--muted-foreground)" }}>Loading workspace…</div>}>
            <div className={activeTab === "overview" ? "" : "hidden"}><Dashboard /></div>
            {activeTab === "ioc" && <IoCDetector />}
            {activeTab === "timeline" && <TimelineViewer />}
            {activeTab === "report" && <ReportGenerator />}
            {activeTab === "hash" && <HashAnalyzer />}
            {activeTab === "metadata" && <MetadataExtractor />}
            {activeTab === "samples" && <SamplesPanel />}
          </Suspense>
        </div>
      </main>
    </div>
  );
}
