import { useEffect, useMemo, useState } from "react";
import {
  ResponsiveContainer,
  BarChart,
  Bar,
  CartesianGrid,
  XAxis,
  YAxis,
  Tooltip,
  PieChart,
  Pie,
  Cell,
  LineChart,
  Line,
  RadarChart,
  Radar,
  PolarGrid,
  PolarAngleAxis,
  PolarRadiusAxis,
} from "recharts";

/* ------------------------------------------------------------------ */
/*  TYPES                                                               */
/* ------------------------------------------------------------------ */
type Trend = { date: string; p1: number; p2: number; p3: number };

type Run = {
  ID: string;
  /* NetWeaver field names (from ZI_ATC_RUNS) */
  scheduledBy?: string;
  scheduledSys?: string;
  runDate?: string;
  central?: boolean; // normalised from 'X'/'' after fetch
  /* BTP mock field names (kept for backward compat) */
  user?: string;
  system?: string;
  date?: string;
  /* shared */
  series?: string;
  title?: string;
  p1: number;
  p2: number;
  p3: number;
};

type KPI = { p1?: number; p2?: number; p3?: number; health?: number };
type AiMessage = { role: string; content: string };

/* ------------------------------------------------------------------ */
/*  CONSTANTS                                                           */
/* ------------------------------------------------------------------ */
const COLORS = ["#ef4444", "#f59e0b", "#3b82f6"];

const CONNECTIONS = {
  btp: {
    label: "BTP",
    icon: "☁️",
    baseUrl: "/odata/v4/atc",
    description: "SAP BTP CAP Service",
  },
  netweaver: {
    label: "NetWeaver",
    icon: "🖥️",
    baseUrl: "/sap/opu/odata4/sap/zui_atc_monitor_o4_bnd/srvd_a2x/sap/zui_atc_monitor_o4/0001",
    description: "ABAP NetWeaver OData V4",
  },
};

const SUGGESTED_QUESTIONS = [
  "Which system has the highest compliance risk?",
  "What should I fix before the next release?",
  "Summarize P1 findings for management",
  "What is the trend over the last 30 days?",
  "Are there any regulatory risks in production?",
  "Which run series is most problematic?",
];

/* ------------------------------------------------------------------ */
/*  APP                                                                 */
/* ------------------------------------------------------------------ */
export default function App() {
  const [tab, setTab] = useState("overview");
  const [collapsed, setCollapsed] = useState(false);
  const [loading, setLoading] = useState(true);
  const [theme, setTheme] = useState("light");

  const [runs, setRuns] = useState<Run[]>([]);
  const [kpi, setKpi] = useState<KPI>({});
  const [selectedRun, setSelectedRun] = useState<Run | null>(null);
  const [drawerOpen, setDrawerOpen] = useState(false);

  const [filters, setFilters] = useState({
    system: "",
    series: "",
    title: "",
    user: "",
    dateFrom: "",
    dateTo: "",
    period: 7,
    scheduleMode: "period",
    visibility: "any",
    baselineOnly: false,
  });

  /* AI state */
  const [aiOpen, setAiOpen] = useState(false);
  const [aiLoading, setAiLoading] = useState(false);
  const [aiMessages, setAiMessages] = useState<AiMessage[]>([]);
  const [aiInput, setAiInput] = useState("");
  const [aiView, setAiView] = useState<"manager" | "developer">("manager");

  /* connection */
  const [connection, setConnection] = useState<"btp" | "netweaver">("btp");

  /* ---------------------------------------------------------------- */
  /*  THEME                                                             */
  /* ---------------------------------------------------------------- */
  useEffect(() => {
    const saved = localStorage.getItem("theme");
    if (saved) setTheme(saved);
  }, []);

  useEffect(() => {
    document.documentElement.setAttribute("data-theme", theme);
    localStorage.setItem("theme", theme);
  }, [theme]);

  /* ---------------------------------------------------------------- */
  /*  FETCH HELPER                                                      */
  /* Returns [] on any error or non-OK response so callers are safe.  */
  /* ---------------------------------------------------------------- */
  const fetchData = async (path: string): Promise<any[]> => {
    const baseUrl = CONNECTIONS[connection].baseUrl;
    const url = `${baseUrl}${path}`;
    try {
      const res = await fetch(url);
      if (!res.ok) return [];
      const json = await res.json();
      const result = json.value ?? json;
      return Array.isArray(result) ? result : [];
    } catch (err) {
      console.error("Fetch failed:", url, err);
      return [];
    }
  };

  /* ---------------------------------------------------------------- */
  /*  FILTER QUERY BUILDER                                              */
  /*  Uses the actual OData field names from ZI_ATC_RUNS.              */
  /* ---------------------------------------------------------------- */
  const buildFilterQuery = (f: typeof filters): string => {
    const conds: string[] = [];
    if (f.system) conds.push(`contains(scheduledSys,'${f.system}')`);
    if (f.series) conds.push(`contains(series,'${f.series}')`);
    if (f.title)  conds.push(`contains(title,'${f.title}')`);
    if (f.user)   conds.push(`contains(scheduledBy,'${f.user}')`);
    if (f.scheduleMode === "date") {
      // Single-quoted date literals are accepted by both BTP CAP and NetWeaver OData V4
      if (f.dateFrom) conds.push(`runDate ge '${f.dateFrom}'`);
      if (f.dateTo)   conds.push(`runDate le '${f.dateTo}'`);
    }
    return conds.length ? `?$filter=${conds.join(" and ")}` : "";
  };

  /* ---------------------------------------------------------------- */
  /*  LOAD                                                              */
  /* ---------------------------------------------------------------- */
  const load = async (overrideFilters?: typeof filters) => {
    setLoading(true);
    const f = overrideFilters ?? filters;
    const query = buildFilterQuery(f);

    // Only /Runs is mandatory. The other endpoints don't exist on NetWeaver
    // and return [] safely via fetchData. Charts are computed from filteredRuns.
    const [r, k] = await Promise.all([
      fetchData(`/Runs${query}`),
      fetchData(`/OverviewKPI`),
    ]);

    // ---- Normalise field names ----
    // NetWeaver returns: scheduledBy, scheduledSys, runDate, central ('X'/'')
    // BTP mock returns:  user, system, date, central (boolean)
    // After normalisation both are available as user/system/date/central(boolean)
    const normalised = r.map((run: any): Run => ({
      ...run,
      user:    run.scheduledBy  ?? run.user   ?? "",
      system:  run.scheduledSys ?? run.system  ?? "",
      date:    run.runDate      ?? run.date    ?? "",
      central: run.central === true || run.central === "X",
    }));

    setRuns(normalised);
    setKpi(Array.isArray(k) && k.length > 0 ? k[0] : {});
    setLoading(false);
  };

  // Initial load + reload when connection changes
  useEffect(() => { load(); }, [connection]); // eslint-disable-line react-hooks/exhaustive-deps

  /* ---------------------------------------------------------------- */
  /*  CLIENT-SIDE FILTERING (filteredRuns)                             */
  /*  This refines the server-returned set locally.                    */
  /* ---------------------------------------------------------------- */
  const filteredRuns = useMemo(() => {
    let data = [...runs];

    if (filters.system.trim())
      data = data.filter((r) =>
        (r.system || "").toLowerCase().includes(filters.system.toLowerCase())
      );
    if (filters.series.trim())
      data = data.filter((r) =>
        (r.series || "").toLowerCase().includes(filters.series.toLowerCase())
      );
    if (filters.title.trim())
      data = data.filter((r) =>
        (r.title || "").toLowerCase().includes(filters.title.toLowerCase())
      );
    if (filters.user.trim())
      data = data.filter((r) =>
        (r.user || "").toLowerCase().includes(filters.user.toLowerCase())
      );

    if (filters.scheduleMode === "date") {
      if (filters.dateFrom)
        data = data.filter((r) => (r.date || "") >= filters.dateFrom);
      if (filters.dateTo)
        data = data.filter((r) => (r.date || "") <= filters.dateTo);
    }
    if (filters.scheduleMode === "period" && filters.period > 0) {
      const cutoff = Date.now() - filters.period * 86_400_000;
      data = data.filter((r) => new Date(r.date || 0).getTime() >= cutoff);
    }

    // central uses real data field (boolean after normalisation)
    if (filters.visibility === "central")
      data = data.filter((r) => r.central === true);
    if (filters.visibility === "noncentral")
      data = data.filter((r) => r.central !== true);

    // baselineOnly: satc_ac_resulth has no baseline flag — filter is a no-op
    // until the backend provides such a field.

    return data;
  }, [runs, filters]);

  /* ---------------------------------------------------------------- */
  /*  KPI COMPUTATIONS (all derived from filteredRuns)                 */
  /* ---------------------------------------------------------------- */
  const totalRuns = filteredRuns.length;

  const totalP1 = useMemo(
    () => filteredRuns.reduce((a, r) => a + (r.p1 || 0), 0),
    [filteredRuns]
  );
  const totalP2 = useMemo(
    () => filteredRuns.reduce((a, r) => a + (r.p2 || 0), 0),
    [filteredRuns]
  );
  const totalP3 = useMemo(
    () => filteredRuns.reduce((a, r) => a + (r.p3 || 0), 0),
    [filteredRuns]
  );
  const healthScore = useMemo(() => {
    const total = totalP1 + totalP2 + totalP3;
    if (total === 0) return 100;
    const weighted = (totalP1 * 3 + totalP2 * 1.5 + totalP3) / total;
    return Math.max(0, Math.round(100 - weighted * 10));
  }, [totalP1, totalP2, totalP3]);

  /* ---------------------------------------------------------------- */
  /*  CHART DATA (all derived from filteredRuns)                       */
  /* ---------------------------------------------------------------- */
  const chartTrend = useMemo(() => {
    const map: Record<string, Trend> = {};
    filteredRuns.forEach((r) => {
      const d = r.date || "unknown";
      if (!map[d]) map[d] = { date: d, p1: 0, p2: 0, p3: 0 };
      map[d].p1 += r.p1 || 0;
      map[d].p2 += r.p2 || 0;
      map[d].p3 += r.p3 || 0;
    });
    return Object.values(map).sort((a, b) => a.date.localeCompare(b.date));
  }, [filteredRuns]);

  const chartSeries = useMemo(() => {
    const map: Record<string, number> = {};
    filteredRuns.forEach((r) => {
      const key = r.series || "Unknown";
      map[key] = (map[key] || 0) + 1;
    });
    return Object.entries(map).map(([name, value]) => ({ name, value }));
  }, [filteredRuns]);

  const chartCategories = useMemo(
    () => [
      { name: "P1", value: totalP1 },
      { name: "P2", value: totalP2 },
      { name: "P3", value: totalP3 },
    ],
    [totalP1, totalP2, totalP3]
  );

  const chartQuality = useMemo(
    () =>
      chartTrend.map((r) => ({
        date: r.date,
        score: Math.max(0, 100 - Math.round((r.p1 * 5 + r.p2 * 2 + r.p3) / 5)),
      })),
    [chartTrend]
  );

  const chartHeatmap = useMemo(
    () =>
      filteredRuns.slice(0, 14).map((r) => ({
        value: r.p1 * 10 + r.p2 * 3 + r.p3,
      })),
    [filteredRuns]
  );

  /* ---------------------------------------------------------------- */
  /*  AI ANALYSIS                                                       */
  /* ---------------------------------------------------------------- */
  const generateAiAnalysis = (
    userMessage: string | undefined,
    view: "manager" | "developer",
    snap: {
      runs: Run[];
      p1: number; p2: number; p3: number;
      score: number; period: number; system: string;
      series: { name: string; value: number }[];
      trend: Trend[];
      totalRuns: number;
    }
  ): string => {
    const topSeries = [...snap.series].sort((a, b) => b.value - a.value)[0];
    const sysMap: Record<string, number> = {};
    snap.runs.forEach((r) => {
      const s = r.system || "Unknown";
      sysMap[s] = (sysMap[s] || 0) + r.p1;
    });
    const topSystem = Object.entries(sysMap).sort((a, b) => b[1] - a[1])[0];
    const prdP1 = snap.runs
      .filter((r) => (r.system || "").includes("PRD"))
      .reduce((a, r) => a + (r.p1 || 0), 0);
    const riskLevel =
      snap.p1 > 500 ? "CRITICAL" : snap.p1 > 200 ? "HIGH" : snap.p1 > 50 ? "MEDIUM" : "LOW";
    const riskColor =
      riskLevel === "CRITICAL" ? "🔴" : riskLevel === "HIGH" ? "🟠" : riskLevel === "MEDIUM" ? "🟡" : "🟢";
    const trendDir =
      snap.trend.length > 1
        ? snap.trend[snap.trend.length - 1].p1 > snap.trend[0].p1
          ? "increasing ⬆️"
          : "decreasing ⬇️"
        : "stable";

    if (userMessage) {
      const q = userMessage.toLowerCase();
      if (q.includes("system") && q.includes("risk"))
        return topSystem
          ? `The highest risk system is **${topSystem[0]}** with ${topSystem[1]} P1 critical findings.\n\nIn a banking/insurance context, P1 findings in ${topSystem[0]} represent potential compliance violations that must be remediated before the next transport cycle.`
          : "No system-specific data available for the current filter selection.";
      if (q.includes("fix") || q.includes("release") || q.includes("before"))
        return `## Pre-Release Checklist\n\n1. **Resolve all P1 findings in PRD_GRP** — ${prdP1} critical findings currently open.\n2. **Review ${topSeries?.name || "DBB_RELEASE"} run results** — highest concentration of findings.\n3. **Security check failures** — must be fixed regardless of priority.\n4. **Transport to CON** — run a full ATC check on consolidation before promoting to production.\n\nEstimated remediation effort: ${Math.ceil(snap.p1 / 10)} developer days for P1 items only.`;
      if (q.includes("trend"))
        return `## Trend Analysis — Last ${snap.period} Days\n\nP1 critical findings are **${trendDir}** over the analyzed period.\n\n- Start of period: ${snap.trend[0]?.p1 || 0} P1 findings\n- End of period: ${snap.trend[snap.trend.length - 1]?.p1 || 0} P1 findings\n- Total runs analyzed: ${snap.totalRuns}`;
      if (q.includes("production") || q.includes("prd") || q.includes("regulat"))
        return `## Production & Regulatory Risk Assessment\n\n${prdP1 > 0 ? `🔴 **ALERT: ${prdP1} P1 findings detected in production systems.**` : "🟢 No P1 findings in production systems currently."}\n\n- **GDPR/Data Privacy**: Unauthorized data access findings are reportable incidents\n- **SOX Compliance**: P1 findings in FI/CO objects must be remediated within 30 days`;
      if (q.includes("series") || q.includes("problematic"))
        return `## Run Series Analysis\n\nMost problematic series: **${topSeries?.name || "N/A"}** with ${topSeries?.value || 0} runs.\n\n${snap.series.map((s, i) => `${i + 1}. ${s.name}: ${s.value} runs`).join("\n")}`;
      return `Based on current data (${snap.totalRuns} runs, ${snap.p1} P1, ${snap.p2} P2 findings):\n\nTry asking:\n- System or series risk levels\n- Pre-release fix priorities\n- Regulatory compliance status\n- Trend analysis over time`;
    }

    if (view === "manager") {
      return `## Executive Summary\n\nYour SAP code quality posture is currently ${riskColor} **${riskLevel} RISK**. Across ${snap.totalRuns} ATC check runs in the last ${snap.period} days, ${snap.p1} critical compliance issues were identified.\n\n${prdP1 > 0 ? `⚠️ **${prdP1} critical findings exist in production systems** — direct regulatory exposure.` : "✅ Production systems are currently clear of critical findings."}\n\n## Risk Assessment\n\n- **Regulatory Risk**: ${snap.p1 > 200 ? "HIGH — Immediate escalation recommended" : snap.p1 > 50 ? "MEDIUM — Remediation plan required" : "LOW — Continue monitoring"}\n- **Audit Readiness**: ${snap.score > 70 ? "Satisfactory" : "Improvement required before next audit"}\n\n## Key Findings\n\n- Most active check series: **${topSeries?.name || "N/A"}**\n- Highest risk system: **${topSystem?.[0] || "N/A"}**\n\n## Trend Prediction\n\nP1 findings are ${trendDir}. ${trendDir.includes("⬆️") ? "Intervention required to prevent compliance breach before quarter end." : "Maintain current quality practices."}`;
    }

    return `## Executive Summary\n\n${snap.totalRuns} ATC runs analyzed. ${snap.p1} P1 / ${snap.p2} P2 / ${snap.p3} P3 findings. Risk: ${riskColor} ${riskLevel}. Health: ${snap.score}%.\n\n## Key Findings\n\n- **Hottest series**: ${topSeries?.name || "N/A"}\n- **Priority system**: ${topSystem?.[0] || "N/A"} with ${topSystem?.[1] || 0} P1 findings\n\n## Recommendations\n\n1. Run transaction SCI on ${topSystem?.[0] || "flagged system"} with full check variant\n2. Fix LOOP+SELECT patterns first — highest performance impact\n3. Review all dynamic SQL for injection vulnerability\n4. Add ATC check to CI/CD pipeline before transport to CON\n\n## Trend\n\nP1 findings are ${trendDir}.`;
  };

  const runAiAnalysis = (userMessage?: string) => {
    const snap = {
      runs: filteredRuns,
      p1: totalP1, p2: totalP2, p3: totalP3,
      score: healthScore,
      period: filters.period,
      system: filters.system,
      series: chartSeries,
      trend: chartTrend,
      totalRuns: filteredRuns.length,
    };
    const msgs = userMessage
      ? [...aiMessages, { role: "user", content: userMessage }]
      : [];
    setAiLoading(true);
    setTimeout(() => {
      try {
        const reply = generateAiAnalysis(userMessage, aiView, snap);
        setAiMessages([...msgs, { role: "assistant", content: reply }]);
      } catch {
        setAiMessages([...msgs, { role: "assistant", content: "Analysis could not be completed. Please try again." }]);
      }
      setAiLoading(false);
    }, 1000);
  };

  /* ---------------------------------------------------------------- */
  /*  LOADING SCREEN                                                    */
  /* ---------------------------------------------------------------- */
  if (loading) {
    return (
      <div className="container">
        <div className="card">Loading dashboard...</div>
      </div>
    );
  }

  /* ================================================================ */
  /*  RENDER                                                            */
  /* ================================================================ */
  return (
    <div>
      {/* HEADER */}
      <div className="header">
        <div className="header-title">ATC RUN MONITOR</div>
        <div style={{ display: "flex", gap: 12, alignItems: "center" }}>
          {/* CONNECTION SWITCH */}
          <div
            style={{
              display: "flex",
              alignItems: "center",
              background: "rgba(255,255,255,0.12)",
              borderRadius: 10,
              padding: "4px 6px",
            }}
          >
            {(["btp", "netweaver"] as const).map((c) => (
              <button
                key={c}
                onClick={() => setConnection(c)}
                title={CONNECTIONS[c].description}
                style={{
                  display: "flex", alignItems: "center", gap: 5,
                  padding: "5px 12px", borderRadius: 7, border: "none",
                  fontSize: 12, fontWeight: 600, cursor: "pointer",
                  background: connection === c ? "#ffffff" : "transparent",
                  color: connection === c ? "#0a6ed1" : "rgba(255,255,255,0.75)",
                  boxShadow: connection === c ? "0 1px 4px rgba(0,0,0,0.15)" : "none",
                  transition: "all 0.2s",
                }}
              >
                {CONNECTIONS[c].icon} {CONNECTIONS[c].label}
              </button>
            ))}
          </div>
          {/* THEME */}
          <select className="input" value={theme} onChange={(e) => setTheme(e.target.value)}>
            <option value="light">🌞 Light</option>
            <option value="dark">🌙 Dark</option>
            <option value="blue">🔵 Blue</option>
          </select>
        </div>
      </div>

      {/* TABS */}
      <div className="tabs">
        {[
          { key: "overview", label: "Overview" },
          { key: "runs",     label: "Run Explorer" },
          { key: "quality",  label: "Code Quality" },
          { key: "sla",      label: "Alerts & SLA" },
        ].map((item) => (
          <div
            key={item.key}
            className={`tab ${tab === item.key ? "active" : ""}`}
            onClick={() => setTab(item.key)}
          >
            {item.label}
          </div>
        ))}
      </div>

      <div className="container">
        {/* ============================================================ */}
        {/* FILTER PANEL                                                  */}
        {/* ============================================================ */}
        <div className="filter-sticky">
          <div className="filter-card-premium">
            <div className="filter-header-premium">
              <div>
                <h3>Filter Runs</h3>
                <div className="subtitle">Refine execution results and analysis</div>
              </div>
              <button className="btn-secondary" onClick={() => setCollapsed(!collapsed)}>
                {collapsed ? "Expand" : "Collapse"}
              </button>
            </div>

            {!collapsed && (
              <>
                <div className="filter-grid">
                  <div className="filter-field">
                    <label>SYSTEM GROUP</label>
                    <input
                      value={filters.system}
                      onChange={(e) => setFilters({ ...filters, system: e.target.value })}
                    />
                  </div>
                  <div className="filter-field">
                    <label>RUN SERIES</label>
                    <input
                      value={filters.series}
                      onChange={(e) => setFilters({ ...filters, series: e.target.value })}
                    />
                  </div>
                  <div className="filter-field">
                    <label>CHECK RUN TITLE</label>
                    <input
                      value={filters.title}
                      onChange={(e) => setFilters({ ...filters, title: e.target.value })}
                    />
                  </div>
                  <div className="filter-field">
                    <label>SCHEDULED BY</label>
                    <input
                      value={filters.user}
                      onChange={(e) => setFilters({ ...filters, user: e.target.value })}
                    />
                  </div>
                  <div className="filter-field">
                    <label>DATE FROM</label>
                    <input
                      type="date"
                      value={filters.dateFrom}
                      onChange={(e) => setFilters({ ...filters, dateFrom: e.target.value })}
                    />
                  </div>
                  <div className="filter-field">
                    <label>DATE TO</label>
                    <input
                      type="date"
                      value={filters.dateTo}
                      onChange={(e) => setFilters({ ...filters, dateTo: e.target.value })}
                    />
                  </div>
                  <div className="filter-field">
                    <label>PERIOD (DAYS)</label>
                    <input
                      type="number"
                      value={filters.period}
                      onChange={(e) => setFilters({ ...filters, period: Number(e.target.value) })}
                    />
                  </div>
                </div>

                <div
                  className="filter-row"
                  style={{
                    display: "grid",
                    gridTemplateColumns: "auto auto",
                    justifyContent: "start",
                    gap: "5px",
                    marginTop: "24px",
                    paddingTop: "20px",
                    borderTop: "1px solid #e5e7eb",
                    alignItems: "start",
                  }}
                >
                  <div className="filter-section">
                    <div className="section-label">SCHEDULE DATA</div>
                    <div className="radio-group">
                      <label>
                        <input
                          type="radio"
                          checked={filters.scheduleMode === "period"}
                          onChange={() => setFilters({ ...filters, scheduleMode: "period" })}
                        />{" "}Period
                      </label>
                      <label>
                        <input
                          type="radio"
                          checked={filters.scheduleMode === "date"}
                          onChange={() => setFilters({ ...filters, scheduleMode: "date" })}
                        />{" "}By Date
                      </label>
                    </div>
                  </div>
                  <div className="filter-section">
                    <div className="section-label">RESULT VISIBILITY</div>
                    <div className="radio-group">
                      <label>
                        <input
                          type="radio"
                          checked={filters.visibility === "central"}
                          onChange={() => setFilters({ ...filters, visibility: "central" })}
                        />{" "}Central Only
                      </label>
                      <label>
                        <input
                          type="radio"
                          checked={filters.visibility === "noncentral"}
                          onChange={() => setFilters({ ...filters, visibility: "noncentral" })}
                        />{" "}Not Central
                      </label>
                      <label>
                        <input
                          type="radio"
                          checked={filters.visibility === "any"}
                          onChange={() => setFilters({ ...filters, visibility: "any" })}
                        />{" "}Any
                      </label>
                      <label>
                        <input
                          type="checkbox"
                          checked={filters.baselineOnly}
                          onChange={(e) => setFilters({ ...filters, baselineOnly: e.target.checked })}
                        />{" "}Only Results in Baseline
                      </label>
                    </div>
                  </div>
                </div>

                <div className="filter-actions">
                  <button
                    className="btn-primary"
                    onClick={() => load(filters)}
                  >
                    GO
                  </button>
                  <button
                    className="btn-secondary"
                    onClick={() => {
                      const reset = {
                        system: "", series: "", title: "", user: "",
                        dateFrom: "", dateTo: "", period: 30,
                        scheduleMode: "period", visibility: "any", baselineOnly: false,
                      };
                      setFilters(reset);
                      load(reset);
                    }}
                  >
                    Reset
                  </button>
                  <button
                    className="btn-ai"
                    onClick={() => {
                      setAiOpen(true);
                      if (aiMessages.length === 0) runAiAnalysis();
                    }}
                  >
                    ✨ AI Analysis
                  </button>
                </div>
              </>
            )}
          </div>
        </div>

        {/* ============================================================ */}
        {/* KPI CARDS                                                     */}
        {/* ============================================================ */}
        <div className="kpi-grid">
          <div className="kpi-card">
            <div className="kpi-title">TOTAL RUNS</div>
            <div className="kpi-value blue-text">{totalRuns}</div>
          </div>
          <div className="kpi-card">
            <div className="kpi-title">CRITICAL (P1)</div>
            {/* Use kpi.p1 from server if available, else compute from filteredRuns */}
            <div className="kpi-value red-text">{kpi.p1 ?? totalP1}</div>
          </div>
          <div className="kpi-card">
            <div className="kpi-title">WARNINGS (P2)</div>
            <div className="kpi-value orange-text">{kpi.p2 ?? totalP2}</div>
          </div>
          <div className="kpi-card">
            <div className="kpi-title">HEALTH SCORE</div>
            <div className="kpi-value green-text">{healthScore}%</div>
          </div>
        </div>

        {/* ============================================================ */}
        {/* OVERVIEW TAB                                                  */}
        {/* ============================================================ */}
        {tab === "overview" && (
          <div className="chart-grid">
            <div className="chart-card large">
              <h3>Daily Findings Trend</h3>
              <ResponsiveContainer width="100%" height={300}>
                <BarChart data={chartTrend}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis dataKey="date" />
                  <YAxis />
                  <Tooltip />
                  <Bar dataKey="p1" stackId="a" fill="#ef4444" name="P1" />
                  <Bar dataKey="p2" stackId="a" fill="#f59e0b" name="P2" />
                  <Bar dataKey="p3" stackId="a" fill="#3b82f6" name="P3" />
                </BarChart>
              </ResponsiveContainer>
            </div>

            <div className="chart-card">
              <h3>Priority Distribution</h3>
              <ResponsiveContainer width="100%" height={300}>
                <PieChart>
                  <Pie
                    data={[
                      { name: "P1", value: totalP1 },
                      { name: "P2", value: totalP2 },
                      { name: "P3", value: totalP3 },
                    ]}
                    innerRadius={70}
                    outerRadius={100}
                    dataKey="value"
                  >
                    {COLORS.map((c, i) => <Cell key={i} fill={c} />)}
                  </Pie>
                  <Tooltip />
                </PieChart>
              </ResponsiveContainer>
            </div>

            <div className="chart-card">
              <h3>Quality Trend</h3>
              <ResponsiveContainer width="100%" height={300}>
                <LineChart data={chartQuality}>
                  <XAxis dataKey="date" />
                  <YAxis domain={[0, 100]} />
                  <Tooltip />
                  <Line dataKey="score" stroke="#0a6ed1" dot={false} />
                </LineChart>
              </ResponsiveContainer>
            </div>

            <div className="chart-card">
              <h3>Run Series Comparison</h3>
              <ResponsiveContainer width="100%" height={300}>
                <BarChart data={chartSeries}>
                  <XAxis dataKey="name" />
                  <YAxis />
                  <Tooltip />
                  <Bar dataKey="value" fill="#3b82f6" name="Runs" />
                </BarChart>
              </ResponsiveContainer>
            </div>

            <div className="chart-card">
              <h3>Heat Map</h3>
              <div
                style={{
                  display: "grid",
                  gridTemplateColumns: "repeat(7, 1fr)",
                  gap: 8,
                  marginTop: 12,
                }}
              >
                {(chartHeatmap.length ? chartHeatmap : Array.from({ length: 14 })).map(
                  (item: any, i) => {
                    const value = item?.value ?? 0;
                    const bg = value > 70 ? "#fecaca" : value > 40 ? "#fde68a" : "#dbeafe";
                    return (
                      <div
                        key={i}
                        title={`Risk score: ${value}`}
                        style={{
                          height: 42, borderRadius: 8, background: bg,
                          display: "flex", alignItems: "center",
                          justifyContent: "center", fontSize: 11, fontWeight: 700,
                        }}
                      >
                        {value}
                      </div>
                    );
                  }
                )}
              </div>
            </div>

            <div className="chart-card large">
              <h3>Check Categories</h3>
              <ResponsiveContainer width="100%" height={300}>
                <RadarChart
                  data={chartCategories.map((c) => ({ subject: c.name, value: c.value }))}
                >
                  <PolarGrid />
                  <PolarAngleAxis dataKey="subject" />
                  <PolarRadiusAxis />
                  <Radar dataKey="value" fill="#3b82f6" fillOpacity={0.5} />
                </RadarChart>
              </ResponsiveContainer>
            </div>
          </div>
        )}

        {/* ============================================================ */}
        {/* CODE QUALITY TAB                                              */}
        {/* ============================================================ */}
        {tab === "quality" && (
          <div className="chart-grid">
            <div className="chart-card">
              <h3>Code quality index</h3>
              <div className="subtitle">Composite score this period</div>
              <div style={{ display: "flex", alignItems: "center", gap: 28, marginTop: 20, marginBottom: 24, flexWrap: "wrap" }}>
                <div style={{ width: 130, height: 130, borderRadius: "50%", border: "12px solid #0a6ed1", borderTopColor: "#dbeafe", display: "flex", alignItems: "center", justifyContent: "center", fontSize: 42, fontWeight: 700 }}>
                  72
                </div>
                <div>
                  <div style={{ fontSize: 13, letterSpacing: 1, fontWeight: 700, color: "#6b7280" }}>QUALITY INDEX</div>
                  <div style={{ marginTop: 10, background: "#fee2e2", color: "#dc2626", padding: "8px 14px", borderRadius: 999, fontSize: 13, display: "inline-block" }}>-4 pts this week</div>
                </div>
              </div>
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 14 }}>
                {[
                  ["MAINTAINABILITY", 68, "#111827"],
                  ["SECURITY", 54, "#dc2626"],
                  ["PERFORMANCE", 71, "#92400e"],
                  ["NAMING / STYLE", 85, "#166534"],
                ].map(([label, value, color], i) => (
                  <div key={i} style={{ background: "#f3f4f6", borderRadius: 10, padding: 18, textAlign: "center" }}>
                    <div style={{ fontSize: 11, color: "#6b7280" }}>{label}</div>
                    <div style={{ marginTop: 10, fontSize: 22, fontWeight: 700, color: color as string }}>{value}</div>
                  </div>
                ))}
              </div>
            </div>

            <div className="chart-card">
              <h3>Top violated objects</h3>
              <div className="subtitle">Programs/classes with most findings</div>
              <div style={{ marginTop: 24 }}>
                {[
                  ["Z_PERF_MONITOR", 48, "#ef4444"],
                  ["ZCL_DATA_PROC",  41, "#ef4444"],
                  ["Z_REPORT_GEN",   35, "#f59e0b"],
                  ["ZIF_CONNECTOR",  29, "#f59e0b"],
                  ["Z_BATCH_JOB",    22, "#3b82f6"],
                ].map(([name, val, color], i) => (
                  <div key={i} style={{ display: "grid", gridTemplateColumns: "130px 1fr 30px", gap: 10, alignItems: "center", marginBottom: 16 }}>
                    <div style={{ fontSize: 13 }}>{name}</div>
                    <div style={{ height: 8, background: "#f3f4f6", borderRadius: 999, overflow: "hidden" }}>
                      <div style={{ width: `${Number(val) * 2}%`, height: "100%", background: color as string, borderRadius: 999 }} />
                    </div>
                    <div style={{ fontSize: 13 }}>{val}</div>
                  </div>
                ))}
              </div>
            </div>

            <div className="chart-card large">
              <h3>Finding resolution SLA</h3>
              <div className="subtitle">Age distribution of open findings (days)</div>
              <div style={{ display: "grid", gridTemplateColumns: "repeat(4,1fr)", gap: 18, alignItems: "end", marginTop: 28, height: 260 }}>
                {[
                  ["0–7 days",   310, "#65a30d"],
                  ["8–30 days",  200, "#f59e0b"],
                  ["31–90 days",  95, "#ef4444"],
                  ["90+ days",    45, "#7f1d1d"],
                ].map(([label, val, color], i) => (
                  <div key={i} style={{ textAlign: "center" }}>
                    <div style={{ height: `${Number(val) / 1.4}px`, background: color as string, borderRadius: 6 }} />
                    <div style={{ marginTop: 10, fontSize: 13, color: "#6b7280" }}>{label}</div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* ============================================================ */}
        {/* ALERTS & SLA TAB                                              */}
        {/* ============================================================ */}
        {tab === "sla" && (
          <div className="chart-grid">
            <div className="chart-card">
              <h3>Active alerts</h3>
              <div className="subtitle">Requires immediate attention</div>
              <div style={{ marginTop: 24 }}>
                {[
                  ["Critical P1 spike: DBB_RELEASE exceeded threshold (+49 errors)", "#ef4444", "Today 02:14"],
                  ["Run DBB_WEEKLY exceeded SLA duration (18m vs 10m target)",       "#f59e0b", "Today 00:31"],
                  ["Security check package: 12 new vulnerabilities since last baseline", "#f59e0b", "Yesterday 23:55"],
                  ["3 consecutive clean runs achieved on DBB_HOTFIX series",          "#3b82f6", "Apr 19"],
                ].map(([text, color, time], i) => (
                  <div key={i} style={{ display: "grid", gridTemplateColumns: "14px 1fr", gap: 10, padding: "14px 0", borderBottom: i !== 3 ? "1px solid #f0f0f0" : "none" }}>
                    <div style={{ width: 10, height: 10, borderRadius: "50%", background: color as string, marginTop: 6 }} />
                    <div>
                      <div style={{ fontSize: 14 }}>{text}</div>
                      <div style={{ fontSize: 12, color: "#6b7280", marginTop: 6 }}>{time}</div>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            <div className="chart-card">
              <h3>SLA compliance</h3>
              <div className="subtitle">Resolution targets by priority</div>
              <div style={{ marginTop: 30 }}>
                {[
                  ["P1 Critical", 72, "#ef4444", "Target: 24h - Avg actual: 31h"],
                  ["P2 Warning",  88, "#f59e0b", "Target: 72h - Avg actual: 58h"],
                  ["P3 Info",     95, "#3b82f6", "Target: 14d - Avg actual: 9d"],
                  ["P4 Note",     99, "#737373", "Target: 30d - Avg actual: 12d"],
                ].map(([label, val, color, sub], i) => (
                  <div key={i} style={{ marginBottom: 22 }}>
                    <div style={{ display: "grid", gridTemplateColumns: "110px 1fr 45px", gap: 10, alignItems: "center" }}>
                      <div style={{ fontSize: 14 }}>{label}</div>
                      <div style={{ height: 8, background: "#f3f4f6", borderRadius: 999, overflow: "hidden" }}>
                        <div style={{ width: `${val}%`, height: "100%", background: color as string }} />
                      </div>
                      <div style={{ fontSize: 14 }}>{val}%</div>
                    </div>
                    <div style={{ marginLeft: 120, marginTop: 6, fontSize: 12, color: "#6b7280" }}>{sub}</div>
                  </div>
                ))}
              </div>
            </div>

            <div className="chart-card large">
              <h3>Schedule adherence</h3>
              <div className="subtitle">Planned vs actual run times this week</div>
              <ResponsiveContainer width="100%" height={300}>
                <BarChart data={[
                  { day: "Mon", planned: 6, actual: 6 },
                  { day: "Tue", planned: 6, actual: 7 },
                  { day: "Wed", planned: 6, actual: 5 },
                  { day: "Thu", planned: 6, actual: 6 },
                  { day: "Fri", planned: 6, actual: 8 },
                  { day: "Sat", planned: 2, actual: 2 },
                  { day: "Sun", planned: 2, actual: 1 },
                ]}>
                  <XAxis dataKey="day" />
                  <YAxis />
                  <Tooltip />
                  <Bar dataKey="actual"  fill="#0a6ed1" radius={[4,4,0,0]} name="Actual" />
                  <Bar dataKey="planned" fill="#bfdbfe" radius={[4,4,0,0]} name="Planned" />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>
        )}

        {/* ============================================================ */}
        {/* RUN EXPLORER TAB                                              */}
        {/* ============================================================ */}
        {tab === "runs" && (
          <div className="table-card premium-results">
            <div className="table-toolbar">
              <h3>Check run results</h3>
              <div className="toolbar-actions">
                <button
                  className="btn-secondary"
                  onClick={() => {
                    const headers = ["ID", "Series", "Title", "Scheduled By", "System", "Date", "P1", "P2", "P3", "Central"];
                    const rows = filteredRuns.map((r) => [
                      r.ID,
                      r.series ?? "",
                      r.title ?? "",
                      r.user ?? "",
                      r.system ?? "",
                      r.date ?? "",
                      r.p1,
                      r.p2,
                      r.p3,
                      r.central ? "Yes" : "No",
                    ]);
                    const csv = [headers, ...rows].map((row) => row.join(",")).join("\n");
                    const blob = new Blob([csv], { type: "text/csv" });
                    const url = URL.createObjectURL(blob);
                    const a = document.createElement("a");
                    a.href = url;
                    a.download = `atc-runs-${new Date().toISOString().split("T")[0]}.csv`;
                    a.click();
                    URL.revokeObjectURL(url);
                  }}
                >
                  Export CSV
                </button>
                <button className="btn-secondary" onClick={() => load(filters)}>
                  Refresh
                </button>
              </div>
            </div>

            <div className="table-wrapper">
              <table className="premium-table">
                <thead>
                  <tr>
                    <th>RUN SERIES</th>
                    <th>CHECK RUN TITLE</th>
                    <th>SCHEDULED BY</th>
                    <th>RUN DATE</th>
                    <th>P1</th>
                    <th>P2</th>
                    <th>P3</th>
                    <th>SEVERITY</th>
                    <th>STATUS</th>
                    <th>CENTRAL</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredRuns.map((r) => {
                    const total = (r.p1 + r.p2 + r.p3) || 1;
                    const p1w = (r.p1 / total) * 100;
                    const p2w = (r.p2 / total) * 100;
                    const p3w = (r.p3 / total) * 100;
                    const highRisk = r.p1 > 20;
                    return (
                      <tr
                        key={r.ID}
                        style={{ cursor: "pointer" }}
                        onClick={() => { setSelectedRun(r); setDrawerOpen(true); }}
                      >
                        <td>
                          <span className="pill-series">{r.series || "—"}</span>
                        </td>
                        <td>{r.title || "—"}</td>
                        <td>{r.user || "—"}</td>
                        <td>{r.date || "—"}</td>
                        <td><span className="badge-red">{r.p1}</span></td>
                        <td><span className="badge-orange">{r.p2}</span></td>
                        <td><span className="badge-blue">{r.p3}</span></td>
                        <td>
                          <div className="sev-bar">
                            <span className="sev-red"    style={{ width: `${p1w}%` }} />
                            <span className="sev-orange" style={{ width: `${p2w}%` }} />
                            <span className="sev-blue"   style={{ width: `${p3w}%` }} />
                          </div>
                        </td>
                        <td>
                          <span className={highRisk ? "status-risk" : "status-error"}>
                            {highRisk ? "High Risk" : "Has Errors"}
                          </span>
                        </td>
                        {/* CENTRAL — uses real data field, not array index */}
                        <td>
                          <span className={r.central ? "central-yes" : "central-no"}>
                            {r.central ? "Central" : "No"}
                          </span>
                        </td>
                      </tr>
                    );
                  })}
                  {filteredRuns.length === 0 && (
                    <tr>
                      <td colSpan={10} style={{ textAlign: "center", padding: 32, color: "#6b7280" }}>
                        No runs match the current filters.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* ============================================================ */}
        {/* RUN DETAIL DRAWER                                             */}
        {/* ============================================================ */}
        {tab === "runs" && drawerOpen && selectedRun && (
          <div className="drawer-overlay">
            <div className="drawer-panel">
              <div className="drawer-header">
                <div>
                  <h2>{selectedRun.title || "ATC Run Detail"}</h2>
                  <div className="drawer-sub">
                    Series: {selectedRun.series || "—"} | Executed: {selectedRun.date || "—"} | System: {selectedRun.system || "—"}
                  </div>
                </div>
                <button className="drawer-close" onClick={() => setDrawerOpen(false)}>✕</button>
              </div>
              <div className="drawer-kpis">
                <div className="drawer-box red-box">
                  <div>CRITICAL (P1)</div>
                  <strong>{selectedRun.p1}</strong>
                </div>
                <div className="drawer-box orange-box">
                  <div>WARNING (P2)</div>
                  <strong>{selectedRun.p2}</strong>
                </div>
                <div className="drawer-box blue-box">
                  <div>INFO (P3)</div>
                  <strong>{selectedRun.p3}</strong>
                </div>
              </div>
              <h3 className="drawer-title">DETAILED FINDINGS SAMPLE</h3>
              <div className="finding-card">
                <b>DB Operations in Loops</b>
                <span className="badge-red">P1</span>
                <p>SELECT inside LOOP detected. Use bulk fetch / FOR ALL ENTRIES.</p>
              </div>
              <div className="finding-card">
                <b>Potential SQL Injection</b>
                <span className="badge-red">P1</span>
                <p>Dynamic WHERE condition needs sanitization.</p>
              </div>
              <div className="finding-card">
                <b>Naming Conventions</b>
                <span className="badge-orange">P2</span>
                <p>Prefix IT_/LT_ missing.</p>
              </div>
              <div className="finding-card">
                <b>Dead Code</b>
                <span className="badge-blue">P3</span>
                <p>Unused variable detected.</p>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* ============================================================== */}
      {/* AI ANALYSIS PANEL                                               */}
      {/* ============================================================== */}
      {aiOpen && (
        <div
          onClick={(e) => { if (e.target === e.currentTarget) setAiOpen(false); }}
          style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,0.35)", zIndex: 1000, display: "flex", justifyContent: "flex-end" }}
        >
          <div style={{ width: "min(800px, 100vw)", height: "100vh", background: "var(--card-bg, #ffffff)", boxShadow: "-4px 0 32px rgba(0,0,0,0.18)", display: "flex", flexDirection: "column", padding: "20px 20px 16px 20px", boxSizing: "border-box", overflowX: "hidden" }}>
            {/* AI HEADER */}
            <div style={{ borderBottom: "1px solid #e5e7eb", paddingBottom: 14, flexShrink: 0, display: "flex", justifyContent: "space-between", alignItems: "flex-start", gap: 12, flexWrap: "wrap" }}>
              <div style={{ minWidth: 0 }}>
                <h2 style={{ fontSize: 18, margin: 0 }}>✨ AI Analysis</h2>
                <div style={{ fontSize: 11, color: "#6b7280", marginTop: 4 }}>
                  {filteredRuns.length} runs · {filters.period} days · {filters.system || "All systems"} · {new Date().toLocaleDateString("en-IN", { day: "numeric", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit" })}
                </div>
              </div>
              <div style={{ display: "flex", alignItems: "center", gap: 8, flexShrink: 0 }}>
                <div style={{ display: "flex", background: "#f3f4f6", borderRadius: 8, padding: 3 }}>
                  {(["manager", "developer"] as const).map((v) => (
                    <button
                      key={v}
                      onClick={() => {
                        setAiView(v);
                        setAiMessages([]);
                        setAiLoading(true);
                        const snap = { runs: filteredRuns, p1: totalP1, p2: totalP2, p3: totalP3, score: healthScore, period: filters.period, system: filters.system, series: chartSeries, trend: chartTrend, totalRuns: filteredRuns.length };
                        setTimeout(() => {
                          try {
                            setAiMessages([{ role: "assistant", content: generateAiAnalysis(undefined, v, snap) }]);
                          } catch {
                            setAiMessages([{ role: "assistant", content: "Analysis could not be completed." }]);
                          }
                          setAiLoading(false);
                        }, 1000);
                      }}
                      style={{ padding: "5px 12px", borderRadius: 6, border: "none", fontSize: 12, fontWeight: 600, cursor: "pointer", background: aiView === v ? "#0a6ed1" : "transparent", color: aiView === v ? "white" : "#6b7280", whiteSpace: "nowrap" }}
                    >
                      {v === "manager" ? "👔 Manager" : "💻 Developer"}
                    </button>
                  ))}
                </div>
                <button className="drawer-close" onClick={() => setAiOpen(false)}>✕</button>
              </div>
            </div>

            {/* MESSAGES */}
            <div style={{ flex: 1, overflowY: "auto", overflowX: "hidden", padding: "16px 0", display: "flex", flexDirection: "column", gap: 16 }}>
              {aiLoading && aiMessages.length === 0 && (
                <div style={{ textAlign: "center", padding: 40, color: "#6b7280" }}>
                  <div style={{ fontSize: 32, marginBottom: 12 }}>🤖</div>
                  <div style={{ fontSize: 14 }}>Analyzing {filteredRuns.length} ATC runs...</div>
                </div>
              )}
              {aiMessages.map((msg, i) => (
                <div key={i} style={{ display: "flex", flexDirection: "column", gap: 4, alignItems: msg.role === "user" ? "flex-end" : "flex-start" }}>
                  <div style={{ fontSize: 11, color: "#9ca3af", paddingLeft: msg.role === "assistant" ? 4 : 0 }}>
                    {msg.role === "user" ? "You" : "🤖 AI Assistant"}
                  </div>
                  <div style={{ maxWidth: "92%", width: msg.role === "assistant" ? "100%" : "auto", padding: "12px 16px", borderRadius: 12, fontSize: 13, lineHeight: 1.75, background: msg.role === "user" ? "#0a6ed1" : "#f8faff", color: msg.role === "user" ? "white" : "#1f2937", border: msg.role === "assistant" ? "1px solid #e0e7ff" : "none", boxSizing: "border-box", wordBreak: "break-word" }}>
                    {msg.content.split("\n").map((line, j) => {
                      if (line.startsWith("## "))
                        return <div key={j} style={{ fontWeight: 700, fontSize: 14, color: "#0a6ed1", marginTop: j > 0 ? 16 : 0, marginBottom: 6, borderBottom: "1px solid #e0e7ff", paddingBottom: 4 }}>{line.replace("## ", "")}</div>;
                      if (line.startsWith("- ") || line.startsWith("• ")) {
                        const text = line.replace(/^[-•] /, "");
                        const parts = text.split("**");
                        return <div key={j} style={{ paddingLeft: 12, marginBottom: 4 }}>{"• "}{parts.map((p, k) => k % 2 === 1 ? <strong key={k}>{p}</strong> : p)}</div>;
                      }
                      if (/^\d+\./.test(line))
                        return <div key={j} style={{ paddingLeft: 12, marginBottom: 4, fontWeight: 500 }}>{line}</div>;
                      if (line.includes("**")) {
                        const parts = line.split("**");
                        return <div key={j} style={{ marginBottom: line === "" ? 8 : 2 }}>{parts.map((p, k) => k % 2 === 1 ? <strong key={k}>{p}</strong> : p)}</div>;
                      }
                      return <div key={j} style={{ marginBottom: line === "" ? 8 : 2 }}>{line}</div>;
                    })}
                  </div>
                  {msg.role === "assistant" && i === aiMessages.length - 1 && (
                    <div style={{ display: "flex", gap: 8, paddingLeft: 4, marginTop: 4, flexWrap: "wrap" }}>
                      <button onClick={() => navigator.clipboard.writeText(msg.content)} style={{ fontSize: 11, padding: "4px 10px", borderRadius: 6, border: "1px solid #e5e7eb", background: "white", cursor: "pointer", color: "#6b7280" }}>📋 Copy</button>
                      <button onClick={() => {
                        const blob = new Blob([`ATC AI Analysis Report\nGenerated: ${new Date().toLocaleString()}\nView: ${aiView}\nRuns: ${filteredRuns.length} | Period: ${filters.period} days | System: ${filters.system || "All"}\n\n${msg.content}`], { type: "text/plain" });
                        const url = URL.createObjectURL(blob);
                        const a = document.createElement("a");
                        a.href = url;
                        a.download = `atc-ai-analysis-${new Date().toISOString().split("T")[0]}.txt`;
                        a.click();
                        URL.revokeObjectURL(url);
                      }} style={{ fontSize: 11, padding: "4px 10px", borderRadius: 6, border: "1px solid #e5e7eb", background: "white", cursor: "pointer", color: "#6b7280" }}>⬇️ Download Report</button>
                    </div>
                  )}
                </div>
              ))}
              {aiLoading && aiMessages.length > 0 && (
                <div style={{ display: "flex", alignItems: "center", gap: 8, color: "#6b7280", fontSize: 13, paddingLeft: 4 }}>
                  <div style={{ width: 8, height: 8, borderRadius: "50%", background: "#0a6ed1" }} />
                  AI is analyzing...
                </div>
              )}
            </div>

            {/* SUGGESTED QUESTIONS */}
            {aiMessages.length > 0 && !aiLoading && (
              <div style={{ borderTop: "1px solid #f3f4f6", paddingTop: 10, paddingBottom: 8, flexShrink: 0 }}>
                <div style={{ fontSize: 11, color: "#9ca3af", marginBottom: 8 }}>Suggested questions:</div>
                <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                  {SUGGESTED_QUESTIONS.map((q, i) => (
                    <button key={i} onClick={() => setAiInput(q)} style={{ fontSize: 11, padding: "5px 10px", borderRadius: 999, border: "1px solid #c7d2fe", background: "#eef2ff", color: "#4f46e5", cursor: "pointer", whiteSpace: "nowrap" }}>{q}</button>
                  ))}
                </div>
              </div>
            )}

            {/* INPUT */}
            <div style={{ borderTop: "1px solid #e5e7eb", paddingTop: 12, display: "flex", gap: 8, flexShrink: 0 }}>
              <input
                value={aiInput}
                onChange={(e) => setAiInput(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter" && aiInput.trim() && !aiLoading) {
                    runAiAnalysis(aiInput);
                    setAiInput("");
                  }
                }}
                placeholder="Ask a follow-up question..."
                style={{ flex: 1, minWidth: 0, padding: "10px 14px", borderRadius: 10, border: "1px solid #d1d5db", fontSize: 13, outline: "none", boxSizing: "border-box" }}
              />
              <button
                onClick={() => { if (aiInput.trim() && !aiLoading) { runAiAnalysis(aiInput); setAiInput(""); } }}
                disabled={!aiInput.trim() || aiLoading}
                style={{ padding: "10px 16px", borderRadius: 10, border: "none", background: aiInput.trim() && !aiLoading ? "#0a6ed1" : "#e5e7eb", color: aiInput.trim() && !aiLoading ? "white" : "#9ca3af", cursor: aiInput.trim() && !aiLoading ? "pointer" : "default", fontSize: 13, fontWeight: 600, flexShrink: 0 }}
              >
                Send
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}