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

type Trend = { date: string; p1: number; p2: number; p3: number };

type Run = {
  ID: string;
  user: string;
  system?: string;
  series?: string;
  title?: string;
  date: string;
  p1: number;
  p2: number;
  p3: number;
};

type KPI = {
  p1?: number;
  p2?: number;
  p3?: number;
  health?: number;
};

type AiMessage = { role: string; content: string };

const COLORS = ["#ef4444", "#f59e0b", "#3b82f6"];

/* ---------------- CONNECTION CONFIG ---------------- */
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
    baseUrl: "/sap/opu/odata/sap/ZCDM_ATC_SRV", // ← replace with your NW path when ready
    description: "ABAP NetWeaver OData",
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

export default function App() {
  const [tab, setTab] = useState("overview");
  const [collapsed, setCollapsed] = useState(false);
  const [loading, setLoading] = useState(true);
  const [theme, setTheme] = useState("light");

  const [trend, setTrend] = useState<Trend[]>([]);
  const [runs, setRuns] = useState<Run[]>([]);
  const [kpi, setKpi] = useState<KPI>({});
  const [categories, setCategories] = useState<any[]>([]);
  const [seriesStats, setSeriesStats] = useState<any[]>([]);
  const [quality, setQuality] = useState<any[]>([]);
  const [heatmap, setHeatmap] = useState<any[]>([]);
  const [selectedRun, setSelectedRun] = useState<any>(null);
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

  /* ---------------- AI STATE ---------------- */
  const [aiOpen, setAiOpen] = useState(false);
  const [aiLoading, setAiLoading] = useState(false);
  const [aiMessages, setAiMessages] = useState<AiMessage[]>([]);
  const [aiInput, setAiInput] = useState("");
  const [aiView, setAiView] = useState<"manager" | "developer">("manager");

  /* ---------------- CONNECTION STATE ---------------- */
  const [connection, setConnection] = useState<"btp" | "netweaver">("btp");

  /* ---------------- THEME ---------------- */
  useEffect(() => {
    const saved = localStorage.getItem("theme");
    if (saved) setTheme(saved);
  }, []);

  useEffect(() => {
    document.documentElement.setAttribute("data-theme", theme);
    localStorage.setItem("theme", theme);
  }, [theme]);

  /* ---------------- HELPERS ---------------- */
  const fetchData = async (path: string) => {
    const baseUrl = CONNECTIONS[connection].baseUrl;
    const url = `${baseUrl}${path}`;
    try {
      const res = await fetch(url);
      const json = await res.json();
      return json.value || json || [];
    } catch (error) {
      console.error("Fetch failed:", url, error);
      return [];
    }
  };

  const buildFilterQuery = () => {
    const conditions: string[] = [];
    if (filters.system) conditions.push(`contains(system,'${filters.system}')`);
    if (filters.series) conditions.push(`contains(series,'${filters.series}')`);
    if (filters.title) conditions.push(`contains(title,'${filters.title}')`);
    if (filters.user) conditions.push(`contains(user,'${filters.user}')`);
    if (filters.scheduleMode === "date") {
      if (filters.dateFrom) conditions.push(`date ge ${filters.dateFrom}`);
      if (filters.dateTo) conditions.push(`date le ${filters.dateTo}`);
    }
    return conditions.length ? `?$filter=${conditions.join(" and ")}` : "";
  };

  /* ---------------- LOAD ---------------- */
  const load = async () => {
    setLoading(true);
    const query = buildFilterQuery();
    const [t, r, k, c, s, q, h] = await Promise.all([
      fetchData(`/Trend`),
      fetchData(`/Runs${query}`),
      fetchData(`/OverviewKPI`),
      fetchData(`/CategoryStats`),
      fetchData(`/RunSeriesStats`),
      fetchData(`/QualityTrend`),
      fetchData(`/Heatmap`),
    ]);
    setTrend(t);
    setRuns(r);
    setKpi(k[0] || {});
    setCategories(c);
    setSeriesStats(s);
    setQuality(q);
    setHeatmap(h);
    setLoading(false);
  };

  useEffect(() => {
    load();
  }, [connection]); // reloads data whenever connection switches

  /* ---------------- FILTERED RUNS ---------------- */
  const filteredRuns = useMemo(() => {
    let data = [...runs];
    if (filters.system.trim())
      data = data.filter((r) =>
        (r.system || "").toLowerCase().includes(filters.system.toLowerCase()),
      );
    if (filters.series.trim())
      data = data.filter((r) =>
        (r.series || "").toLowerCase().includes(filters.series.toLowerCase()),
      );
    if (filters.title.trim())
      data = data.filter((r) =>
        (r.title || "").toLowerCase().includes(filters.title.toLowerCase()),
      );
    if (filters.user.trim())
      data = data.filter((r) =>
        (r.user || "").toLowerCase().includes(filters.user.toLowerCase()),
      );
    if (filters.scheduleMode === "date") {
      if (filters.dateFrom)
        data = data.filter((r) => r.date >= filters.dateFrom);
      if (filters.dateTo) data = data.filter((r) => r.date <= filters.dateTo);
    }
    if (filters.scheduleMode === "period" && filters.period > 0) {
      const cutoff = Date.now() - filters.period * 86400000;
      data = data.filter((r) => new Date(r.date).getTime() >= cutoff);
    }
    if (filters.visibility === "central")
      data = data.filter((_, i) => i % 3 !== 0);
    if (filters.visibility === "noncentral")
      data = data.filter((_, i) => i % 3 === 0);
    if (filters.baselineOnly) data = data.filter((_, i) => i % 2 === 0);
    return data;
  }, [runs, filters]);

  /* ---------------- KPI ---------------- */
  const totalRuns = filteredRuns.length;
  const totalP1 = useMemo(
    () => filteredRuns.reduce((a, b) => a + (b.p1 || 0), 0),
    [filteredRuns],
  );
  const totalP2 = useMemo(
    () => filteredRuns.reduce((a, b) => a + (b.p2 || 0), 0),
    [filteredRuns],
  );
  const totalP3 = useMemo(
    () => filteredRuns.reduce((a, b) => a + (b.p3 || 0), 0),
    [filteredRuns],
  );
  const healthScore = useMemo(() => {
    const total = totalP1 + totalP2 + totalP3;
    if (total === 0) return 100;
    const weighted = (totalP1 * 3 + totalP2 * 1.5 + totalP3) / total;
    return Math.max(0, Math.round(100 - weighted * 10));
  }, [totalP1, totalP2, totalP3]);

  /* ---------------- CHART DATA ---------------- */
  const chartTrend = useMemo(() => {
    const map: Record<
      string,
      { date: string; p1: number; p2: number; p3: number }
    > = {};
    filteredRuns.forEach((r) => {
      if (!map[r.date]) map[r.date] = { date: r.date, p1: 0, p2: 0, p3: 0 };
      map[r.date].p1 += r.p1 || 0;
      map[r.date].p2 += r.p2 || 0;
      map[r.date].p3 += r.p3 || 0;
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
    [totalP1, totalP2, totalP3],
  );

  const chartQuality = useMemo(
    () =>
      chartTrend.map((r) => ({
        date: r.date,
        score: Math.max(0, 100 - Math.round((r.p1 * 5 + r.p2 * 2 + r.p3) / 5)),
      })),
    [chartTrend],
  );

  const chartHeatmap = useMemo(
    () =>
      filteredRuns.slice(0, 14).map((r) => ({
        value: r.p1 * 10 + r.p2 * 3 + r.p3,
      })),
    [filteredRuns],
  );

  /* ---------------- AI ANALYSIS (MOCK — READY FOR REAL API) ---------------- */
  const generateAiAnalysis = (
    userMessage: string | undefined,
    view: "manager" | "developer",
    snap: {
      runs: Run[];
      p1: number;
      p2: number;
      p3: number;
      score: number;
      period: number;
      system: string;
      series: { name: string; value: number }[];
      trend: { date: string; p1: number; p2: number; p3: number }[];
      totalRuns: number;
    },
  ): string => {
    const topSeries = [...snap.series].sort((a, b) => b.value - a.value)[0];
    const sysMap: Record<string, number> = {};
    snap.runs.forEach((r) => {
      const s = r.system || "Unknown";
      sysMap[s] = (sysMap[s] || 0) + r.p1;
    });
    const topSystem = Object.entries(sysMap).sort((a, b) => b[1] - a[1])[0];
    const prdP1 = snap.runs
      .filter((r) => r.system?.includes("PRD"))
      .reduce((a, b) => a + (b.p1 || 0), 0);
    const riskLevel =
      snap.p1 > 500
        ? "CRITICAL"
        : snap.p1 > 200
          ? "HIGH"
          : snap.p1 > 50
            ? "MEDIUM"
            : "LOW";
    const riskColor =
      riskLevel === "CRITICAL"
        ? "🔴"
        : riskLevel === "HIGH"
          ? "🟠"
          : riskLevel === "MEDIUM"
            ? "🟡"
            : "🟢";
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
          ? `The highest risk system is **${topSystem[0]}** with ${topSystem[1]} P1 critical findings.\n\nIn a banking/insurance context, P1 findings in ${topSystem[0]} represent potential compliance violations that must be remediated before the next transport cycle. Recommend immediate code review and fix prioritization for this system.`
          : "No system-specific data available for the current filter selection.";
      if (q.includes("fix") || q.includes("release") || q.includes("before"))
        return `## Pre-Release Checklist\n\n1. **Resolve all P1 findings in PRD_GRP** — ${prdP1} critical findings currently open. Blocking for production transport.\n2. **Review ${topSeries?.name || "DBB_RELEASE"} run results** — highest concentration of findings.\n3. **Security check failures** — authority check or SQL injection findings must be fixed regardless of priority.\n4. **Transport to CON** — run a full ATC check on consolidation before promoting to production.\n\nEstimated remediation effort: ${Math.ceil(snap.p1 / 10)} developer days for P1 items only.`;
      if (q.includes("trend"))
        return `## Trend Analysis — Last ${snap.period} Days\n\nP1 critical findings are **${trendDir}** over the analyzed period.\n\n- Start of period: ${snap.trend[0]?.p1 || 0} P1 findings\n- End of period: ${snap.trend[snap.trend.length - 1]?.p1 || 0} P1 findings\n- Total runs analyzed: ${snap.totalRuns}\n\nIn banking/insurance environments, an increasing P1 trend requires escalation to the compliance team and a formal remediation plan with deadlines.`;
      if (
        q.includes("production") ||
        q.includes("prd") ||
        q.includes("regulat")
      )
        return `## Production & Regulatory Risk Assessment\n\n${prdP1 > 0 ? `🔴 **ALERT: ${prdP1} P1 findings detected in production systems.**` : "🟢 No P1 findings in production systems currently."}\n\n- **GDPR/Data Privacy**: Unauthorized data access findings are reportable incidents\n- **SOX Compliance**: P1 findings in FI/CO objects must be remediated within 30 days\n- **Banking Regulations**: Security vulnerabilities in payment processing may trigger mandatory disclosure\n\nRecommend: Engage compliance officer if P1 count in PRD exceeds 10 findings.`;
      if (q.includes("series") || q.includes("problematic"))
        return `## Run Series Analysis\n\nMost problematic series: **${topSeries?.name || "N/A"}** with ${topSeries?.value || 0} runs.\n\n${snap.series.map((s, i) => `${i + 1}. ${s.name}: ${s.value} runs`).join("\n")}\n\nRecommendation: Focus remediation on ${topSeries?.name || "the top series"} first.`;
      if (
        q.includes("manag") ||
        q.includes("summar") ||
        q.includes("executive")
      )
        return `## Executive Summary\n\nOverall code quality risk: ${riskColor} **${riskLevel}**\n\nYour SAP landscape has ${snap.totalRuns} ATC check runs in the last ${snap.period} days with ${snap.p1} critical findings.\n${prdP1 > 0 ? `${prdP1} are in production — direct regulatory risk.` : "No critical findings in production — good compliance posture."}\n\n## Key Numbers\n- Total Runs: ${snap.totalRuns}\n- Critical (P1): ${snap.p1}\n- Warnings (P2): ${snap.p2}\n- Health Score: ${snap.score}%\n\n## Recommended Action\n${snap.p1 > 100 ? "Initiate immediate code freeze and remediation sprint." : "Continue current quality processes with increased monitoring."}`;
      return `Based on current data (${snap.totalRuns} runs, ${snap.p1} P1, ${snap.p2} P2 findings):\n\nTry asking:\n- System or series risk levels\n- Pre-release fix priorities\n- Regulatory compliance status\n- Trend analysis over time`;
    }

    if (view === "manager") {
      return `## Executive Summary\n\nYour SAP code quality posture is currently ${riskColor} **${riskLevel} RISK**. Across ${snap.totalRuns} ATC check runs in the last ${snap.period} days, ${snap.p1} critical compliance issues were identified.\n\n${prdP1 > 0 ? `⚠️ **${prdP1} critical findings exist in production systems** — direct regulatory exposure for your banking and insurance clients.` : "✅ Production systems are currently clear of critical findings — good compliance posture."}\n\n## Risk Assessment\n\n- **Regulatory Risk**: ${snap.p1 > 200 ? "HIGH — Immediate escalation recommended" : snap.p1 > 50 ? "MEDIUM — Remediation plan required" : "LOW — Continue monitoring"}\n- **Client Impact**: ${snap.p1 > 100 ? "Potential SLA breach if unresolved before next delivery" : "Within acceptable thresholds"}\n- **Audit Readiness**: ${snap.score > 70 ? "Satisfactory" : "Improvement required before next audit"}\n\n## Key Findings\n\n- Most active check series: **${topSeries?.name || "N/A"}**\n- Highest risk system: **${topSystem?.[0] || "N/A"}** — concentrate remediation here\n- P1 to P2 ratio: ${snap.p2 > 0 ? (snap.p1 / snap.p2).toFixed(2) : "N/A"} — ${snap.p1 / Math.max(snap.p2, 1) > 0.5 ? "concerning, indicates systemic issues" : "acceptable range"}\n\n## Recommendations\n\n1. **Immediate**: Freeze transports from systems with P1 findings until resolved\n2. **This week**: Assign dedicated developer capacity to top 5 P1 categories\n3. **This month**: Implement mandatory ATC gates in all transport routes\n\n## Trend Prediction\n\nP1 findings are ${trendDir}. ${trendDir.includes("⬆️") ? "Intervention required to prevent compliance breach before quarter end." : "Maintain current quality practices."}`;
    }

    return `## Executive Summary\n\n${snap.totalRuns} ATC runs analyzed. ${snap.p1} P1 / ${snap.p2} P2 / ${snap.p3} P3 findings. Risk: ${riskColor} ${riskLevel}. Health: ${snap.score}%.\n\n## Risk Assessment\n\n- **Transport Blocks**: ${snap.p1} P1 findings will block transport if ATC gates are enforced\n- **Security Findings**: Check authority check (SU53) and injection vulnerabilities first\n- **Performance**: DB operations in LOOP and missing indexes are likely P1 sources\n- **Production Risk**: ${prdP1} P1 in PRD — ${prdP1 > 0 ? "REQUIRES IMMEDIATE HOTFIX" : "clean"}\n\n## Key Findings\n\n- **Hottest series**: ${topSeries?.name || "N/A"} — review check configuration\n- **Priority system**: ${topSystem?.[0] || "N/A"} with ${topSystem?.[1] || 0} P1 findings\n- **Top issues**: DB ops in LOOPs, dynamic WHERE without escaping, missing authority checks, naming violations\n\n## Recommendations\n\n1. Run transaction SCI on ${topSystem?.[0] || "flagged system"} with full check variant\n2. Fix LOOP+SELECT patterns first — highest performance impact\n3. Review all dynamic SQL for injection vulnerability\n4. Apply ATC exemptions only for documented false positives\n5. Add ATC check to CI/CD pipeline before transport to CON\n\n## Trend Prediction\n\nP1 findings are ${trendDir}. ${trendDir.includes("⬆️") ? "Technical debt accumulating — recommend dedicated refactoring sprint." : "Continue current practices and focus on P2 reduction."}`;
  };

  const generateExecutiveSummary = (
    riskLevel: string,
    riskColor: string,
    prdP1: number,
    topSeries: any,
    topSystem: any,
  ) => {
    return `## Executive Summary\n\nOverall code quality risk: ${riskColor} **${riskLevel}**\n\nYour SAP landscape has ${totalRuns} ATC check runs in the last ${filters.period} days with ${totalP1} critical findings requiring immediate attention. ${prdP1 > 0 ? `${prdP1} of these are in production systems, posing direct regulatory risk.` : "No critical findings in production — good compliance posture."}\n\n## Key Numbers\n- Total Runs: ${totalRuns}\n- Critical (P1): ${totalP1}\n- Warnings (P2): ${totalP2}\n- Health Score: ${healthScore}%\n\n## Recommended Action\n${totalP1 > 100 ? "Initiate immediate code freeze and remediation sprint before next transport." : "Continue current quality processes with increased monitoring frequency."}`;
  };

  const generateManagerReport = (
    riskLevel: string,
    riskColor: string,
    prdP1: number,
    topSeries: any,
    topSystem: any,
  ) => {
    return `## Executive Summary\n\nYour SAP code quality posture is currently ${riskColor} **${riskLevel} RISK**. Across ${totalRuns} ATC check runs in the last ${filters.period} days, ${totalP1} critical compliance issues were identified that require executive attention.\n\n${prdP1 > 0 ? `⚠️ **${prdP1} critical findings exist in production systems** — this represents direct regulatory exposure for your banking and insurance clients.` : "✅ Production systems are currently clear of critical findings — good compliance posture."}\n\n## Risk Assessment\n\n- **Regulatory Risk**: ${totalP1 > 200 ? "HIGH — Immediate escalation recommended" : totalP1 > 50 ? "MEDIUM — Remediation plan required" : "LOW — Continue monitoring"}\n- **Client Impact**: ${totalP1 > 100 ? "Potential SLA breach if unresolved before next delivery" : "Within acceptable thresholds"}\n- **Audit Readiness**: ${healthScore > 70 ? "Satisfactory" : "Improvement required before next audit"}\n\n## Key Findings\n\n- Most active check series: **${topSeries?.name || "N/A"}** — highest volume of runs\n- Highest risk system: **${topSystem?.[0] || "N/A"}** — concentrate remediation here\n- P1 to P2 ratio: ${totalP2 > 0 ? (totalP1 / totalP2).toFixed(2) : "N/A"} — ${totalP1 / Math.max(totalP2, 1) > 0.5 ? "concerning, indicates systemic issues" : "acceptable range"}\n\n## Recommendations\n\n1. **Immediate**: Freeze transports from systems with P1 findings until resolved\n2. **This week**: Assign dedicated developer capacity to top 5 P1 categories\n3. **This month**: Implement mandatory ATC gates in all transport routes\n\n## Trend Prediction\n\nBased on current velocity, ${totalP1 > chartTrend[0]?.p1 ? "findings are increasing — intervention required to prevent compliance breach before quarter end." : "findings are stable or decreasing — maintain current quality practices."}`;
  };

  const generateDeveloperReport = (
    riskLevel: string,
    riskColor: string,
    prdP1: number,
    topSeries: any,
    topSystem: any,
  ) => {
    return `## Executive Summary\n\n${totalRuns} ATC runs analyzed. ${totalP1} P1 / ${totalP2} P2 / ${totalP3} P3 findings. Overall risk: ${riskColor} ${riskLevel}. Health score: ${healthScore}%.\n\n## Risk Assessment\n\n- **Transport Blocks**: ${totalP1} P1 findings will block transport if ATC gates are enforced\n- **Security Findings**: Pay special attention to authority check (SU53) and injection vulnerabilities\n- **Performance**: DB operations in loops and missing indexes are likely P1 sources\n- **Production Risk**: ${prdP1} P1 findings in PRD — ${prdP1 > 0 ? "REQUIRES IMMEDIATE HOTFIX" : "clean"}\n\n## Key Findings\n\n- **Hottest series**: ${topSeries?.name || "N/A"} — review check configuration and exemption list\n- **Priority system**: ${topSystem?.[0] || "N/A"} with ${topSystem?.[1] || 0} P1 findings — start here\n- **Check categories to focus on**:\n  - DB operations in LOOP constructs (PERFORMANCE)\n  - Dynamic WHERE clauses without escaping (SECURITY)\n  - Missing authority checks on sensitive transactions (SECURITY)\n  - Naming convention violations (NAMING)\n\n## Recommendations\n\n1. Run transaction SCI on ${topSystem?.[0] || "flagged system"} with full check variant\n2. Apply ATC exemptions only for false positives — document all exemptions\n3. Fix LOOP+SELECT patterns first — highest performance impact\n4. Review all dynamic SQL constructs for injection vulnerability\n5. Add ATC check to CI/CD pipeline before transport to CON\n\n## Trend Prediction\n\n${chartTrend.length > 1 && chartTrend[chartTrend.length - 1].p1 > chartTrend[0].p1 ? "P1 count is trending UP — technical debt is accumulating. Recommend dedicated refactoring sprint." : "P1 count is stable or improving — continue current practices and focus on P2 reduction."}`;
  };

  const runAiAnalysis = (userMessage?: string) => {
    const snap = {
      runs: filteredRuns,
      p1: totalP1,
      p2: totalP2,
      p3: totalP3,
      score: healthScore,
      period: filters.period,
      system: filters.system,
      series: chartSeries,
      trend: chartTrend,
      totalRuns: filteredRuns.length,
    };
    const currentView = aiView;
    const msgs = userMessage
      ? [...aiMessages, { role: "user", content: userMessage }]
      : [];

    setAiLoading(true);
    setTimeout(() => {
      try {
        const reply = generateAiAnalysis(userMessage, currentView, snap);
        setAiMessages([...msgs, { role: "assistant", content: reply }]);
      } catch (err) {
        setAiMessages([
          ...msgs,
          {
            role: "assistant",
            content: "Analysis could not be completed. Please try again.",
          },
        ]);
      }
      setAiLoading(false);
    }, 1000);
  };

  /* ---------------- LOADING ---------------- */
  if (loading) {
    return (
      <div className="container">
        <div className="card">Loading dashboard...</div>
      </div>
    );
  }

  /* ---------------- UI ---------------- */
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
                  display: "flex",
                  alignItems: "center",
                  gap: 5,
                  padding: "5px 12px",
                  borderRadius: 7,
                  border: "none",
                  fontSize: 12,
                  fontWeight: 600,
                  cursor: "pointer",
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
          {/* THEME SELECTOR */}
          <select
            className="input"
            value={theme}
            onChange={(e) => setTheme(e.target.value)}
          >
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
          { key: "runs", label: "Run Explorer" },
          { key: "quality", label: "Code Quality" },
          { key: "sla", label: "Alerts & SLA" },
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
        {/* FILTER */}
        <div className="filter-sticky">
          <div className="filter-card-premium">
            <div className="filter-header-premium">
              <div>
                <h3>Filter Runs</h3>
                <div className="subtitle">
                  Refine execution results and analysis
                </div>
              </div>
              <button
                className="btn-secondary"
                onClick={() => setCollapsed(!collapsed)}
              >
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
                      onChange={(e) =>
                        setFilters({ ...filters, system: e.target.value })
                      }
                    />
                  </div>
                  <div className="filter-field">
                    <label>RUN SERIES</label>
                    <input
                      value={filters.series}
                      onChange={(e) =>
                        setFilters({ ...filters, series: e.target.value })
                      }
                    />
                  </div>
                  <div className="filter-field">
                    <label>CHECK RUN TITLE</label>
                    <input
                      value={filters.title}
                      onChange={(e) =>
                        setFilters({ ...filters, title: e.target.value })
                      }
                    />
                  </div>
                  <div className="filter-field">
                    <label>SCHEDULED BY</label>
                    <input
                      value={filters.user}
                      onChange={(e) =>
                        setFilters({ ...filters, user: e.target.value })
                      }
                    />
                  </div>
                  <div className="filter-field">
                    <label>DATE FROM</label>
                    <input
                      type="date"
                      value={filters.dateFrom}
                      onChange={(e) =>
                        setFilters({ ...filters, dateFrom: e.target.value })
                      }
                    />
                  </div>
                  <div className="filter-field">
                    <label>DATE TO</label>
                    <input
                      type="date"
                      value={filters.dateTo}
                      onChange={(e) =>
                        setFilters({ ...filters, dateTo: e.target.value })
                      }
                    />
                  </div>
                  <div className="filter-field">
                    <label>PERIOD (DAYS)</label>
                    <input
                      type="number"
                      value={filters.period}
                      onChange={(e) =>
                        setFilters({
                          ...filters,
                          period: Number(e.target.value),
                        })
                      }
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
                          onChange={() =>
                            setFilters({ ...filters, scheduleMode: "period" })
                          }
                        />{" "}
                        Period
                      </label>
                      <label>
                        <input
                          type="radio"
                          checked={filters.scheduleMode === "date"}
                          onChange={() =>
                            setFilters({ ...filters, scheduleMode: "date" })
                          }
                        />{" "}
                        By Date
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
                          onChange={() =>
                            setFilters({ ...filters, visibility: "central" })
                          }
                        />{" "}
                        Central Only
                      </label>
                      <label>
                        <input
                          type="radio"
                          checked={filters.visibility === "noncentral"}
                          onChange={() =>
                            setFilters({ ...filters, visibility: "noncentral" })
                          }
                        />{" "}
                        Not Central
                      </label>
                      <label>
                        <input
                          type="radio"
                          checked={filters.visibility === "any"}
                          onChange={() =>
                            setFilters({ ...filters, visibility: "any" })
                          }
                        />{" "}
                        Any
                      </label>
                      <label>
                        <input
                          type="checkbox"
                          checked={filters.baselineOnly}
                          onChange={(e) =>
                            setFilters({
                              ...filters,
                              baselineOnly: e.target.checked,
                            })
                          }
                        />{" "}
                        Only Results in Baseline
                      </label>
                    </div>
                  </div>
                </div>

                <div className="filter-actions">
                  <button className="btn-primary" onClick={load}>
                    GO
                  </button>
                  <button
                    className="btn-secondary"
                    onClick={() =>
                      setFilters({
                        system: "",
                        series: "",
                        title: "",
                        user: "",
                        dateFrom: "",
                        dateTo: "",
                        period: 30,
                        scheduleMode: "period",
                        visibility: "any",
                        baselineOnly: false,
                      })
                    }
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

        {/* KPI */}
        <div className="kpi-grid">
          <div className="kpi-card">
            <div className="kpi-title">TOTAL RUNS</div>
            <div className="kpi-value blue-text">{totalRuns}</div>
          </div>
          <div className="kpi-card">
            <div className="kpi-title">CRITICAL (P1)</div>
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

        {/* OVERVIEW */}
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
                  <Bar dataKey="p1" stackId="a" fill="#ef4444" />
                  <Bar dataKey="p2" stackId="a" fill="#f59e0b" />
                  <Bar dataKey="p3" stackId="a" fill="#3b82f6" />
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
                    {COLORS.map((c, i) => (
                      <Cell key={i} fill={c} />
                    ))}
                  </Pie>
                </PieChart>
              </ResponsiveContainer>
            </div>

            <div className="chart-card">
              <h3>Quality Trend</h3>
              <ResponsiveContainer width="100%" height={300}>
                <LineChart data={chartQuality}>
                  <XAxis dataKey="date" />
                  <YAxis />
                  <Tooltip />
                  <Line dataKey="score" stroke="#0a6ed1" />
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
                  <Bar dataKey="value" fill="#3b82f6" />
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
                {(chartHeatmap.length
                  ? chartHeatmap
                  : Array.from({ length: 14 })
                ).map((item: any, i: number) => {
                  const value = item?.value ?? (i * 17) % 100;
                  let bg = "#dbeafe";
                  if (value > 70) bg = "#fecaca";
                  else if (value > 40) bg = "#fde68a";
                  return (
                    <div
                      key={i}
                      title={`Value: ${value}`}
                      style={{
                        height: 42,
                        borderRadius: 8,
                        background: bg,
                        display: "flex",
                        alignItems: "center",
                        justifyContent: "center",
                        fontSize: 11,
                        fontWeight: 700,
                      }}
                    >
                      {value}
                    </div>
                  );
                })}
              </div>
            </div>

            <div className="chart-card large">
              <h3>Check Categories</h3>
              <ResponsiveContainer width="100%" height={300}>
                <RadarChart
                  data={chartCategories.map((c) => ({
                    subject: c.name,
                    value: c.value,
                  }))}
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

        {/* CODE QUALITY */}
        {tab === "quality" && (
          <div className="chart-grid">
            <div className="chart-card">
              <h3>Code quality index</h3>
              <div className="subtitle">Composite score this period</div>
              <div
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: 28,
                  marginTop: 20,
                  marginBottom: 24,
                  flexWrap: "wrap",
                }}
              >
                <div
                  style={{
                    width: 130,
                    height: 130,
                    borderRadius: "50%",
                    border: "12px solid #0a6ed1",
                    borderTopColor: "#dbeafe",
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "center",
                    fontSize: 42,
                    fontWeight: 700,
                  }}
                >
                  72
                </div>
                <div>
                  <div
                    style={{
                      fontSize: 13,
                      letterSpacing: 1,
                      fontWeight: 700,
                      color: "#6b7280",
                    }}
                  >
                    QUALITY INDEX
                  </div>
                  <div
                    style={{
                      marginTop: 10,
                      background: "#fee2e2",
                      color: "#dc2626",
                      padding: "8px 14px",
                      borderRadius: 999,
                      fontSize: 13,
                      display: "inline-block",
                    }}
                  >
                    -4 pts this week
                  </div>
                </div>
              </div>
              <div
                style={{
                  display: "grid",
                  gridTemplateColumns: "1fr 1fr",
                  gap: 14,
                }}
              >
                {[
                  ["MAINTAINABILITY", 68, "#111827"],
                  ["SECURITY", 54, "#dc2626"],
                  ["PERFORMANCE", 71, "#92400e"],
                  ["NAMING / STYLE", 85, "#166534"],
                ].map(([label, value, color], i) => (
                  <div
                    key={i}
                    style={{
                      background: "#f3f4f6",
                      borderRadius: 10,
                      padding: 18,
                      textAlign: "center",
                    }}
                  >
                    <div style={{ fontSize: 11, color: "#6b7280" }}>
                      {label}
                    </div>
                    <div
                      style={{
                        marginTop: 10,
                        fontSize: 22,
                        fontWeight: 700,
                        color: color as string,
                      }}
                    >
                      {value}
                    </div>
                  </div>
                ))}
              </div>
            </div>

            <div className="chart-card">
              <h3>Top violated objects</h3>
              <div className="subtitle">
                Programs/classes with most findings
              </div>
              <div style={{ marginTop: 24 }}>
                {[
                  ["Z_PERF_MONITOR", 48, "#ef4444"],
                  ["ZCL_DATA_PROC", 41, "#ef4444"],
                  ["Z_REPORT_GEN", 35, "#f59e0b"],
                  ["ZIF_CONNECTOR", 29, "#f59e0b"],
                  ["Z_BATCH_JOB", 22, "#3b82f6"],
                ].map(([name, val, color], i) => (
                  <div
                    key={i}
                    style={{
                      display: "grid",
                      gridTemplateColumns: "130px 1fr 30px",
                      gap: 10,
                      alignItems: "center",
                      marginBottom: 16,
                    }}
                  >
                    <div style={{ fontSize: 13 }}>{name}</div>
                    <div
                      style={{
                        height: 8,
                        background: "#f3f4f6",
                        borderRadius: 999,
                        overflow: "hidden",
                      }}
                    >
                      <div
                        style={{
                          width: `${Number(val) * 2}%`,
                          height: "100%",
                          background: color as string,
                          borderRadius: 999,
                        }}
                      />
                    </div>
                    <div style={{ fontSize: 13 }}>{val}</div>
                  </div>
                ))}
              </div>
            </div>

            <div className="chart-card large">
              <h3>Finding resolution SLA</h3>
              <div className="subtitle">
                Age distribution of open findings (days)
              </div>
              <div
                style={{
                  display: "grid",
                  gridTemplateColumns: "repeat(4,1fr)",
                  gap: 18,
                  alignItems: "end",
                  marginTop: 28,
                  height: 260,
                }}
              >
                {[
                  ["0–7 days", 310, "#65a30d"],
                  ["8–30 days", 200, "#f59e0b"],
                  ["31–90 days", 95, "#ef4444"],
                  ["90+ days", 45, "#7f1d1d"],
                ].map(([label, val, color], i) => (
                  <div key={i} style={{ textAlign: "center" }}>
                    <div
                      style={{
                        height: `${Number(val) / 1.4}px`,
                        background: color as string,
                        borderRadius: 6,
                      }}
                    />
                    <div
                      style={{ marginTop: 10, fontSize: 13, color: "#6b7280" }}
                    >
                      {label}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* ALERTS & SLA */}
        {tab === "sla" && (
          <div className="chart-grid">
            <div className="chart-card">
              <h3>Active alerts</h3>
              <div className="subtitle">Requires immediate attention</div>
              <div style={{ marginTop: 24 }}>
                {[
                  [
                    "Critical P1 spike: DBB_RELEASE exceeded threshold (+49 errors)",
                    "#ef4444",
                    "Today 02:14",
                  ],
                  [
                    "Run DBB_WEEKLY exceeded SLA duration (18m vs 10m target)",
                    "#f59e0b",
                    "Today 00:31",
                  ],
                  [
                    "Security check package: 12 new vulnerabilities since last baseline",
                    "#f59e0b",
                    "Yesterday 23:55",
                  ],
                  [
                    "3 consecutive clean runs achieved on DBB_HOTFIX series",
                    "#3b82f6",
                    "Apr 19",
                  ],
                ].map(([text, color, time], i) => (
                  <div
                    key={i}
                    style={{
                      display: "grid",
                      gridTemplateColumns: "14px 1fr",
                      gap: 10,
                      padding: "14px 0",
                      borderBottom: i !== 3 ? "1px solid #f0f0f0" : "none",
                    }}
                  >
                    <div
                      style={{
                        width: 10,
                        height: 10,
                        borderRadius: "50%",
                        background: color as string,
                        marginTop: 6,
                      }}
                    />
                    <div>
                      <div style={{ fontSize: 14 }}>{text}</div>
                      <div
                        style={{ fontSize: 12, color: "#6b7280", marginTop: 6 }}
                      >
                        {time}
                      </div>
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
                  [
                    "P1 Critical",
                    72,
                    "#ef4444",
                    "Target: 24h - Avg actual: 31h",
                  ],
                  [
                    "P2 Warning",
                    88,
                    "#f59e0b",
                    "Target: 72h - Avg actual: 58h",
                  ],
                  ["P3 Info", 95, "#3b82f6", "Target: 14d - Avg actual: 9d"],
                  ["P4 Note", 99, "#737373", "Target: 30d - Avg actual: 12d"],
                ].map(([label, val, color, sub], i) => (
                  <div key={i} style={{ marginBottom: 22 }}>
                    <div
                      style={{
                        display: "grid",
                        gridTemplateColumns: "110px 1fr 45px",
                        gap: 10,
                        alignItems: "center",
                      }}
                    >
                      <div style={{ fontSize: 14 }}>{label}</div>
                      <div
                        style={{
                          height: 8,
                          background: "#f3f4f6",
                          borderRadius: 999,
                          overflow: "hidden",
                        }}
                      >
                        <div
                          style={{
                            width: `${val}%`,
                            height: "100%",
                            background: color as string,
                          }}
                        />
                      </div>
                      <div style={{ fontSize: 14 }}>{val}%</div>
                    </div>
                    <div
                      style={{
                        marginLeft: 120,
                        marginTop: 6,
                        fontSize: 12,
                        color: "#6b7280",
                      }}
                    >
                      {sub}
                    </div>
                  </div>
                ))}
              </div>
            </div>

            <div className="chart-card large">
              <h3>Schedule adherence</h3>
              <div className="subtitle">
                Planned vs actual run times this week
              </div>
              <ResponsiveContainer width="100%" height={300}>
                <BarChart
                  data={[
                    { day: "Mon", planned: 6, actual: 6 },
                    { day: "Tue", planned: 6, actual: 7 },
                    { day: "Wed", planned: 6, actual: 5 },
                    { day: "Thu", planned: 6, actual: 6 },
                    { day: "Fri", planned: 6, actual: 8 },
                    { day: "Sat", planned: 2, actual: 2 },
                    { day: "Sun", planned: 2, actual: 1 },
                  ]}
                >
                  <XAxis dataKey="day" />
                  <YAxis />
                  <Tooltip />
                  <Bar dataKey="actual" fill="#0a6ed1" radius={[4, 4, 0, 0]} />
                  <Bar dataKey="planned" fill="#bfdbfe" radius={[4, 4, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>
        )}

        {/* RUN EXPLORER */}
        {tab === "runs" && (
          <div className="table-card premium-results">
            <div className="table-toolbar">
              <h3>Check run results</h3>
              <div className="toolbar-actions">
                <button
                  className="btn-secondary"
                  onClick={() => {
                    const headers = [
                      "ID",
                      "Series",
                      "Title",
                      "User",
                      "System",
                      "Date",
                      "P1",
                      "P2",
                      "P3",
                    ];
                    const rows = filteredRuns.map((r) => [
                      r.ID,
                      r.series,
                      r.title,
                      r.user,
                      r.system,
                      r.date,
                      r.p1,
                      r.p2,
                      r.p3,
                    ]);
                    const csv = [headers, ...rows]
                      .map((r) => r.join(","))
                      .join("\n");
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
                <button className="btn-secondary" onClick={load}>
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
                    <th>DURATION</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredRuns.map((r, i) => {
                    const total = r.p1 + r.p2 + r.p3 || 1;
                    const p1w = (r.p1 / total) * 100;
                    const p2w = (r.p2 / total) * 100;
                    const p3w = (r.p3 / total) * 100;
                    const highRisk = r.p1 > 20;
                    return (
                      <tr
                        key={r.ID}
                        style={{ cursor: "pointer" }}
                        onClick={() => {
                          setSelectedRun(r);
                          setDrawerOpen(true);
                        }}
                      >
                        <td>
                          <span className="pill-series">
                            {r.series || "DBB_DAILY"}
                          </span>
                        </td>
                        <td>{r.title || "Daily Nightly Check"}</td>
                        <td>{r.user}</td>
                        <td>{r.date}</td>
                        <td>
                          <span className="badge-red">{r.p1}</span>
                        </td>
                        <td>
                          <span className="badge-orange">{r.p2}</span>
                        </td>
                        <td>
                          <span className="badge-blue">{r.p3}</span>
                        </td>
                        <td>
                          <div className="sev-bar">
                            <span
                              className="sev-red"
                              style={{ width: `${p1w}%` }}
                            />
                            <span
                              className="sev-orange"
                              style={{ width: `${p2w}%` }}
                            />
                            <span
                              className="sev-blue"
                              style={{ width: `${p3w}%` }}
                            />
                          </div>
                        </td>
                        <td>
                          <span
                            className={
                              highRisk ? "status-risk" : "status-error"
                            }
                          >
                            {highRisk ? "High Risk" : "Has Errors"}
                          </span>
                        </td>
                        <td>
                          <span
                            className={
                              i % 3 === 0 ? "central-no" : "central-yes"
                            }
                          >
                            {i % 3 === 0 ? "No" : "Central"}
                          </span>
                        </td>
                        <td>
                          {4 + (i % 7)}m {String(10 + i * 3).padStart(2, "0")}s
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* RUN DETAIL DRAWER */}
        {tab === "runs" && drawerOpen && selectedRun && (
          <div className="drawer-overlay">
            <div className="drawer-panel">
              <div className="drawer-header">
                <div>
                  <h2>{selectedRun.title || "Daily Nightly Check"}</h2>
                  <div className="drawer-sub">
                    Run ID: {selectedRun.series || "DBB_DAILY"} | Executed:{" "}
                    {selectedRun.date}
                  </div>
                </div>
                <button
                  className="drawer-close"
                  onClick={() => setDrawerOpen(false)}
                >
                  ✕
                </button>
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
                <p>
                  SELECT inside LOOP detected. Use bulk fetch / FOR ALL ENTRIES.
                </p>
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

      {/* ============ AI ANALYSIS PANEL ============ */}
      {aiOpen && (
        <div
          onClick={(e) => {
            if (e.target === e.currentTarget) setAiOpen(false);
          }}
          style={{
            position: "fixed",
            inset: 0,
            background: "rgba(0,0,0,0.35)",
            zIndex: 1000,
            display: "flex",
            justifyContent: "flex-end",
          }}
        >
          <div
            style={{
              width: "min(800px, 100vw)",
              height: "100vh",
              background: "var(--card-bg, #ffffff)",
              boxShadow: "-4px 0 32px rgba(0,0,0,0.18)",
              display: "flex",
              flexDirection: "column",
              padding: "20px 20px 16px 20px",
              boxSizing: "border-box",
              overflowX: "hidden",
            }}
          >
            {/* AI HEADER */}
            <div
              style={{
                borderBottom: "1px solid #e5e7eb",
                paddingBottom: 14,
                flexShrink: 0,
                display: "flex",
                justifyContent: "space-between",
                alignItems: "flex-start",
                gap: 12,
                flexWrap: "wrap",
              }}
            >
              <div style={{ minWidth: 0 }}>
                <h2 style={{ fontSize: 18, margin: 0 }}>✨ AI Analysis</h2>
                <div
                  style={{
                    fontSize: 11,
                    color: "#6b7280",
                    marginTop: 4,
                    whiteSpace: "nowrap",
                    overflow: "hidden",
                    textOverflow: "ellipsis",
                  }}
                >
                  {filteredRuns.length} runs · {filters.period} days ·{" "}
                  {filters.system || "All systems"} ·{" "}
                  {new Date().toLocaleDateString("en-IN", {
                    day: "numeric",
                    month: "short",
                    year: "numeric",
                    hour: "2-digit",
                    minute: "2-digit",
                  })}
                </div>
              </div>
              <div style={{ display: "flex", alignItems: "center", gap: 8, flexShrink: 0 }}>
                {/* MANAGER / DEVELOPER TOGGLE */}
                <div
                  style={{
                    display: "flex",
                    background: "#f3f4f6",
                    borderRadius: 8,
                    padding: 3,
                  }}
                >
                  {(["manager", "developer"] as const).map((v) => (
                    <button
                      key={v}
                      onClick={() => {
                        const snap = {
                          runs: filteredRuns,
                          p1: totalP1,
                          p2: totalP2,
                          p3: totalP3,
                          score: healthScore,
                          period: filters.period,
                          system: filters.system,
                          series: chartSeries,
                          trend: chartTrend,
                          totalRuns: filteredRuns.length,
                        };
                        setAiView(v);
                        setAiMessages([]);
                        setAiLoading(true);
                        setTimeout(() => {
                          try {
                            const reply = generateAiAnalysis(undefined, v, snap);
                            setAiMessages([{ role: "assistant", content: reply }]);
                          } catch {
                            setAiMessages([{ role: "assistant", content: "Analysis could not be completed." }]);
                          }
                          setAiLoading(false);
                        }, 1000);
                      }}
                      style={{
                        padding: "5px 12px",
                        borderRadius: 6,
                        border: "none",
                        fontSize: 12,
                        fontWeight: 600,
                        cursor: "pointer",
                        background: aiView === v ? "#0a6ed1" : "transparent",
                        color: aiView === v ? "white" : "#6b7280",
                        whiteSpace: "nowrap",
                      }}
                    >
                      {v === "manager" ? "👔 Manager" : "💻 Developer"}
                    </button>
                  ))}
                </div>
                <button
                  className="drawer-close"
                  onClick={() => setAiOpen(false)}
                >
                  ✕
                </button>
              </div>
            </div>

            {/* MESSAGES AREA */}
            <div
              style={{
                flex: 1,
                overflowY: "auto",
                overflowX: "hidden",
                padding: "16px 0",
                display: "flex",
                flexDirection: "column",
                gap: 16,
              }}
            >
              {/* LOADING INITIAL */}
              {aiLoading && aiMessages.length === 0 && (
                <div
                  style={{ textAlign: "center", padding: 40, color: "#6b7280" }}
                >
                  <div style={{ fontSize: 32, marginBottom: 12 }}>🤖</div>
                  <div style={{ fontSize: 14 }}>
                    Analyzing {filteredRuns.length} ATC runs...
                  </div>
                  <div style={{ fontSize: 12, marginTop: 6, color: "#9ca3af" }}>
                    Checking compliance risk for banking & insurance context
                  </div>
                </div>
              )}

              {/* MESSAGES */}
              {aiMessages.map((msg, i) => (
                <div
                  key={i}
                  style={{
                    display: "flex",
                    flexDirection: "column",
                    gap: 4,
                    alignItems: msg.role === "user" ? "flex-end" : "flex-start",
                  }}
                >
                  <div
                    style={{
                      fontSize: 11,
                      color: "#9ca3af",
                      paddingLeft: msg.role === "assistant" ? 4 : 0,
                    }}
                  >
                    {msg.role === "user" ? "You" : "🤖 AI Assistant"}
                  </div>
                  <div
                    style={{
                      maxWidth: "92%",
                      width: msg.role === "assistant" ? "100%" : "auto",
                      padding: "12px 16px",
                      borderRadius: 12,
                      fontSize: 13,
                      lineHeight: 1.75,
                      background: msg.role === "user" ? "#0a6ed1" : "#f8faff",
                      color: msg.role === "user" ? "white" : "#1f2937",
                      border:
                        msg.role === "assistant" ? "1px solid #e0e7ff" : "none",
                      boxSizing: "border-box",
                      wordBreak: "break-word",
                    }}
                  >
                    {msg.content.split("\n").map((line, j) => {
                      if (line.startsWith("## "))
                        return (
                          <div
                            key={j}
                            style={{
                              fontWeight: 700,
                              fontSize: 14,
                              color: "#0a6ed1",
                              marginTop: j > 0 ? 16 : 0,
                              marginBottom: 6,
                              borderBottom: "1px solid #e0e7ff",
                              paddingBottom: 4,
                            }}
                          >
                            {line.replace("## ", "")}
                          </div>
                        );
                      if (line.startsWith("- ") || line.startsWith("• ")) {
                        const text = line.replace(/^[-•] /, "");
                        const parts = text.split("**");
                        return (
                          <div key={j} style={{ paddingLeft: 12, marginBottom: 4 }}>
                            {"• "}
                            {parts.map((p, k) =>
                              k % 2 === 1 ? <strong key={k}>{p}</strong> : p,
                            )}
                          </div>
                        );
                      }
                      if (/^\d+\./.test(line))
                        return (
                          <div
                            key={j}
                            style={{
                              paddingLeft: 12,
                              marginBottom: 4,
                              fontWeight: 500,
                            }}
                          >
                            {line}
                          </div>
                        );
                      if (line.includes("**")) {
                        const parts = line.split("**");
                        return (
                          <div
                            key={j}
                            style={{ marginBottom: line === "" ? 8 : 2 }}
                          >
                            {parts.map((p, k) =>
                              k % 2 === 1 ? <strong key={k}>{p}</strong> : p,
                            )}
                          </div>
                        );
                      }
                      return (
                        <div
                          key={j}
                          style={{ marginBottom: line === "" ? 8 : 2 }}
                        >
                          {line}
                        </div>
                      );
                    })}
                  </div>
                  {/* COPY + DOWNLOAD for last assistant message */}
                  {msg.role === "assistant" && i === aiMessages.length - 1 && (
                    <div
                      style={{
                        display: "flex",
                        gap: 8,
                        paddingLeft: 4,
                        marginTop: 4,
                        flexWrap: "wrap",
                      }}
                    >
                      <button
                        onClick={() =>
                          navigator.clipboard.writeText(msg.content)
                        }
                        style={{
                          fontSize: 11,
                          padding: "4px 10px",
                          borderRadius: 6,
                          border: "1px solid #e5e7eb",
                          background: "white",
                          cursor: "pointer",
                          color: "#6b7280",
                        }}
                      >
                        📋 Copy
                      </button>
                      <button
                        onClick={() => {
                          const blob = new Blob(
                            [
                              `ATC AI Analysis Report\nGenerated: ${new Date().toLocaleString()}\nView: ${aiView === "manager" ? "Manager" : "Developer"}\nRuns: ${filteredRuns.length} | Period: ${filters.period} days | System: ${filters.system || "All"}\n\n${msg.content}`,
                            ],
                            { type: "text/plain" },
                          );
                          const url = URL.createObjectURL(blob);
                          const a = document.createElement("a");
                          a.href = url;
                          a.download = `atc-ai-analysis-${new Date().toISOString().split("T")[0]}.txt`;
                          a.click();
                          URL.revokeObjectURL(url);
                        }}
                        style={{
                          fontSize: 11,
                          padding: "4px 10px",
                          borderRadius: 6,
                          border: "1px solid #e5e7eb",
                          background: "white",
                          cursor: "pointer",
                          color: "#6b7280",
                        }}
                      >
                        ⬇️ Download Report
                      </button>
                    </div>
                  )}
                </div>
              ))}

              {/* LOADING FOLLOW-UP */}
              {aiLoading && aiMessages.length > 0 && (
                <div
                  style={{
                    display: "flex",
                    alignItems: "center",
                    gap: 8,
                    color: "#6b7280",
                    fontSize: 13,
                    paddingLeft: 4,
                  }}
                >
                  <div
                    style={{
                      width: 8,
                      height: 8,
                      borderRadius: "50%",
                      background: "#0a6ed1",
                    }}
                  />
                  AI is analyzing...
                </div>
              )}
            </div>

            {/* SUGGESTED QUESTIONS */}
            {aiMessages.length > 0 && !aiLoading && (
              <div
                style={{
                  borderTop: "1px solid #f3f4f6",
                  paddingTop: 10,
                  paddingBottom: 8,
                  flexShrink: 0,
                }}
              >
                <div
                  style={{ fontSize: 11, color: "#9ca3af", marginBottom: 8 }}
                >
                  Suggested questions:
                </div>
                <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                  {SUGGESTED_QUESTIONS.map((q, i) => (
                    <button
                      key={i}
                      onClick={() => setAiInput(q)}
                      style={{
                        fontSize: 11,
                        padding: "5px 10px",
                        borderRadius: 999,
                        border: "1px solid #c7d2fe",
                        background: "#eef2ff",
                        color: "#4f46e5",
                        cursor: "pointer",
                        whiteSpace: "nowrap",
                      }}
                    >
                      {q}
                    </button>
                  ))}
                </div>
              </div>
            )}

            {/* INPUT */}
            <div
              style={{
                borderTop: "1px solid #e5e7eb",
                paddingTop: 12,
                display: "flex",
                gap: 8,
                flexShrink: 0,
              }}
            >
              <input
                value={aiInput}
                onChange={(e) => setAiInput(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter" && aiInput.trim() && !aiLoading) {
                    runAiAnalysis(aiInput);
                    setAiInput("");
                  }
                }}
                placeholder="Ask a follow-up question... (e.g. Which system is most at risk?)"
                style={{
                  flex: 1,
                  minWidth: 0,
                  padding: "10px 14px",
                  borderRadius: 10,
                  border: "1px solid #d1d5db",
                  fontSize: 13,
                  outline: "none",
                  boxSizing: "border-box",
                }}
              />
              <button
                onClick={() => {
                  if (aiInput.trim() && !aiLoading) {
                    runAiAnalysis(aiInput);
                    setAiInput("");
                  }
                }}
                disabled={!aiInput.trim() || aiLoading}
                style={{
                  padding: "10px 16px",
                  borderRadius: 10,
                  border: "none",
                  background:
                    aiInput.trim() && !aiLoading ? "#0a6ed1" : "#e5e7eb",
                  color: aiInput.trim() && !aiLoading ? "white" : "#9ca3af",
                  cursor: aiInput.trim() && !aiLoading ? "pointer" : "default",
                  fontSize: 13,
                  fontWeight: 600,
                  flexShrink: 0,
                }}
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