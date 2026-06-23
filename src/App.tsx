import React, {
  useEffect,
  useMemo,
  useState,
  useCallback,
  useRef,
} from "react";

// ─── Types ────────────────────────────────────────────────────────────────────
type Run = {
  ID: string;
  scheduledBy?: string;
  scheduledSys?: string;
  runDate?: string;
  central?: boolean;
  user?: string;
  system?: string;
  date?: string;
  series?: string;
  title?: string;
  p1: number;
  p2: number;
  p3: number;
  p4: number;
  RunKind?: string;
};
type KPI = { p1?: number; p2?: number; p3?: number; health?: number };
type AiMessage = { role: string; content: string };
type DevProfile = {
  UserId: string;
  DisplayName: string;
  Email: string;
  ProductId: string;
  TeamId: string;
  IsAdmin: boolean;
  IsActive: boolean;
};

type CheckModule = {
  ModuleId: string;
  CiId: string;
  ModuleIx: number;
  ModuleTitle: string;
};

// ─── Pure helpers ─────────────────────────────────────────────────────────────
const parseSince = (s: string | null | undefined): Date | null => {
  if (!s || s.length < 8) return null;
  const y = +s.slice(0, 4),
    mo = +s.slice(4, 6) - 1,
    d = +s.slice(6, 8);
  if (isNaN(y) || isNaN(mo) || isNaN(d)) return null;
  return new Date(y, mo, d);
};
const ageDays = (d: Date): number =>
  Math.floor((Date.now() - d.getTime()) / 86_400_000);
const computeScore = (
  p1: number,
  p2: number,
  p3: number,
  p4: number,
): number => {
  const t = p1 + p2 + p3 + p4;
  if (t === 0) return 100;
  return Math.max(
    0,
    Math.round(100 - Math.log10(p1 * 4 + p2 * 2 + p3 + p4 * 0.5 + 1) * 20),
  );
};

// ─── Static configuration ─────────────────────────────────────────────────────
type SystemConfig = {
  SystemId: string;
  SystemName: string;
  SystemType: string;
  BaseUrl: string;
  Host: string;
  SystemIdLabel: string;
  Description: string;
  IsActive: string;
};

// Bootstrap URL — used only for initial Systems fetch.
// This MUST point to a valid NetWeaver OData endpoint that exposes the Systems entity.
// Once systems are loaded, this is no longer used.
const BOOTSTRAP_URL =
  "/sap/opu/odata4/sap/zui_atc_monitor_o4_bnd/srvd_a2x/sap/zui_atc_monitor_o4/0001";
const SUGGESTED_QUESTIONS = [
  "Which system has the highest compliance risk?",
  "What should I fix before the next release?",
  "Summarize P1 findings for management",
  "What is the trend over the last 30 days?",
  "Are there any regulatory risks in production?",
  "Which run series is most problematic?",
];
// Patterns used as FALLBACK only — primary classification uses QualityStandard from backend
const SECURITY_CI_PATTERNS = [
  "CVA",
  "SEC",
  "AUTH",
  "CRIT",
  "DYN_SQL",
  "DYN_SEL",
  "DDIC_LOG",
  "SHO_CLIENT",
  "SU22",
  "SVIM",
  "RFC_CALL",
  "INJECT",
  "XSS",
  "SECURITY",
];
const SECURITY_TITLE_PATTERNS = [
  "SQL INJECTION",
  "INJECT",
  "AUTHORITY",
  "AUTH CHECK",
  "AUTHORIT",
  "HARD-COD",
  "HARDCOD",
  "DYNAMIC WHERE",
  "DYNAMIC SQL",
  "DYNAMIC SELECT",
  "RFC",
  "REMOTE-ENABLED",
  "REMOTE ENABLED",
  "XSS",
  "CROSS-SITE",
  "PRIVILEGE",
  "BYPASS",
  "ESCAPE",
  "CRITICAL STATEMENT",
  "SU22",
  "SU24",
  "PERMISSION",
  "ACCESS CONTROL",
  "MISSING CHECK",
  "SECURITY",
];
// NVD quick-search topics for CVE Intelligence widget
const CVE_QUICK_TOPICS = [
  { label: "SQL Injection", query: "SQL injection ABAP" },
  { label: "Auth Bypass", query: "authorization bypass SAP" },
  { label: "RFC Exploit", query: "RFC remote function module SAP" },
  { label: "Priv. Escalation", query: "privilege escalation SAP ABAP" },
  { label: "XSS / BSP", query: "cross-site scripting SAP BSP" },
  { label: "Code Injection", query: "code injection ABAP" },
];

function isTitleSecurityCheck(t: string): boolean {
  if (!t) return false;
  const u = t.toUpperCase();
  return SECURITY_TITLE_PATTERNS.some((p) => u.includes(p));
}
function resolveCheckTitle(
  tmpl: string | null | undefined,
  nav: string | null | undefined,
): string {
  if (!tmpl?.trim()) return "";
  if (!nav?.trim()) return tmpl;
  let r = tmpl;
  for (let i = 1; i <= 4; i++) {
    const m =
      new RegExp(`<PARAM${i}>(.*?)<\\/PARAM${i}>`, "s").exec(nav) ||
      new RegExp(`<PARAM_${i}>(.*?)<\\/PARAM_${i}>`, "s").exec(nav) ||
      new RegExp(`<P${i}>(.*?)<\\/P${i}>`, "s").exec(nav);
    if (m) {
      r = r
        .replaceAll(`&${i}`, m[1].trim())
        .replaceAll(`&${String.fromCharCode(64 + i)}`, m[1].trim());
    }
  }
  return r;
}

// Security knowledge — your application's security documentation (intentionally static)
const SECURITY_KNOWLEDGE: Record<
  string,
  {
    riskName: string;
    severity: "CRITICAL" | "HIGH" | "MEDIUM";
    description: string;
    attackScenario: string;
    fixGuidance: string;
  }
> = {
  CVA: {
    riskName: "Code Vulnerability Analysis (CVA)",
    severity: "CRITICAL",
    description:
      "SAP CVA detects exploitable vulnerabilities including SQL injection, authority check bypass, and OS command injection in ABAP code.",
    attackScenario:
      "An attacker with dialog or RFC access can exploit these to read arbitrary data, bypass authorization, or execute OS commands on the application server.",
    fixGuidance:
      "Replace dynamic SQL with static Open SQL. Add missing authority checks before sensitive operations. Never pass user input directly into dynamic statements.",
  },
  SEC: {
    riskName: "Extended Security Check",
    severity: "HIGH",
    description:
      "Identifies ABAP code patterns violating SAP security best practices — insecure file access, hardcoded credentials, insecure RFC calls.",
    attackScenario:
      "Exploitable by an authenticated user to escalate privileges, read configuration data, or access functionality beyond their authorization.",
    fixGuidance:
      "Follow SAP Security Note guidance per check. Review transaction SU24 for proper authorization object maintenance.",
  },
  AUTH: {
    riskName: "Missing or Bypassed Authority Check",
    severity: "CRITICAL",
    description:
      "Authority checks are missing or can be bypassed before sensitive operations. This is the most common SAP security vulnerability.",
    attackScenario:
      "Any authenticated SAP user can execute functionality or read data they are not authorized for.",
    fixGuidance:
      "Add AUTHORITY-CHECK OBJECT statements before sensitive READ, WRITE, or EXECUTE operations. Ensure checks cannot be bypassed via early EXIT. Maintain SU22/SU24 entries.",
  },
  CRIT: {
    riskName: "Critical Statement",
    severity: "CRITICAL",
    description:
      "Statements flagged as critical — INSERT/UPDATE/DELETE on cross-client tables, SUBMIT with dangerous parameters, or CALL TRANSACTION bypassing authorization.",
    attackScenario: "Direct manipulation of cross-client configuration data.",
    fixGuidance:
      "Replace cross-client table writes with client-safe alternatives. Use CALL TRANSACTION with WITH AUTHORITY-CHECK.",
  },
  DYN_SQL: {
    riskName: "SQL Injection via Dynamic Open SQL",
    severity: "CRITICAL",
    description:
      "Dynamic WHERE clauses, ORDER BY, or table names constructed from user-controlled input without sanitization.",
    attackScenario:
      "An attacker who controls input can read any table in the SAP database.",
    fixGuidance:
      "Use static Open SQL wherever possible. If dynamic SQL is unavoidable, validate all dynamic parts against a whitelist using CL_ABAP_DYN_PRG=>CHECK_WHITELIST_STR.",
  },
  DYN_SEL: {
    riskName: "Dynamic and Client-Specific SELECT",
    severity: "HIGH",
    description:
      "SELECT statements access cross-client tables or use dynamic client bypasses.",
    attackScenario:
      "An attacker can read data from other SAP clients within the same system.",
    fixGuidance:
      "Add CLIENT SPECIFIED only when explicitly required and controlled. Validate client parameter against sy-mandt.",
  },
  DDIC_LOG: {
    riskName: "Database Table Missing Change Logging",
    severity: "MEDIUM",
    description:
      "A DDIC table storing sensitive business data has logging disabled.",
    attackScenario:
      "An attacker who modifies sensitive data leaves no audit trail.",
    fixGuidance:
      "In SE13, enable logging for the table. Ensure the profile parameter rec/client is set appropriately.",
  },
  SHO_CLIENT: {
    riskName: "Client-Specific Shared Objects",
    severity: "HIGH",
    description:
      "Shared objects methods are accessed without proper client isolation.",
    attackScenario:
      "An attacker can read or manipulate shared memory areas belonging to other clients.",
    fixGuidance:
      "Use client-specific shared object areas. Validate client context before accessing shared memory.",
  },
  SU22: {
    riskName: "Incorrect SU22/SU24 Auth Object Maintenance",
    severity: "MEDIUM",
    description:
      "Authorization objects used in AUTHORITY-CHECK are not correctly maintained in SU22/SU24.",
    attackScenario:
      "Roles generated from PFCG may grant more or fewer authorizations than intended.",
    fixGuidance:
      "Run SU22 for the affected program and maintain all authorization objects. Regenerate affected roles in PFCG.",
  },
  SVIM: {
    riskName: "Authority Check Bypass Pattern",
    severity: "CRITICAL",
    description:
      "The code uses patterns that allow authority checks to be skipped.",
    attackScenario:
      "An attacker who understands the bypass condition can access restricted functionality without authorization.",
    fixGuidance:
      "Ensure AUTHORITY-CHECK result (sy-subrc) is checked immediately and unconditionally.",
  },
  RFC_CALL: {
    riskName: "Insecure RFC / Remote-Enabled Function Module",
    severity: "HIGH",
    description:
      "A remote-enabled function module lacks proper input validation or authorization checks.",
    attackScenario:
      "Any system with RFC connectivity can call this FM and exploit missing validation.",
    fixGuidance:
      "Add AUTHORITY-CHECK at the start of all remote-enabled FMs. Validate all input parameters.",
  },
  INJECT: {
    riskName: "Code Injection Risk",
    severity: "CRITICAL",
    description:
      "User-controlled input is passed to executable contexts without sanitization.",
    attackScenario:
      "An attacker can inject arbitrary ABAP or SQL code — potential full system compromise.",
    fixGuidance:
      "Never pass user input to code generation statements. Validate against a strict allowlist before execution.",
  },
  XSS: {
    riskName: "Cross-Site Scripting in BSP/ICF",
    severity: "HIGH",
    description: "Output written to BSP or ICF responses is not HTML-encoded.",
    attackScenario:
      "An attacker can inject JavaScript running in the victim's browser.",
    fixGuidance:
      "Use CL_HTTP_UTILITY=>ESCAPE_HTML for all user-controlled content written to HTTP responses.",
  },
};

// OBJECT_TYPE_LABELS — SAP DDIC standard domain values (stable, intentionally static).
// Can be made fully dynamic by exposing DD07T via OData entity /ObjectTypes.
const OBJECT_TYPE_LABELS: Record<string, string> = {
  REPO: "Report Source Code and Texts",
  REPS: "Report Source Code",
  PROG: "ABAP Program",
  CLAS: "ABAP Class",
  INTF: "ABAP Interface",
  FUGR: "Function Group",
  FUGS: "Function Group (SAP Part)",
  FUGX: "Function Group (Customer Part)",
  FUNC: "Function Module",
  METH: "Method",
  CINC: "Class Include",
  CLSD: "Class Definition",
  CPUB: "Class Public Header",
  CPRO: "Class Protected Header",
  CPRI: "Class Private Header",
  FORM: "Subroutine (FORM)",
  TRAN: "Transaction Code",
  DEVC: "Package",
  TABL: "Database Table",
  VIEW: "Database View",
  DOMA: "Domain",
  DTEL: "Data Element",
  TYPE: "Type Group",
  DYNP: "Screen",
  MSAG: "Message Class",
  MESS: "Single Message",
  ENQU: "Lock Object",
  SHLP: "Search Help",
  NROB: "Number Range Object",
  DDLS: "CDS Data Definition",
  DDLX: "CDS Metadata Extension",
  SRVD: "Service Definition",
  SRVB: "Service Binding",
  BDEF: "Behavior Definition",
  DCLS: "ABAP Data Control Language Source",
  WAPA: "BSP Application",
  WAPP: "BSP Application Page/Controller",
  HTTP: "HTTP Service",
  SICF: "ICF Service",
  WDYN: "Web Dynpro Component",
  WDYV: "Web Dynpro View",
  WDYC: "Web Dynpro Controller",
  WDYA: "Web Dynpro Application",
  TABT: "Table Technical Attributes",
  INDX: "Table Index",
  TTYP: "Table Type",
  SSFO: "SAP Smart Form",
  SFPF: "Form Object: Form",
  SFPI: "Form Object: Interface",
  DOCU: "Documentation",
  PARA: "SPA/GPA Parameter",
  ACID: "Checkpoint Group",
  ENHS: "Enhancement Spot",
  ENHO: "Enhancement Implementation",
  IEXT: "Enhancement",
  SMOD: "SAP Enhancement",
  CMOD: "Customer Enhancement Project",
  XSLT: "XSLT Transformation",
  LDBA: "Logical Database",
  DIAL: "Dialog Module",
  ACGR: "Authorization Role",
  SUSO: "Authorization Object",
  SUSC: "Authorization Object Class",
  IWMO: "SAP Gateway Model",
  IWSV: "SAP Gateway Service",
  BOBF: "BOPF Business Object",
  SAJC: "Application Job Catalog Entry",
  APLO: "Application Log Object",
  AOBJ: "Archiving Object",
  CHKV: "ATC Check Variant",
  CHKO: "ATC Check",
  RFCT: "RFC Destination",
  DMON: "ABAP Daemon Application",
  SQSC: "Database Procedure Proxy",
  DDSO: "Datastore Object",
  ADSO: "Advanced Datastore Object",
  DDLA: "CDS Annotation Definition",
  EVTB: "RAP Event Binding",
  SAMC: "ABAP Messaging Channel Application",
  SAPC: "ABAP Push Channel Application",
};

// Converts SAP ATC check class names to readable labels — used when no title from backend.
// CL_CI_TEST_DDIC_TABLES → "Ddic Tables"   /SCWM/CL_ATC_FUNCTION_CALL → "Function Call"
function formatCiClassName(ciId: string): string {
  if (!ciId || ciId === "*INVALID*" || ciId === "") return "";
  let n = ciId.toUpperCase();
  n = n.replace(/^\/[^/]+\//, ""); // strip namespace /NS/
  for (const pfx of [
    "CL_CI_TEST_",
    "CL_CI_CHK_",
    "CL_CI_CHECK_",
    "CL_CI_ATC_",
    "CL_CI_",
  ]) {
    if (n.startsWith(pfx)) {
      n = n.slice(pfx.length);
      break;
    }
  }
  return n
    .split("_")
    .filter(Boolean)
    .map((w) => w.charAt(0) + w.slice(1).toLowerCase())
    .join(" ");
}

// ─────────────────────────────────────────────────────────────────────────────
export default function App() {
  // ── Core UI state ──────────────────────────────────────────────────────────
  const [tab, setTab] = useState("overview");
  const [collapsed, setCollapsed] = useState(false);
  const [loading, setLoading] = useState(true);
  const [theme, setTheme] = useState("light");
  const [isMobile, setIsMobile] = useState(window.innerWidth < 768);

  // ── Run / findings state ───────────────────────────────────────────────────
  const [runs, setRuns] = useState<Run[]>([]);
  const [kpi, setKpi] = useState<KPI>({});
  const [selectedRun, setSelectedRun] = useState<Run | null>(null);
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [findings, setFindings] = useState<any[]>([]);
  const [findingsLoading, setFindingsLoading] = useState(false);
  const [findingPriorityFilter, setFindingPriorityFilter] = useState<
    number | null
  >(null);
  const [findingsPage, setFindingsPage] = useState(1);
  const FINDINGS_PER_PAGE = 50;

  // ── Security drawer ────────────────────────────────────────────────────────
  const [secDrawerOpen, setSecDrawerOpen] = useState(false);
  const [secDrawerFindings, setSecDrawerFindings] = useState<any[]>([]);
  const [secDrawerTitle, setSecDrawerTitle] = useState("");
  const [secCatDrawerOpen, setSecCatDrawerOpen] = useState(false);
  const [secCatDrawerFindings, setSecCatDrawerFindings] = useState<any[]>([]);
  const [secCatDrawerTitle, setSecCatDrawerTitle] = useState("");
  const [secFindingDrawerOpen, setSecFindingDrawerOpen] = useState(false);
  const [secFindingDrawerData, setSecFindingDrawerData] = useState<any>(null);

  // ── Run comparison ─────────────────────────────────────────────────────────
  const [compareRun, setCompareRun] = useState<Run | null>(null);
  const [compareDrawerOpen, setCompareDrawerOpen] = useState(false);
  const [compareFindings, setCompareFindings] = useState<any[]>([]);
  const [compareFindingsLoading, setCompareFindingsLoading] = useState(false);

  // ── Code Quality sort/filter ───────────────────────────────────────────────
  const [objSortCol, setObjSortCol] = useState<
    "p1" | "p2" | "p3" | "total" | "age"
  >("p1");
  const [objSortDir, setObjSortDir] = useState<"asc" | "desc">("desc");
  const [objFilterPrio, setObjFilterPrio] = useState<number | null>(null);

  // ── Developer Hub ──────────────────────────────────────────────────────────
  const [assignments, setAssignments] = useState<Record<string, string>>({});
  const [patternResult, setPatternResult] = useState<any>(null);
  const [patternLoading, setPatternLoading] = useState(false);
  const [patternError, setPatternError] = useState("");
  const [expandedCheck, setExpandedCheck] = useState<string | null>(null);
  const [devTabSearch, setDevTabSearch] = useState("");
  const [devFindingsDrawerOpen, setDevFindingsDrawerOpen] = useState(false);
  const [devFindingsDrawerTitle, setDevFindingsDrawerTitle] = useState("");
  const [devFindingsDrawerData, setDevFindingsDrawerData] = useState<any[]>([]);

  // ── CVE Intelligence ───────────────────────────────────────────────────────
  const [cveSearchTerm, setCveSearchTerm] = useState("");
  const [cveResults, setCveResults] = useState<any[]>([]);
  const [cveLoading, setCveLoading] = useState(false);
  const [cveError, setCveError] = useState("");
  const [cveTotalResults, setCveTotalResults] = useState(0);
  const [cveActiveQuery, setCveActiveQuery] = useState("");

  // ── Check modules, user, filters ──────────────────────────────────────────
  const [checkModules, setCheckModules] = useState<CheckModule[]>([]);
  const [checkModulesLoading, setCheckModulesLoading] = useState(false);
  const [myUserId, setMyUserId] = useState("");
  const [myUserIdInput, setMyUserIdInput] = useState("");
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

  const [runExportOpen, setRunExportOpen] = useState(false);
  const [assignExportOpen, setAssignExportOpen] = useState(false);
  const [devHubView, setDevHubView] = useState<"check" | "package">("check");
  const [packageAssignments, setPackageAssignments] = useState<
    Record<string, string>
  >({});
  const [pkgFindingsDrawerOpen, setPkgFindingsDrawerOpen] = useState(false);
  const [pkgFindingsDrawerTitle, setPkgFindingsDrawerTitle] = useState("");
  const [pkgFindingsDrawerData, setPkgFindingsDrawerData] = useState<any[]>([]);
  const [fixCache, setFixCache] = useState<Map<string, string>>(new Map());
  const [fixLoadingKey, setFixLoadingKey] = useState("");
  const [checkAssignments, setCheckAssignments] = useState<any[]>([]);
  const [pkgAssignmentsBackend, setPkgAssignmentsBackend] = useState<any[]>([]);
  const [jiraTickets, setJiraTickets] = useState<any[]>([]);
  const [assignmentsSaving, setAssignmentsSaving] = useState(false);
  const [assignmentsSaveError, setAssignmentsSaveError] = useState("");
  const [assignmentsSaveSuccess, setAssignmentsSaveSuccess] = useState("");
  const [pkgSaving, setPkgSaving] = useState(false);
  const [pkgSaveError, setPkgSaveError] = useState("");
  const [pkgSaveSuccess, setPkgSaveSuccess] = useState("");
  const [devProfiles, setDevProfiles] = useState<DevProfile[]>([]);
  const [products, setProducts] = useState<any[]>([]);
  const [productRunSeries, setProductRunSeries] = useState<any[]>([]);
  const [selectedProduct, setSelectedProduct] = useState<any>(null);
  const [certSeriesDrawerOpen, setCertSeriesDrawerOpen] = useState(false);
  const [certSeriesDrawerSeries, setCertSeriesDrawerSeries] =
    useState<string>("");
  const [certSeriesDrawerRun, setCertSeriesDrawerRun] = useState<Run | null>(
    null,
  );
  const [adminSection, setAdminSection] = useState<string>("profiles");
  const [adminLoading, setAdminLoading] = useState(false);
  const [adminError, setAdminError] = useState("");
  const [adminSuccess, setAdminSuccess] = useState("");
  const [teams, setTeams] = useState<any[]>([]);
  const [integrationConfig, setIntegrationConfig] = useState<any[]>([]);
  const [editingRow, setEditingRow] = useState<any>(null);
  const [addingRow, setAddingRow] = useState<any>(null);
  const [currentUser, setCurrentUser] = useState<any>(null);

  // ── AI panel ───────────────────────────────────────────────────────────────
  const [aiOpen, setAiOpen] = useState(false);
  const [aiLoading, setAiLoading] = useState(false);
  const [aiMessages, setAiMessages] = useState<AiMessage[]>([]);
  const [aiInput, setAiInput] = useState("");
  const [aiView, setAiView] = useState<"manager" | "developer">("manager");

  // ── Connection / settings ──────────────────────────────────────────────────
  const [systems, setSystems] = useState<SystemConfig[]>([]);
  const [systemsLoading, setSystemsLoading] = useState(true);
  const [activeSystemId, setActiveSystemId] = useState<string>("");
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [settingsTab, setSettingsTab] = useState<"connections" | "admin">(
    "connections",
  );
  const [sysAddingRow, setSysAddingRow] =
    useState<Partial<SystemConfig> | null>(null);
  const [sysEditingId, setSysEditingId] = useState<string | null>(null);
  const [sysEditingRow, setSysEditingRow] =
    useState<Partial<SystemConfig> | null>(null);
  const [sysLoading, setSysLoading] = useState(false);
  const [sysError, setSysError] = useState("");
  const [sysSuccess, setSysSuccess] = useState("");

  const activeSystem: SystemConfig | null =
    systems.find((s) => s.SystemId === activeSystemId) ||
    systems.find((s) => s.IsActive === "X") ||
    null;
  const connection: "btp" | "netweaver" =
    activeSystem?.SystemType === "BTP" ? "btp" : "netweaver";
  const connections = {
    btp: {
      baseUrl: activeSystem?.BaseUrl || BOOTSTRAP_URL,
      systemId: activeSystem?.SystemIdLabel || "",
      host: activeSystem?.Host || "",
      label: activeSystem?.SystemName || "",
      icon: "☁️",
      description: activeSystem?.Description || "",
    },
    netweaver: {
      baseUrl: activeSystem?.BaseUrl || BOOTSTRAP_URL,
      systemId: activeSystem?.SystemIdLabel || "",
      host: activeSystem?.Host || "",
      label: activeSystem?.SystemName || "",
      icon: "🖥️",
      description: activeSystem?.Description || "",
    },
  };

  // ── AI Security ────────────────────────────────────────────────────────────
  const [aiSecReport, setAiSecReport] = useState("");
  const [aiSecLoading, setAiSecLoading] = useState(false);
  const [aiSecError, setAiSecError] = useState("");
  const [aiSecRunId, setAiSecRunId] = useState("");

  // ── Refs ────────────────────────────────────────────────────────────────────
  const findingsAbortRef = useRef<AbortController | null>(null);
  const compareAbortRef = useRef<AbortController | null>(null);
  const selectedRunRef = useRef<Run | null>(null);
  const findingsRef = useRef<any[]>([]);
  const fetchInProgressRef = useRef(false);
  useEffect(() => {
    selectedRunRef.current = selectedRun;
  }, [selectedRun]);
  useEffect(() => {
    findingsRef.current = findings;
  }, [findings]);

  // ── Theme / resize ──────────────────────────────────────────────────────────
  useEffect(() => {
    const s = localStorage.getItem("theme");
    if (s) setTheme(s);
  }, []);
  useEffect(() => {
    document.documentElement.setAttribute("data-theme", theme);
    localStorage.setItem("theme", theme);
  }, [theme]);
  useEffect(() => {
    const h = () => setIsMobile(window.innerWidth < 768);
    window.addEventListener("resize", h);
    return () => window.removeEventListener("resize", h);
  }, []);

  const saveSettings = () => {
    setSettingsOpen(false);
  };

  // ── Security CI classification patterns ───────────────────────────────────
  const SECURITY_CI_CLASS_PATTERNS = [
    "_CVA_",
    "_CVA_BSP",
    "_AUTH_",
    "_AUTH_CHECK",
    "_SVIM_",
    "_TAW_SEC",
    "_CHECK_SEC",
    "_EXTENDED_CHECK_SEC",
    "_IMUD_TAW_SEC",
    "_SELECT_TAW",
    "_DYN_SQL",
    "_DYN_SEL",
    "_INJECT",
    "_XSS_",
    "_SU22_",
    "_SU24_",
    "_SVIM_AUTH",
    "_HARDCOD",
    "_RFC_SEC",
    "_CROSS_CLIENT",
  ];
  const isSecurityCiId = useCallback(
    (ciId: string | null | undefined): boolean => {
      if (!ciId || ciId === "*INVALID*" || ciId === "") return false;
      const u = ciId.toUpperCase();
      if (SECURITY_CI_CLASS_PATTERNS.some((p) => u.includes(p.toUpperCase())))
        return true;
      return SECURITY_CI_PATTERNS.some((p) => u.includes(p.toUpperCase()));
    },
    [],
  );

  const resolveCiId = useCallback((f: any): string => {
    const c = f.CheckCiId ?? "";
    if (c && c !== "*INVALID*") return c;
    return f.RstismCiId ?? "";
  }, []);

  const securityModuleIds = useMemo((): Set<string> => {
    const s = new Set<string>();
    checkModules.forEach((m) => {
      if (
        isSecurityCiId(m.CiId) ||
        (m.ModuleTitle &&
          SECURITY_TITLE_PATTERNS.some((p) =>
            m.ModuleTitle.toUpperCase().includes(p.toUpperCase()),
          ))
      )
        s.add(m.ModuleId.toLowerCase());
    });
    return s;
  }, [checkModules, isSecurityCiId]);

  const getSecurityKnowledge = useCallback((ciId: string) => {
    if (!ciId || ciId === "*INVALID*") return null;
    const u = ciId.toUpperCase();
    for (const p of SECURITY_CI_PATTERNS) {
      if (u.includes(p.toUpperCase()) && SECURITY_KNOWLEDGE[p])
        return SECURITY_KNOWLEDGE[p];
    }
    return null;
  }, []);

  const getSecurityKnowledgeByModuleId = useCallback(
    (moduleId: string) => {
      if (!moduleId) return null;
      const m = checkModules.find(
        (m) => m.ModuleId.toLowerCase() === moduleId.toLowerCase(),
      );
      return m ? getSecurityKnowledge(m.CiId) : null;
    },
    [checkModules, getSecurityKnowledge],
  );

  // Dynamic check category name resolution — 5-step priority chain, never shows raw UUIDs
  const resolveCheckCategory = useCallback(
    (f: any): string => {
      // 1. msg_title from RSTISM view (language-aware, best for Code Inspector runs)
      if (f.RstismTitle?.trim()) return f.RstismTitle.trim();
      // 2. ModuleTitle from ZI_ATC_CHECK_MODULES entity
      const mod = checkModules.find(
        (m) =>
          m.ModuleId.toLowerCase() === (f.CheckCategory || "").toLowerCase(),
      );
      if (mod?.ModuleTitle?.trim()) return mod.ModuleTitle.trim();
      // 3. Format CI class name (strips CL_CI_TEST_ prefix, converts underscores)
      const ciId = resolveCiId(f);
      const fmtCi = formatCiClassName(ciId);
      if (fmtCi) return fmtCi;
      // 4. Format class name from CheckModules record
      if (mod?.CiId) {
        const fmtMod = formatCiClassName(mod.CiId);
        if (fmtMod) return fmtMod;
      }
      // 5. MessageKey prefix
      const msgKey = f.MessageKey?.split("/")?.[0]?.trim();
      if (msgKey) return msgKey;
      return f.CheckCategory || "Unknown";
    },
    [checkModules, resolveCiId],
  );

  // Dynamic security classification — uses QualityStandard from backend first (satc_ac_cmm.quality_standard),
  // falls back to CI pattern matching. No hardcoded list once backend exposes quality_standard.
  const isSecurityFinding = useCallback(
    (f: any): boolean => {
      if (f.QualityStandard?.trim()) {
        const qs = f.QualityStandard.trim().toUpperCase();
        if (qs === "S" || qs === "SEC" || qs.includes("SEC")) return true;
      }
      return (
        isSecurityCiId(resolveCiId(f)) ||
        (securityModuleIds.size > 0 &&
          !!(
            f.CheckCategory &&
            securityModuleIds.has((f.CheckCategory || "").toLowerCase())
          )) ||
        isTitleSecurityCheck(f.RstismTitle || "") ||
        isTitleSecurityCheck(f.CheckTitle || "") ||
        isTitleSecurityCheck(f.CheckMessage || "") ||
        isTitleSecurityCheck(f.MessageKey || "")
      );
    },
    [isSecurityCiId, resolveCiId, securityModuleIds],
  );

  // ── Data fetching ──────────────────────────────────────────────────────────
  const fetchData = async (path: string): Promise<any[]> => {
    if (!activeSystem) return [];
    const url = `${activeSystem.BaseUrl}${path}`;
    try {
      const r = await fetch(url);
      if (!r.ok) return [];
      const j = await r.json();
      const res = j.value ?? j;
      return Array.isArray(res) ? res : [];
    } catch (e) {
      console.error("Fetch failed:", url, e);
      return [];
    }
  };

  // Fetches from ZI_ATC_CHECK_MODULES — exposes ModuleId, CiId, ModuleTitle dynamically.
  // No BTP guard — entity should be exposed in both NetWeaver and CAP services.
  // Filters *INVALID* (deleted/inactive modules that never appear in active ATC results).
  const fetchCheckModules = useCallback(async () => {
    if (!activeSystem) return;
    setCheckModulesLoading(true);
    const base = activeSystem.BaseUrl;
    let url = `${base}/CheckModules`;
    const all: CheckModule[] = [];
    try {
      while (url) {
        const r = await fetch(url);
        if (!r.ok) break;
        const j = await r.json();
        all.push(...(Array.isArray(j.value) ? j.value : []));
        url = j["@odata.nextLink"] || "";
      }
    } catch (e) {
      console.error("CheckModules fetch failed:", e);
    }
    setCheckModules(all.filter((m) => m.CiId && m.CiId !== "*INVALID*"));
    setCheckModulesLoading(false);
  }, [activeSystem]);

  useEffect(() => {
    fetchCheckModules();
  }, [fetchCheckModules]);

  useEffect(() => {
    const fetchSystems = async () => {
      setSystemsLoading(true);
      try {
        const r = await fetch(`${BOOTSTRAP_URL}/Systems`);
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        const j = await r.json();
        const allSystems: SystemConfig[] = j.value || [];
        setSystems(allSystems);
        const firstActive = allSystems.find((s) => s.IsActive === "X");
        if (firstActive) setActiveSystemId(firstActive.SystemId);
      } catch (e) {
        console.error("Failed to fetch systems:", e);
      } finally {
        setSystemsLoading(false);
      }
    };
    fetchSystems();
  }, []);

  // Reload everything whenever the active system changes
  useEffect(() => {
    if (!activeSystemId || systemsLoading) return;
    // Reset all state
    setRuns([]);
    setKpi({});
    setFindings([]);
    setSelectedRun(null);
    setDrawerOpen(false);
    setCompareRun(null);
    setCompareDrawerOpen(false);
    setCompareFindings([]);
    setAssignments({});
    setPackageAssignments({});
    setCheckAssignments([]);
    setPkgAssignmentsBackend([]);
    setJiraTickets([]);
    setAssignmentsSaveError("");
    setAssignmentsSaveSuccess("");
    setPkgSaveError("");
    setPkgSaveSuccess("");
    setAiSecReport("");
    setAiSecError("");
    setPatternResult(null);
    setProducts([]);
    setProductRunSeries([]);
    setDevProfiles([]);
    setTeams([]);
    setIntegrationConfig([]);
    setCurrentUser(null);
    // Load runs for new system
    load();
    // Load admin data if NetWeaver
    if (activeSystem?.SystemType === "NETWEAVER") {
      fetchData("/DeveloperProfiles")
        .then((profiles) => {
          const active = profiles
            .filter((p: any) => p.IsActive)
            .sort((a: any, b: any) =>
              a.DisplayName.localeCompare(b.DisplayName),
            );
          setDevProfiles(active);
          const userId = "F0002688";
          if (userId)
            setCurrentUser(
              active.find(
                (p: any) => p.UserId.toUpperCase() === userId.toUpperCase(),
              ) || null,
            );
        })
        .catch(() => {});
      fetchData("/Products")
        .then((p) => setProducts(p))
        .catch(() => {});
      fetchData("/ProductRunSeries")
        .then((s) => setProductRunSeries(s))
        .catch(() => {});
      fetchData("/Teams")
        .then((t) => setTeams(t))
        .catch(() => {});
      fetchData("/IntegrationConfig")
        .then((c) => setIntegrationConfig(c))
        .catch(() => {});
    }
  }, [activeSystemId, systemsLoading]); // eslint-disable-line

  // Removed — activeSystemId useEffect handles admin data fetch now

  const buildFilterQuery = (f: typeof filters): string => {
    const c: string[] = [];
    const nw = connection === "netweaver";
    if (f.system)
      c.push(`contains(${nw ? "scheduledSys" : "system"},'${f.system}')`);
    if (f.series) c.push(`contains(series,'${f.series}')`);
    if (f.title) c.push(`contains(title,'${f.title}')`);
    if (f.user) c.push(`contains(${nw ? "scheduledBy" : "user"},'${f.user}')`);
    if (f.scheduleMode === "date") {
      const df = nw ? "runDate" : "date";
      const q = nw ? "" : "'";
      if (f.dateFrom) c.push(`${df} ge ${q}${f.dateFrom}${q}`);
      if (f.dateTo) c.push(`${df} le ${q}${f.dateTo}${q}`);
    }
    return c.length ? `?$filter=${c.join(" and ")}` : "";
  };

  const load = async (overrideFilters?: typeof filters) => {
    setLoading(true);
    const f = overrideFilters ?? filters;
    const q = buildFilterQuery(f);
    const [r, k] = await Promise.all([
      fetchData(`/Runs${q}`),
      fetchData(`/OverviewKPI`),
    ]);
    const norm = r.map(
      (run: any): Run => ({
        ...run,
        user: run.scheduledBy ?? run.user ?? "",
        system: run.scheduledSys ?? run.system ?? "",
        date: run.runDate ?? run.date ?? "",
        central: run.central === true || run.central === "X",
        p4: Number(run.p4 ?? 0),
        RunKind: run.RunKind ?? run.kind ?? "",
      }),
    );
    setRuns(norm);
    setKpi(Array.isArray(k) && k.length > 0 ? k[0] : {});
    setLoading(false);
  };

  const fetchFindings = useCallback(
    async (runId: string) => {
      if (findingsAbortRef.current) findingsAbortRef.current.abort();
      const ctrl = new AbortController();
      findingsAbortRef.current = ctrl;
      const sig = ctrl.signal;
      fetchInProgressRef.current = true;
      setFindingsLoading(true);
      setFindings([]);
      setFindingsPage(1);
      setFindingPriorityFilter(null);
      const base = connections[connection].baseUrl;
      let url = `${base}/Findings?$filter=RunId eq ${runId}&$orderby=Priority asc`;
      const all: any[] = [];
      try {
        while (url) {
          if (sig.aborted) break;
          const r = await fetch(url, { signal: sig });
          if (!r.ok) break;
          const j = await r.json();
          all.push(...(Array.isArray(j.value) ? j.value : []));
          if (!sig.aborted) {
            setFindings([...all]);
            await new Promise((r) => setTimeout(r, 0));
          }
          url = sig.aborted ? "" : j["@odata.nextLink"] || "";
        }
      } catch (e: any) {
        if (e?.name !== "AbortError")
          console.error("Findings fetch failed:", e);
      }
      if (!sig.aborted) setFindingsLoading(false);
      fetchInProgressRef.current = false;
    },
    [connection, connections],
  );

  const fetchCompareFindings = useCallback(
    async (runId: string) => {
      if (compareAbortRef.current) compareAbortRef.current.abort();
      const ctrl = new AbortController();
      compareAbortRef.current = ctrl;
      const sig = ctrl.signal;
      setCompareFindingsLoading(true);
      setCompareFindings([]);
      const base = connections[connection].baseUrl;
      let url = `${base}/Findings?$filter=RunId eq ${runId}&$orderby=Priority asc`;
      const all: any[] = [];
      try {
        while (url) {
          if (sig.aborted) break;
          const r = await fetch(url, { signal: sig });
          if (!r.ok) break;
          const j = await r.json();
          all.push(...(Array.isArray(j.value) ? j.value : []));
          if (!sig.aborted) {
            setCompareFindings([...all]);
            await new Promise((r) => setTimeout(r, 0));
          }
          url = sig.aborted ? "" : j["@odata.nextLink"] || "";
        }
      } catch (e: any) {
        if (e?.name !== "AbortError") console.error("Compare fetch failed:", e);
      }
      if (!sig.aborted) setCompareFindingsLoading(false);
    },
    [connection, connections],
  );

  // NVD CVE fetch — NIST National Vulnerability Database public API, no auth required
  const fetchCveData = useCallback(async (query: string) => {
    if (!query.trim()) return;
    setCveLoading(true);
    setCveError("");
    setCveResults([]);
    setCveTotalResults(0);
    setCveActiveQuery(query);
    try {
      const enc = encodeURIComponent(`SAP ABAP ${query}`);
      const res = await fetch(
        `https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${enc}&resultsPerPage=8`,
        { headers: { Accept: "application/json" } },
      );
      if (!res.ok) throw new Error(`NVD API returned HTTP ${res.status}`);
      const data = await res.json();
      setCveResults(data.vulnerabilities || []);
      setCveTotalResults(data.totalResults || 0);
    } catch (e: any) {
      const msg = e?.message || "";
      setCveError(
        msg.includes("Failed to fetch") || msg.includes("NetworkError")
          ? "Browser blocked the NVD request (CORS/network). Use the 'Open NVD Search →' link to search directly."
          : msg || "CVE lookup failed.",
      );
    } finally {
      setCveLoading(false);
    }
  }, []);

  // Removed — activeSystemId useEffect handles this now
  useEffect(() => {
    if (
      (tab === "quality" || tab === "security" || tab === "developer") &&
      selectedRunRef.current &&
      !fetchInProgressRef.current &&
      connection !== "btp"
    ) {
      const run = selectedRunRef.current;
      const cur = findingsRef.current;
      const exp = (run.p1 ?? 0) + (run.p2 ?? 0) + (run.p3 ?? 0) + (run.p4 ?? 0);
      if (cur.length === 0 || cur.length < exp) fetchFindings(run.ID);
    }
  }, [tab, fetchFindings, findingsLoading, connection]); // eslint-disable-line

  // ── Filtered runs ───────────────────────────────────────────────────────────
  const filteredRuns = useMemo(() => {
    let d = [...runs];
    if (filters.system.trim())
      d = d.filter((r) =>
        (r.system || "").toLowerCase().includes(filters.system.toLowerCase()),
      );
    if (filters.series.trim())
      d = d.filter((r) =>
        (r.series || "").toLowerCase().includes(filters.series.toLowerCase()),
      );
    if (filters.title.trim())
      d = d.filter((r) =>
        (r.title || "").toLowerCase().includes(filters.title.toLowerCase()),
      );
    if (filters.user.trim())
      d = d.filter((r) =>
        (r.user || "").toLowerCase().includes(filters.user.toLowerCase()),
      );
    if (filters.scheduleMode === "date") {
      if (filters.dateFrom)
        d = d.filter((r) => (r.date || "") >= filters.dateFrom);
      if (filters.dateTo) d = d.filter((r) => (r.date || "") <= filters.dateTo);
    }
    if (filters.scheduleMode === "period" && filters.period > 0) {
      const cut = Date.now() - filters.period * 86_400_000;
      d = d.filter((r) => new Date(r.date || 0).getTime() >= cut);
    }
    if (filters.visibility === "central")
      d = d.filter((r) => r.central === true);
    if (filters.visibility === "noncentral")
      d = d.filter((r) => r.central !== true);
    if (filters.baselineOnly) {
      const baselineSeries = new Set(
        productRunSeries
          .filter((s: any) => s.IsBaseline === "X")
          .map((s: any) => s.RunSeries.toUpperCase()),
      );
      d = d.filter((r) => baselineSeries.has((r.series || "").toUpperCase()));
    }
    return d;
  }, [runs, filters]);

  const filteredFindings = useMemo(
    () =>
      findings.filter(
        (f) =>
          findingPriorityFilter === null ||
          f.Priority === findingPriorityFilter,
      ),
    [findings, findingPriorityFilter],
  );
  const currentPageData = useMemo(() => {
    const s = (findingsPage - 1) * FINDINGS_PER_PAGE;
    return filteredFindings.slice(s, s + FINDINGS_PER_PAGE);
  }, [filteredFindings, findingsPage]);
  const totalPages = Math.ceil(filteredFindings.length / FINDINGS_PER_PAGE);
  const handlePriorityFilter = useCallback((p: number | null) => {
    setFindingPriorityFilter((prev) => (prev === p ? null : p));
    setFindingsPage(1);
  }, []);

  const totalRuns = filteredRuns.length;
  const totalP1 = useMemo(
    () => filteredRuns.reduce((a, r) => a + (r.p1 || 0), 0),
    [filteredRuns],
  );
  const totalP2 = useMemo(
    () => filteredRuns.reduce((a, r) => a + (r.p2 || 0), 0),
    [filteredRuns],
  );
  const totalP3 = useMemo(
    () => filteredRuns.reduce((a, r) => a + (r.p3 || 0), 0),
    [filteredRuns],
  );
  const totalP4 = useMemo(
    () => filteredRuns.reduce((a, r) => a + (r.p4 || 0), 0),
    [filteredRuns],
  );
  const healthScore = useMemo(() => {
    const w = totalP1 * 4 + totalP2 * 2 + totalP3 + totalP4 * 0.5;
    if (w === 0) return 100;
    return Math.max(0, Math.round(100 - Math.log10(w + 1) * 20));
  }, [totalP1, totalP2, totalP3, totalP4]);

  // ── Overview computed ───────────────────────────────────────────────────────
  const systemHealthSnapshot = useMemo(() => {
    const map: Record<string, Run[]> = {};
    filteredRuns.forEach((r) => {
      const k = r.series || r.title || r.ID;
      if (!map[k]) map[k] = [];
      map[k].push(r);
    });
    return Object.entries(map)
      .map(([series, runs]) => {
        const sorted = [...runs].sort((a, b) =>
          (b.date || "").localeCompare(a.date || ""),
        );
        const lat = sorted[0],
          prev = sorted[1] || null;
        const daysSince = lat.date
          ? Math.floor((Date.now() - new Date(lat.date).getTime()) / 86_400_000)
          : null;
        const p1Delta = prev !== null ? lat.p1 - prev.p1 : null;
        let trajectory = "Single Run";
        if (sorted.length >= 3) {
          if (sorted[0].p1 > sorted[1].p1 && sorted[1].p1 > sorted[2].p1)
            trajectory = "Deteriorating";
          else if (sorted[0].p1 < sorted[1].p1 && sorted[1].p1 < sorted[2].p1)
            trajectory = "Improving";
          else if (sorted[0].p1 > sorted[1].p1) trajectory = "Worsening";
          else if (sorted[0].p1 < sorted[1].p1) trajectory = "Recovering";
          else trajectory = "Stable";
        } else if (sorted.length === 2) {
          trajectory =
            sorted[0].p1 > sorted[1].p1
              ? "Worsening"
              : sorted[0].p1 < sorted[1].p1
                ? "Recovering"
                : "Stable";
        }
        return {
          series,
          latest: lat,
          daysSince,
          p1Delta,
          trajectory,
          light: lat.p1 > 0 ? "#ef4444" : lat.p2 > 0 ? "#f59e0b" : "#22c55e",
          runCount: runs.length,
        };
      })
      .sort((a, b) => b.latest.p1 - a.latest.p1);
  }, [filteredRuns]);

  const attentionAlerts = useMemo(() => {
    const map: Record<string, Run[]> = {};
    filteredRuns.forEach((r) => {
      const k = r.series || r.title || r.ID;
      if (!map[k]) map[k] = [];
      map[k].push(r);
    });
    const alerts: {
      text: string;
      severity: "red" | "amber" | "blue";
      detail: string;
    }[] = [];
    Object.entries(map).forEach(([series, runs]) => {
      if (runs.length < 2) return;
      const s = [...runs].sort((a, b) =>
        (b.date || "").localeCompare(a.date || ""),
      );
      const diff = s[0].p1 - s[1].p1;
      if (diff > 5)
        alerts.push({
          text: `P1 spike in "${series}"`,
          severity: diff > 50 ? "red" : "amber",
          detail: `+${diff} P1 vs previous run (${s[0].date})`,
        });
      const ds = s[0].date
        ? Math.floor((Date.now() - new Date(s[0].date).getTime()) / 86_400_000)
        : null;
      if (ds !== null && ds > 14)
        alerts.push({
          text: `No run in "${series}" for ${ds} days`,
          severity: "amber",
          detail: `Last run: ${s[0].date}. Consider scheduling a fresh ATC run.`,
        });
      if (runs.length >= 3 && s[0].p1 > s[1].p1 && s[1].p1 > s[2].p1)
        alerts.push({
          text: `3 consecutive P1 increases in "${series}"`,
          severity: "red",
          detail: `${s[2].p1} → ${s[1].p1} → ${s[0].p1}. Trend is deteriorating.`,
        });
    });
    return alerts.slice(0, 6);
  }, [filteredRuns]);

  const weekComparison = useMemo(() => {
    const now = Date.now();
    const tw = filteredRuns.filter(
      (r) => now - new Date(r.date || 0).getTime() <= 7 * 86_400_000,
    );
    const lw = filteredRuns.filter((r) => {
      const a = now - new Date(r.date || 0).getTime();
      return a > 7 * 86_400_000 && a <= 14 * 86_400_000;
    });
    return {
      thisP1: tw.reduce((a, r) => a + r.p1, 0),
      lastP1: lw.reduce((a, r) => a + r.p1, 0),
      thisP2: tw.reduce((a, r) => a + r.p2, 0),
      lastP2: lw.reduce((a, r) => a + r.p2, 0),
      thisRuns: tw.length,
      lastRuns: lw.length,
      hasLast: lw.length > 0,
    };
  }, [filteredRuns]);

  // Run Quality Leaderboard — built from ALL filteredRuns, no findings dependency
  const topRiskRunsSummary = useMemo(
    () =>
      [...filteredRuns]
        .sort((a, b) => b.p1 - a.p1 || b.p2 - a.p2 || b.p3 - a.p3)
        .slice(0, 10)
        .map((r) => ({
          ...r,
          total: r.p1 + r.p2 + r.p3 + (r.p4 ?? 0),
          score: computeScore(r.p1, r.p2, r.p3, r.p4 ?? 0),
        })),
    [filteredRuns],
  );

  // ── Code Quality computed ───────────────────────────────────────────────────
  const prevRunInSeries = useMemo(() => {
    if (!selectedRun) return null;
    return (
      filteredRuns
        .filter(
          (r) =>
            r.ID !== selectedRun.ID &&
            (r.series || r.title) === (selectedRun.series || selectedRun.title),
        )
        .sort((a, b) => (b.date || "").localeCompare(a.date || ""))[0] || null
    );
  }, [selectedRun, filteredRuns]);
  const qualityScore = useMemo(
    () =>
      selectedRun
        ? computeScore(
            selectedRun.p1,
            selectedRun.p2,
            selectedRun.p3,
            selectedRun.p4 ?? 0,
          )
        : null,
    [selectedRun],
  );
  const qualityDelta = useMemo(() => {
    if (!selectedRun || !prevRunInSeries) return null;
    return (
      computeScore(
        selectedRun.p1,
        selectedRun.p2,
        selectedRun.p3,
        selectedRun.p4 ?? 0,
      ) -
      computeScore(
        prevRunInSeries.p1,
        prevRunInSeries.p2,
        prevRunInSeries.p3,
        prevRunInSeries.p4 ?? 0,
      )
    );
  }, [selectedRun, prevRunInSeries]);

  const findingsByCategory = useMemo(() => {
    const map: Record<
      string,
      { p1: number; p2: number; p3: number; p4: number; total: number }
    > = {};
    findings.forEach((f) => {
      const key = resolveCheckCategory(f); // dynamic — never shows raw UUID
      if (!map[key]) map[key] = { p1: 0, p2: 0, p3: 0, p4: 0, total: 0 };
      map[key as string].total++;
      if (f.Priority === 1) map[key].p1++;
      else if (f.Priority === 2) map[key].p2++;
      else if (f.Priority === 3) map[key].p3++;
      else if (f.Priority === 4) map[key].p4++;
    });
    return Object.entries(map)
      .map(([cat, v]) => ({ cat, ...v }))
      .sort((a, b) => b.p1 - a.p1 || b.p2 - a.p2 || b.total - a.total);
  }, [findings, resolveCheckCategory]);

  const objectRiskTable = useMemo(() => {
    const map: Record<
      string,
      {
        p1: number;
        p2: number;
        p3: number;
        p4: number;
        total: number;
        objType: string;
        pkg: string;
        dev: string;
        oldestAge: number;
      }
    > = {};
    findings.forEach((f) => {
      const k = f.ObjectName || "Unknown";
      if (!map[k])
        map[k] = {
          p1: 0,
          p2: 0,
          p3: 0,
          p4: 0,
          total: 0,
          objType: f.ObjectType || "",
          pkg: f.PackageName || "—",
          dev: f.ContactPerson || f.Processor || "—",
          oldestAge: 0,
        };
      map[k].total++;
      if (f.Priority === 1) map[k].p1++;
      else if (f.Priority === 2) map[k].p2++;
      else if (f.Priority === 3) map[k].p3++;
      else if (f.Priority === 4) map[k].p4++;
      const d = parseSince(f.Since);
      if (d) {
        const a = ageDays(d);
        if (a > map[k].oldestAge) map[k].oldestAge = a;
      }
      if (f.ObjectType) map[k].objType = f.ObjectType;
    });
    let rows = Object.entries(map).map(([name, v]) => ({ name, ...v }));
    if (objFilterPrio !== null)
      rows = rows.filter(
        (r) =>
          (objFilterPrio === 1
            ? r.p1
            : objFilterPrio === 2
              ? r.p2
              : objFilterPrio === 3
                ? r.p3
                : r.p4) > 0,
      );
    rows.sort((a, b) => {
      const va =
        objSortCol === "p1"
          ? a.p1
          : objSortCol === "p2"
            ? a.p2
            : objSortCol === "p3"
              ? a.p3
              : objSortCol === "total"
                ? a.total
                : a.oldestAge;
      const vb =
        objSortCol === "p1"
          ? b.p1
          : objSortCol === "p2"
            ? b.p2
            : objSortCol === "p3"
              ? b.p3
              : objSortCol === "total"
                ? b.total
                : b.oldestAge;
      return objSortDir === "desc" ? vb - va : va - vb;
    });
    return rows;
  }, [findings, objSortCol, objSortDir, objFilterPrio]);

  const devAccountability = useMemo(() => {
    const map: Record<
      string,
      {
        p1: number;
        p2: number;
        p3: number;
        p4: number;
        total: number;
        pkgs: Set<string>;
        oldestAge: number;
      }
    > = {};
    findings.forEach((f) => {
      const d = f.ContactPerson || f.Processor || "Unknown";
      if (!map[d])
        map[d] = {
          p1: 0,
          p2: 0,
          p3: 0,
          p4: 0,
          total: 0,
          pkgs: new Set(),
          oldestAge: 0,
        };
      map[d].total++;
      if (f.Priority === 1) map[d].p1++;
      else if (f.Priority === 2) map[d].p2++;
      else if (f.Priority === 3) map[d].p3++;
      else if (f.Priority === 4) map[d].p4++;
      if (f.PackageName) map[d].pkgs.add(f.PackageName);
      const dt = parseSince(f.Since);
      if (dt) {
        const a = ageDays(dt);
        if (a > map[d].oldestAge) map[d].oldestAge = a;
      }
    });
    return Object.entries(map)
      .map(([dev, v]) => ({ dev, ...v, pkgCount: v.pkgs.size }))
      .sort((a, b) => b.p1 - a.p1 || b.p2 - a.p2 || b.total - a.total);
  }, [findings]);

  const slaIntelligence = useMemo(() => {
    const tgt: Record<number, number> = { 1: 1, 2: 3, 3: 14, 4: 30 };
    const b: Record<
      number,
      { overdue: number; total: number; maxAge: number }
    > = {
      1: { overdue: 0, total: 0, maxAge: 0 },
      2: { overdue: 0, total: 0, maxAge: 0 },
      3: { overdue: 0, total: 0, maxAge: 0 },
      4: { overdue: 0, total: 0, maxAge: 0 },
    };
    findings.forEach((f) => {
      const p = f.Priority as number;
      if (!b[p]) return;
      b[p].total++;
      const d = parseSince(f.Since);
      if (d) {
        const a = ageDays(d);
        if (a > (tgt[p] || 30)) b[p].overdue++;
        if (a > b[p].maxAge) b[p].maxAge = a;
      }
    });
    const over30 = findings.filter((f) => {
      const d = parseSince(f.Since);
      return d && ageDays(d) > 30;
    }).length;
    const over90 = findings.filter((f) => {
      const d = parseSince(f.Since);
      return d && ageDays(d) > 90;
    }).length;
    return { buckets: b, over30, over90, totalFindings: findings.length };
  }, [findings]);

  // ── Package registry (REQ 1) ────────────────────────────────────────────────
  const packageRegistry = useMemo(() => {
    const map: Record<
      string,
      {
        p1: number;
        p2: number;
        p3: number;
        p4: number;
        total: number;
        checkTypes: Set<string>;
        objects: Set<string>;
        developers: Set<string>;
      }
    > = {};
    findings.forEach((f) => {
      const key: string = String(f.PackageName || "—");
      if (!map[key])
        map[key] = {
          p1: 0,
          p2: 0,
          p3: 0,
          p4: 0,
          total: 0,
          checkTypes: new Set(),
          objects: new Set(),
          developers: new Set(),
        };
      map[key].total++;
      if (f.Priority === 1) map[key].p1++;
      else if (f.Priority === 2) map[key].p2++;
      else if (f.Priority === 3) map[key].p3++;
      else if (f.Priority === 4) map[key].p4++;
      map[key].checkTypes.add(resolveCheckCategory(f) as string);
      if (f.ObjectName) map[key].objects.add(f.ObjectName);
      const d = f.ContactPerson || f.Processor;
      if (d) map[key].developers.add(d.trim());
    });
    return Object.entries(map)
      .map(([key, v]) => ({
        key,
        ...v,
        checkTypeCount: v.checkTypes.size,
        objectCount: v.objects.size,
        devList: [...v.developers],
      }))
      .sort((a, b) => b.p1 - a.p1 || b.p2 - a.p2 || b.total - a.total);
  }, [findings, resolveCheckCategory]);

  const packageWorkload = useMemo(() => {
    const map: Record<
      string,
      {
        assignedPkgs: string[];
        totalFindings: number;
        p1: number;
        p2: number;
        objects: Set<string>;
        oldestAge: number;
      }
    > = {};
    (Object.entries(packageAssignments) as [string, string][]).forEach(
      ([pkg, dev]) => {
        if (!dev) return;
        if (!map[dev])
          map[dev] = {
            assignedPkgs: [],
            totalFindings: 0,
            p1: 0,
            p2: 0,
            objects: new Set(),
            oldestAge: 0,
          };
        if (!map[dev].assignedPkgs.includes(pkg))
          map[dev].assignedPkgs.push(pkg);
      },
    );
    findings.forEach((f) => {
      const pkg: string = String(f.PackageName || "—");
      const dev = packageAssignments[pkg];
      if (!dev) return;
      if (!map[dev])
        map[dev] = {
          assignedPkgs: [],
          totalFindings: 0,
          p1: 0,
          p2: 0,
          objects: new Set(),
          oldestAge: 0,
        };
      map[dev].totalFindings++;
      if (f.Priority === 1) map[dev].p1++;
      else if (f.Priority === 2) map[dev].p2++;
      if (f.ObjectName) map[dev].objects.add(f.ObjectName);
      const d = parseSince(f.Since);
      if (d) {
        const a = ageDays(d);
        if (a > map[dev].oldestAge) map[dev].oldestAge = a;
      }
    });
    return Object.entries(map)
      .map(([dev, v]) => ({
        dev,
        ...v,
        objectCount: v.objects.size,
        priorityScore: v.p1 * 10 + v.p2 * 3 + Math.min(v.oldestAge / 10, 10),
      }))
      .sort((a, b) => b.priorityScore - a.priorityScore);
  }, [findings, packageAssignments]);

  // ── Developer Hub computed ──────────────────────────────────────────────────
  const allKnownDevelopers = useMemo(() => {
    const s = new Set<string>();
    findings.forEach((f) => {
      const d = f.ContactPerson || f.Processor;
      if (d && d.trim() && d !== "Unknown") s.add(d.trim());
    });
    return [...s].sort();
  }, [findings]);

  const checkRegistry = useMemo(() => {
    const map: Record<
      string,
      {
        p1: number;
        p2: number;
        p3: number;
        p4: number;
        total: number;
        objects: Set<string>;
        developers: Set<string>;
      }
    > = {};
    findings.forEach((f) => {
      const key = (f.CheckCategory || resolveCheckCategory(f)) as string;
      if (!map[key])
        map[key] = {
          p1: 0,
          p2: 0,
          p3: 0,
          p4: 0,
          total: 0,
          objects: new Set(),
          developers: new Set(),
        };
      map[key].total++;
      if (f.Priority === 1) map[key].p1++;
      else if (f.Priority === 2) map[key].p2++;
      else if (f.Priority === 3) map[key].p3++;
      else if (f.Priority === 4) map[key].p4++;
      if (f.ObjectName) map[key].objects.add(f.ObjectName);
      const d = f.ContactPerson || f.Processor;
      if (d && d.trim()) map[key].developers.add(d.trim());
    });
    return Object.entries(map)
      .map(([key, v]) => ({
        key,
        ...v,
        objectCount: v.objects.size,
        objectList: [...v.objects].sort(),
        devList: [...v.developers],
      }))
      .sort((a, b) => b.p1 - a.p1 || b.p2 - a.p2 || b.total - a.total);
  }, [findings, resolveCheckCategory]);

  const developerWorkload = useMemo(() => {
    const map: Record<
      string,
      {
        assignedChecks: string[];
        totalFindings: number;
        p1: number;
        p2: number;
        objects: Set<string>;
        oldestAge: number;
      }
    > = {};
    Object.entries(assignments).forEach(([ck, dev]: [string, string]) => {
      if (!dev) return;
      if (!map[dev])
        map[dev] = {
          assignedChecks: [],
          totalFindings: 0,
          p1: 0,
          p2: 0,
          objects: new Set(),
          oldestAge: 0,
        };
      if (!map[dev].assignedChecks.includes(ck))
        map[dev].assignedChecks.push(ck);
    });
    findings.forEach((f) => {
      const key = (f.CheckCategory || resolveCheckCategory(f)) as string;
      const dev = assignments[key];
      if (!dev) return;
      if (!map[dev])
        map[dev] = {
          assignedChecks: [],
          totalFindings: 0,
          p1: 0,
          p2: 0,
          objects: new Set(),
          oldestAge: 0,
        };
      map[dev].totalFindings++;
      if (f.Priority === 1) map[dev].p1++;
      else if (f.Priority === 2) map[dev].p2++;
      if (f.ObjectName) map[dev].objects.add(f.ObjectName);
      const d = parseSince(f.Since);
      if (d) {
        const a = ageDays(d);
        if (a > map[dev].oldestAge) map[dev].oldestAge = a;
      }
    });
    return Object.entries(map)
      .map(([dev, v]) => ({
        dev,
        ...v,
        objectCount: v.objects.size,
        priorityScore: v.p1 * 10 + v.p2 * 3 + Math.min(v.oldestAge / 10, 10),
      }))
      .sort((a, b) => b.priorityScore - a.priorityScore);
  }, [findings, assignments, resolveCheckCategory]);

  const assignmentCoverage = useMemo(() => {
    if (checkRegistry.length === 0) return 0;
    return Math.round(
      (checkRegistry.filter((c) => assignments[c.key]).length /
        checkRegistry.length) *
        100,
    );
  }, [checkRegistry, assignments]);
  const unassignedP1Count = useMemo(
    () =>
      checkRegistry
        .filter((c) => !assignments[c.key] && c.p1 > 0)
        .reduce((a, c) => a + c.p1, 0),
    [checkRegistry, assignments],
  );

  const currentProductContext = useMemo(() => {
    if (!selectedRun?.series) return null;
    const seriesEntry = productRunSeries.find(
      (s: any) =>
        (s.RunSeries || "").toUpperCase() ===
        (selectedRun.series || "").toUpperCase(),
    );
    if (!seriesEntry?.ProductId) return null;
    const product = products.find(
      (p: any) =>
        (p.ProductId || "").toUpperCase() ===
        (seriesEntry.ProductId || "").toUpperCase(),
    );
    return {
      productId: seriesEntry.ProductId,
      seriesEntry,
      product,
      jiraProjectKey: (product?.JiraProjectKey || "").trim(),
    };
  }, [selectedRun?.series, productRunSeries, products]);

  const getConfigValue = useCallback(
    (productId: string, key: string, fallback = ""): string => {
      const normKey = key.toUpperCase();
      const normProduct = (productId || "").toUpperCase();
      const productValue = integrationConfig.find(
        (c: any) =>
          (c.ProductId || "").toUpperCase() === normProduct &&
          (c.ConfigKey || "").toUpperCase() === normKey,
      );
      const globalValue = integrationConfig.find(
        (c: any) =>
          (c.ProductId || "").toUpperCase() === "GLOBAL" &&
          (c.ConfigKey || "").toUpperCase() === normKey,
      );
      return String(productValue?.ConfigValue || globalValue?.ConfigValue || fallback);
    },
    [integrationConfig],
  );

  const getAssignmentFindings = useCallback(
    (assignmentType: "CHECK" | "PACKAGE", assignmentKey: string): any[] => {
      if (assignmentType === "PACKAGE") {
        return findings.filter((f) => (f.PackageName || "Unassigned") === assignmentKey);
      }
      return findings.filter(
        (f) => (f.CheckCategory || resolveCheckCategory(f)) === assignmentKey,
      );
    },
    [findings, resolveCheckCategory],
  );

  const getJiraTicket = useCallback(
    (assignmentType: "CHECK" | "PACKAGE", assignmentKey: string) =>
      jiraTickets.find(
        (t: any) =>
          t.AssignmentType === assignmentType && t.AssignmentKey === assignmentKey,
      ),
    [jiraTickets],
  );

  const getJiraIssueUrl = useCallback(
    (issueKey: string, productId?: string): string => {
      if (!issueKey) return "";
      const base = getConfigValue(
        productId || currentProductContext?.productId || "",
        "JiraBaseUrl",
      );
      return base ? `${base.replace(/\/+$/, "")}/browse/${encodeURIComponent(issueKey)}` : "";
    },
    [currentProductContext?.productId, getConfigValue],
  );

  const renderJiraTicketBadge = useCallback(
    (assignmentType: "CHECK" | "PACKAGE", assignmentKey: string) => {
      const ticket = getJiraTicket(assignmentType, assignmentKey);
      if (!ticket) return null;
      const issueKey = ticket.JiraIssueKey || "";
      if (!issueKey) {
        return (
          <span
            style={{
              fontSize: 10,
              color: "#92400e",
              background: "#fffbeb",
              border: "1px solid #fde047",
              borderRadius: 999,
              padding: "1px 7px",
              fontWeight: 700,
            }}
          >
            Jira pending
          </span>
        );
      }
      const href = getJiraIssueUrl(issueKey, ticket.ProductId);
      const badge = (
        <span
          style={{
            fontSize: 10,
            color: "#0a6ed1",
            background: "#eff6ff",
            border: "1px solid #bfdbfe",
            borderRadius: 999,
            padding: "1px 7px",
            fontWeight: 700,
          }}
        >
          Jira {issueKey}
        </span>
      );
      return href ? (
        <a href={href} target="_blank" rel="noreferrer" style={{ textDecoration: "none" }}>
          {badge}
        </a>
      ) : (
        badge
      );
    },
    [getJiraIssueUrl, getJiraTicket],
  );

  // ── Security computed ───────────────────────────────────────────────────────
  const securityClassified = securityModuleIds.size > 0;
  const isCheckmanRun = selectedRun?.RunKind === "M";

  const securityFindings = useMemo(() => {
    if (findings.length === 0) return [];
    const hasCi = findings.some((f) => {
      const c = resolveCiId(f);
      return c && c !== "*INVALID*" && c !== "";
    });
    if (hasCi) return findings.filter((f) => isSecurityCiId(resolveCiId(f)));
    if (securityModuleIds.size > 0) {
      const g = findings.filter(
        (f) =>
          f.CheckCategory &&
          securityModuleIds.has((f.CheckCategory || "").toLowerCase()),
      );
      if (g.length > 0) return g;
    }
    return findings.filter((f) => {
      const r = resolveCheckTitle(f.CheckTitle, f.NavigationData);
      return (
        isTitleSecurityCheck(r) ||
        isTitleSecurityCheck(f.CheckTitle || "") ||
        isTitleSecurityCheck(f.CheckMessage || "") ||
        isTitleSecurityCheck(f.MessageKey || "")
      );
    });
  }, [findings, securityModuleIds, isSecurityCiId, resolveCiId]);

  const secP1 = useMemo(
    () => securityFindings.filter((f) => f.Priority === 1).length,
    [securityFindings],
  );
  const secP2 = useMemo(
    () => securityFindings.filter((f) => f.Priority === 2).length,
    [securityFindings],
  );
  const secP3 = useMemo(
    () => securityFindings.filter((f) => f.Priority === 3).length,
    [securityFindings],
  );
  const secP4 = useMemo(
    () => securityFindings.filter((f) => f.Priority === 4).length,
    [securityFindings],
  );
  const certificationBlocking = useMemo(() => secP1 + secP2, [secP1, secP2]);
  const isCertificationReady = certificationBlocking === 0;

  const getAttackVector = useCallback((ot: string, ci: string) => {
    const o = (ot || "").toUpperCase();
    const c = (ci || "").toUpperCase();
    if (
      o === "FUGR" ||
      o === "FUGS" ||
      o === "FUGX" ||
      o === "FUNC" ||
      c.includes("RFC") ||
      c.includes("REMOTE")
    )
      return {
        vector: "RFC",
        label: "RFC / Remote",
        color: "#dc2626",
        bg: "#fee2e2",
        icon: "📡",
      };
    if (o === "PROG" || o === "REPO" || o === "REPS" || o === "TRAN")
      return {
        vector: "DIALOG",
        label: "Dialog / Report",
        color: "#d97706",
        bg: "#fef3c7",
        icon: "🖥️",
      };
    if (
      o === "CLAS" ||
      o === "INTF" ||
      o === "METH" ||
      o === "CINC" ||
      o === "CLSD" ||
      o === "CPUB" ||
      o === "CPRO" ||
      o === "CPRI"
    )
      return {
        vector: "APP",
        label: "Application Layer",
        color: "#7c3aed",
        bg: "#ede9fe",
        icon: "⚙️",
      };
    if (
      o === "WAPA" ||
      o === "WAPP" ||
      o === "HTTP" ||
      o === "SICF" ||
      o === "WDYN" ||
      o === "WDYV" ||
      o === "WDYC" ||
      o === "WDYA"
    )
      return {
        vector: "WEB",
        label: "Web / UI Layer",
        color: "#0369a1",
        bg: "#e0f2fe",
        icon: "🌐",
      };
    return {
      vector: "OTHER",
      label: "Other",
      color: "#6b7280",
      bg: "#f3f4f6",
      icon: "📦",
    };
  }, []);

  const attackVectorSummary = useMemo(() => {
    const map: Record<string, any> = {};
    securityFindings.forEach((f) => {
      const av = getAttackVector(f.ObjectType || "", resolveCiId(f));
      const v = av.vector;
      if (!map[v])
        map[v] = {
          ...av,
          p1: 0,
          p2: 0,
          p3: 0,
          p4: 0,
          count: 0,
          objects: new Set(),
        };
      map[v].count++;
      map[v].objects.add(f.ObjectName || "Unknown");
      if (f.Priority === 1) map[v].p1++;
      else if (f.Priority === 2) map[v].p2++;
      else if (f.Priority === 3) map[v].p3++;
      else if (f.Priority === 4) map[v].p4++;
    });
    return Object.values(map).sort(
      (a, b) => b.p1 - a.p1 || b.p2 - a.p2 || b.count - a.count,
    );
  }, [securityFindings, resolveCiId, getAttackVector]);

  const securityByObject = useMemo(() => {
    const map: Record<
      string,
      {
        count: number;
        p1: number;
        p2: number;
        types: Set<string>;
        objType: string;
        ciIds: Set<string>;
      }
    > = {};
    securityFindings.forEach((f) => {
      const k = f.ObjectName || "Unknown";
      if (!map[k])
        map[k] = {
          count: 0,
          p1: 0,
          p2: 0,
          types: new Set(),
          objType: f.ObjectType || "",
          ciIds: new Set(),
        };
      map[k].count++;
      if (f.Priority === 1) map[k].p1++;
      if (f.Priority === 2) map[k].p2++;
      const ci = resolveCiId(f);
      if (ci && ci !== "*INVALID*") {
        map[k].types.add(ci);
        map[k].ciIds.add(ci);
      }
      if (f.ObjectType) map[k].objType = f.ObjectType;
    });
    return Object.entries(map)
      .map(([name, v]) => {
        const pci = [...v.ciIds][0] || "";
        const av = getAttackVector(v.objType, pci);
        return {
          name,
          count: v.count,
          p1: v.p1,
          p2: v.p2,
          typeCount: v.types.size,
          objType: v.objType,
          attackVector: av,
        };
      })
      .sort((a, b) => b.p1 - a.p1 || b.p2 - a.p2 || b.count - a.count)
      .slice(0, 15);
  }, [securityFindings, resolveCiId, getAttackVector]);

  const securityByDeveloper = useMemo(() => {
    const map: Record<
      string,
      {
        count: number;
        p1: number;
        p2: number;
        p3: number;
        p4: number;
        oldest: number;
      }
    > = {};
    securityFindings.forEach((f) => {
      const d = f.ContactPerson || f.Processor || "Unknown";
      if (!map[d]) map[d] = { count: 0, p1: 0, p2: 0, p3: 0, p4: 0, oldest: 0 };
      map[d].count++;
      if (f.Priority === 1) map[d].p1++;
      else if (f.Priority === 2) map[d].p2++;
      else if (f.Priority === 3) map[d].p3++;
      else if (f.Priority === 4) map[d].p4++;
      const dt = parseSince(f.Since);
      if (dt) {
        const a = ageDays(dt);
        if (a > map[d].oldest) map[d].oldest = a;
      }
    });
    return Object.entries(map)
      .map(([dev, v]) => ({ dev, ...v }))
      .sort((a, b) => b.p1 - a.p1 || b.p2 - a.p2 || b.count - a.count);
  }, [securityFindings]);

  const securityByCheckType = useMemo(() => {
    const map: Record<
      string,
      { count: number; p1: number; p2: number; riskName: string }
    > = {};
    securityFindings.forEach((f) => {
      const ci =
        resolveCiId(f) ||
        checkModules.find(
          (m) =>
            m.ModuleId.toLowerCase() === (f.CheckCategory || "").toLowerCase(),
        )?.CiId ||
        "";
      const kn = getSecurityKnowledge(ci);
      const mod = checkModules.find(
        (m) =>
          m.ModuleId.toLowerCase() === (f.CheckCategory || "").toLowerCase(),
      );
      const lbl =
        kn?.riskName ||
        mod?.ModuleTitle?.trim() ||
        f.RstismTitle?.trim() ||
        (ci && ci !== "*INVALID*" ? ci : "Security Check");
      if (!map[lbl]) map[lbl] = { count: 0, p1: 0, p2: 0, riskName: lbl };
      map[lbl].count++;
      if (f.Priority === 1) map[lbl].p1++;
      if (f.Priority === 2) map[lbl].p2++;
    });
    return Object.entries(map)
      .map(([, v]) => v)
      .sort((a, b) => b.p1 - a.p1 || b.p2 - a.p2 || b.count - a.count);
  }, [securityFindings, checkModules, getSecurityKnowledge, resolveCiId]);

  const securityAgeBuckets = useMemo(() => {
    const b = { "0–7 days": 0, "8–30 days": 0, "31–90 days": 0, "90+ days": 0 };
    securityFindings.forEach((f) => {
      const d = parseSince(f.Since);
      if (!d) return;
      const a = ageDays(d);
      if (a <= 7) b["0–7 days"]++;
      else if (a <= 30) b["8–30 days"]++;
      else if (a <= 90) b["31–90 days"]++;
      else b["90+ days"]++;
    });
    return Object.entries(b).map(([label, value]) => ({ label, value }));
  }, [securityFindings]);

  const myQueueFindings = useMemo(() => {
    if (!myUserId.trim()) return [];
    const uid = myUserId.trim().toUpperCase();
    return securityFindings
      .filter(
        (f) =>
          (f.ContactPerson || "").toUpperCase() === uid ||
          (f.Processor || "").toUpperCase() === uid,
      )
      .sort((a, b) => (a.Priority || 9) - (b.Priority || 9));
  }, [securityFindings, myUserId]);

  const certTimeline = useMemo(() => {
    if (filteredRuns.length < 2) return null;
    const s = [...filteredRuns].sort((a, b) =>
      (a.date || "").localeCompare(b.date || ""),
    );
    const h = Math.floor(s.length / 2);
    const af = s.slice(0, h).reduce((a, r) => a + r.p1 + r.p2, 0) / h;
    const as2 =
      s.slice(h).reduce((a, r) => a + r.p1 + r.p2, 0) / s.slice(h).length;
    const wi = (af - as2) / Math.max(h, 1);
    if (wi <= 0) return null;
    const cur = (selectedRun?.p1 || 0) + (selectedRun?.p2 || 0);
    return {
      weeklyImprovement: Math.round(wi),
      weeksNeeded: cur > 0 ? Math.ceil(cur / wi) : 0,
      currentP1P2: cur,
    };
  }, [filteredRuns, selectedRun]);

  // ── Comparison computed ─────────────────────────────────────────────────────
  const comparisonResult = useMemo(() => {
    if (
      !selectedRun ||
      !compareRun ||
      findings.length === 0 ||
      compareFindings.length === 0
    )
      return null;
    const key = (f: any) =>
      `${f.ObjectName}||${f.CheckCategory || ""}||${f.MessageKey || ""}||${f.Priority}`;
    const bSet = new Set(findings.map(key));
    const cSet = new Set(compareFindings.map(key));
    const regressions = compareFindings
      .filter((f) => !bSet.has(key(f)))
      .sort((a, b) => a.Priority - b.Priority);
    const improvements = findings
      .filter((f) => !cSet.has(key(f)))
      .sort((a, b) => a.Priority - b.Priority);
    const bObj: Record<string, number> = {};
    findings.forEach((f) => {
      const k = f.ObjectName || "Unknown";
      bObj[k] = (bObj[k] || 0) + 1;
    });
    const cObj: Record<string, number> = {};
    compareFindings.forEach((f) => {
      const k = f.ObjectName || "Unknown";
      cObj[k] = (cObj[k] || 0) + 1;
    });
    const allO = new Set([...Object.keys(bObj), ...Object.keys(cObj)]);
    const changed: {
      name: string;
      basTotal: number;
      cmpTotal: number;
      delta: number;
      worse: boolean;
    }[] = [];
    allO.forEach((o) => {
      const b = bObj[o] || 0;
      const c = cObj[o] || 0;
      if (b !== c)
        changed.push({
          name: o,
          basTotal: b,
          cmpTotal: c,
          delta: c - b,
          worse: c > b,
        });
    });
    changed.sort((a, b) => Math.abs(b.delta) - Math.abs(a.delta));
    return {
      regressions,
      improvements,
      changedObjects: changed,
      netChange: compareFindings.length - findings.length,
    };
  }, [selectedRun, compareRun, findings, compareFindings]);

  // ── Fix suggestion (REQ 4) ──────────────────────────────────────────────────
  const getFixSuggestion = useCallback(
    async (f: any) => {
      const key = f.MessageKey || f.CheckCategory || "";
      if (!key || fixCache.has(key) || fixLoadingKey === key) return;
      setFixLoadingKey(key);
      const title = (f.RstismTitle || f.CheckTitle || "").trim();
      const prompt = `You are an SAP ABAP expert. Give a concise practical fix for this ATC finding in 3-4 sentences. Focus on the exact code change needed.\n\nObject: ${f.ObjectName || "—"} (${f.ObjectType || "—"})\nCheck: ${resolveCheckCategory(f)}\nMessage: ${title || f.MessageKey || "—"}\nPriority: P${f.Priority}`;
      try {
        const r = await fetch("https://api.anthropic.com/v1/messages", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            model: "claude-sonnet-4-20250514",
            max_tokens: 300,
            messages: [{ role: "user", content: prompt }],
          }),
        });
        const data = await r.json();
        const text = (data.content || [])
          .filter((b: any) => b.type === "text")
          .map((b: any) => b.text)
          .join("");
        setFixCache((prev) => new Map(prev).set(key, text));
      } catch {
        setFixCache((prev) =>
          new Map(prev).set(
            key,
            "Could not generate suggestion. Please try again.",
          ),
        );
      } finally {
        setFixLoadingKey("");
      }
    },
    [fixCache, fixLoadingKey, resolveCheckCategory],
  );

  const renderFixGuidance = useCallback(
    (f: any) => {
      const ci = resolveCiId(f);
      const staticFix =
        getSecurityKnowledge(ci) ||
        getSecurityKnowledgeByModuleId(f.CheckCategory);
      const key = f.MessageKey || f.CheckCategory || "";
      const cached = fixCache.get(key);
      const isLoading = fixLoadingKey === key;
      return (
        <details style={{ marginTop: 8, borderRadius: 8, overflow: "hidden" }}>
          <summary
            style={{
              fontSize: 11,
              fontWeight: 700,
              color: "#0a6ed1",
              cursor: "pointer",
              padding: "6px 10px",
              background: "#eff6ff",
              borderRadius: 8,
              listStyle: "none",
              display: "flex",
              alignItems: "center",
              gap: 6,
            }}
          >
            💡 Fix Guidance{" "}
            {staticFix ? (
              <span
                style={{
                  fontSize: 10,
                  background: "#dcfce7",
                  color: "#15803d",
                  borderRadius: 999,
                  padding: "1px 6px",
                }}
              >
                Available
              </span>
            ) : null}
          </summary>
          <div
            style={{
              padding: "10px 12px",
              background: "#f0fdf4",
              borderLeft: "3px solid #22c55e",
              borderRadius: "0 0 8px 8px",
              marginTop: 2,
            }}
          >
            {staticFix ? (
              <>
                <div
                  style={{
                    fontSize: 11,
                    fontWeight: 700,
                    color: "#15803d",
                    marginBottom: 4,
                  }}
                >
                  {staticFix.riskName}
                </div>
                <div
                  style={{ fontSize: 11, color: "#166534", lineHeight: 1.6 }}
                >
                  {staticFix.fixGuidance}
                </div>
              </>
            ) : cached ? (
              <div
                style={{
                  fontSize: 11,
                  color: "#166534",
                  lineHeight: 1.6,
                  whiteSpace: "pre-wrap",
                }}
              >
                {cached}
              </div>
            ) : (
              <button
                onClick={() => getFixSuggestion(f)}
                disabled={isLoading}
                style={{
                  fontSize: 11,
                  padding: "5px 12px",
                  borderRadius: 6,
                  border: "none",
                  background: isLoading ? "#e5e7eb" : "#0a6ed1",
                  color: isLoading ? "#6b7280" : "white",
                  cursor: isLoading ? "default" : "pointer",
                  fontWeight: 600,
                }}
              >
                {isLoading
                  ? "⏳ Getting suggestion..."
                  : "✨ Get AI Fix Suggestion"}
              </button>
            )}
          </div>
        </details>
      );
    },
    [
      fixCache,
      fixLoadingKey,
      getFixSuggestion,
      getSecurityKnowledge,
      getSecurityKnowledgeByModuleId,
      resolveCiId,
    ],
  );

  const renderNavButtons = useCallback(
    (f: any) => {
      if (connection !== "netweaver") return null;
      const host = ((connections.netweaver as any).host || "").replace(
        /\/$/,
        "",
      );
      if (!host)
        return (
          <div
            style={{
              marginTop: 8,
              padding: "6px 10px",
              background: "#fefce8",
              borderRadius: 6,
              fontSize: 11,
              color: "#713f12",
              border: "1px solid #fde047",
            }}
          >
            ⚠️ Set System Host URL in Settings to enable Eclipse navigation
          </div>
        );

      const adtHost = host.replace(/^https?:\/\//, "");

      // Build ADT path — use Location field first, fall back to object type mapping
      const buildAdtPath = (): string | null => {
        if (f.Location && f.Location.trim()) return f.Location.trim();
        const obj = (f.ObjectName || "").toUpperCase();
        const ot = (f.ObjectType || "").toUpperCase();
        if (!obj) return null;
        const map: Record<string, string> = {
          PROG: `/sap/bc/adt/programs/programs/${obj}`,
          REPO: `/sap/bc/adt/programs/programs/${obj}`,
          REPS: `/sap/bc/adt/programs/programs/${obj}`,
          CLAS: `/sap/bc/adt/oo/classes/${obj}/source/main`,
          INTF: `/sap/bc/adt/oo/interfaces/${obj}/source/main`,
          METH: `/sap/bc/adt/oo/classes/${obj}/source/main`,
          FUGR: `/sap/bc/adt/function_groups/${obj}/source/main`,
          FUGS: `/sap/bc/adt/function_groups/${obj}/source/main`,
          FUNC: `/sap/bc/adt/function_groups/${obj}/source/main`,
          TABL: `/sap/bc/adt/ddic/tables/${obj}/source/main`,
          VIEW: `/sap/bc/adt/ddic/views/${obj}/source/main`,
          DOMA: `/sap/bc/adt/ddic/domains/${obj}/source/main`,
          DTEL: `/sap/bc/adt/ddic/dataelements/${obj}/source/main`,
          DDLS: `/sap/bc/adt/ddic/ddl/sources/${obj}/source/main`,
          BDEF: `/sap/bc/adt/bo/behaviors/${obj}/source/main`,
          TRAN: `/sap/bc/adt/transactions/${obj}`,
          DEVC: `/sap/bc/adt/packages/${obj}`,
        };
        return map[ot] || null;
      };

      const adtPath = buildAdtPath();
      if (!adtPath) return null;

      const adtUrl = `adt://${adtHost}${adtPath}`;
      const isFromLocation = !!(f.Location && f.Location.trim());

      return (
        <div
          style={{
            display: "flex",
            gap: 6,
            marginTop: 10,
            paddingTop: 10,
            borderTop: "1px solid #f3f4f6",
            alignItems: "center",
            flexWrap: "wrap",
          }}
        >
          <a
            href={adtUrl}
            style={{
              fontSize: 11,
              padding: "4px 12px",
              borderRadius: 6,
              border: "1px solid #bfdbfe",
              background: "#eff6ff",
              color: "#1e40af",
              textDecoration: "none",
              fontWeight: 600,
              display: "inline-flex",
              alignItems: "center",
              gap: 4,
            }}
          >
            🔵 Open in Eclipse ADT
          </a>
          {!isFromLocation && (
            <span style={{ fontSize: 10, color: "#9ca3af" }}>
              (path derived from object type — verify line accuracy)
            </span>
          )}
        </div>
      );
    },
    [connection, connections],
  );
  // ── Check & Package Assignment OData helpers ────────────────────────────────
  const odataKey = (v: any) =>
    encodeURIComponent(String(v ?? "").replace(/'/g, "''"));

  const buildJiraPayload = useCallback(
    (
      assignmentType: "CHECK" | "PACKAGE",
      assignmentKey: string,
      assignedUserId: string,
    ) => {
      if (!selectedRun || !currentProductContext) {
        throw new Error("No selected run/product context for Jira ticket.");
      }
      if (!currentProductContext.jiraProjectKey) {
        throw new Error(
          `Jira project key is missing for product ${currentProductContext.productId}.`,
        );
      }

      const rows = getAssignmentFindings(assignmentType, assignmentKey);
      const p1 = rows.filter((f) => Number(f.Priority) === 1).length;
      const p2 = rows.filter((f) => Number(f.Priority) === 2).length;
      const p3 = rows.filter((f) => Number(f.Priority) === 3).length;
      const p4 = rows.filter((f) => Number(f.Priority) === 4).length;
      const label =
        assignmentType === "CHECK"
          ? resolveCheckCategory(rows[0] || { CheckCategory: assignmentKey }) ||
            assignmentKey
          : `Package ${assignmentKey}`;
      const title = `[ATC] ${assignmentType === "CHECK" ? "Check" : "Package"} ${label} - ${rows.length} finding${rows.length === 1 ? "" : "s"}`;
      const objectList = [
        ...new Set(rows.map((f) => f.ObjectName).filter(Boolean)),
      ].slice(0, 20);
      const issueType = getConfigValue(
        currentProductContext.productId,
        "JiraIssueType",
        "",
      );
      const priorityName =
        p1 > 0
          ? getConfigValue(currentProductContext.productId, "JiraPriorityP1", "")
          : p2 > 0
            ? getConfigValue(currentProductContext.productId, "JiraPriorityP2", "")
            : "";
      const labels = [
        getConfigValue(
          currentProductContext.productId,
          "JiraLabels",
          "atc,atc-monitor",
        ),
        assignmentType.toLowerCase(),
        currentProductContext.productId,
      ]
        .filter(Boolean)
        .join(",");
      const description = [
        "ATC remediation ticket created from ATC Run Monitor.",
        "",
        `Run: ${selectedRun.title || selectedRun.series || selectedRun.ID}`,
        `Run ID: ${selectedRun.ID}`,
        `Run series: ${selectedRun.series || "-"}`,
        `System: ${selectedRun.system || "-"}`,
        `Run date: ${selectedRun.date || "-"}`,
        `Product: ${currentProductContext.productId}`,
        `Assignment: ${assignmentType} / ${assignmentKey}`,
        `Assigned owner: ${assignedUserId}`,
        "",
        `Findings: ${rows.length} total | P1 ${p1} | P2 ${p2} | P3 ${p3} | P4 ${p4}`,
        "",
        objectList.length ? "Affected objects:" : "Affected objects: none found",
        ...objectList.map((obj) => `- ${obj}`),
        rows.length > objectList.length
          ? `- ...and ${rows.length - objectList.length} more finding rows`
          : "",
      ]
        .filter((line) => line !== "")
        .join("\n");

      return {
        projectKey: currentProductContext.jiraProjectKey,
        issueType,
        summary: title,
        description,
        labels,
        priorityName,
        assigneeAccountId: "",
      };
    },
    [
      currentProductContext,
      getAssignmentFindings,
      getConfigValue,
      resolveCheckCategory,
      selectedRun,
    ],
  );

  const raiseJiraIssue = useCallback(async (payload: any) => {
    const r = await fetch("/odata/v4/atc/raiseJiraTicket", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const data = await r.json().catch(() => ({}));
    if (!r.ok) {
      throw new Error(data?.error?.message || `HTTP ${r.status}`);
    }
    const result = data?.value || data;
    if (!result?.issueKey) {
      throw new Error("Jira did not return an issue key.");
    }
    return result;
  }, []);

  const ensureJiraTicketRecord = useCallback(
    async (
      base: string,
      token: string,
      productId: string,
      runSeries: string,
      run: Run,
      assignmentType: "CHECK" | "PACKAGE",
      assignmentKey: string,
      assignedUserId: string,
    ): Promise<{ issueKey: string; created: boolean }> => {
      const existing = getJiraTicket(assignmentType, assignmentKey);
      if (existing?.JiraIssueKey) {
        return { issueKey: existing.JiraIssueKey, created: false };
      }

      const issue = await raiseJiraIssue(
        buildJiraPayload(assignmentType, assignmentKey, assignedUserId),
      );
      const body = {
        ProductId: productId,
        RunSeries: runSeries,
        RunId: run.ID,
        AssignmentType: assignmentType,
        AssignmentKey: assignmentKey,
        JiraIssueKey: issue.issueKey,
        AssignedUserId: assignedUserId,
        RunDate: run.date || "",
      };
      const headers = {
        "Content-Type": "application/json",
        "X-CSRF-Token": token,
      };
      const keyPath = `${base}/JiraTickets(ProductId='${odataKey(productId)}',RunSeries='${odataKey(runSeries)}',RunId='${odataKey(run.ID)}',AssignmentType='${assignmentType}',AssignmentKey='${odataKey(assignmentKey)}')`;
      const write = existing
        ? await fetch(keyPath, {
            method: "PATCH",
            headers,
            body: JSON.stringify({
              JiraIssueKey: issue.issueKey,
              AssignedUserId: assignedUserId,
              RunDate: run.date || "",
            }),
          })
        : await fetch(`${base}/JiraTickets`, {
            method: "POST",
            headers,
            body: JSON.stringify(body),
          });

      if (!write.ok) {
        throw new Error(`Jira ticket tracking update failed: HTTP ${write.status}`);
      }

      return { issueKey: issue.issueKey, created: true };
    },
    [buildJiraPayload, getJiraTicket, raiseJiraIssue],
  );

  const fetchAssignments = useCallback(
    async (run: Run) => {
      if (!run.series || connection !== "netweaver") return;
      const base = connections[connection].baseUrl;
      const seriesEntry = productRunSeries.find(
        (s) => s.RunSeries.toUpperCase() === (run.series || "").toUpperCase(),
      );
      if (!seriesEntry) return;
      const productId = seriesEntry.ProductId;
      const runSeries = run.series;

      try {
        const url = `${base}/CheckAssignments?$filter=ProductId eq '${productId}' and RunSeries eq '${runSeries}' and RunId eq '${run.ID}'`;
        const r = await fetch(url);
        if (r.ok) {
          const j = await r.json();
          const rows = j.value || [];
          setCheckAssignments(rows);
          const map: Record<string, string> = {};
          rows.forEach((row: any) => {
            if (row.CheckCategory && row.AssignedUserId) {
              map[row.CheckCategory] = row.AssignedUserId;
            }
          });
          setAssignments(map);
        }
      } catch (e) {
        console.error("Failed to fetch check assignments:", e);
      }

      try {
        const url = `${base}/PackageAssignments?$filter=ProductId eq '${productId}' and RunSeries eq '${runSeries}' and RunId eq '${run.ID}'`;
        const r = await fetch(url);
        if (r.ok) {
          const j = await r.json();
          const rows = j.value || [];
          setPkgAssignmentsBackend(rows);
          const map: Record<string, string> = {};
          rows.forEach((row: any) => {
            if (row.PackageName && row.AssignedUserId)
              map[row.PackageName] = row.AssignedUserId;
          });
          setPackageAssignments(map);
        }
      } catch (e) {
        console.error("Failed to fetch package assignments:", e);
      }

      try {
        const url = `${base}/JiraTickets?$filter=ProductId eq '${productId}' and RunSeries eq '${runSeries}' and RunId eq '${run.ID}'`;
        const r = await fetch(url);
        if (r.ok) {
          const j = await r.json();
          setJiraTickets(j.value || []);
        }
      } catch (e) {
        console.error("Failed to fetch JIRA tickets:", e);
      }
    },
    [connection, connections, productRunSeries, findings, resolveCheckCategory],
  );

  const saveCheckAssignments = useCallback(async () => {
    if (!selectedRun || connection !== "netweaver") return;
    const seriesEntry = productRunSeries.find(
      (s) =>
        s.RunSeries.toUpperCase() === (selectedRun.series || "").toUpperCase(),
    );
    if (!seriesEntry) {
      setAssignmentsSaveError(
        "Could not determine ProductId for this run series.",
      );
      return;
    }
    const productId = seriesEntry.ProductId;
    const runSeries = selectedRun.series || "";
    setAssignmentsSaving(true);
    setAssignmentsSaveError("");
    setAssignmentsSaveSuccess("");
    try {
      const base = connections[connection].baseUrl;
      const csrfR = await fetch(`${base}/Runs?$top=1`, {
        method: "GET",
        headers: { "X-CSRF-Token": "Fetch" },
      });
      const token =
        csrfR.headers.get("x-csrf-token") ||
        csrfR.headers.get("X-CSRF-Token") ||
        "";
      const errors: string[] = [];
      let jiraCreated = 0;
      let jiraExisting = 0;

      for (const [checkCategory, assignedUserId] of Object.entries(
        assignments,
      )) {
        const existing = checkAssignments.find(
          (r) => r.CheckCategory === checkCategory,
        );
        let assignmentSaved = false;
        if (existing) {
          const r = await fetch(
            `${base}/CheckAssignments(ProductId='${productId}',RunSeries='${runSeries}',RunId='${selectedRun.ID}',CheckCategory='${encodeURIComponent(checkCategory)}')`,
            {
              method: "PATCH",
              headers: {
                "Content-Type": "application/json",
                "X-CSRF-Token": token,
              },
              body: JSON.stringify({ AssignedUserId: assignedUserId }),
            },
          );
          if (!r.ok)
            errors.push(`PATCH failed for ${checkCategory}: HTTP ${r.status}`);
          else assignmentSaved = true;
        } else {
          const r = await fetch(`${base}/CheckAssignments`, {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              "X-CSRF-Token": token,
            },
            body: JSON.stringify({
              ProductId: productId,
              RunSeries: runSeries,
              RunId: selectedRun.ID,
              CheckCategory: checkCategory,
              AssignedUserId: assignedUserId,
            }),
          });
          if (!r.ok) {
            errors.push(`POST failed for ${checkCategory}: HTTP ${r.status}`);
          } else {
            assignmentSaved = true;
          }
        }
        if (assignmentSaved) {
          try {
            const jira = await ensureJiraTicketRecord(
              base,
              token,
              productId,
              runSeries,
              selectedRun,
              "CHECK",
              checkCategory,
              assignedUserId,
            );
            if (jira.created) jiraCreated++;
            else if (jira.issueKey) jiraExisting++;
          } catch (e: any) {
            errors.push(
              `Jira failed for ${checkCategory}: ${e?.message || "unknown error"}`,
            );
          }
        }
      }
      for (const existing of checkAssignments) {
        if (!assignments[existing.CheckCategory]) {
          const r = await fetch(
            `${base}/CheckAssignments(ProductId='${productId}',RunSeries='${runSeries}',RunId='${selectedRun.ID}',CheckCategory='${encodeURIComponent(existing.CheckCategory)}')`,
            { method: "DELETE", headers: { "X-CSRF-Token": token } },
          );
          if (!r.ok)
            errors.push(
              `DELETE failed for ${existing.CheckCategory}: HTTP ${r.status}`,
            );
        }
      }
      if (errors.length > 0) {
        setAssignmentsSaveError(errors.join(" | "));
        await fetchAssignments(selectedRun);
      } else {
        setAssignmentsSaveSuccess(
          `Check assignments saved successfully. ${jiraCreated} Jira ticket${jiraCreated === 1 ? "" : "s"} created${jiraExisting ? `, ${jiraExisting} already linked` : ""}.`,
        );
        await fetchAssignments(selectedRun);
      }
    } catch (e: any) {
      setAssignmentsSaveError(e?.message || "Save failed.");
    } finally {
      setAssignmentsSaving(false);
    }
  }, [
    selectedRun,
    assignments,
    checkAssignments,
    jiraTickets,
    connection,
    connections,
    productRunSeries,
    fetchAssignments,
    ensureJiraTicketRecord,
  ]);

  const savePackageAssignments = useCallback(async () => {
    if (!selectedRun || connection !== "netweaver") return;
    const seriesEntry = productRunSeries.find(
      (s) =>
        s.RunSeries.toUpperCase() === (selectedRun.series || "").toUpperCase(),
    );
    if (!seriesEntry) {
      setPkgSaveError("Could not determine ProductId for this run series.");
      return;
    }
    const productId = seriesEntry.ProductId;
    const runSeries = selectedRun.series || "";
    setPkgSaving(true);
    setPkgSaveError("");
    setPkgSaveSuccess("");
    try {
      const base = connections[connection].baseUrl;
      const csrfR = await fetch(`${base}/Runs?$top=1`, {
        method: "GET",
        headers: { "X-CSRF-Token": "Fetch" },
      });
      const token =
        csrfR.headers.get("x-csrf-token") ||
        csrfR.headers.get("X-CSRF-Token") ||
        "";
      const errors: string[] = [];
      let jiraCreated = 0;
      let jiraExisting = 0;

      for (const [packageName, assignedUserId] of Object.entries(
        packageAssignments,
      )) {
        const existing = pkgAssignmentsBackend.find(
          (r) => r.PackageName === packageName,
        );
        let assignmentSaved = false;
        if (existing) {
          const r = await fetch(
            `${base}/PackageAssignments(ProductId='${productId}',RunSeries='${runSeries}',RunId='${selectedRun.ID}',PackageName='${encodeURIComponent(packageName)}')`,
            {
              method: "PATCH",
              headers: {
                "Content-Type": "application/json",
                "X-CSRF-Token": token,
              },
              body: JSON.stringify({ AssignedUserId: assignedUserId }),
            },
          );
          if (!r.ok)
            errors.push(`PATCH failed for ${packageName}: HTTP ${r.status}`);
          else assignmentSaved = true;
        } else {
          const r = await fetch(`${base}/PackageAssignments`, {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              "X-CSRF-Token": token,
            },
            body: JSON.stringify({
              ProductId: productId,
              RunSeries: runSeries,
              RunId: selectedRun.ID,
              PackageName: packageName,
              AssignedUserId: assignedUserId,
            }),
          });
          if (!r.ok) {
            errors.push(`POST failed for ${packageName}: HTTP ${r.status}`);
          } else {
            assignmentSaved = true;
          }
        }
        if (assignmentSaved) {
          try {
            const jira = await ensureJiraTicketRecord(
              base,
              token,
              productId,
              runSeries,
              selectedRun,
              "PACKAGE",
              packageName,
              assignedUserId,
            );
            if (jira.created) jiraCreated++;
            else if (jira.issueKey) jiraExisting++;
          } catch (e: any) {
            errors.push(
              `Jira failed for ${packageName}: ${e?.message || "unknown error"}`,
            );
          }
        }
      }
      for (const existing of pkgAssignmentsBackend) {
        if (!packageAssignments[existing.PackageName]) {
          const r = await fetch(
            `${base}/PackageAssignments(ProductId='${productId}',RunSeries='${runSeries}',RunId='${selectedRun.ID}',PackageName='${encodeURIComponent(existing.PackageName)}')`,
            { method: "DELETE", headers: { "X-CSRF-Token": token } },
          );
          if (!r.ok)
            errors.push(
              `DELETE failed for ${existing.PackageName}: HTTP ${r.status}`,
            );
        }
      }
      if (errors.length > 0) {
        setPkgSaveError(errors.join(" | "));
        await fetchAssignments(selectedRun);
      } else {
        setPkgSaveSuccess(
          `Package assignments saved successfully. ${jiraCreated} Jira ticket${jiraCreated === 1 ? "" : "s"} created${jiraExisting ? `, ${jiraExisting} already linked` : ""}.`,
        );
        await fetchAssignments(selectedRun);
      }
    } catch (e: any) {
      setPkgSaveError(e?.message || "Save failed.");
    } finally {
      setPkgSaving(false);
    }
  }, [
    selectedRun,
    packageAssignments,
    pkgAssignmentsBackend,
    jiraTickets,
    connection,
    connections,
    productRunSeries,
    fetchAssignments,
    ensureJiraTicketRecord,
  ]);
  // ── Admin write helpers ─────────────────────────────────────────────────────
  const fetchCsrfToken = useCallback(async (): Promise<string> => {
    const base = connections[connection].baseUrl;
    try {
      const r = await fetch(`${base}/`, {
        method: "GET",
        headers: { "X-CSRF-Token": "Fetch" },
      });
      return r.headers.get("x-csrf-token") || "";
    } catch {
      return "";
    }
  }, [activeSystem]);

  const adminWrite = useCallback(
    async (
      method: "POST" | "PATCH" | "DELETE",
      path: string,
      body?: any,
    ): Promise<{ ok: boolean; status: number; data?: any }> => {
      setAdminLoading(true);
      setAdminError("");
      setAdminSuccess("");
      try {
        const base = connections[connection].baseUrl;
        const token = await fetchCsrfToken();
        const headers: any = {
          "Content-Type": "application/json",
          "X-CSRF-Token": token,
        };
        const r = await fetch(`${base}${path}`, {
          method,
          headers,
          body: body ? JSON.stringify(body) : undefined,
        });
        if (!r.ok) {
          const err = await r.json().catch(() => ({}));
          const msg = err?.error?.message || `HTTP ${r.status}`;
          setAdminError(msg);
          return { ok: false, status: r.status };
        }
        setAdminSuccess("Saved successfully.");
        return { ok: true, status: r.status };
      } catch (e: any) {
        setAdminError(e?.message || "Request failed.");
        return { ok: false, status: 0 };
      } finally {
        setAdminLoading(false);
      }
    },
    [connection, connections, fetchCsrfToken],
  );

  const refreshAdminData = useCallback(() => {
    if (!activeSystem || activeSystem.SystemType !== "NETWEAVER") return;
    fetchData("/Products")
      .then((p) => setProducts(p))
      .catch(() => {});
    fetchData("/ProductRunSeries")
      .then((s) => setProductRunSeries(s))
      .catch(() => {});
    fetchData("/Teams")
      .then((t) => setTeams(t))
      .catch(() => {});
    fetchData("/IntegrationConfig")
      .then((c) => setIntegrationConfig(c))
      .catch(() => {});
    fetchData("/DeveloperProfiles")
      .then((profiles) => {
        setDevProfiles(
          profiles
            .filter((p: any) => p.IsActive)
            .sort((a: any, b: any) =>
              a.DisplayName.localeCompare(b.DisplayName),
            ),
        );
      })
      .catch(() => {});
  }, [activeSystem]); // eslint-disable-line

  // ── Systems CRUD helpers ────────────────────────────────────────────────────
  const fetchSystemsCsrf = useCallback(async (): Promise<string> => {
    try {
      const r = await fetch(`${BOOTSTRAP_URL}/Runs?$top=1`, {
        method: "GET",
        headers: { "X-CSRF-Token": "Fetch" },
      });
      return (
        r.headers.get("x-csrf-token") || r.headers.get("X-CSRF-Token") || ""
      );
    } catch {
      return "";
    }
  }, []);

  const refreshSystems = useCallback(async () => {
    try {
      const r = await fetch(`${BOOTSTRAP_URL}/Systems`);
      if (!r.ok) return;
      const j = await r.json();
      setSystems(j.value || []);
    } catch {}
  }, []);

  const saveSystem = useCallback(
    async (
      method: "POST" | "PATCH" | "DELETE",
      systemId: string,
      body?: Partial<SystemConfig>,
    ): Promise<boolean> => {
      setSysLoading(true);
      setSysError("");
      setSysSuccess("");
      try {
        const token = await fetchSystemsCsrf();
        const url =
          method === "POST"
            ? `${BOOTSTRAP_URL}/Systems`
            : `${BOOTSTRAP_URL}/Systems(SystemId='${encodeURIComponent(systemId)}')`;
        const r = await fetch(url, {
          method,
          headers: {
            "Content-Type": "application/json",
            "X-CSRF-Token": token,
          },
          body: body ? JSON.stringify(body) : undefined,
        });
        if (!r.ok) {
          const err = await r.json().catch(() => ({}));
          setSysError(err?.error?.message || `HTTP ${r.status}`);
          return false;
        }
        setSysSuccess("Saved successfully.");
        await refreshSystems();
        return true;
      } catch (e: any) {
        setSysError(e?.message || "Request failed.");
        return false;
      } finally {
        setSysLoading(false);
      }
    },
    [fetchSystemsCsrf, refreshSystems],
  );

  // ── Developer profile lookup (Phase 2) ─────────────────────────────────────
  const displayUser = useCallback(
    (userId: string | undefined | null): string => {
      if (!userId || userId.trim() === "") return "—";
      const p = devProfiles.find(
        (d) => d.UserId.toUpperCase() === userId.trim().toUpperCase(),
      );
      return p ? p.DisplayName : userId;
    },
    [devProfiles],
  );

  // ── Package findings drawer opener (REQ 1) ──────────────────────────────────
  const openPkgFindingsDrawer = useCallback(
    (packageName: string) => {
      setPkgFindingsDrawerTitle(packageName);
      setPkgFindingsDrawerData(
        findings.filter((f) => (f.PackageName || "—") === packageName),
      );
      setPkgFindingsDrawerOpen(true);
    },
    [findings],
  );

  // ── Security drawer openers ─────────────────────────────────────────────────
  const openSecurityPriorityDrawer = useCallback(
    (priority: number) => {
      const lbl =
        priority === 1
          ? "P1 — Critical"
          : priority === 2
            ? "P2 — Warning"
            : priority === 3
              ? "P3 — Info"
              : `P${priority}`;
      setSecDrawerTitle(`Security Findings — ${lbl}`);
      setSecDrawerFindings(
        securityFindings.filter((f) => Number(f.Priority) === priority),
      );
      setSecDrawerOpen(true);
    },
    [securityFindings],
  );
  const openSecurityDeveloperDrawer = useCallback(
    (developer: string) => {
      setSecDrawerTitle(`Security Findings — Developer: ${developer}`);
      setSecDrawerFindings(
        securityFindings.filter(
          (f) =>
            (f.Processor ?? "Unknown") === developer ||
            (f.ContactPerson ?? "Unknown") === developer,
        ),
      );
      setSecDrawerOpen(true);
    },
    [securityFindings],
  );
  const openDevFindingsDrawer = useCallback(
    (checkKey: string) => {
      const checkFindings = findings.filter(
        (f) => (f.CheckCategory || resolveCheckCategory(f)) === checkKey,
      );
      const displayTitle =
        checkFindings.length > 0
          ? resolveCheckCategory(checkFindings[0])
          : checkKey;
      setDevFindingsDrawerTitle(displayTitle);
      setDevFindingsDrawerData(checkFindings);
      setDevFindingsDrawerOpen(true);
    },
    [findings, resolveCheckCategory],
  );
  // ── AI Pattern Analysis (Developer Hub) ────────────────────────────────────
  const runPatternAnalysis = useCallback(async () => {
    if (findings.length === 0) return;
    setPatternLoading(true);
    setPatternError("");
    setPatternResult(null);
    const cs = checkRegistry.slice(0, 25).map((c) => ({
      check: c.key,
      p1: c.p1,
      p2: c.p2,
      p3: c.p3,
      total: c.total,
      topObjects: c.objectList.slice(0, 8),
      currentOwners: c.devList.slice(0, 5),
    }));
    const dOwn: Record<string, { checks: string[]; p1Total: number }> = {};
    findings.forEach((f) => {
      const dev = (f.ContactPerson || f.Processor || "Unknown").trim();
      const k = resolveCheckCategory(f);
      if (!dOwn[dev]) dOwn[dev] = { checks: [], p1Total: 0 };
      if (!dOwn[dev].checks.includes(k)) dOwn[dev].checks.push(k);
      if (f.Priority === 1) dOwn[dev].p1Total++;
    });
    const prompt = `You are an expert SAP ABAP quality architect. Analyze ATC findings and produce developer assignment recommendations.\n\nRun: ${selectedRun?.title || selectedRun?.series || "current"} (${selectedRun?.date || "unknown"})\nSystem: ${selectedRun?.system || "unknown"}\nFindings: ${findings.length} | Developers: ${allKnownDevelopers.length} | Check types: ${checkRegistry.length}\n\nCHECK CATEGORIES:\n${JSON.stringify(cs, null, 2)}\n\nDEVELOPER OWNERSHIP:\n${JSON.stringify(dOwn, null, 2)}\n\nReturn ONLY valid JSON, no markdown:\n{"summary":"2-3 sentence overview","topPriority":"most important fix","workloadBalance":"1 sentence","patterns":[{"patternName":"","checkCategories":[],"riskLevel":"CRITICAL|HIGH|MEDIUM","totalFindings":0,"rootCause":"","fixBrief":"","suggestedDeveloper":null,"assignmentReason":"","estimatedEffort":""}]}`;
    try {
      const r = await fetch("https://api.anthropic.com/v1/messages", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          model: "claude-sonnet-4-20250514",
          max_tokens: 1000,
          messages: [{ role: "user", content: prompt }],
        }),
      });
      if (!r.ok) {
        const e = await r.json().catch(() => ({}));
        throw new Error((e as any)?.error?.message || `API error ${r.status}`);
      }
      const data = await r.json();
      const text = (data.content || [])
        .filter((b: any) => b.type === "text")
        .map((b: any) => b.text)
        .join("");
      setPatternResult(JSON.parse(text.replace(/```json|```/g, "").trim()));
    } catch (e: any) {
      setPatternError(e?.message || "Pattern analysis failed.");
    } finally {
      setPatternLoading(false);
    }
  }, [
    findings,
    checkRegistry,
    allKnownDevelopers,
    selectedRun,
    resolveCheckCategory,
  ]); // ── Excel helpers ────────────────────────────────────────────────────────────
  const buildXlsx = useCallback(
    async (
      sheets: {
        name: string;
        rows: any[][];
        colWidths: number[];
        headerStyle?: string;
      }[],
    ) => {
      const JSZip = (window as any).JSZip;
      if (!JSZip) {
        alert("JSZip not loaded. Check index.html.");
        return;
      }
      const zip = new JSZip();
      const esc = (v: any) =>
        String(v ?? "")
          .replace(/&/g, "&amp;")
          .replace(/</g, "&lt;")
          .replace(/>/g, "&gt;")
          .replace(/"/g, "&quot;");
      const cellRef = (r: number, c: number) => {
        let col = "";
        let n = c + 1;
        while (n > 0) {
          col = String.fromCharCode(65 + ((n - 1) % 26)) + col;
          n = Math.floor((n - 1) / 26);
        }
        return col + (r + 1);
      };
      const sharedStrings: string[] = [];
      const ssMap: Record<string, number> = {};
      const ss = (v: string) => {
        if (ssMap[v] === undefined) {
          ssMap[v] = sharedStrings.length;
          sharedStrings.push(v);
        }
        return ssMap[v];
      };

      const STYLES = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
  <fonts count="6">
    <font><sz val="10"/><name val="Calibri"/></font>
    <font><b/><sz val="11"/><color rgb="FFFFFFFF"/><name val="Calibri"/></font>
    <font><b/><sz val="10"/><color rgb="FFDC2626"/><name val="Calibri"/></font>
    <font><b/><sz val="10"/><color rgb="FFD97706"/><name val="Calibri"/></font>
    <font><b/><sz val="10"/><color rgb="FF15803D"/><name val="Calibri"/></font>
    <font><b/><sz val="14"/><color rgb="FFFFFFFF"/><name val="Calibri"/></font>
  </fonts>
  <fills count="14">
    <fill><patternFill patternType="none"/></fill>
    <fill><patternFill patternType="gray125"/></fill>
    <fill><patternFill patternType="solid"><fgColor rgb="FF0A6ED1"/></patternFill></fill>
    <fill><patternFill patternType="solid"><fgColor rgb="FFFFFFFF"/></patternFill></fill>
    <fill><patternFill patternType="solid"><fgColor rgb="FFF0F7FF"/></patternFill></fill>
    <fill><patternFill patternType="solid"><fgColor rgb="FFFEE2E2"/></patternFill></fill>
    <fill><patternFill patternType="solid"><fgColor rgb="FFFFF3C7"/></patternFill></fill>
    <fill><patternFill patternType="solid"><fgColor rgb="FFDCFCE7"/></patternFill></fill>
    <fill><patternFill patternType="solid"><fgColor rgb="FF0F172A"/></patternFill></fill>
    <fill><patternFill patternType="solid"><fgColor rgb="FFF8FAFC"/></patternFill></fill>
    <fill><patternFill patternType="solid"><fgColor rgb="FFFFF1F2"/></patternFill></fill>
    <fill><patternFill patternType="solid"><fgColor rgb="FFF0FDF4"/></patternFill></fill>
    <fill><patternFill patternType="solid"><fgColor rgb="FFFEF3C7"/></patternFill></fill>
    <fill><patternFill patternType="solid"><fgColor rgb="FFEFF6FF"/></patternFill></fill>
  </fills>
  <borders count="3">
    <border><left/><right/><top/><bottom/><diagonal/></border>
    <border><left style="thin"><color rgb="FFE5E7EB"/></left><right style="thin"><color rgb="FFE5E7EB"/></right><top style="thin"><color rgb="FFE5E7EB"/></top><bottom style="thin"><color rgb="FFE5E7EB"/></bottom><diagonal/></border>
    <border><left style="medium"><color rgb="FF0A6ED1"/></left><right style="medium"><color rgb="FF0A6ED1"/></right><top style="medium"><color rgb="FF0A6ED1"/></top><bottom style="medium"><color rgb="FF0A6ED1"/></bottom><diagonal/></border>
  </borders>
  <cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>
  <cellXfs count="16">
    <xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/>
    <xf numFmtId="0" fontId="1" fillId="2" borderId="0" xfId="0" applyFont="1" applyFill="1"><alignment horizontal="center" vertical="center" wrapText="1"/></xf>
    <xf numFmtId="0" fontId="0" fillId="3" borderId="1" xfId="0" applyBorder="1"><alignment vertical="center"/></xf>
    <xf numFmtId="0" fontId="0" fillId="4" borderId="1" xfId="0" applyFill="1" applyBorder="1"><alignment vertical="center"/></xf>
    <xf numFmtId="0" fontId="2" fillId="5" borderId="1" xfId="0" applyFont="1" applyFill="1" applyBorder="1"><alignment horizontal="center" vertical="center"/></xf>
    <xf numFmtId="0" fontId="3" fillId="6" borderId="1" xfId="0" applyFont="1" applyFill="1" applyBorder="1"><alignment horizontal="center" vertical="center"/></xf>
    <xf numFmtId="0" fontId="4" fillId="7" borderId="1" xfId="0" applyFont="1" applyFill="1" applyBorder="1"><alignment horizontal="center" vertical="center"/></xf>
    <xf numFmtId="0" fontId="0" fillId="3" borderId="1" xfId="0" applyBorder="1"><alignment horizontal="center" vertical="center"/></xf>
    <xf numFmtId="0" fontId="0" fillId="3" borderId="1" xfId="0" applyBorder="1"><alignment horizontal="right" vertical="center"/></xf>
    <xf numFmtId="0" fontId="1" fillId="8" borderId="0" xfId="0" applyFont="1" applyFill="1"><alignment horizontal="left" vertical="center"/></xf>
    <xf numFmtId="0" fontId="0" fillId="10" borderId="1" xfId="0" applyFill="1" applyBorder="1"><alignment vertical="center"/></xf>
    <xf numFmtId="0" fontId="4" fillId="11" borderId="1" xfId="0" applyFont="1" applyFill="1" applyBorder="1"><alignment horizontal="center" vertical="center"/></xf>
    <xf numFmtId="0" fontId="3" fillId="12" borderId="1" xfId="0" applyFont="1" applyFill="1" applyBorder="1"><alignment horizontal="center" vertical="center"/></xf>
    <xf numFmtId="0" fontId="0" fillId="13" borderId="1" xfId="0" applyFill="1" applyBorder="1"><alignment horizontal="center" vertical="center"/></xf>
    <xf numFmtId="0" fontId="2" fillId="3" borderId="1" xfId="0" applyFont="1" applyBorder="1"><alignment vertical="center"/></xf>
    <xf numFmtId="0" fontId="5" fillId="2" borderId="0" xfId="0" applyFont="1" applyFill="1"><alignment horizontal="left" vertical="center"/></xf>
  </cellXfs>
</styleSheet>`;

      const wbXml = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
  <sheets>${sheets.map((s, i) => `<sheet name="${esc(s.name)}" sheetId="${i + 1}" r:id="rId${i + 1}"/>`).join("")}</sheets>
</workbook>`;

      const wbRels = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  ${sheets.map((_, i) => `<Relationship Id="rId${i + 1}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet${i + 1}.xml"/>`).join("\n  ")}
  <Relationship Id="rIdSS" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/sharedStrings" Target="sharedStrings.xml"/>
  <Relationship Id="rIdSt" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>
</Relationships>`;

      const sheetXmls: string[] = [];
      for (const sheet of sheets) {
        const { rows, colWidths } = sheet;
        const colsXml = colWidths
          .map(
            (w, i) =>
              `<col min="${i + 1}" max="${i + 1}" width="${w}" customWidth="1"/>`,
          )
          .join("");
        let rowsXml = "";
        rows.forEach((row, ri) => {
          const isHeader = ri === 0;
          const isEven = ri % 2 === 0;
          let cells = "";
          row.forEach((val, ci) => {
            const ref = cellRef(ri, ci);
            const isNum = typeof val === "number";
            let styleIdx = 2;
            if (isHeader) {
              styleIdx = sheet.headerStyle === "dark" ? 1 : 1;
            } else {
              styleIdx = isEven ? 2 : 3;
            }
            if (isNum) {
              cells += `<c r="${ref}" s="${styleIdx}" t="n"><v>${val}</v></c>`;
            } else {
              const idx = ss(String(val ?? ""));
              cells += `<c r="${ref}" s="${styleIdx}" t="s"><v>${idx}</v></c>`;
            }
          });
          rowsXml += `<row r="${ri + 1}" ht="18" customHeight="1">${cells}</row>`;
        });
        sheetXmls.push(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
  <sheetViews><sheetView workbookViewId="0"><pane ySplit="1" topLeftCell="A2" activePane="bottomLeft" state="frozen"/></sheetView></sheetViews>
  <cols>${colsXml}</cols>
  <sheetData>${rowsXml}</sheetData>
</worksheet>`);
      }

      const ssXml = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" count="${sharedStrings.length}" uniqueCount="${sharedStrings.length}">
${sharedStrings.map((s) => `<si><t xml:space="preserve">${esc(s)}</t></si>`).join("\n")}
</sst>`;

      const ct = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>
  ${sheets.map((_, i) => `<Override PartName="/xl/worksheets/sheet${i + 1}.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>`).join("\n  ")}
  <Override PartName="/xl/sharedStrings.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sharedStrings+xml"/>
  <Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>
</Types>`;

      zip.file("[Content_Types].xml", ct);
      zip.file(
        "_rels/.rels",
        `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>`,
      );
      zip.file("xl/workbook.xml", wbXml);
      zip.file("xl/_rels/workbook.xml.rels", wbRels);
      zip.file("xl/styles.xml", STYLES);
      zip.file("xl/sharedStrings.xml", ssXml);
      sheets.forEach((_, i) =>
        zip.file(`xl/worksheets/sheet${i + 1}.xml`, sheetXmls[i]),
      );

      const blob = await zip.generateAsync({
        type: "blob",
        mimeType:
          "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
      });
      return blob;
    },
    [],
  );

  const exportRunsExcel = useCallback(async () => {
    const date = new Date().toISOString().split("T")[0];
    const summaryRows: any[][] = [
      ["ATC Run Explorer — Summary Report", ""],
      ["Generated", new Date().toLocaleString("en-GB")],
      ["Total Runs", filteredRuns.length],
      ["Total P1 Findings", filteredRuns.reduce((a, r) => a + r.p1, 0)],
      ["Total P2 Findings", filteredRuns.reduce((a, r) => a + r.p2, 0)],
      [
        "High Risk Runs (P1 > 20)",
        filteredRuns.filter((r) => r.p1 > 20).length,
      ],
      ["Overall Health Score", `${healthScore}%`],
      [
        "Systems",
        [...new Set(filteredRuns.map((r) => r.system).filter(Boolean))].join(
          ", ",
        ),
      ],
    ];
    const dataHeaders = [
      "Run Series",
      "Check Run Title",
      "Scheduled By",
      "Run Date",
      "Source",
      "P1 Critical",
      "P2 Warning",
      "P3 Info",
      "P4 Note",
      "Total Findings",
      "Quality Score",
      "Central Run",
    ];
    const dataRows = filteredRuns.map((r) => {
      const p4 = r.p4 ?? 0;
      return [
        r.series ?? "",
        r.title ?? "",
        r.user ?? "",
        r.date ?? "",
        r.RunKind === "C"
          ? "Code Inspector"
          : r.RunKind === "M"
            ? "Checkman"
            : "",
        r.p1,
        r.p2,
        r.p3,
        p4,
        r.p1 + r.p2 + r.p3 + p4,
        computeScore(r.p1, r.p2, r.p3, p4),
        r.central ? "Yes" : "No",
      ];
    });
    const blob = await buildXlsx([
      {
        name: "Summary",
        rows: summaryRows,
        colWidths: [32, 42],
        headerStyle: "dark",
      },
      {
        name: "Run Data",
        rows: [dataHeaders, ...dataRows],
        colWidths: [28, 34, 18, 14, 16, 12, 12, 10, 10, 16, 14, 14],
      },
    ]);
    if (!blob) return;
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `ATC-Runs-${date}.xlsx`;
    a.click();
    URL.revokeObjectURL(url);
  }, [filteredRuns, healthScore, buildXlsx]);

  const exportAssignmentsExcel = useCallback(async () => {
    const date = new Date().toISOString().split("T")[0];
    const assigned = checkRegistry.filter((c) => assignments[c.key]).length;
    const summaryRows: any[][] = [
      ["ATC Check Assignment Report", ""],
      ["Generated", new Date().toLocaleString("en-GB")],
      ["Run", selectedRun?.title || selectedRun?.series || "—"],
      ["System", selectedRun?.system || "—"],
      ["Run Date", selectedRun?.date || "—"],
      ["Total Check Types", checkRegistry.length],
      ["Assigned", assigned],
      ["Unassigned", checkRegistry.length - assigned],
      ["Assignment Coverage", `${assignmentCoverage}%`],
      [
        "Unassigned P1 Findings",
        checkRegistry
          .filter((c) => !assignments[c.key] && c.p1 > 0)
          .reduce((a, c) => a + c.p1, 0),
      ],
      ["Total Developers", developerWorkload.length],
    ];
    const assignHeaders = [
      "Check Category",
      "Assigned Developer",
      "P1 Critical",
      "P2 Warning",
      "P3 Info",
      "P4 Note",
      "Total Findings",
      "Affected Objects",
      "Assignment Status",
    ];
    const assignRows = checkRegistry.map((c) => [
      c.key,
      assignments[c.key] || "",
      c.p1,
      c.p2,
      c.p3,
      c.p4,
      c.total,
      c.objectCount,
      assignments[c.key] ? "Assigned" : "Unassigned",
    ]);
    const devHeaders = [
      "Developer",
      "Assigned Check Types",
      "Total Findings",
      "P1 Critical",
      "P2 Warning",
      "Affected Objects",
      "Oldest Finding (days)",
      "Priority Score",
    ];
    const devRows = developerWorkload.map((dw) => [
      dw.dev,
      dw.assignedChecks.length,
      dw.totalFindings,
      dw.p1,
      dw.p2,
      dw.objectCount,
      dw.oldestAge > 0 ? dw.oldestAge : 0,
      Math.round(dw.priorityScore),
    ]);
    const blob = await buildXlsx([
      {
        name: "Summary",
        rows: summaryRows,
        colWidths: [28, 36],
        headerStyle: "dark",
      },
      {
        name: "Check Assignments",
        rows: [assignHeaders, ...assignRows],
        colWidths: [36, 22, 12, 12, 10, 10, 16, 18, 18],
      },
      {
        name: "Developer Workload",
        rows: [devHeaders, ...devRows],
        colWidths: [22, 22, 18, 14, 14, 18, 22, 16],
      },
    ]);
    if (!blob) return;
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `ATC-Assignments-${date}.xlsx`;
    a.click();
    URL.revokeObjectURL(url);
  }, [
    checkRegistry,
    assignments,
    developerWorkload,
    selectedRun,
    assignmentCoverage,
    buildXlsx,
  ]);

  // ── Code Quality PDF Generator ──────────────────────────────────────────────

  const generateCodeQualityPdf = useCallback(() => {
    if (!selectedRun || findings.length === 0) return;
    const now = new Date();
    const ds = now.toLocaleDateString("en-GB", {
      day: "2-digit",
      month: "long",
      year: "numeric",
    });
    const ts = now.toLocaleTimeString("en-GB", {
      hour: "2-digit",
      minute: "2-digit",
    });
    const rl = selectedRun.title || selectedRun.series || selectedRun.ID;
    const rk =
      selectedRun.RunKind === "C"
        ? "Code Inspector"
        : selectedRun.RunKind === "M"
          ? "Checkman"
          : "ATC";
    const total =
      selectedRun.p1 + selectedRun.p2 + selectedRun.p3 + (selectedRun.p4 ?? 0);
    const qs = qualityScore ?? 0;
    const qColor = qs >= 70 ? "#15803d" : qs >= 50 ? "#d97706" : "#dc2626";
    const qBg = qs >= 70 ? "#f0fdf4" : qs >= 50 ? "#fffbeb" : "#fef2f2";
    const dir =
      qualityDelta === null
        ? null
        : qualityDelta > 0
          ? "improving"
          : qualityDelta < 0
            ? "deteriorating"
            : "stable";
    const verdict = `This run has ${total.toLocaleString()} findings${qualityDelta !== null ? ` and quality is ${dir} by ${Math.abs(qualityDelta)} points versus the previous run in this series` : ""}.${selectedRun.p1 > 0 ? ` ${selectedRun.p1} P1 critical findings require immediate attention.` : " No P1 critical findings — P1 gate is clear."}${slaIntelligence.over90 > 0 ? ` ${slaIntelligence.over90} findings have been open for more than 90 days.` : ""}`;
    const sb = (p: number, v: number) =>
      v === 0
        ? `<span style="color:#9ca3af">0</span>`
        : `<span style="color:${p === 1 ? "#dc2626" : p === 2 ? "#d97706" : p === 3 ? "#2563eb" : "#6b7280"};font-weight:700">${v}</span>`;

    const html = `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"/>
<title>ATC Code Quality Report — ${rl}</title>
<style>
*{margin:0;padding:0;box-sizing:border-box;}
body{font-family:Arial,sans-serif;font-size:10pt;color:#1a1a2e;background:#fff;line-height:1.6;}
.pb{page-break-before:always;break-before:page;}.nb{page-break-inside:avoid;}
table{width:100%;border-collapse:collapse;margin-bottom:20px;font-size:9pt;}
thead tr{background:#0a6ed1;}thead th{color:white;padding:8px 10px;text-align:left;font-size:7.5pt;font-weight:700;text-transform:uppercase;}
tbody tr:nth-child(even){background:#f8fafc;}tbody td{padding:7px 10px;border-bottom:1px solid #f1f5f9;vertical-align:top;}
.section-title{font-size:16pt;font-weight:800;color:#0f172a;margin-bottom:6px;}
.section-header{margin-bottom:18px;padding-bottom:10px;border-bottom:2px solid #f3f4f6;}
.kpi-grid{display:grid;grid-template-columns:repeat(6,1fr);gap:10px;margin-bottom:20px;}
.kpi-box{border-radius:8px;padding:14px 10px;border:1px solid #e5e7eb;text-align:center;}
.kpi-label{font-size:7.5pt;font-weight:700;color:#6b7280;text-transform:uppercase;margin-bottom:4px;}
.kpi-value{font-size:20pt;font-weight:800;line-height:1;}
.badge-ok{background:#dcfce7;color:#15803d;border-radius:4px;padding:2px 7px;font-weight:700;font-size:8pt;}
.badge-risk{background:#fee2e2;color:#dc2626;border-radius:4px;padding:2px 7px;font-weight:700;font-size:8pt;}
@media print{body{-webkit-print-color-adjust:exact;print-color-adjust:exact;}@page{margin:18mm;size:A4;}}
</style></head><body>

<div style="padding-bottom:24px;border-bottom:3px solid #0a6ed1;margin-bottom:24px;">
  <div style="font-size:20pt;font-weight:800;color:#0a6ed1;margin-bottom:4px;">SAP Fioneer · ATC Code Quality Report</div>
  <div style="font-size:11pt;color:#374151;margin-top:4px;">Run: ${rl} · System: ${selectedRun.system || "—"} · Date: ${selectedRun.date || "—"} · ${rk}</div>
  <div style="margin-top:12px;display:inline-flex;align-items:center;gap:14px;padding:10px 20px;border-radius:8px;background:${qBg};border:2px solid ${qColor};">
    <span style="font-size:13pt;font-weight:700;color:${qColor};">Quality Score: ${qs}/100</span>
    ${qualityDelta !== null ? `<span style="font-size:11pt;color:${qualityDelta >= 0 ? "#15803d" : "#dc2626"};font-weight:700;">${qualityDelta >= 0 ? "+" : ""}${qualityDelta} pts vs previous run</span>` : ""}
  </div>
</div>

<div class="kpi-grid">
  <div class="kpi-box" style="background:#fef2f2;"><div class="kpi-label" style="color:#dc2626;">P1 Critical</div><div class="kpi-value" style="color:#dc2626;">${selectedRun.p1}</div></div>
  <div class="kpi-box" style="background:#fffbeb;"><div class="kpi-label" style="color:#d97706;">P2 Warning</div><div class="kpi-value" style="color:#d97706;">${selectedRun.p2}</div></div>
  <div class="kpi-box" style="background:#eff6ff;"><div class="kpi-label" style="color:#2563eb;">P3 Info</div><div class="kpi-value" style="color:#2563eb;">${selectedRun.p3}</div></div>
  <div class="kpi-box" style="background:#f9fafb;"><div class="kpi-label" style="color:#6b7280;">P4 Note</div><div class="kpi-value" style="color:#6b7280;">${selectedRun.p4 ?? 0}</div></div>
  <div class="kpi-box" style="background:#f3f4f6;"><div class="kpi-label">Total</div><div class="kpi-value">${total.toLocaleString()}</div></div>
  <div class="kpi-box" style="background:${qBg};"><div class="kpi-label" style="color:${qColor};">Q-Score</div><div class="kpi-value" style="color:${qColor};">${qs}</div></div>
</div>

<div style="padding:14px 16px;background:#f8fafc;border:1px solid #e5e7eb;border-radius:8px;margin-bottom:20px;font-size:12pt;line-height:1.7;color:#374151;">${verdict}</div>

<div class="pb" style="padding-top:28px;">
  <div class="section-header"><div class="section-title">1. Finding Breakdown by Check Category</div><div style="font-size:10pt;color:#6b7280;">${findings.length.toLocaleString()} findings · ${findingsByCategory.length} check categories</div></div>
  <table><thead><tr><th>Check Category</th><th>P1</th><th>P2</th><th>P3</th><th>P4</th><th>Total</th><th>Share</th></tr></thead>
  <tbody>${findingsByCategory.map((row) => `<tr class="nb"><td style="font-weight:600;color:#111827;">${row.cat}</td><td>${sb(1, row.p1)}</td><td>${sb(2, row.p2)}</td><td>${sb(3, row.p3)}</td><td>${sb(4, row.p4)}</td><td style="font-weight:700;">${row.total}</td><td style="color:#6b7280;font-size:8.5pt;">${((row.total / findings.length) * 100).toFixed(1)}%</td></tr>`).join("")}</tbody>
  </table>
</div>

<div class="pb" style="padding-top:28px;">
  <div class="section-header"><div class="section-title">2. Object Risk Table</div><div style="font-size:10pt;color:#6b7280;">Top 20 objects sorted by P1 finding count</div></div>
  <table><thead><tr><th>Object</th><th>Type</th><th>Package</th><th>P1</th><th>P2</th><th>P3</th><th>Total</th><th>Oldest (d)</th><th>Developer</th></tr></thead>
  <tbody>${objectRiskTable
    .slice(0, 20)
    .map(
      (obj) =>
        `<tr class="nb"><td style="font-family:monospace;font-weight:600;font-size:9pt;word-break:break-all;">${obj.name}</td><td style="font-size:8.5pt;color:#6b7280;">${OBJECT_TYPE_LABELS[obj.objType] || obj.objType || "—"}</td><td style="font-size:8.5pt;color:#6b7280;">${obj.pkg}</td><td>${sb(1, obj.p1)}</td><td>${sb(2, obj.p2)}</td><td>${sb(3, obj.p3)}</td><td style="font-weight:700;">${obj.total}</td><td style="color:${obj.oldestAge > 90 ? "#dc2626" : obj.oldestAge > 30 ? "#d97706" : "#374151"};font-weight:${obj.oldestAge > 30 ? 700 : 400};">${obj.oldestAge > 0 ? obj.oldestAge : "—"}</td><td style="font-family:monospace;font-size:8.5pt;">${obj.dev}</td></tr>`,
    )
    .join("")}</tbody>
  </table>
</div>

<div class="pb" style="padding-top:28px;">
  <div class="section-header"><div class="section-title">3. Developer Accountability</div><div style="font-size:10pt;color:#6b7280;">${devAccountability.length} developers · finding ownership from selected run</div></div>
  <table><thead><tr><th>Developer</th><th>P1</th><th>P2</th><th>P3</th><th>P4</th><th>Total</th><th>Packages</th><th>Oldest (d)</th><th>Status</th></tr></thead>
  <tbody>${devAccountability.map((d) => `<tr class="nb"><td style="font-family:monospace;font-weight:700;">${d.dev}</td><td>${sb(1, d.p1)}</td><td>${sb(2, d.p2)}</td><td>${sb(3, d.p3)}</td><td>${sb(4, d.p4)}</td><td style="font-weight:700;">${d.total}</td><td style="color:#6b7280;">${d.pkgCount}</td><td style="color:${d.oldestAge > 90 ? "#dc2626" : d.oldestAge > 30 ? "#d97706" : "#374151"};font-weight:${d.oldestAge > 30 ? 700 : 400};">${d.oldestAge > 0 ? d.oldestAge : "—"}</td><td><span class="${d.p1 + d.p2 > 0 ? "badge-risk" : "badge-ok"}">${d.p1 + d.p2 > 0 ? "Action Required" : "No Blockers"}</span></td></tr>`).join("")}</tbody>
  </table>
</div>

<div class="pb" style="padding-top:28px;">
  <div class="section-header"><div class="section-title">4. SLA Intelligence</div></div>
  <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:20px;">
    ${[
      {
        label: "P1 Critical",
        target: "SLA: 1 day",
        p: 1,
        color: "#dc2626",
        bg: "#fee2e2",
      },
      {
        label: "P2 Warning",
        target: "SLA: 3 days",
        p: 2,
        color: "#d97706",
        bg: "#fef3c7",
      },
      {
        label: "P3 Info",
        target: "SLA: 14 days",
        p: 3,
        color: "#2563eb",
        bg: "#dbeafe",
      },
      {
        label: "P4 Note",
        target: "SLA: 30 days",
        p: 4,
        color: "#6b7280",
        bg: "#f3f4f6",
      },
    ]
      .map(
        (item) =>
          `<div style="background:${item.bg};border-radius:8px;padding:14px;text-align:center;border:1px solid #e5e7eb;"><div style="font-size:7.5pt;font-weight:700;color:#6b7280;text-transform:uppercase;margin-bottom:4px;">${item.label}</div><div style="font-size:22pt;font-weight:800;color:${item.color};line-height:1;">${slaIntelligence.buckets[item.p].overdue}</div><div style="font-size:8pt;color:#9ca3af;margin-top:2px;">overdue of ${slaIntelligence.buckets[item.p].total}</div><div style="font-size:8pt;color:${item.color};margin-top:4px;">${item.target}</div></div>`,
      )
      .join("")}
  </div>
  ${slaIntelligence.over90 > 0 ? `<div style="padding:12px 16px;background:#fef2f2;border-left:4px solid #ef4444;border-radius:8px;font-size:12pt;color:#374151;line-height:1.7;"><strong style="color:#dc2626;">${slaIntelligence.over90} findings</strong> have been open for more than 90 days — immediate escalation required.${slaIntelligence.over30 > 0 ? ` A further <strong>${slaIntelligence.over30 - slaIntelligence.over90}</strong> findings have exceeded 30 days.` : ""}</div>` : `<div style="padding:12px 16px;background:#f0fdf4;border-left:4px solid #22c55e;border-radius:8px;font-size:12pt;color:#374151;">All findings are within SLA thresholds. No overdue items detected.</div>`}
</div>

<div style="margin-top:20px;font-size:8pt;color:#9ca3af;border-top:1px solid #e5e7eb;padding-top:8px;">Generated by ATC Run Monitor · ${ds} ${ts} · CONFIDENTIAL</div>
</body></html>`;

    const w = window.open("", "_blank", "width=1200,height=900");
    if (!w) {
      alert("Allow popups to generate PDF report.");
      return;
    }
    w.document.write(html);
    w.document.close();
    w.onload = () => setTimeout(() => w.print(), 800);
  }, [
    selectedRun,
    findings,
    findingsByCategory,
    objectRiskTable,
    devAccountability,
    slaIntelligence,
    qualityScore,
    qualityDelta,
  ]);

  // ── Security PDF Generator ──────────────────────────────────────────────────
  const generateSecurityPdf = useCallback(() => {
    if (!selectedRun || securityFindings.length === 0) return;
    const now = new Date();
    const ds = now.toLocaleDateString("en-GB", {
      day: "2-digit",
      month: "long",
      year: "numeric",
    });
    const ts = now.toLocaleTimeString("en-GB", {
      hour: "2-digit",
      minute: "2-digit",
    });
    const rl = selectedRun.title || selectedRun.series || selectedRun.ID;
    const rk =
      selectedRun.RunKind === "C"
        ? "Code Inspector"
        : selectedRun.RunKind === "M"
          ? "Checkman"
          : "ATC";
    const ab = { a: 0, b: 0, c: 0, d: 0 };
    securityFindings.forEach((f) => {
      const d = parseSince(f.Since);
      if (!d) return;
      const a = ageDays(d);
      if (a <= 7) ab.a++;
      else if (a <= 30) ab.b++;
      else if (a <= 90) ab.c++;
      else ab.d++;
    });
    const dm: Record<string, any> = {};
    securityFindings.forEach((f) => {
      const dev = f.ContactPerson || f.Processor || "UNKNOWN";
      if (!dm[dev])
        dm[dev] = {
          p1: 0,
          p2: 0,
          p3: 0,
          p4: 0,
          count: 0,
          oldest: 0,
          packages: new Set(),
        };
      dm[dev].count++;
      if (f.Priority === 1) dm[dev].p1++;
      else if (f.Priority === 2) dm[dev].p2++;
      else if (f.Priority === 3) dm[dev].p3++;
      else if (f.Priority === 4) dm[dev].p4++;
      if (f.PackageName) dm[dev].packages.add(f.PackageName);
      const d = parseSince(f.Since);
      if (d) {
        const a = ageDays(d);
        if (a > dm[dev].oldest) dm[dev].oldest = a;
      }
    });
    const devRows = Object.entries(dm).sort(
      (a, b) => b[1].p1 - a[1].p1 || b[1].count - a[1].count,
    );
    const cm: Record<string, any> = {};
    securityFindings.forEach((f) => {
      const ci = resolveCiId(f) || f.CheckCategory || "UNKNOWN";
      const t = (f.RstismTitle || "").trim() || resolveCheckCategory(f);
      if (!cm[t]) cm[t] = { p1: 0, p2: 0, p3: 0, p4: 0, count: 0 };
      cm[t].count++;
      if (f.Priority === 1) cm[t].p1++;
      else if (f.Priority === 2) cm[t].p2++;
      else if (f.Priority === 3) cm[t].p3++;
      else if (f.Priority === 4) cm[t].p4++;
    });
    const checkRows = Object.entries(cm).sort(
      (a, b) => b[1].p1 - a[1].p1 || b[1].count - a[1].count,
    );
    const appendix = [...securityFindings].sort(
      (a, b) =>
        a.Priority - b.Priority ||
        (a.ObjectName || "").localeCompare(b.ObjectName || ""),
    );
    const sb = (p: number, v: number) =>
      v === 0
        ? `<span style="color:#9ca3af">0</span>`
        : `<span style="color:${p === 1 ? "#dc2626" : p === 2 ? "#d97706" : p === 3 ? "#2563eb" : "#6b7280"};font-weight:700">${v}</span>`;
    const cc = isCertificationReady ? "#15803d" : "#dc2626";
    const cbg = isCertificationReady ? "#f0fdf4" : "#fef2f2";
    const cbo = isCertificationReady ? "#22c55e" : "#ef4444";
    const html = `<!DOCTYPE html><html><head><meta charset="UTF-8"/><title>ATC Security — ${rl}</title><style>*{margin:0;padding:0;box-sizing:border-box;}body{font-family:Arial,sans-serif;font-size:10pt;color:#1a1a2e;background:#fff;line-height:1.6;}.pb{page-break-before:always;}.nb{page-break-inside:avoid;}table{width:100%;border-collapse:collapse;margin-bottom:20px;font-size:9pt;}thead tr{background:#0070f3;}thead th{color:white;padding:8px 10px;text-align:left;font-size:7.5pt;font-weight:700;text-transform:uppercase;}tbody tr:nth-child(even){background:#f8fafc;}tbody td{padding:7px 10px;border-bottom:1px solid #f1f5f9;vertical-align:top;}.badge-p1{background:#fee2e2;color:#dc2626;border-radius:4px;padding:1px 6px;font-weight:700;font-size:8pt;}.badge-p2{background:#fef3c7;color:#d97706;border-radius:4px;padding:1px 6px;font-weight:700;font-size:8pt;}.badge-ok{background:#dcfce7;color:#15803d;border-radius:4px;padding:2px 7px;font-weight:700;font-size:8pt;}.badge-risk{background:#fee2e2;color:#dc2626;border-radius:4px;padding:2px 7px;font-weight:700;font-size:8pt;}@media print{body{-webkit-print-color-adjust:exact;print-color-adjust:exact;}@page{margin:18mm;size:A4;}}</style></head><body>
<div style="padding-bottom:24px;border-bottom:3px solid #0070f3;margin-bottom:24px;"><div style="font-size:20pt;font-weight:800;color:#0070f3;">SAP Fioneer · ATC Security Report</div><div style="font-size:11pt;color:#374151;margin-top:4px;">Run: ${rl} · System: ${selectedRun.system || "—"} · Date: ${selectedRun.date || "—"} · ${rk}</div><div style="margin-top:10px;display:inline-block;padding:7px 16px;border-radius:6px;font-weight:800;background:${cbg};color:${cc};border:2px solid ${cbo};">${isCertificationReady ? "✅ CERTIFICATION READY" : "❌ NOT READY FOR CERTIFICATION"}</div></div>
<div style="display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-bottom:20px;"><div style="background:#fef2f2;border-radius:8px;padding:12px;text-align:center;"><div style="font-size:7pt;color:#dc2626;font-weight:700;text-transform:uppercase;">P1 Critical</div><div style="font-size:22pt;font-weight:800;color:#dc2626;">${secP1}</div></div><div style="background:#fffbeb;border-radius:8px;padding:12px;text-align:center;"><div style="font-size:7pt;color:#d97706;font-weight:700;text-transform:uppercase;">P2 Warning</div><div style="font-size:22pt;font-weight:800;color:#d97706;">${secP2}</div></div><div style="background:#eff6ff;border-radius:8px;padding:12px;text-align:center;"><div style="font-size:7pt;color:#2563eb;font-weight:700;text-transform:uppercase;">P3 Info</div><div style="font-size:22pt;font-weight:800;color:#2563eb;">${secP3}</div></div><div style="background:#f9fafb;border-radius:8px;padding:12px;text-align:center;"><div style="font-size:7pt;color:#374151;font-weight:700;text-transform:uppercase;">Total</div><div style="font-size:22pt;font-weight:800;color:#374151;">${securityFindings.length}</div></div></div>
<div class="pb" style="padding-top:28px;"><div style="font-size:16pt;font-weight:800;margin-bottom:16px;">Security Risk Category Breakdown</div><table><thead><tr><th>Risk Category</th><th>P1</th><th>P2</th><th>P3</th><th>Total</th><th>Share</th></tr></thead><tbody>${checkRows.map(([t, v]) => `<tr class="nb"><td style="font-weight:600;">${t}</td><td>${sb(1, v.p1)}</td><td>${sb(2, v.p2)}</td><td>${sb(3, v.p3)}</td><td style="font-weight:700;">${v.count}</td><td style="color:#6b7280;font-size:8.5pt;">${securityFindings.length > 0 ? ((v.count / securityFindings.length) * 100).toFixed(1) + "%" : "—"}</td></tr>`).join("")}</tbody></table></div>
<div class="pb" style="padding-top:28px;"><div style="font-size:16pt;font-weight:800;margin-bottom:16px;">Developer Accountability</div><table><thead><tr><th>Developer</th><th>P1</th><th>P2</th><th>P3</th><th>Total</th><th>Oldest (d)</th><th>Status</th></tr></thead><tbody>${devRows.map(([d, v]) => `<tr class="nb"><td style="font-family:monospace;font-weight:700;">${d}</td><td>${sb(1, v.p1)}</td><td>${sb(2, v.p2)}</td><td>${sb(3, v.p3)}</td><td style="font-weight:700;">${v.count}</td><td style="color:${v.oldest > 90 ? "#dc2626" : v.oldest > 30 ? "#d97706" : "#374151"};font-weight:${v.oldest > 30 ? 700 : 400};">${v.oldest > 0 ? v.oldest : "—"}</td><td><span class="${v.p1 + v.p2 > 0 ? "badge-risk" : "badge-ok"}">${v.p1 + v.p2 > 0 ? "Action Required" : "No Blockers"}</span></td></tr>`).join("")}</tbody></table></div>
<div class="pb" style="padding-top:28px;"><div style="font-size:16pt;font-weight:800;margin-bottom:16px;">All Security Findings</div><table><thead><tr><th>#</th><th>Object</th><th>Type</th><th>Risk Category</th><th>Package</th><th>P</th><th>Developer</th><th>Age (d)</th><th>Status</th></tr></thead><tbody>${appendix
      .map((f, idx) => {
        const d = parseSince(f.Since);
        const a = d ? ageDays(d) : null;
        const t = resolveCheckCategory(f) || "—";
        const ci = resolveCiId(f) || "";
        const kn = getSecurityKnowledge(ci);
        const mod = checkModules.find(
          (m: any) =>
            m.ModuleId.toLowerCase() === (f.CheckCategory || "").toLowerCase(),
        );
        const riskName =
          kn?.riskName ||
          mod?.ModuleTitle?.trim() ||
          f.RstismTitle?.trim() ||
          t;
        const statusText =
          f.StatusNew === "1"
            ? "Open"
            : f.StatusNew === "2"
              ? "In Progress"
              : f.StatusNew === "3"
                ? "Resolved"
                : "—";
        return `<tr class="nb"><td style="color:#9ca3af;font-size:8pt;">${idx + 1}</td><td style="font-family:monospace;font-weight:600;font-size:9pt;word-break:break-all;">${f.ObjectName || "—"}</td><td style="font-size:8pt;color:#6b7280;">${OBJECT_TYPE_LABELS[f.ObjectType] || f.ObjectType || "—"}</td><td style="font-size:8.5pt;">${riskName}</td><td style="font-size:8pt;color:#6b7280;">${f.PackageName || "—"}</td><td><span class="badge-p${f.Priority}">P${f.Priority}</span></td><td style="font-family:monospace;font-size:8pt;">${f.ContactPerson || f.Processor || "—"}</td><td style="font-size:8pt;color:${a && a > 30 ? "#dc2626" : "#374151"};font-weight:${a && a > 30 ? 700 : 400};">${a !== null ? a : "—"}</td><td style="font-size:8pt;color:${f.StatusNew === "1" ? "#dc2626" : f.StatusNew === "2" ? "#d97706" : "#16a34a"}">${statusText}</td></tr>`;
      })
      .join("")}</tbody></table></div>
<div style="margin-top:20px;font-size:8pt;color:#9ca3af;border-top:1px solid #e5e7eb;padding-top:8px;">Generated by ATC Run Monitor · ${ds} ${ts} · CONFIDENTIAL</div>
</body></html>`;
    const w = window.open("", "_blank", "width=1200,height=900");
    if (!w) {
      alert("Allow popups.");
      return;
    }
    w.document.write(html);
    w.document.close();
    w.onload = () => setTimeout(() => w.print(), 800);
  }, [
    selectedRun,
    securityFindings,
    secP1,
    secP2,
    secP3,
    secP4,
    isCertificationReady,
    resolveCiId,
    resolveCheckCategory,
    checkModules,
    getSecurityKnowledge,
  ]);

  const runAiSecurityAnalysis = useCallback(async () => {
    if (securityFindings.length === 0) return;
    setAiSecLoading(true);
    setAiSecError("");
    setAiSecReport("");
    const byDev: Record<string, any> = {};
    const byPkg: Record<string, any> = {};
    const byCheck: Record<string, any> = {};
    const ageBD = { fresh: 0, moderate: 0, old: 0, critical: 0 };
    const oldDev: Record<string, number> = {};
    securityFindings.forEach((f) => {
      const dev = f.ContactPerson || f.Processor || "UNKNOWN";
      const pkg = f.PackageName || "UNKNOWN";
      const ci = resolveCiId(f) || f.CheckCategory || "UNKNOWN";
      if (!byDev[dev])
        byDev[dev] = { p1: 0, p2: 0, count: 0, packages: new Set() };
      byDev[dev].count++;
      byDev[dev].packages.add(pkg);
      if (f.Priority === 1) byDev[dev].p1++;
      if (f.Priority === 2) byDev[dev].p2++;
      if (!byPkg[pkg]) byPkg[pkg] = { p1: 0, p2: 0, count: 0 };
      byPkg[pkg].count++;
      if (f.Priority === 1) byPkg[pkg].p1++;
      if (f.Priority === 2) byPkg[pkg].p2++;
      if (!byCheck[ci]) byCheck[ci] = { p1: 0, p2: 0, count: 0, ciId: ci };
      byCheck[ci].count++;
      if (f.Priority === 1) byCheck[ci].p1++;
      if (f.Priority === 2) byCheck[ci].p2++;
      const d = parseSince(f.Since);
      if (d) {
        const a = ageDays(d);
        if (a <= 7) ageBD.fresh++;
        else if (a <= 30) ageBD.moderate++;
        else if (a <= 90) ageBD.old++;
        else ageBD.critical++;
        if (!oldDev[dev] || a > oldDev[dev]) oldDev[dev] = a;
      }
    });
    const topDevs = Object.entries(byDev)
      .sort((a, b) => b[1].p1 - a[1].p1 || b[1].count - a[1].count)
      .slice(0, 8)
      .map(
        ([d, v]) =>
          `${d}: ${v.p1} P1, ${v.p2} P2, ${v.count} total, oldest: ${oldDev[d] || 0}d`,
      );
    const topPkgs = Object.entries(byPkg)
      .sort((a, b) => b[1].p1 - a[1].p1 || b[1].count - a[1].count)
      .slice(0, 8)
      .map(([p, v]) => `${p}: ${v.p1} P1, ${v.p2} P2, ${v.count} total`);
    const checkBD = Object.entries(byCheck)
      .sort((a, b) => b[1].p1 - a[1].p1 || b[1].count - a[1].count)
      .map(([, v]) => `${v.ciId}: ${v.p1} P1, ${v.p2} P2, ${v.count} total`);
    const rl = selectedRun
      ? `${selectedRun.title || selectedRun.series || selectedRun.ID} (${selectedRun.date || "unknown"})`
      : "current run";
    const prompt = `You are an enterprise SAP ABAP security architect.\n\nRun: ${rl}\nSystem: ${selectedRun?.system || "unknown"}\nFindings: total=${securityFindings.length}, P1=${secP1}, P2=${secP2}, P3=${secP3}, cert=${isCertificationReady ? "READY" : "NOT READY - " + certificationBlocking + " blocking"}\nAGE: 0-7d=${ageBD.fresh}, 8-30d=${ageBD.moderate}, 31-90d=${ageBD.old}, 90+d=${ageBD.critical}\nCHECKS:\n${checkBD.join("\n")}\nPACKAGES:\n${topPkgs.join("\n")}\nDEVELOPERS:\n${topDevs.join("\n")}\n\nProvide:\n## Executive Risk Summary\n## Critical Vulnerabilities\n## Remediation Priority Order\n## Developer Action Plan\n## Certification Timeline\n\nBe specific, use actual data.`;
    try {
      const r = await fetch("https://api.anthropic.com/v1/messages", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          model: "claude-sonnet-4-20250514",
          max_tokens: 1000,
          messages: [{ role: "user", content: prompt }],
        }),
      });
      if (!r.ok) {
        const e = await r.json().catch(() => ({}));
        throw new Error((e as any)?.error?.message || `API error ${r.status}`);
      }
      const data = await r.json();
      setAiSecReport(
        (data.content || [])
          .filter((b: any) => b.type === "text")
          .map((b: any) => b.text)
          .join(""),
      );
      setAiSecRunId(selectedRun?.ID || "");
    } catch (e: any) {
      setAiSecError(e?.message || "AI analysis failed.");
    } finally {
      setAiSecLoading(false);
    }
  }, [
    securityFindings,
    secP1,
    secP2,
    secP3,
    certificationBlocking,
    isCertificationReady,
    checkModules,
    selectedRun,
    resolveCiId,
  ]);

  useEffect(() => {
    if (selectedRun?.ID && selectedRun.ID !== aiSecRunId) {
      setAiSecReport("");
      setAiSecError("");
    }
  }, [selectedRun?.ID, aiSecRunId]);

  const generateAiAnalysis = (
    msg: string | undefined,
    view: "manager" | "developer",
    snap: {
      runs: Run[];
      p1: number;
      p2: number;
      p3: number;
      score: number;
      period: number;
      system: string;
      totalRuns: number;
    },
  ): string => {
    const sysMap: Record<string, number> = {};
    snap.runs.forEach((r) => {
      const s = r.system || "Unknown";
      sysMap[s] = (sysMap[s] || 0) + r.p1;
    });
    const topSys = Object.entries(sysMap).sort((a, b) => b[1] - a[1])[0];
    const prdP1 = snap.runs
      .filter((r) => (r.system || "").includes("PRD"))
      .reduce((a, r) => a + (r.p1 || 0), 0);
    const rk =
      snap.p1 > 500
        ? "CRITICAL"
        : snap.p1 > 200
          ? "HIGH"
          : snap.p1 > 50
            ? "MEDIUM"
            : "LOW";
    const rc =
      rk === "CRITICAL"
        ? "🔴"
        : rk === "HIGH"
          ? "🟠"
          : rk === "MEDIUM"
            ? "🟡"
            : "🟢";
    if (msg) {
      const q = msg.toLowerCase();
      if (q.includes("system") && q.includes("risk"))
        return topSys
          ? `The highest risk system is **${topSys[0]}** with ${topSys[1]} P1 findings.`
          : "No system data available.";
      if (q.includes("fix") || q.includes("release"))
        return `## Pre-Release Checklist\n\n1. **Resolve all P1 findings** — ${snap.p1} critical findings.\n2. **Fix P2 findings** — ${snap.p2} warnings.\n3. Run full ATC before transport.\n\nEstimated effort: ${Math.ceil(snap.p1 / 10)} developer days.`;
      return `Based on ${snap.totalRuns} runs, ${snap.p1} P1. Ask about system risk or pre-release fixes.`;
    }
    if (view === "manager")
      return `## Executive Summary\n\nRisk: ${rc} **${rk}**. ${snap.totalRuns} ATC runs, ${snap.p1} P1 in last ${snap.period} days.\n\n${prdP1 > 0 ? `⚠️ **${prdP1} P1 in production.**` : "✅ Production clear."}\n\n## Key Findings\n\n- Highest risk system: **${topSys?.[0] || "N/A"}**\n- P1: **${snap.p1}** · P2: **${snap.p2}** · P3: **${snap.p3}**`;
    return `## Summary\n\n${snap.totalRuns} runs · P1/${snap.p1} P2/${snap.p2} P3/${snap.p3} · Health: ${snap.score}%\n\n## Recommendations\n\n1. Fix LOOP+SELECT patterns first\n2. Review all dynamic SQL\n3. Add ATC to CI/CD pipeline`;
  };
  const runAiAnalysis = (userMsg?: string) => {
    const snap = {
      runs: filteredRuns,
      p1: totalP1,
      p2: totalP2,
      p3: totalP3,
      score: healthScore,
      period: filters.period,
      system: filters.system,
      totalRuns: filteredRuns.length,
    };
    const msgs = userMsg
      ? [...aiMessages, { role: "user", content: userMsg }]
      : [];
    setAiLoading(true);
    setTimeout(() => {
      try {
        const r = generateAiAnalysis(userMsg, aiView, snap);
        setAiMessages([...msgs, { role: "assistant", content: r }]);
      } catch {
        setAiMessages([
          ...msgs,
          { role: "assistant", content: "Analysis could not be completed." },
        ]);
      }
      setAiLoading(false);
    }, 1000);
  };

  // ── Render helpers ──────────────────────────────────────────────────────────
  const renderAiText = (text: string) =>
    text.split("\n").map((line, i) => {
      if (line.startsWith("## "))
        return (
          <div
            key={i}
            style={{
              fontWeight: 700,
              fontSize: 14,
              color: "#0a6ed1",
              marginTop: i > 0 ? 16 : 0,
              marginBottom: 6,
              borderBottom: "1px solid #e0e7ff",
              paddingBottom: 4,
            }}
          >
            {line.replace("## ", "")}
          </div>
        );
      if (line.startsWith("- ") || line.startsWith("• ")) {
        const parts = line.replace(/^[-•] /, "").split("**");
        return (
          <div key={i} style={{ paddingLeft: 12, marginBottom: 4 }}>
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
            key={i}
            style={{ paddingLeft: 12, marginBottom: 4, fontWeight: 500 }}
          >
            {line}
          </div>
        );
      if (line.includes("**")) {
        const parts = line.split("**");
        return (
          <div key={i} style={{ marginBottom: line === "" ? 8 : 2 }}>
            {parts.map((p, k) =>
              k % 2 === 1 ? <strong key={k}>{p}</strong> : p,
            )}
          </div>
        );
      }
      return (
        <div key={i} style={{ marginBottom: line === "" ? 8 : 2 }}>
          {line}
        </div>
      );
    });
  const handleObjSort = (col: typeof objSortCol) => {
    if (objSortCol === col)
      setObjSortDir((d) => (d === "desc" ? "asc" : "desc"));
    else {
      setObjSortCol(col);
      setObjSortDir("desc");
    }
  };
  const si = (col: typeof objSortCol) =>
    objSortCol === col ? (objSortDir === "desc" ? " ▼" : " ▲") : " ▲▼";

  // ── Shared table styles ─────────────────────────────────────────────────────
  const tH: React.CSSProperties = {
    background: "#f8fafc",
    borderBottom: "2px solid #e5e7eb",
  };
  const tTh: React.CSSProperties = {
    padding: "10px 14px",
    fontSize: 10,
    fontWeight: 700,
    color: "#6b7280",
    textTransform: "uppercase",
    letterSpacing: "0.6px",
    textAlign: "left",
    whiteSpace: "nowrap",
  };
  const tTd: React.CSSProperties = {
    padding: "10px 14px",
    fontSize: 12,
    color: "#374151",
    borderBottom: "1px solid #f3f4f6",
    verticalAlign: "top",
  };
  const tTdR: React.CSSProperties = { ...tTd, textAlign: "right" };
  const pb = (p: number, v: number) => {
    if (v === 0)
      return <span style={{ color: "#d1d5db", fontSize: 12 }}>—</span>;
    const cfg: Record<number, [string, string]> = {
      1: ["#fee2e2", "#dc2626"],
      2: ["#fef3c7", "#d97706"],
      3: ["#dbeafe", "#2563eb"],
      4: ["#f3f4f6", "#6b7280"],
    };
    const [bg, c] = cfg[p] || cfg[4];
    return (
      <span
        style={{
          background: bg,
          color: c,
          borderRadius: 999,
          padding: "2px 8px",
          fontSize: 11,
          fontWeight: 700,
        }}
      >
        {v}
      </span>
    );
  };
  const tl = (color: string) => (
    <span
      style={{
        display: "inline-block",
        width: 10,
        height: 10,
        borderRadius: "50%",
        background: color,
        flexShrink: 0,
      }}
    />
  );
  const dc = (a: number, b: number) => {
    const d = a - b;
    if (d === 0)
      return (
        <span
          style={{
            background: "#f3f4f6",
            color: "#9ca3af",
            borderRadius: 999,
            padding: "1px 7px",
            fontSize: 11,
            fontWeight: 600,
          }}
        >
          —
        </span>
      );
    return (
      <span
        style={{
          background: d > 0 ? "#fee2e2" : "#dcfce7",
          color: d > 0 ? "#dc2626" : "#15803d",
          borderRadius: 999,
          padding: "1px 7px",
          fontSize: 11,
          fontWeight: 700,
        }}
      >
        {d > 0 ? `+${d}` : d}
      </span>
    );
  };

  if (systemsLoading)
    return (
      <div className="container">
        <div className="card">Loading systems...</div>
      </div>
    );

  if (!activeSystem)
    return (
      <div className="container">
        <div className="card" style={{ textAlign: "center", padding: 40 }}>
          <div style={{ fontSize: 28, marginBottom: 12 }}>🖥️</div>
          <div
            style={{
              fontSize: 14,
              fontWeight: 700,
              color: "#374151",
              marginBottom: 6,
            }}
          >
            No active system configured
          </div>
          <div style={{ fontSize: 13, color: "#9ca3af", marginBottom: 16 }}>
            Open Settings to add a system connection.
          </div>
          <button
            onClick={() => setSettingsOpen(true)}
            style={{
              padding: "8px 20px",
              borderRadius: 8,
              border: "none",
              background: "#0a6ed1",
              color: "white",
              fontSize: 13,
              fontWeight: 600,
              cursor: "pointer",
            }}
          >
            Open Settings
          </button>
        </div>
      </div>
    );

  if (loading)
    return (
      <div className="container">
        <div className="card">Loading dashboard...</div>
      </div>
    );

  return (
    <div>
      {/* ── HEADER ── */}
      <div className="header">
        <div className="header-title">ATC RUN MONITOR</div>
        <div style={{ display: "flex", gap: 12, alignItems: "center" }}>
          {systemsLoading ? (
            <div
              style={{
                fontSize: 12,
                color: "rgba(255,255,255,0.7)",
                padding: "6px 12px",
              }}
            >
              Loading systems...
            </div>
          ) : systems.filter((s) => s.IsActive === "X").length === 0 ? (
            <div
              style={{
                fontSize: 12,
                color: "rgba(255,255,255,0.7)",
                padding: "6px 12px",
              }}
            >
              No active systems — configure in Settings
            </div>
          ) : (
            <div style={{ position: "relative" }}>
              <select
                value={activeSystemId}
                onChange={(e) => {
                  setActiveSystemId(e.target.value);
                }}
                style={{
                  padding: "6px 32px 6px 12px",
                  borderRadius: 8,
                  border: "none",
                  fontSize: 12,
                  fontWeight: 600,
                  cursor: "pointer",
                  background: "rgba(255,255,255,0.15)",
                  color: "white",
                  appearance: "none",
                  WebkitAppearance: "none",
                  outline: "none",
                  minWidth: 180,
                }}
              >
                {systems
                  .filter((s) => s.IsActive === "X")
                  .map((s) => (
                    <option
                      key={s.SystemId}
                      value={s.SystemId}
                      style={{ color: "#111827", background: "white" }}
                    >
                      {s.SystemType === "BTP" ? "☁️" : "🖥️"} {s.SystemName}
                      {s.SystemIdLabel ? ` (${s.SystemIdLabel})` : ""}
                    </option>
                  ))}
              </select>
              <span
                style={{
                  position: "absolute",
                  right: 10,
                  top: "50%",
                  transform: "translateY(-50%)",
                  pointerEvents: "none",
                  color: "rgba(255,255,255,0.8)",
                  fontSize: 10,
                }}
              >
                ▼
              </span>
            </div>
          )}
          <button
            onClick={() => {
              setSettingsOpen(true);
            }}
            style={{
              display: "flex",
              alignItems: "center",
              gap: 5,
              padding: "6px 12px",
              borderRadius: 8,
              border: "none",
              fontSize: 12,
              fontWeight: 600,
              cursor: "pointer",
              background: "rgba(255,255,255,0.15)",
              color: "rgba(255,255,255,0.9)",
            }}
          >
            ⚙️ Settings
          </button>
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

      {/* ── SETTINGS MODAL ── */}
      {settingsOpen && (
        <div
          onClick={(e) => {
            if (e.target === e.currentTarget) setSettingsOpen(false);
          }}
          style={{
            position: "fixed",
            inset: 0,
            background: "rgba(0,0,0,0.45)",
            zIndex: 2000,
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
          }}
        >
          <div
            style={{
              width: "min(860px,95vw)",
              background: "var(--card-bg,#fff)",
              borderRadius: 16,
              boxShadow: "0 8px 40px rgba(0,0,0,0.2)",
              padding: 32,
              boxSizing: "border-box",
              maxHeight: "90vh",
              overflowY: "auto",
              overflowX: "hidden",
            }}
          >
            <div
              style={{
                display: "flex",
                justifyContent: "space-between",
                alignItems: "center",
                marginBottom: 20,
              }}
            >
              <h2 style={{ margin: 0, fontSize: 18, fontWeight: 700 }}>
                ⚙️ Settings
              </h2>
              <button
                onClick={() => setSettingsOpen(false)}
                style={{
                  background: "none",
                  border: "none",
                  fontSize: 20,
                  cursor: "pointer",
                  color: "#6b7280",
                  padding: "4px 8px",
                }}
              >
                ✕
              </button>
            </div>

            {/* Settings Tabs */}
            <div
              style={{
                display: "flex",
                gap: 4,
                marginBottom: 24,
                background: "#f3f4f6",
                borderRadius: 10,
                padding: 4,
              }}
            >
              {[
                { key: "connections", label: "🔌 Connections" },
                ...(currentUser?.IsAdmin
                  ? [{ key: "admin", label: "🛡️ Admin Panel" }]
                  : []),
              ].map((t: any) => (
                <button
                  key={t.key}
                  onClick={() => setSettingsTab(t.key)}
                  style={{
                    flex: 1,
                    padding: "8px 16px",
                    borderRadius: 7,
                    border: "none",
                    fontSize: 13,
                    fontWeight: 600,
                    cursor: "pointer",
                    background: settingsTab === t.key ? "white" : "transparent",
                    color: settingsTab === t.key ? "#0a6ed1" : "#6b7280",
                    boxShadow:
                      settingsTab === t.key
                        ? "0 1px 4px rgba(0,0,0,0.1)"
                        : "none",
                    transition: "all 0.15s",
                  }}
                >
                  {t.label}
                </button>
              ))}
            </div>

            {settingsTab === "connections" && (
              <div>
                <div
                  style={{
                    display: "flex",
                    justifyContent: "space-between",
                    alignItems: "center",
                    marginBottom: 14,
                  }}
                >
                  <div>
                    <div
                      style={{
                        fontSize: 14,
                        fontWeight: 700,
                        color: "#0f172a",
                      }}
                    >
                      System Connections
                    </div>
                    <div
                      style={{ fontSize: 12, color: "#6b7280", marginTop: 2 }}
                    >
                      Add and manage SAP systems. Only active systems appear in
                      the header dropdown.
                    </div>
                  </div>
                  <button
                    onClick={() => {
                      setSysAddingRow({
                        SystemType: "NETWEAVER",
                        IsActive: "X",
                      });
                      setSysEditingId(null);
                      setSysError("");
                      setSysSuccess("");
                    }}
                    style={{
                      padding: "6px 14px",
                      borderRadius: 8,
                      border: "none",
                      background: "#0a6ed1",
                      color: "white",
                      fontSize: 12,
                      fontWeight: 700,
                      cursor: "pointer",
                    }}
                  >
                    + Add System
                  </button>
                </div>

                {sysError && (
                  <div
                    style={{
                      padding: "8px 12px",
                      background: "#fef2f2",
                      border: "1px solid #fecaca",
                      borderRadius: 8,
                      fontSize: 12,
                      color: "#dc2626",
                      marginBottom: 10,
                    }}
                  >
                    ❌ {sysError}
                  </div>
                )}
                {sysSuccess && (
                  <div
                    style={{
                      padding: "8px 12px",
                      background: "#f0fdf4",
                      border: "1px solid #bbf7d0",
                      borderRadius: 8,
                      fontSize: 12,
                      color: "#15803d",
                      marginBottom: 10,
                    }}
                  >
                    ✅ {sysSuccess}
                  </div>
                )}

                {sysAddingRow && (
                  <div
                    style={{
                      padding: 16,
                      background: "#f0f7ff",
                      borderRadius: 10,
                      border: "1px solid #bfdbfe",
                      marginBottom: 16,
                    }}
                  >
                    <div
                      style={{
                        fontSize: 12,
                        fontWeight: 700,
                        color: "#0a6ed1",
                        marginBottom: 12,
                      }}
                    >
                      New System
                    </div>
                    <div
                      style={{
                        display: "grid",
                        gridTemplateColumns: "1fr 1fr",
                        gap: 10,
                      }}
                    >
                      {[
                        {
                          key: "SystemId",
                          label: "System ID *",
                          placeholder: "e.g. V21_DEV",
                        },
                        {
                          key: "SystemName",
                          label: "Display Name *",
                          placeholder: "e.g. V21 Development",
                        },
                        {
                          key: "SystemIdLabel",
                          label: "Label (header)",
                          placeholder: "e.g. V21",
                        },
                        {
                          key: "BaseUrl",
                          label: "Base URL *",
                          placeholder: "/sap/opu/odata4/...",
                        },
                        {
                          key: "Host",
                          label: "Host (ADT links)",
                          placeholder: "https://v21.company.com",
                        },
                        {
                          key: "Description",
                          label: "Description",
                          placeholder: "Optional",
                        },
                      ].map((f) => (
                        <div key={f.key}>
                          <label
                            style={{
                              fontSize: 11,
                              fontWeight: 700,
                              color: "#374151",
                              display: "block",
                              marginBottom: 3,
                            }}
                          >
                            {f.label}
                          </label>
                          <input
                            value={(sysAddingRow as any)[f.key] || ""}
                            onChange={(e) =>
                              setSysAddingRow({
                                ...sysAddingRow,
                                [f.key]: e.target.value,
                              })
                            }
                            placeholder={f.placeholder}
                            style={{
                              width: "100%",
                              padding: "7px 10px",
                              borderRadius: 6,
                              border: "1px solid #d1d5db",
                              fontSize: 12,
                              boxSizing: "border-box" as const,
                            }}
                          />
                        </div>
                      ))}
                      <div>
                        <label
                          style={{
                            fontSize: 11,
                            fontWeight: 700,
                            color: "#374151",
                            display: "block",
                            marginBottom: 3,
                          }}
                        >
                          System Type *
                        </label>
                        <select
                          value={sysAddingRow.SystemType || "NETWEAVER"}
                          onChange={(e) =>
                            setSysAddingRow({
                              ...sysAddingRow,
                              SystemType: e.target.value,
                            })
                          }
                          style={{
                            width: "100%",
                            padding: "7px 10px",
                            borderRadius: 6,
                            border: "1px solid #d1d5db",
                            fontSize: 12,
                            boxSizing: "border-box" as const,
                          }}
                        >
                          <option value="NETWEAVER">🖥️ NetWeaver</option>
                          <option value="BTP">☁️ BTP</option>
                        </select>
                      </div>
                      <div>
                        <label
                          style={{
                            fontSize: 11,
                            fontWeight: 700,
                            color: "#374151",
                            display: "block",
                            marginBottom: 3,
                          }}
                        >
                          Is Active
                        </label>
                        <select
                          value={sysAddingRow.IsActive || "X"}
                          onChange={(e) =>
                            setSysAddingRow({
                              ...sysAddingRow,
                              IsActive: e.target.value,
                            })
                          }
                          style={{
                            width: "100%",
                            padding: "7px 10px",
                            borderRadius: 6,
                            border: "1px solid #d1d5db",
                            fontSize: 12,
                            boxSizing: "border-box" as const,
                          }}
                        >
                          <option value="X">Active</option>
                          <option value="">Inactive</option>
                        </select>
                      </div>
                    </div>
                    <div style={{ display: "flex", gap: 8, marginTop: 14 }}>
                      <button
                        disabled={
                          sysLoading ||
                          !sysAddingRow.SystemId ||
                          !sysAddingRow.SystemName ||
                          !sysAddingRow.BaseUrl
                        }
                        onClick={async () => {
                          const ok = await saveSystem(
                            "POST",
                            sysAddingRow.SystemId!,
                            sysAddingRow as SystemConfig,
                          );
                          if (ok) setSysAddingRow(null);
                        }}
                        style={{
                          padding: "6px 16px",
                          borderRadius: 8,
                          border: "none",
                          background: sysLoading ? "#e5e7eb" : "#0a6ed1",
                          color: sysLoading ? "#9ca3af" : "white",
                          fontSize: 12,
                          fontWeight: 700,
                          cursor: sysLoading ? "default" : "pointer",
                        }}
                      >
                        {sysLoading ? "Saving..." : "Save"}
                      </button>
                      <button
                        onClick={() => setSysAddingRow(null)}
                        style={{
                          padding: "6px 16px",
                          borderRadius: 8,
                          border: "1px solid #d1d5db",
                          background: "white",
                          fontSize: 12,
                          fontWeight: 600,
                          cursor: "pointer",
                          color: "#374151",
                        }}
                      >
                        Cancel
                      </button>
                    </div>
                  </div>
                )}

                {systems.length === 0 && !sysAddingRow ? (
                  <div
                    style={{
                      padding: "32px 20px",
                      textAlign: "center",
                      background: "#f9fafb",
                      borderRadius: 10,
                      border: "1px dashed #d1d5db",
                    }}
                  >
                    <div style={{ fontSize: 28, marginBottom: 8 }}>🖥️</div>
                    <div
                      style={{
                        fontSize: 13,
                        fontWeight: 700,
                        color: "#374151",
                        marginBottom: 4,
                      }}
                    >
                      No systems configured
                    </div>
                    <div style={{ fontSize: 12, color: "#9ca3af" }}>
                      Add your first system using the button above. Systems are
                      stored in ZATC_SYSTEMS.
                    </div>
                  </div>
                ) : (
                  <div
                    style={{
                      border: "1px solid #e5e7eb",
                      borderRadius: 8,
                      maxHeight: 320,
                      overflowY: "auto",
                      overflowX: "auto",
                    }}
                  >
                    <table
                      style={{
                        width: "100%",
                        borderCollapse: "collapse",
                        fontSize: 12,
                      }}
                    >
                      <thead
                        style={{
                          background: "#f8fafc",
                          position: "sticky",
                          top: 0,
                        }}
                      >
                        <tr>
                          {[
                            "System ID",
                            "Name",
                            "Type",
                            "Base URL",
                            "Host",
                            "Active",
                            "Actions",
                          ].map((h) => (
                            <th
                              key={h}
                              style={{
                                padding: "8px 12px",
                                textAlign: "left",
                                fontSize: 10,
                                fontWeight: 700,
                                color: "#6b7280",
                                textTransform: "uppercase",
                                borderBottom: "1px solid #e5e7eb",
                                whiteSpace: "nowrap",
                              }}
                            >
                              {h}
                            </th>
                          ))}
                        </tr>
                      </thead>
                      <tbody>
                        {systems.map((s, i) => (
                          <tr
                            key={i}
                            style={{
                              background: i % 2 === 0 ? "#fff" : "#fafafa",
                            }}
                          >
                            {sysEditingId === s.SystemId ? (
                              <>
                                <td
                                  style={{
                                    padding: "7px 12px",
                                    fontFamily: "monospace",
                                    fontWeight: 600,
                                  }}
                                >
                                  {s.SystemId}
                                </td>
                                <td style={{ padding: "4px 8px" }}>
                                  <input
                                    value={sysEditingRow?.SystemName || ""}
                                    onChange={(e) =>
                                      setSysEditingRow({
                                        ...sysEditingRow,
                                        SystemName: e.target.value,
                                      })
                                    }
                                    style={{
                                      width: "100%",
                                      padding: "4px 8px",
                                      borderRadius: 6,
                                      border: "1px solid #d1d5db",
                                      fontSize: 12,
                                    }}
                                  />
                                </td>
                                <td style={{ padding: "4px 8px" }}>
                                  <select
                                    value={sysEditingRow?.SystemType || ""}
                                    onChange={(e) =>
                                      setSysEditingRow({
                                        ...sysEditingRow,
                                        SystemType: e.target.value,
                                      })
                                    }
                                    style={{
                                      width: "100%",
                                      padding: "4px 8px",
                                      borderRadius: 6,
                                      border: "1px solid #d1d5db",
                                      fontSize: 12,
                                    }}
                                  >
                                    <option value="NETWEAVER">NetWeaver</option>
                                    <option value="BTP">BTP</option>
                                  </select>
                                </td>
                                <td style={{ padding: "4px 8px" }}>
                                  <input
                                    value={sysEditingRow?.BaseUrl || ""}
                                    onChange={(e) =>
                                      setSysEditingRow({
                                        ...sysEditingRow,
                                        BaseUrl: e.target.value,
                                      })
                                    }
                                    style={{
                                      width: "100%",
                                      padding: "4px 8px",
                                      borderRadius: 6,
                                      border: "1px solid #d1d5db",
                                      fontSize: 11,
                                      fontFamily: "monospace",
                                    }}
                                  />
                                </td>
                                <td style={{ padding: "4px 8px" }}>
                                  <input
                                    value={sysEditingRow?.Host || ""}
                                    onChange={(e) =>
                                      setSysEditingRow({
                                        ...sysEditingRow,
                                        Host: e.target.value,
                                      })
                                    }
                                    style={{
                                      width: "100%",
                                      padding: "4px 8px",
                                      borderRadius: 6,
                                      border: "1px solid #d1d5db",
                                      fontSize: 11,
                                      fontFamily: "monospace",
                                    }}
                                  />
                                </td>
                                <td style={{ padding: "4px 8px" }}>
                                  <select
                                    value={sysEditingRow?.IsActive || ""}
                                    onChange={(e) =>
                                      setSysEditingRow({
                                        ...sysEditingRow,
                                        IsActive: e.target.value,
                                      })
                                    }
                                    style={{
                                      width: "100%",
                                      padding: "4px 8px",
                                      borderRadius: 6,
                                      border: "1px solid #d1d5db",
                                      fontSize: 12,
                                    }}
                                  >
                                    <option value="X">Active</option>
                                    <option value="">Inactive</option>
                                  </select>
                                </td>
                                <td style={{ padding: "4px 8px" }}>
                                  <div style={{ display: "flex", gap: 4 }}>
                                    <button
                                      disabled={sysLoading}
                                      onClick={async () => {
                                        const ok = await saveSystem(
                                          "PATCH",
                                          s.SystemId,
                                          sysEditingRow!,
                                        );
                                        if (ok) {
                                          setSysEditingId(null);
                                          setSysEditingRow(null);
                                        }
                                      }}
                                      style={{
                                        padding: "3px 10px",
                                        borderRadius: 6,
                                        border: "none",
                                        background: "#0a6ed1",
                                        color: "white",
                                        fontSize: 11,
                                        fontWeight: 700,
                                        cursor: "pointer",
                                      }}
                                    >
                                      Save
                                    </button>
                                    <button
                                      onClick={() => {
                                        setSysEditingId(null);
                                        setSysEditingRow(null);
                                      }}
                                      style={{
                                        padding: "3px 10px",
                                        borderRadius: 6,
                                        border: "1px solid #d1d5db",
                                        background: "white",
                                        fontSize: 11,
                                        cursor: "pointer",
                                        color: "#374151",
                                      }}
                                    >
                                      Cancel
                                    </button>
                                  </div>
                                </td>
                              </>
                            ) : (
                              <>
                                <td
                                  style={{
                                    padding: "7px 12px",
                                    fontFamily: "monospace",
                                    fontWeight: 600,
                                  }}
                                >
                                  {s.SystemId}
                                  {s.SystemId === activeSystemId && (
                                    <span
                                      style={{
                                        marginLeft: 6,
                                        background: "#dbeafe",
                                        color: "#1e40af",
                                        borderRadius: 999,
                                        padding: "1px 6px",
                                        fontSize: 10,
                                        fontWeight: 600,
                                      }}
                                    >
                                      Active
                                    </span>
                                  )}
                                </td>
                                <td style={{ padding: "7px 12px" }}>
                                  {s.SystemName}
                                </td>
                                <td style={{ padding: "7px 12px" }}>
                                  <span
                                    style={{
                                      background:
                                        s.SystemType === "BTP"
                                          ? "#eff6ff"
                                          : "#f0fdf4",
                                      color:
                                        s.SystemType === "BTP"
                                          ? "#1e40af"
                                          : "#15803d",
                                      borderRadius: 999,
                                      padding: "1px 8px",
                                      fontSize: 11,
                                      fontWeight: 700,
                                    }}
                                  >
                                    {s.SystemType === "BTP"
                                      ? "☁️ BTP"
                                      : "🖥️ NetWeaver"}
                                  </span>
                                </td>
                                <td
                                  style={{
                                    padding: "7px 12px",
                                    color: "#6b7280",
                                    fontFamily: "monospace",
                                    fontSize: 10,
                                    wordBreak: "break-all",
                                    minWidth: 200,
                                  }}
                                >
                                  {s.BaseUrl}
                                </td>
                                <td
                                  style={{
                                    padding: "7px 12px",
                                    color: "#6b7280",
                                    fontFamily: "monospace",
                                    fontSize: 10,
                                    wordBreak: "break-all",
                                    minWidth: 160,
                                  }}
                                >
                                  {s.Host || "—"}
                                </td>
                                <td style={{ padding: "7px 12px" }}>
                                  {s.IsActive === "X" ? "✅" : "—"}
                                </td>
                                <td style={{ padding: "7px 12px" }}>
                                  <div style={{ display: "flex", gap: 4 }}>
                                    <button
                                      onClick={() => {
                                        setSysEditingId(s.SystemId);
                                        setSysEditingRow({ ...s });
                                        setSysAddingRow(null);
                                        setSysError("");
                                        setSysSuccess("");
                                      }}
                                      style={{
                                        padding: "3px 10px",
                                        borderRadius: 6,
                                        border: "1px solid #bfdbfe",
                                        background: "#eff6ff",
                                        color: "#0a6ed1",
                                        fontSize: 11,
                                        fontWeight: 600,
                                        cursor: "pointer",
                                      }}
                                    >
                                      Edit
                                    </button>
                                    <button
                                      onClick={async () => {
                                        if (
                                          !window.confirm(
                                            `Delete system ${s.SystemId}?`,
                                          )
                                        )
                                          return;
                                        const ok = await saveSystem(
                                          "DELETE",
                                          s.SystemId,
                                        );
                                        if (
                                          ok &&
                                          activeSystemId === s.SystemId
                                        ) {
                                          const remaining = systems.filter(
                                            (x) =>
                                              x.SystemId !== s.SystemId &&
                                              x.IsActive === "X",
                                          );
                                          if (remaining.length > 0)
                                            setActiveSystemId(
                                              remaining[0].SystemId,
                                            );
                                          else setActiveSystemId("");
                                        }
                                      }}
                                      style={{
                                        padding: "3px 10px",
                                        borderRadius: 6,
                                        border: "1px solid #fecaca",
                                        background: "#fef2f2",
                                        color: "#dc2626",
                                        fontSize: 11,
                                        fontWeight: 600,
                                        cursor: "pointer",
                                      }}
                                    >
                                      Delete
                                    </button>
                                  </div>
                                </td>
                              </>
                            )}
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
                <div style={{ marginTop: 10, fontSize: 11, color: "#9ca3af" }}>
                  Systems are persisted to ZATC_SYSTEMS. Only systems with
                  IsActive = X appear in the header dropdown.
                </div>
              </div>
            )}
            {/* ── ADMIN SECTION ── */}
            {settingsTab === "admin" && currentUser?.IsAdmin && (
              <div style={{ marginTop: 8 }}>
                <div
                  style={{
                    height: 1,
                    background: "#e5e7eb",
                    margin: "8px 0 20px",
                  }}
                />
                <div
                  style={{
                    fontSize: 14,
                    fontWeight: 700,
                    color: "#0f172a",
                    marginBottom: 4,
                  }}
                >
                  🛡️ Admin Panel
                </div>
                <div
                  style={{ fontSize: 12, color: "#6b7280", marginBottom: 14 }}
                >
                  Manage master data — visible only to admins
                </div>

                {/* Section tabs */}
                <div
                  style={{
                    display: "flex",
                    gap: 6,
                    flexWrap: "wrap",
                    marginBottom: 16,
                  }}
                >
                  {[
                    { key: "profiles", label: "👤 Profiles" },
                    { key: "teams", label: "👥 Teams" },
                    { key: "products", label: "📦 Products" },
                    { key: "series", label: "🔄 Run Series" },
                    { key: "config", label: "⚙️ Integration" },
                  ].map((s) => (
                    <button
                      key={s.key}
                      onClick={() => {
                        setAdminSection(s.key);
                        setEditingRow(null);
                        setAddingRow(null);
                        setAdminError("");
                        setAdminSuccess("");
                      }}
                      style={{
                        padding: "5px 12px",
                        borderRadius: 999,
                        border: `1px solid ${adminSection === s.key ? "#0a6ed1" : "#e5e7eb"}`,
                        background:
                          adminSection === s.key ? "#0a6ed1" : "white",
                        color: adminSection === s.key ? "white" : "#374151",
                        fontSize: 11,
                        fontWeight: 600,
                        cursor: "pointer",
                      }}
                    >
                      {s.label}
                    </button>
                  ))}
                </div>

                {/* Feedback */}
                {adminError && (
                  <div
                    style={{
                      padding: "8px 12px",
                      background: "#fef2f2",
                      border: "1px solid #fecaca",
                      borderRadius: 8,
                      fontSize: 12,
                      color: "#dc2626",
                      marginBottom: 10,
                    }}
                  >
                    ❌ {adminError}
                  </div>
                )}
                {adminSuccess && (
                  <div
                    style={{
                      padding: "8px 12px",
                      background: "#f0fdf4",
                      border: "1px solid #bbf7d0",
                      borderRadius: 8,
                      fontSize: 12,
                      color: "#15803d",
                      marginBottom: 10,
                    }}
                  >
                    ✅ {adminSuccess}
                  </div>
                )}

                {/* ── PROFILES (read only) ── */}
                {adminSection === "profiles" && (
                  <div>
                    <div
                      style={{
                        fontSize: 12,
                        color: "#6b7280",
                        marginBottom: 10,
                      }}
                    >
                      Developer profiles are maintained directly in
                      ZATC_DEV_PROF via SE16N. Showing {devProfiles.length}{" "}
                      active profiles.
                    </div>
                    <div
                      style={{
                        maxHeight: 320,
                        overflowY: "auto",
                        overflowX: "auto",
                        border: "1px solid #e5e7eb",
                        borderRadius: 8,
                      }}
                    >
                      <table
                        style={{
                          width: "100%",
                          borderCollapse: "collapse",
                          fontSize: 12,
                          minWidth: 500,
                        }}
                      >
                        <thead
                          style={{
                            background: "#f8fafc",
                            position: "sticky",
                            top: 0,
                          }}
                        >
                          <tr>
                            {[
                              "User ID",
                              "Name",
                              "Email",
                              "Product",
                              "Admin",
                            ].map((h) => (
                              <th
                                key={h}
                                style={{
                                  padding: "8px 12px",
                                  textAlign: "left",
                                  fontSize: 10,
                                  fontWeight: 700,
                                  color: "#6b7280",
                                  textTransform: "uppercase",
                                  borderBottom: "1px solid #e5e7eb",
                                }}
                              >
                                {h}
                              </th>
                            ))}
                          </tr>
                        </thead>
                        <tbody>
                          {devProfiles.map((p, i) => (
                            <tr
                              key={i}
                              style={{
                                background: i % 2 === 0 ? "#fff" : "#fafafa",
                              }}
                            >
                              <td
                                style={{
                                  padding: "7px 12px",
                                  fontFamily: "monospace",
                                  fontWeight: 600,
                                }}
                              >
                                {p.UserId}
                              </td>
                              <td style={{ padding: "7px 12px" }}>
                                {p.DisplayName}
                              </td>
                              <td
                                style={{
                                  padding: "7px 12px",
                                  color: "#6b7280",
                                }}
                              >
                                {p.Email || "—"}
                              </td>
                              <td style={{ padding: "7px 12px" }}>
                                {p.ProductId || "—"}
                              </td>
                              <td style={{ padding: "7px 12px" }}>
                                {p.IsAdmin ? "✅" : "—"}
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>
                )}

                {/* ── TEAMS (read only) ── */}
                {adminSection === "teams" && (
                  <div>
                    <div
                      style={{
                        fontSize: 12,
                        color: "#6b7280",
                        marginBottom: 10,
                      }}
                    >
                      Teams are maintained directly in ZATC_TEAMS via SE16N.
                      Showing {teams.length} teams.
                    </div>
                    <div
                      style={{
                        maxHeight: 320,
                        overflowY: "auto",
                        overflowX: "auto",
                        border: "1px solid #e5e7eb",
                        borderRadius: 8,
                      }}
                    >
                      <table
                        style={{
                          width: "100%",
                          borderCollapse: "collapse",
                          fontSize: 12,
                          minWidth: 400,
                        }}
                      >
                        <thead
                          style={{
                            background: "#f8fafc",
                            position: "sticky",
                            top: 0,
                          }}
                        >
                          <tr>
                            {["Team ID", "Team Name", "Product", "Lead"].map(
                              (h) => (
                                <th
                                  key={h}
                                  style={{
                                    padding: "8px 12px",
                                    textAlign: "left",
                                    fontSize: 10,
                                    fontWeight: 700,
                                    color: "#6b7280",
                                    textTransform: "uppercase",
                                    borderBottom: "1px solid #e5e7eb",
                                  }}
                                >
                                  {h}
                                </th>
                              ),
                            )}
                          </tr>
                        </thead>
                        <tbody>
                          {teams.map((t, i) => (
                            <tr
                              key={i}
                              style={{
                                background: i % 2 === 0 ? "#fff" : "#fafafa",
                              }}
                            >
                              <td
                                style={{
                                  padding: "7px 12px",
                                  fontFamily: "monospace",
                                  fontWeight: 600,
                                }}
                              >
                                {t.TeamId}
                              </td>
                              <td style={{ padding: "7px 12px" }}>
                                {t.TeamName}
                              </td>
                              <td style={{ padding: "7px 12px" }}>
                                {t.ProductId || "—"}
                              </td>
                              <td style={{ padding: "7px 12px" }}>
                                {t.TeamLead || "—"}
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>
                )}

                {/* ── PRODUCTS (full CRUD) ── */}
                {adminSection === "products" && (
                  <div>
                    <div
                      style={{
                        display: "flex",
                        justifyContent: "space-between",
                        alignItems: "center",
                        marginBottom: 10,
                      }}
                    >
                      <div style={{ fontSize: 12, color: "#6b7280" }}>
                        {products.length} products configured
                      </div>
                      <button
                        onClick={() => {
                          setAddingRow({
                            ProductId: "",
                            ProductName: "",
                            JiraProjectKey: "",
                            SharePointUrl: "",
                            IsActive: true,
                          });
                          setEditingRow(null);
                        }}
                        style={{
                          padding: "5px 14px",
                          borderRadius: 8,
                          border: "none",
                          background: "#0a6ed1",
                          color: "white",
                          fontSize: 12,
                          fontWeight: 700,
                          cursor: "pointer",
                        }}
                      >
                        + Add Product
                      </button>
                    </div>

                    {addingRow && adminSection === "products" && (
                      <div
                        style={{
                          padding: "14px",
                          background: "#f0f7ff",
                          borderRadius: 10,
                          border: "1px solid #bfdbfe",
                          marginBottom: 12,
                        }}
                      >
                        <div
                          style={{
                            fontSize: 12,
                            fontWeight: 700,
                            color: "#0a6ed1",
                            marginBottom: 10,
                          }}
                        >
                          New Product
                        </div>
                        {[
                          {
                            key: "ProductId",
                            label: "Product ID",
                            required: true,
                          },
                          {
                            key: "ProductName",
                            label: "Product Name",
                            required: true,
                          },
                          { key: "JiraProjectKey", label: "Jira Project Key" },
                          { key: "SharePointUrl", label: "SharePoint URL" },
                        ].map((f) => (
                          <div key={f.key} style={{ marginBottom: 8 }}>
                            <label
                              style={{
                                fontSize: 11,
                                fontWeight: 700,
                                color: "#374151",
                                display: "block",
                                marginBottom: 3,
                              }}
                            >
                              {f.label}
                              {f.required && " *"}
                            </label>
                            <input
                              value={addingRow[f.key] || ""}
                              onChange={(e) =>
                                setAddingRow({
                                  ...addingRow,
                                  [f.key]: e.target.value,
                                })
                              }
                              style={{
                                width: "100%",
                                padding: "7px 10px",
                                borderRadius: 6,
                                border: "1px solid #d1d5db",
                                fontSize: 12,
                                boxSizing: "border-box" as const,
                              }}
                            />
                          </div>
                        ))}
                        <div style={{ marginBottom: 8 }}>
                          <label
                            style={{
                              fontSize: 11,
                              fontWeight: 700,
                              color: "#374151",
                              display: "block",
                              marginBottom: 3,
                            }}
                          >
                            Is Active
                          </label>
                          <select
                            value={addingRow.IsActive ? "X" : ""}
                            onChange={(e) =>
                              setAddingRow({
                                ...addingRow,
                                IsActive: e.target.value === "X",
                              })
                            }
                            style={{
                              width: "100%",
                              padding: "7px 10px",
                              borderRadius: 6,
                              border: "1px solid #d1d5db",
                              fontSize: 12,
                              boxSizing: "border-box" as const,
                            }}
                          >
                            <option value="X">Active</option>
                            <option value="">Inactive</option>
                          </select>
                        </div>
                        <div style={{ display: "flex", gap: 8, marginTop: 10 }}>
                          <button
                            disabled={
                              adminLoading ||
                              !addingRow.ProductId ||
                              !addingRow.ProductName
                            }
                            onClick={async () => {
                              const r = await adminWrite("POST", "/Products", {
                                ProductId: addingRow.ProductId,
                                ProductName: addingRow.ProductName,
                                JiraProjectKey: addingRow.JiraProjectKey || "",
                                SharePointUrl: addingRow.SharePointUrl || "",
                                IsActive: true,
                              });
                              if (r.ok) {
                                setAddingRow(null);
                                refreshAdminData();
                              }
                            }}
                            style={{
                              padding: "6px 16px",
                              borderRadius: 8,
                              border: "none",
                              background: adminLoading ? "#e5e7eb" : "#0a6ed1",
                              color: adminLoading ? "#9ca3af" : "white",
                              fontSize: 12,
                              fontWeight: 700,
                              cursor: adminLoading ? "default" : "pointer",
                            }}
                          >
                            {adminLoading ? "Saving..." : "Save"}
                          </button>
                          <button
                            onClick={() => setAddingRow(null)}
                            style={{
                              padding: "6px 16px",
                              borderRadius: 8,
                              border: "1px solid #d1d5db",
                              background: "white",
                              fontSize: 12,
                              fontWeight: 600,
                              cursor: "pointer",
                              color: "#374151",
                            }}
                          >
                            Cancel
                          </button>
                        </div>
                      </div>
                    )}

                    <div
                      style={{
                        maxHeight: 320,
                        overflowY: "auto",
                        overflowX: "auto",
                        border: "1px solid #e5e7eb",
                        borderRadius: 8,
                      }}
                    >
                      <table
                        style={{
                          width: "100%",
                          borderCollapse: "collapse",
                          fontSize: 12,
                          minWidth: 500,
                        }}
                      >
                        <thead
                          style={{
                            background: "#f8fafc",
                            position: "sticky",
                            top: 0,
                          }}
                        >
                          <tr>
                            {[
                              "Product ID",
                              "Name",
                              "Jira Key",
                              "SharePoint",
                              "Active",
                              "Actions",
                            ].map((h) => (
                              <th
                                key={h}
                                style={{
                                  padding: "8px 12px",
                                  textAlign: "left",
                                  fontSize: 10,
                                  fontWeight: 700,
                                  color: "#6b7280",
                                  textTransform: "uppercase",
                                  borderBottom: "1px solid #e5e7eb",
                                }}
                              >
                                {h}
                              </th>
                            ))}
                          </tr>
                        </thead>
                        <tbody>
                          {products.map((p, i) => (
                            <tr
                              key={i}
                              style={{
                                background: i % 2 === 0 ? "#fff" : "#fafafa",
                              }}
                            >
                              {editingRow?.ProductId === p.ProductId &&
                              adminSection === "products" ? (
                                <>
                                  <td
                                    style={{
                                      padding: "7px 12px",
                                      fontFamily: "monospace",
                                      fontWeight: 600,
                                    }}
                                  >
                                    {p.ProductId}
                                  </td>
                                  <td style={{ padding: "4px 8px" }}>
                                    <input
                                      value={editingRow.ProductName || ""}
                                      onChange={(e) =>
                                        setEditingRow({
                                          ...editingRow,
                                          ProductName: e.target.value,
                                        })
                                      }
                                      style={{
                                        width: "100%",
                                        padding: "4px 8px",
                                        borderRadius: 6,
                                        border: "1px solid #d1d5db",
                                        fontSize: 12,
                                      }}
                                    />
                                  </td>
                                  <td style={{ padding: "4px 8px" }}>
                                    <input
                                      value={editingRow.JiraProjectKey || ""}
                                      onChange={(e) =>
                                        setEditingRow({
                                          ...editingRow,
                                          JiraProjectKey: e.target.value,
                                        })
                                      }
                                      style={{
                                        width: "100%",
                                        padding: "4px 8px",
                                        borderRadius: 6,
                                        border: "1px solid #d1d5db",
                                        fontSize: 12,
                                      }}
                                    />
                                  </td>
                                  <td style={{ padding: "4px 8px" }}>
                                    <input
                                      value={editingRow.SharePointUrl || ""}
                                      onChange={(e) =>
                                        setEditingRow({
                                          ...editingRow,
                                          SharePointUrl: e.target.value,
                                        })
                                      }
                                      style={{
                                        width: "100%",
                                        padding: "4px 8px",
                                        borderRadius: 6,
                                        border: "1px solid #d1d5db",
                                        fontSize: 12,
                                      }}
                                    />
                                  </td>
                                  <td style={{ padding: "4px 8px" }}>
                                    <select
                                      value={editingRow.IsActive ? "X" : ""}
                                      onChange={(e) =>
                                        setEditingRow({
                                          ...editingRow,
                                          IsActive: e.target.value === "X",
                                        })
                                      }
                                      style={{
                                        width: "100%",
                                        padding: "4px 8px",
                                        borderRadius: 6,
                                        border: "1px solid #d1d5db",
                                        fontSize: 12,
                                      }}
                                    >
                                      <option value="X">Active</option>
                                      <option value="">Inactive</option>
                                    </select>
                                  </td>
                                  <td style={{ padding: "4px 8px" }}>
                                    <div style={{ display: "flex", gap: 4 }}>
                                      <button
                                        disabled={adminLoading}
                                        onClick={async () => {
                                          const r = await adminWrite(
                                            "PATCH",
                                            `/Products(ProductId='${p.ProductId}')`,
                                            {
                                              ProductName:
                                                editingRow.ProductName,
                                              JiraProjectKey:
                                                editingRow.JiraProjectKey,
                                              SharePointUrl:
                                                editingRow.SharePointUrl,
                                            },
                                          );
                                          if (r.ok) {
                                            setEditingRow(null);
                                            refreshAdminData();
                                          }
                                        }}
                                        style={{
                                          padding: "3px 10px",
                                          borderRadius: 6,
                                          border: "none",
                                          background: "#0a6ed1",
                                          color: "white",
                                          fontSize: 11,
                                          fontWeight: 700,
                                          cursor: "pointer",
                                        }}
                                      >
                                        Save
                                      </button>
                                      <button
                                        onClick={() => setEditingRow(null)}
                                        style={{
                                          padding: "3px 10px",
                                          borderRadius: 6,
                                          border: "1px solid #d1d5db",
                                          background: "white",
                                          fontSize: 11,
                                          cursor: "pointer",
                                          color: "#374151",
                                        }}
                                      >
                                        Cancel
                                      </button>
                                    </div>
                                  </td>
                                </>
                              ) : (
                                <>
                                  <td
                                    style={{
                                      padding: "7px 12px",
                                      fontFamily: "monospace",
                                      fontWeight: 600,
                                    }}
                                  >
                                    {p.ProductId}
                                  </td>
                                  <td style={{ padding: "7px 12px" }}>
                                    {p.ProductName}
                                  </td>
                                  <td
                                    style={{
                                      padding: "7px 12px",
                                      color: "#6b7280",
                                    }}
                                  >
                                    {p.JiraProjectKey || "—"}
                                  </td>
                                  <td
                                    style={{
                                      padding: "7px 12px",
                                      color: "#6b7280",
                                      fontSize: 10,
                                      maxWidth: 180,
                                      overflow: "hidden",
                                      textOverflow: "ellipsis",
                                      whiteSpace: "nowrap",
                                    }}
                                  >
                                    {p.SharePointUrl || "—"}
                                  </td>
                                  <td style={{ padding: "7px 12px" }}>
                                    {p.IsActive ? "✅" : "—"}
                                  </td>
                                  <td style={{ padding: "7px 12px" }}>
                                    <div style={{ display: "flex", gap: 4 }}>
                                      <button
                                        onClick={() => {
                                          setEditingRow({ ...p });
                                          setAddingRow(null);
                                        }}
                                        style={{
                                          padding: "3px 10px",
                                          borderRadius: 6,
                                          border: "1px solid #bfdbfe",
                                          background: "#eff6ff",
                                          color: "#0a6ed1",
                                          fontSize: 11,
                                          fontWeight: 600,
                                          cursor: "pointer",
                                        }}
                                      >
                                        Edit
                                      </button>
                                      <button
                                        onClick={async () => {
                                          if (
                                            !window.confirm(
                                              `Delete product ${p.ProductId}?`,
                                            )
                                          )
                                            return;
                                          const r = await adminWrite(
                                            "DELETE",
                                            `/Products(ProductId='${p.ProductId}')`,
                                          );
                                          if (r.ok) refreshAdminData();
                                        }}
                                        style={{
                                          padding: "3px 10px",
                                          borderRadius: 6,
                                          border: "1px solid #fecaca",
                                          background: "#fef2f2",
                                          color: "#dc2626",
                                          fontSize: 11,
                                          fontWeight: 600,
                                          cursor: "pointer",
                                        }}
                                      >
                                        Delete
                                      </button>
                                    </div>
                                  </td>
                                </>
                              )}
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>
                )}

                {/* ── PRODUCT RUN SERIES (full CRUD) ── */}
                {adminSection === "series" && (
                  <div>
                    <div
                      style={{
                        display: "flex",
                        justifyContent: "space-between",
                        alignItems: "center",
                        marginBottom: 10,
                      }}
                    >
                      <div style={{ fontSize: 12, color: "#6b7280" }}>
                        {productRunSeries.length} series configured
                      </div>
                      <button
                        onClick={() => {
                          setAddingRow({
                            ProductId: "",
                            RunSeries: "",
                            Description: "",
                            IsActive: true,
                          });
                          setEditingRow(null);
                        }}
                        style={{
                          padding: "5px 14px",
                          borderRadius: 8,
                          border: "none",
                          background: "#0a6ed1",
                          color: "white",
                          fontSize: 12,
                          fontWeight: 700,
                          cursor: "pointer",
                        }}
                      >
                        + Add Series
                      </button>
                    </div>

                    {addingRow && adminSection === "series" && (
                      <div
                        style={{
                          padding: "14px",
                          background: "#f0f7ff",
                          borderRadius: 10,
                          border: "1px solid #bfdbfe",
                          marginBottom: 12,
                        }}
                      >
                        <div
                          style={{
                            fontSize: 12,
                            fontWeight: 700,
                            color: "#0a6ed1",
                            marginBottom: 10,
                          }}
                        >
                          New Run Series
                        </div>
                        <div style={{ marginBottom: 8 }}>
                          <label
                            style={{
                              fontSize: 11,
                              fontWeight: 700,
                              color: "#374151",
                              display: "block",
                              marginBottom: 3,
                            }}
                          >
                            Product ID *
                          </label>
                          <select
                            value={addingRow.ProductId || ""}
                            onChange={(e) =>
                              setAddingRow({
                                ...addingRow,
                                ProductId: e.target.value,
                              })
                            }
                            style={{
                              width: "100%",
                              padding: "7px 10px",
                              borderRadius: 6,
                              border: "1px solid #d1d5db",
                              fontSize: 12,
                              boxSizing: "border-box" as const,
                            }}
                          >
                            <option value="">Select product...</option>
                            {products.map((p) => (
                              <option key={p.ProductId} value={p.ProductId}>
                                {p.ProductName || p.ProductId}
                              </option>
                            ))}
                          </select>
                        </div>
                        {[
                          {
                            key: "RunSeries",
                            label: "Run Series ID",
                            required: true,
                          },
                          { key: "Description", label: "Description" },
                          {
                            key: "IsBaseline",
                            label: "Is Baseline (X or blank)",
                          },
                          { key: "DisplayOrder", label: "Display Order" },
                        ].map((f) => (
                          <div key={f.key} style={{ marginBottom: 8 }}>
                            <label
                              style={{
                                fontSize: 11,
                                fontWeight: 700,
                                color: "#374151",
                                display: "block",
                                marginBottom: 3,
                              }}
                            >
                              {f.label}
                              {f.required && " *"}
                            </label>
                            <input
                              value={addingRow[f.key] || ""}
                              onChange={(e) =>
                                setAddingRow({
                                  ...addingRow,
                                  [f.key]: e.target.value,
                                })
                              }
                              style={{
                                width: "100%",
                                padding: "7px 10px",
                                borderRadius: 6,
                                border: "1px solid #d1d5db",
                                fontSize: 12,
                                boxSizing: "border-box" as const,
                              }}
                            />
                          </div>
                        ))}
                        <div style={{ marginBottom: 8 }}>
                          <label
                            style={{
                              fontSize: 11,
                              fontWeight: 700,
                              color: "#374151",
                              display: "block",
                              marginBottom: 3,
                            }}
                          >
                            Is Active
                          </label>
                          <select
                            value={addingRow.IsActive || ""}
                            onChange={(e) =>
                              setAddingRow({
                                ...addingRow,
                                IsActive: e.target.value,
                              })
                            }
                            style={{
                              width: "100%",
                              padding: "7px 10px",
                              borderRadius: 6,
                              border: "1px solid #d1d5db",
                              fontSize: 12,
                              boxSizing: "border-box" as const,
                            }}
                          >
                            <option value="">Inactive</option>
                            <option value="X">Active</option>
                          </select>
                        </div>
                        <div style={{ display: "flex", gap: 8, marginTop: 10 }}>
                          <button
                            disabled={
                              adminLoading ||
                              !addingRow.ProductId ||
                              !addingRow.RunSeries
                            }
                            onClick={async () => {
                              const r = await adminWrite(
                                "POST",
                                "/ProductRunSeries",
                                {
                                  ProductId: addingRow.ProductId,
                                  RunSeries: addingRow.RunSeries,
                                  Description: addingRow.Description || "",
                                  IsBaseline: addingRow.IsBaseline || "",
                                  DisplayOrder: addingRow.DisplayOrder
                                    ? Number(addingRow.DisplayOrder)
                                    : 0,
                                  IsActive: addingRow.IsActive || "",
                                },
                              );
                              if (r.ok) {
                                setAddingRow(null);
                                refreshAdminData();
                              }
                            }}
                            style={{
                              padding: "6px 16px",
                              borderRadius: 8,
                              border: "none",
                              background: adminLoading ? "#e5e7eb" : "#0a6ed1",
                              color: adminLoading ? "#9ca3af" : "white",
                              fontSize: 12,
                              fontWeight: 700,
                              cursor: adminLoading ? "default" : "pointer",
                            }}
                          >
                            {adminLoading ? "Saving..." : "Save"}
                          </button>
                          <button
                            onClick={() => setAddingRow(null)}
                            style={{
                              padding: "6px 16px",
                              borderRadius: 8,
                              border: "1px solid #d1d5db",
                              background: "white",
                              fontSize: 12,
                              fontWeight: 600,
                              cursor: "pointer",
                              color: "#374151",
                            }}
                          >
                            Cancel
                          </button>
                        </div>
                      </div>
                    )}

                    <div
                      style={{
                        maxHeight: 320,
                        overflowY: "auto",
                        overflowX: "auto",
                        border: "1px solid #e5e7eb",
                        borderRadius: 8,
                      }}
                    >
                      <table
                        style={{
                          width: "100%",
                          borderCollapse: "collapse",
                          fontSize: 12,
                          minWidth: 700,
                        }}
                      >
                        <thead
                          style={{
                            background: "#f8fafc",
                            position: "sticky",
                            top: 0,
                          }}
                        >
                          <tr>
                            {[
                              "Product",
                              "Run Series",
                              "Description",
                              "Baseline",
                              "Display Order",
                              "Active",
                              "Actions",
                            ].map((h) => (
                              <th
                                key={h}
                                style={{
                                  padding: "8px 12px",
                                  textAlign: "left",
                                  fontSize: 10,
                                  fontWeight: 700,
                                  color: "#6b7280",
                                  textTransform: "uppercase",
                                  borderBottom: "1px solid #e5e7eb",
                                }}
                              >
                                {h}
                              </th>
                            ))}
                          </tr>
                        </thead>
                        <tbody>
                          {[...productRunSeries]
                            .sort(
                              (a, b) =>
                                (a.DisplayOrder || 0) - (b.DisplayOrder || 0),
                            )
                            .map((s, i) => (
                              <tr
                                key={i}
                                style={{
                                  background: i % 2 === 0 ? "#fff" : "#fafafa",
                                }}
                              >
                                {editingRow?.ProductId === s.ProductId &&
                                editingRow?.RunSeries === s.RunSeries &&
                                adminSection === "series" ? (
                                  <>
                                    <td
                                      style={{
                                        padding: "7px 12px",
                                        fontFamily: "monospace",
                                      }}
                                    >
                                      {s.ProductId}
                                    </td>
                                    <td
                                      style={{
                                        padding: "7px 12px",
                                        fontFamily: "monospace",
                                      }}
                                    >
                                      {s.RunSeries}
                                    </td>
                                    <td style={{ padding: "4px 8px" }}>
                                      <input
                                        value={editingRow.Description || ""}
                                        onChange={(e) =>
                                          setEditingRow({
                                            ...editingRow,
                                            Description: e.target.value,
                                          })
                                        }
                                        style={{
                                          width: "100%",
                                          padding: "4px 8px",
                                          borderRadius: 6,
                                          border: "1px solid #d1d5db",
                                          fontSize: 12,
                                        }}
                                      />
                                    </td>
                                    <td style={{ padding: "7px 12px" }}>
                                      {s.IsBaseline === "X" ? "✅" : "—"}
                                    </td>
                                    <td style={{ padding: "4px 8px" }}>
                                      <input
                                        value={editingRow.DisplayOrder || ""}
                                        onChange={(e) =>
                                          setEditingRow({
                                            ...editingRow,
                                            DisplayOrder: e.target.value,
                                          })
                                        }
                                        style={{
                                          width: "100%",
                                          padding: "4px 8px",
                                          borderRadius: 6,
                                          border: "1px solid #d1d5db",
                                          fontSize: 12,
                                        }}
                                      />
                                    </td>
                                    <td style={{ padding: "4px 8px" }}>
                                      <select
                                        value={editingRow.IsActive || ""}
                                        onChange={(e) =>
                                          setEditingRow({
                                            ...editingRow,
                                            IsActive: e.target.value,
                                          })
                                        }
                                        style={{
                                          width: "100%",
                                          padding: "4px 8px",
                                          borderRadius: 6,
                                          border: "1px solid #d1d5db",
                                          fontSize: 12,
                                        }}
                                      >
                                        <option value="">Inactive</option>
                                        <option value="X">Active</option>
                                      </select>
                                    </td>
                                    <td style={{ padding: "4px 8px" }}>
                                      <div style={{ display: "flex", gap: 4 }}>
                                        <button
                                          disabled={adminLoading}
                                          onClick={async () => {
                                            const r = await adminWrite(
                                              "PATCH",
                                              `/ProductRunSeries(ProductId='${s.ProductId}',RunSeries='${s.RunSeries}')`,
                                              {
                                                Description:
                                                  editingRow.Description || "",
                                                IsBaseline:
                                                  editingRow.IsBaseline || "",
                                                DisplayOrder:
                                                  editingRow.DisplayOrder
                                                    ? Number(
                                                        editingRow.DisplayOrder,
                                                      )
                                                    : 0,
                                                IsActive:
                                                  editingRow.IsActive || "",
                                              },
                                            );
                                            if (r.ok) {
                                              setEditingRow(null);
                                              refreshAdminData();
                                            }
                                          }}
                                          style={{
                                            padding: "3px 10px",
                                            borderRadius: 6,
                                            border: "none",
                                            background: "#0a6ed1",
                                            color: "white",
                                            fontSize: 11,
                                            fontWeight: 700,
                                            cursor: "pointer",
                                          }}
                                        >
                                          Save
                                        </button>
                                        <button
                                          onClick={() => setEditingRow(null)}
                                          style={{
                                            padding: "3px 10px",
                                            borderRadius: 6,
                                            border: "1px solid #d1d5db",
                                            background: "white",
                                            fontSize: 11,
                                            cursor: "pointer",
                                            color: "#374151",
                                          }}
                                        >
                                          Cancel
                                        </button>
                                      </div>
                                    </td>
                                  </>
                                ) : (
                                  <>
                                    <td
                                      style={{
                                        padding: "7px 12px",
                                        fontFamily: "monospace",
                                      }}
                                    >
                                      {s.ProductId}
                                    </td>
                                    <td
                                      style={{
                                        padding: "7px 12px",
                                        fontFamily: "monospace",
                                        fontWeight: 600,
                                      }}
                                    >
                                      {s.RunSeries}
                                    </td>
                                    <td
                                      style={{
                                        padding: "7px 12px",
                                        color: "#6b7280",
                                      }}
                                    >
                                      {s.Description || "—"}
                                    </td>
                                    <td style={{ padding: "7px 12px" }}>
                                      {s.IsBaseline === "X" ? "✅" : "—"}
                                    </td>
                                    <td
                                      style={{
                                        padding: "7px 12px",
                                        color: "#6b7280",
                                      }}
                                    >
                                      {s.DisplayOrder || "—"}
                                    </td>
                                    <td style={{ padding: "7px 12px" }}>
                                      {s.IsActive === "X" ? "✅" : "—"}
                                    </td>
                                    <td style={{ padding: "7px 12px" }}>
                                      <div style={{ display: "flex", gap: 4 }}>
                                        <button
                                          onClick={() => {
                                            setEditingRow({ ...s });
                                            setAddingRow(null);
                                          }}
                                          style={{
                                            padding: "3px 10px",
                                            borderRadius: 6,
                                            border: "1px solid #bfdbfe",
                                            background: "#eff6ff",
                                            color: "#0a6ed1",
                                            fontSize: 11,
                                            fontWeight: 600,
                                            cursor: "pointer",
                                          }}
                                        >
                                          Edit
                                        </button>
                                        <button
                                          onClick={async () => {
                                            if (
                                              !window.confirm(
                                                `Delete series ${s.RunSeries}?`,
                                              )
                                            )
                                              return;
                                            const r = await adminWrite(
                                              "DELETE",
                                              `/ProductRunSeries(ProductId='${s.ProductId}',RunSeries='${s.RunSeries}')`,
                                            );
                                            if (r.ok) refreshAdminData();
                                          }}
                                          style={{
                                            padding: "3px 10px",
                                            borderRadius: 6,
                                            border: "1px solid #fecaca",
                                            background: "#fef2f2",
                                            color: "#dc2626",
                                            fontSize: 11,
                                            fontWeight: 600,
                                            cursor: "pointer",
                                          }}
                                        >
                                          Delete
                                        </button>
                                      </div>
                                    </td>
                                  </>
                                )}
                              </tr>
                            ))}
                        </tbody>
                      </table>
                    </div>
                  </div>
                )}

                {/* ── INTEGRATION CONFIG (full CRUD) ── */}
                {adminSection === "config" && (
                  <div>
                    <div
                      style={{
                        display: "flex",
                        justifyContent: "space-between",
                        alignItems: "center",
                        marginBottom: 10,
                      }}
                    >
                      <div style={{ fontSize: 12, color: "#6b7280" }}>
                        {integrationConfig.length} config entries
                      </div>
                      <button
                        onClick={() => {
                          setAddingRow({
                            ProductId: "GLOBAL",
                            ConfigKey: "",
                            ConfigValue: "",
                          });
                          setEditingRow(null);
                        }}
                        style={{
                          padding: "5px 14px",
                          borderRadius: 8,
                          border: "none",
                          background: "#0a6ed1",
                          color: "white",
                          fontSize: 12,
                          fontWeight: 700,
                          cursor: "pointer",
                        }}
                      >
                        + Add Config
                      </button>
                    </div>

                    {addingRow && adminSection === "config" && (
                      <div
                        style={{
                          padding: "14px",
                          background: "#f0f7ff",
                          borderRadius: 10,
                          border: "1px solid #bfdbfe",
                          marginBottom: 12,
                        }}
                      >
                        <div
                          style={{
                            fontSize: 12,
                            fontWeight: 700,
                            color: "#0a6ed1",
                            marginBottom: 10,
                          }}
                        >
                          New Config Entry
                        </div>
                        {[
                          {
                            key: "ProductId",
                            label: "Product ID (use GLOBAL for system-wide)",
                            required: true,
                          },
                          {
                            key: "ConfigKey",
                            label:
                              "Config Key (e.g. JiraBaseUrl, WebGuiBaseUrl)",
                            required: true,
                          },
                          {
                            key: "ConfigValue",
                            label: "Config Value",
                            required: true,
                          },
                        ].map((f) => (
                          <div key={f.key} style={{ marginBottom: 8 }}>
                            <label
                              style={{
                                fontSize: 11,
                                fontWeight: 700,
                                color: "#374151",
                                display: "block",
                                marginBottom: 3,
                              }}
                            >
                              {f.label}
                              {f.required && " *"}
                            </label>
                            <input
                              value={addingRow[f.key] || ""}
                              onChange={(e) =>
                                setAddingRow({
                                  ...addingRow,
                                  [f.key]: e.target.value,
                                })
                              }
                              style={{
                                width: "100%",
                                padding: "7px 10px",
                                borderRadius: 6,
                                border: "1px solid #d1d5db",
                                fontSize: 12,
                                boxSizing: "border-box" as const,
                              }}
                            />
                          </div>
                        ))}
                        <div style={{ display: "flex", gap: 8, marginTop: 10 }}>
                          <button
                            disabled={
                              adminLoading ||
                              !addingRow.ProductId ||
                              !addingRow.ConfigKey ||
                              !addingRow.ConfigValue
                            }
                            onClick={async () => {
                              const r = await adminWrite(
                                "POST",
                                "/IntegrationConfig",
                                {
                                  ProductId: addingRow.ProductId,
                                  ConfigKey: addingRow.ConfigKey,
                                  ConfigValue: addingRow.ConfigValue,
                                },
                              );
                              if (r.ok) {
                                setAddingRow(null);
                                refreshAdminData();
                              }
                            }}
                            style={{
                              padding: "6px 16px",
                              borderRadius: 8,
                              border: "none",
                              background: adminLoading ? "#e5e7eb" : "#0a6ed1",
                              color: adminLoading ? "#9ca3af" : "white",
                              fontSize: 12,
                              fontWeight: 700,
                              cursor: adminLoading ? "default" : "pointer",
                            }}
                          >
                            {adminLoading ? "Saving..." : "Save"}
                          </button>
                          <button
                            onClick={() => setAddingRow(null)}
                            style={{
                              padding: "6px 16px",
                              borderRadius: 8,
                              border: "1px solid #d1d5db",
                              background: "white",
                              fontSize: 12,
                              fontWeight: 600,
                              cursor: "pointer",
                              color: "#374151",
                            }}
                          >
                            Cancel
                          </button>
                        </div>
                      </div>
                    )}

                    <div
                      style={{
                        maxHeight: 240,
                        overflowY: "auto",
                        border: "1px solid #e5e7eb",
                        borderRadius: 8,
                      }}
                    >
                      <table
                        style={{
                          width: "100%",
                          borderCollapse: "collapse",
                          fontSize: 12,
                        }}
                      >
                        <thead
                          style={{
                            background: "#f8fafc",
                            position: "sticky",
                            top: 0,
                          }}
                        >
                          <tr>
                            {[
                              "Product",
                              "Config Key",
                              "Config Value",
                              "Actions",
                            ].map((h) => (
                              <th
                                key={h}
                                style={{
                                  padding: "8px 12px",
                                  textAlign: "left",
                                  fontSize: 10,
                                  fontWeight: 700,
                                  color: "#6b7280",
                                  textTransform: "uppercase",
                                  borderBottom: "1px solid #e5e7eb",
                                }}
                              >
                                {h}
                              </th>
                            ))}
                          </tr>
                        </thead>
                        <tbody>
                          {integrationConfig.map((c, i) => (
                            <tr
                              key={i}
                              style={{
                                background: i % 2 === 0 ? "#fff" : "#fafafa",
                              }}
                            >
                              {editingRow?.ProductId === c.ProductId &&
                              editingRow?.ConfigKey === c.ConfigKey &&
                              adminSection === "config" ? (
                                <>
                                  <td
                                    style={{
                                      padding: "7px 12px",
                                      fontFamily: "monospace",
                                    }}
                                  >
                                    {c.ProductId}
                                  </td>
                                  <td
                                    style={{
                                      padding: "7px 12px",
                                      fontFamily: "monospace",
                                    }}
                                  >
                                    {c.ConfigKey}
                                  </td>
                                  <td style={{ padding: "4px 8px" }}>
                                    <input
                                      value={editingRow.ConfigValue || ""}
                                      onChange={(e) =>
                                        setEditingRow({
                                          ...editingRow,
                                          ConfigValue: e.target.value,
                                        })
                                      }
                                      style={{
                                        width: "100%",
                                        padding: "4px 8px",
                                        borderRadius: 6,
                                        border: "1px solid #d1d5db",
                                        fontSize: 12,
                                      }}
                                    />
                                  </td>
                                  <td style={{ padding: "4px 8px" }}>
                                    <div style={{ display: "flex", gap: 4 }}>
                                      <button
                                        disabled={adminLoading}
                                        onClick={async () => {
                                          const r = await adminWrite(
                                            "PATCH",
                                            `/IntegrationConfig(ProductId='${c.ProductId}',ConfigKey='${c.ConfigKey}')`,
                                            {
                                              ConfigValue:
                                                editingRow.ConfigValue,
                                            },
                                          );
                                          if (r.ok) {
                                            setEditingRow(null);
                                            refreshAdminData();
                                          }
                                        }}
                                        style={{
                                          padding: "3px 10px",
                                          borderRadius: 6,
                                          border: "none",
                                          background: "#0a6ed1",
                                          color: "white",
                                          fontSize: 11,
                                          fontWeight: 700,
                                          cursor: "pointer",
                                        }}
                                      >
                                        Save
                                      </button>
                                      <button
                                        onClick={() => setEditingRow(null)}
                                        style={{
                                          padding: "3px 10px",
                                          borderRadius: 6,
                                          border: "1px solid #d1d5db",
                                          background: "white",
                                          fontSize: 11,
                                          cursor: "pointer",
                                          color: "#374151",
                                        }}
                                      >
                                        Cancel
                                      </button>
                                    </div>
                                  </td>
                                </>
                              ) : (
                                <>
                                  <td
                                    style={{
                                      padding: "7px 12px",
                                      fontFamily: "monospace",
                                    }}
                                  >
                                    {c.ProductId}
                                  </td>
                                  <td
                                    style={{
                                      padding: "7px 12px",
                                      fontFamily: "monospace",
                                      fontWeight: 600,
                                    }}
                                  >
                                    {c.ConfigKey}
                                  </td>
                                  <td
                                    style={{
                                      padding: "7px 12px",
                                      color: "#6b7280",
                                      wordBreak: "break-all",
                                    }}
                                  >
                                    {c.ConfigValue}
                                  </td>
                                  <td style={{ padding: "7px 12px" }}>
                                    <div style={{ display: "flex", gap: 4 }}>
                                      <button
                                        onClick={() => {
                                          setEditingRow({ ...c });
                                          setAddingRow(null);
                                        }}
                                        style={{
                                          padding: "3px 10px",
                                          borderRadius: 6,
                                          border: "1px solid #bfdbfe",
                                          background: "#eff6ff",
                                          color: "#0a6ed1",
                                          fontSize: 11,
                                          fontWeight: 600,
                                          cursor: "pointer",
                                        }}
                                      >
                                        Edit
                                      </button>
                                      <button
                                        onClick={async () => {
                                          if (
                                            !window.confirm(
                                              `Delete config ${c.ConfigKey}?`,
                                            )
                                          )
                                            return;
                                          const r = await adminWrite(
                                            "DELETE",
                                            `/IntegrationConfig(ProductId='${c.ProductId}',ConfigKey='${c.ConfigKey}')`,
                                          );
                                          if (r.ok) refreshAdminData();
                                        }}
                                        style={{
                                          padding: "3px 10px",
                                          borderRadius: 6,
                                          border: "1px solid #fecaca",
                                          background: "#fef2f2",
                                          color: "#dc2626",
                                          fontSize: 11,
                                          fontWeight: 600,
                                          cursor: "pointer",
                                        }}
                                      >
                                        Delete
                                      </button>
                                    </div>
                                  </td>
                                </>
                              )}
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>
                )}
              </div>
            )}

            <div
              style={{
                display: "flex",
                justifyContent: "flex-end",
                marginTop: 8,
              }}
            >
              <button
                onClick={() => setSettingsOpen(false)}
                style={{
                  padding: "10px 24px",
                  borderRadius: 8,
                  border: "none",
                  background: "#0a6ed1",
                  color: "white",
                  fontSize: 13,
                  fontWeight: 700,
                  cursor: "pointer",
                }}
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ── TABS ── */}
      <div className="tabs">
        {[
          { key: "overview", label: "Overview" },
          { key: "runs", label: "Run Explorer" },
          { key: "quality", label: "Code Quality" },
          { key: "developer", label: "👥 Developer Hub" },
          { key: "security", label: "🔐 Security" },
          { key: "certification", label: "🏆 Certification" },
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
        {/* ── FILTER PANEL ── */}
        <div className="filter-sticky">
          <div className="filter-card-premium" style={{ padding: "10px 16px" }}>
            <div
              className="filter-header-premium"
              style={{ marginBottom: collapsed ? 0 : 8 }}
            >
              <div>
                <h3 style={{ fontSize: 13, margin: 0 }}>Filter Runs</h3>
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
                <div
                  style={{
                    display: "grid",
                    gridTemplateColumns: "repeat(7,1fr)",
                    gap: "8px 12px",
                    alignItems: "end",
                  }}
                >
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
                    display: "flex",
                    flexWrap: "wrap",
                    alignItems: "center",
                    gap: "16px",
                    marginTop: "12px",
                    paddingTop: "12px",
                    borderTop: "1px solid #e5e7eb",
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
                <div style={{ display: "flex", gap: 8, marginLeft: "auto" }}>
                  <button className="btn-primary" onClick={() => load(filters)}>
                    GO
                  </button>
                  <button
                    className="btn-secondary"
                    onClick={() => {
                      const r = {
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
                      };
                      setFilters(r);
                      load(r);
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
        {/* ── KPI CARDS ── */}
        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(4,1fr)",
            gap: 10,
            marginBottom: 16,
          }}
        >
          {[
            { title: "TOTAL RUNS", value: totalRuns, cls: "blue-text" },
            {
              title: "CRITICAL (P1)",
              value: totalP1,
              cls: "red-text",
            },
            {
              title: "WARNINGS (P2)",
              value: totalP2,
              cls: "orange-text",
            },
            {
              title: "HEALTH SCORE",
              value: `${healthScore}%`,
              cls: "green-text",
            },
          ].map((k, i) => (
            <div
              key={i}
              style={{
                background: "var(--card-bg,#fff)",
                borderRadius: 10,
                padding: "10px 16px",
                border: "1px solid #e5e7eb",
                display: "flex",
                alignItems: "center",
                justifyContent: "space-between",
              }}
            >
              <div
                style={{
                  fontSize: 10,
                  fontWeight: 700,
                  color: "#6b7280",
                  textTransform: "uppercase",
                  letterSpacing: 0.5,
                }}
              >
                {k.title}
              </div>
              <div
                className={`kpi-value ${k.cls}`}
                style={{ fontSize: 22, margin: 0 }}
              >
                {k.value}
              </div>
            </div>
          ))}
        </div>

        {/* ── RUN SELECTOR BANNER ── */}
        {(tab === "quality" || tab === "security" || tab === "developer") && (
          <div
            style={{
              display: "flex",
              alignItems: "center",
              justifyContent: "space-between",
              flexWrap: "wrap",
              gap: 10,
              padding: "10px 16px",
              marginBottom: 16,
              background: selectedRun
                ? "linear-gradient(135deg,#eff6ff,#f0fdf4)"
                : "#fefce8",
              border: `1px solid ${selectedRun ? "#bfdbfe" : "#fde047"}`,
              borderRadius: 10,
            }}
          >
            {selectedRun ? (
              <>
                <div
                  style={{
                    display: "flex",
                    alignItems: "center",
                    gap: 10,
                    flexWrap: "wrap",
                  }}
                >
                  <span
                    style={{
                      fontSize: 11,
                      fontWeight: 700,
                      color: "#6b7280",
                      letterSpacing: 0.5,
                    }}
                  >
                    ANALYZING RUN
                  </span>
                  <span
                    style={{ fontSize: 13, fontWeight: 700, color: "#111827" }}
                  >
                    {selectedRun.title || selectedRun.series || selectedRun.ID}
                  </span>
                  <span
                    style={{
                      fontSize: 10,
                      fontWeight: 700,
                      padding: "2px 8px",
                      borderRadius: 999,
                      background:
                        selectedRun.RunKind === "C" ? "#dcfce7" : "#dbeafe",
                      color:
                        selectedRun.RunKind === "C" ? "#15803d" : "#1e40af",
                    }}
                  >
                    {selectedRun.RunKind === "C"
                      ? "Code Inspector"
                      : selectedRun.RunKind === "M"
                        ? "Checkman"
                        : "—"}
                  </span>
                  <span style={{ fontSize: 11, color: "#6b7280" }}>
                    {selectedRun.date} · {selectedRun.system}
                    {findingsLoading && (
                      <span
                        style={{
                          marginLeft: 8,
                          color: "#3b82f6",
                          fontWeight: 600,
                        }}
                      >
                        · Loading...{" "}
                        {findings.length > 0
                          ? `${findings.length.toLocaleString()} loaded`
                          : ""}
                      </span>
                    )}
                    {!findingsLoading && findings.length > 0 && (
                      <span
                        style={{
                          marginLeft: 8,
                          color: "#16a34a",
                          fontWeight: 600,
                        }}
                      >
                        · {findings.length.toLocaleString()} findings loaded
                      </span>
                    )}
                  </span>
                </div>
                <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                  {[
                    { l: "P1", v: selectedRun.p1, c: "#dc2626", b: "#fee2e2" },
                    { l: "P2", v: selectedRun.p2, c: "#d97706", b: "#fef3c7" },
                    { l: "P3", v: selectedRun.p3, c: "#2563eb", b: "#dbeafe" },
                    {
                      l: "P4",
                      v: selectedRun.p4 ?? 0,
                      c: "#374151",
                      b: "#f3f4f6",
                    },
                  ].map((p) => (
                    <span
                      key={p.l}
                      style={{
                        background: p.b,
                        color: p.c,
                        borderRadius: 999,
                        padding: "2px 8px",
                        fontSize: 11,
                        fontWeight: 700,
                      }}
                    >
                      {p.l}:{p.v}
                    </span>
                  ))}
                  <button
                    onClick={() => setTab("runs")}
                    style={{
                      padding: "4px 12px",
                      borderRadius: 6,
                      border: "1px solid #d1d5db",
                      background: "white",
                      fontSize: 11,
                      fontWeight: 600,
                      cursor: "pointer",
                      color: "#374151",
                    }}
                  >
                    Change Run →
                  </button>
                </div>
              </>
            ) : (
              <div
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: 10,
                  width: "100%",
                }}
              >
                <span style={{ fontSize: 13, color: "#713f12" }}>
                  ⚠️ No run selected — go to <strong>Run Explorer</strong> and
                  click any run to load findings.
                </span>
                <button
                  onClick={() => setTab("runs")}
                  style={{
                    marginLeft: "auto",
                    padding: "5px 14px",
                    borderRadius: 6,
                    border: "none",
                    background: "#0a6ed1",
                    color: "white",
                    fontSize: 12,
                    fontWeight: 600,
                    cursor: "pointer",
                    flexShrink: 0,
                  }}
                >
                  Go to Run Explorer
                </button>
              </div>
            )}
          </div>
        )}

        {/* ════ OVERVIEW TAB ════ */}
        {tab === "overview" && (
          <div style={{ display: "flex", flexDirection: "column", gap: 20 }}>
            {/* Panel 1 — System Health Snapshot */}
            <div
              style={{
                background: "var(--card-bg,#fff)",
                borderRadius: 12,
                boxShadow: "0 1px 4px rgba(0,0,0,0.06)",
                border: "1px solid #e5e7eb",
                overflow: "hidden",
              }}
            >
              <div
                style={{
                  padding: "18px 20px 14px",
                  borderBottom: "1px solid #f3f4f6",
                }}
              >
                <div
                  style={{
                    fontSize: 10,
                    fontWeight: 700,
                    color: "#0a6ed1",
                    letterSpacing: 1,
                    textTransform: "uppercase",
                    marginBottom: 4,
                  }}
                >
                  System Intelligence
                </div>
                <div
                  style={{ fontSize: 16, fontWeight: 700, color: "#0f172a" }}
                >
                  System Health Snapshot
                </div>
                <div style={{ fontSize: 12, color: "#6b7280", marginTop: 2 }}>
                  Latest run per series — Δ P1 shows change vs previous run ·
                  Direction from last 3 runs
                </div>
              </div>
              {systemHealthSnapshot.length === 0 ? (
                <div
                  style={{
                    padding: "32px 20px",
                    textAlign: "center",
                    color: "#9ca3af",
                    fontSize: 13,
                  }}
                >
                  No run data available.
                </div>
              ) : (
                <div style={{ overflowX: "auto" }}>
                  <table style={{ width: "100%", borderCollapse: "collapse" }}>
                    <thead style={tH}>
                      <tr>
                        <th style={tTh}>Status</th>
                        <th style={tTh}>Run Series</th>
                        <th style={tTh}>System</th>
                        <th style={{ ...tTh, textAlign: "right" }}>P1</th>
                        <th style={{ ...tTh, textAlign: "right" }}>P2</th>
                        <th style={{ ...tTh, textAlign: "right" }}>P3</th>
                        <th style={{ ...tTh, textAlign: "right" }}>
                          Δ P1 vs Last Run
                        </th>
                        <th style={tTh}>Direction</th>
                        <th style={{ ...tTh, textAlign: "right" }}>
                          Days Since Run
                        </th>
                        <th style={{ ...tTh, textAlign: "right" }}>Runs</th>
                      </tr>
                    </thead>
                    <tbody>
                      {systemHealthSnapshot.map((row, i) => {
                        const trajColor =
                          row.trajectory === "Deteriorating" ||
                          row.trajectory === "Worsening"
                            ? "#dc2626"
                            : row.trajectory === "Improving" ||
                                row.trajectory === "Recovering"
                              ? "#15803d"
                              : "#6b7280";
                        const trajBg =
                          row.trajectory === "Deteriorating" ||
                          row.trajectory === "Worsening"
                            ? "#fee2e2"
                            : row.trajectory === "Improving" ||
                                row.trajectory === "Recovering"
                              ? "#dcfce7"
                              : "#f3f4f6";
                        const trajIcon =
                          row.trajectory === "Deteriorating"
                            ? "📉 "
                            : row.trajectory === "Worsening"
                              ? "⚠️ "
                              : row.trajectory === "Improving"
                                ? "📈 "
                                : row.trajectory === "Recovering"
                                  ? "↗️ "
                                  : row.trajectory === "Single Run"
                                    ? "🔹 "
                                    : "➡️ ";
                        return (
                          <tr
                            key={i}
                            style={{
                              background: i % 2 === 0 ? "#fff" : "#fafafa",
                            }}
                          >
                            <td style={{ ...tTd, width: 40 }}>
                              {tl(row.light)}
                            </td>
                            <td
                              style={{
                                ...tTd,
                                fontWeight: 600,
                                color: "#111827",
                              }}
                            >
                              {row.series}
                            </td>
                            <td style={tTd}>{row.latest.system || "—"}</td>
                            <td style={tTdR}>{pb(1, row.latest.p1)}</td>
                            <td style={tTdR}>{pb(2, row.latest.p2)}</td>
                            <td style={tTdR}>{pb(3, row.latest.p3)}</td>
                            <td style={tTdR}>
                              {row.p1Delta === null ? (
                                <span
                                  style={{ color: "#9ca3af", fontSize: 11 }}
                                >
                                  First run
                                </span>
                              ) : row.p1Delta === 0 ? (
                                <span
                                  style={{
                                    color: "#6b7280",
                                    fontSize: 11,
                                    fontWeight: 600,
                                  }}
                                >
                                  No change
                                </span>
                              ) : (
                                <span
                                  style={{
                                    background:
                                      row.p1Delta > 0 ? "#fee2e2" : "#dcfce7",
                                    color:
                                      row.p1Delta > 0 ? "#dc2626" : "#15803d",
                                    borderRadius: 999,
                                    padding: "2px 8px",
                                    fontSize: 11,
                                    fontWeight: 700,
                                  }}
                                >
                                  {row.p1Delta > 0
                                    ? `+${row.p1Delta}`
                                    : row.p1Delta}{" "}
                                  P1
                                </span>
                              )}
                            </td>
                            <td style={tTd}>
                              <span
                                style={{
                                  background: trajBg,
                                  color: trajColor,
                                  borderRadius: 6,
                                  padding: "3px 9px",
                                  fontSize: 11,
                                  fontWeight: 600,
                                  whiteSpace: "nowrap",
                                }}
                              >
                                {trajIcon}
                                {row.trajectory}
                              </span>
                            </td>
                            <td
                              style={{
                                ...tTdR,
                                color:
                                  (row.daysSince ?? 0) > 14
                                    ? "#d97706"
                                    : "#374151",
                                fontWeight:
                                  (row.daysSince ?? 0) > 14 ? 600 : 400,
                              }}
                            >
                              {row.daysSince !== null
                                ? `${row.daysSince}d`
                                : "—"}
                            </td>
                            <td style={tTdR}>{row.runCount}</td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
            {/* Panels 2+3 */}
            <div
              style={{
                display: "grid",
                gridTemplateColumns: isMobile ? "1fr" : "1fr 1fr",
                gap: 20,
              }}
            >
              <div
                style={{
                  background: "var(--card-bg,#fff)",
                  borderRadius: 12,
                  boxShadow: "0 1px 4px rgba(0,0,0,0.06)",
                  border: "1px solid #e5e7eb",
                  padding: "18px 20px",
                }}
              >
                <div
                  style={{
                    fontSize: 10,
                    fontWeight: 700,
                    color: "#0a6ed1",
                    letterSpacing: 1,
                    textTransform: "uppercase",
                    marginBottom: 4,
                  }}
                >
                  Interpreted Signals
                </div>
                <div
                  style={{
                    fontSize: 16,
                    fontWeight: 700,
                    color: "#0f172a",
                    marginBottom: 4,
                  }}
                >
                  What Needs Attention Now
                </div>
                <div
                  style={{ fontSize: 12, color: "#6b7280", marginBottom: 16 }}
                >
                  Spikes, stale runs, and deteriorating series
                </div>
                {attentionAlerts.length === 0 ? (
                  <div
                    style={{
                      padding: "20px 16px",
                      background: "#f0fdf4",
                      borderRadius: 10,
                      border: "1px solid #bbf7d0",
                      borderLeft: "4px solid #22c55e",
                    }}
                  >
                    <div
                      style={{
                        fontSize: 13,
                        fontWeight: 700,
                        color: "#15803d",
                      }}
                    >
                      ✅ No attention items
                    </div>
                    <div
                      style={{ fontSize: 12, color: "#166534", marginTop: 3 }}
                    >
                      All series are stable within the current filter period.
                    </div>
                  </div>
                ) : (
                  <div
                    style={{
                      display: "flex",
                      flexDirection: "column",
                      gap: 10,
                    }}
                  >
                    {attentionAlerts.map((a, i) => (
                      <div
                        key={i}
                        style={{
                          padding: "12px 14px",
                          background:
                            a.severity === "red"
                              ? "#fef2f2"
                              : a.severity === "amber"
                                ? "#fffbeb"
                                : "#eff6ff",
                          borderRadius: 8,
                          borderLeft: `4px solid ${a.severity === "red" ? "#ef4444" : a.severity === "amber" ? "#f59e0b" : "#3b82f6"}`,
                        }}
                      >
                        <div
                          style={{
                            fontSize: 13,
                            fontWeight: 700,
                            color:
                              a.severity === "red"
                                ? "#dc2626"
                                : a.severity === "amber"
                                  ? "#d97706"
                                  : "#2563eb",
                          }}
                        >
                          {a.severity === "red"
                            ? "🔴"
                            : a.severity === "amber"
                              ? "🟡"
                              : "🔵"}{" "}
                          {a.text}
                        </div>
                        <div
                          style={{
                            fontSize: 12,
                            color: "#374151",
                            marginTop: 3,
                          }}
                        >
                          {a.detail}
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
              <div
                style={{
                  background: "var(--card-bg,#fff)",
                  borderRadius: 12,
                  boxShadow: "0 1px 4px rgba(0,0,0,0.06)",
                  border: "1px solid #e5e7eb",
                  padding: "18px 20px",
                }}
              >
                <div
                  style={{
                    fontSize: 10,
                    fontWeight: 700,
                    color: "#0a6ed1",
                    letterSpacing: 1,
                    textTransform: "uppercase",
                    marginBottom: 4,
                  }}
                >
                  Period Comparison
                </div>
                <div
                  style={{
                    fontSize: 16,
                    fontWeight: 700,
                    color: "#0f172a",
                    marginBottom: 4,
                  }}
                >
                  This Week vs Last Week
                </div>
                <div
                  style={{ fontSize: 12, color: "#6b7280", marginBottom: 20 }}
                >
                  Numbers with context
                </div>
                {!weekComparison.hasLast ? (
                  <div
                    style={{
                      padding: "16px",
                      background: "#f9fafb",
                      borderRadius: 8,
                      border: "1px solid #e5e7eb",
                      fontSize: 12,
                      color: "#6b7280",
                    }}
                  >
                    Not enough data for week-over-week comparison in the current
                    filter window.
                  </div>
                ) : (
                  <div
                    style={{
                      display: "grid",
                      gridTemplateColumns: "1fr 1fr 1fr",
                      gap: 0,
                      borderRadius: 10,
                      overflow: "hidden",
                      border: "1px solid #e5e7eb",
                    }}
                  >
                    {[
                      {
                        label: "P1 Critical",
                        this: weekComparison.thisP1,
                        last: weekComparison.lastP1,
                        color: "#dc2626",
                      },
                      {
                        label: "P2 Warning",
                        this: weekComparison.thisP2,
                        last: weekComparison.lastP2,
                        color: "#d97706",
                      },
                      {
                        label: "Runs Executed",
                        this: weekComparison.thisRuns,
                        last: weekComparison.lastRuns,
                        color: "#0a6ed1",
                      },
                    ].map((item, i) => (
                      <div
                        key={i}
                        style={{
                          padding: "16px 12px",
                          background: "#fafafa",
                          borderRight: i < 2 ? "1px solid #e5e7eb" : "none",
                        }}
                      >
                        <div
                          style={{
                            fontSize: 10,
                            fontWeight: 700,
                            color: "#6b7280",
                            textTransform: "uppercase",
                            letterSpacing: 0.5,
                            marginBottom: 8,
                          }}
                        >
                          {item.label}
                        </div>
                        <div
                          style={{
                            fontSize: 22,
                            fontWeight: 800,
                            color: item.color,
                          }}
                        >
                          {item.this}
                        </div>
                        <div
                          style={{
                            fontSize: 11,
                            color: "#9ca3af",
                            marginTop: 2,
                          }}
                        >
                          Last week: {item.last}
                        </div>
                        <div style={{ marginTop: 8 }}>
                          {dc(item.this, item.last)}
                        </div>
                      </div>
                    ))}
                    <div
                      style={{
                        gridColumn: "1/-1",
                        padding: "12px 14px",
                        borderTop: "1px solid #e5e7eb",
                        background: "#fff",
                        fontSize: 12,
                        color: "#374151",
                        lineHeight: 1.6,
                      }}
                    >
                      {weekComparison.thisP1 > weekComparison.lastP1 ? (
                        <>
                          <strong style={{ color: "#dc2626" }}>
                            P1 findings increased
                          </strong>{" "}
                          by {weekComparison.thisP1 - weekComparison.lastP1}{" "}
                          this week.
                        </>
                      ) : weekComparison.thisP1 < weekComparison.lastP1 ? (
                        <>
                          <strong style={{ color: "#15803d" }}>
                            P1 findings decreased
                          </strong>{" "}
                          by {weekComparison.lastP1 - weekComparison.thisP1}{" "}
                          this week.
                        </>
                      ) : (
                        <>
                          P1 findings are <strong>stable</strong>{" "}
                          week-over-week.
                        </>
                      )}
                    </div>
                  </div>
                )}
              </div>
            </div>
            {/* Panel 4 — Run Quality Leaderboard (all runs, no findings dependency) */}
            <div
              style={{
                background: "var(--card-bg,#fff)",
                borderRadius: 12,
                boxShadow: "0 1px 4px rgba(0,0,0,0.06)",
                border: "1px solid #e5e7eb",
                overflow: "hidden",
              }}
            >
              <div
                style={{
                  padding: "18px 20px 14px",
                  borderBottom: "1px solid #f3f4f6",
                }}
              >
                <div
                  style={{
                    fontSize: 10,
                    fontWeight: 700,
                    color: "#0a6ed1",
                    letterSpacing: 1,
                    textTransform: "uppercase",
                    marginBottom: 4,
                  }}
                >
                  Run Quality Intelligence
                </div>
                <div
                  style={{ fontSize: 16, fontWeight: 700, color: "#0f172a" }}
                >
                  Run Quality Leaderboard
                </div>
                <div style={{ fontSize: 12, color: "#6b7280", marginTop: 2 }}>
                  {filteredRuns.length > 0
                    ? `Top 10 highest-risk runs from all ${filteredRuns.length} runs in the current filter — click Inspect to drill in`
                    : "No runs in current filter window"}
                </div>
              </div>
              {topRiskRunsSummary.length === 0 ? (
                <div
                  style={{
                    padding: "32px 20px",
                    textAlign: "center",
                    color: "#9ca3af",
                    fontSize: 13,
                  }}
                >
                  No runs available. Adjust your filter period or refresh.
                </div>
              ) : (
                <div style={{ overflowX: "auto" }}>
                  <table style={{ width: "100%", borderCollapse: "collapse" }}>
                    <thead style={tH}>
                      <tr>
                        <th style={tTh}>Run Series</th>
                        <th style={tTh}>System</th>
                        <th style={tTh}>Run Date</th>
                        <th style={tTh}>Source</th>
                        <th style={{ ...tTh, textAlign: "right" }}>P1</th>
                        <th style={{ ...tTh, textAlign: "right" }}>P2</th>
                        <th style={{ ...tTh, textAlign: "right" }}>P3</th>
                        <th style={{ ...tTh, textAlign: "right" }}>Total</th>
                        <th style={{ ...tTh, textAlign: "right" }}>Q-Score</th>
                        <th style={tTh} />
                      </tr>
                    </thead>
                    <tbody>
                      {topRiskRunsSummary.map((r, i) => {
                        const sc =
                          r.score >= 70
                            ? "#15803d"
                            : r.score >= 50
                              ? "#d97706"
                              : "#dc2626";
                        const sb2 =
                          r.score >= 70
                            ? "#f0fdf4"
                            : r.score >= 50
                              ? "#fffbeb"
                              : "#fee2e2";
                        return (
                          <tr
                            key={i}
                            style={{
                              background: i % 2 === 0 ? "#fff" : "#fafafa",
                            }}
                          >
                            <td
                              style={{
                                ...tTd,
                                fontWeight: 600,
                                color: "#111827",
                                maxWidth: 180,
                                overflow: "hidden",
                                textOverflow: "ellipsis",
                                whiteSpace: "nowrap",
                              }}
                            >
                              {r.series || r.title || "—"}
                            </td>
                            <td
                              style={{ ...tTd, fontSize: 11, color: "#6b7280" }}
                            >
                              {r.system || "—"}
                            </td>
                            <td
                              style={{
                                ...tTd,
                                fontSize: 11,
                                color: "#374151",
                                whiteSpace: "nowrap",
                              }}
                            >
                              {r.date || "—"}
                            </td>
                            <td style={tTd}>
                              {r.RunKind === "C" ? (
                                <span
                                  style={{
                                    background: "#dcfce7",
                                    color: "#15803d",
                                    borderRadius: 999,
                                    padding: "1px 7px",
                                    fontSize: 10,
                                    fontWeight: 700,
                                  }}
                                >
                                  Code Inspector
                                </span>
                              ) : r.RunKind === "M" ? (
                                <span
                                  style={{
                                    background: "#dbeafe",
                                    color: "#1e40af",
                                    borderRadius: 999,
                                    padding: "1px 7px",
                                    fontSize: 10,
                                    fontWeight: 700,
                                  }}
                                >
                                  Checkman
                                </span>
                              ) : (
                                <span
                                  style={{ color: "#9ca3af", fontSize: 11 }}
                                >
                                  —
                                </span>
                              )}
                            </td>
                            <td style={tTdR}>{pb(1, r.p1)}</td>
                            <td style={tTdR}>{pb(2, r.p2)}</td>
                            <td style={tTdR}>{pb(3, r.p3)}</td>
                            <td
                              style={{
                                ...tTdR,
                                fontWeight: 700,
                                color: "#111827",
                              }}
                            >
                              {r.total.toLocaleString()}
                            </td>
                            <td style={tTdR}>
                              <span
                                style={{
                                  background: sb2,
                                  color: sc,
                                  borderRadius: 6,
                                  padding: "2px 8px",
                                  fontSize: 11,
                                  fontWeight: 700,
                                }}
                              >
                                {r.score}
                              </span>
                            </td>
                            <td style={{ ...tTd, textAlign: "right" }}>
                              <button
                                onClick={() => {
                                  setSelectedRun(r);
                                  fetchFindings(r.ID);
                                  fetchAssignments(r);
                                  setTab("quality");
                                }}
                                style={{
                                  padding: "4px 10px",
                                  borderRadius: 6,
                                  border: "1px solid #bfdbfe",
                                  background: "#eff6ff",
                                  color: "#0a6ed1",
                                  fontSize: 11,
                                  fontWeight: 700,
                                  cursor: "pointer",
                                  whiteSpace: "nowrap",
                                }}
                              >
                                Inspect →
                              </button>
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </div>
        )}

        {/* ════ CODE QUALITY TAB ════ */}
        {tab === "quality" && (
          <div style={{ display: "flex", flexDirection: "column", gap: 20 }}>
            {/* PDF Export button */}
            <div style={{ display: "flex", justifyContent: "flex-end" }}>
              <button
                onClick={generateCodeQualityPdf}
                disabled={findings.length === 0 || !selectedRun}
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: 8,
                  padding: "10px 20px",
                  borderRadius: 10,
                  border: "none",
                  cursor:
                    findings.length === 0 || !selectedRun
                      ? "default"
                      : "pointer",
                  background:
                    findings.length === 0 || !selectedRun
                      ? "#f3f4f6"
                      : "linear-gradient(135deg,#0a6ed1,#0369a1)",
                  color:
                    findings.length === 0 || !selectedRun ? "#9ca3af" : "white",
                  fontSize: 13,
                  fontWeight: 700,
                }}
              >
                📄 Export Code Quality Report PDF
              </button>
            </div>
            {/* Block 1 — Run Summary */}
            <div
              style={{
                background: "var(--card-bg,#fff)",
                borderRadius: 12,
                boxShadow: "0 1px 4px rgba(0,0,0,0.06)",
                border: `2px solid ${qualityScore === null ? "#e5e7eb" : qualityScore >= 70 ? "#22c55e" : qualityScore >= 50 ? "#f59e0b" : "#ef4444"}`,
                padding: "20px 24px",
              }}
            >
              <div
                style={{
                  fontSize: 10,
                  fontWeight: 700,
                  color: "#0a6ed1",
                  letterSpacing: 1,
                  textTransform: "uppercase",
                  marginBottom: 4,
                }}
              >
                Run Assessment
              </div>
              <div
                style={{
                  fontSize: 16,
                  fontWeight: 700,
                  color: "#0f172a",
                  marginBottom: 14,
                }}
              >
                Run Summary
              </div>
              {!selectedRun ? (
                <div style={{ fontSize: 13, color: "#6b7280" }}>
                  No run selected. Go to Run Explorer and click a run to begin
                  analysis.
                </div>
              ) : (
                <>
                  <div
                    style={{
                      display: "grid",
                      gridTemplateColumns: isMobile
                        ? "1fr 1fr"
                        : "repeat(5,1fr)",
                      gap: 12,
                      marginBottom: 16,
                    }}
                  >
                    {[
                      {
                        label: "Quality Score",
                        value: qualityScore !== null ? `${qualityScore}` : "—",
                        sub:
                          qualityDelta !== null
                            ? qualityDelta >= 0
                              ? `+${qualityDelta} vs prev`
                              : `${qualityDelta} vs prev`
                            : "No prev run",
                        color:
                          qualityScore === null
                            ? "#9ca3af"
                            : qualityScore >= 70
                              ? "#15803d"
                              : qualityScore >= 50
                                ? "#d97706"
                                : "#dc2626",
                        bg:
                          qualityScore === null
                            ? "#f9fafb"
                            : qualityScore >= 70
                              ? "#f0fdf4"
                              : qualityScore >= 50
                                ? "#fffbeb"
                                : "#fef2f2",
                      },
                      {
                        label: "P1 Critical",
                        value: selectedRun.p1.toLocaleString(),
                        sub: "Blocking",
                        color: "#dc2626",
                        bg: "#fee2e2",
                      },
                      {
                        label: "P2 Warning",
                        value: selectedRun.p2.toLocaleString(),
                        sub: "High priority",
                        color: "#d97706",
                        bg: "#fef3c7",
                      },
                      {
                        label: "P3 Info",
                        value: selectedRun.p3.toLocaleString(),
                        sub: "Informational",
                        color: "#2563eb",
                        bg: "#dbeafe",
                      },
                      {
                        label: "P4 Note",
                        value: (selectedRun.p4 ?? 0).toLocaleString(),
                        sub: "Advisory",
                        color: "#6b7280",
                        bg: "#f3f4f6",
                      },
                    ].map((item, i) => (
                      <div
                        key={i}
                        style={{
                          background: item.bg,
                          borderRadius: 10,
                          padding: "14px 12px",
                          textAlign: "center",
                        }}
                      >
                        <div
                          style={{
                            fontSize: 10,
                            fontWeight: 700,
                            color: "#6b7280",
                            textTransform: "uppercase",
                            letterSpacing: 0.5,
                          }}
                        >
                          {item.label}
                        </div>
                        <div
                          style={{
                            fontSize: 26,
                            fontWeight: 800,
                            color: item.color,
                            margin: "6px 0 2px",
                          }}
                        >
                          {item.value}
                        </div>
                        <div style={{ fontSize: 11, color: "#9ca3af" }}>
                          {item.sub}
                        </div>
                      </div>
                    ))}
                  </div>
                  <div
                    style={{
                      padding: "14px 16px",
                      background: "#f8fafc",
                      borderRadius: 10,
                      border: "1px solid #e5e7eb",
                      fontSize: 13,
                      lineHeight: 1.7,
                      color: "#374151",
                    }}
                  >
                    {(() => {
                      const total =
                        selectedRun.p1 +
                        selectedRun.p2 +
                        selectedRun.p3 +
                        (selectedRun.p4 ?? 0);
                      const dir =
                        qualityDelta === null
                          ? null
                          : qualityDelta > 0
                            ? "improving"
                            : qualityDelta < 0
                              ? "deteriorating"
                              : "stable";
                      return (
                        <>
                          {`This run has `}
                          <strong style={{ color: "#111827" }}>
                            {total.toLocaleString()} findings
                          </strong>
                          {qualityDelta !== null && (
                            <>
                              {` and quality is `}
                              <strong
                                style={{
                                  color:
                                    dir === "improving"
                                      ? "#15803d"
                                      : dir === "deteriorating"
                                        ? "#dc2626"
                                        : "#6b7280",
                                }}
                              >
                                {dir}
                              </strong>
                              {` by ${Math.abs(qualityDelta)} points vs previous run in this series`}
                            </>
                          )}
                          {"."}{" "}
                          {selectedRun.p1 > 0 ? (
                            <>
                              <strong style={{ color: "#dc2626" }}>
                                {selectedRun.p1} P1 critical findings
                              </strong>{" "}
                              require immediate attention.
                            </>
                          ) : (
                            <>
                              <strong style={{ color: "#15803d" }}>
                                No P1 critical findings
                              </strong>{" "}
                              — P1 gate is clear.
                            </>
                          )}{" "}
                          {slaIntelligence.over90 > 0 && (
                            <>
                              <strong style={{ color: "#dc2626" }}>
                                {slaIntelligence.over90} findings
                              </strong>{" "}
                              have been open for more than 90 days.
                            </>
                          )}
                        </>
                      );
                    })()}
                  </div>
                </>
              )}
            </div>
            {/* Block 2 — By Category */}
            <div
              style={{
                background: "var(--card-bg,#fff)",
                borderRadius: 12,
                boxShadow: "0 1px 4px rgba(0,0,0,0.06)",
                border: "1px solid #e5e7eb",
                overflow: "hidden",
              }}
            >
              <div
                style={{
                  padding: "18px 20px 14px",
                  borderBottom: "1px solid #f3f4f6",
                }}
              >
                <div
                  style={{
                    fontSize: 10,
                    fontWeight: 700,
                    color: "#0a6ed1",
                    letterSpacing: 1,
                    textTransform: "uppercase",
                    marginBottom: 4,
                  }}
                >
                  Check Analysis
                </div>
                <div
                  style={{ fontSize: 16, fontWeight: 700, color: "#0f172a" }}
                >
                  Finding Breakdown by Check Category
                </div>
                <div style={{ fontSize: 12, color: "#6b7280", marginTop: 2 }}>
                  {findings.length > 0
                    ? `${findings.length.toLocaleString()} findings · ${findingsByCategory.length} check categories`
                    : "Open a run to populate"}
                </div>
              </div>
              {findingsByCategory.length === 0 ? (
                <div
                  style={{
                    padding: "32px 20px",
                    textAlign: "center",
                    color: "#9ca3af",
                    fontSize: 13,
                  }}
                >
                  No findings loaded. Select a run in Run Explorer.
                </div>
              ) : (
                <div style={{ overflowX: "auto" }}>
                  <table style={{ width: "100%", borderCollapse: "collapse" }}>
                    <thead style={tH}>
                      <tr>
                        <th style={tTh}>Check Category</th>
                        <th style={{ ...tTh, textAlign: "right" }}>P1</th>
                        <th style={{ ...tTh, textAlign: "right" }}>P2</th>
                        <th style={{ ...tTh, textAlign: "right" }}>P3</th>
                        <th style={{ ...tTh, textAlign: "right" }}>P4</th>
                        <th style={{ ...tTh, textAlign: "right" }}>Total</th>
                        <th style={{ ...tTh, textAlign: "right" }}>Share</th>
                      </tr>
                    </thead>
                    <tbody>
                      {findingsByCategory.map((row, i) => (
                        <tr
                          key={i}
                          style={{
                            background: i % 2 === 0 ? "#fff" : "#fafafa",
                          }}
                        >
                          <td
                            style={{
                              ...tTd,
                              fontWeight: 600,
                              color: "#111827",
                              wordBreak: "break-all",
                            }}
                          >
                            {row.cat}
                          </td>
                          <td style={tTdR}>{pb(1, row.p1)}</td>
                          <td style={tTdR}>{pb(2, row.p2)}</td>
                          <td style={tTdR}>{pb(3, row.p3)}</td>
                          <td style={tTdR}>{pb(4, row.p4)}</td>
                          <td
                            style={{
                              ...tTdR,
                              fontWeight: 700,
                              color: "#111827",
                            }}
                          >
                            {row.total}
                          </td>
                          <td
                            style={{ ...tTdR, fontSize: 11, color: "#6b7280" }}
                          >
                            {findings.length > 0
                              ? `${((row.total / findings.length) * 100).toFixed(1)}%`
                              : "—"}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
            {/* Block 3 — Object Risk Table */}
            <div
              style={{
                background: "var(--card-bg,#fff)",
                borderRadius: 12,
                boxShadow: "0 1px 4px rgba(0,0,0,0.06)",
                border: "1px solid #e5e7eb",
                overflow: "hidden",
              }}
            >
              <div
                style={{
                  padding: "18px 20px 14px",
                  borderBottom: "1px solid #f3f4f6",
                  display: "flex",
                  justifyContent: "space-between",
                  alignItems: "flex-start",
                  flexWrap: "wrap",
                  gap: 10,
                }}
              >
                <div>
                  <div
                    style={{
                      fontSize: 10,
                      fontWeight: 700,
                      color: "#0a6ed1",
                      letterSpacing: 1,
                      textTransform: "uppercase",
                      marginBottom: 4,
                    }}
                  >
                    Object Risk
                  </div>
                  <div
                    style={{ fontSize: 16, fontWeight: 700, color: "#0f172a" }}
                  >
                    Object Risk Table
                  </div>
                  <div style={{ fontSize: 12, color: "#6b7280", marginTop: 2 }}>
                    {objectRiskTable.length} objects · click headers to sort
                  </div>
                </div>
                <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                  {[null, 1, 2, 3].map((p) => (
                    <button
                      key={p ?? "all"}
                      onClick={() =>
                        setObjFilterPrio(objFilterPrio === p ? null : p)
                      }
                      style={{
                        padding: "5px 12px",
                        borderRadius: 999,
                        border: `1px solid ${objFilterPrio === p ? (p === 1 ? "#ef4444" : p === 2 ? "#f59e0b" : p === 3 ? "#3b82f6" : "#0a6ed1") : "#d1d5db"}`,
                        background:
                          objFilterPrio === p
                            ? p === 1
                              ? "#fee2e2"
                              : p === 2
                                ? "#fef3c7"
                                : p === 3
                                  ? "#dbeafe"
                                  : "#eff6ff"
                            : "white",
                        color:
                          objFilterPrio === p
                            ? p === 1
                              ? "#dc2626"
                              : p === 2
                                ? "#d97706"
                                : p === 3
                                  ? "#2563eb"
                                  : "#0a6ed1"
                            : "#6b7280",
                        fontSize: 11,
                        fontWeight: 600,
                        cursor: "pointer",
                      }}
                    >
                      {p === null ? "All" : `P${p} only`}
                    </button>
                  ))}
                </div>
              </div>
              {objectRiskTable.length === 0 ? (
                <div
                  style={{
                    padding: "32px 20px",
                    textAlign: "center",
                    color: "#9ca3af",
                    fontSize: 13,
                  }}
                >
                  No objects match filter.
                </div>
              ) : (
                <div style={{ overflowX: "auto" }}>
                  <table style={{ width: "100%", borderCollapse: "collapse" }}>
                    <thead style={tH}>
                      <tr>
                        <th style={tTh}>Object</th>
                        <th style={tTh}>Type</th>
                        <th style={tTh}>Package</th>
                        <th
                          style={{
                            ...tTh,
                            textAlign: "right",
                            cursor: "pointer",
                          }}
                          onClick={() => handleObjSort("p1")}
                        >
                          P1{si("p1")}
                        </th>
                        <th
                          style={{
                            ...tTh,
                            textAlign: "right",
                            cursor: "pointer",
                          }}
                          onClick={() => handleObjSort("p2")}
                        >
                          P2{si("p2")}
                        </th>
                        <th
                          style={{
                            ...tTh,
                            textAlign: "right",
                            cursor: "pointer",
                          }}
                          onClick={() => handleObjSort("p3")}
                        >
                          P3{si("p3")}
                        </th>
                        <th
                          style={{
                            ...tTh,
                            textAlign: "right",
                            cursor: "pointer",
                          }}
                          onClick={() => handleObjSort("total")}
                        >
                          Total{si("total")}
                        </th>
                        <th
                          style={{
                            ...tTh,
                            textAlign: "right",
                            cursor: "pointer",
                          }}
                          onClick={() => handleObjSort("age")}
                        >
                          Oldest (d){si("age")}
                        </th>
                        <th style={tTh}>Developer</th>
                      </tr>
                    </thead>
                    <tbody>
                      {objectRiskTable.map((obj, i) => (
                        <tr
                          key={i}
                          style={{
                            background: i % 2 === 0 ? "#fff" : "#fafafa",
                          }}
                        >
                          <td
                            style={{
                              ...tTd,
                              fontFamily: "monospace",
                              fontWeight: 600,
                              color: "#111827",
                              wordBreak: "break-all",
                              maxWidth: 200,
                            }}
                          >
                            {obj.name}
                          </td>
                          <td
                            style={{ ...tTd, fontSize: 11, color: "#6b7280" }}
                          >
                            {OBJECT_TYPE_LABELS[obj.objType] ||
                              obj.objType ||
                              "—"}
                          </td>
                          <td
                            style={{ ...tTd, fontSize: 11, color: "#6b7280" }}
                          >
                            {obj.pkg}
                          </td>
                          <td style={tTdR}>{pb(1, obj.p1)}</td>
                          <td style={tTdR}>{pb(2, obj.p2)}</td>
                          <td style={tTdR}>{pb(3, obj.p3)}</td>
                          <td
                            style={{
                              ...tTdR,
                              fontWeight: 700,
                              color: "#111827",
                            }}
                          >
                            {obj.total}
                          </td>
                          <td
                            style={{
                              ...tTdR,
                              color:
                                obj.oldestAge > 90
                                  ? "#dc2626"
                                  : obj.oldestAge > 30
                                    ? "#d97706"
                                    : "#374151",
                              fontWeight: obj.oldestAge > 30 ? 700 : 400,
                            }}
                          >
                            {obj.oldestAge > 0 ? obj.oldestAge : "—"}
                          </td>
                          <td
                            style={{
                              ...tTd,
                              fontFamily: "monospace",
                              fontSize: 11,
                            }}
                          >
                            {obj.dev}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
            {/* Block 4 — Developer Accountability */}
            <div
              style={{
                background: "var(--card-bg,#fff)",
                borderRadius: 12,
                boxShadow: "0 1px 4px rgba(0,0,0,0.06)",
                border: "1px solid #e5e7eb",
                overflow: "hidden",
              }}
            >
              <div
                style={{
                  padding: "18px 20px 14px",
                  borderBottom: "1px solid #f3f4f6",
                }}
              >
                <div
                  style={{
                    fontSize: 10,
                    fontWeight: 700,
                    color: "#0a6ed1",
                    letterSpacing: 1,
                    textTransform: "uppercase",
                    marginBottom: 4,
                  }}
                >
                  Ownership
                </div>
                <div
                  style={{ fontSize: 16, fontWeight: 700, color: "#0f172a" }}
                >
                  Developer Accountability
                </div>
                <div style={{ fontSize: 12, color: "#6b7280", marginTop: 2 }}>
                  {devAccountability.length > 0
                    ? `${devAccountability.length} developers`
                    : "Open a run to populate"}
                </div>
              </div>
              {devAccountability.length === 0 ? (
                <div
                  style={{
                    padding: "32px 20px",
                    textAlign: "center",
                    color: "#9ca3af",
                    fontSize: 13,
                  }}
                >
                  No findings loaded.
                </div>
              ) : (
                <div style={{ overflowX: "auto" }}>
                  <table style={{ width: "100%", borderCollapse: "collapse" }}>
                    <thead style={tH}>
                      <tr>
                        <th style={tTh}>Developer</th>
                        <th style={{ ...tTh, textAlign: "right" }}>P1</th>
                        <th style={{ ...tTh, textAlign: "right" }}>P2</th>
                        <th style={{ ...tTh, textAlign: "right" }}>P3</th>
                        <th style={{ ...tTh, textAlign: "right" }}>P4</th>
                        <th style={{ ...tTh, textAlign: "right" }}>Total</th>
                        <th style={{ ...tTh, textAlign: "right" }}>Packages</th>
                        <th style={{ ...tTh, textAlign: "right" }}>
                          Oldest (d)
                        </th>
                        <th style={tTh}>Status</th>
                      </tr>
                    </thead>
                    <tbody>
                      {devAccountability.map((d, i) => (
                        <tr
                          key={i}
                          style={{
                            background: i % 2 === 0 ? "#fff" : "#fafafa",
                          }}
                        >
                          <td
                            style={{
                              ...tTd,
                              fontFamily: "monospace",
                              fontWeight: 700,
                              color: "#111827",
                            }}
                          >
                            {d.dev}
                          </td>
                          <td style={tTdR}>{pb(1, d.p1)}</td>
                          <td style={tTdR}>{pb(2, d.p2)}</td>
                          <td style={tTdR}>{pb(3, d.p3)}</td>
                          <td style={tTdR}>{pb(4, d.p4)}</td>
                          <td
                            style={{
                              ...tTdR,
                              fontWeight: 700,
                              color: "#111827",
                            }}
                          >
                            {d.total}
                          </td>
                          <td style={tTdR}>{d.pkgCount}</td>
                          <td
                            style={{
                              ...tTdR,
                              color:
                                d.oldestAge > 90
                                  ? "#dc2626"
                                  : d.oldestAge > 30
                                    ? "#d97706"
                                    : "#374151",
                              fontWeight: d.oldestAge > 30 ? 700 : 400,
                            }}
                          >
                            {d.oldestAge > 0 ? d.oldestAge : "—"}
                          </td>
                          <td style={tTd}>
                            <span
                              style={{
                                background:
                                  d.p1 + d.p2 > 0 ? "#fee2e2" : "#dcfce7",
                                color: d.p1 + d.p2 > 0 ? "#dc2626" : "#15803d",
                                borderRadius: 999,
                                padding: "2px 8px",
                                fontSize: 11,
                                fontWeight: 700,
                              }}
                            >
                              {d.p1 + d.p2 > 0
                                ? "Action Required"
                                : "No Blockers"}
                            </span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
            {/* Block 5 — SLA Intelligence */}
            <div
              style={{
                background: "var(--card-bg,#fff)",
                borderRadius: 12,
                boxShadow: "0 1px 4px rgba(0,0,0,0.06)",
                border: "1px solid #e5e7eb",
                padding: "20px 24px",
              }}
            >
              <div
                style={{
                  fontSize: 10,
                  fontWeight: 700,
                  color: "#0a6ed1",
                  letterSpacing: 1,
                  textTransform: "uppercase",
                  marginBottom: 4,
                }}
              >
                SLA Compliance
              </div>
              <div
                style={{
                  fontSize: 16,
                  fontWeight: 700,
                  color: "#0f172a",
                  marginBottom: 14,
                }}
              >
                SLA Intelligence
              </div>
              {findings.length === 0 ? (
                <div style={{ fontSize: 13, color: "#9ca3af" }}>
                  No findings loaded.
                </div>
              ) : (
                <>
                  <div
                    style={{
                      display: "grid",
                      gridTemplateColumns: isMobile
                        ? "1fr 1fr"
                        : "repeat(4,1fr)",
                      gap: 12,
                      marginBottom: 16,
                    }}
                  >
                    {[
                      {
                        label: "P1 Critical",
                        target: "SLA: 1 day",
                        p: 1,
                        color: "#dc2626",
                        bg: "#fee2e2",
                      },
                      {
                        label: "P2 Warning",
                        target: "SLA: 3 days",
                        p: 2,
                        color: "#d97706",
                        bg: "#fef3c7",
                      },
                      {
                        label: "P3 Info",
                        target: "SLA: 14 days",
                        p: 3,
                        color: "#2563eb",
                        bg: "#dbeafe",
                      },
                      {
                        label: "P4 Note",
                        target: "SLA: 30 days",
                        p: 4,
                        color: "#6b7280",
                        bg: "#f3f4f6",
                      },
                    ].map((item) => {
                      const b = slaIntelligence.buckets[item.p];
                      return (
                        <div
                          key={item.p}
                          style={{
                            background: item.bg,
                            borderRadius: 10,
                            padding: "14px 12px",
                            textAlign: "center",
                          }}
                        >
                          <div
                            style={{
                              fontSize: 10,
                              fontWeight: 700,
                              color: "#6b7280",
                              textTransform: "uppercase",
                              letterSpacing: 0.5,
                            }}
                          >
                            {item.label}
                          </div>
                          <div
                            style={{
                              fontSize: 22,
                              fontWeight: 800,
                              color: item.color,
                              margin: "6px 0 2px",
                            }}
                          >
                            {b.overdue}
                          </div>
                          <div style={{ fontSize: 11, color: "#9ca3af" }}>
                            overdue of {b.total}
                          </div>
                          <div
                            style={{
                              fontSize: 10,
                              color: item.color,
                              marginTop: 4,
                            }}
                          >
                            {item.target}
                          </div>
                        </div>
                      );
                    })}
                  </div>
                  <div
                    style={{
                      padding: "14px 16px",
                      background:
                        slaIntelligence.over90 > 0
                          ? "#fef2f2"
                          : slaIntelligence.over30 > 0
                            ? "#fffbeb"
                            : "#f0fdf4",
                      borderRadius: 10,
                      borderLeft: `4px solid ${slaIntelligence.over90 > 0 ? "#ef4444" : slaIntelligence.over30 > 0 ? "#f59e0b" : "#22c55e"}`,
                      fontSize: 13,
                      lineHeight: 1.7,
                      color: "#374151",
                    }}
                  >
                    {slaIntelligence.over90 > 0 ? (
                      <>
                        <strong style={{ color: "#dc2626" }}>
                          {slaIntelligence.over90} findings
                        </strong>{" "}
                        have been open for more than 90 days. Immediate
                        escalation required.{" "}
                        {slaIntelligence.over30 > 0 && (
                          <>
                            A further{" "}
                            <strong>
                              {slaIntelligence.over30 - slaIntelligence.over90}
                            </strong>{" "}
                            findings have exceeded 30 days.
                          </>
                        )}
                      </>
                    ) : slaIntelligence.over30 > 0 ? (
                      <>
                        <strong style={{ color: "#d97706" }}>
                          {slaIntelligence.over30} findings
                        </strong>{" "}
                        have been open for more than 30 days.
                      </>
                    ) : (
                      <>All findings are within SLA thresholds.</>
                    )}
                  </div>
                </>
              )}
            </div>
          </div>
        )}
        {/* ════ DEVELOPER HUB TAB ════ */}
        {tab === "developer" && (
          <div
            style={{
              display: "flex",
              flexDirection: "column",
              gap: 20,
              marginTop: 0,
            }}
          >
            <div
              style={{
                display: "flex",
                justifyContent: "space-between",
                alignItems: "flex-start",
                flexWrap: "wrap",
                gap: 12,
              }}
            >
              <div>
                <div
                  style={{
                    fontSize: 10,
                    fontWeight: 700,
                    color: "#0a6ed1",
                    letterSpacing: 1,
                    textTransform: "uppercase",
                    marginBottom: 4,
                  }}
                >
                  Developer Intelligence
                </div>
                <div
                  style={{ fontSize: 20, fontWeight: 800, color: "#0f172a" }}
                >
                  Developer Assignment Hub
                </div>
                <div style={{ fontSize: 13, color: "#6b7280", marginTop: 4 }}>
                  {findings.length > 0
                    ? `${checkRegistry.length} check types · ${findings.length.toLocaleString()} findings · ${allKnownDevelopers.length} developers · ${assignmentCoverage}% assigned`
                    : "Select a run in Run Explorer to load findings"}
                </div>
              </div>
              <div
                style={{
                  display: "flex",
                  gap: 8,
                  flexWrap: "wrap",
                  alignItems: "center",
                }}
              >
                <div
                  style={{
                    display: "flex",
                    background: "#f3f4f6",
                    borderRadius: 10,
                    padding: 3,
                  }}
                >
                  {(["check", "package"] as const).map((v) => (
                    <button
                      key={v}
                      onClick={() => setDevHubView(v)}
                      style={{
                        padding: "6px 14px",
                        borderRadius: 7,
                        border: "none",
                        fontSize: 12,
                        fontWeight: 600,
                        cursor: "pointer",
                        background: devHubView === v ? "white" : "transparent",
                        color: devHubView === v ? "#0a6ed1" : "#6b7280",
                        boxShadow:
                          devHubView === v
                            ? "0 1px 4px rgba(0,0,0,0.1)"
                            : "none",
                      }}
                    >
                      {v === "check" ? "🔍 By Check Type" : "📦 By Package"}
                    </button>
                  ))}
                </div>
                <button
                  onClick={runPatternAnalysis}
                  disabled={patternLoading || findings.length === 0}
                  style={{
                    display: "flex",
                    alignItems: "center",
                    gap: 8,
                    padding: "10px 18px",
                    borderRadius: 10,
                    border: "none",
                    cursor:
                      findings.length === 0 || patternLoading
                        ? "default"
                        : "pointer",
                    background:
                      findings.length === 0
                        ? "#f3f4f6"
                        : patternLoading
                          ? "#dbeafe"
                          : "linear-gradient(135deg,#0a6ed1,#6366f1)",
                    color:
                      findings.length === 0
                        ? "#9ca3af"
                        : patternLoading
                          ? "#1e40af"
                          : "white",
                    fontSize: 13,
                    fontWeight: 700,
                  }}
                >
                  {patternLoading ? (
                    <>
                      <div
                        style={{
                          width: 14,
                          height: 14,
                          border: "2px solid #3b82f6",
                          borderTopColor: "transparent",
                          borderRadius: "50%",
                          animation: "spin 0.8s linear infinite",
                        }}
                      />
                      Analyzing...
                    </>
                  ) : (
                    <>✨ AI Pattern Analysis</>
                  )}
                </button>
                <div
                  style={{ position: "relative" }}
                  onClick={(e) => e.stopPropagation()}
                >
                  <button
                    disabled={findings.length === 0}
                    onClick={() => setAssignExportOpen((o) => !o)}
                    style={{
                      display: "flex",
                      alignItems: "center",
                      gap: 6,
                      padding: "10px 16px",
                      borderRadius: 10,
                      border: "1px solid #d1d5db",
                      background: "white",
                      fontSize: 13,
                      fontWeight: 600,
                      cursor: findings.length === 0 ? "default" : "pointer",
                      color: findings.length === 0 ? "#9ca3af" : "#374151",
                    }}
                  >
                    ⬇ Download {assignExportOpen ? "▲" : "▼"}
                  </button>
                  {assignExportOpen && findings.length > 0 && (
                    <div
                      style={{
                        position: "absolute",
                        top: "calc(100% + 6px)",
                        right: 0,
                        background: "var(--card-bg,#fff)",
                        border: "1px solid #e5e7eb",
                        borderRadius: 10,
                        boxShadow: "0 8px 24px rgba(0,0,0,0.12)",
                        zIndex: 200,
                        minWidth: 210,
                        overflow: "hidden",
                      }}
                    >
                      <div
                        style={{
                          padding: "8px 12px 4px",
                          fontSize: 10,
                          fontWeight: 700,
                          color: "#9ca3af",
                          letterSpacing: 0.5,
                          textTransform: "uppercase",
                        }}
                      >
                        Export format
                      </div>
                      <button
                        onClick={() => {
                          const rows = checkRegistry.map((c) => [
                            c.key,
                            c.p1,
                            c.p2,
                            c.p3,
                            c.total,
                            c.objectCount,
                            assignments[c.key] || "Unassigned",
                          ]);
                          const csv = [
                            [
                              "Check Category",
                              "P1",
                              "P2",
                              "P3",
                              "Total",
                              "Objects",
                              "Assigned To",
                            ],
                            ...rows,
                          ]
                            .map((r) => r.join(","))
                            .join("\n");
                          const blob = new Blob([csv], { type: "text/csv" });
                          const url = URL.createObjectURL(blob);
                          const a = document.createElement("a");
                          a.href = url;
                          a.download = `atc-assignments-${new Date().toISOString().split("T")[0]}.csv`;
                          a.click();
                          URL.revokeObjectURL(url);
                          setAssignExportOpen(false);
                        }}
                        style={{
                          display: "flex",
                          alignItems: "center",
                          gap: 10,
                          width: "100%",
                          padding: "10px 14px",
                          border: "none",
                          background: "none",
                          cursor: "pointer",
                          fontSize: 13,
                          color: "#374151",
                          textAlign: "left",
                        }}
                        onMouseEnter={(e) =>
                          (e.currentTarget.style.background = "#f3f4f6")
                        }
                        onMouseLeave={(e) =>
                          (e.currentTarget.style.background = "none")
                        }
                      >
                        <span style={{ fontSize: 16 }}>📄</span>
                        <div>
                          <div style={{ fontWeight: 600 }}>CSV</div>
                          <div style={{ fontSize: 11, color: "#9ca3af" }}>
                            Simple comma-separated file
                          </div>
                        </div>
                      </button>
                      <div
                        style={{
                          height: "0.5px",
                          background: "#f3f4f6",
                          margin: "0 12px",
                        }}
                      />
                      <button
                        onClick={() => {
                          exportAssignmentsExcel();
                          setAssignExportOpen(false);
                        }}
                        style={{
                          display: "flex",
                          alignItems: "center",
                          gap: 10,
                          width: "100%",
                          padding: "10px 14px",
                          border: "none",
                          background: "none",
                          cursor: "pointer",
                          fontSize: 13,
                          color: "#374151",
                          textAlign: "left",
                        }}
                        onMouseEnter={(e) =>
                          (e.currentTarget.style.background = "#f0fdf4")
                        }
                        onMouseLeave={(e) =>
                          (e.currentTarget.style.background = "none")
                        }
                      >
                        <span style={{ fontSize: 16 }}>📊</span>
                        <div>
                          <div style={{ fontWeight: 600, color: "#15803d" }}>
                            Excel (.xlsx)
                          </div>
                          <div style={{ fontSize: 11, color: "#9ca3af" }}>
                            Formatted · 3 sheets · coloured
                          </div>
                        </div>
                      </button>
                      <div style={{ height: 6 }} />
                    </div>
                  )}
                </div>
                {Object.keys(assignments).length > 0 && (
                  <button
                    onClick={() => {
                      if (window.confirm("Clear all assignments?"))
                        setAssignments({});
                    }}
                    style={{
                      padding: "10px 14px",
                      borderRadius: 10,
                      border: "1px solid #fecaca",
                      background: "#fef2f2",
                      fontSize: 13,
                      fontWeight: 600,
                      cursor: "pointer",
                      color: "#dc2626",
                    }}
                  >
                    Clear All
                  </button>
                )}
              </div>
            </div>
            {findings.length > 0 && (
              <div
                style={{
                  display: "grid",
                  gridTemplateColumns: isMobile ? "1fr 1fr" : "repeat(4,1fr)",
                  gap: 12,
                }}
              >
                {(devHubView === "check"
                  ? [
                      {
                        label: "Check Types",
                        value: checkRegistry.length,
                        color: "#0a6ed1",
                        bg: "#eff6ff",
                        sub: "in this run",
                      },
                      {
                        label: "Assigned",
                        value: checkRegistry.filter((c) => assignments[c.key])
                          .length,
                        color: "#15803d",
                        bg: "#f0fdf4",
                        sub: `${assignmentCoverage}% coverage`,
                      },
                      {
                        label: "Unassigned Types",
                        value: checkRegistry.filter((c) => !assignments[c.key])
                          .length,
                        color: "#d97706",
                        bg: "#fffbeb",
                        sub: "need an owner",
                      },
                      {
                        label: "Unassigned P1s",
                        value: unassignedP1Count,
                        color: unassignedP1Count > 0 ? "#dc2626" : "#15803d",
                        bg: unassignedP1Count > 0 ? "#fee2e2" : "#f0fdf4",
                        sub: "critical with no owner",
                      },
                    ]
                  : [
                      {
                        label: "Packages",
                        value: packageRegistry.length,
                        color: "#0a6ed1",
                        bg: "#eff6ff",
                        sub: "in this run",
                      },
                      {
                        label: "Assigned",
                        value: packageRegistry.filter(
                          (p) => packageAssignments[p.key],
                        ).length,
                        color: "#15803d",
                        bg: "#f0fdf4",
                        sub: `${Math.round((packageRegistry.filter((p) => packageAssignments[p.key]).length / Math.max(packageRegistry.length, 1)) * 100)}% coverage`,
                      },
                      {
                        label: "Unassigned Packages",
                        value: packageRegistry.filter(
                          (p) => !packageAssignments[p.key],
                        ).length,
                        color: "#d97706",
                        bg: "#fffbeb",
                        sub: "need an owner",
                      },
                      {
                        label: "Unassigned P1s",
                        value: packageRegistry
                          .filter((p) => !packageAssignments[p.key] && p.p1 > 0)
                          .reduce((a, p) => a + p.p1, 0),
                        color:
                          packageRegistry
                            .filter(
                              (p) => !packageAssignments[p.key] && p.p1 > 0,
                            )
                            .reduce((a, p) => a + p.p1, 0) > 0
                            ? "#dc2626"
                            : "#15803d",
                        bg:
                          packageRegistry
                            .filter(
                              (p) => !packageAssignments[p.key] && p.p1 > 0,
                            )
                            .reduce((a, p) => a + p.p1, 0) > 0
                            ? "#fee2e2"
                            : "#f0fdf4",
                        sub: "critical with no owner",
                      },
                    ]
                ).map((item, i) => (
                  <div
                    key={i}
                    style={{
                      background: item.bg,
                      borderRadius: 10,
                      padding: "14px 16px",
                      border: "1px solid #e5e7eb",
                    }}
                  >
                    <div
                      style={{
                        fontSize: 10,
                        fontWeight: 700,
                        color: "#6b7280",
                        textTransform: "uppercase",
                        letterSpacing: 0.5,
                      }}
                    >
                      {item.label}
                    </div>
                    <div
                      style={{
                        fontSize: 26,
                        fontWeight: 800,
                        color: item.color,
                        margin: "4px 0 2px",
                      }}
                    >
                      {item.value}
                    </div>
                    <div style={{ fontSize: 11, color: "#9ca3af" }}>
                      {item.sub}
                    </div>
                  </div>
                ))}
              </div>
            )}
            {patternError && (
              <div
                style={{
                  padding: "12px 16px",
                  background: "#fef2f2",
                  borderRadius: 10,
                  border: "1px solid #fecaca",
                  fontSize: 13,
                  color: "#dc2626",
                }}
              >
                ❌ {patternError}{" "}
                <button
                  onClick={runPatternAnalysis}
                  style={{
                    marginLeft: 12,
                    padding: "3px 10px",
                    borderRadius: 6,
                    border: "1px solid #fca5a5",
                    background: "white",
                    color: "#dc2626",
                    fontSize: 12,
                    fontWeight: 600,
                    cursor: "pointer",
                  }}
                >
                  Retry
                </button>
              </div>
            )}
            {patternResult && (
              <div
                style={{
                  background: "var(--card-bg,#fff)",
                  borderRadius: 12,
                  border: "1px solid #e5e7eb",
                  padding: "20px 24px",
                }}
              >
                <div
                  style={{
                    fontSize: 10,
                    fontWeight: 700,
                    color: "#0a6ed1",
                    letterSpacing: 1,
                    textTransform: "uppercase",
                    marginBottom: 4,
                  }}
                >
                  AI Root Cause Intelligence
                </div>
                <div
                  style={{
                    fontSize: 16,
                    fontWeight: 700,
                    color: "#0f172a",
                    marginBottom: 14,
                  }}
                >
                  Pattern Analysis & Assignment Recommendations
                </div>
                <div
                  style={{
                    padding: "14px 16px",
                    background: "#f8fafc",
                    borderRadius: 10,
                    border: "1px solid #e5e7eb",
                    fontSize: 13,
                    lineHeight: 1.75,
                    color: "#374151",
                    marginBottom: 8,
                  }}
                >
                  {patternResult.summary}
                </div>
                {(patternResult.topPriority ||
                  patternResult.workloadBalance) && (
                  <div
                    style={{
                      display: "grid",
                      gridTemplateColumns:
                        patternResult.topPriority &&
                        patternResult.workloadBalance
                          ? "1fr 1fr"
                          : "1fr",
                      gap: 8,
                      marginBottom: 16,
                    }}
                  >
                    {patternResult.topPriority && (
                      <div
                        style={{
                          padding: "10px 14px",
                          background: "#fef2f2",
                          borderRadius: 8,
                          borderLeft: "4px solid #ef4444",
                          fontSize: 12,
                          color: "#374151",
                        }}
                      >
                        <strong style={{ color: "#dc2626" }}>
                          Top Priority:
                        </strong>{" "}
                        {patternResult.topPriority}
                      </div>
                    )}
                    {patternResult.workloadBalance && (
                      <div
                        style={{
                          padding: "10px 14px",
                          background: "#eff6ff",
                          borderRadius: 8,
                          borderLeft: "4px solid #3b82f6",
                          fontSize: 12,
                          color: "#374151",
                        }}
                      >
                        <strong style={{ color: "#0a6ed1" }}>Workload:</strong>{" "}
                        {patternResult.workloadBalance}
                      </div>
                    )}
                  </div>
                )}
                <div
                  style={{ display: "flex", flexDirection: "column", gap: 10 }}
                >
                  {(patternResult.patterns || []).map((p: any, i: number) => {
                    const rb =
                      p.riskLevel === "CRITICAL"
                        ? "#ef4444"
                        : p.riskLevel === "HIGH"
                          ? "#f59e0b"
                          : "#3b82f6";
                    const rbg =
                      p.riskLevel === "CRITICAL"
                        ? "#fff8f8"
                        : p.riskLevel === "HIGH"
                          ? "#fffdf0"
                          : "#f8faff";
                    const alr = (p.checkCategories || []).every(
                      (c: string) => assignments[c] === p.suggestedDeveloper,
                    );
                    return (
                      <div
                        key={i}
                        style={{
                          border: `1px solid ${rb}33`,
                          borderLeft: `4px solid ${rb}`,
                          borderRadius: 10,
                          padding: "14px 18px",
                          background: rbg,
                        }}
                      >
                        <div
                          style={{
                            display: "flex",
                            justifyContent: "space-between",
                            alignItems: "flex-start",
                            flexWrap: "wrap",
                            gap: 10,
                            marginBottom: 10,
                          }}
                        >
                          <div>
                            <div
                              style={{
                                display: "flex",
                                alignItems: "center",
                                gap: 8,
                                marginBottom: 5,
                              }}
                            >
                              <span
                                style={{
                                  fontSize: 14,
                                  fontWeight: 700,
                                  color: "#111827",
                                }}
                              >
                                {p.patternName}
                              </span>
                              <span
                                style={{
                                  background:
                                    p.riskLevel === "CRITICAL"
                                      ? "#fee2e2"
                                      : p.riskLevel === "HIGH"
                                        ? "#fef3c7"
                                        : "#dbeafe",
                                  color:
                                    p.riskLevel === "CRITICAL"
                                      ? "#dc2626"
                                      : p.riskLevel === "HIGH"
                                        ? "#d97706"
                                        : "#2563eb",
                                  borderRadius: 999,
                                  padding: "2px 8px",
                                  fontSize: 10,
                                  fontWeight: 700,
                                }}
                              >
                                {p.riskLevel}
                              </span>
                              {p.totalFindings > 0 && (
                                <span
                                  style={{ fontSize: 11, color: "#6b7280" }}
                                >
                                  {p.totalFindings} findings ·{" "}
                                  {p.estimatedEffort}
                                </span>
                              )}
                            </div>
                            <div
                              style={{
                                display: "flex",
                                gap: 4,
                                flexWrap: "wrap",
                              }}
                            >
                              {(p.checkCategories || []).map(
                                (c: string, j: number) => (
                                  <span
                                    key={j}
                                    style={{
                                      background: "#f3f4f6",
                                      color: "#374151",
                                      borderRadius: 4,
                                      padding: "1px 7px",
                                      fontSize: 11,
                                      fontWeight: 600,
                                    }}
                                  >
                                    {c}
                                  </span>
                                ),
                              )}
                            </div>
                          </div>
                          {p.suggestedDeveloper && (
                            <button
                              onClick={() => {
                                const n = { ...assignments };
                                (p.checkCategories || []).forEach(
                                  (c: string) => {
                                    n[c] = p.suggestedDeveloper;
                                  },
                                );
                                setAssignments(n);
                              }}
                              disabled={alr}
                              style={{
                                padding: "7px 14px",
                                borderRadius: 8,
                                border: "none",
                                background: alr ? "#dcfce7" : "#0a6ed1",
                                color: alr ? "#15803d" : "white",
                                fontSize: 12,
                                fontWeight: 700,
                                cursor: alr ? "default" : "pointer",
                                flexShrink: 0,
                              }}
                            >
                              {alr
                                ? "✓ Assigned"
                                : `Accept → ${displayUser(p.suggestedDeveloper)}`}
                            </button>
                          )}
                        </div>
                        <div
                          style={{
                            fontSize: 12,
                            color: "#374151",
                            marginBottom: 6,
                          }}
                        >
                          <strong>Root cause:</strong> {p.rootCause}
                        </div>
                        <div
                          style={{
                            padding: "8px 12px",
                            background: "#f0fdf4",
                            borderRadius: 8,
                            borderLeft: "3px solid #22c55e",
                            fontSize: 12,
                            color: "#166534",
                            marginBottom: p.assignmentReason ? 6 : 0,
                          }}
                        >
                          ✅ {p.fixBrief}
                        </div>
                        {p.assignmentReason && (
                          <div
                            style={{
                              fontSize: 11,
                              color: "#6b7280",
                              marginTop: 6,
                            }}
                          >
                            💡 {p.assignmentReason}
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              </div>
            )}
            {devHubView === "package" && findings.length > 0 && (
              <div
                style={{
                  display: "grid",
                  gridTemplateColumns: isMobile ? "1fr" : "360px 1fr",
                  gap: 20,
                  alignItems: "start",
                }}
              >
                <div
                  style={{
                    background: "var(--card-bg,#fff)",
                    borderRadius: 12,
                    border: "1px solid #e5e7eb",
                    overflow: "hidden",
                  }}
                >
                  <div
                    style={{
                      padding: "16px 18px 12px",
                      borderBottom: "1px solid #f3f4f6",
                    }}
                  >
                    <div
                      style={{
                        fontSize: 10,
                        fontWeight: 700,
                        color: "#0a6ed1",
                        letterSpacing: 1,
                        textTransform: "uppercase",
                        marginBottom: 4,
                      }}
                    >
                      Registry
                    </div>
                    <div
                      style={{
                        fontSize: 15,
                        fontWeight: 700,
                        color: "#0f172a",
                      }}
                    >
                      Package Registry
                    </div>
                    <div
                      style={{ fontSize: 12, color: "#6b7280", marginTop: 2 }}
                    >
                      {packageRegistry.length} packages · click name to inspect
                      findings
                    </div>
                  </div>
                  <div
                    style={{
                      maxHeight: "calc(100vh - 320px)",
                      overflowY: "auto",
                    }}
                  >
                    {packageRegistry.map((pkg, i) => (
                      <div
                        key={i}
                        style={{
                          padding: "11px 16px",
                          borderBottom: "1px solid #f3f4f6",
                          background: packageAssignments[pkg.key]
                            ? i % 2 === 0
                              ? "#f0fdf4"
                              : "#e8fdf0"
                            : i % 2 === 0
                              ? "#fff"
                              : "#fafafa",
                        }}
                      >
                        <div
                          style={{
                            display: "flex",
                            justifyContent: "space-between",
                            alignItems: "flex-start",
                            gap: 8,
                          }}
                        >
                          <div style={{ minWidth: 0, flex: 1 }}>
                            <div
                              style={{
                                fontSize: 12,
                                fontWeight: 700,
                                color: "#0a6ed1",
                                cursor: "pointer",
                                overflowWrap: "break-word",
                                marginBottom: 4,
                              }}
                              onClick={() => openPkgFindingsDrawer(pkg.key)}
                            >
                              {pkg.key}
                            </div>
                            <div
                              style={{
                                display: "flex",
                                gap: 4,
                                flexWrap: "wrap",
                              }}
                            >
                              {pkg.p1 > 0 && (
                                <span
                                  style={{
                                    background: "#fee2e2",
                                    color: "#dc2626",
                                    borderRadius: 999,
                                    padding: "1px 6px",
                                    fontSize: 10,
                                    fontWeight: 700,
                                  }}
                                >
                                  P1:{pkg.p1}
                                </span>
                              )}
                              {pkg.p2 > 0 && (
                                <span
                                  style={{
                                    background: "#fef3c7",
                                    color: "#d97706",
                                    borderRadius: 999,
                                    padding: "1px 6px",
                                    fontSize: 10,
                                    fontWeight: 700,
                                  }}
                                >
                                  P2:{pkg.p2}
                                </span>
                              )}
                              {pkg.p3 > 0 && (
                                <span
                                  style={{
                                    background: "#dbeafe",
                                    color: "#2563eb",
                                    borderRadius: 999,
                                    padding: "1px 6px",
                                    fontSize: 10,
                                    fontWeight: 700,
                                  }}
                                >
                                  P3:{pkg.p3}
                                </span>
                              )}
                              <span style={{ fontSize: 10, color: "#9ca3af" }}>
                                {pkg.objectCount} obj · {pkg.checkTypeCount}{" "}
                                checks
                              </span>
                              {renderJiraTicketBadge("PACKAGE", pkg.key)}
                            </div>
                          </div>
                          <div style={{ flexShrink: 0 }}>
                            {packageAssignments[pkg.key] ? (
                              <span
                                style={{
                                  fontSize: 11,
                                  fontWeight: 700,
                                  color: "#15803d",
                                  background: "#f0fdf4",
                                  borderRadius: 6,
                                  padding: "3px 8px",
                                  border: "1px solid #bbf7d0",
                                }}
                              >
                                ✓ {displayUser(packageAssignments[pkg.key])}
                              </span>
                            ) : (
                              <span
                                style={{
                                  fontSize: 11,
                                  color: "#9ca3af",
                                  background: "#f9fafb",
                                  borderRadius: 6,
                                  padding: "3px 8px",
                                  border: "1px solid #e5e7eb",
                                }}
                              >
                                Unassigned
                              </span>
                            )}
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
                <div
                  style={{ display: "flex", flexDirection: "column", gap: 14 }}
                >
                  <div
                    style={{
                      background: "#fffbeb",
                      borderRadius: 12,
                      border: "2px solid #fde047",
                      padding: "16px 20px",
                    }}
                  >
                    {pkgSaveError && (
                      <div
                        style={{
                          padding: "8px 12px",
                          background: "#fef2f2",
                          border: "1px solid #fecaca",
                          borderRadius: 8,
                          fontSize: 12,
                          color: "#dc2626",
                          marginBottom: 10,
                        }}
                      >
                        ❌ {pkgSaveError}
                      </div>
                    )}
                    {pkgSaveSuccess && (
                      <div
                        style={{
                          padding: "8px 12px",
                          background: "#f0fdf4",
                          border: "1px solid #bbf7d0",
                          borderRadius: 8,
                          fontSize: 12,
                          color: "#15803d",
                          marginBottom: 10,
                        }}
                      >
                        ✅ {pkgSaveSuccess}
                      </div>
                    )}
                    <div
                      style={{
                        display: "flex",
                        justifyContent: "flex-end",
                        marginBottom: 10,
                      }}
                    >
                      <button
                        onClick={savePackageAssignments}
                        disabled={pkgSaving || !selectedRun}
                        style={{
                          padding: "8px 20px",
                          borderRadius: 8,
                          border: "none",
                          background:
                            pkgSaving || !selectedRun ? "#e5e7eb" : "#0a6ed1",
                          color:
                            pkgSaving || !selectedRun ? "#9ca3af" : "white",
                          fontSize: 13,
                          fontWeight: 700,
                          cursor:
                            pkgSaving || !selectedRun ? "default" : "pointer",
                        }}
                      >
                        {pkgSaving ? "Saving..." : "Save + Create Jira Tickets"}
                      </button>
                    </div>
                    <div
                      style={{
                        fontSize: 11,
                        fontWeight: 700,
                        color: "#713f12",
                        marginBottom: 4,
                      }}
                    >
                      📦 All Packages — {packageRegistry.length} total ·{" "}
                      {
                        packageRegistry.filter(
                          (p) => !packageAssignments[p.key],
                        ).length
                      }{" "}
                      unassigned
                    </div>
                    <div
                      style={{
                        fontSize: 11,
                        color: "#92400e",
                        marginBottom: 12,
                      }}
                    >
                      Click a package name to inspect · use dropdown to assign
                      developer
                    </div>
                    <div
                      style={{
                        display: "flex",
                        flexDirection: "column",
                        gap: 6,
                      }}
                    >
                      {packageRegistry.map((pkg, i) => (
                        <div
                          key={i}
                          style={{
                            display: "flex",
                            justifyContent: "space-between",
                            alignItems: "center",
                            padding: "9px 12px",
                            background: packageAssignments[pkg.key]
                              ? "#f0fdf4"
                              : "#fff",
                            borderRadius: 8,
                            border: `1px solid ${packageAssignments[pkg.key] ? "#bbf7d0" : "#fde047"}`,
                          }}
                        >
                          <div style={{ flex: 1, minWidth: 0 }}>
                            <span
                              onClick={() => openPkgFindingsDrawer(pkg.key)}
                              style={{
                                fontSize: 12,
                                fontWeight: 700,
                                color: "#0a6ed1",
                                cursor: "pointer",
                                textDecoration: "underline",
                                textDecorationStyle: "dotted",
                              }}
                            >
                              {pkg.key}
                            </span>
                            <div
                              style={{
                                display: "flex",
                                gap: 4,
                                flexWrap: "wrap",
                                marginTop: 3,
                              }}
                            >
                              {pkg.p1 > 0 && (
                                <span
                                  style={{
                                    background: "#fee2e2",
                                    color: "#dc2626",
                                    borderRadius: 999,
                                    padding: "1px 6px",
                                    fontSize: 10,
                                    fontWeight: 700,
                                  }}
                                >
                                  P1:{pkg.p1}
                                </span>
                              )}
                              {pkg.p2 > 0 && (
                                <span
                                  style={{
                                    background: "#fef3c7",
                                    color: "#d97706",
                                    borderRadius: 999,
                                    padding: "1px 6px",
                                    fontSize: 10,
                                    fontWeight: 700,
                                  }}
                                >
                                  P2:{pkg.p2}
                                </span>
                              )}
                              <span style={{ fontSize: 10, color: "#9ca3af" }}>
                                {pkg.objectCount} objects
                              </span>
                              {renderJiraTicketBadge("PACKAGE", pkg.key)}
                            </div>
                          </div>
                          <select
                            value={packageAssignments[pkg.key] || ""}
                            onChange={(e) => {
                              const v = e.target.value;
                              setPackageAssignments((prev) => {
                                const n = { ...prev };
                                if (v) n[pkg.key] = v;
                                else delete n[pkg.key];
                                return n;
                              });
                            }}
                            style={{
                              padding: "4px 8px",
                              borderRadius: 6,
                              border: `1px solid ${packageAssignments[pkg.key] ? "#22c55e" : "#fde047"}`,
                              fontSize: 11,
                              background: packageAssignments[pkg.key]
                                ? "#f0fdf4"
                                : "white",
                              color: packageAssignments[pkg.key]
                                ? "#15803d"
                                : "#374151",
                              fontWeight: packageAssignments[pkg.key]
                                ? 700
                                : 400,
                              maxWidth: 160,
                              cursor: "pointer",
                              flexShrink: 0,
                              marginLeft: 10,
                            }}
                          >
                            <option value="">Unassigned</option>
                            {devProfiles.length > 0
                              ? devProfiles.map((p) => (
                                  <option key={p.UserId} value={p.UserId}>
                                    {p.DisplayName}
                                  </option>
                                ))
                              : allKnownDevelopers.map((d) => (
                                  <option key={d} value={d}>
                                    {d}
                                  </option>
                                ))}
                          </select>
                        </div>
                      ))}
                    </div>
                  </div>
                  {packageWorkload.length > 0 && (
                    <>
                      <div
                        style={{
                          fontSize: 10,
                          fontWeight: 700,
                          color: "#0a6ed1",
                          letterSpacing: 1,
                          textTransform: "uppercase",
                        }}
                      >
                        Developer Workload — by Package
                      </div>
                      {packageWorkload.map((dw, i) => (
                        <div
                          key={i}
                          style={{
                            background: "var(--card-bg,#fff)",
                            borderRadius: 12,
                            border: `1px solid ${dw.p1 > 0 ? "#fecaca" : "#e5e7eb"}`,
                            overflow: "hidden",
                          }}
                        >
                          <div
                            style={{
                              padding: "14px 18px",
                              background: dw.p1 > 20 ? "#fff8f8" : "#fafafa",
                              borderBottom: "1px solid #f3f4f6",
                              display: "flex",
                              justifyContent: "space-between",
                              alignItems: "flex-start",
                              flexWrap: "wrap",
                              gap: 8,
                            }}
                          >
                            <div>
                              <div
                                style={{
                                  fontSize: 14,
                                  fontWeight: 700,
                                  color: "#111827",
                                  fontFamily: "monospace",
                                }}
                              >
                                {dw.dev}
                              </div>
                              <div
                                style={{
                                  fontSize: 11,
                                  color: "#6b7280",
                                  marginTop: 2,
                                }}
                              >
                                {dw.assignedPkgs.length} package
                                {dw.assignedPkgs.length !== 1 ? "s" : ""} ·{" "}
                                {dw.objectCount} objects
                              </div>
                            </div>
                            <div style={{ display: "flex", gap: 6 }}>
                              {dw.p1 > 0 && (
                                <span
                                  style={{
                                    background: "#fee2e2",
                                    color: "#dc2626",
                                    borderRadius: 999,
                                    padding: "3px 9px",
                                    fontSize: 11,
                                    fontWeight: 700,
                                  }}
                                >
                                  P1:{dw.p1}
                                </span>
                              )}
                              {dw.p2 > 0 && (
                                <span
                                  style={{
                                    background: "#fef3c7",
                                    color: "#d97706",
                                    borderRadius: 999,
                                    padding: "3px 9px",
                                    fontSize: 11,
                                    fontWeight: 700,
                                  }}
                                >
                                  P2:{dw.p2}
                                </span>
                              )}
                              <span
                                style={{
                                  background: "#f3f4f6",
                                  color: "#6b7280",
                                  borderRadius: 6,
                                  padding: "3px 9px",
                                  fontSize: 11,
                                  fontWeight: 700,
                                }}
                              >
                                Score:{Math.round(dw.priorityScore)}
                              </span>
                            </div>
                          </div>
                          <div style={{ padding: "8px 18px 12px" }}>
                            {dw.assignedPkgs.map((pkg, j) => {
                              const reg = packageRegistry.find(
                                (p) => p.key === pkg,
                              );
                              if (!reg) return null;
                              return (
                                <div
                                  key={j}
                                  style={{
                                    display: "flex",
                                    justifyContent: "space-between",
                                    alignItems: "center",
                                    padding: "6px 0",
                                    borderBottom: "1px solid #f3f4f6",
                                  }}
                                >
                                  <span
                                    style={{
                                      fontSize: 12,
                                      fontWeight: 600,
                                      color: "#374151",
                                    }}
                                  >
                                    {pkg}
                                  </span>
                                  <div style={{ display: "flex", gap: 6 }}>
                                    {reg.p1 > 0 && (
                                      <span
                                        style={{
                                          background: "#fee2e2",
                                          color: "#dc2626",
                                          borderRadius: 999,
                                          padding: "1px 6px",
                                          fontSize: 11,
                                          fontWeight: 700,
                                        }}
                                      >
                                        {reg.p1}
                                      </span>
                                    )}
                                    {reg.p2 > 0 && (
                                      <span
                                        style={{
                                          background: "#fef3c7",
                                          color: "#d97706",
                                          borderRadius: 999,
                                          padding: "1px 6px",
                                          fontSize: 11,
                                          fontWeight: 700,
                                        }}
                                      >
                                        {reg.p2}
                                      </span>
                                    )}
                                    <span
                                      style={{ fontSize: 11, color: "#6b7280" }}
                                    >
                                      {reg.total} total
                                    </span>
                                  </div>
                                </div>
                              );
                            })}
                          </div>
                        </div>
                      ))}
                    </>
                  )}
                </div>
              </div>
            )}

            {findings.length === 0 ? (
              <div
                style={{
                  padding: "48px 20px",
                  textAlign: "center",
                  background: "var(--card-bg,#fff)",
                  borderRadius: 12,
                  border: "1px dashed #d1d5db",
                }}
              >
                <div style={{ fontSize: 36, marginBottom: 12 }}>👥</div>
                <div
                  style={{
                    fontSize: 14,
                    fontWeight: 700,
                    color: "#374151",
                    marginBottom: 6,
                  }}
                >
                  No findings loaded
                </div>
                <div
                  style={{ fontSize: 13, color: "#9ca3af", marginBottom: 16 }}
                >
                  Select a run in Run Explorer, then return here to assign check
                  types.
                </div>
                <button
                  onClick={() => setTab("runs")}
                  style={{
                    padding: "8px 20px",
                    borderRadius: 8,
                    border: "none",
                    background: "#0a6ed1",
                    color: "white",
                    fontSize: 13,
                    fontWeight: 600,
                    cursor: "pointer",
                  }}
                >
                  Go to Run Explorer →
                </button>
              </div>
            ) : devHubView === "check" ? (
              <div
                style={{
                  display: "grid",
                  gridTemplateColumns: isMobile ? "1fr" : "360px 1fr",
                  gap: 20,
                  alignItems: "start",
                }}
              >
                {/* Left: Check Issue Registry */}
                <div
                  style={{
                    background: "var(--card-bg,#fff)",
                    borderRadius: 12,
                    border: "1px solid #e5e7eb",
                    overflow: "hidden",
                  }}
                >
                  <div
                    style={{
                      padding: "16px 18px 12px",
                      borderBottom: "1px solid #f3f4f6",
                    }}
                  >
                    <div
                      style={{
                        fontSize: 10,
                        fontWeight: 700,
                        color: "#0a6ed1",
                        letterSpacing: 1,
                        textTransform: "uppercase",
                        marginBottom: 4,
                      }}
                    >
                      Registry
                    </div>
                    <div
                      style={{
                        fontSize: 15,
                        fontWeight: 700,
                        color: "#0f172a",
                      }}
                    >
                      Check Issue Registry
                    </div>
                    <div
                      style={{
                        fontSize: 12,
                        color: "#6b7280",
                        marginTop: 2,
                        marginBottom: 10,
                      }}
                    >
                      Click ▶ to see affected objects · assign each check type
                    </div>
                    <input
                      value={devTabSearch}
                      onChange={(e) => setDevTabSearch(e.target.value)}
                      placeholder="Search check types..."
                      style={{
                        width: "100%",
                        padding: "7px 10px",
                        borderRadius: 8,
                        border: "1px solid #d1d5db",
                        fontSize: 12,
                        boxSizing: "border-box",
                      }}
                    />
                  </div>
                  <div
                    style={{
                      maxHeight: "calc(100vh - 320px)",
                      overflowY: "auto",
                    }}
                  >
                    {checkRegistry
                      .filter(
                        (c) =>
                          !devTabSearch ||
                          c.key
                            .toLowerCase()
                            .includes(devTabSearch.toLowerCase()),
                      )
                      .map((c, i) => (
                        <div key={i}>
                          <div
                            onClick={() =>
                              setExpandedCheck(
                                expandedCheck === c.key ? null : c.key,
                              )
                            }
                            style={{
                              padding: "11px 16px",
                              borderBottom: "1px solid #f3f4f6",
                              cursor: "pointer",
                              background:
                                expandedCheck === c.key
                                  ? "#f8faff"
                                  : assignments[c.key]
                                    ? i % 2 === 0
                                      ? "#f0fdf4"
                                      : "#e8fdf0"
                                    : i % 2 === 0
                                      ? "#fff"
                                      : "#fafafa",
                              transition: "background 0.1s",
                            }}
                          >
                            <div
                              style={{
                                display: "flex",
                                justifyContent: "space-between",
                                alignItems: "flex-start",
                                gap: 8,
                              }}
                            >
                              <div style={{ minWidth: 0, flex: 1 }}>
                                <div
                                  style={{
                                    fontSize: 12,
                                    fontWeight: 700,
                                    color: "#111827",
                                    overflowWrap: "break-word",
                                    wordBreak: "normal",
                                    marginBottom: 4,
                                  }}
                                >
                                  <span
                                    style={{ color: "#0a6ed1", marginRight: 5 }}
                                  >
                                    {expandedCheck === c.key ? "▼" : "▶"}
                                  </span>
                                  {resolveCheckCategory(
                                    findings.find(
                                      (f) =>
                                        (f.CheckCategory ||
                                          resolveCheckCategory(f)) === c.key,
                                    ) || {},
                                  ) || c.key}
                                </div>
                                <div
                                  style={{
                                    display: "flex",
                                    gap: 4,
                                    flexWrap: "wrap",
                                  }}
                                >
                                  {c.p1 > 0 && (
                                    <span
                                      style={{
                                        background: "#fee2e2",
                                        color: "#dc2626",
                                        borderRadius: 999,
                                        padding: "1px 6px",
                                        fontSize: 10,
                                        fontWeight: 700,
                                      }}
                                    >
                                      P1:{c.p1}
                                    </span>
                                  )}
                                  {c.p2 > 0 && (
                                    <span
                                      style={{
                                        background: "#fef3c7",
                                        color: "#d97706",
                                        borderRadius: 999,
                                        padding: "1px 6px",
                                        fontSize: 10,
                                        fontWeight: 700,
                                      }}
                                    >
                                      P2:{c.p2}
                                    </span>
                                  )}
                                  {c.p3 > 0 && (
                                    <span
                                      style={{
                                        background: "#dbeafe",
                                        color: "#2563eb",
                                        borderRadius: 999,
                                        padding: "1px 6px",
                                        fontSize: 10,
                                        fontWeight: 700,
                                      }}
                                    >
                                      P3:{c.p3}
                                    </span>
                                  )}
                                  {c.p4 > 0 && (
                                    <span
                                      style={{
                                        background: "#f3f4f6",
                                        color: "#6b7280",
                                        borderRadius: 999,
                                        padding: "1px 6px",
                                        fontSize: 10,
                                        fontWeight: 700,
                                      }}
                                    >
                                      P4:{c.p4}
                                    </span>
                                  )}
                                  <span
                                    style={{ fontSize: 10, color: "#9ca3af" }}
                                  >
                                    {c.objectCount} obj
                                  </span>
                                  {renderJiraTicketBadge("CHECK", c.key)}
                                </div>
                              </div>
                              <div style={{ flexShrink: 0 }}>
                                {assignments[c.key] ? (
                                  <span
                                    style={{
                                      fontSize: 11,
                                      fontWeight: 700,
                                      color: "#15803d",
                                      background: "#f0fdf4",
                                      borderRadius: 6,
                                      padding: "3px 8px",
                                      border: "1px solid #bbf7d0",
                                      whiteSpace: "nowrap",
                                    }}
                                  >
                                    ✓ {displayUser(assignments[c.key])}
                                  </span>
                                ) : (
                                  <span
                                    style={{
                                      fontSize: 11,
                                      color: "#9ca3af",
                                      background: "#f9fafb",
                                      borderRadius: 6,
                                      padding: "3px 8px",
                                      border: "1px solid #e5e7eb",
                                    }}
                                  >
                                    Unassigned
                                  </span>
                                )}
                              </div>
                            </div>
                          </div>
                          {expandedCheck === c.key && (
                            <div
                              style={{
                                background: "#f0f6ff",
                                borderBottom: "1px solid #e5e7eb",
                                padding: "10px 16px 12px 28px",
                              }}
                            >
                              <div
                                style={{
                                  fontSize: 10,
                                  fontWeight: 700,
                                  color: "#0a6ed1",
                                  letterSpacing: 0.5,
                                  textTransform: "uppercase",
                                  marginBottom: 6,
                                }}
                              >
                                Affected Objects — {c.objectCount} total
                              </div>
                              {c.objectList.slice(0, 20).map((obj, j) => (
                                <div
                                  key={j}
                                  style={{
                                    fontSize: 11,
                                    fontFamily: "monospace",
                                    color: "#374151",
                                    padding: "3px 0",
                                    borderBottom: "1px dotted #dbeafe",
                                  }}
                                >
                                  {obj}
                                </div>
                              ))}
                              {c.objectCount > 20 && (
                                <div
                                  style={{
                                    fontSize: 11,
                                    color: "#9ca3af",
                                    marginTop: 6,
                                  }}
                                >
                                  +{c.objectCount - 20} more objects
                                </div>
                              )}
                              {c.devList.length > 0 && (
                                <div
                                  style={{
                                    marginTop: 8,
                                    fontSize: 11,
                                    color: "#6b7280",
                                  }}
                                >
                                  Current owners:{" "}
                                  <strong>{c.devList.join(", ")}</strong>
                                </div>
                              )}
                            </div>
                          )}
                        </div>
                      ))}
                  </div>
                </div>
                {/* Right: Developer Workload */}
                <div
                  style={{ display: "flex", flexDirection: "column", gap: 14 }}
                >
                  {/* All check types — assignment happens here */}
                  <div
                    style={{
                      background: "#fffbeb",
                      borderRadius: 12,
                      border: "2px solid #fde047",
                      padding: "16px 20px",
                    }}
                  >
                    {assignmentsSaveError && (
                      <div
                        style={{
                          padding: "8px 12px",
                          background: "#fef2f2",
                          border: "1px solid #fecaca",
                          borderRadius: 8,
                          fontSize: 12,
                          color: "#dc2626",
                          marginBottom: 10,
                        }}
                      >
                        ❌ {assignmentsSaveError}
                      </div>
                    )}
                    {assignmentsSaveSuccess && (
                      <div
                        style={{
                          padding: "8px 12px",
                          background: "#f0fdf4",
                          border: "1px solid #bbf7d0",
                          borderRadius: 8,
                          fontSize: 12,
                          color: "#15803d",
                          marginBottom: 10,
                        }}
                      >
                        ✅ {assignmentsSaveSuccess}
                      </div>
                    )}
                    <div
                      style={{
                        display: "flex",
                        justifyContent: "flex-end",
                        marginBottom: 10,
                      }}
                    >
                      <button
                        onClick={saveCheckAssignments}
                        disabled={assignmentsSaving || !selectedRun}
                        style={{
                          padding: "8px 20px",
                          borderRadius: 8,
                          border: "none",
                          background:
                            assignmentsSaving || !selectedRun
                              ? "#e5e7eb"
                              : "#0a6ed1",
                          color:
                            assignmentsSaving || !selectedRun
                              ? "#9ca3af"
                              : "white",
                          fontSize: 13,
                          fontWeight: 700,
                          cursor:
                            assignmentsSaving || !selectedRun
                              ? "default"
                              : "pointer",
                        }}
                      >
                        {assignmentsSaving
                          ? "Saving..."
                          : "Save + Create Jira Tickets"}
                      </button>
                    </div>
                    <div
                      style={{
                        fontSize: 11,
                        fontWeight: 700,
                        color: "#713f12",
                        marginBottom: 4,
                      }}
                    >
                      📋 All Check Types — {checkRegistry.length} total ·{" "}
                      {checkRegistry.filter((c) => !assignments[c.key]).length}{" "}
                      unassigned · {unassignedP1Count} unassigned P1 findings
                    </div>
                    <div
                      style={{
                        fontSize: 11,
                        color: "#92400e",
                        marginBottom: 12,
                      }}
                    >
                      Click a check type name to view finding details · use the
                      dropdown to assign
                    </div>
                    <div
                      style={{
                        display: "flex",
                        flexDirection: "column",
                        gap: 6,
                      }}
                    >
                      {checkRegistry.map((c, i) => (
                        <div
                          key={i}
                          style={{
                            display: "flex",
                            justifyContent: "space-between",
                            alignItems: "center",
                            padding: "9px 12px",
                            background: assignments[c.key] ? "#f0fdf4" : "#fff",
                            borderRadius: 8,
                            border: `1px solid ${assignments[c.key] ? "#bbf7d0" : "#fde047"}`,
                          }}
                        >
                          <div style={{ flex: 1, minWidth: 0 }}>
                            <span
                              onClick={() => openDevFindingsDrawer(c.key)}
                              style={{
                                fontSize: 12,
                                fontWeight: 700,
                                color: "#0a6ed1",
                                cursor: "pointer",
                                textDecoration: "underline",
                                textDecorationStyle: "dotted",
                              }}
                            >
                              {resolveCheckCategory(
                                findings.find(
                                  (f) =>
                                    (f.CheckCategory ||
                                      resolveCheckCategory(f)) === c.key,
                                ) || {},
                              ) || c.key}
                            </span>
                            <div
                              style={{
                                display: "flex",
                                gap: 4,
                                flexWrap: "wrap",
                                marginTop: 3,
                              }}
                            >
                              {c.p1 > 0 && (
                                <span
                                  style={{
                                    background: "#fee2e2",
                                    color: "#dc2626",
                                    borderRadius: 999,
                                    padding: "1px 6px",
                                    fontSize: 10,
                                    fontWeight: 700,
                                  }}
                                >
                                  P1:{c.p1}
                                </span>
                              )}
                              {c.p2 > 0 && (
                                <span
                                  style={{
                                    background: "#fef3c7",
                                    color: "#d97706",
                                    borderRadius: 999,
                                    padding: "1px 6px",
                                    fontSize: 10,
                                    fontWeight: 700,
                                  }}
                                >
                                  P2:{c.p2}
                                </span>
                              )}
                              {c.p3 > 0 && (
                                <span
                                  style={{
                                    background: "#dbeafe",
                                    color: "#2563eb",
                                    borderRadius: 999,
                                    padding: "1px 6px",
                                    fontSize: 10,
                                    fontWeight: 700,
                                  }}
                                >
                                  P3:{c.p3}
                                </span>
                              )}
                              {c.p4 > 0 && (
                                <span
                                  style={{
                                    background: "#f3f4f6",
                                    color: "#6b7280",
                                    borderRadius: 999,
                                    padding: "1px 6px",
                                    fontSize: 10,
                                    fontWeight: 700,
                                  }}
                                >
                                  P4:{c.p4}
                                </span>
                              )}
                              <span style={{ fontSize: 10, color: "#9ca3af" }}>
                                {c.objectCount} objects
                              </span>
                              {renderJiraTicketBadge("CHECK", c.key)}
                            </div>
                          </div>
                          <select
                            value={assignments[c.key] || ""}
                            onChange={(e) => {
                              const v = e.target.value;
                              setAssignments((p) => {
                                const n = { ...p };
                                if (v) n[c.key] = v;
                                else delete n[c.key];
                                return n;
                              });
                            }}
                            style={{
                              padding: "4px 8px",
                              borderRadius: 6,
                              border: `1px solid ${assignments[c.key] ? "#22c55e" : "#fde047"}`,
                              fontSize: 11,
                              background: assignments[c.key]
                                ? "#f0fdf4"
                                : "white",
                              color: assignments[c.key] ? "#15803d" : "#374151",
                              fontWeight: assignments[c.key] ? 700 : 400,
                              maxWidth: 160,
                              cursor: "pointer",
                              flexShrink: 0,
                              marginLeft: 10,
                            }}
                          >
                            <option value="">Unassigned</option>
                            {devProfiles.length > 0
                              ? devProfiles.map((p) => (
                                  <option key={p.UserId} value={p.UserId}>
                                    {p.DisplayName}
                                  </option>
                                ))
                              : allKnownDevelopers.map((d) => (
                                  <option key={d} value={d}>
                                    {d}
                                  </option>
                                ))}
                          </select>
                        </div>
                      ))}
                    </div>
                  </div>
                  {developerWorkload.length === 0 ? (
                    <div
                      style={{
                        padding: "32px 20px",
                        textAlign: "center",
                        background: "var(--card-bg,#fff)",
                        borderRadius: 12,
                        border: "1px dashed #d1d5db",
                        color: "#9ca3af",
                        fontSize: 13,
                      }}
                    >
                      <div style={{ fontSize: 28, marginBottom: 8 }}>📋</div>No
                      assignments yet. Use the registry to assign check types,
                      or run <strong>AI Pattern Analysis</strong> for smart
                      suggestions.
                    </div>
                  ) : (
                    <>
                      <div
                        style={{
                          fontSize: 10,
                          fontWeight: 700,
                          color: "#0a6ed1",
                          letterSpacing: 1,
                          textTransform: "uppercase",
                        }}
                      >
                        Developer Workload — sorted by priority score
                      </div>
                      {developerWorkload.map((dw, i) => (
                        <div
                          key={i}
                          style={{
                            background: "var(--card-bg,#fff)",
                            borderRadius: 12,
                            border: `1px solid ${dw.p1 > 0 ? "#fecaca" : "#e5e7eb"}`,
                            overflow: "hidden",
                          }}
                        >
                          <div
                            style={{
                              padding: "14px 18px",
                              background: dw.p1 > 20 ? "#fff8f8" : "#fafafa",
                              borderBottom: "1px solid #f3f4f6",
                            }}
                          >
                            <div
                              style={{
                                display: "flex",
                                justifyContent: "space-between",
                                alignItems: "flex-start",
                                flexWrap: "wrap",
                                gap: 8,
                              }}
                            >
                              <div>
                                <div
                                  style={{
                                    fontSize: 14,
                                    fontWeight: 700,
                                    color: "#111827",
                                  }}
                                >
                                  {displayUser(dw.dev)}
                                </div>
                                <div
                                  style={{
                                    fontSize: 11,
                                    color: "#6b7280",
                                    marginTop: 2,
                                  }}
                                >
                                  {dw.assignedChecks.length} check type
                                  {dw.assignedChecks.length !== 1
                                    ? "s"
                                    : ""} · {dw.objectCount} objects · oldest:{" "}
                                  {dw.oldestAge > 0 ? `${dw.oldestAge}d` : "—"}
                                </div>
                              </div>
                              <div
                                style={{
                                  display: "flex",
                                  gap: 6,
                                  alignItems: "center",
                                  flexWrap: "wrap",
                                }}
                              >
                                {dw.p1 > 0 && (
                                  <span
                                    style={{
                                      background: "#fee2e2",
                                      color: "#dc2626",
                                      borderRadius: 999,
                                      padding: "3px 9px",
                                      fontSize: 11,
                                      fontWeight: 700,
                                    }}
                                  >
                                    P1:{dw.p1}
                                  </span>
                                )}
                                {dw.p2 > 0 && (
                                  <span
                                    style={{
                                      background: "#fef3c7",
                                      color: "#d97706",
                                      borderRadius: 999,
                                      padding: "3px 9px",
                                      fontSize: 11,
                                      fontWeight: 700,
                                    }}
                                  >
                                    P2:{dw.p2}
                                  </span>
                                )}
                                <span
                                  style={{
                                    background: "#f3f4f6",
                                    color: "#6b7280",
                                    borderRadius: 6,
                                    padding: "3px 9px",
                                    fontSize: 11,
                                    fontWeight: 700,
                                  }}
                                >
                                  Score:{Math.round(dw.priorityScore)}
                                </span>
                              </div>
                            </div>
                          </div>
                          <div
                            style={{ padding: "10px 18px", overflowX: "auto" }}
                          >
                            <table
                              style={{
                                width: "100%",
                                borderCollapse: "collapse",
                              }}
                            >
                              <thead>
                                <tr style={{ background: "#f8fafc" }}>
                                  <th
                                    style={{
                                      padding: "7px 10px",
                                      fontSize: 10,
                                      fontWeight: 700,
                                      color: "#6b7280",
                                      textTransform: "uppercase",
                                      letterSpacing: 0.5,
                                      textAlign: "left",
                                      borderBottom: "1px solid #e5e7eb",
                                    }}
                                  >
                                    Check Type
                                  </th>
                                  <th
                                    style={{
                                      padding: "7px 10px",
                                      fontSize: 10,
                                      fontWeight: 700,
                                      color: "#6b7280",
                                      textTransform: "uppercase",
                                      letterSpacing: 0.5,
                                      textAlign: "right",
                                      borderBottom: "1px solid #e5e7eb",
                                    }}
                                  >
                                    P1
                                  </th>
                                  <th
                                    style={{
                                      padding: "7px 10px",
                                      fontSize: 10,
                                      fontWeight: 700,
                                      color: "#6b7280",
                                      textTransform: "uppercase",
                                      letterSpacing: 0.5,
                                      textAlign: "right",
                                      borderBottom: "1px solid #e5e7eb",
                                    }}
                                  >
                                    P2
                                  </th>
                                  <th
                                    style={{
                                      padding: "7px 10px",
                                      fontSize: 10,
                                      fontWeight: 700,
                                      color: "#6b7280",
                                      textTransform: "uppercase",
                                      letterSpacing: 0.5,
                                      textAlign: "right",
                                      borderBottom: "1px solid #e5e7eb",
                                    }}
                                  >
                                    Objects
                                  </th>
                                  <th
                                    style={{
                                      padding: "7px 10px",
                                      fontSize: 10,
                                      fontWeight: 700,
                                      color: "#6b7280",
                                      textTransform: "uppercase",
                                      letterSpacing: 0.5,
                                      textAlign: "right",
                                      borderBottom: "1px solid #e5e7eb",
                                    }}
                                  >
                                    Total
                                  </th>
                                </tr>
                              </thead>
                              <tbody>
                                {dw.assignedChecks.map((ck, j) => {
                                  const reg = checkRegistry.find(
                                    (c) => c.key === ck,
                                  );
                                  if (!reg) return null;
                                  return (
                                    <tr
                                      key={j}
                                      style={{
                                        background:
                                          j % 2 === 0 ? "#fff" : "#fafafa",
                                      }}
                                    >
                                      <td
                                        style={{
                                          padding: "7px 10px",
                                          fontSize: 12,
                                          fontWeight: 600,
                                          color: "#374151",
                                          wordBreak: "break-all",
                                        }}
                                      >
                                        {resolveCheckCategory(
                                          findings.find(
                                            (f) =>
                                              (f.CheckCategory ||
                                                resolveCheckCategory(f)) === ck,
                                          ) || {},
                                        ) || ck}
                                      </td>
                                      <td
                                        style={{
                                          padding: "7px 10px",
                                          textAlign: "right",
                                        }}
                                      >
                                        {reg.p1 > 0 ? (
                                          <span
                                            style={{
                                              background: "#fee2e2",
                                              color: "#dc2626",
                                              borderRadius: 999,
                                              padding: "1px 6px",
                                              fontSize: 11,
                                              fontWeight: 700,
                                            }}
                                          >
                                            {reg.p1}
                                          </span>
                                        ) : (
                                          <span
                                            style={{
                                              color: "#d1d5db",
                                              fontSize: 11,
                                            }}
                                          >
                                            —
                                          </span>
                                        )}
                                      </td>
                                      <td
                                        style={{
                                          padding: "7px 10px",
                                          textAlign: "right",
                                        }}
                                      >
                                        {reg.p2 > 0 ? (
                                          <span
                                            style={{
                                              background: "#fef3c7",
                                              color: "#d97706",
                                              borderRadius: 999,
                                              padding: "1px 6px",
                                              fontSize: 11,
                                              fontWeight: 700,
                                            }}
                                          >
                                            {reg.p2}
                                          </span>
                                        ) : (
                                          <span
                                            style={{
                                              color: "#d1d5db",
                                              fontSize: 11,
                                            }}
                                          >
                                            —
                                          </span>
                                        )}
                                      </td>
                                      <td
                                        style={{
                                          padding: "7px 10px",
                                          textAlign: "right",
                                          fontSize: 12,
                                          color: "#6b7280",
                                        }}
                                      >
                                        {reg.objectCount}
                                      </td>
                                      <td
                                        style={{
                                          padding: "7px 10px",
                                          textAlign: "right",
                                          fontSize: 12,
                                          fontWeight: 700,
                                          color: "#111827",
                                        }}
                                      >
                                        {reg.total}
                                      </td>
                                      <td
                                        style={{
                                          padding: "7px 4px",
                                          textAlign: "right",
                                        }}
                                      />
                                    </tr>
                                  );
                                })}
                              </tbody>
                            </table>
                          </div>
                        </div>
                      ))}
                    </>
                  )}
                </div>
              </div>
            ) : null}

            {/* Package Findings Drawer */}
            {pkgFindingsDrawerOpen && (
              <div
                onClick={(e) => {
                  if (e.target === e.currentTarget)
                    setPkgFindingsDrawerOpen(false);
                }}
                style={{
                  position: "fixed",
                  inset: 0,
                  background: "rgba(0,0,0,0.35)",
                  zIndex: 700,
                  display: "flex",
                  justifyContent: "flex-end",
                }}
              >
                <div
                  style={{
                    width: isMobile ? "100vw" : "min(680px,100vw)",
                    height: "100vh",
                    background: "var(--card-bg,#fff)",
                    boxShadow: "-4px 0 32px rgba(0,0,0,0.18)",
                    display: "flex",
                    flexDirection: "column",
                    boxSizing: "border-box",
                  }}
                >
                  <div style={{ padding: "20px 20px 0 20px", flexShrink: 0 }}>
                    <div
                      style={{
                        display: "flex",
                        justifyContent: "space-between",
                        alignItems: "flex-start",
                        marginBottom: 12,
                      }}
                    >
                      <div>
                        <h2
                          style={{ margin: 0, fontSize: 16, fontWeight: 700 }}
                        >
                          📦 {pkgFindingsDrawerTitle}
                        </h2>
                        <div
                          style={{
                            fontSize: 12,
                            color: "#6b7280",
                            marginTop: 4,
                          }}
                        >
                          {pkgFindingsDrawerData.length} findings · sorted by
                          priority
                        </div>
                      </div>
                      <button
                        className="drawer-close"
                        onClick={() => setPkgFindingsDrawerOpen(false)}
                      >
                        ✕
                      </button>
                    </div>
                    <div
                      style={{
                        display: "grid",
                        gridTemplateColumns: "1fr 1fr 1fr 1fr",
                        gap: 8,
                        marginBottom: 12,
                      }}
                    >
                      {[
                        { l: "P1", p: 1, c: "#dc2626", b: "#fee2e2" },
                        { l: "P2", p: 2, c: "#d97706", b: "#fef3c7" },
                        { l: "P3", p: 3, c: "#2563eb", b: "#dbeafe" },
                        { l: "P4", p: 4, c: "#374151", b: "#f3f4f6" },
                      ].map(({ l, p, c, b }) => {
                        const cnt = pkgFindingsDrawerData.filter(
                          (f) => Number(f.Priority) === p,
                        ).length;
                        return (
                          <div
                            key={p}
                            style={{
                              padding: "10px 8px",
                              borderRadius: 10,
                              textAlign: "center",
                              background: cnt > 0 ? b : "#f9fafb",
                              border: `2px solid ${cnt > 0 ? c : "#e5e7eb"}`,
                            }}
                          >
                            <div
                              style={{
                                fontSize: 10,
                                color: cnt > 0 ? c : "#6b7280",
                                fontWeight: 600,
                              }}
                            >
                              {l}
                            </div>
                            <div
                              style={{
                                fontSize: 20,
                                fontWeight: 700,
                                color: cnt > 0 ? c : "#9ca3af",
                                marginTop: 2,
                              }}
                            >
                              {cnt}
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                  <div
                    style={{
                      flex: 1,
                      overflowY: "auto",
                      padding: "0 20px 20px 20px",
                    }}
                  >
                    {[...pkgFindingsDrawerData]
                      .sort((a, b) => Number(a.Priority) - Number(b.Priority))
                      .map((f, i) => {
                        const pColor =
                          f.Priority === 1
                            ? "#ef4444"
                            : f.Priority === 2
                              ? "#f59e0b"
                              : f.Priority === 3
                                ? "#3b82f6"
                                : "#6b7280";
                        const pBg =
                          f.Priority === 1
                            ? "#fee2e2"
                            : f.Priority === 2
                              ? "#fef3c7"
                              : f.Priority === 3
                                ? "#dbeafe"
                                : "#f3f4f6";
                        const sinceDate = parseSince(f.Since);
                        const age = sinceDate ? ageDays(sinceDate) : null;
                        return (
                          <div
                            key={i}
                            style={{
                              border: "1px solid #e5e7eb",
                              borderLeft: `4px solid ${pColor}`,
                              borderRadius: 8,
                              padding: "12px 14px",
                              marginBottom: 10,
                              background: "#fafafa",
                            }}
                          >
                            <div
                              style={{
                                display: "flex",
                                justifyContent: "space-between",
                                alignItems: "flex-start",
                                marginBottom: 6,
                              }}
                            >
                              <div
                                style={{
                                  fontWeight: 700,
                                  fontSize: 13,
                                  wordBreak: "break-all",
                                  flex: 1,
                                  marginRight: 8,
                                  color: "#111827",
                                }}
                              >
                                {f.ObjectName || "—"}
                              </div>
                              <span
                                style={{
                                  background: pBg,
                                  color: pColor,
                                  border: `1px solid ${pColor}`,
                                  borderRadius: 999,
                                  padding: "2px 8px",
                                  fontSize: 11,
                                  fontWeight: 700,
                                }}
                              >
                                P{f.Priority}
                              </span>
                            </div>
                            {(f.RstismTitle || "").trim() && (
                              <div
                                style={{
                                  fontSize: 12,
                                  color: "#374151",
                                  marginBottom: 6,
                                  fontStyle: "italic",
                                }}
                              >
                                {f.RstismTitle}
                              </div>
                            )}
                            <div
                              style={{
                                display: "grid",
                                gridTemplateColumns: "100px 1fr",
                                gap: "3px 8px",
                                fontSize: 12,
                              }}
                            >
                              <span style={{ color: "#9ca3af" }}>Check</span>
                              <span style={{ color: "#374151" }}>
                                {resolveCheckCategory(f)}
                              </span>
                              <span style={{ color: "#9ca3af" }}>
                                Object Type
                              </span>
                              <span style={{ color: "#374151" }}>
                                {OBJECT_TYPE_LABELS[f.ObjectType] ||
                                  f.ObjectType ||
                                  "—"}
                              </span>
                              <span style={{ color: "#9ca3af" }}>Package</span>
                              <span style={{ color: "#374151" }}>
                                {f.PackageName || "—"}
                              </span>
                              <span style={{ color: "#9ca3af" }}>Contact</span>
                              <span style={{ color: "#374151" }}>
                                {f.ContactPerson || f.Processor || "—"}
                              </span>
                              <span style={{ color: "#9ca3af" }}>
                                Message Key
                              </span>
                              <span style={{ color: "#374151" }}>
                                {f.MessageKey || "—"}
                              </span>
                              {f.Location && f.Location.trim() !== "" && (
                                <>
                                  <span style={{ color: "#9ca3af" }}>
                                    Location
                                  </span>
                                  <span
                                    style={{
                                      color: "#374151",
                                      wordBreak: "break-all",
                                    }}
                                  >
                                    {f.Location}
                                  </span>
                                </>
                              )}
                              {age !== null && (
                                <>
                                  <span style={{ color: "#9ca3af" }}>Age</span>
                                  <span
                                    style={{
                                      color:
                                        age > 90
                                          ? "#dc2626"
                                          : age > 30
                                            ? "#d97706"
                                            : "#374151",
                                      fontWeight: age > 30 ? 600 : 400,
                                    }}
                                  >
                                    {age} day{age !== 1 ? "s" : ""} open
                                  </span>
                                </>
                              )}
                            </div>
                            {renderNavButtons(f)}
                            {renderFixGuidance(f)}
                          </div>
                        );
                      })}
                  </div>
                </div>
              </div>
            )}

            {/* Developer Hub Findings Drawer */}
            {devFindingsDrawerOpen && (
              <div
                onClick={(e) => {
                  if (e.target === e.currentTarget)
                    setDevFindingsDrawerOpen(false);
                }}
                style={{
                  position: "fixed",
                  inset: 0,
                  background: "rgba(0,0,0,0.35)",
                  zIndex: 700,
                  display: "flex",
                  justifyContent: "flex-end",
                }}
              >
                <div
                  style={{
                    width: isMobile ? "100vw" : "min(680px,100vw)",
                    height: "100vh",
                    background: "var(--card-bg,#ffffff)",
                    boxShadow: "-4px 0 32px rgba(0,0,0,0.18)",
                    display: "flex",
                    flexDirection: "column",
                    boxSizing: "border-box",
                    overflowX: "hidden",
                  }}
                >
                  <div style={{ padding: "20px 20px 0 20px", flexShrink: 0 }}>
                    <div
                      style={{
                        display: "flex",
                        justifyContent: "space-between",
                        alignItems: "flex-start",
                        marginBottom: 12,
                      }}
                    >
                      <div style={{ minWidth: 0 }}>
                        <h2
                          style={{
                            margin: 0,
                            fontSize: 16,
                            fontWeight: 700,
                            wordBreak: "break-word",
                          }}
                        >
                          Findings — {devFindingsDrawerTitle}
                        </h2>
                        <div
                          style={{
                            fontSize: 12,
                            color: "#6b7280",
                            marginTop: 4,
                          }}
                        >
                          {devFindingsDrawerData.length} finding
                          {devFindingsDrawerData.length !== 1 ? "s" : ""} ·
                          sorted by priority
                        </div>
                      </div>
                      <button
                        className="drawer-close"
                        onClick={() => setDevFindingsDrawerOpen(false)}
                        style={{ flexShrink: 0, marginLeft: 12 }}
                      >
                        ✕
                      </button>
                    </div>
                    <div
                      style={{
                        display: "grid",
                        gridTemplateColumns: isMobile
                          ? "1fr 1fr"
                          : "1fr 1fr 1fr 1fr",
                        gap: 8,
                        marginBottom: 12,
                      }}
                    >
                      {[
                        {
                          label: "P1",
                          prio: 1,
                          color: "#dc2626",
                          bg: "#fee2e2",
                          border: "#ef4444",
                        },
                        {
                          label: "P2",
                          prio: 2,
                          color: "#d97706",
                          bg: "#fef3c7",
                          border: "#f59e0b",
                        },
                        {
                          label: "P3",
                          prio: 3,
                          color: "#2563eb",
                          bg: "#dbeafe",
                          border: "#3b82f6",
                        },
                        {
                          label: "P4",
                          prio: 4,
                          color: "#374151",
                          bg: "#f3f4f6",
                          border: "#6b7280",
                        },
                      ].map(({ label, prio, color, bg, border }) => {
                        const cnt = devFindingsDrawerData.filter(
                          (f) => Number(f.Priority) === prio,
                        ).length;
                        return (
                          <div
                            key={prio}
                            style={{
                              padding: "10px 8px",
                              borderRadius: 10,
                              textAlign: "center",
                              background: cnt > 0 ? bg : "#f9fafb",
                              border: `2px solid ${cnt > 0 ? border : "#e5e7eb"}`,
                            }}
                          >
                            <div
                              style={{
                                fontSize: 10,
                                color: cnt > 0 ? color : "#6b7280",
                                fontWeight: 600,
                              }}
                            >
                              {label}
                            </div>
                            <div
                              style={{
                                fontSize: 20,
                                fontWeight: 700,
                                color: cnt > 0 ? color : "#9ca3af",
                                marginTop: 2,
                              }}
                            >
                              {cnt}
                            </div>
                          </div>
                        );
                      })}
                    </div>
                    <div
                      style={{
                        display: "flex",
                        alignItems: "center",
                        gap: 10,
                        padding: "10px 12px",
                        background: assignments[devFindingsDrawerTitle]
                          ? "#f0fdf4"
                          : "#f9fafb",
                        borderRadius: 8,
                        border: `1px solid ${assignments[devFindingsDrawerTitle] ? "#bbf7d0" : "#e5e7eb"}`,
                        marginBottom: 12,
                      }}
                    >
                      <span
                        style={{
                          fontSize: 12,
                          fontWeight: 600,
                          color: "#374151",
                        }}
                      >
                        Assigned to:
                      </span>
                      <span
                        style={{
                          fontSize: 12,
                          fontWeight: 700,
                          color: assignments[devFindingsDrawerTitle]
                            ? "#15803d"
                            : "#9ca3af",
                        }}
                      >
                        {assignments[devFindingsDrawerTitle] || "Unassigned"}
                      </span>
                    </div>{" "}
                  </div>
                  <div
                    style={{
                      flex: 1,
                      overflowY: "auto",
                      padding: "0 20px 20px 20px",
                    }}
                  >
                    {devFindingsDrawerData.length === 0 ? (
                      <div
                        style={{
                          textAlign: "center",
                          padding: 32,
                          color: "#6b7280",
                          fontSize: 13,
                        }}
                      >
                        No findings for this check type.
                      </div>
                    ) : (
                      [...devFindingsDrawerData]
                        .sort((a, b) => Number(a.Priority) - Number(b.Priority))
                        .map((f, i) => {
                          const pColor =
                            f.Priority === 1
                              ? "#ef4444"
                              : f.Priority === 2
                                ? "#f59e0b"
                                : f.Priority === 3
                                  ? "#3b82f6"
                                  : "#6b7280";
                          const pBg =
                            f.Priority === 1
                              ? "#fee2e2"
                              : f.Priority === 2
                                ? "#fef3c7"
                                : f.Priority === 3
                                  ? "#dbeafe"
                                  : "#f3f4f6";
                          const statusText =
                            f.StatusNew === "1"
                              ? "Open"
                              : f.StatusNew === "2"
                                ? "In Progress"
                                : f.StatusNew === "3"
                                  ? "Resolved"
                                  : f.StatusNew || "—";
                          const sinceDate = parseSince(f.Since);
                          const age = sinceDate ? ageDays(sinceDate) : null;
                          const rstismTitle = (f.RstismTitle ?? "").trim();
                          const fallbackTitle = resolveCheckTitle(
                            f.CheckTitle,
                            f.NavigationData,
                          );
                          const displayTitle = rstismTitle
                            ? rstismTitle
                            : fallbackTitle || null;
                          const resolvedCiId = resolveCiId(f);
                          return (
                            <div
                              key={`devhub-${f.ItemId ?? i}`}
                              style={{
                                border: "1px solid #e5e7eb",
                                borderLeft: `4px solid ${pColor}`,
                                borderRadius: 8,
                                padding: "12px 14px",
                                marginBottom: 10,
                                background: "#fafafa",
                              }}
                            >
                              <div
                                style={{
                                  display: "flex",
                                  justifyContent: "space-between",
                                  alignItems: "flex-start",
                                  marginBottom: 6,
                                }}
                              >
                                <div
                                  style={{
                                    fontWeight: 700,
                                    fontSize: 13,
                                    wordBreak: "break-all",
                                    flex: 1,
                                    marginRight: 8,
                                    color: "#111827",
                                  }}
                                >
                                  {f.ObjectName || "—"}
                                </div>
                                <span
                                  style={{
                                    background: pBg,
                                    color: pColor,
                                    border: `1px solid ${pColor}`,
                                    borderRadius: 999,
                                    padding: "2px 8px",
                                    fontSize: 11,
                                    fontWeight: 700,
                                    flexShrink: 0,
                                  }}
                                >
                                  P{f.Priority}
                                </span>
                              </div>
                              {displayTitle && (
                                <div
                                  style={{
                                    fontSize: 12,
                                    color: "#374151",
                                    marginBottom: 6,
                                    fontStyle: "italic",
                                  }}
                                >
                                  {displayTitle}
                                </div>
                              )}
                              <div
                                style={{
                                  display: "grid",
                                  gridTemplateColumns: "100px 1fr",
                                  gap: "3px 8px",
                                  fontSize: 12,
                                }}
                              >
                                <span style={{ color: "#9ca3af" }}>
                                  Object Type
                                </span>
                                <span style={{ color: "#374151" }}>
                                  {OBJECT_TYPE_LABELS[f.ObjectType] ||
                                    f.ObjectType ||
                                    "—"}
                                </span>
                                <span style={{ color: "#9ca3af" }}>
                                  Package
                                </span>
                                <span style={{ color: "#374151" }}>
                                  {f.PackageName || "—"}
                                </span>
                                <span style={{ color: "#9ca3af" }}>
                                  Contact
                                </span>
                                <span style={{ color: "#374151" }}>
                                  {f.ContactPerson || f.Processor || "—"}
                                </span>
                                <span style={{ color: "#9ca3af" }}>
                                  Message Key
                                </span>
                                <span style={{ color: "#374151" }}>
                                  {f.MessageKey || "—"}
                                </span>
                                {f.Location && f.Location.trim() !== "" && (
                                  <>
                                    <span style={{ color: "#9ca3af" }}>
                                      Location
                                    </span>
                                    <span
                                      style={{
                                        color: "#374151",
                                        wordBreak: "break-all",
                                      }}
                                    >
                                      {f.Location}
                                    </span>
                                  </>
                                )}
                                {age !== null && (
                                  <>
                                    <span style={{ color: "#9ca3af" }}>
                                      Age
                                    </span>
                                    <span
                                      style={{
                                        color:
                                          age > 90
                                            ? "#dc2626"
                                            : age > 30
                                              ? "#d97706"
                                              : "#374151",
                                        fontWeight: age > 30 ? 600 : 400,
                                      }}
                                    >
                                      {age} day{age !== 1 ? "s" : ""} open
                                    </span>
                                  </>
                                )}
                                <span style={{ color: "#9ca3af" }}>Status</span>
                                <span
                                  style={{
                                    color:
                                      f.StatusNew === "1"
                                        ? "#dc2626"
                                        : f.StatusNew === "2"
                                          ? "#d97706"
                                          : "#16a34a",
                                    fontWeight: 600,
                                  }}
                                >
                                  {statusText}
                                </span>
                              </div>
                              {renderNavButtons(f)}
                              {renderFixGuidance(f)}
                            </div>
                          );
                        })
                    )}
                  </div>
                </div>
              </div>
            )}
          </div>
        )}
        {/* ════ CERTIFICATION TAB ════ */}
        {tab === "certification" && (
          <div style={{ display: "flex", flexDirection: "column", gap: 20 }}>
            <div>
              <div
                style={{
                  fontSize: 10,
                  fontWeight: 700,
                  color: "#0a6ed1",
                  letterSpacing: 1,
                  textTransform: "uppercase",
                  marginBottom: 4,
                }}
              >
                Product Certification Intelligence
              </div>
              <div style={{ fontSize: 20, fontWeight: 800, color: "#0f172a" }}>
                Certification Readiness
              </div>
              <div style={{ fontSize: 13, color: "#6b7280", marginTop: 4 }}>
                Select a product · click a run series to see packages
              </div>
            </div>

            {products.length === 0 ? (
              <div
                style={{
                  padding: "48px 20px",
                  textAlign: "center",
                  background: "var(--card-bg,#fff)",
                  borderRadius: 12,
                  border: "1px dashed #d1d5db",
                }}
              >
                <div style={{ fontSize: 36, marginBottom: 12 }}>🏆</div>
                <div
                  style={{
                    fontSize: 14,
                    fontWeight: 700,
                    color: "#374151",
                    marginBottom: 6,
                  }}
                >
                  No products configured
                </div>
                <div style={{ fontSize: 13, color: "#9ca3af" }}>
                  Add products and run series to ZATC_PRODUCTS and
                  ZATC_PROD_SERIES in the backend.
                </div>
              </div>
            ) : (
              <div
                style={{
                  display: "grid",
                  gridTemplateColumns: isMobile ? "1fr" : "240px 1fr",
                  gap: 20,
                  alignItems: "start",
                }}
              >
                {/* Left panel — product list */}
                <div
                  style={{
                    background: "var(--card-bg,#fff)",
                    borderRadius: 12,
                    border: "1px solid #e5e7eb",
                    overflow: "hidden",
                  }}
                >
                  <div
                    style={{
                      padding: "14px 16px",
                      borderBottom: "1px solid #f3f4f6",
                    }}
                  >
                    <div
                      style={{
                        fontSize: 10,
                        fontWeight: 700,
                        color: "#0a6ed1",
                        letterSpacing: 1,
                        textTransform: "uppercase",
                        marginBottom: 2,
                      }}
                    >
                      Products
                    </div>
                    <div style={{ fontSize: 12, color: "#6b7280" }}>
                      {products.length} configured
                    </div>
                  </div>
                  {products.map((p: any) => {
                    const isSelected =
                      selectedProduct?.ProductId === p.ProductId;
                    const seriesForProduct = productRunSeries.filter(
                      (s: any) => s.ProductId === p.ProductId,
                    );
                    const latestRunForProduct =
                      seriesForProduct
                        .flatMap((s: any) =>
                          filteredRuns.filter(
                            (r) =>
                              (r.series || "").toUpperCase() ===
                              (s.RunSeries || "").toUpperCase(),
                          ),
                        )
                        .sort((a, b) =>
                          (b.date || "").localeCompare(a.date || ""),
                        )[0] || null;
                    const isReady = latestRunForProduct
                      ? latestRunForProduct.p1 + latestRunForProduct.p2 === 0
                      : null;
                    return (
                      <div
                        key={p.ProductId}
                        onClick={() => setSelectedProduct(p)}
                        style={{
                          padding: "14px 16px",
                          borderBottom: "1px solid #f3f4f6",
                          cursor: "pointer",
                          background: isSelected ? "#eff6ff" : "transparent",
                          borderLeft: isSelected
                            ? "3px solid #0a6ed1"
                            : "3px solid transparent",
                          transition: "all 0.15s",
                        }}
                      >
                        <div
                          style={{
                            display: "flex",
                            justifyContent: "space-between",
                            alignItems: "center",
                          }}
                        >
                          <div>
                            <div
                              style={{
                                fontSize: 13,
                                fontWeight: 700,
                                color: isSelected ? "#0a6ed1" : "#111827",
                              }}
                            >
                              {p.ProductName || p.ProductId}
                            </div>
                            <div
                              style={{
                                fontSize: 11,
                                color: "#6b7280",
                                marginTop: 2,
                              }}
                            >
                              {seriesForProduct.length} series
                            </div>
                          </div>
                          {isReady === null ? (
                            <span
                              style={{
                                width: 10,
                                height: 10,
                                borderRadius: "50%",
                                background: "#d1d5db",
                                display: "inline-block",
                              }}
                            />
                          ) : isReady ? (
                            <span
                              style={{
                                width: 10,
                                height: 10,
                                borderRadius: "50%",
                                background: "#22c55e",
                                display: "inline-block",
                              }}
                            />
                          ) : (
                            <span
                              style={{
                                width: 10,
                                height: 10,
                                borderRadius: "50%",
                                background: "#ef4444",
                                display: "inline-block",
                              }}
                            />
                          )}
                        </div>
                      </div>
                    );
                  })}
                </div>

                {/* Right panel — series cards */}
                {!selectedProduct ? (
                  <div
                    style={{
                      padding: "48px 20px",
                      textAlign: "center",
                      background: "var(--card-bg,#fff)",
                      borderRadius: 12,
                      border: "1px dashed #d1d5db",
                    }}
                  >
                    <div style={{ fontSize: 36, marginBottom: 12 }}>👆</div>
                    <div
                      style={{
                        fontSize: 14,
                        fontWeight: 700,
                        color: "#374151",
                        marginBottom: 6,
                      }}
                    >
                      Select a product
                    </div>
                    <div style={{ fontSize: 13, color: "#9ca3af" }}>
                      Choose a product from the left panel to view its
                      certification readiness.
                    </div>
                  </div>
                ) : (
                  <div
                    style={{
                      display: "flex",
                      flexDirection: "column",
                      gap: 16,
                    }}
                  >
                    {/* Product header */}
                    <div
                      style={{
                        background: "var(--card-bg,#fff)",
                        borderRadius: 12,
                        border: "1px solid #e5e7eb",
                        padding: "18px 22px",
                      }}
                    >
                      <div
                        style={{
                          fontSize: 18,
                          fontWeight: 800,
                          color: "#0f172a",
                          marginBottom: 2,
                        }}
                      >
                        {selectedProduct.ProductName ||
                          selectedProduct.ProductId}
                      </div>
                      <div style={{ fontSize: 12, color: "#6b7280" }}>
                        {selectedProduct.ProductId} ·{" "}
                        {
                          productRunSeries.filter(
                            (s: any) =>
                              s.ProductId === selectedProduct.ProductId,
                          ).length
                        }{" "}
                        run series assigned
                      </div>
                    </div>

                    {/* Series cards */}
                    {productRunSeries
                      .filter(
                        (s: any) => 
                          s.ProductId === selectedProduct.ProductId &&
                          s.IsActive === "X"
                      )
                      .sort(
                        (a, b) => (a.DisplayOrder || 0) - (b.DisplayOrder || 0),
                      )
                      .map((s: any, si: number) => {
                        const runsForSeries = filteredRuns
                          .filter(
                            (r) =>
                              (r.series || "").toUpperCase() ===
                              (s.RunSeries || "").toUpperCase(),
                          )
                          .sort((a, b) =>
                            (b.date || "").localeCompare(a.date || ""),
                          );
                        const latestRun = runsForSeries[0] || null;
                        const isReady = latestRun
                          ? latestRun.p1 + latestRun.p2 === 0
                          : null;

                        return (
                          <div
                            key={si}
                            style={{
                              background: "var(--card-bg,#fff)",
                              borderRadius: 12,
                              border: `2px solid ${isReady === null ? "#e5e7eb" : isReady ? "#22c55e" : "#ef4444"}`,
                              overflow: "hidden",
                              boxShadow: "0 1px 4px rgba(0,0,0,0.06)",
                            }}
                          >
                            <div
                              style={{
                                padding: "16px 20px",
                                background:
                                  isReady === null
                                    ? "#f9fafb"
                                    : isReady
                                      ? "linear-gradient(135deg,#f0fdf4,#dcfce7)"
                                      : "linear-gradient(135deg,#fef2f2,#fee2e2)",
                                borderBottom: "1px solid #f3f4f6",
                                display: "flex",
                                justifyContent: "space-between",
                                alignItems: "center",
                                flexWrap: "wrap",
                                gap: 10,
                              }}
                            >
                              <div>
                                <div
                                  style={{
                                    fontSize: 15,
                                    fontWeight: 700,
                                    color: "#0f172a",
                                  }}
                                >
                                  {s.RunSeries}
                                </div>
                                {s.Description && (
                                  <div
                                    style={{
                                      fontSize: 12,
                                      color: "#6b7280",
                                      marginTop: 2,
                                    }}
                                  >
                                    {s.Description}
                                  </div>
                                )}
                                {latestRun && (
                                  <div
                                    style={{
                                      fontSize: 11,
                                      color: "#6b7280",
                                      marginTop: 2,
                                    }}
                                  >
                                    Latest: {latestRun.date} ·{" "}
                                    {runsForSeries.length} total run
                                    {runsForSeries.length !== 1 ? "s" : ""}
                                  </div>
                                )}
                              </div>
                              <div
                                style={{
                                  display: "flex",
                                  gap: 8,
                                  alignItems: "center",
                                }}
                              >
                                {latestRun && (
                                  <>
                                    {[
                                      {
                                        l: "P1",
                                        v: latestRun.p1,
                                        c: "#dc2626",
                                        b: "#fee2e2",
                                      },
                                      {
                                        l: "P2",
                                        v: latestRun.p2,
                                        c: "#d97706",
                                        b: "#fef3c7",
                                      },
                                      {
                                        l: "P3",
                                        v: latestRun.p3,
                                        c: "#2563eb",
                                        b: "#dbeafe",
                                      },
                                    ].map((item) => (
                                      <span
                                        key={item.l}
                                        style={{
                                          background: item.b,
                                          color: item.c,
                                          borderRadius: 999,
                                          padding: "2px 8px",
                                          fontSize: 11,
                                          fontWeight: 700,
                                        }}
                                      >
                                        {item.l}:{item.v}
                                      </span>
                                    ))}
                                  </>
                                )}
                                <span
                                  style={{
                                    padding: "6px 14px",
                                    borderRadius: 999,
                                    fontWeight: 800,
                                    fontSize: 12,
                                    background:
                                      isReady === null
                                        ? "#f3f4f6"
                                        : isReady
                                          ? "#dcfce7"
                                          : "#fee2e2",
                                    color:
                                      isReady === null
                                        ? "#6b7280"
                                        : isReady
                                          ? "#15803d"
                                          : "#dc2626",
                                    border: `1px solid ${isReady === null ? "#e5e7eb" : isReady ? "#22c55e" : "#ef4444"}`,
                                  }}
                                >
                                  {isReady === null
                                    ? "⚪ No Runs"
                                    : isReady
                                      ? "✅ READY"
                                      : "❌ NOT READY"}
                                </span>
                                {latestRun && (
                                  <button
                                    onClick={() => {
                                      setCertSeriesDrawerSeries(s.RunSeries);
                                      setCertSeriesDrawerRun(latestRun);
                                      setSelectedRun(latestRun);
                                      fetchFindings(latestRun.ID);
                                      setCertSeriesDrawerOpen(true);
                                    }}
                                    style={{
                                      padding: "6px 14px",
                                      borderRadius: 8,
                                      border: "none",
                                      background: "#0a6ed1",
                                      color: "white",
                                      fontSize: 12,
                                      fontWeight: 700,
                                      cursor: "pointer",
                                      flexShrink: 0,
                                    }}
                                  >
                                    View Packages →
                                  </button>
                                )}
                              </div>
                            </div>
                            {!latestRun && (
                              <div
                                style={{
                                  padding: "14px 20px",
                                  fontSize: 12,
                                  color: "#9ca3af",
                                }}
                              >
                                No runs found for this series in the current
                                filter period.
                              </div>
                            )}
                            {latestRun && !isReady && (
                              <div
                                style={{
                                  padding: "10px 20px",
                                  background: "#fef2f2",
                                  borderTop: "1px solid #fecaca",
                                  fontSize: 12,
                                  color: "#dc2626",
                                  fontWeight: 600,
                                }}
                              >
                                {latestRun.p1 + latestRun.p2} blocking finding
                                {latestRun.p1 + latestRun.p2 !== 1
                                  ? "s"
                                  : ""}{" "}
                                (P1 + P2) must be resolved before certification
                              </div>
                            )}
                          </div>
                        );
                      })}
                  </div>
                )}
              </div>
            )}

            {/* Series Packages Drawer */}
            {certSeriesDrawerOpen && certSeriesDrawerRun && (
              <div
                onClick={(e) => {
                  if (e.target === e.currentTarget)
                    setCertSeriesDrawerOpen(false);
                }}
                style={{
                  position: "fixed",
                  inset: 0,
                  background: "rgba(0,0,0,0.35)",
                  zIndex: 600,
                  display: "flex",
                  justifyContent: "flex-end",
                }}
              >
                <div
                  style={{
                    width: isMobile ? "100vw" : "min(560px,100vw)",
                    height: "100vh",
                    background: "var(--card-bg,#ffffff)",
                    boxShadow: "-4px 0 32px rgba(0,0,0,0.18)",
                    display: "flex",
                    flexDirection: "column",
                    boxSizing: "border-box",
                  }}
                >
                  <div style={{ padding: "20px 20px 0 20px", flexShrink: 0 }}>
                    <div
                      style={{
                        display: "flex",
                        justifyContent: "space-between",
                        alignItems: "flex-start",
                        marginBottom: 14,
                      }}
                    >
                      <div>
                        <h2
                          style={{ margin: 0, fontSize: 16, fontWeight: 700 }}
                        >
                          📦 {certSeriesDrawerSeries}
                        </h2>
                        <div
                          style={{
                            fontSize: 12,
                            color: "#6b7280",
                            marginTop: 3,
                          }}
                        >
                          Run:{" "}
                          {certSeriesDrawerRun.title ||
                            certSeriesDrawerRun.series}{" "}
                          · {certSeriesDrawerRun.date}
                        </div>
                      </div>
                      <button
                        className="drawer-close"
                        onClick={() => setCertSeriesDrawerOpen(false)}
                        style={{ flexShrink: 0, marginLeft: 12 }}
                      >
                        ✕
                      </button>
                    </div>
                    <div
                      style={{
                        display: "grid",
                        gridTemplateColumns: "repeat(4,1fr)",
                        gap: 8,
                        marginBottom: 14,
                      }}
                    >
                      {[
                        {
                          l: "P1",
                          v: certSeriesDrawerRun.p1,
                          c: "#dc2626",
                          b: "#fee2e2",
                        },
                        {
                          l: "P2",
                          v: certSeriesDrawerRun.p2,
                          c: "#d97706",
                          b: "#fef3c7",
                        },
                        {
                          l: "P3",
                          v: certSeriesDrawerRun.p3,
                          c: "#2563eb",
                          b: "#dbeafe",
                        },
                        {
                          l: "P4",
                          v: certSeriesDrawerRun.p4 ?? 0,
                          c: "#374151",
                          b: "#f3f4f6",
                        },
                      ].map((item) => (
                        <div
                          key={item.l}
                          style={{
                            padding: "10px 8px",
                            borderRadius: 10,
                            textAlign: "center",
                            background: item.v > 0 ? item.b : "#f9fafb",
                            border: `2px solid ${item.v > 0 ? item.c : "#e5e7eb"}`,
                          }}
                        >
                          <div
                            style={{
                              fontSize: 10,
                              fontWeight: 700,
                              color: item.v > 0 ? item.c : "#9ca3af",
                              textTransform: "uppercase",
                            }}
                          >
                            {item.l}
                          </div>
                          <div
                            style={{
                              fontSize: 20,
                              fontWeight: 800,
                              color: item.v > 0 ? item.c : "#d1d5db",
                              marginTop: 2,
                            }}
                          >
                            {item.v}
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                  <div
                    style={{
                      flex: 1,
                      overflowY: "auto",
                      padding: "0 20px 20px 20px",
                    }}
                  >
                    {findingsLoading && findings.length === 0 && (
                      <div
                        style={{
                          textAlign: "center",
                          padding: 32,
                          color: "#6b7280",
                          fontSize: 13,
                        }}
                      >
                        Loading packages...
                      </div>
                    )}
                    {findingsLoading && findings.length > 0 && (
                      <div
                        style={{
                          padding: "10px 14px",
                          background: "#eff6ff",
                          borderRadius: 8,
                          border: "1px solid #93c5fd",
                          fontSize: 12,
                          color: "#1e40af",
                          fontWeight: 600,
                          marginBottom: 12,
                        }}
                      >
                        Loading... {findings.length.toLocaleString()} findings
                        loaded
                      </div>
                    )}
                    {!findingsLoading && findings.length === 0 && (
                      <div
                        style={{
                          textAlign: "center",
                          padding: 32,
                          color: "#9ca3af",
                          fontSize: 13,
                        }}
                      >
                        No findings loaded for this run.
                      </div>
                    )}
                    {findings.length > 0 &&
                      (() => {
                        const pkgMap: Record<
                          string,
                          {
                            p1: number;
                            p2: number;
                            p3: number;
                            p4: number;
                            total: number;
                            objects: Set<string>;
                          }
                        > = {};
                        findings.forEach((f) => {
                          const pkg = f.PackageName || "—";
                          if (!pkgMap[pkg])
                            pkgMap[pkg] = {
                              p1: 0,
                              p2: 0,
                              p3: 0,
                              p4: 0,
                              total: 0,
                              objects: new Set(),
                            };
                          pkgMap[pkg].total++;
                          if (f.Priority === 1) pkgMap[pkg].p1++;
                          else if (f.Priority === 2) pkgMap[pkg].p2++;
                          else if (f.Priority === 3) pkgMap[pkg].p3++;
                          else if (f.Priority === 4) pkgMap[pkg].p4++;
                          if (f.ObjectName)
                            pkgMap[pkg].objects.add(f.ObjectName);
                        });
                        const pkgList = Object.entries(pkgMap).sort(
                          (a, b) =>
                            b[1].p1 - a[1].p1 ||
                            b[1].p2 - a[1].p2 ||
                            b[1].total - a[1].total,
                        );
                        return (
                          <div>
                            <div
                              style={{
                                fontSize: 11,
                                fontWeight: 700,
                                color: "#6b7280",
                                textTransform: "uppercase",
                                letterSpacing: 0.5,
                                marginBottom: 10,
                              }}
                            >
                              {pkgList.length} packages · {findings.length}{" "}
                              total findings
                            </div>
                            {pkgList.map(([pkg, v], i) => (
                              <div
                                key={i}
                                style={{
                                  padding: "12px 14px",
                                  marginBottom: 8,
                                  borderRadius: 8,
                                  border: `1px solid ${v.p1 > 0 ? "#fecaca" : v.p2 > 0 ? "#fde68a" : "#e5e7eb"}`,
                                  background:
                                    v.p1 > 0
                                      ? "#fff8f8"
                                      : v.p2 > 0
                                        ? "#fffdf0"
                                        : "#fafafa",
                                }}
                              >
                                <div
                                  style={{
                                    display: "flex",
                                    justifyContent: "space-between",
                                    alignItems: "flex-start",
                                    gap: 8,
                                  }}
                                >
                                  <div
                                    style={{
                                      fontSize: 12,
                                      fontWeight: 700,
                                      color: "#111827",
                                      fontFamily: "monospace",
                                      flex: 1,
                                      overflowWrap: "break-word",
                                    }}
                                  >
                                    {pkg}
                                  </div>
                                  <div
                                    style={{
                                      display: "flex",
                                      gap: 4,
                                      flexShrink: 0,
                                    }}
                                  >
                                    {v.p1 > 0 && (
                                      <span
                                        style={{
                                          background: "#fee2e2",
                                          color: "#dc2626",
                                          borderRadius: 999,
                                          padding: "1px 7px",
                                          fontSize: 11,
                                          fontWeight: 700,
                                        }}
                                      >
                                        P1:{v.p1}
                                      </span>
                                    )}
                                    {v.p2 > 0 && (
                                      <span
                                        style={{
                                          background: "#fef3c7",
                                          color: "#d97706",
                                          borderRadius: 999,
                                          padding: "1px 7px",
                                          fontSize: 11,
                                          fontWeight: 700,
                                        }}
                                      >
                                        P2:{v.p2}
                                      </span>
                                    )}
                                    {v.p3 > 0 && (
                                      <span
                                        style={{
                                          background: "#dbeafe",
                                          color: "#2563eb",
                                          borderRadius: 999,
                                          padding: "1px 7px",
                                          fontSize: 11,
                                          fontWeight: 700,
                                        }}
                                      >
                                        P3:{v.p3}
                                      </span>
                                    )}
                                  </div>
                                </div>
                                <div
                                  style={{
                                    fontSize: 11,
                                    color: "#6b7280",
                                    marginTop: 4,
                                  }}
                                >
                                  {v.objects.size} object
                                  {v.objects.size !== 1 ? "s" : ""} · {v.total}{" "}
                                  finding{v.total !== 1 ? "s" : ""}
                                  {v.p1 + v.p2 === 0 && (
                                    <span
                                      style={{
                                        marginLeft: 8,
                                        color: "#15803d",
                                        fontWeight: 600,
                                      }}
                                    >
                                      ✅ Clear
                                    </span>
                                  )}
                                </div>
                              </div>
                            ))}
                          </div>
                        );
                      })()}
                  </div>
                </div>
              </div>
            )}
          </div>
        )}
        {/* ════ SECURITY TAB ════ */}
        {tab === "security" && (
          <div className="chart-grid">
            <div
              style={{
                gridColumn: "1/-1",
                display: "flex",
                justifyContent: "flex-end",
                marginBottom: -8,
              }}
            >
              <button
                onClick={generateSecurityPdf}
                disabled={securityFindings.length === 0 || !selectedRun}
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: 8,
                  padding: "10px 20px",
                  borderRadius: 10,
                  border: "none",
                  cursor:
                    securityFindings.length === 0 || !selectedRun
                      ? "default"
                      : "pointer",
                  background:
                    securityFindings.length === 0 || !selectedRun
                      ? "#f3f4f6"
                      : "linear-gradient(135deg,#0f172a,#1e3a5f)",
                  color:
                    securityFindings.length === 0 || !selectedRun
                      ? "#9ca3af"
                      : "white",
                  fontSize: 13,
                  fontWeight: 700,
                }}
              >
                📄 Export Security Report PDF
              </button>
            </div>
            {isCheckmanRun && (
              <div
                style={{
                  gridColumn: "1/-1",
                  padding: "12px 16px",
                  background: "#fefce8",
                  border: "1px solid #fde047",
                  borderRadius: 10,
                  fontSize: 13,
                  color: "#713f12",
                  display: "flex",
                  alignItems: "center",
                  gap: 10,
                }}
              >
                <span style={{ fontSize: 16 }}>⚠️</span>
                <span>
                  <strong>Checkman run selected.</strong> Security
                  classification is not available for Checkman runs. Switch to a{" "}
                  <strong>Code Inspector</strong> run for full security
                  analysis.
                </span>
              </div>
            )}
            {checkModulesLoading && (
              <div
                style={{
                  gridColumn: "1/-1",
                  padding: "12px 16px",
                  background: "#eff6ff",
                  border: "1px solid #93c5fd",
                  borderRadius: 10,
                  fontSize: 13,
                  color: "#1e40af",
                  display: "flex",
                  alignItems: "center",
                  gap: 10,
                }}
              >
                <div
                  style={{
                    width: 16,
                    height: 16,
                    border: "2px solid #3b82f6",
                    borderTopColor: "transparent",
                    borderRadius: "50%",
                    animation: "spin 1s linear infinite",
                  }}
                />
                Loading security check classification...
              </div>
            )}
            {!checkModulesLoading && findings.length > 0 && (
              <div
                style={{
                  gridColumn: "1/-1",
                  padding: "10px 16px",
                  background: securityClassified
                    ? "#f0fdf4"
                    : securityFindings.length > 0
                      ? "#fefce8"
                      : "#fafafa",
                  border: `1px solid ${securityClassified ? "#bbf7d0" : securityFindings.length > 0 ? "#fde047" : "#e5e7eb"}`,
                  borderRadius: 10,
                  fontSize: 12,
                  color: securityClassified
                    ? "#14532d"
                    : securityFindings.length > 0
                      ? "#713f12"
                      : "#6b7280",
                  display: "flex",
                  alignItems: "center",
                  gap: 8,
                }}
              >
                {securityClassified
                  ? `✅ Security module classification active · ${securityModuleIds.size} check types · ${securityFindings.length} security findings from ${findings.length} total`
                  : securityFindings.length > 0
                    ? `⚠️ Classified ${securityFindings.length} findings by keyword matching`
                    : `ℹ️ No security findings detected`}
              </div>
            )}
            {!findingsLoading &&
              findings.length === 0 &&
              !checkModulesLoading && (
                <div
                  style={{
                    gridColumn: "1/-1",
                    padding: "16px 20px",
                    background: "#fefce8",
                    border: "1px solid #fde047",
                    borderRadius: 10,
                    fontSize: 13,
                    color: "#713f12",
                  }}
                >
                  ⚠️ Open a run in <strong>Run Explorer</strong> to load
                  findings. Security analysis requires finding-level data.
                </div>
              )}

            {/* W2 — Risk Categories */}
            <div className="chart-card">
              <h3>Security Risk Categories</h3>
              <div className="subtitle">
                {securityFindings.length > 0
                  ? `${securityFindings.length} findings across ${securityByCheckType.length || "multiple"} risk categories · click a category to see findings`
                  : "Open a run to populate"}
              </div>
              <div style={{ marginTop: 16 }}>
                {securityByCheckType.length === 0 &&
                securityFindings.length > 0 ? (
                  <div
                    style={{
                      padding: "14px 16px",
                      background: "#f9fafb",
                      borderRadius: 10,
                      border: "1px solid #e5e7eb",
                    }}
                  >
                    <div
                      style={{
                        fontSize: 12,
                        color: "#6b7280",
                        marginBottom: 10,
                      }}
                    >
                      Security check module metadata unavailable — showing
                      priority breakdown:
                    </div>
                    {[
                      {
                        label: "P1 Critical",
                        value: secP1,
                        color: "#ef4444",
                        bg: "#fee2e2",
                        prio: 1,
                      },
                      {
                        label: "P2 Warning",
                        value: secP2,
                        color: "#f59e0b",
                        bg: "#fef3c7",
                        prio: 2,
                      },
                      {
                        label: "P3 Info",
                        value: secP3,
                        color: "#3b82f6",
                        bg: "#dbeafe",
                        prio: 3,
                      },
                    ]
                      .filter((x) => x.value > 0)
                      .map((x, i) => (
                        <div
                          key={i}
                          onClick={() => {
                            setSecCatDrawerTitle(
                              `${x.label} Security Findings`,
                            );
                            setSecCatDrawerFindings(
                              securityFindings.filter(
                                (f) => f.Priority === x.prio,
                              ),
                            );
                            setSecCatDrawerOpen(true);
                          }}
                          style={{
                            display: "flex",
                            justifyContent: "space-between",
                            alignItems: "center",
                            padding: "8px 10px",
                            background: x.bg,
                            borderRadius: 8,
                            marginBottom: 8,
                            cursor: "pointer",
                          }}
                        >
                          <span
                            style={{
                              fontSize: 13,
                              fontWeight: 600,
                              color: x.color,
                            }}
                          >
                            {x.label}
                          </span>
                          <span
                            style={{
                              fontSize: 16,
                              fontWeight: 700,
                              color: x.color,
                            }}
                          >
                            {x.value}
                          </span>
                        </div>
                      ))}
                  </div>
                ) : securityByCheckType.length === 0 ? (
                  <div
                    style={{
                      color: "#9ca3af",
                      fontSize: 13,
                      textAlign: "center",
                      paddingTop: 24,
                    }}
                  >
                    No security findings in current run
                  </div>
                ) : (
                  securityByCheckType.map((cat, i) => {
                    const catFindings = securityFindings.filter((f) => {
                      const ci =
                        resolveCiId(f) ||
                        checkModules.find(
                          (m) =>
                            m.ModuleId.toLowerCase() ===
                            (f.CheckCategory || "").toLowerCase(),
                        )?.CiId ||
                        "";
                      const kn = getSecurityKnowledge(ci);
                      const mod = checkModules.find(
                        (m) =>
                          m.ModuleId.toLowerCase() ===
                          (f.CheckCategory || "").toLowerCase(),
                      );
                      const lbl =
                        kn?.riskName ||
                        mod?.ModuleTitle?.trim() ||
                        f.RstismTitle?.trim() ||
                        (ci && ci !== "*INVALID*" ? ci : "Security Check");
                      return lbl === cat.riskName;
                    });
                    return (
                      <div
                        key={i}
                        onClick={() => {
                          setSecCatDrawerTitle(cat.riskName);
                          setSecCatDrawerFindings(catFindings);
                          setSecCatDrawerOpen(true);
                        }}
                        style={{
                          marginBottom: 18,
                          paddingBottom: 14,
                          borderBottom:
                            i < securityByCheckType.length - 1
                              ? "1px solid #f3f4f6"
                              : "none",
                          cursor: "pointer",
                          borderRadius: 8,
                          padding: "10px 8px",
                          transition: "background 0.1s",
                        }}
                        onMouseEnter={(e) =>
                          (e.currentTarget.style.background = "#f8faff")
                        }
                        onMouseLeave={(e) =>
                          (e.currentTarget.style.background = "transparent")
                        }
                      >
                        <div
                          style={{
                            display: "flex",
                            justifyContent: "space-between",
                            alignItems: "flex-start",
                            marginBottom: 6,
                          }}
                        >
                          <div
                            style={{
                              fontSize: 13,
                              fontWeight: 600,
                              color: "#111827",
                              flex: 1,
                              marginRight: 8,
                            }}
                          >
                            {cat.riskName}
                          </div>
                          <div
                            style={{ display: "flex", gap: 6, flexShrink: 0 }}
                          >
                            {cat.p1 > 0 && (
                              <span
                                style={{
                                  background: "#fee2e2",
                                  color: "#dc2626",
                                  borderRadius: 999,
                                  padding: "2px 8px",
                                  fontSize: 11,
                                  fontWeight: 700,
                                }}
                              >
                                P1:{cat.p1}
                              </span>
                            )}
                            {cat.p2 > 0 && (
                              <span
                                style={{
                                  background: "#fef3c7",
                                  color: "#d97706",
                                  borderRadius: 999,
                                  padding: "2px 8px",
                                  fontSize: 11,
                                  fontWeight: 700,
                                }}
                              >
                                P2:{cat.p2}
                              </span>
                            )}
                            <span
                              style={{
                                fontSize: 11,
                                color: "#0a6ed1",
                                fontWeight: 600,
                              }}
                            >
                              View →
                            </span>
                          </div>
                        </div>
                        <div
                          style={{
                            height: 6,
                            background: "#f3f4f6",
                            borderRadius: 999,
                            overflow: "hidden",
                          }}
                        >
                          <div
                            style={{
                              width: `${(cat.count / Math.max(...securityByCheckType.map((c) => c.count), 1)) * 100}%`,
                              height: "100%",
                              background:
                                cat.p1 > 0
                                  ? "#ef4444"
                                  : cat.p2 > 0
                                    ? "#f59e0b"
                                    : "#6b7280",
                              borderRadius: 999,
                            }}
                          />
                        </div>
                        <div
                          style={{
                            fontSize: 11,
                            color: "#6b7280",
                            marginTop: 4,
                          }}
                        >
                          {cat.count} total findings · {catFindings.length}{" "}
                          matched
                        </div>
                      </div>
                    );
                  })
                )}
              </div>
            </div>

            {/* W3 — Attack Surface */}
            <div className="chart-card">
              <h3>Attack Surface Map</h3>
              <div className="subtitle">
                {securityFindings.length > 0
                  ? `${securityFindings.length} findings · ${attackVectorSummary.reduce((a, v) => a + v.objects.size, 0)} unique objects`
                  : "Open a run to populate"}
              </div>
              {securityByObject.length === 0 ? (
                <div
                  style={{
                    color: "#9ca3af",
                    fontSize: 13,
                    textAlign: "center",
                    paddingTop: 24,
                  }}
                >
                  No security findings
                </div>
              ) : (
                <>
                  <div style={{ marginTop: 14, marginBottom: 16 }}>
                    <div
                      style={{
                        fontSize: 10,
                        fontWeight: 700,
                        color: "#6b7280",
                        letterSpacing: 0.8,
                        marginBottom: 8,
                      }}
                    >
                      ATTACK VECTORS
                    </div>
                    <div
                      style={{
                        display: "grid",
                        gridTemplateColumns: "1fr 1fr",
                        gap: 8,
                      }}
                    >
                      {attackVectorSummary.map((v, i) => (
                        <div
                          key={i}
                          style={{
                            background: v.bg,
                            borderRadius: 10,
                            padding: "10px 12px",
                            border: `1px solid ${v.color}22`,
                          }}
                        >
                          <div
                            style={{
                              display: "flex",
                              alignItems: "center",
                              gap: 6,
                              marginBottom: 6,
                            }}
                          >
                            <span style={{ fontSize: 14 }}>{v.icon}</span>
                            <span
                              style={{
                                fontSize: 11,
                                fontWeight: 700,
                                color: v.color,
                              }}
                            >
                              {v.label}
                            </span>
                          </div>
                          <div
                            style={{
                              fontSize: 11,
                              color: "#6b7280",
                              marginBottom: 6,
                            }}
                          >
                            {v.objects.size} object
                            {v.objects.size !== 1 ? "s" : ""} · {v.count}{" "}
                            finding{v.count !== 1 ? "s" : ""}
                          </div>
                          <div
                            style={{
                              display: "flex",
                              gap: 4,
                              flexWrap: "wrap",
                            }}
                          >
                            {v.p1 > 0 && (
                              <span
                                style={{
                                  background: "#fee2e2",
                                  color: "#dc2626",
                                  borderRadius: 999,
                                  padding: "1px 7px",
                                  fontSize: 10,
                                  fontWeight: 700,
                                }}
                              >
                                P1:{v.p1}
                              </span>
                            )}
                            {v.p2 > 0 && (
                              <span
                                style={{
                                  background: "#fef3c7",
                                  color: "#d97706",
                                  borderRadius: 999,
                                  padding: "1px 7px",
                                  fontSize: 10,
                                  fontWeight: 700,
                                }}
                              >
                                P2:{v.p2}
                              </span>
                            )}
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                  <div>
                    {securityByObject.map((obj, i) => (
                      <div
                        key={i}
                        style={{
                          display: "grid",
                          gridTemplateColumns: "1fr auto",
                          gap: 8,
                          alignItems: "start",
                          marginBottom: 12,
                          paddingBottom: 10,
                          borderBottom:
                            i < securityByObject.length - 1
                              ? "1px solid #f3f4f6"
                              : "none",
                        }}
                      >
                        <div>
                          <div
                            style={{
                              display: "flex",
                              alignItems: "center",
                              gap: 6,
                              marginBottom: 2,
                            }}
                          >
                            <span style={{ fontSize: 11 }}>
                              {obj.attackVector.icon}
                            </span>
                            <span
                              style={{
                                fontSize: 12,
                                fontWeight: 600,
                                color: "#111827",
                                wordBreak: "break-all",
                              }}
                            >
                              {obj.name}
                            </span>
                          </div>
                          <div
                            style={{
                              display: "flex",
                              alignItems: "center",
                              gap: 6,
                              flexWrap: "wrap",
                            }}
                          >
                            <span
                              style={{
                                fontSize: 10,
                                background: obj.attackVector.bg,
                                color: obj.attackVector.color,
                                borderRadius: 999,
                                padding: "1px 6px",
                                fontWeight: 600,
                              }}
                            >
                              {obj.attackVector.label}
                            </span>
                            <span style={{ fontSize: 10, color: "#9ca3af" }}>
                              {OBJECT_TYPE_LABELS[obj.objType] ||
                                obj.objType ||
                                "—"}{" "}
                              · {obj.count} finding{obj.count !== 1 ? "s" : ""}
                            </span>
                          </div>
                        </div>
                        <div style={{ display: "flex", gap: 4, flexShrink: 0 }}>
                          {obj.p1 > 0 && (
                            <span
                              style={{
                                background: "#fee2e2",
                                color: "#dc2626",
                                borderRadius: 999,
                                padding: "2px 7px",
                                fontSize: 11,
                                fontWeight: 700,
                              }}
                            >
                              P1:{obj.p1}
                            </span>
                          )}
                          {obj.p2 > 0 && (
                            <span
                              style={{
                                background: "#fef3c7",
                                color: "#d97706",
                                borderRadius: 999,
                                padding: "2px 7px",
                                fontSize: 11,
                                fontWeight: 700,
                              }}
                            >
                              P2:{obj.p2}
                            </span>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                </>
              )}
            </div>

            {/* W4 — Developer Security Accountability */}
            <div className="chart-card">
              <h3>Developer Security Accountability</h3>
              <div className="subtitle">
                {securityByDeveloper.length > 0
                  ? `${securityByDeveloper.length} developer${securityByDeveloper.length !== 1 ? "s" : ""} · ${securityFindings.length} total security findings`
                  : "Open a run to populate"}
              </div>
              <div
                style={{
                  display: "flex",
                  gap: 8,
                  marginTop: 12,
                  marginBottom: 16,
                }}
              >
                <input
                  value={myUserIdInput}
                  onChange={(e) => setMyUserIdInput(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === "Enter") setMyUserId(myUserIdInput.trim());
                  }}
                  placeholder="Enter your SAP user ID..."
                  style={{
                    flex: 1,
                    padding: "7px 12px",
                    borderRadius: 8,
                    border: "1px solid #d1d5db",
                    fontSize: 12,
                  }}
                />
                <button
                  onClick={() => setMyUserId(myUserIdInput.trim())}
                  style={{
                    padding: "7px 14px",
                    borderRadius: 8,
                    border: "none",
                    background: "#0a6ed1",
                    color: "white",
                    fontSize: 12,
                    fontWeight: 600,
                    cursor: "pointer",
                  }}
                >
                  My Queue
                </button>
                {myUserId && (
                  <button
                    onClick={() => {
                      setMyUserId("");
                      setMyUserIdInput("");
                    }}
                    style={{
                      padding: "7px 10px",
                      borderRadius: 8,
                      border: "1px solid #d1d5db",
                      background: "white",
                      fontSize: 12,
                      cursor: "pointer",
                      color: "#6b7280",
                    }}
                  >
                    ✕
                  </button>
                )}
              </div>
              {myUserId && (
                <div
                  style={{
                    marginBottom: 16,
                    padding: "10px 14px",
                    background:
                      myQueueFindings.length > 0 ? "#fef3c7" : "#f0fdf4",
                    borderRadius: 8,
                    border: `1px solid ${myQueueFindings.length > 0 ? "#fde047" : "#bbf7d0"}`,
                  }}
                >
                  <div
                    style={{
                      fontSize: 12,
                      fontWeight: 700,
                      color: myQueueFindings.length > 0 ? "#713f12" : "#15803d",
                    }}
                  >
                    {myUserId.toUpperCase()}: {myQueueFindings.length} open
                    finding{myQueueFindings.length !== 1 ? "s" : ""}
                    {myQueueFindings.length > 0
                      ? ` (${myQueueFindings.filter((f) => f.Priority === 1).length} P1, ${myQueueFindings.filter((f) => f.Priority === 2).length} P2)`
                      : ""}
                  </div>
                  {myQueueFindings.length === 0 && (
                    <div style={{ fontSize: 11, color: "#15803d" }}>
                      No open security findings — great work!
                    </div>
                  )}
                </div>
              )}
              <div>
                {securityByDeveloper.length === 0 ? (
                  <div
                    style={{
                      color: "#9ca3af",
                      fontSize: 13,
                      textAlign: "center",
                      paddingTop: 16,
                    }}
                  >
                    No security findings
                  </div>
                ) : (
                  securityByDeveloper.map((d, i) => (
                    <div
                      key={i}
                      style={{
                        display: "grid",
                        gridTemplateColumns: "1fr auto",
                        gap: 8,
                        alignItems: "center",
                        marginBottom: 12,
                        padding: "8px 10px",
                        borderRadius: 8,
                        background:
                          myUserId &&
                          d.dev.toUpperCase() === myUserId.toUpperCase()
                            ? "#fffbeb"
                            : "transparent",
                        border:
                          myUserId &&
                          d.dev.toUpperCase() === myUserId.toUpperCase()
                            ? "1px solid #fde047"
                            : "1px solid transparent",
                      }}
                    >
                      <div>
                        <div
                          onClick={(e) => {
                            e.stopPropagation();
                            openSecurityDeveloperDrawer(d.dev);
                          }}
                          style={{
                            fontSize: 12,
                            fontWeight: 600,
                            color: "#1d4ed8",
                            cursor: "pointer",
                            textDecoration: "underline",
                            textDecorationStyle: "dotted",
                            display: "inline-block",
                          }}
                        >
                          {d.dev}
                        </div>
                        <div
                          style={{
                            fontSize: 11,
                            color: "#6b7280",
                            marginTop: 1,
                          }}
                        >
                          {d.count} finding{d.count !== 1 ? "s" : ""}
                          {d.oldest > 0 ? ` · oldest: ${d.oldest}d` : ""}
                        </div>
                      </div>
                      <div
                        style={{
                          display: "flex",
                          gap: 4,
                          flexWrap: "wrap",
                          justifyContent: "flex-end",
                        }}
                      >
                        {d.p1 > 0 && (
                          <span
                            style={{
                              background: "#fee2e2",
                              color: "#dc2626",
                              borderRadius: 999,
                              padding: "2px 7px",
                              fontSize: 11,
                              fontWeight: 700,
                            }}
                          >
                            P1:{d.p1}
                          </span>
                        )}
                        {d.p2 > 0 && (
                          <span
                            style={{
                              background: "#fef3c7",
                              color: "#d97706",
                              borderRadius: 999,
                              padding: "2px 7px",
                              fontSize: 11,
                              fontWeight: 700,
                            }}
                          >
                            P2:{d.p2}
                          </span>
                        )}
                        {d.p3 > 0 && (
                          <span
                            style={{
                              background: "#dbeafe",
                              color: "#2563eb",
                              borderRadius: 999,
                              padding: "2px 7px",
                              fontSize: 11,
                              fontWeight: 700,
                            }}
                          >
                            P3:{d.p3}
                          </span>
                        )}
                      </div>
                    </div>
                  ))
                )}
              </div>
            </div>

            {/* W5 — Exposure Duration */}
            <div className="chart-card">
              <h3>Vulnerability Exposure Duration</h3>
              <div className="subtitle">
                {securityFindings.length > 0
                  ? `${securityFindings.length} findings — how long vulnerabilities have been open`
                  : "Open a run to populate"}
              </div>
              {securityFindings.length === 0 ? (
                <div
                  style={{
                    color: "#9ca3af",
                    fontSize: 13,
                    textAlign: "center",
                    paddingTop: 32,
                  }}
                >
                  No security findings
                </div>
              ) : (
                <>
                  <div
                    style={{
                      display: "grid",
                      gridTemplateColumns: "repeat(4,1fr)",
                      gap: 12,
                      marginTop: 20,
                    }}
                  >
                    {securityAgeBuckets.map(({ label, value }, i) => {
                      const colors = [
                        "#22c55e",
                        "#f59e0b",
                        "#ef4444",
                        "#7f1d1d",
                      ];
                      const bgs = ["#f0fdf4", "#fefce8", "#fff1f2", "#1c0a0a"];
                      const max = Math.max(
                        ...securityAgeBuckets.map((b) => b.value),
                        1,
                      );
                      return (
                        <div
                          key={i}
                          style={{
                            textAlign: "center",
                            padding: 12,
                            background: bgs[i],
                            borderRadius: 10,
                          }}
                        >
                          <div
                            style={{
                              fontSize: 22,
                              fontWeight: 700,
                              color: colors[i],
                            }}
                          >
                            {value}
                          </div>
                          <div
                            style={{
                              fontSize: 11,
                              color: colors[i],
                              fontWeight: 600,
                              marginTop: 4,
                            }}
                          >
                            {label}
                          </div>
                          <div
                            style={{
                              marginTop: 8,
                              height: 4,
                              background: "rgba(0,0,0,0.1)",
                              borderRadius: 999,
                            }}
                          >
                            <div
                              style={{
                                width: `${(value / max) * 100}%`,
                                height: "100%",
                                background: colors[i],
                                borderRadius: 999,
                              }}
                            />
                          </div>
                        </div>
                      );
                    })}
                  </div>
                  {securityAgeBuckets[3]?.value > 0 && (
                    <div
                      style={{
                        marginTop: 14,
                        padding: "10px 14px",
                        background: "#450a0a",
                        borderRadius: 8,
                        fontSize: 12,
                        color: "#fca5a5",
                      }}
                    >
                      🚨{" "}
                      <strong>
                        {securityAgeBuckets[3].value} vulnerabilities
                      </strong>{" "}
                      open for more than 90 days.
                    </div>
                  )}
                </>
              )}
            </div>

            {/* W6 — AI Security Analysis */}
            <div className="chart-card large">
              <div
                style={{
                  display: "flex",
                  alignItems: "flex-start",
                  justifyContent: "space-between",
                  gap: 12,
                  flexWrap: "wrap",
                  marginBottom: 4,
                }}
              >
                <div>
                  <h3 style={{ margin: 0 }}>AI Security Analysis</h3>
                  <div className="subtitle">
                    Real-time enterprise security assessment
                    {selectedRun &&
                      ` · ${selectedRun.title || selectedRun.series || "current run"}`}
                  </div>
                </div>
                <button
                  onClick={runAiSecurityAnalysis}
                  disabled={aiSecLoading || securityFindings.length === 0}
                  style={{
                    padding: "10px 20px",
                    borderRadius: 10,
                    border: "none",
                    cursor:
                      securityFindings.length === 0 || aiSecLoading
                        ? "default"
                        : "pointer",
                    background:
                      securityFindings.length === 0
                        ? "#f3f4f6"
                        : aiSecLoading
                          ? "#dbeafe"
                          : "linear-gradient(135deg,#0a6ed1,#6366f1)",
                    color:
                      securityFindings.length === 0
                        ? "#9ca3af"
                        : aiSecLoading
                          ? "#1e40af"
                          : "white",
                    fontSize: 13,
                    fontWeight: 700,
                    flexShrink: 0,
                    display: "flex",
                    alignItems: "center",
                    gap: 8,
                  }}
                >
                  {aiSecLoading ? (
                    <>
                      <div
                        style={{
                          width: 14,
                          height: 14,
                          border: "2px solid #3b82f6",
                          borderTopColor: "transparent",
                          borderRadius: "50%",
                          animation: "spin 0.8s linear infinite",
                        }}
                      />
                      Analyzing...
                    </>
                  ) : (
                    <>✨ {aiSecReport ? "Re-Analyze" : "Analyze Security"}</>
                  )}
                </button>
              </div>
              {!aiSecReport && !aiSecLoading && !aiSecError && (
                <div style={{ marginTop: 20 }}>
                  {securityFindings.length === 0 ? (
                    <div
                      style={{
                        padding: "32px 20px",
                        textAlign: "center",
                        background: "#f9fafb",
                        borderRadius: 12,
                        border: "1px dashed #d1d5db",
                      }}
                    >
                      <div style={{ fontSize: 28, marginBottom: 10 }}>🔐</div>
                      <div
                        style={{
                          fontSize: 13,
                          color: "#6b7280",
                          fontWeight: 600,
                        }}
                      >
                        Open a run in Run Explorer to load findings
                      </div>
                    </div>
                  ) : (
                    <div
                      style={{
                        padding: "24px 20px",
                        background: "linear-gradient(135deg,#eff6ff,#f0fdf4)",
                        borderRadius: 12,
                        border: "1px solid #bfdbfe",
                      }}
                    >
                      <div
                        style={{
                          fontSize: 14,
                          fontWeight: 700,
                          color: "#1e40af",
                          marginBottom: 8,
                        }}
                      >
                        Ready to analyze {securityFindings.length} security
                        findings
                      </div>
                      <div
                        style={{
                          display: "grid",
                          gridTemplateColumns: "1fr 1fr",
                          gap: 8,
                          marginBottom: 16,
                        }}
                      >
                        {[
                          {
                            label: "P1+P2 Blocking",
                            value: certificationBlocking,
                            color:
                              certificationBlocking > 0 ? "#dc2626" : "#16a34a",
                          },
                          {
                            label: "Check Types",
                            value: securityByCheckType.length || "N/A",
                            color: "#0a6ed1",
                          },
                          {
                            label: "Developers Affected",
                            value: securityByDeveloper.length,
                            color: "#7c3aed",
                          },
                          {
                            label: "90+ Day Exposure",
                            value: securityAgeBuckets[3]?.value || 0,
                            color:
                              securityAgeBuckets[3]?.value > 0
                                ? "#dc2626"
                                : "#16a34a",
                          },
                        ].map((item, i) => (
                          <div
                            key={i}
                            style={{
                              background: "white",
                              borderRadius: 8,
                              padding: "10px 12px",
                              border: "1px solid #e5e7eb",
                            }}
                          >
                            <div style={{ fontSize: 11, color: "#6b7280" }}>
                              {item.label}
                            </div>
                            <div
                              style={{
                                fontSize: 20,
                                fontWeight: 700,
                                color: item.color,
                                marginTop: 2,
                              }}
                            >
                              {item.value}
                            </div>
                          </div>
                        ))}
                      </div>
                      <div style={{ fontSize: 12, color: "#374151" }}>
                        Click <strong>Analyze Security</strong> to generate a
                        real-time assessment.
                      </div>
                    </div>
                  )}
                </div>
              )}
              {aiSecLoading && (
                <div
                  style={{
                    marginTop: 20,
                    padding: "28px 20px",
                    background: "linear-gradient(135deg,#eff6ff,#dbeafe)",
                    borderRadius: 12,
                    border: "1px solid #93c5fd",
                    textAlign: "center",
                  }}
                >
                  <div
                    style={{
                      fontSize: 14,
                      fontWeight: 700,
                      color: "#1e40af",
                      marginBottom: 6,
                    }}
                  >
                    Analyzing your security findings...
                  </div>
                  <div style={{ fontSize: 12, color: "#3b82f6" }}>
                    Reviewing {securityFindings.length} findings across{" "}
                    {securityByDeveloper.length} developers
                  </div>
                </div>
              )}
              {aiSecError && !aiSecLoading && (
                <div
                  style={{
                    marginTop: 16,
                    padding: "12px 16px",
                    background: "#fef2f2",
                    borderRadius: 8,
                    border: "1px solid #fecaca",
                  }}
                >
                  <div
                    style={{
                      fontSize: 12,
                      fontWeight: 700,
                      color: "#dc2626",
                      marginBottom: 4,
                    }}
                  >
                    Analysis failed
                  </div>
                  <div style={{ fontSize: 12, color: "#7f1d1d" }}>
                    {aiSecError}
                  </div>
                  <button
                    onClick={runAiSecurityAnalysis}
                    style={{
                      marginTop: 10,
                      padding: "6px 14px",
                      borderRadius: 6,
                      border: "1px solid #fca5a5",
                      background: "white",
                      color: "#dc2626",
                      fontSize: 12,
                      fontWeight: 600,
                      cursor: "pointer",
                    }}
                  >
                    Retry
                  </button>
                </div>
              )}
              {aiSecReport && !aiSecLoading && (
                <div style={{ marginTop: 16 }}>
                  <div
                    style={{
                      display: "flex",
                      justifyContent: "space-between",
                      alignItems: "center",
                      marginBottom: 12,
                    }}
                  >
                    <div style={{ fontSize: 11, color: "#6b7280" }}>
                      Analysis based on {securityFindings.length} findings ·{" "}
                      {new Date().toLocaleString()}
                    </div>
                    <div style={{ display: "flex", gap: 6 }}>
                      <button
                        onClick={() =>
                          navigator.clipboard.writeText(aiSecReport)
                        }
                        style={{
                          padding: "4px 10px",
                          borderRadius: 6,
                          border: "1px solid #e5e7eb",
                          background: "white",
                          fontSize: 11,
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
                              `SAP ATC Security Analysis\n${new Date().toLocaleString()}\nRun: ${selectedRun?.title || selectedRun?.series || "unknown"}\n\n${aiSecReport}`,
                            ],
                            { type: "text/plain" },
                          );
                          const url = URL.createObjectURL(blob);
                          const a = document.createElement("a");
                          a.href = url;
                          a.download = `security-analysis-${selectedRun?.date || new Date().toISOString().split("T")[0]}.txt`;
                          a.click();
                          URL.revokeObjectURL(url);
                        }}
                        style={{
                          padding: "4px 10px",
                          borderRadius: 6,
                          border: "1px solid #e5e7eb",
                          background: "white",
                          fontSize: 11,
                          cursor: "pointer",
                          color: "#6b7280",
                        }}
                      >
                        ⬇️ Export
                      </button>
                    </div>
                  </div>
                  <div
                    style={{
                      background: "#fafafa",
                      border: "1px solid #e5e7eb",
                      borderRadius: 12,
                      padding: "20px 24px",
                      fontSize: 13,
                      lineHeight: 1.75,
                      color: "#1f2937",
                    }}
                  >
                    {renderAiText(aiSecReport)}
                  </div>
                </div>
              )}
            </div>

            {/* Security Findings Drawer */}
            {secDrawerOpen && (
              <div
                onClick={(e) => {
                  if (e.target === e.currentTarget) setSecDrawerOpen(false);
                }}
                style={{
                  position: "fixed",
                  inset: 0,
                  background: "rgba(0,0,0,0.35)",
                  zIndex: 500,
                  display: "flex",
                  justifyContent: "flex-end",
                }}
              >
                <div
                  style={{
                    width: isMobile ? "100vw" : "min(680px,100vw)",
                    height: "100vh",
                    background: "var(--card-bg,#ffffff)",
                    boxShadow: "-4px 0 32px rgba(0,0,0,0.18)",
                    display: "flex",
                    flexDirection: "column",
                    boxSizing: "border-box",
                    overflowX: "hidden",
                  }}
                >
                  <div style={{ padding: "20px 20px 0 20px", flexShrink: 0 }}>
                    <div
                      style={{
                        display: "flex",
                        justifyContent: "space-between",
                        alignItems: "flex-start",
                        marginBottom: 12,
                      }}
                    >
                      <div style={{ minWidth: 0 }}>
                        <h2
                          style={{
                            margin: 0,
                            fontSize: 16,
                            fontWeight: 700,
                            wordBreak: "break-word",
                          }}
                        >
                          {secDrawerTitle}
                        </h2>
                        <div
                          style={{
                            fontSize: 12,
                            color: "#6b7280",
                            marginTop: 4,
                          }}
                        >
                          {secDrawerFindings.length} finding
                          {secDrawerFindings.length !== 1 ? "s" : ""}
                          {selectedRun && (
                            <span style={{ marginLeft: 8 }}>
                              · Run:{" "}
                              {selectedRun.title ||
                                selectedRun.series ||
                                selectedRun.ID}
                            </span>
                          )}
                        </div>
                      </div>
                      <button
                        className="drawer-close"
                        onClick={() => setSecDrawerOpen(false)}
                        style={{ flexShrink: 0, marginLeft: 12 }}
                      >
                        ✕
                      </button>
                    </div>
                    <div
                      style={{
                        display: "grid",
                        gridTemplateColumns: isMobile
                          ? "1fr 1fr"
                          : "1fr 1fr 1fr 1fr",
                        gap: 8,
                        marginBottom: 8,
                      }}
                    >
                      {[
                        {
                          label: "CRITICAL (P1)",
                          prio: 1,
                          color: "#dc2626",
                          bg: "#fee2e2",
                          border: "#ef4444",
                        },
                        {
                          label: "WARNING (P2)",
                          prio: 2,
                          color: "#d97706",
                          bg: "#fef3c7",
                          border: "#f59e0b",
                        },
                        {
                          label: "INFO (P3)",
                          prio: 3,
                          color: "#2563eb",
                          bg: "#dbeafe",
                          border: "#3b82f6",
                        },
                        {
                          label: "NOTE (P4)",
                          prio: 4,
                          color: "#374151",
                          bg: "#f3f4f6",
                          border: "#6b7280",
                        },
                      ].map(({ label, prio, color, bg, border }) => {
                        const cnt = secDrawerFindings.filter(
                          (f) => Number(f.Priority) === prio,
                        ).length;
                        return (
                          <div
                            key={prio}
                            style={{
                              padding: "10px 8px",
                              borderRadius: 10,
                              textAlign: "center",
                              background: cnt > 0 ? bg : "#f9fafb",
                              border: `2px solid ${cnt > 0 ? border : "#e5e7eb"}`,
                            }}
                          >
                            <div
                              style={{
                                fontSize: 10,
                                color: cnt > 0 ? color : "#6b7280",
                                fontWeight: 600,
                                letterSpacing: 0.5,
                              }}
                            >
                              {label}
                            </div>
                            <div
                              style={{
                                fontSize: 20,
                                fontWeight: 700,
                                color: cnt > 0 ? color : "#9ca3af",
                                marginTop: 2,
                              }}
                            >
                              {cnt}
                            </div>
                          </div>
                        );
                      })}
                    </div>
                    <div
                      style={{
                        display: "flex",
                        justifyContent: "space-between",
                        alignItems: "center",
                        background: "#f9fafb",
                        borderRadius: 8,
                        padding: "6px 12px",
                        marginBottom: 8,
                        border: "1px solid #e5e7eb",
                      }}
                    >
                      <span
                        style={{
                          fontSize: 11,
                          color: "#6b7280",
                          fontWeight: 600,
                          letterSpacing: 0.4,
                        }}
                      >
                        TOTAL FINDINGS
                      </span>
                      <span
                        style={{
                          fontSize: 14,
                          fontWeight: 700,
                          color: "#111827",
                        }}
                      >
                        {secDrawerFindings.length.toLocaleString()}
                      </span>
                    </div>
                    <div
                      style={{
                        fontSize: 12,
                        fontWeight: 700,
                        color: "#374151",
                        marginBottom: 8,
                      }}
                    >
                      FINDINGS — sorted by priority
                    </div>
                  </div>
                  <div
                    style={{
                      flex: 1,
                      overflowY: "auto",
                      padding: "0 20px 20px 20px",
                    }}
                  >
                    {secDrawerFindings.length === 0 && (
                      <div
                        style={{
                          textAlign: "center",
                          padding: 32,
                          color: "#6b7280",
                          fontSize: 13,
                        }}
                      >
                        No findings in this selection.
                      </div>
                    )}
                    {[...secDrawerFindings]
                      .sort((a, b) => Number(a.Priority) - Number(b.Priority))
                      .map((f, i) => {
                        const pColor =
                          f.Priority === 1
                            ? "#ef4444"
                            : f.Priority === 2
                              ? "#f59e0b"
                              : f.Priority === 3
                                ? "#3b82f6"
                                : "#6b7280";
                        const pBg =
                          f.Priority === 1
                            ? "#fee2e2"
                            : f.Priority === 2
                              ? "#fef3c7"
                              : f.Priority === 3
                                ? "#dbeafe"
                                : "#f3f4f6";
                        const statusText =
                          f.StatusNew === "1"
                            ? "Open"
                            : f.StatusNew === "2"
                              ? "In Progress"
                              : f.StatusNew === "3"
                                ? "Resolved"
                                : f.StatusNew || "—";
                        const sinceDate = parseSince(f.Since);
                        const age = sinceDate ? ageDays(sinceDate) : null;
                        const rstismTitle = (f.RstismTitle ?? "").trim();
                        const fallbackTitle = resolveCheckTitle(
                          f.CheckTitle,
                          f.NavigationData,
                        );
                        const isCheckmanFinding = selectedRun?.RunKind === "M";
                        const displayTitle = rstismTitle
                          ? rstismTitle
                          : isCheckmanFinding
                            ? null
                            : fallbackTitle || null;
                        const resolvedCiId = resolveCiId(f);
                        const isSecF =
                          isSecurityFinding(f) ||
                          isTitleSecurityCheck(displayTitle || "");
                        const secKnowledge = isSecF
                          ? getSecurityKnowledge(resolvedCiId) ||
                            getSecurityKnowledgeByModuleId(f.CheckCategory)
                          : null;
                        return (
                          <div
                            key={`sd-${f.ItemId ?? i}`}
                            style={{
                              border: "1px solid #e5e7eb",
                              borderLeft: `4px solid ${pColor}`,
                              borderRadius: 8,
                              padding: "12px 14px",
                              marginBottom: 10,
                              background: "#fafafa",
                            }}
                          >
                            <div
                              style={{
                                display: "flex",
                                justifyContent: "space-between",
                                alignItems: "flex-start",
                                marginBottom: 6,
                              }}
                            >
                              <div
                                style={{
                                  fontWeight: 700,
                                  fontSize: 13,
                                  wordBreak: "break-all",
                                  flex: 1,
                                  marginRight: 8,
                                  color: "#111827",
                                }}
                              >
                                {f.ObjectName || "—"}
                              </div>
                              <div
                                style={{
                                  display: "flex",
                                  gap: 4,
                                  flexShrink: 0,
                                  flexWrap: "wrap",
                                  justifyContent: "flex-end",
                                }}
                              >
                                {isSecF && (
                                  <span
                                    style={{
                                      background:
                                        f.Priority <= 2 ? pBg : "#fff7ed",
                                      color:
                                        f.Priority <= 2 ? pColor : "#c2410c",
                                      border: `1px solid ${f.Priority <= 2 ? pColor : "#fed7aa"}`,
                                      borderRadius: 999,
                                      padding: "2px 8px",
                                      fontSize: 10,
                                      fontWeight: 700,
                                    }}
                                  >
                                    🔐 SECURITY
                                  </span>
                                )}
                                <span
                                  style={{
                                    background: pBg,
                                    color: pColor,
                                    border: `1px solid ${pColor}`,
                                    borderRadius: 999,
                                    padding: "2px 8px",
                                    fontSize: 11,
                                    fontWeight: 700,
                                    flexShrink: 0,
                                  }}
                                >
                                  P{f.Priority}
                                </span>
                              </div>
                            </div>
                            {displayTitle && (
                              <div
                                style={{
                                  fontSize: 12,
                                  color: "#374151",
                                  marginBottom: 6,
                                  fontStyle: "italic",
                                }}
                              >
                                {displayTitle}
                              </div>
                            )}
                            {!rstismTitle && isCheckmanFinding && (
                              <div
                                style={{
                                  fontSize: 11,
                                  color: "#9ca3af",
                                  marginBottom: 6,
                                  fontStyle: "italic",
                                }}
                              >
                                Message not available for Checkman runs
                              </div>
                            )}
                            {isSecF && (
                              <div
                                style={{
                                  margin: "8px 0",
                                  padding: "8px 12px",
                                  background:
                                    f.Priority <= 2 ? "#fff7ed" : "#f9fafb",
                                  borderRadius: 8,
                                  borderLeft: `3px solid ${f.Priority <= 2 ? "#f97316" : "#9ca3af"}`,
                                }}
                              >
                                {secKnowledge ? (
                                  <>
                                    <div
                                      style={{
                                        fontSize: 11,
                                        fontWeight: 700,
                                        color:
                                          f.Priority <= 2
                                            ? "#9a3412"
                                            : "#374151",
                                        marginBottom: 3,
                                      }}
                                    >
                                      {secKnowledge.riskName}
                                    </div>
                                    <div
                                      style={{
                                        fontSize: 11,
                                        color: "#4b5563",
                                        lineHeight: 1.5,
                                      }}
                                    >
                                      {secKnowledge.description}
                                    </div>
                                    <details style={{ marginTop: 6 }}>
                                      <summary
                                        style={{
                                          fontSize: 11,
                                          color: "#0a6ed1",
                                          cursor: "pointer",
                                        }}
                                      >
                                        Attack scenario & fix guidance
                                      </summary>
                                      <div
                                        style={{
                                          marginTop: 6,
                                          fontSize: 11,
                                          color: "#7c2d12",
                                          lineHeight: 1.5,
                                        }}
                                      >
                                        ⚠️ {secKnowledge.attackScenario}
                                      </div>
                                      <div
                                        style={{
                                          marginTop: 6,
                                          fontSize: 11,
                                          color: "#166534",
                                          lineHeight: 1.5,
                                        }}
                                      >
                                        ✅ {secKnowledge.fixGuidance}
                                      </div>
                                    </details>
                                  </>
                                ) : (
                                  <div
                                    style={{ fontSize: 11, color: "#4b5563" }}
                                  >
                                    Security check:{" "}
                                    {resolvedCiId ||
                                      f.CheckCategory ||
                                      "Unknown"}
                                  </div>
                                )}
                              </div>
                            )}
                            <div
                              style={{
                                display: "grid",
                                gridTemplateColumns: "100px 1fr",
                                gap: "3px 8px",
                                fontSize: 12,
                              }}
                            >
                              <span style={{ color: "#9ca3af" }}>
                                Object Type
                              </span>
                              <span style={{ color: "#374151" }}>
                                {OBJECT_TYPE_LABELS[f.ObjectType] ||
                                  f.ObjectType ||
                                  "—"}
                              </span>
                              <span style={{ color: "#9ca3af" }}>Package</span>
                              <span style={{ color: "#374151" }}>
                                {f.PackageName || "—"}
                              </span>
                              <span style={{ color: "#9ca3af" }}>Contact</span>
                              <span style={{ color: "#374151" }}>
                                {f.ContactPerson || f.Processor || "—"}
                              </span>
                              <span style={{ color: "#9ca3af" }}>
                                Message Key
                              </span>
                              <span style={{ color: "#374151" }}>
                                {f.MessageKey || "—"}
                              </span>
                              {f.Location && f.Location.trim() !== "" && (
                                <>
                                  <span style={{ color: "#9ca3af" }}>
                                    Location
                                  </span>
                                  <span
                                    style={{
                                      color: "#374151",
                                      wordBreak: "break-all",
                                    }}
                                  >
                                    {f.Location}
                                  </span>
                                </>
                              )}
                              {age !== null && (
                                <>
                                  <span style={{ color: "#9ca3af" }}>Age</span>
                                  <span
                                    style={{
                                      color:
                                        age > 90
                                          ? "#dc2626"
                                          : age > 30
                                            ? "#d97706"
                                            : "#374151",
                                      fontWeight: age > 30 ? 600 : 400,
                                    }}
                                  >
                                    {age} day{age !== 1 ? "s" : ""} open
                                    {isSecF && age > 30 && (
                                      <span
                                        style={{
                                          marginLeft: 6,
                                          fontSize: 10,
                                          color: "#dc2626",
                                          fontWeight: 700,
                                        }}
                                      >
                                        HIGH EXPOSURE
                                      </span>
                                    )}
                                  </span>
                                </>
                              )}
                              <span style={{ color: "#9ca3af" }}>Status</span>
                              <span
                                style={{
                                  color:
                                    f.StatusNew === "1"
                                      ? "#dc2626"
                                      : f.StatusNew === "2"
                                        ? "#d97706"
                                        : "#16a34a",
                                  fontWeight: 600,
                                }}
                              >
                                {statusText}
                              </span>
                            </div>
                            {renderNavButtons(f)}
                            {renderFixGuidance(f)}
                          </div>
                        );
                      })}
                  </div>
                </div>
              </div>
            )}
            {/* Security Category Findings Drawer */}
            {secCatDrawerOpen && (
              <div
                onClick={(e) => {
                  if (e.target === e.currentTarget) setSecCatDrawerOpen(false);
                }}
                style={{
                  position: "fixed",
                  inset: 0,
                  background: "rgba(0,0,0,0.35)",
                  zIndex: 600,
                  display: "flex",
                  justifyContent: "flex-end",
                }}
              >
                <div
                  style={{
                    width: isMobile ? "100vw" : "min(680px,100vw)",
                    height: "100vh",
                    background: "var(--card-bg,#ffffff)",
                    boxShadow: "-4px 0 32px rgba(0,0,0,0.18)",
                    display: "flex",
                    flexDirection: "column",
                    boxSizing: "border-box",
                    overflowX: "hidden",
                  }}
                >
                  <div style={{ padding: "20px 20px 0 20px", flexShrink: 0 }}>
                    <div
                      style={{
                        display: "flex",
                        justifyContent: "space-between",
                        alignItems: "flex-start",
                        marginBottom: 12,
                      }}
                    >
                      <div style={{ minWidth: 0 }}>
                        <h2
                          style={{
                            margin: 0,
                            fontSize: 16,
                            fontWeight: 700,
                            wordBreak: "break-word",
                          }}
                        >
                          🔐 {secCatDrawerTitle}
                        </h2>
                        <div
                          style={{
                            fontSize: 12,
                            color: "#6b7280",
                            marginTop: 4,
                          }}
                        >
                          {secCatDrawerFindings.length} findings · sorted by
                          priority
                        </div>
                      </div>
                      <button
                        className="drawer-close"
                        onClick={() => setSecCatDrawerOpen(false)}
                        style={{ flexShrink: 0, marginLeft: 12 }}
                      >
                        ✕
                      </button>
                    </div>
                    <div
                      style={{
                        display: "grid",
                        gridTemplateColumns: "1fr 1fr 1fr 1fr",
                        gap: 8,
                        marginBottom: 12,
                      }}
                    >
                      {[
                        { l: "P1", p: 1, c: "#dc2626", b: "#fee2e2" },
                        { l: "P2", p: 2, c: "#d97706", b: "#fef3c7" },
                        { l: "P3", p: 3, c: "#2563eb", b: "#dbeafe" },
                        { l: "P4", p: 4, c: "#374151", b: "#f3f4f6" },
                      ].map(({ l, p, c, b }) => {
                        const cnt = secCatDrawerFindings.filter(
                          (f) => Number(f.Priority) === p,
                        ).length;
                        return (
                          <div
                            key={p}
                            style={{
                              padding: "10px 8px",
                              borderRadius: 10,
                              textAlign: "center",
                              background: cnt > 0 ? b : "#f9fafb",
                              border: `2px solid ${cnt > 0 ? c : "#e5e7eb"}`,
                            }}
                          >
                            <div
                              style={{
                                fontSize: 10,
                                color: cnt > 0 ? c : "#6b7280",
                                fontWeight: 600,
                              }}
                            >
                              {l}
                            </div>
                            <div
                              style={{
                                fontSize: 20,
                                fontWeight: 700,
                                color: cnt > 0 ? c : "#9ca3af",
                                marginTop: 2,
                              }}
                            >
                              {cnt}
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                  <div
                    style={{
                      flex: 1,
                      overflowY: "auto",
                      padding: "0 20px 20px 20px",
                    }}
                  >
                    {[...secCatDrawerFindings]
                      .sort((a, b) => Number(a.Priority) - Number(b.Priority))
                      .map((f, i) => {
                        const pColor =
                          f.Priority === 1
                            ? "#ef4444"
                            : f.Priority === 2
                              ? "#f59e0b"
                              : f.Priority === 3
                                ? "#3b82f6"
                                : "#6b7280";
                        const pBg =
                          f.Priority === 1
                            ? "#fee2e2"
                            : f.Priority === 2
                              ? "#fef3c7"
                              : f.Priority === 3
                                ? "#dbeafe"
                                : "#f3f4f6";
                        const sinceDate = parseSince(f.Since);
                        const age = sinceDate ? ageDays(sinceDate) : null;
                        return (
                          <div
                            key={i}
                            style={{
                              border: "1px solid #e5e7eb",
                              borderLeft: `4px solid ${pColor}`,
                              borderRadius: 8,
                              padding: "12px 14px",
                              marginBottom: 10,
                              background: "#fafafa",
                            }}
                          >
                            <div
                              style={{
                                display: "flex",
                                justifyContent: "space-between",
                                alignItems: "flex-start",
                                marginBottom: 6,
                              }}
                            >
                              <div
                                style={{
                                  fontWeight: 700,
                                  fontSize: 13,
                                  wordBreak: "break-all",
                                  flex: 1,
                                  marginRight: 8,
                                  color: "#111827",
                                }}
                              >
                                {f.ObjectName || "—"}
                              </div>
                              <span
                                style={{
                                  background: pBg,
                                  color: pColor,
                                  border: `1px solid ${pColor}`,
                                  borderRadius: 999,
                                  padding: "2px 8px",
                                  fontSize: 11,
                                  fontWeight: 700,
                                  flexShrink: 0,
                                }}
                              >
                                P{f.Priority}
                              </span>
                            </div>
                            {(f.RstismTitle || "").trim() && (
                              <div
                                style={{
                                  fontSize: 12,
                                  color: "#374151",
                                  marginBottom: 6,
                                  fontStyle: "italic",
                                }}
                              >
                                {f.RstismTitle}
                              </div>
                            )}
                            <div
                              style={{
                                display: "grid",
                                gridTemplateColumns: "100px 1fr",
                                gap: "3px 8px",
                                fontSize: 12,
                              }}
                            >
                              <span style={{ color: "#9ca3af" }}>Check</span>
                              <span style={{ color: "#374151" }}>
                                {resolveCheckCategory(f)}
                              </span>
                              <span style={{ color: "#9ca3af" }}>
                                Object Type
                              </span>
                              <span style={{ color: "#374151" }}>
                                {OBJECT_TYPE_LABELS[f.ObjectType] ||
                                  f.ObjectType ||
                                  "—"}
                              </span>
                              <span style={{ color: "#9ca3af" }}>Package</span>
                              <span style={{ color: "#374151" }}>
                                {f.PackageName || "—"}
                              </span>
                              <span style={{ color: "#9ca3af" }}>Contact</span>
                              <span style={{ color: "#374151" }}>
                                {f.ContactPerson || f.Processor || "—"}
                              </span>
                              {age !== null && (
                                <>
                                  <span style={{ color: "#9ca3af" }}>Age</span>
                                  <span
                                    style={{
                                      color:
                                        age > 90
                                          ? "#dc2626"
                                          : age > 30
                                            ? "#d97706"
                                            : "#374151",
                                      fontWeight: age > 30 ? 600 : 400,
                                    }}
                                  >
                                    {age} day{age !== 1 ? "s" : ""} open
                                  </span>
                                </>
                              )}
                            </div>
                            {renderNavButtons(f)}
                            {renderFixGuidance(f)}
                          </div>
                        );
                      })}
                  </div>
                </div>
              </div>
            )}

            {/* All Security Findings — always visible below cards */}
            {securityFindings.length > 0 && (
              <div
                style={{
                  gridColumn: "1/-1",
                  background: "var(--card-bg,#fff)",
                  borderRadius: 12,
                  border: "1px solid #e5e7eb",
                  overflow: "hidden",
                  marginTop: 8,
                }}
              >
                <div
                  style={{
                    padding: "18px 20px 14px",
                    borderBottom: "1px solid #f3f4f6",
                    display: "flex",
                    justifyContent: "space-between",
                    alignItems: "center",
                    flexWrap: "wrap",
                    gap: 10,
                  }}
                >
                  <div>
                    <div
                      style={{
                        fontSize: 10,
                        fontWeight: 700,
                        color: "#0a6ed1",
                        letterSpacing: 1,
                        textTransform: "uppercase",
                        marginBottom: 4,
                      }}
                    >
                      All Findings
                    </div>
                    <div
                      style={{
                        fontSize: 16,
                        fontWeight: 700,
                        color: "#0f172a",
                      }}
                    >
                      Security Findings
                    </div>
                    <div
                      style={{ fontSize: 12, color: "#6b7280", marginTop: 2 }}
                    >
                      {securityFindings.length} total · sorted by priority ·
                      click developer name to filter
                    </div>
                  </div>
                  <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                    {[
                      { l: "P1", p: 1, c: "#dc2626", b: "#fee2e2" },
                      { l: "P2", p: 2, c: "#d97706", b: "#fef3c7" },
                      { l: "P3", p: 3, c: "#2563eb", b: "#dbeafe" },
                      { l: "All", p: null, c: "#374151", b: "#f3f4f6" },
                    ].map(({ l, p, c, b }) => {
                      const cnt =
                        p === null
                          ? securityFindings.length
                          : securityFindings.filter((f) => f.Priority === p)
                              .length;
                      return (
                        <div
                          key={l}
                          style={{
                            padding: "8px 14px",
                            borderRadius: 8,
                            textAlign: "center",
                            background: b,
                            border: `1px solid ${c}22`,
                          }}
                        >
                          <div
                            style={{
                              fontSize: 10,
                              fontWeight: 700,
                              color: c,
                              textTransform: "uppercase",
                            }}
                          >
                            {l}
                          </div>
                          <div
                            style={{ fontSize: 18, fontWeight: 800, color: c }}
                          >
                            {cnt}
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>
                <div style={{ maxHeight: 600, overflowY: "auto" }}>
                  <table style={{ width: "100%", borderCollapse: "collapse" }}>
                    <thead
                      style={{
                        background: "#f8fafc",
                        position: "sticky",
                        top: 0,
                      }}
                    >
                      <tr>
                        {[
                          "Priority",
                          "Object",
                          "Object Type",
                          "Check Category",
                          "Package",
                          "Developer",
                          "Age (d)",
                          "Fix",
                        ].map((h) => (
                          <th
                            key={h}
                            style={{
                              padding: "10px 14px",
                              fontSize: 10,
                              fontWeight: 700,
                              color: "#6b7280",
                              textTransform: "uppercase",
                              letterSpacing: 0.6,
                              textAlign: "left",
                              borderBottom: "2px solid #e5e7eb",
                              whiteSpace: "nowrap",
                            }}
                          >
                            {h}
                          </th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {[...securityFindings]
                        .sort((a, b) => a.Priority - b.Priority)
                        .map((f, i) => {
                          const pColor =
                            f.Priority === 1
                              ? "#dc2626"
                              : f.Priority === 2
                                ? "#d97706"
                                : f.Priority === 3
                                  ? "#2563eb"
                                  : "#6b7280";
                          const pBg =
                            f.Priority === 1
                              ? "#fee2e2"
                              : f.Priority === 2
                                ? "#fef3c7"
                                : f.Priority === 3
                                  ? "#dbeafe"
                                  : "#f3f4f6";
                          const sinceDate = parseSince(f.Since);
                          const age = sinceDate ? ageDays(sinceDate) : null;
                          const dev = f.ContactPerson || f.Processor || "—";
                          return (
                            <tr
                              key={i}
                              onClick={() => {
                                setSecFindingDrawerData(f);
                                setSecFindingDrawerOpen(true);
                              }}
                              style={{
                                background: i % 2 === 0 ? "#fff" : "#fafafa",
                                borderBottom: "1px solid #f3f4f6",
                                cursor: "pointer",
                                transition: "background 0.1s",
                              }}
                              onMouseEnter={(e) =>
                                (e.currentTarget.style.background = "#f8faff")
                              }
                              onMouseLeave={(e) =>
                                (e.currentTarget.style.background =
                                  i % 2 === 0 ? "#fff" : "#fafafa")
                              }
                            >
                              <td style={{ padding: "10px 14px" }}>
                                <span
                                  style={{
                                    background: pBg,
                                    color: pColor,
                                    borderRadius: 999,
                                    padding: "2px 8px",
                                    fontSize: 11,
                                    fontWeight: 700,
                                  }}
                                >
                                  P{f.Priority}
                                </span>
                              </td>
                              <td
                                style={{
                                  padding: "10px 14px",
                                  fontSize: 12,
                                  fontFamily: "monospace",
                                  fontWeight: 600,
                                  color: "#111827",
                                  maxWidth: 160,
                                  overflow: "hidden",
                                  textOverflow: "ellipsis",
                                  whiteSpace: "nowrap",
                                }}
                              >
                                {f.ObjectName || "—"}
                              </td>
                              <td
                                style={{
                                  padding: "10px 14px",
                                  fontSize: 11,
                                  color: "#6b7280",
                                }}
                              >
                                {OBJECT_TYPE_LABELS[f.ObjectType] ||
                                  f.ObjectType ||
                                  "—"}
                              </td>
                              <td
                                style={{
                                  padding: "10px 14px",
                                  fontSize: 12,
                                  color: "#374151",
                                  maxWidth: 200,
                                  overflow: "hidden",
                                  textOverflow: "ellipsis",
                                  whiteSpace: "nowrap",
                                }}
                              >
                                {resolveCheckCategory(f)}
                              </td>
                              <td
                                style={{
                                  padding: "10px 14px",
                                  fontSize: 11,
                                  color: "#6b7280",
                                }}
                              >
                                {f.PackageName || "—"}
                              </td>
                              <td
                                style={{
                                  padding: "10px 14px",
                                  fontSize: 11,
                                  fontFamily: "monospace",
                                  color: "#374151",
                                }}
                              >
                                {dev}
                              </td>
                              <td
                                style={{
                                  padding: "10px 14px",
                                  fontSize: 12,
                                  color:
                                    age && age > 90
                                      ? "#dc2626"
                                      : age && age > 30
                                        ? "#d97706"
                                        : "#374151",
                                  fontWeight: age && age > 30 ? 600 : 400,
                                }}
                              >
                                {age !== null ? age : "—"}
                              </td>
                              <td style={{ padding: "10px 14px" }}>
                                {renderFixGuidance(f)}
                              </td>
                            </tr>
                          );
                        })}
                    </tbody>
                  </table>
                </div>
              </div>
            )}
            {/* Single Security Finding Drawer */}
            {secFindingDrawerOpen && secFindingDrawerData && (
              <div
                onClick={(e) => {
                  if (e.target === e.currentTarget)
                    setSecFindingDrawerOpen(false);
                }}
                style={{
                  position: "fixed",
                  inset: 0,
                  background: "rgba(0,0,0,0.35)",
                  zIndex: 700,
                  display: "flex",
                  justifyContent: "flex-end",
                }}
              >
                <div
                  style={{
                    width: isMobile ? "100vw" : "min(560px,100vw)",
                    height: "100vh",
                    background: "var(--card-bg,#fff)",
                    boxShadow: "-4px 0 32px rgba(0,0,0,0.18)",
                    display: "flex",
                    flexDirection: "column",
                    boxSizing: "border-box",
                  }}
                >
                  <div style={{ padding: "20px 20px 0 20px", flexShrink: 0 }}>
                    <div
                      style={{
                        display: "flex",
                        justifyContent: "space-between",
                        alignItems: "flex-start",
                        marginBottom: 12,
                      }}
                    >
                      <div style={{ minWidth: 0, flex: 1 }}>
                        <h2
                          style={{
                            margin: 0,
                            fontSize: 16,
                            fontWeight: 700,
                            wordBreak: "break-word",
                          }}
                        >
                          🔐{" "}
                          {secFindingDrawerData.ObjectName ||
                            "Security Finding"}
                        </h2>
                        <div
                          style={{
                            fontSize: 12,
                            color: "#6b7280",
                            marginTop: 4,
                          }}
                        >
                          <span
                            style={{
                              background:
                                secFindingDrawerData.Priority === 1
                                  ? "#fee2e2"
                                  : secFindingDrawerData.Priority === 2
                                    ? "#fef3c7"
                                    : "#dbeafe",
                              color:
                                secFindingDrawerData.Priority === 1
                                  ? "#dc2626"
                                  : secFindingDrawerData.Priority === 2
                                    ? "#d97706"
                                    : "#2563eb",
                              borderRadius: 999,
                              padding: "2px 8px",
                              fontSize: 11,
                              fontWeight: 700,
                            }}
                          >
                            P{secFindingDrawerData.Priority}
                          </span>
                          <span style={{ marginLeft: 8 }}>
                            {OBJECT_TYPE_LABELS[
                              secFindingDrawerData.ObjectType
                            ] ||
                              secFindingDrawerData.ObjectType ||
                              "—"}
                          </span>
                        </div>
                      </div>
                      <button
                        className="drawer-close"
                        onClick={() => setSecFindingDrawerOpen(false)}
                        style={{ flexShrink: 0, marginLeft: 12 }}
                      >
                        ✕
                      </button>
                    </div>
                  </div>
                  <div
                    style={{
                      flex: 1,
                      overflowY: "auto",
                      padding: "0 20px 20px 20px",
                    }}
                  >
                    {(secFindingDrawerData.RstismTitle || "").trim() && (
                      <div
                        style={{
                          padding: "12px 16px",
                          background: "#f8fafc",
                          borderRadius: 8,
                          border: "1px solid #e5e7eb",
                          fontSize: 13,
                          color: "#374151",
                          fontStyle: "italic",
                          marginBottom: 14,
                        }}
                      >
                        {secFindingDrawerData.RstismTitle}
                      </div>
                    )}
                    <div
                      style={{
                        display: "grid",
                        gridTemplateColumns: "120px 1fr",
                        gap: "10px 16px",
                        fontSize: 13,
                        marginBottom: 16,
                      }}
                    >
                      <span style={{ color: "#6b7280", fontWeight: 600 }}>
                        Object Name
                      </span>
                      <span
                        style={{
                          color: "#111827",
                          fontFamily: "monospace",
                          fontWeight: 600,
                          wordBreak: "break-all",
                        }}
                      >
                        {secFindingDrawerData.ObjectName || "—"}
                      </span>

                      <span style={{ color: "#6b7280", fontWeight: 600 }}>
                        Check Category
                      </span>
                      <span style={{ color: "#374151" }}>
                        {resolveCheckCategory(secFindingDrawerData)}
                      </span>

                      <span style={{ color: "#6b7280", fontWeight: 600 }}>
                        Package
                      </span>
                      <span style={{ color: "#374151" }}>
                        {secFindingDrawerData.PackageName || "—"}
                      </span>

                      <span style={{ color: "#6b7280", fontWeight: 600 }}>
                        Developer
                      </span>
                      <span
                        style={{ color: "#374151", fontFamily: "monospace" }}
                      >
                        {secFindingDrawerData.ContactPerson ||
                          secFindingDrawerData.Processor ||
                          "—"}
                      </span>

                      <span style={{ color: "#6b7280", fontWeight: 600 }}>
                        Message Key
                      </span>
                      <span
                        style={{
                          color: "#374151",
                          fontFamily: "monospace",
                          fontSize: 11,
                        }}
                      >
                        {secFindingDrawerData.MessageKey || "—"}
                      </span>

                      {secFindingDrawerData.Location &&
                        secFindingDrawerData.Location.trim() && (
                          <>
                            <span style={{ color: "#6b7280", fontWeight: 600 }}>
                              Location
                            </span>
                            <span
                              style={{
                                color: "#374151",
                                fontFamily: "monospace",
                                fontSize: 11,
                                wordBreak: "break-all",
                              }}
                            >
                              {secFindingDrawerData.Location}
                            </span>
                          </>
                        )}

                      {(() => {
                        const sinceDate = parseSince(
                          secFindingDrawerData.Since,
                        );
                        const age = sinceDate ? ageDays(sinceDate) : null;
                        return age !== null ? (
                          <>
                            <span style={{ color: "#6b7280", fontWeight: 600 }}>
                              Age
                            </span>
                            <span
                              style={{
                                color:
                                  age > 90
                                    ? "#dc2626"
                                    : age > 30
                                      ? "#d97706"
                                      : "#374151",
                                fontWeight: age > 30 ? 700 : 400,
                              }}
                            >
                              {age} day{age !== 1 ? "s" : ""} open
                              {age > 30 && (
                                <span
                                  style={{
                                    marginLeft: 8,
                                    fontSize: 11,
                                    color: "#dc2626",
                                    fontWeight: 700,
                                  }}
                                >
                                  HIGH EXPOSURE
                                </span>
                              )}
                            </span>
                          </>
                        ) : null;
                      })()}

                      <span style={{ color: "#6b7280", fontWeight: 600 }}>
                        Status
                      </span>
                      <span
                        style={{
                          color:
                            secFindingDrawerData.StatusNew === "1"
                              ? "#dc2626"
                              : secFindingDrawerData.StatusNew === "2"
                                ? "#d97706"
                                : "#16a34a",
                          fontWeight: 600,
                        }}
                      >
                        {secFindingDrawerData.StatusNew === "1"
                          ? "Open"
                          : secFindingDrawerData.StatusNew === "2"
                            ? "In Progress"
                            : secFindingDrawerData.StatusNew === "3"
                              ? "Resolved"
                              : "—"}
                      </span>
                    </div>

                    {renderNavButtons(secFindingDrawerData)}
                    {renderFixGuidance(secFindingDrawerData)}
                  </div>
                </div>
              </div>
            )}
          </div>
        )}
        {/* ════ RUN EXPLORER TAB ════ */}
        {tab === "runs" && (
          <div className="table-card premium-results">
            <div className="table-toolbar">
              <h3>Check run results</h3>
              <div className="toolbar-actions">
                <div
                  style={{ position: "relative" }}
                  onClick={(e) => e.stopPropagation()}
                >
                  <button
                    className="btn-secondary"
                    onClick={() => setRunExportOpen((o) => !o)}
                    style={{ display: "flex", alignItems: "center", gap: 6 }}
                  >
                    ⬇ Download {runExportOpen ? "▲" : "▼"}
                  </button>
                  {runExportOpen && (
                    <div
                      style={{
                        position: "absolute",
                        top: "calc(100% + 6px)",
                        right: 0,
                        background: "var(--card-bg,#fff)",
                        border: "1px solid #e5e7eb",
                        borderRadius: 10,
                        boxShadow: "0 8px 24px rgba(0,0,0,0.12)",
                        zIndex: 200,
                        minWidth: 210,
                        overflow: "hidden",
                      }}
                    >
                      <div
                        style={{
                          padding: "8px 12px 4px",
                          fontSize: 10,
                          fontWeight: 700,
                          color: "#9ca3af",
                          letterSpacing: 0.5,
                          textTransform: "uppercase",
                        }}
                      >
                        Export format
                      </div>
                      <button
                        onClick={() => {
                          const headers = [
                            "ID",
                            "Series",
                            "Title",
                            "Scheduled By",
                            "System",
                            "Date",
                            "Source",
                            "P1",
                            "P2",
                            "P3",
                            "P4",
                            "Total",
                            "Central",
                          ];
                          const rows = filteredRuns.map((r) => [
                            r.ID,
                            r.series ?? "",
                            r.title ?? "",
                            r.user ?? "",
                            r.system ?? "",
                            r.date ?? "",
                            r.RunKind === "C"
                              ? "Code Inspector"
                              : r.RunKind === "M"
                                ? "Checkman"
                                : (r.RunKind ?? ""),
                            r.p1,
                            r.p2,
                            r.p3,
                            r.p4 ?? 0,
                            r.p1 + r.p2 + r.p3 + (r.p4 ?? 0),
                            r.central ? "Yes" : "No",
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
                          setRunExportOpen(false);
                        }}
                        style={{
                          display: "flex",
                          alignItems: "center",
                          gap: 10,
                          width: "100%",
                          padding: "10px 14px",
                          border: "none",
                          background: "none",
                          cursor: "pointer",
                          fontSize: 13,
                          color: "#374151",
                          textAlign: "left",
                        }}
                        onMouseEnter={(e) =>
                          (e.currentTarget.style.background = "#f3f4f6")
                        }
                        onMouseLeave={(e) =>
                          (e.currentTarget.style.background = "none")
                        }
                      >
                        <span style={{ fontSize: 16 }}>📄</span>
                        <div>
                          <div style={{ fontWeight: 600 }}>CSV</div>
                          <div style={{ fontSize: 11, color: "#9ca3af" }}>
                            Simple comma-separated file
                          </div>
                        </div>
                      </button>
                      <div
                        style={{
                          height: "0.5px",
                          background: "#f3f4f6",
                          margin: "0 12px",
                        }}
                      />
                      <button
                        onClick={() => {
                          exportRunsExcel();
                          setRunExportOpen(false);
                        }}
                        style={{
                          display: "flex",
                          alignItems: "center",
                          gap: 10,
                          width: "100%",
                          padding: "10px 14px",
                          border: "none",
                          background: "none",
                          cursor: "pointer",
                          fontSize: 13,
                          color: "#374151",
                          textAlign: "left",
                        }}
                        onMouseEnter={(e) =>
                          (e.currentTarget.style.background = "#f0fdf4")
                        }
                        onMouseLeave={(e) =>
                          (e.currentTarget.style.background = "none")
                        }
                      >
                        <span style={{ fontSize: 16 }}>📊</span>
                        <div>
                          <div style={{ fontWeight: 600, color: "#15803d" }}>
                            Excel (.xlsx)
                          </div>
                          <div style={{ fontSize: 11, color: "#9ca3af" }}>
                            Formatted · coloured · 2 sheets
                          </div>
                        </div>
                      </button>
                      <div style={{ height: 6 }} />
                    </div>
                  )}
                </div>
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
                    <th>SOURCE</th>
                    <th>P1</th>
                    <th>P2</th>
                    <th>P3</th>
                    <th>P4</th>
                    <th>TOTAL</th>
                    <th>SEVERITY</th>
                    <th>STATUS</th>
                    <th>CENTRAL</th>
                    <th>ACTIONS</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredRuns.map((r) => {
                    const p4 = r.p4 ?? 0;
                    const grandTotal = r.p1 + r.p2 + r.p3 + p4;
                    const safeTotal = grandTotal || 1;
                    const highRisk = r.p1 > 20;
                    const isSelected = selectedRun?.ID === r.ID;
                    const isCompare = compareRun?.ID === r.ID;
                    return (
                      <tr
                        key={r.ID}
                        style={{
                          cursor: "pointer",
                          background: isSelected
                            ? "#eff6ff"
                            : isCompare
                              ? "#f0fdf4"
                              : undefined,
                        }}
                        onClick={() => {
                          setSelectedRun(r);
                          setDrawerOpen(true);
                          fetchFindings(r.ID);
                          fetchAssignments(r);
                        }}
                      >
                        <td>
                          <span className="pill-series">{r.series || "—"}</span>
                        </td>
                        <td>{r.title || "—"}</td>
                        <td>{r.user || "—"}</td>
                        <td>{r.date || "—"}</td>
                        <td>
                          {r.RunKind === "C" ? (
                            <span
                              style={{
                                background: "#dcfce7",
                                color: "#15803d",
                                borderRadius: 999,
                                padding: "2px 9px",
                                fontSize: 11,
                                fontWeight: 700,
                                whiteSpace: "nowrap",
                              }}
                            >
                              Code Inspector
                            </span>
                          ) : r.RunKind === "M" ? (
                            <span
                              style={{
                                background: "#dbeafe",
                                color: "#1e40af",
                                borderRadius: 999,
                                padding: "2px 9px",
                                fontSize: 11,
                                fontWeight: 700,
                                whiteSpace: "nowrap",
                              }}
                            >
                              Checkman
                            </span>
                          ) : (
                            <span style={{ color: "#9ca3af", fontSize: 12 }}>
                              —
                            </span>
                          )}
                        </td>
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
                          <span className="badge-grey">{p4}</span>
                        </td>
                        <td>
                          <span
                            style={{
                              fontSize: 12,
                              fontWeight: 700,
                              color: "#374151",
                            }}
                          >
                            {grandTotal.toLocaleString()}
                          </span>
                        </td>
                        <td>
                          <div className="sev-bar">
                            <span
                              className="sev-red"
                              style={{ width: `${(r.p1 / safeTotal) * 100}%` }}
                            />
                            <span
                              className="sev-orange"
                              style={{ width: `${(r.p2 / safeTotal) * 100}%` }}
                            />
                            <span
                              className="sev-blue"
                              style={{ width: `${(r.p3 / safeTotal) * 100}%` }}
                            />
                            <span
                              className="sev-grey"
                              style={{ width: `${(p4 / safeTotal) * 100}%` }}
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
                            className={r.central ? "central-yes" : "central-no"}
                          >
                            {r.central ? "Central" : "No"}
                          </span>
                        </td>
                        <td onClick={(e) => e.stopPropagation()}>
                          <button
                            onClick={() => {
                              if (compareRun?.ID === r.ID) {
                                setCompareRun(null);
                                setCompareDrawerOpen(false);
                                setCompareFindings([]);
                                return;
                              }
                              if (!selectedRun) {
                                alert(
                                  "First click a row to set the baseline, then click Compare on another run.",
                                );
                                return;
                              }
                              if (selectedRun.ID === r.ID) {
                                alert(
                                  "Select a different run to compare against the baseline.",
                                );
                                return;
                              }
                              setCompareRun(r);
                              setCompareDrawerOpen(true);
                              fetchCompareFindings(r.ID);
                            }}
                            style={{
                              padding: "4px 10px",
                              borderRadius: 6,
                              border: `1px solid ${isCompare ? "#22c55e" : "#d1d5db"}`,
                              background: isCompare ? "#dcfce7" : "white",
                              color: isCompare ? "#15803d" : "#374151",
                              fontSize: 11,
                              fontWeight: 600,
                              cursor: "pointer",
                              whiteSpace: "nowrap",
                            }}
                          >
                            {isCompare ? "✓ Comparing" : "⇄ Compare"}
                          </button>
                        </td>
                      </tr>
                    );
                  })}
                  {filteredRuns.length === 0 && (
                    <tr>
                      <td
                        colSpan={14}
                        style={{
                          textAlign: "center",
                          padding: 32,
                          color: "#6b7280",
                        }}
                      >
                        No runs match the current filters.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* ── RUN DETAIL DRAWER ── */}
        {tab === "runs" && drawerOpen && selectedRun && (
          <div
            className="drawer-overlay"
            onClick={(e) => {
              if (e.target === e.currentTarget) setDrawerOpen(false);
            }}
            style={{
              position: "fixed",
              inset: 0,
              background: "rgba(0,0,0,0.35)",
              zIndex: 500,
              display: "flex",
              justifyContent: "flex-end",
            }}
          >
            <div
              style={{
                width: isMobile ? "100vw" : "min(680px,100vw)",
                height: "100vh",
                background: "var(--card-bg,#ffffff)",
                boxShadow: "-4px 0 32px rgba(0,0,0,0.18)",
                display: "flex",
                flexDirection: "column",
                boxSizing: "border-box",
                overflowX: "hidden",
              }}
            >
              <div style={{ padding: "20px 20px 0 20px", flexShrink: 0 }}>
                <div
                  style={{
                    display: "flex",
                    justifyContent: "space-between",
                    alignItems: "flex-start",
                    marginBottom: 12,
                  }}
                >
                  <div style={{ minWidth: 0 }}>
                    <h2
                      style={{
                        margin: 0,
                        fontSize: 16,
                        fontWeight: 700,
                        wordBreak: "break-word",
                      }}
                    >
                      {selectedRun.title || "ATC Run Detail"}
                    </h2>
                    <div
                      style={{
                        fontSize: 12,
                        color: "#6b7280",
                        marginTop: 4,
                        display: "flex",
                        alignItems: "center",
                        gap: 8,
                        flexWrap: "wrap",
                      }}
                    >
                      <span>
                        Series: {selectedRun.series || "—"} | Date:{" "}
                        {selectedRun.date || "—"} | System:{" "}
                        {selectedRun.system || "—"}
                      </span>
                      {selectedRun.RunKind && (
                        <span
                          style={{
                            background:
                              selectedRun.RunKind === "C"
                                ? "#dcfce7"
                                : "#dbeafe",
                            color:
                              selectedRun.RunKind === "C"
                                ? "#15803d"
                                : "#1e40af",
                            borderRadius: 999,
                            padding: "1px 7px",
                            fontSize: 10,
                            fontWeight: 700,
                          }}
                        >
                          {selectedRun.RunKind === "C"
                            ? "Code Inspector"
                            : "Checkman"}
                        </span>
                      )}
                    </div>
                  </div>
                  <button
                    className="drawer-close"
                    onClick={() => {
                      if (findingsAbortRef.current) {
                        findingsAbortRef.current.abort();
                        findingsAbortRef.current = null;
                      }
                      setDrawerOpen(false);
                    }}
                    style={{ flexShrink: 0, marginLeft: 12 }}
                  >
                    ✕
                  </button>
                </div>
                <div
                  style={{
                    display: "grid",
                    gridTemplateColumns: isMobile
                      ? "1fr 1fr"
                      : "1fr 1fr 1fr 1fr",
                    gap: 8,
                    marginBottom: 8,
                  }}
                >
                  {[
                    {
                      label: "CRITICAL (P1)",
                      value: selectedRun.p1,
                      prio: 1,
                      active: "#fee2e2",
                      border: "#ef4444",
                      text: "#dc2626",
                    },
                    {
                      label: "WARNING (P2)",
                      value: selectedRun.p2,
                      prio: 2,
                      active: "#fef3c7",
                      border: "#f59e0b",
                      text: "#d97706",
                    },
                    {
                      label: "INFO (P3)",
                      value: selectedRun.p3,
                      prio: 3,
                      active: "#dbeafe",
                      border: "#3b82f6",
                      text: "#2563eb",
                    },
                    {
                      label: "NOTE (P4)",
                      value: selectedRun.p4 ?? 0,
                      prio: 4,
                      active: "#f3f4f6",
                      border: "#6b7280",
                      text: "#374151",
                    },
                  ].map(({ label, value, prio, active, border, text }) => {
                    const isActive = findingPriorityFilter === prio;
                    return (
                      <div
                        key={prio}
                        onClick={() => handlePriorityFilter(prio)}
                        style={{
                          padding: "10px 8px",
                          borderRadius: 10,
                          textAlign: "center",
                          cursor: "pointer",
                          background: isActive ? active : "#f9fafb",
                          border: `2px solid ${isActive ? border : "#e5e7eb"}`,
                          transition: "all 0.15s",
                        }}
                      >
                        <div
                          style={{
                            fontSize: 10,
                            color: isActive ? text : "#6b7280",
                            fontWeight: 600,
                            letterSpacing: 0.5,
                          }}
                        >
                          {label}
                        </div>
                        <div
                          style={{
                            fontSize: 20,
                            fontWeight: 700,
                            color: isActive ? text : "#111827",
                            marginTop: 2,
                          }}
                        >
                          {(value ?? 0).toLocaleString()}
                        </div>
                      </div>
                    );
                  })}
                </div>
                <div
                  style={{
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "space-between",
                    background: "#f9fafb",
                    borderRadius: 8,
                    padding: "6px 12px",
                    marginBottom: 8,
                    border: "1px solid #e5e7eb",
                  }}
                >
                  <span
                    style={{
                      fontSize: 11,
                      color: "#6b7280",
                      fontWeight: 600,
                      letterSpacing: 0.4,
                    }}
                  >
                    TOTAL FINDINGS
                  </span>
                  <span
                    style={{ fontSize: 14, fontWeight: 700, color: "#111827" }}
                  >
                    {(
                      selectedRun.p1 +
                      selectedRun.p2 +
                      selectedRun.p3 +
                      (selectedRun.p4 ?? 0)
                    ).toLocaleString()}
                  </span>
                </div>
                <div
                  style={{
                    display: "flex",
                    justifyContent: "space-between",
                    alignItems: "center",
                    marginBottom: 8,
                  }}
                >
                  <div
                    style={{
                      fontSize: 12,
                      fontWeight: 700,
                      color: "#374151",
                      letterSpacing: 0.5,
                    }}
                  >
                    FINDINGS
                    {findingPriorityFilter && (
                      <span
                        style={{
                          marginLeft: 8,
                          color:
                            findingPriorityFilter === 1
                              ? "#dc2626"
                              : findingPriorityFilter === 2
                                ? "#d97706"
                                : findingPriorityFilter === 3
                                  ? "#2563eb"
                                  : "#374151",
                        }}
                      >
                        — P{findingPriorityFilter} only
                      </span>
                    )}
                  </div>
                  <div style={{ fontSize: 11, color: "#9ca3af" }}>
                    {filteredFindings.length} of {findings.length} shown
                    {findingPriorityFilter && (
                      <button
                        onClick={() => handlePriorityFilter(null)}
                        style={{
                          marginLeft: 8,
                          fontSize: 11,
                          color: "#6b7280",
                          background: "none",
                          border: "none",
                          cursor: "pointer",
                          textDecoration: "underline",
                        }}
                      >
                        Clear filter
                      </button>
                    )}
                  </div>
                </div>
              </div>
              <div
                style={{
                  flex: 1,
                  overflowY: "auto",
                  padding: "0 20px 20px 20px",
                }}
              >
                {findingsLoading && findings.length === 0 && (
                  <div
                    style={{
                      textAlign: "center",
                      padding: 32,
                      color: "#6b7280",
                      fontSize: 13,
                    }}
                  >
                    Loading findings...
                  </div>
                )}
                {findingsLoading && findings.length > 0 && (
                  <div
                    style={{
                      padding: 14,
                      background: "#eff6ff",
                      borderRadius: 12,
                      marginBottom: 14,
                      border: "1px solid #93c5fd",
                      fontSize: 13,
                      color: "#1e40af",
                      fontWeight: 600,
                    }}
                  >
                    Loading... {findings.length.toLocaleString()} findings
                    loaded
                  </div>
                )}
                {!findingsLoading && findings.length === 0 && (
                  <div
                    style={{
                      textAlign: "center",
                      padding: 32,
                      color: "#6b7280",
                      fontSize: 13,
                    }}
                  >
                    {connection === "btp"
                      ? "Findings detail is only available in NetWeaver mode."
                      : "No open findings for this run."}
                  </div>
                )}
                {currentPageData.map((f, i) => {
                  const pColor =
                    f.Priority === 1
                      ? "#ef4444"
                      : f.Priority === 2
                        ? "#f59e0b"
                        : f.Priority === 3
                          ? "#3b82f6"
                          : "#6b7280";
                  const pBg =
                    f.Priority === 1
                      ? "#fee2e2"
                      : f.Priority === 2
                        ? "#fef3c7"
                        : f.Priority === 3
                          ? "#dbeafe"
                          : "#f3f4f6";
                  const statusText =
                    f.StatusNew === "1"
                      ? "Open"
                      : f.StatusNew === "2"
                        ? "In Progress"
                        : f.StatusNew === "3"
                          ? "Resolved"
                          : f.StatusNew || "—";
                  const sinceDate = parseSince(f.Since);
                  const age = sinceDate ? ageDays(sinceDate) : null;
                  const rstismTitle = (f.RstismTitle ?? "").trim();
                  const fallbackTitle = resolveCheckTitle(
                    f.CheckTitle,
                    f.NavigationData,
                  );
                  const isCheckmanFinding =
                    f.RunKind === "M" || selectedRun?.RunKind === "M";
                  const displayTitle = rstismTitle
                    ? rstismTitle
                    : isCheckmanFinding
                      ? null
                      : fallbackTitle || null;
                  const resolvedCiId = resolveCiId(f);
                  const isSecF =
                    isSecurityFinding(f) ||
                    isTitleSecurityCheck(displayTitle || "");
                  const secKnowledge = isSecF
                    ? getSecurityKnowledge(resolvedCiId) ||
                      getSecurityKnowledgeByModuleId(f.CheckCategory)
                    : null;
                  return (
                    <div
                      key={`${f.ItemId}-${i}`}
                      style={{
                        border: "1px solid #e5e7eb",
                        borderLeft: `4px solid ${pColor}`,
                        borderRadius: 8,
                        padding: "12px 14px",
                        marginBottom: 10,
                        background: "#fafafa",
                      }}
                    >
                      <div
                        style={{
                          display: "flex",
                          justifyContent: "space-between",
                          alignItems: "flex-start",
                          marginBottom: 6,
                        }}
                      >
                        <div
                          style={{
                            fontWeight: 700,
                            fontSize: 13,
                            wordBreak: "break-all",
                            flex: 1,
                            marginRight: 8,
                            color: "#111827",
                          }}
                        >
                          {f.ObjectName || "—"}
                        </div>
                        <div
                          style={{
                            display: "flex",
                            gap: 4,
                            flexShrink: 0,
                            flexWrap: "wrap",
                            justifyContent: "flex-end",
                          }}
                        >
                          {isSecF && (
                            <span
                              style={{
                                background: f.Priority <= 2 ? pBg : "#fff7ed",
                                color: f.Priority <= 2 ? pColor : "#c2410c",
                                border: `1px solid ${f.Priority <= 2 ? pColor : "#fed7aa"}`,
                                borderRadius: 999,
                                padding: "2px 8px",
                                fontSize: 10,
                                fontWeight: 700,
                              }}
                            >
                              🔐 SECURITY
                            </span>
                          )}
                          <span
                            style={{
                              background: pBg,
                              color: pColor,
                              border: `1px solid ${pColor}`,
                              borderRadius: 999,
                              padding: "2px 8px",
                              fontSize: 11,
                              fontWeight: 700,
                              flexShrink: 0,
                            }}
                          >
                            P{f.Priority}
                          </span>
                        </div>
                      </div>
                      {displayTitle && (
                        <div
                          style={{
                            fontSize: 12,
                            color: "#374151",
                            marginBottom: 6,
                            fontStyle: "italic",
                          }}
                        >
                          {displayTitle}
                        </div>
                      )}
                      {!rstismTitle && isCheckmanFinding && (
                        <div
                          style={{
                            fontSize: 11,
                            color: "#9ca3af",
                            marginBottom: 6,
                            fontStyle: "italic",
                          }}
                        >
                          Message not available for Checkman runs
                        </div>
                      )}
                      {isSecF && secKnowledge && (
                        <div
                          style={{
                            margin: "8px 0",
                            padding: "8px 12px",
                            background: f.Priority <= 2 ? "#fff7ed" : "#f9fafb",
                            borderRadius: 8,
                            borderLeft: `3px solid ${f.Priority <= 2 ? "#f97316" : "#9ca3af"}`,
                          }}
                        >
                          <div
                            style={{
                              fontSize: 11,
                              fontWeight: 700,
                              color: f.Priority <= 2 ? "#9a3412" : "#374151",
                              marginBottom: 3,
                            }}
                          >
                            {secKnowledge.riskName}
                            <span
                              style={{
                                marginLeft: 8,
                                fontWeight: 400,
                                fontSize: 10,
                                color: "#6b7280",
                              }}
                            >
                              ({secKnowledge.severity})
                            </span>
                          </div>
                          <div
                            style={{
                              fontSize: 11,
                              color: "#4b5563",
                              lineHeight: 1.5,
                            }}
                          >
                            {secKnowledge.description}
                          </div>
                          <details style={{ marginTop: 6 }}>
                            <summary
                              style={{
                                fontSize: 11,
                                color: "#0a6ed1",
                                cursor: "pointer",
                                userSelect: "none",
                              }}
                            >
                              Attack scenario & fix guidance
                            </summary>
                            <div
                              style={{
                                marginTop: 6,
                                fontSize: 11,
                                color: "#7c2d12",
                                lineHeight: 1.5,
                              }}
                            >
                              ⚠️ {secKnowledge.attackScenario}
                            </div>
                            <div
                              style={{
                                marginTop: 6,
                                fontSize: 11,
                                color: "#166534",
                                lineHeight: 1.5,
                              }}
                            >
                              ✅ {secKnowledge.fixGuidance}
                            </div>
                          </details>
                        </div>
                      )}
                      <div
                        style={{
                          display: "grid",
                          gridTemplateColumns: "100px 1fr",
                          gap: "3px 8px",
                          fontSize: 12,
                        }}
                      >
                        <span style={{ color: "#9ca3af" }}>Object Type</span>
                        <span style={{ color: "#374151" }}>
                          {OBJECT_TYPE_LABELS[f.ObjectType] ||
                            f.ObjectType ||
                            "—"}
                        </span>
                        <span style={{ color: "#9ca3af" }}>Package</span>
                        <span style={{ color: "#374151" }}>
                          {f.PackageName || "—"}
                        </span>
                        <span style={{ color: "#9ca3af" }}>Contact</span>
                        <span style={{ color: "#374151" }}>
                          {f.ContactPerson || f.Processor || "—"}
                        </span>
                        <span style={{ color: "#9ca3af" }}>Message Key</span>
                        <span style={{ color: "#374151" }}>
                          {f.MessageKey || "—"}
                        </span>
                        {f.Location && f.Location.trim() !== "" && (
                          <>
                            <span style={{ color: "#9ca3af" }}>Location</span>
                            <span
                              style={{
                                color: "#374151",
                                wordBreak: "break-all",
                              }}
                            >
                              {f.Location}
                            </span>
                          </>
                        )}
                        {age !== null && (
                          <>
                            <span style={{ color: "#9ca3af" }}>Age</span>
                            <span
                              style={{
                                color:
                                  age > 90
                                    ? "#dc2626"
                                    : age > 30
                                      ? "#d97706"
                                      : "#374151",
                                fontWeight: age > 30 ? 600 : 400,
                              }}
                            >
                              {age} day{age !== 1 ? "s" : ""} open
                              {isSecF && age > 30 && (
                                <span
                                  style={{
                                    marginLeft: 6,
                                    fontSize: 10,
                                    color: "#dc2626",
                                    fontWeight: 700,
                                  }}
                                >
                                  HIGH EXPOSURE
                                </span>
                              )}
                            </span>
                          </>
                        )}
                        <span style={{ color: "#9ca3af" }}>Status</span>
                        <span
                          style={{
                            color:
                              f.StatusNew === "1"
                                ? "#dc2626"
                                : f.StatusNew === "2"
                                  ? "#d97706"
                                  : "#16a34a",
                            fontWeight: 600,
                          }}
                        >
                          {statusText}
                        </span>
                      </div>
                      {renderNavButtons(f)}
                      {renderFixGuidance(f)}
                    </div>
                  );
                })}
                {totalPages > 1 && (
                  <div
                    style={{
                      display: "flex",
                      justifyContent: "center",
                      alignItems: "center",
                      gap: 8,
                      marginTop: 16,
                      paddingTop: 16,
                      borderTop: "1px solid #e5e7eb",
                    }}
                  >
                    <button
                      onClick={() =>
                        setFindingsPage(Math.max(1, findingsPage - 1))
                      }
                      disabled={findingsPage === 1}
                      style={{
                        padding: "6px 12px",
                        borderRadius: 6,
                        border: "1px solid #d1d5db",
                        background: findingsPage === 1 ? "#f3f4f6" : "white",
                        color: findingsPage === 1 ? "#9ca3af" : "#374151",
                        cursor: findingsPage === 1 ? "default" : "pointer",
                        fontSize: 12,
                        fontWeight: 600,
                      }}
                    >
                      ← Previous
                    </button>
                    <span style={{ fontSize: 12, color: "#6b7280" }}>
                      Page {findingsPage} of {totalPages}
                    </span>
                    <button
                      onClick={() =>
                        setFindingsPage(Math.min(totalPages, findingsPage + 1))
                      }
                      disabled={findingsPage === totalPages}
                      style={{
                        padding: "6px 12px",
                        borderRadius: 6,
                        border: "1px solid #d1d5db",
                        background:
                          findingsPage === totalPages ? "#f3f4f6" : "white",
                        color:
                          findingsPage === totalPages ? "#9ca3af" : "#374151",
                        cursor:
                          findingsPage === totalPages ? "default" : "pointer",
                        fontSize: 12,
                        fontWeight: 600,
                      }}
                    >
                      Next →
                    </button>
                  </div>
                )}
                {findings.length > 0 && (
                  <div
                    style={{
                      textAlign: "center",
                      padding: 10,
                      fontSize: 11,
                      color: "#6b7280",
                      borderTop: "1px solid #f3f4f6",
                      marginTop: 8,
                    }}
                  >
                    {findingsLoading ? (
                      <span style={{ color: "#1e40af", fontWeight: 600 }}>
                        📊 Showing {currentPageData.length} of{" "}
                        {findings.length.toLocaleString()} loaded · Loading
                        continues...
                      </span>
                    ) : (
                      <span>
                        Showing {currentPageData.length} of{" "}
                        {filteredFindings.length.toLocaleString()} total
                        findings
                      </span>
                    )}
                  </div>
                )}
              </div>
            </div>
          </div>
        )}

        {/* ── COMPARISON DRAWER ── */}
        {tab === "runs" && compareDrawerOpen && selectedRun && compareRun && (
          <div
            onClick={(e) => {
              if (e.target === e.currentTarget) {
                setCompareDrawerOpen(false);
                setCompareRun(null);
                setCompareFindings([]);
              }
            }}
            style={{
              position: "fixed",
              inset: 0,
              background: "rgba(0,0,0,0.35)",
              zIndex: 600,
              display: "flex",
              justifyContent: "flex-end",
            }}
          >
            <div
              style={{
                width: isMobile ? "100vw" : "min(760px,100vw)",
                height: "100vh",
                background: "var(--card-bg,#ffffff)",
                boxShadow: "-4px 0 32px rgba(0,0,0,0.18)",
                display: "flex",
                flexDirection: "column",
                boxSizing: "border-box",
                overflowX: "hidden",
              }}
            >
              <div style={{ padding: "20px 20px 0 20px", flexShrink: 0 }}>
                <div
                  style={{
                    display: "flex",
                    justifyContent: "space-between",
                    alignItems: "flex-start",
                    marginBottom: 16,
                  }}
                >
                  <div>
                    <div
                      style={{
                        fontSize: 10,
                        fontWeight: 700,
                        color: "#0a6ed1",
                        letterSpacing: 1,
                        textTransform: "uppercase",
                        marginBottom: 4,
                      }}
                    >
                      Run Comparison
                    </div>
                    <h2 style={{ margin: 0, fontSize: 16, fontWeight: 700 }}>
                      Side-by-Side Analysis
                    </h2>
                  </div>
                  <button
                    className="drawer-close"
                    onClick={() => {
                      setCompareDrawerOpen(false);
                      setCompareRun(null);
                      setCompareFindings([]);
                    }}
                    style={{ flexShrink: 0, marginLeft: 12 }}
                  >
                    ✕
                  </button>
                </div>
                <div
                  style={{
                    display: "grid",
                    gridTemplateColumns: "1fr auto 1fr",
                    gap: 10,
                    alignItems: "center",
                    marginBottom: 16,
                  }}
                >
                  <div
                    style={{
                      padding: "12px 14px",
                      background: "#eff6ff",
                      borderRadius: 10,
                      border: "2px solid #3b82f6",
                    }}
                  >
                    <div
                      style={{
                        fontSize: 10,
                        fontWeight: 700,
                        color: "#1e40af",
                        textTransform: "uppercase",
                        marginBottom: 3,
                      }}
                    >
                      Baseline (A)
                    </div>
                    <div
                      style={{
                        fontSize: 13,
                        fontWeight: 700,
                        color: "#111827",
                      }}
                    >
                      {selectedRun.title ||
                        selectedRun.series ||
                        selectedRun.ID}
                    </div>
                    <div
                      style={{ fontSize: 11, color: "#6b7280", marginTop: 2 }}
                    >
                      {selectedRun.date} · P1:{selectedRun.p1} P2:
                      {selectedRun.p2} P3:{selectedRun.p3}
                    </div>
                  </div>
                  <div
                    style={{
                      fontSize: 20,
                      color: "#9ca3af",
                      fontWeight: 700,
                      textAlign: "center",
                    }}
                  >
                    ⇄
                  </div>
                  <div
                    style={{
                      padding: "12px 14px",
                      background: "#f0fdf4",
                      borderRadius: 10,
                      border: "2px solid #22c55e",
                    }}
                  >
                    <div
                      style={{
                        fontSize: 10,
                        fontWeight: 700,
                        color: "#15803d",
                        textTransform: "uppercase",
                        marginBottom: 3,
                      }}
                    >
                      Comparison (B)
                    </div>
                    <div
                      style={{
                        fontSize: 13,
                        fontWeight: 700,
                        color: "#111827",
                      }}
                    >
                      {compareRun.title || compareRun.series || compareRun.ID}
                    </div>
                    <div
                      style={{ fontSize: 11, color: "#6b7280", marginTop: 2 }}
                    >
                      {compareRun.date} · P1:{compareRun.p1} P2:{compareRun.p2}{" "}
                      P3:{compareRun.p3}
                    </div>
                  </div>
                </div>
                {comparisonResult && (
                  <div
                    style={{
                      padding: "12px 16px",
                      background:
                        comparisonResult.netChange > 0
                          ? "#fef2f2"
                          : comparisonResult.netChange < 0
                            ? "#f0fdf4"
                            : "#f9fafb",
                      borderRadius: 10,
                      borderLeft: `4px solid ${comparisonResult.netChange > 0 ? "#ef4444" : comparisonResult.netChange < 0 ? "#22c55e" : "#9ca3af"}`,
                      marginBottom: 12,
                      fontSize: 13,
                      color: "#374151",
                    }}
                  >
                    <strong
                      style={{
                        color:
                          comparisonResult.netChange > 0
                            ? "#dc2626"
                            : comparisonResult.netChange < 0
                              ? "#15803d"
                              : "#6b7280",
                      }}
                    >
                      {comparisonResult.netChange > 0
                        ? `+${comparisonResult.netChange} new findings`
                        : comparisonResult.netChange < 0
                          ? `${comparisonResult.netChange} findings resolved`
                          : "No net change"}
                    </strong>{" "}
                    —{" "}
                    <strong style={{ color: "#dc2626" }}>
                      {comparisonResult.regressions.length} regressions
                    </strong>
                    ,{" "}
                    <strong style={{ color: "#15803d" }}>
                      {comparisonResult.improvements.length} improvements
                    </strong>
                    ,{" "}
                    <strong>
                      {comparisonResult.changedObjects.length} objects changed
                    </strong>
                    .
                  </div>
                )}
              </div>
              <div
                style={{
                  flex: 1,
                  overflowY: "auto",
                  padding: "0 20px 20px 20px",
                }}
              >
                {(compareFindingsLoading || findingsLoading) && (
                  <div
                    style={{
                      textAlign: "center",
                      padding: 32,
                      color: "#6b7280",
                      fontSize: 13,
                    }}
                  >
                    Loading findings for comparison...
                  </div>
                )}
                {!compareFindingsLoading &&
                  !findingsLoading &&
                  !comparisonResult && (
                    <div
                      style={{
                        textAlign: "center",
                        padding: 32,
                        color: "#9ca3af",
                        fontSize: 13,
                      }}
                    >
                      Findings not yet loaded for one or both runs.
                    </div>
                  )}
                {comparisonResult && (
                  <>
                    {/* Regressions */}
                    <div style={{ marginBottom: 24 }}>
                      <div
                        style={{
                          fontSize: 10,
                          fontWeight: 700,
                          color: "#dc2626",
                          letterSpacing: 1,
                          textTransform: "uppercase",
                          marginBottom: 8,
                        }}
                      >
                        🔴 Regressions — New in B, not in A (
                        {comparisonResult.regressions.length})
                      </div>
                      {comparisonResult.regressions.length === 0 ? (
                        <div
                          style={{
                            padding: "12px 16px",
                            background: "#f0fdf4",
                            borderRadius: 8,
                            borderLeft: "4px solid #22c55e",
                            fontSize: 13,
                            color: "#15803d",
                            fontWeight: 600,
                          }}
                        >
                          ✅ No regressions — Run B has no new findings vs
                          baseline.
                        </div>
                      ) : (
                        comparisonResult.regressions
                          .slice(0, 50)
                          .map((f, i) => {
                            const pColor =
                              f.Priority === 1
                                ? "#ef4444"
                                : f.Priority === 2
                                  ? "#f59e0b"
                                  : f.Priority === 3
                                    ? "#3b82f6"
                                    : "#6b7280";
                            const pBg =
                              f.Priority === 1
                                ? "#fee2e2"
                                : f.Priority === 2
                                  ? "#fef3c7"
                                  : f.Priority === 3
                                    ? "#dbeafe"
                                    : "#f3f4f6";
                            return (
                              <div
                                key={i}
                                style={{
                                  border: "1px solid #fecaca",
                                  borderLeft: "4px solid #ef4444",
                                  borderRadius: 8,
                                  padding: "10px 12px",
                                  marginBottom: 8,
                                  background: "#fff8f8",
                                }}
                              >
                                <div
                                  style={{
                                    display: "flex",
                                    justifyContent: "space-between",
                                    alignItems: "flex-start",
                                  }}
                                >
                                  <span
                                    style={{
                                      fontWeight: 700,
                                      fontSize: 12,
                                      color: "#111827",
                                      wordBreak: "break-all",
                                      flex: 1,
                                      marginRight: 8,
                                    }}
                                  >
                                    {f.ObjectName || "—"}
                                  </span>
                                  <span
                                    style={{
                                      background: pBg,
                                      color: pColor,
                                      borderRadius: 999,
                                      padding: "2px 7px",
                                      fontSize: 11,
                                      fontWeight: 700,
                                      flexShrink: 0,
                                    }}
                                  >
                                    P{f.Priority}
                                  </span>
                                </div>
                                <div
                                  style={{
                                    fontSize: 11,
                                    color: "#6b7280",
                                    marginTop: 3,
                                  }}
                                >
                                  {resolveCheckCategory(f)} ·{" "}
                                  {OBJECT_TYPE_LABELS[f.ObjectType] ||
                                    f.ObjectType ||
                                    "—"}{" "}
                                  · {f.PackageName || "—"}
                                </div>
                              </div>
                            );
                          })
                      )}
                      {comparisonResult.regressions.length > 50 && (
                        <div
                          style={{
                            fontSize: 11,
                            color: "#9ca3af",
                            textAlign: "center",
                            padding: "8px 0",
                          }}
                        >
                          +{comparisonResult.regressions.length - 50} more
                          regressions not shown
                        </div>
                      )}
                    </div>
                    {/* Improvements */}
                    <div style={{ marginBottom: 24 }}>
                      <div
                        style={{
                          fontSize: 10,
                          fontWeight: 700,
                          color: "#15803d",
                          letterSpacing: 1,
                          textTransform: "uppercase",
                          marginBottom: 8,
                        }}
                      >
                        🟢 Improvements — In A, resolved in B (
                        {comparisonResult.improvements.length})
                      </div>
                      {comparisonResult.improvements.length === 0 ? (
                        <div
                          style={{
                            padding: "12px 16px",
                            background: "#fef2f2",
                            borderRadius: 8,
                            borderLeft: "4px solid #ef4444",
                            fontSize: 13,
                            color: "#dc2626",
                            fontWeight: 600,
                          }}
                        >
                          No improvements — Run B did not resolve any findings
                          from baseline.
                        </div>
                      ) : (
                        comparisonResult.improvements
                          .slice(0, 50)
                          .map((f, i) => {
                            const pColor =
                              f.Priority === 1
                                ? "#ef4444"
                                : f.Priority === 2
                                  ? "#f59e0b"
                                  : f.Priority === 3
                                    ? "#3b82f6"
                                    : "#6b7280";
                            const pBg =
                              f.Priority === 1
                                ? "#fee2e2"
                                : f.Priority === 2
                                  ? "#fef3c7"
                                  : f.Priority === 3
                                    ? "#dbeafe"
                                    : "#f3f4f6";
                            return (
                              <div
                                key={i}
                                style={{
                                  border: "1px solid #bbf7d0",
                                  borderLeft: "4px solid #22c55e",
                                  borderRadius: 8,
                                  padding: "10px 12px",
                                  marginBottom: 8,
                                  background: "#f8fff8",
                                }}
                              >
                                <div
                                  style={{
                                    display: "flex",
                                    justifyContent: "space-between",
                                    alignItems: "flex-start",
                                  }}
                                >
                                  <span
                                    style={{
                                      fontWeight: 700,
                                      fontSize: 12,
                                      color: "#111827",
                                      wordBreak: "break-all",
                                      flex: 1,
                                      marginRight: 8,
                                    }}
                                  >
                                    {f.ObjectName || "—"}
                                  </span>
                                  <span
                                    style={{
                                      background: pBg,
                                      color: pColor,
                                      borderRadius: 999,
                                      padding: "2px 7px",
                                      fontSize: 11,
                                      fontWeight: 700,
                                      flexShrink: 0,
                                    }}
                                  >
                                    P{f.Priority}
                                  </span>
                                </div>
                                <div
                                  style={{
                                    fontSize: 11,
                                    color: "#6b7280",
                                    marginTop: 3,
                                  }}
                                >
                                  {resolveCheckCategory(f)} ·{" "}
                                  {OBJECT_TYPE_LABELS[f.ObjectType] ||
                                    f.ObjectType ||
                                    "—"}
                                </div>
                              </div>
                            );
                          })
                      )}
                    </div>
                    {/* Changed Objects */}
                    <div>
                      <div
                        style={{
                          fontSize: 10,
                          fontWeight: 700,
                          color: "#7c3aed",
                          letterSpacing: 1,
                          textTransform: "uppercase",
                          marginBottom: 8,
                        }}
                      >
                        📊 Changed Objects (
                        {comparisonResult.changedObjects.length})
                      </div>
                      {comparisonResult.changedObjects.length === 0 ? (
                        <div
                          style={{
                            padding: "12px 16px",
                            background: "#f9fafb",
                            borderRadius: 8,
                            border: "1px solid #e5e7eb",
                            fontSize: 13,
                            color: "#6b7280",
                          }}
                        >
                          No objects with changed finding counts.
                        </div>
                      ) : (
                        <div style={{ overflowX: "auto" }}>
                          <table
                            style={{
                              width: "100%",
                              borderCollapse: "collapse",
                            }}
                          >
                            <thead
                              style={{
                                background: "#f8fafc",
                                borderBottom: "2px solid #e5e7eb",
                              }}
                            >
                              <tr>
                                <th
                                  style={{
                                    padding: "10px 14px",
                                    fontSize: 10,
                                    fontWeight: 700,
                                    color: "#6b7280",
                                    textTransform: "uppercase",
                                    letterSpacing: "0.6px",
                                    textAlign: "left",
                                  }}
                                >
                                  Object
                                </th>
                                <th
                                  style={{
                                    padding: "10px 14px",
                                    fontSize: 10,
                                    fontWeight: 700,
                                    color: "#6b7280",
                                    textTransform: "uppercase",
                                    letterSpacing: "0.6px",
                                    textAlign: "right",
                                  }}
                                >
                                  Baseline (A)
                                </th>
                                <th
                                  style={{
                                    padding: "10px 14px",
                                    fontSize: 10,
                                    fontWeight: 700,
                                    color: "#6b7280",
                                    textTransform: "uppercase",
                                    letterSpacing: "0.6px",
                                    textAlign: "right",
                                  }}
                                >
                                  Compare (B)
                                </th>
                                <th
                                  style={{
                                    padding: "10px 14px",
                                    fontSize: 10,
                                    fontWeight: 700,
                                    color: "#6b7280",
                                    textTransform: "uppercase",
                                    letterSpacing: "0.6px",
                                    textAlign: "right",
                                  }}
                                >
                                  Delta
                                </th>
                              </tr>
                            </thead>
                            <tbody>
                              {comparisonResult.changedObjects
                                .slice(0, 30)
                                .map((obj, i) => (
                                  <tr
                                    key={i}
                                    style={{
                                      background: obj.worse
                                        ? "#fff8f8"
                                        : "#f8fff8",
                                    }}
                                  >
                                    <td
                                      style={{
                                        padding: "10px 14px",
                                        fontSize: 12,
                                        fontFamily: "monospace",
                                        fontWeight: 600,
                                        color: "#111827",
                                        wordBreak: "break-all",
                                      }}
                                    >
                                      {obj.name}
                                    </td>
                                    <td
                                      style={{
                                        padding: "10px 14px",
                                        fontSize: 12,
                                        textAlign: "right",
                                      }}
                                    >
                                      {obj.basTotal}
                                    </td>
                                    <td
                                      style={{
                                        padding: "10px 14px",
                                        fontSize: 12,
                                        textAlign: "right",
                                      }}
                                    >
                                      {obj.cmpTotal}
                                    </td>
                                    <td
                                      style={{
                                        padding: "10px 14px",
                                        textAlign: "right",
                                      }}
                                    >
                                      <span
                                        style={{
                                          background: obj.worse
                                            ? "#fee2e2"
                                            : "#dcfce7",
                                          color: obj.worse
                                            ? "#dc2626"
                                            : "#15803d",
                                          borderRadius: 999,
                                          padding: "2px 8px",
                                          fontSize: 11,
                                          fontWeight: 700,
                                        }}
                                      >
                                        {obj.delta > 0
                                          ? `+${obj.delta}`
                                          : obj.delta}
                                      </span>
                                    </td>
                                  </tr>
                                ))}
                            </tbody>
                          </table>
                        </div>
                      )}
                    </div>
                  </>
                )}
              </div>
            </div>
          </div>
        )}
      </div>
      {/* closes .container */}

      {/* ── AI PANEL ── */}
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
              width: "min(800px,100vw)",
              height: "100vh",
              background: "var(--card-bg,#ffffff)",
              boxShadow: "-4px 0 32px rgba(0,0,0,0.18)",
              display: "flex",
              flexDirection: "column",
              padding: "20px 20px 16px 20px",
              boxSizing: "border-box",
              overflowX: "hidden",
            }}
          >
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
                <div style={{ fontSize: 11, color: "#6b7280", marginTop: 4 }}>
                  {filteredRuns.length} runs · {filters.period} days ·{" "}
                  {filters.system || "All systems"}
                </div>
              </div>
              <div
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: 8,
                  flexShrink: 0,
                }}
              >
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
                        setAiView(v);
                        setAiMessages([]);
                        setAiLoading(true);
                        const snap = {
                          runs: filteredRuns,
                          p1: totalP1,
                          p2: totalP2,
                          p3: totalP3,
                          score: healthScore,
                          period: filters.period,
                          system: filters.system,
                          totalRuns: filteredRuns.length,
                        };
                        setTimeout(() => {
                          try {
                            setAiMessages([
                              {
                                role: "assistant",
                                content: generateAiAnalysis(undefined, v, snap),
                              },
                            ]);
                          } catch {
                            setAiMessages([
                              {
                                role: "assistant",
                                content: "Analysis could not be completed.",
                              },
                            ]);
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
              {aiLoading && aiMessages.length === 0 && (
                <div
                  style={{ textAlign: "center", padding: 40, color: "#6b7280" }}
                >
                  <div style={{ fontSize: 32, marginBottom: 12 }}>🤖</div>
                  <div style={{ fontSize: 14 }}>
                    Analyzing {filteredRuns.length} ATC runs...
                  </div>
                </div>
              )}
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
                    {renderAiText(msg.content)}
                  </div>
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
                              `ATC AI Analysis\n${new Date().toLocaleString()}\nView: ${aiView}\n\n${msg.content}`,
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
                placeholder="Ask a follow-up question..."
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
