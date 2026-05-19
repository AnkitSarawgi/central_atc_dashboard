export const LABELS14 = ['Apr 10','Apr 11','Apr 12','Apr 13','Apr 14','Apr 15','Apr 16','Apr 17','Apr 18','Apr 19','Apr 20','Apr 21','Apr 22','Apr 23'];
export const ERR14 = [18,22,19,27,35,20,12,49,35,8,22,45,31,28];
export const WRN14 = [72,85,68,91,110,75,50,114,95,14,79,120,88,91];
export const INF14 = [30,44,28,55,68,40,22,192,60,6,38,73,52,44];

export const TREND_DATA = LABELS14.map((label, i) => ({
  date: label,
  p1: ERR14[i],
  p2: WRN14[i],
  p3: INF14[i],
}));

export const RUN_SERIES_DATA = [
  { name: 'DBB_DAILY', value: 620 },
  { name: 'DBB_WEEKLY', value: 238 },
  { name: 'DBB_RELEASE', value: 355 },
  { name: 'DBB_PERF', value: 95 },
  { name: 'DBB_HOTFIX', value: 28 },
];

export const QUALITY_TREND = [
  { date: 'Apr 17', score: 80 },
  { date: 'Apr 18', score: 76 },
  { date: 'Apr 19', score: 82 },
  { date: 'Apr 20', score: 78 },
  { date: 'Apr 21', score: 75 },
  { date: 'Apr 22', score: 73 },
  { date: 'Apr 23', score: 72 },
];

export const RADAR_DATA = [
  { subject: 'Performance', A: 85, fullMark: 100 },
  { subject: 'Security', A: 54, fullMark: 100 },
  { subject: 'Naming', A: 32, fullMark: 100 },
  { subject: 'Dead Code', A: 38, fullMark: 100 },
  { subject: 'SQL', A: 68, fullMark: 100 },
  { subject: 'Style', A: 28, fullMark: 100 },
];

export const SLA_DATA = [
  { name: '0–7 days', value: 312 },
  { name: '8–30 days', value: 198 },
  { name: '31–90 days', value: 95 },
  { name: '90+ days', value: 48 },
];

export const SCHED_DATA = [
  { day: 'Mon', planned: 6, actual: 6 },
  { day: 'Tue', planned: 6, actual: 7 },
  { day: 'Wed', planned: 6, actual: 5 },
  { day: 'Thu', planned: 6, actual: 6 },
  { day: 'Fri', planned: 6, actual: 8 },
  { day: 'Sat', planned: 2, actual: 2 },
  { day: 'Sun', planned: 2, actual: 1 },
];

export const RUNS = [
  { s: 'DBB_DAILY', t: 'Daily Nightly Check', by: 'ATCUSER', dt: '2026-04-23', p1: 28, p2: 91, p3: 44, central: true, dur: '4m 12s' },
  { s: 'DBB_DAILY', t: 'Daily Nightly Check', by: 'ATCUSER', dt: '2026-04-22', p1: 31, p2: 88, p3: 52, central: true, dur: '4m 08s' },
  { s: 'DBB_WEEKLY', t: 'Full Code Scan', by: 'BATCHJOB', dt: '2026-04-21', p1: 45, p2: 120, p3: 73, central: true, dur: '18m 34s' },
  { s: 'DBB_DAILY', t: 'Daily Nightly Check', by: 'ATCUSER', dt: '2026-04-20', p1: 22, p2: 79, p3: 38, central: false, dur: '4m 01s' },
  { s: 'DBB_HOTFIX', t: 'Hotfix Validation', by: 'DEVUSER1', dt: '2026-04-19', p1: 8, p2: 14, p3: 6, central: false, dur: '1m 58s' },
  { s: 'DBB_DAILY', t: 'Daily Nightly Check', by: 'ATCUSER', dt: '2026-04-18', p1: 35, p2: 95, p3: 60, central: true, dur: '4m 22s' },
  { s: 'DBB_RELEASE', t: 'Pre-Release Gate', by: 'RELMANAGER', dt: '2026-04-17', p1: 49, p2: 114, p3: 192, central: true, dur: '22m 10s' },
  { s: 'DBB_DAILY', t: 'Daily Nightly Check', by: 'ATCUSER', dt: '2026-04-16', p1: 12, p2: 50, p3: 22, central: true, dur: '3m 48s' },
  { s: 'DBB_PERF', t: 'Performance Scan', by: 'PERFBOT', dt: '2026-04-15', p1: 20, p2: 75, p3: 40, central: false, dur: '9m 05s' },
  { s: 'DBB_DAILY', t: 'Daily Nightly Check', by: 'ATCUSER', dt: '2026-04-14', p1: 35, p2: 110, p3: 68, central: true, dur: '4m 17s' },
];

export const CATS = [
  { n: 'Performance', v: 312, c: '#E24B4A' },
  { n: 'Naming Conv.', v: 287, c: '#EF9F27' },
  { n: 'Security', v: 198, c: '#378ADD' },
  { n: 'Dead Code', v: 145, c: '#888780' },
  { n: 'Code Style', v: 128, c: '#7F77DD' },
  { n: 'SQL Tuning', v: 89, c: '#1D9E75' },
];

export const OBJS = [
  { n: 'Z_PERF_MONITOR', v: 48, c: '#E24B4A' },
  { n: 'ZCL_DATA_PROC', v: 41, c: '#E24B4A' },
  { n: 'Z_REPORT_GEN', v: 35, c: '#EF9F27' },
  { n: 'ZIF_CONNECTOR', v: 29, c: '#EF9F27' },
  { n: 'Z_BATCH_JOB', v: 22, c: '#378ADD' },
];

export const ALERTS = [
  { lvl: 'err', msg: 'Critical P1 spike: DBB_RELEASE exceeded threshold (+49 errors)', time: 'Today 02:14' },
  { lvl: 'warn', msg: 'Run DBB_WEEKLY exceeded SLA duration (18m vs 10m target)', time: 'Today 00:31' },
  { lvl: 'warn', msg: 'Security check package: 12 new vulnerabilities since last baseline', time: 'Yesterday 23:55' },
  { lvl: 'info', msg: '3 consecutive clean runs achieved on DBB_HOTFIX series', time: 'Apr 19' },
];

export const SLAS = [
  { lbl: 'P1 Critical', target: '24h', actual: '31h', pct: 72, c: '#E24B4A' },
  { lbl: 'P2 Warning', target: '72h', actual: '58h', pct: 88, c: '#EF9F27' },
  { lbl: 'P3 Info', target: '14d', actual: '9d', pct: 95, c: '#378ADD' },
  { lbl: 'P4 Note', target: '30d', actual: '12d', pct: 99, c: '#888780' },
];

export const MOCK_FINDINGS = [
  { id: 'F01', priority: 'P1', rule: 'DB Operations in Loops', object: 'ZCL_DATA_PROC', line: 142, message: 'SELECT statement found inside a LOOP without bulk processing. This causes severe performance degradation.', snippet: 'LOOP AT lt_items INTO ls_item.\n  SELECT SINGLE * FROM mara INTO ls_mara WHERE matnr = ls_item-matnr.\nENDLOOP.' },
  { id: 'F02', priority: 'P1', rule: 'Potential SQL Injection', object: 'Z_REPORT_GEN', line: 45, message: 'Dynamic WHERE condition is vulnerable to SQL injection if input is not sanitized.', snippet: 'DATA: lv_where TYPE string.\nlv_where = |UNAME = \'| && p_user && |\'|.\nSELECT * FROM usr02 INTO TABLE @DATA(lt_users) WHERE (lv_where).' },
  { id: 'F03', priority: 'P2', rule: 'Naming Conventions', object: 'ZIF_CONNECTOR', line: 12, message: 'Interface parameter does not follow standard SAP naming convention (expected prefix "IT_").', snippet: 'METHODS: get_data\n  IMPORTING\n    data_table TYPE STANDARD TABLE.' },
  { id: 'F04', priority: 'P2', rule: 'Missing sy-subrc Check', object: 'Z_PERF_MONITOR', line: 88, message: 'Missing evaluation of sy-subrc after database operation. Can lead to unexpected behavior.', snippet: 'UPDATE zperf_log SET status = \'X\' WHERE id = lv_id.\n\n* Execution continues without checking if update succeeded\nPERFORM aggregate_results.' },
  { id: 'F05', priority: 'P3', rule: 'Dead Code', object: 'Z_BATCH_JOB', line: 312, message: 'Variable lv_counter is declared but never used.', snippet: 'DATA: lv_counter TYPE i,\n      lv_timestamp TYPE timestamp.\n\nGET TIME STAMP FIELD lv_timestamp.' }
];
