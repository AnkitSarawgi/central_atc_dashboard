const cds = require("@sap/cds");
const { SELECT } = cds.ql;
const { createJiraIssue } = require("./jira");

const Runs = 'atc_Run';

const getFilterVal = (where, field) => {
  if (!where) return null;
  const idx = where.findIndex((w) => w?.ref?.[0] === field);
  return idx !== -1 ? (where[idx + 2]?.val ?? null) : null;
};

const buildQuery = (entity, where) => {
  let q = SELECT.from(entity);
  const system = getFilterVal(where, "system");
  const user   = getFilterVal(where, "user");
  const series = getFilterVal(where, "series");
  if (system) q = q.where({ system });
  if (user)   q = q.where({ user });
  if (series) q = q.where({ series });
  return q;
};

module.exports = cds.service.impl(function () {

  this.on("raiseJiraTicket", async (req) => {
    try {
      return await createJiraIssue(req.data || {});
    } catch (err) {
      req.error(502, err.message);
    }
  });

  this.on("READ", "Runs", async (req) => {
    try {
      return await buildQuery(Runs, req.query?.SELECT?.where);
    } catch (err) {
      req.error(500, `Failed to read Runs: ${err.message}`);
    }
  });

  this.on("READ", "Trend", async (req) => {
    try {
      const data = await buildQuery(Runs, req.query?.SELECT?.where);
      return data.map((r) => ({ date: r.date, p1: r.p1, p2: r.p2, p3: r.p3 }));
    } catch (err) {
      req.error(500, `Failed to read Trend: ${err.message}`);
    }
  });

  this.on("READ", "OverviewKPI", async (req) => {
    try {
      const data = await buildQuery(Runs, req.query?.SELECT?.where);
      const p1 = data.reduce((a, b) => a + (b.p1 || 0), 0);
      const p2 = data.reduce((a, b) => a + (b.p2 || 0), 0);
      const p3 = data.reduce((a, b) => a + (b.p3 || 0), 0);
      const total = p1 + p2 + p3;
      const health = total === 0
        ? 100
        : Math.max(0, Math.round(100 - ((p1 * 3 + p2 * 1.5) / total) * 10));
      return [{ ID: cds.utils.uuid(), p1, p2, p3, health }];
    } catch (err) {
      req.error(500, `Failed to read OverviewKPI: ${err.message}`);
    }
  });

  this.on("READ", "CategoryStats", async (req) => {
    try {
      const data = await buildQuery(Runs, req.query?.SELECT?.where);
      return [
        { name: "Performance", value: data.filter((d) => d.p1 > 0).length },
        { name: "Security",    value: data.filter((d) => d.p2 > 0).length },
        { name: "Naming",      value: data.filter((d) => d.p3 > 0).length },
      ];
    } catch (err) {
      req.error(500, `Failed to read CategoryStats: ${err.message}`);
    }
  });

  this.on("READ", "RunSeriesStats", async (req) => {
    try {
      const data = await buildQuery(Runs, req.query?.SELECT?.where);
      const map = {};
      data.forEach((d) => { map[d.series] = (map[d.series] || 0) + 1; });
      return Object.keys(map).map((k) => ({ name: k, value: map[k] }));
    } catch (err) {
      req.error(500, `Failed to read RunSeriesStats: ${err.message}`);
    }
  });

  this.on("READ", "QualityTrend", async (req) => {
    try {
      const data = await buildQuery(Runs, req.query?.SELECT?.where);
      return data.map((r) => ({ date: r.date, score: r.p3 }));
    } catch (err) {
      req.error(500, `Failed to read QualityTrend: ${err.message}`);
    }
  });

  this.on("READ", "Heatmap", async (req) => {
    try {
      const data = await buildQuery(Runs, req.query?.SELECT?.where);
      return data.map((r) => ({
        ID:    cds.utils.uuid(),
        value: (r.p1 || 0) * 10 + (r.p2 || 0) * 3 + (r.p3 || 0),
      }));
    } catch (err) {
      req.error(500, `Failed to read Heatmap: ${err.message}`);
    }
  });

  this.on("READ", "Radar", () => [
    { subject: "Security",    value: 8 },
    { subject: "Performance", value: 6 },
    { subject: "Syntax",      value: 7 },
    { subject: "SQL",         value: 5 },
    { subject: "Robustness",  value: 9 },
  ]);

  this.on("READ", "SLA", () => [
    { name: "0-7 days",  value: 10 },
    { name: "8-30 days", value: 20 },
    { name: "30+ days",  value: 5  },
  ]);
});
