import React from "react";

type Props = {
  filters: any;
  setFilters: any;
  onApply: () => void;
};

export default function FilterPanel({ filters, setFilters, onApply }: Props) {
  return (
    <div className="bg-white border rounded-lg shadow-sm p-5 mb-6">

      {/* HEADER */}
      <div className="flex justify-between items-center mb-4">
        <h2 className="text-sm font-semibold text-gray-600 tracking-wide">
          FILTER RUNS
        </h2>
        <span className="text-sm text-gray-400 cursor-pointer">⌃ collapse</span>
      </div>

      {/* MAIN GRID */}
      <div className="grid grid-cols-7 gap-4">

        {/* SYSTEM GROUP */}
        <Field label="SYSTEM GROUP">
          <input
            placeholder="e.g. PROD_GRP"
            className="input"
            onChange={(e) =>
              setFilters({ ...filters, system: e.target.value })
            }
          />
        </Field>

        {/* RUN SERIES */}
        <Field label="RUN SERIES">
          <input
            placeholder="DBB*"
            className="input"
            onChange={(e) =>
              setFilters({ ...filters, series: e.target.value })
            }
          />
        </Field>

        {/* CHECK TITLE */}
        <Field label="CHECK RUN TITLE">
          <input placeholder="e.g. Nightly" className="input" />
        </Field>

        {/* SCHEDULED BY */}
        <Field label="SCHEDULED BY">
          <input
            placeholder="e.g. BATCHUSER"
            className="input"
            onChange={(e) =>
              setFilters({ ...filters, user: e.target.value })
            }
          />
        </Field>

        {/* DATE FROM */}
        <Field label="DATE FROM">
          <input
            type="date"
            className="input"
            onChange={(e) =>
              setFilters({ ...filters, from: e.target.value })
            }
          />
        </Field>

        {/* DATE TO */}
        <Field label="DATE TO">
          <input
            type="date"
            className="input"
            onChange={(e) =>
              setFilters({ ...filters, to: e.target.value })
            }
          />
        </Field>

        {/* PERIOD */}
        <Field label="PERIOD (DAYS)">
          <input type="number" defaultValue={7} className="input" />
        </Field>
      </div>

      {/* SECOND ROW */}
      <div className="grid grid-cols-2 gap-8 mt-6">

        {/* SCHEDULE DATA */}
        <div>
          <label className="section-label">SCHEDULE DATA</label>
          <div className="flex gap-6 mt-2">
            <Radio name="schedule" label="By Period" defaultChecked />
            <Radio name="schedule" label="By Date" />
          </div>
        </div>

        {/* RESULT VISIBILITY */}
        <div>
          <label className="section-label">RESULT VISIBILITY</label>
          <div className="flex flex-wrap gap-6 mt-2 items-center">
            <Radio name="visibility" label="Central Only" />
            <Radio name="visibility" label="Not Central" />
            <Radio name="visibility" label="Any" defaultChecked />

            <label className="flex items-center gap-2">
              <input type="checkbox" />
              <span>Only Results in Baseline</span>
            </label>
          </div>
        </div>
      </div>

      {/* ACTIONS */}
      <div className="flex items-center gap-3 mt-6">
        <button
          onClick={onApply}
          className="bg-blue-600 text-white px-6 py-2 rounded-md font-medium hover:bg-blue-700"
        >
          GO
        </button>

        <button className="bg-gray-100 px-5 py-2 rounded-md text-gray-600 font-medium">
          Adapt Filters (12)
        </button>

        <button className="bg-indigo-100 text-indigo-600 px-5 py-2 rounded-md font-medium">
          ✨ AI Analysis
        </button>
      </div>
    </div>
  );
}

/* ---------- SMALL COMPONENTS ---------- */

function Field({ label, children }: any) {
  return (
    <div className="flex flex-col text-sm">
      <label className="text-gray-500 mb-1 font-medium">{label}</label>
      {children}
    </div>
  );
}

function Radio({ name, label, defaultChecked = false }: any) {
  return (
    <label className="flex items-center gap-2">
      <input type="radio" name={name} defaultChecked={defaultChecked} />
      <span>{label}</span>
    </label>
  );
}