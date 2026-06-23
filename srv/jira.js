const required = (value, name) => {
  if (!value || !String(value).trim()) {
    throw new Error(`${name} is required`);
  }
  return String(value).trim();
};

const trimBaseUrl = (value) => required(value, "JIRA_BASE_URL").replace(/\/+$/, "");

const parseLabels = (value) =>
  String(value || "")
    .split(",")
    .map((label) =>
      label
        .trim()
        .toLowerCase()
        .replace(/[^a-z0-9-_]/g, "-")
        .replace(/-+/g, "-")
        .replace(/^-|-$/g, ""),
    )
    .filter(Boolean)
    .slice(0, 20);

const textNode = (text) => ({
  type: "text",
  text,
});

const paragraph = (text) => ({
  type: "paragraph",
  content: text ? [textNode(text)] : [],
});

const toAdf = (text) => {
  const lines = String(text || "")
    .replace(/\r\n/g, "\n")
    .split("\n")
    .map((line) => line.trimEnd());

  return {
    type: "doc",
    version: 1,
    content: lines.length ? lines.map(paragraph) : [paragraph("")],
  };
};

const buildIssueFields = (input) => {
  const projectKey = required(input.projectKey, "projectKey");
  const summary = required(input.summary, "summary").slice(0, 255);
  const issueType = input.issueType || process.env.JIRA_DEFAULT_ISSUE_TYPE || "Task";
  const labels = parseLabels(input.labels || "atc,atc-monitor");

  const fields = {
    project: { key: projectKey },
    issuetype: { name: issueType },
    summary,
    description: toAdf(input.description || ""),
    labels,
  };

  if (input.priorityName) {
    fields.priority = { name: String(input.priorityName).trim() };
  }

  if (input.assigneeAccountId) {
    fields.assignee = { accountId: String(input.assigneeAccountId).trim() };
  }

  return fields;
};

const readErrorBody = async (response) => {
  const text = await response.text();
  if (!text) return `HTTP ${response.status}`;
  try {
    const json = JSON.parse(text);
    const messages = [
      ...(json.errorMessages || []),
      ...Object.values(json.errors || {}),
    ].filter(Boolean);
    return messages.length ? messages.join(" | ") : text;
  } catch {
    return text;
  }
};

const createJiraIssue = async (input) => {
  const baseUrl = trimBaseUrl(process.env.JIRA_BASE_URL);
  const email = required(process.env.JIRA_EMAIL, "JIRA_EMAIL");
  const token = required(process.env.JIRA_API_TOKEN, "JIRA_API_TOKEN");
  const fields = buildIssueFields(input);

  const response = await fetch(`${baseUrl}/rest/api/3/issue`, {
    method: "POST",
    headers: {
      Accept: "application/json",
      Authorization: `Basic ${Buffer.from(`${email}:${token}`).toString("base64")}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ fields }),
  });

  if (!response.ok) {
    throw new Error(`Jira issue creation failed: ${await readErrorBody(response)}`);
  }

  const issue = await response.json();
  return {
    ok: true,
    issueId: issue.id || "",
    issueKey: issue.key || "",
    issueUrl: issue.key ? `${baseUrl}/browse/${issue.key}` : issue.self || "",
    message: "Jira issue created.",
  };
};

module.exports = {
  createJiraIssue,
};
