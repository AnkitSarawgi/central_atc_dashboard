<div align="center">
<img width="1200" height="475" alt="GHBanner" src="https://github.com/user-attachments/assets/0aa67016-6eaf-458a-adb2-6e31a0763ed6" />
</div>

# Run and deploy your AI Studio app

This contains everything you need to run your app locally.

View your app in AI Studio: https://ai.studio/apps/556121a5-757e-4a13-9355-47d6d800f266

## Run Locally

**Prerequisites:**  Node.js


1. Install dependencies:
   `npm install`
2. Set the `GEMINI_API_KEY` in [.env.local](.env.local) to your Gemini API key
3. Run the app:
   `npm run dev`

## Jira integration

Jira ticket creation runs through the CAP service, not from the browser. Set `JIRA_BASE_URL`, `JIRA_EMAIL`, `JIRA_API_TOKEN`, and optionally `JIRA_DEFAULT_ISSUE_TYPE` in the service environment.

In the app admin data, keep `Products.JiraProjectKey` populated for each product. `IntegrationConfig` can contain non-secret values such as `GLOBAL / JiraBaseUrl`, `GLOBAL / JiraIssueType`, and comma-separated `GLOBAL / JiraLabels`.
