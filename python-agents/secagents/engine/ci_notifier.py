"""CI/CD notification: Slack webhooks and Jira ticket creation."""

from __future__ import annotations

import os

import httpx


class CINotifier:
    def __init__(self):
        self.slack_webhook = os.environ.get("SLACK_WEBHOOK_URL")
        self.jira_url = os.environ.get("JIRA_URL")
        self.jira_token = os.environ.get("JIRA_API_TOKEN")
        self.jira_project = os.environ.get("JIRA_PROJECT", "SEC")

    async def notify_slack(self, findings: list[dict], report_path: str) -> bool:
        if not self.slack_webhook:
            return False
        severity_counts: dict[str, int] = {}
        for f in findings:
            sev = f.get("severity", "info")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        icon = (
            "🔴"
            if severity_counts.get("critical")
            else "🟠"
            if severity_counts.get("high")
            else "🟢"
        )
        text = f"{icon} *SecAgents Scan Complete*\n"
        text += " | ".join(f"{k}: {v}" for k, v in severity_counts.items())
        text += f"\nReport: `{report_path}`"

        async with httpx.AsyncClient() as client:
            resp = await client.post(self.slack_webhook, json={"text": text})
            return resp.status_code == 200

    async def create_jira_tickets(self, findings: list[dict]) -> list[str]:
        if not self.jira_url or not self.jira_token:
            return []
        created = []
        async with httpx.AsyncClient() as client:
            for f in findings:
                if f.get("severity") not in ("critical", "high"):
                    continue
                issue = {
                    "fields": {
                        "project": {"key": self.jira_project},
                        "summary": f"[SecAgents] {f.get('title', 'Finding')}",
                        "description": f"Severity: {f.get('severity')}\nCVSS: {f.get('cvss', 'N/A')}\n\n{f.get('summary', '')}",
                        "issuetype": {"name": "Bug"},
                        "priority": {
                            "name": "Highest" if f.get("severity") == "critical" else "High"
                        },
                    }
                }
                resp = await client.post(
                    f"{self.jira_url}/rest/api/2/issue",
                    json=issue,
                    headers={
                        "Authorization": f"Bearer {self.jira_token}",
                        "Content-Type": "application/json",
                    },
                )
                if resp.status_code == 201:
                    created.append(resp.json().get("key", ""))
        return created

    @staticmethod
    def exit_code(findings: list[dict]) -> int:
        """CI exit code: 0=clean, 1=critical, 2=high."""
        severities = {f.get("severity") for f in findings}
        if "critical" in severities:
            return 1
        if "high" in severities:
            return 2
        return 0
