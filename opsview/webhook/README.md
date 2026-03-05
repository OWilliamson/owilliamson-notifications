# Webhook notification (Opsview)

Sends Opsview alerts to an arbitrary HTTP **webhook** URL. Builds a JSON payload from Opsview or Nagios environment variables and POSTs it to the configured endpoint (e.g. for Slack, PagerDuty, or custom integrations).

- **notify_by_webhook** – Perl script: uses Opsview::Config::Notifications and Opsview::Schema, builds message from `OPSVIEW_*` or `NAGIOS_*` env vars, and sends the payload to the URL (configurable or overridden with `-u`).
