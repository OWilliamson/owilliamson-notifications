# BMC Remedy notification (Opsview)

Sends Opsview host and service alerts to **BMC Remedy** (or a Remedy-style API). Builds messages from Opsview (BSM) or Nagios-style environment variables and submits them to a configurable Remedy endpoint.

- **notify_by_remedy** – Python script: reads `OPSVIEW_*` or `NAGIOS_*` env vars, formats the notification message, and POSTs to the Remedy URL (e.g. for incident creation).
