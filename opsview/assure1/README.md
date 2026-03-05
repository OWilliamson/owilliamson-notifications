# Assure1 notification (Opsview)

Sends Opsview host and service alerts to **Assure1** (or a compatible API). Builds a JSON payload from Opsview or Nagios environment variables and POSTs it to a configurable URL.

- **notify_by_assure1** – Perl script: uses Opsview::Config::Notifications and Opsview::Schema, builds message from `OPSVIEW_*` or `NAGIOS_*` env vars, and POSTs to the Assure1 endpoint (configurable or overridden with `-u`). Supports debug mode and optional test payload output.
