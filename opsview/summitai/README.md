# Summit AI notification (Opsview)

Integrates Opsview with **Summit AI** (ticketing/incident management). Sends host and service alerts as incidents, with optional acknowledgements and state sync.

- **notify_by_summitai** – Main notification script: reads Opsview/NAGIOS env vars and config, creates/updates Summit tickets, can send acknowledgements.
- **notify_by_summitai_debug** – Debug variant with extra logging and diagnostics for development and troubleshooting.
- **submit_to_summit.py** – Example/skeleton script showing the Summit API payload format (Classification "Opsview Event", Source "Opsview") for building incident JSON.
