# SNMPv3 notification (OP5)

Sends monitoring notifications from **ITRS OP5 Monitor** as SNMP traps (v1, v2c, or v3) using the NAGIOS-NOTIFY-MIB. Supports host and service events and notifications (including acknowledgements) in the OP5/NAGIOS variable format.

**Active scripts**

- **notify_by_snmpv3.py** – Python implementation: builds NAGIOS-NOTIFY-MIB varbinds from `--type` and `--notification-var`, sends traps via pysnmp.
- **notify_by_snmp_v3.pl** – Perl script for OP5: reads OP5/NAGIOS environment variables and sends SNMPv3 traps using Net::SNMP (`snmpv3_trap`).

**archive/** – Older Perl and Python variants plus the standalone trap sender `snmpv3_trap_send.py`, kept for reference. See `archive/README.md` for details.
