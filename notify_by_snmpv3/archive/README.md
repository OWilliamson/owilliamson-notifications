# Archived SNMPv3 notification scripts

These files are older or broken attempts. The active scripts are in the parent directory.

## Why these were archived

### Python

| File | Reason |
|------|--------|
| `snmpv3_trap_send_2.py` | Bug: `obj_identity = obj_identity(oid)` (undefined); var-bind values not wrapped in OctetString/Integer. Uses deprecated synchronous pysnmp API. |
| `snmpv3_trap_send_3.py` | Duplicate of `snmpv3_trap_send.py` (identical implementation). |
| `snmpv3_trap_send_4.py` | Bug in `validate_resolved_oid`: `oid_str` may be undefined in the except block. Otherwise same as `snmpv3_trap_send.py`. |
| `snmpv3_trap_send_dev.py` | Experimental multi-version (v1/v2c/v3) script; has transport API bug `UdpTransportTarget.create((target_ip, target_port))` (should be two arguments). Kept for reference if multi-version support is needed later. |

### Perl

| File | Reason |
|------|--------|
| `notify_by_snmp_v3_new.pl` | Uses `inform_request` for SNMPv3 (informs are request/response, not fire-and-forget traps). Wrong OID for snmpTrapOID (`1.3.6.1.2.1.2.2.1.0`). Debug-style output. |
| `notify_by_snmp_v3_new_2.pl` | Uses `snmpv2_trap` for SNMPv3 (wrong method; should use `snmpv3_trap`). Debug-style output. |

## Active scripts (parent directory)

- **notify_by_snmp_v3.pl** – OP5 (ITRS OP5 Monitor) / Nagios-style notification script; sends SNMPv3 traps using NAGIOS-NOTIFY-MIB and `snmpv3_trap`.
- **snmpv3_trap_send.py** – Generic SNMPv3 trap sender (CLI); asyncio pysnmp v3arch, supports numeric and symbolic OIDs, correct var-bind types.
