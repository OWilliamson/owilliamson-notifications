#!/usr/bin/python3
"""SNMP trap sender (v1/v2c/v3) with OP5 notification mode (NAGIOS-NOTIFY-MIB)."""
# pyright: reportMissingImports=false, reportUndefinedVariable=false
# pylint: disable=wildcard-import,undefined-variable,import-error,duplicate-code,protected-access

import re
import sys
import argparse
import asyncio
import logging
import time
from ipaddress import ip_address
from pysnmp.hlapi.v3arch.asyncio import *  # noqa: F403,F401  # pylint: disable=import-error
from pysnmp.proto.rfc1902 import (  # pylint: disable=import-error
    Integer,
    IpAddress,
    OctetString,
    ObjectIdentifier,
    TimeTicks,
)
from pysnmp import debug  # pylint: disable=import-error
from pysnmp.smi import builder, view, compiler  # pylint: disable=import-error


# Initialize MIB components globally
mib_builder = builder.MibBuilder()
compiler.add_mib_compiler(mib_builder)
mib_view = view.MibViewController(mib_builder)

# Load essential MIBs
try:
    mib_builder.load_modules('SNMPv2-MIB')
except Exception:  # pylint: disable=broad-except
    pass  # Initialization will be finalized after logging setup

# Helper function to check if OID is numerical
def is_numerical_oid(oid_str):
    """Return True if oid_str is a dotted-decimal OID (e.g. 1.3.6.1.4.1)."""
    return re.match(r'^[0-9.]+$', oid_str) is not None


def is_hostname(host):
    """Return True if host is a valid hostname or IPv4 address (match Perl validation)."""
    if not host or not host.strip():
        return False
    host = host.strip()
    try:
        ip_address(host)
        return True
    except ValueError:
        pass
    # Hostname: letter then letters, digits, hyphens; optional dotted components
    return bool(re.match(r'^[a-zA-Z][-a-zA-Z0-9]*(\.[a-zA-Z][-a-zA-Z0-9]*)*$', host))

def setup_logging(debug_flag=False):
    """Configure logging to both console and file"""
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG if debug_flag else logging.INFO)

    if logger.handlers:
        for handler in logger.handlers[:]:
            logger.removeHandler(handler)

    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    if debug_flag:
        file_handler = logging.FileHandler('snmp_trap_debug.log')
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
        debug.set_logger(debug.Debug('io', 'msgproc', 'secmod'))

    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.DEBUG if debug_flag else logging.INFO)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    # Re-attempt MIB loading with logging available
    try:
        mib_builder.load_modules('SNMPv2-MIB')
    except Exception as e:  # pylint: disable=broad-except
        logger.warning("Failed to load MIB modules: %s", e)


def validate_resolved_oid(oid_identity, original_str):
    """Ensure OID is either resolved to numerical form or valid numerical format"""
    try:
        # First check if original input is numerical
        if is_numerical_oid(original_str):
            return

        # Attempt to get string representation
        try:
            oid_str = str(oid_identity)
        except Exception:  # pylint: disable=broad-except
            oid_str = None

        # Try resolution if needed
        if not oid_str or not is_numerical_oid(oid_str):
            oid_identity.resolve_with_mib(mib_view)
            oid_str = str(oid_identity)

        if not is_numerical_oid(oid_str):
            raise ValueError(f"OID {original_str} resolves to non-numerical {oid_str}")

    except Exception as e:  # pylint: disable=broad-except
        if not is_numerical_oid(original_str):
            raise ValueError(f"OID {original_str} could not be resolved to numerical form") from e

def resolve_oid(oid_str):
    """Handle both numerical and symbolic OIDs safely"""
    try:
        if '::' in oid_str:
            mib_name, symbol = oid_str.split('::', 1)
            obj_identity = ObjectIdentity(mib_name, symbol)
        else:
            obj_identity = ObjectIdentity(oid_str)

        validate_resolved_oid(obj_identity, oid_str)
        return obj_identity
    except Exception as e:  # pylint: disable=broad-except
        logging.error("Invalid OID format: %s - %s", oid_str, e)
        raise

# OP5 (ITRS OP5 Monitor) / NAGIOS-NOTIFY-MIB (numeric OIDs; see NAGIOS-ROOT-MIB + NAGIOS-NOTIFY-MIB)
# Base: nagios = { enterprises 20006 } = 1.3.6.1.4.1.20006; nagiosNotify = { nagios 1 } = 20006.1
# Trap types (NOTIFICATION-TYPE): nHostEvent=5, nHostNotify=6, nSvcEvent=7, nSvcNotify=8 under nagiosNotify
ENTERPRISE_OID = "1.3.6.1.4.1.20006.1"  # nagiosNotify (base for all suffixes below)
OP5_TRAP_OID_SUFFIXES = {"nHostEvent": "1.5", "nHostNotify": "1.6", "nSvcEvent": "1.7", "nSvcNotify": "1.8"}
OP5_DEFAULT_TEST_OID_SUFFIX = "1.1.1.2"  # nHostname under nagiosHostEventEntry
# SNMPv2/v3 notification: first two varbinds are sysUpTime.0 and snmpTrapOID.0 (RFC 3416)
SYS_UPTIME_OID = "1.3.6.1.2.1.1.3.0"
SNMP_TRAP_OID = "1.3.6.1.6.3.1.1.4.1.0"
# Object suffixes under ENTERPRISE_OID: HostEventEntry=1.1.1, HostNotifyEntry=2.1, SvcEventEntry=3.1, SvcNotifyEntry=4.1
# nSvcEvent/nSvcNotify OBJECTS use nHostname/nHostStateID (1.1.1.2, 1.1.1.4) then service objects (3.1.x)
OP5_OID_SUFFIXES = {
    "nHostEvent": {
        "nHostname": "1.1.1.2", "nHostStateID": "1.1.1.4", "nHostStateType": "1.1.1.5",
        "nHostAttempt": "1.1.1.6", "nHostDurationSec": "1.1.1.7", "nHostGroupName": "1.1.1.8",
        "nHostLastCheck": "1.1.1.9", "nHostLastChange": "1.1.1.10", "nHostOutput": "1.1.1.14",
    },
    "nHostNotify": {
        "nHostNotifyType": "2.1.1", "nHostNotifyNum": "2.1.2", "nHostAckAuthor": "2.1.3",
        "nHostAckComment": "2.1.4", "nHostname": "1.1.1.2", "nHostStateID": "1.1.1.4",
        "nHostStateType": "1.1.1.5", "nHostAttempt": "1.1.1.6", "nHostDurationSec": "1.1.1.7",
        "nHostGroupName": "1.1.1.8", "nHostLastCheck": "1.1.1.9", "nHostLastChange": "1.1.1.10",
        "nHostOutput": "1.1.1.14",
    },
    # nSvcEvent/nSvcNotify OBJECTS use nHostname, nHostStateID (host table 1.1.1.x) then service table (3.1.x)
    "nSvcEvent": {
        "nSvcHostname": "1.1.1.2", "nSvcHostStateID": "1.1.1.4", "nSvcDesc": "3.1.6",
        "nSvcStateID": "3.1.7", "nSvcAttempt": "3.1.8", "nSvcDurationSec": "3.1.9",
        "nSvcGroupName": "3.1.10", "nSvcLastCheck": "3.1.11", "nSvcLastChange": "3.1.12",
        "nSvcOutput": "3.1.17",
    },
    "nSvcNotify": {
        "nSvcNotifyType": "4.1.1", "nSvcNotifyNum": "4.1.2", "nSvcAckAuthor": "4.1.3",
        "nSvcAckComment": "4.1.4", "nSvcHostname": "1.1.1.2", "nSvcHostStateID": "1.1.1.4",
        "nSvcDesc": "3.1.6", "nSvcStateID": "3.1.7", "nSvcAttempt": "3.1.8",
        "nSvcDurationSec": "3.1.9", "nSvcGroupName": "3.1.10", "nSvcLastCheck": "3.1.11",
        "nSvcLastChange": "3.1.12", "nSvcOutput": "3.1.17",
    },
}

# Map notification type names to (oid_suffix_key, val_key) for each varbind
OP5_VARBIND_SPEC = {
    "nHostEvent": [
        ("nHostname", "HOSTNAME"), ("nHostStateID", "HOSTSTATEID"),
        ("nHostStateType", "HOSTSTATETYPE"), ("nHostAttempt", "HOSTATTEMPT"),
        ("nHostDurationSec", "HOSTDURATIONSEC"),
        ("nHostGroupName", "HOSTGROUPNAME"), ("nHostLastCheck", "LASTHOSTCHECK"),
        ("nHostLastChange", "LASTHOSTSTATECHANGE"), ("nHostOutput", "HOSTOUTPUT"),
    ],
    "nHostNotify": [
        ("nHostNotifyType", "NOTIFICATIONTYPE"), ("nHostNotifyNum", "NOTIFICATIONNUMBER"),
        ("nHostAckAuthor", "HOSTACKAUTHOR"), ("nHostAckComment", "HOSTACKCOMMENT"),
        ("nHostname", "HOSTNAME"), ("nHostStateID", "HOSTSTATEID"),
        ("nHostStateType", "HOSTSTATETYPE"), ("nHostAttempt", "HOSTATTEMPT"),
        ("nHostDurationSec", "HOSTDURATIONSEC"),
        ("nHostGroupName", "HOSTGROUPNAME"), ("nHostLastCheck", "LASTHOSTCHECK"),
        ("nHostLastChange", "LASTHOSTSTATECHANGE"), ("nHostOutput", "HOSTOUTPUT"),
    ],
    "nSvcEvent": [
        ("nSvcHostname", "HOSTNAME"), ("nSvcHostStateID", "HOSTSTATEID"),
        ("nSvcDesc", "SERVICEDESCRIPTION"), ("nSvcStateID", "SERVICESTATEID"),
        ("nSvcAttempt", "SERVICEATTEMPT"), ("nSvcDurationSec", "SERVICEDURATIONSEC"),
        ("nSvcGroupName", "SERVICEGROUPNAME"), ("nSvcLastCheck", "LASTSERVICECHECK"),
        ("nSvcLastChange", "LASTSERVICESTATECHANGE"), ("nSvcOutput", "SERVICEOUTPUT"),
    ],
    "nSvcNotify": [
        ("nSvcNotifyType", "NOTIFICATIONTYPE"), ("nSvcNotifyNum", "NOTIFICATIONNUMBER"),
        ("nSvcAckAuthor", "SERVICEACKAUTHOR"), ("nSvcAckComment", "SERVICEACKCOMMENT"),
        ("nSvcHostname", "HOSTNAME"), ("nSvcHostStateID", "HOSTSTATEID"),
        ("nSvcDesc", "SERVICEDESCRIPTION"), ("nSvcStateID", "SERVICESTATEID"),
        ("nSvcAttempt", "SERVICEATTEMPT"), ("nSvcDurationSec", "SERVICEDURATIONSEC"),
        ("nSvcGroupName", "SERVICEGROUPNAME"), ("nSvcLastCheck", "LASTSERVICECHECK"),
        ("nSvcLastChange", "LASTSERVICESTATECHANGE"), ("nSvcOutput", "SERVICEOUTPUT"),
    ],
}


def _op5_normalize_macro_names(val, notification_type):
    """Map standard macro names to internal keys.
    - $SERVICEDESC$ (standard) -> SERVICEDESCRIPTION (MIB name)
    - $HOSTNOTIFICATIONNUMBER$ / $SERVICENOTIFICATIONNUMBER$ -> NOTIFICATIONNUMBER
    """
    if val.get("SERVICEDESC") is not None and val.get("SERVICEDESC") != "":
        if val.get("SERVICEDESCRIPTION") is None or val.get("SERVICEDESCRIPTION") == "":
            val["SERVICEDESCRIPTION"] = val["SERVICEDESC"]
    if notification_type == "nHostNotify" and val.get("HOSTNOTIFICATIONNUMBER") is not None:
        if val.get("NOTIFICATIONNUMBER") is None or val.get("NOTIFICATIONNUMBER") == "":
            val["NOTIFICATIONNUMBER"] = val["HOSTNOTIFICATIONNUMBER"]
    if notification_type == "nSvcNotify" and val.get("SERVICENOTIFICATIONNUMBER") is not None:
        if val.get("NOTIFICATIONNUMBER") is None or val.get("NOTIFICATIONNUMBER") == "":
            val["NOTIFICATIONNUMBER"] = val["SERVICENOTIFICATIONNUMBER"]


def _op5_required_keys(notification_type):
    """Return required variable keys for the given notification type."""
    required = {
        "nHostEvent": ["HOSTNAME"],
        "nHostNotify": ["NOTIFICATIONTYPE", "HOSTNAME"],
        "nSvcEvent": ["HOSTNAME", "SERVICEDESCRIPTION"],
        "nSvcNotify": ["NOTIFICATIONTYPE", "HOSTNAME", "SERVICEDESCRIPTION"],
    }
    return required.get(notification_type, [])


def _op5_set_defaults(notification_type, val):  # pylint: disable=unused-argument
    """Set default values for optional OP5 variables (match Perl script)."""
    defaults = [
        ("HOSTSTATEID", 0), ("HOSTSTATETYPE", 0), ("HOSTATTEMPT", 0), ("HOSTDURATIONSEC", 0),
        ("HOSTGROUPNAME", ""), ("LASTHOSTCHECK", 0), ("LASTHOSTSTATECHANGE", 0),
        ("HOSTOUTPUT", "<No output from host>"), ("NOTIFICATIONNUMBER", 0),
        ("HOSTACKAUTHOR", ""), ("HOSTACKCOMMENT", ""), ("SERVICESTATEID", 0),
        ("SERVICEATTEMPT", 0), ("SERVICEDURATIONSEC", 0), ("SERVICEGROUPNAME", ""),
        ("LASTSERVICECHECK", 0), ("LASTSERVICESTATECHANGE", 0),
        ("SERVICEOUTPUT", "<No output from service>"),
        ("SERVICEACKAUTHOR", ""), ("SERVICEACKCOMMENT", ""),
    ]
    for k, v in defaults:
        if val.get(k) is None or val.get(k) == "":
            val[k] = v
    # Coerce numeric fields to int where needed
    num_keys = (
        "HOSTSTATEID", "HOSTSTATETYPE", "HOSTATTEMPT", "HOSTDURATIONSEC",
        "LASTHOSTCHECK", "LASTHOSTSTATECHANGE", "NOTIFICATIONTYPE", "NOTIFICATIONNUMBER",
        "SERVICESTATEID", "SERVICEATTEMPT", "SERVICEDURATIONSEC",
        "LASTSERVICECHECK", "LASTSERVICESTATECHANGE")
    for key in num_keys:
        if key in val and isinstance(val[key], str) and val[key].isdigit():
            val[key] = int(val[key])


def _op5_normalize_val(val):
    """Apply same NOTIFICATIONTYPE and HOSTSTATETYPE mappings as Perl script."""
    if val.get("NOTIFICATIONTYPE") == "PROBLEM":
        val["NOTIFICATIONTYPE"] = 0
    elif val.get("NOTIFICATIONTYPE") == "RECOVERY":
        val["NOTIFICATIONTYPE"] = 1
    elif val.get("NOTIFICATIONTYPE") == "ACKNOWLEDGEMENT":
        val["NOTIFICATIONTYPE"] = 2
    elif val.get("NOTIFICATIONTYPE") == "FLAPPINGSTART":
        val["NOTIFICATIONTYPE"] = 3
    elif val.get("NOTIFICATIONTYPE") == "FLAPPINGSTOP":
        val["NOTIFICATIONTYPE"] = 4
    # Service-state strings sometimes used for NOTIFICATIONTYPE by OP5
    elif val.get("NOTIFICATIONTYPE") == "OK":
        val["NOTIFICATIONTYPE"] = 0
    elif val.get("NOTIFICATIONTYPE") == "WARNING":
        val["NOTIFICATIONTYPE"] = 1
    elif val.get("NOTIFICATIONTYPE") == "CRITICAL":
        val["NOTIFICATIONTYPE"] = 2
    elif val.get("NOTIFICATIONTYPE") == "UNKNOWN":
        val["NOTIFICATIONTYPE"] = 3
    if val.get("HOSTSTATETYPE") == "UP":
        val["HOSTSTATETYPE"] = 0
    elif val.get("HOSTSTATETYPE") == "DOWN":
        val["HOSTSTATETYPE"] = 1
    elif val.get("HOSTSTATETYPE") == "UNREACHABLE":
        val["HOSTSTATETYPE"] = 2


def _op5_trap_oid(notification_type):
    """Return trap OID for notification type (NAGIOS-NOTIFY-MIB NOTIFICATION-TYPE)."""
    suffix = OP5_TRAP_OID_SUFFIXES.get(notification_type)
    if not suffix:
        raise ValueError(f"Unknown notification type: {notification_type}")
    return ENTERPRISE_OID + "." + suffix


def build_op5_notification_varbinds(notification_type, val, sys_uptime_ticks=None):
    """Build SNMPv2 trap varbinds for OP5/NAGIOS (sysUpTime, snmpTrapOID, then type-specific)."""
    if sys_uptime_ticks is None:
        sys_uptime_ticks = int(time.time() * 100)
    spec = OP5_VARBIND_SPEC.get(notification_type)
    if not spec:
        raise ValueError(f"Unknown notification type: {notification_type}")
    suffixes = OP5_OID_SUFFIXES[notification_type]
    trap_oid = _op5_trap_oid(notification_type)
    out = [
        ObjectType(ObjectIdentity(SYS_UPTIME_OID), TimeTicks(sys_uptime_ticks)),
        ObjectType(ObjectIdentity(SNMP_TRAP_OID), ObjectIdentifier(trap_oid)),
    ]
    for oid_key, val_key in spec:
        suffix = suffixes[oid_key]
        oid_str = ENTERPRISE_OID + "." + suffix
        v = val.get(val_key, "")
        if isinstance(v, int):
            out.append(ObjectType(ObjectIdentity(oid_str), Integer(v)))
        else:
            out.append(ObjectType(ObjectIdentity(oid_str), OctetString(str(v))))
    return out


def build_test_trap_varbinds(test_oid, test_value, sys_uptime_ticks=None):
    """Build varbinds for a test trap: sysUpTime, snmpTrapOID, then (test_oid, test_value)."""
    if sys_uptime_ticks is None:
        sys_uptime_ticks = int(time.time() * 100)
    trap_oid = ENTERPRISE_OID + ".1"  # nagiosNotify
    out = [
        ObjectType(ObjectIdentity(SYS_UPTIME_OID), TimeTicks(sys_uptime_ticks)),
        ObjectType(ObjectIdentity(SNMP_TRAP_OID), ObjectIdentifier(trap_oid)),
        ObjectType(ObjectIdentity(test_oid), OctetString(str(test_value))),
    ]
    return out, trap_oid


def parse_var_bind(var_bind_str):
    """Universal variable binding parser with strict OID validation"""
    try:
        # Split from right to handle OIDs containing ::
        parts = var_bind_str.rsplit(':', 2)
        if len(parts) != 3:
            raise ValueError("Invalid format - expected OID:type:value")

        oid_part, data_type, value = parts

        # Resolve and validate OID
        obj_identity = resolve_oid(oid_part)

        # Handle value types
        if data_type == 'string':
            converted_value = OctetString(value)
        elif data_type == 'int':
            converted_value = Integer(int(value))
        elif data_type == 'oid':
            oid_identity = resolve_oid(value)
            converted_value = ObjectIdentifier(str(oid_identity))
        elif data_type == 'ipaddress':
            try:
                ip_address(value)
            except ValueError as ve:
                raise ValueError(f"Invalid ipaddress value: {value}") from ve
            converted_value = IpAddress(value)
        else:
            raise ValueError(f"Unsupported data type: {data_type}")

        return ObjectType(obj_identity, converted_value)

    except Exception as e:  # pylint: disable=broad-except
        raise ValueError(f"Invalid var-bind: {var_bind_str} - {str(e)}") from e

async def send_trap(args):  # pylint: disable=too-many-locals,too-many-branches
    """Asynchronous function to send SNMP trap. Returns True on success, False on failure."""
    # Version-specific configuration
    if args.version in ['1', '2c'] and not args.community:
        logging.error("Community string required for SNMPv1/v2c")
        return False

    if args.version == '3' and not all([args.user, args.auth_key, args.priv_key]):
        logging.error("SNMPv3 requires --user, --auth-key, and --priv-key")
        return False

    # Protocol mappings
    auth_proto_map = {'SHA': USM_AUTH_HMAC96_SHA, 'MD5': USM_AUTH_HMAC96_MD5}
    priv_proto_map = {'AES': USM_PRIV_CFB128_AES, 'DES': USM_PRIV_CBC56_DES}

    try:
        # Create transport (host from target, port from --port or target:port or default 162)
        target_host, _, target_port_str = args.target.partition(':')
        if getattr(args, 'port', None) is not None:
            target_port = args.port
        elif target_port_str:
            try:
                target_port = int(target_port_str)
            except ValueError:
                logging.error("Invalid port in --target: %r (must be numeric)", target_port_str)
                return False
        else:
            target_port = 162
        transport = await UdpTransportTarget.create(target_host, target_port)

        # Prepare security parameters
        if args.version == '3':
            user_data = UsmUserData(
                args.user,
                authKey=args.auth_key.encode(),
                privKey=args.priv_key.encode(),
                authProtocol=auth_proto_map.get(args.auth_protocol),
                privProtocol=priv_proto_map.get(args.priv_protocol),
            )
        else:
            user_data = CommunityData(
                args.community,
                mpModel=0 if args.version == '1' else 1
            )

        # Build variable bindings
        if getattr(args, '_test_trap', False):
            var_binds, trap_oid_str = build_test_trap_varbinds(
                args._test_oid, args._test_trap_value)
            trap_oid = resolve_oid(trap_oid_str)
        elif getattr(args, '_var_binds_from_op5', False):
            var_binds = build_op5_notification_varbinds(args.type, args._op5_val)
            trap_oid = resolve_oid(_op5_trap_oid(args.type))
        else:
            var_binds = []
            for vb in args.var_bind:
                try:
                    var_binds.append(parse_var_bind(vb))
                except ValueError as e:
                    logging.error("Error processing var-bind: %s", e)
                    return False
            trap_oid = resolve_oid(args.trap_oid)

        # Build notification payload
        if args.version == '1':
            enterprise_oid = str(resolve_oid(args.enterprise_oid))
            notification = SNMPv1TrapPDU(
                enterprise=enterprise_oid,
                agent_addr=IpAddress(args.agent_address),
                generic_trap=args.generic_trap,
                specific_trap=args.specific_trap,
                variable_binds=var_binds
            )
        else:
            notification = NotificationType(trap_oid).add_varbinds(*var_binds)

        # Send notification
        error_indication, _, _, _ = await send_notification(
            SnmpEngine(),
            user_data,
            transport,
            ContextData(),
            'trap',
            notification
        )

        if error_indication:
            logging.error("Trap failed to send: %s", error_indication)
            return False
        logging.info("Trap successfully sent!")
        return True

    except Exception as e:  # pylint: disable=broad-except
        logging.error("Error sending trap: %s: %s", type(e).__name__, e)
        if args.debug:
            logging.exception("Full error trace:")
        return False

def _build_op5_val(args):
    """Build OP5 notification val dict from --notification-var and set args._op5_val, args._var_binds_from_op5.
    Handle --testtrap / --testoid. Exits with 1 on validation error.
    """
    if getattr(args, 'testtrap', None) is not None:
        args._test_trap = True
        args._test_trap_value = args.testtrap
        args._test_oid = (
            args.testoid
            if getattr(args, 'testoid', None) not in (None, "")
            else ENTERPRISE_OID + "." + OP5_DEFAULT_TEST_OID_SUFFIX
        )
        args._var_binds_from_op5 = False
        args._op5_val = None
        return
    args._test_trap = False
    args._test_oid = None
    args._test_trap_value = None

    if args.type:
        if not args.notification_var:
            logging.error("--type requires at least one --notification-var (KEY=VALUE)")
            sys.exit(1)
        val = {}
        for nv in args.notification_var:
            if "=" not in nv:
                logging.error("Invalid --notification-var: %r (expected KEY=VALUE)", nv)
                sys.exit(1)
            k, v = nv.split("=", 1)
            val[k.strip()] = v.strip()
        _op5_normalize_macro_names(val, args.type)
        _op5_set_defaults(args.type, val)
        required = _op5_required_keys(args.type)
        for r in required:
            v = val.get(r)
            if v is None or v == "":
                logging.error("--type %s requires: %s", args.type, ", ".join(required))
                sys.exit(1)
        _op5_normalize_val(val)
        args._op5_val = val
        args._var_binds_from_op5 = True
    else:
        args._op5_val = None
        args._var_binds_from_op5 = False
        if not args.var_bind:
            logging.error("Either --var-bind, --type with --notification-var, or --testtrap is required")
            sys.exit(1)


def _validate_args(args):
    """Validate version-specific and target/agent options. Exits with 1 on error."""
    target_host = args.target.partition(':')[0].strip()
    if not is_hostname(target_host):
        logging.error("%s is not a valid hostname or IP address", target_host)
        sys.exit(1)

    op5_or_test = args._var_binds_from_op5 or getattr(args, '_test_trap', False)
    if args.version == '1':
        if op5_or_test:
            if args.enterprise_oid is None or args.enterprise_oid == "":
                args.enterprise_oid = ENTERPRISE_OID
            if args.agent_address is None or args.agent_address == "":
                args.agent_address = target_host
            if args.generic_trap is None:
                args.generic_trap = 6
            if args.specific_trap is None:
                args.specific_trap = 1
        if not all([args.enterprise_oid, args.agent_address,
                    args.generic_trap is not None,
                    args.specific_trap is not None]):
            logging.error("SNMPv1 requires --enterprise-oid, --agent-address, "
                          "--generic-trap, and --specific-trap")
            sys.exit(1)
        try:
            ip_address(args.agent_address)
        except ValueError:
            logging.error("Invalid --agent-address: %s (must be a valid IP address)", args.agent_address)
            sys.exit(1)

    if args.version in ['2c', '3'] and not op5_or_test and not args.trap_oid:
        logging.error("SNMPv%s requires --trap-oid (or use --type for OP5, or --testtrap)", args.version)
        sys.exit(1)


def main():
    """Parse arguments and send SNMP trap (v1/v2c/v3 or OP5 notification mode)."""
    parser = argparse.ArgumentParser(description='SNMP Trap Sender')
    parser.add_argument('--version', choices=['1', '2c', '3'], default='3',
                        help='SNMP version (default: 3)')

    # SNMPv3 specific
    parser.add_argument('--user', help='SNMPv3 username')
    parser.add_argument('--auth-key', help='SNMPv3 authentication key')
    parser.add_argument('--priv-key', help='SNMPv3 privacy key')
    parser.add_argument('--auth-protocol', choices=['SHA', 'MD5'], default='SHA',
                        help='Authentication protocol (v3 only)')
    parser.add_argument('--priv-protocol', choices=['AES', 'DES'], default='AES',
                        help='Privacy protocol (v3 only)')

    # SNMPv1 specific
    parser.add_argument('--enterprise-oid',
                        help='Enterprise OID (required for SNMPv1)')
    parser.add_argument('--agent-address',
                        help='Agent IP address (required for SNMPv1)')
    parser.add_argument('--generic-trap', type=int, choices=range(0, 7),
                        help='Generic trap type 0-6 (required for SNMPv1)')
    parser.add_argument('--specific-trap', type=int,
                        help='Specific trap code (required for SNMPv1)')

    # Common parameters
    parser.add_argument('--community', help='SNMP community string (v1/v2c)')
    parser.add_argument('--target', '--hostname', required=True,
                        help='Target host or IP (optionally use with --port)')
    parser.add_argument('--port', '-P', type=int, default=None,
                        help='Target port (default: 162; overrides port in --target if both given)')
    parser.add_argument('--trap-oid',
                        help='Trap OID (required for v2c/v3 when not using --type or --testtrap)')
    parser.add_argument('--testtrap', '-T', metavar='VALUE',
                        help='Send a test trap with the given string as the single varbind value')
    parser.add_argument('--testoid', '-o', default=None,
                        help='OID for test trap varbind (default: enterprise nHostname OID)')
    parser.add_argument('--var-bind', '-v', action='append',
                        help='Variable binding in format "OID:type:value"')
    parser.add_argument('--type', choices=['nHostEvent', 'nHostNotify', 'nSvcEvent', 'nSvcNotify'],
                        help='OP5 notification type (builds NAGIOS-NOTIFY-MIB varbinds)')
    parser.add_argument('--notification-var', '-V', action='append', metavar='KEY=VALUE',
                        help='OP5 variable (e.g. HOSTNAME=$HOSTNAME$, SERVICEDESC=$SERVICEDESC$). '
                             'Accepts macro names: SERVICEDESC, HOSTNOTIFICATIONNUMBER, '
                             'SERVICENOTIFICATIONNUMBER. Use with --type.')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')

    args = parser.parse_args()
    setup_logging(args.debug)
    _build_op5_val(args)
    _validate_args(args)
    success = asyncio.run(send_trap(args))
    if not success:
        sys.exit(1)

if __name__ == '__main__':
    main()
