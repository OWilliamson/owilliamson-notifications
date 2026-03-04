#!/usr/bin/python3
# pyright: reportMissingImports=false, reportUndefinedVariable=false
# pylint: disable=wildcard-import,undefined-variable

import re
import argparse
import asyncio
import logging
from pysnmp.hlapi.v3arch.asyncio import *  # noqa: F403,F401
from pysnmp.proto.rfc1902 import (
    Integer,
    IpAddress,
    OctetString,
    ObjectIdentifier,
    TimeTicks,
)
from pysnmp import debug
from pysnmp.smi import builder, view, compiler


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
    return re.match(r'^[0-9.]+$', oid_str) is not None

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

# OP5 (ITRS OP5 Monitor) / NAGIOS-NOTIFY-MIB (numeric OIDs; no MIB files required)
ENTERPRISE_OID = "1.3.6.1.4.1.20006.1"
SYS_UPTIME_OID = "1.3.6.1.2.1.1.3.0"
SNMP_TRAP_OID = "1.3.6.1.6.3.1.1.4.1.0"
# Table suffixes: 1.x = nHostEvent, 2.x = nHostNotify, 3.x = nSvcEvent, 4.x = nSvcNotify
OP5_OID_SUFFIXES = {
    "nHostEvent": {
        "nHostname": "1.1.2", "nHostStateID": "1.1.4", "nHostStateType": "1.1.5",
        "nHostAttempt": "1.1.6", "nHostDurationSec": "1.1.7", "nHostGroupName": "1.1.8",
        "nHostLastCheck": "1.1.9", "nHostLastChange": "1.1.10", "nHostOutput": "1.1.14",
    },
    "nHostNotify": {
        "nHostNotifyType": "2.1.1", "nHostNotifyNum": "2.1.2", "nHostAckAuthor": "2.1.3",
        "nHostAckComment": "2.1.4", "nHostname": "1.1.2", "nHostStateID": "1.1.4",
        "nHostStateType": "1.1.5", "nHostAttempt": "1.1.6", "nHostDurationSec": "1.1.7",
        "nHostGroupName": "1.1.8", "nHostLastCheck": "1.1.9", "nHostLastChange": "1.1.10",
        "nHostOutput": "1.1.14",
    },
    "nSvcEvent": {
        "nSvcHostname": "3.1.2", "nSvcHostStateID": "3.1.4", "nSvcDesc": "3.1.6",
        "nSvcStateID": "3.1.7", "nSvcAttempt": "3.1.8", "nSvcDurationSec": "3.1.9",
        "nSvcGroupName": "3.1.10", "nSvcLastCheck": "3.1.11", "nSvcLastChange": "3.1.12",
        "nSvcOutput": "3.1.17",
    },
    "nSvcNotify": {
        "nSvcNotifyType": "4.1.1", "nSvcNotifyNum": "4.1.2", "nSvcAckAuthor": "4.1.3",
        "nSvcAckComment": "4.1.4", "nSvcHostname": "3.1.2", "nSvcHostStateID": "3.1.4",
        "nSvcDesc": "3.1.6", "nSvcStateID": "3.1.7", "nSvcAttempt": "3.1.8",
        "nSvcDurationSec": "3.1.9", "nSvcGroupName": "3.1.10", "nSvcLastCheck": "3.1.11",
        "nSvcLastChange": "3.1.12", "nSvcOutput": "3.1.17",
    },
}

# Map notification type names to (oid_suffix_key, val_key) for each varbind
OP5_VARBIND_SPEC = {
    "nHostEvent": [
        ("nHostname", "HOSTNAME"), ("nHostStateID", "HOSTSTATEID"), ("nHostStateType", "HOSTSTATETYPE"),
        ("nHostAttempt", "HOSTATTEMPT"), ("nHostDurationSec", "HOSTDURATIONSEC"), ("nHostGroupName", "HOSTGROUPNAME"),
        ("nHostLastCheck", "LASTHOSTCHECK"), ("nHostLastChange", "LASTHOSTSTATECHANGE"), ("nHostOutput", "HOSTOUTPUT"),
    ],
    "nHostNotify": [
        ("nHostNotifyType", "NOTIFICATIONTYPE"), ("nHostNotifyNum", "NOTIFICATIONNUMBER"),
        ("nHostAckAuthor", "HOSTACKAUTHOR"), ("nHostAckComment", "HOSTACKCOMMENT"),
        ("nHostname", "HOSTNAME"), ("nHostStateID", "HOSTSTATEID"), ("nHostStateType", "HOSTSTATETYPE"),
        ("nHostAttempt", "HOSTATTEMPT"), ("nHostDurationSec", "HOSTDURATIONSEC"), ("nHostGroupName", "HOSTGROUPNAME"),
        ("nHostLastCheck", "LASTHOSTCHECK"), ("nHostLastChange", "LASTHOSTSTATECHANGE"), ("nHostOutput", "HOSTOUTPUT"),
    ],
    "nSvcEvent": [
        ("nSvcHostname", "HOSTNAME"), ("nSvcHostStateID", "HOSTSTATEID"), ("nSvcDesc", "SERVICEDESCRIPTION"),
        ("nSvcStateID", "SERVICESTATEID"), ("nSvcAttempt", "SERVICEATTEMPT"),
        ("nSvcDurationSec", "SERVICEDURATIONSEC"), ("nSvcGroupName", "SERVICEGROUPNAME"),
        ("nSvcLastCheck", "LASTSERVICECHECK"), ("nSvcLastChange", "LASTSERVICESTATECHANGE"), ("nSvcOutput", "SERVICEOUTPUT"),
    ],
    "nSvcNotify": [
        ("nSvcNotifyType", "NOTIFICATIONTYPE"), ("nSvcNotifyNum", "NOTIFICATIONNUMBER"),
        ("nSvcAckAuthor", "SERVICEACKAUTHOR"), ("nSvcAckComment", "SERVICEACKCOMMENT"),
        ("nSvcHostname", "HOSTNAME"), ("nSvcHostStateID", "HOSTSTATEID"), ("nSvcDesc", "SERVICEDESCRIPTION"),
        ("nSvcStateID", "SERVICESTATEID"), ("nSvcAttempt", "SERVICEATTEMPT"),
        ("nSvcDurationSec", "SERVICEDURATIONSEC"), ("nSvcGroupName", "SERVICEGROUPNAME"),
        ("nSvcLastCheck", "LASTSERVICECHECK"), ("nSvcLastChange", "LASTSERVICESTATECHANGE"), ("nSvcOutput", "SERVICEOUTPUT"),
    ],
}


def _op5_required_keys(notification_type):
    """Return required variable keys for the given notification type."""
    required = {"nHostEvent": ["HOSTNAME"], "nHostNotify": ["NOTIFICATIONTYPE", "HOSTNAME"],
                "nSvcEvent": ["HOSTNAME", "SERVICEDESCRIPTION"], "nSvcNotify": ["NOTIFICATIONTYPE", "HOSTNAME", "SERVICEDESCRIPTION"]}
    return required.get(notification_type, [])


def _op5_set_defaults(notification_type, val):
    """Set default values for optional OP5 variables (match Perl script)."""
    defaults = [
        ("HOSTSTATEID", 0), ("HOSTSTATETYPE", 0), ("HOSTATTEMPT", 0), ("HOSTDURATIONSEC", 0),
        ("HOSTGROUPNAME", ""), ("LASTHOSTCHECK", 0), ("LASTHOSTSTATECHANGE", 0),
        ("HOSTOUTPUT", "<No output from host>"), ("NOTIFICATIONNUMBER", 0),
        ("HOSTACKAUTHOR", ""), ("HOSTACKCOMMENT", ""), ("SERVICESTATEID", 0),
        ("SERVICEATTEMPT", 0), ("SERVICEDURATIONSEC", 0), ("SERVICEGROUPNAME", ""),
        ("LASTSERVICECHECK", 0), ("LASTSERVICESTATECHANGE", 0),
        ("SERVICEOUTPUT", "<No output from service>"), ("SERVICEACKAUTHOR", ""), ("SERVICEACKCOMMENT", ""),
    ]
    for k, v in defaults:
        if val.get(k) is None or val.get(k) == "":
            val[k] = v
    # Coerce numeric fields to int where needed
    for key in ("HOSTSTATEID", "HOSTSTATETYPE", "HOSTATTEMPT", "HOSTDURATIONSEC", "LASTHOSTCHECK",
                "LASTHOSTSTATECHANGE", "NOTIFICATIONTYPE", "NOTIFICATIONNUMBER", "SERVICESTATEID",
                "SERVICEATTEMPT", "SERVICEDURATIONSEC", "LASTSERVICECHECK", "LASTSERVICESTATECHANGE"):
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


def build_op5_notification_varbinds(notification_type, val, sys_uptime_ticks=None):
    """Build SNMPv2 trap varbinds for OP5/NAGIOS notification (sysUpTime, snmpTrapOID, then type-specific)."""
    if sys_uptime_ticks is None:
        sys_uptime_ticks = int(__import__("time").time() * 100)
    spec = OP5_VARBIND_SPEC.get(notification_type)
    if not spec:
        raise ValueError(f"Unknown notification type: {notification_type}")
    suffixes = OP5_OID_SUFFIXES[notification_type]
    out = [
        ObjectType(ObjectIdentity(SYS_UPTIME_OID), TimeTicks(sys_uptime_ticks)),
        ObjectType(ObjectIdentity(SNMP_TRAP_OID), ObjectIdentifier(ENTERPRISE_OID)),
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
            converted_value = IpAddress(value)
        else:
            raise ValueError(f"Unsupported data type: {data_type}")

        return ObjectType(obj_identity, converted_value)

    except Exception as e:  # pylint: disable=broad-except
        raise ValueError(f"Invalid var-bind: {var_bind_str} - {str(e)}") from e

async def send_trap(args):
    """Asynchronous function to send SNMP trap"""
    # Version-specific configuration
    if args.version in ['1', '2c'] and not args.community:
        logging.error("Community string required for SNMPv1/v2c")
        return

    if args.version == '3' and not all([args.user, args.auth_key, args.priv_key]):
        logging.error("SNMPv3 requires --user, --auth-key, and --priv-key")
        return

    # Protocol mappings
    auth_proto_map = {'SHA': USM_AUTH_HMAC96_SHA, 'MD5': USM_AUTH_HMAC96_MD5}
    priv_proto_map = {'AES': USM_PRIV_CFB128_AES, 'DES': USM_PRIV_CBC56_DES}

    try:
        # Create transport
        target_ip, _, target_port = args.target.partition(':')
        target_port = int(target_port) if target_port else 162
        transport = await UdpTransportTarget.create(target_ip, target_port)

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
        if getattr(args, '_var_binds_from_op5', False):
            var_binds = build_op5_notification_varbinds(args.type, args._op5_val)
            trap_oid = resolve_oid(ENTERPRISE_OID)
        else:
            var_binds = []
            for vb in args.var_bind:
                try:
                    var_binds.append(parse_var_bind(vb))
                except ValueError as e:
                    logging.error("Error processing var-bind: %s", e)
                    return
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
        error_indication, error_status, error_index, _ = await send_notification(
            SnmpEngine(),
            user_data,
            transport,
            ContextData(),
            'trap',
            notification
        )

        if error_indication:
            logging.error("Trap failed to send: %s", error_indication)
        else:
            logging.info("Trap successfully sent!")

    except Exception as e:  # pylint: disable=broad-except
        logging.error("Error sending trap: %s", e)
        if args.debug:
            logging.exception("Full error trace:")

def main():
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
    parser.add_argument('--target', required=True,
                      help='Target IP:port (e.g., 192.168.1.100:162)')
    parser.add_argument('--trap-oid',
                      help='Trap OID (required for v2c/v3)')
    parser.add_argument('--var-bind', '-v', action='append',
                      help='Variable binding in format "OID:type:value"')
    parser.add_argument('--type', choices=['nHostEvent', 'nHostNotify', 'nSvcEvent', 'nSvcNotify'],
                      help='OP5 notification type (builds NAGIOS-NOTIFY-MIB varbinds)')
    parser.add_argument('--notification-var', '-V', action='append', metavar='KEY=VALUE',
                      help='OP5 variable (e.g. HOSTNAME=host1). Use with --type.')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')

    args = parser.parse_args()

    # OP5 mode: build val from --notification-var and set defaults
    if args.type:
        if not args.notification_var:
            logging.error("--type requires at least one --notification-var (KEY=VALUE)")
            return
        val = {}
        for nv in args.notification_var:
            if "=" not in nv:
                logging.error("Invalid --notification-var: %r (expected KEY=VALUE)", nv)
                return
            k, v = nv.split("=", 1)
            val[k.strip()] = v.strip()
        _op5_set_defaults(args.type, val)
        required = _op5_required_keys(args.type)
        for r in required:
            if not val.get(r):
                logging.error("--type %s requires: %s", args.type, ", ".join(required))
                return
        _op5_normalize_val(val)
        args._op5_val = val
        args._var_binds_from_op5 = True
    else:
        args._op5_val = None
        args._var_binds_from_op5 = False
        if not args.var_bind:
            logging.error("Either --var-bind or --type with --notification-var is required")
            return

    # Validate version-specific requirements
    if args.version == '1' and not all([args.enterprise_oid, args.agent_address,
                                      args.generic_trap is not None,
                                      args.specific_trap is not None]):
        logging.error("SNMPv1 requires --enterprise-oid, --agent-address, "
                    "--generic-trap, and --specific-trap")
        return

    if args.version in ['2c', '3'] and not args.trap_oid and not args._var_binds_from_op5:
        logging.error("SNMPv%s requires --trap-oid (or use --type for OP5)", args.version)
        return

    if args._var_binds_from_op5 and args.version != '3':
        logging.error("OP5 notification mode (--type) is only supported with SNMPv3")
        return

    setup_logging(args.debug)
    asyncio.run(send_trap(args))

if __name__ == '__main__':
    main()
