#!/usr/bin/python3

import re
import argparse
import asyncio
import logging
from pysnmp.hlapi.v3arch.asyncio import *
from pysnmp.proto.rfc1902 import *
from pysnmp import debug
from pysnmp.smi import builder, view, compiler


# Initialize MIB components globally
mib_builder = builder.MibBuilder()
compiler.add_mib_compiler(mib_builder)
mib_view = view.MibViewController(mib_builder)

# Load essential MIBs
try:
    mib_builder.load_modules('SNMPv2-MIB')
except Exception as e:
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
    except Exception as e:
        logger.warning(f"Failed to load MIB modules: {e}")


def validate_resolved_oid(oid_identity, original_str):
    """Ensure OID is either resolved to numerical form or valid numerical format"""
    try:
        # First check if original input is numerical
        if is_numerical_oid(original_str):
            return
        
        # Attempt to get string representation
        try:
            oid_str = str(oid_identity)
        except Exception:
            oid_str = None
        
        # Try resolution if needed
        if not oid_str or not is_numerical_oid(oid_str):
            oid_identity.resolve_with_mib(mib_view)
            oid_str = str(oid_identity)
            
        if not is_numerical_oid(oid_str):
            raise ValueError(f"OID {original_str} resolves to non-numerical {oid_str}")

    except Exception as e:
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
    except Exception as e:
        logging.error(f"Invalid OID format: {oid_str} - {str(e)}")
        raise

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

    except Exception as e:
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
        transport = await UdpTransportTarget.create((target_ip, target_port))

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
        var_binds = []
        for vb in args.var_bind:
            try:
                var_binds.append(parse_var_bind(vb))
            except ValueError as e:
                logging.error(f"Error processing var-bind: {e}")
                return

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
            trap_oid = resolve_oid(args.trap_oid)
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
            logging.error(f"Trap failed to send: {error_indication}")
        else:
            logging.info("Trap successfully sent!")

    except Exception as e:
        logging.error(f"Error sending trap: {str(e)}")
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
    parser.add_argument('--var-bind', '-v', action='append', required=True,
                      help='Variable binding in format "OID:type:value"')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')

    args = parser.parse_args()

    # Validate version-specific requirements
    if args.version == '1' and not all([args.enterprise_oid, args.agent_address,
                                      args.generic_trap is not None,
                                      args.specific_trap is not None]):
        logging.error("SNMPv1 requires --enterprise-oid, --agent-address, "
                    "--generic-trap, and --specific-trap")
        return

    if args.version in ['2c', '3'] and not args.trap_oid:
        logging.error(f"SNMPv{args.version} requires --trap-oid")
        return

    setup_logging(args.debug)
    asyncio.run(send_trap(args))

if __name__ == '__main__':
    main()
