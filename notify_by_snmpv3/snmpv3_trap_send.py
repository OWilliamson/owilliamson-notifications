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
        else:
            raise ValueError(f"Unsupported data type: {data_type}")

        return ObjectType(obj_identity, converted_value)

    except Exception as e:
        raise ValueError(f"Invalid var-bind: {var_bind_str} - {str(e)}") from e

async def send_trap(args):
    """Asynchronous function to send SNMPv3 trap"""
    # Updated protocol mappings with non-deprecated constants
    auth_proto_map = {
        'SHA': USM_AUTH_HMAC96_SHA,
        'MD5': USM_AUTH_HMAC96_MD5
    }
    priv_proto_map = {
        'AES': USM_PRIV_CFB128_AES,
        'DES': USM_PRIV_CBC56_DES
    }

    try:
        # Conditional MIB loading for trap OID
        # Resolve trap OID
        trap_oid = resolve_oid(args.trap_oid)

        target_ip, _, target_port = args.target.partition(':')
        target_port = int(target_port) if target_port else 162

        logging.debug(f"Target: {target_ip}:{target_port}")
    except ValueError as e:
        logging.error(f"Invalid target format: {e}")
        return

    var_binds = []
    for vb in args.var_bind:
        try:
            var_bind = parse_var_bind(vb)
            var_binds.append(var_bind)
            logging.debug(f"Added var-bind: {vb}")
        except ValueError as e:
            logging.error(f"Error processing var-bind: {e}")
            return

    try:
        # Create transport target asynchronously
        transport = await UdpTransportTarget.create(target_ip, target_port)
        
        error_indication, error_status, error_index, _ = await send_notification(
            SnmpEngine(),
            UsmUserData(
                args.user,
                authKey=args.auth_key.encode(),
                privKey=args.priv_key.encode(),
                authProtocol=auth_proto_map[args.auth_protocol],
                privProtocol=priv_proto_map[args.priv_protocol],
            ),
            transport,  # Use created transport target
            ContextData(),
            'trap',
            NotificationType(trap_oid).add_varbinds(*var_binds)
        )

        if error_indication:
            logging.error(f"Trap failed to send: {error_indication}")
        elif error_status:
            logging.error(f"Error in response: {error_status.prettyPrint()}")
        else:
            logging.info("Trap successfully sent!")

    except Exception as e:
        logging.error(f"Error sending trap: {str(e)}")
        if args.debug:
            logging.exception("Full error trace:")

def main():
    parser = argparse.ArgumentParser(description='Send SNMPv3 trap with command-line parameters')
    parser.add_argument('--user', required=True, help='SNMPv3 username')
    parser.add_argument('--auth-key', required=True, help='Authentication key')
    parser.add_argument('--priv-key', required=True, help='Privacy key')
    parser.add_argument('--auth-protocol', choices=['SHA', 'MD5'], default='SHA',
                      help='Authentication protocol (SHA|MD5)')
    parser.add_argument('--priv-protocol', choices=['AES', 'DES'], default='AES',
                      help='Privacy protocol (AES|DES)')
    parser.add_argument('--target', required=True, help='Target IP:port (e.g., 192.168.1.100:162)')
    parser.add_argument('--trap-oid', default='1.3.6.1.6.3.1.1.5.6',  # Default numeric OID
                      help='Trap OID (use numeric format)')
    parser.add_argument('--var-bind', '-v', action='append', required=True,
                      help='Variable binding in format "OID:type:value"')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')

    args = parser.parse_args()
    setup_logging(args.debug)
    asyncio.run(send_trap(args))

if __name__ == '__main__':
    main()
