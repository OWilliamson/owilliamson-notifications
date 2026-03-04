#!/usr/bin/python3

import argparse
import logging
from pysnmp.entity import engine
from pysnmp.hlapi import *
from pysnmp.entity import config
from pysnmp import debug

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
        debug.set_logger(debug.Debug('all'))

    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.DEBUG if debug_flag else logging.INFO)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

def parse_var_bind(var_bind_str):
    """Parse variable binding string into ObjectType"""
    try:
        oid, data_type, value = var_bind_str.split(':', 2)
        obj_identity = obj_identity(oid)

        if data_type == 'string':
            converted_value = value
        elif data_type == 'int':
            converted_value = int(value)
        elif data_type == 'oid':
            converted_value = ObjectIdentity(value)
        else:
            raise ValueError(f"Unsupported data type: {data_type}")

        return ObjectType(obj_identity, converted_value)
    except ValueError:
        raise ValueError(f"Invalid var-bind format: {var_bind_str}. Expected OID:type:value")

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
    parser.add_argument('--trap-oid', required=True,
                      help='Trap OID (e.g., SNMPv2-MIB::authenticationFailure)')
    parser.add_argument('--var-bind', '-v', action='append', required=True,
                      help='Variable binding in format "OID:type:value"')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')

    args = parser.parse_args()
    setup_logging(args.debug)

    # Protocol mappings
    auth_proto_map = {
        'SHA': config.usmHMACSHAAuthProtocol,
        'MD5': config.usmHMACMD5AuthProtocol
    }
    priv_proto_map = {
        'AES': config.usmAesCfb128Protocol,
        'DES': config.usmDESPrivProtocol
    }

    try:
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
        snmp_engine = engine.SnmpEngine()

        error_indication, error_status, error_index, _ = sendNotification(
            snmp_engine,
            config.UsmUserData(
                args.user,
                authKey=args.auth_key,
                privKey=args.priv_key,
                authProtocol=auth_proto_map[args.auth_protocol],
                privProtocol=priv_proto_map[args.priv_protocol],
            ),
            UdpTransportTarget((target_ip, target_port)),
            ContextData(),
            'trap',
            NotificationType(ObjectIdentity(args.trap_oid)).addVarBinds(*var_binds)
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

if __name__ == '__main__':
    main()
