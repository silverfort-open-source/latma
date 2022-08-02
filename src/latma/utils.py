import logging
import os
import re
import socket
import sys
import xml.etree.ElementTree as ET
from impacket.dcerpc.v5 import epm, transport
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.uuid import uuidtup_to_bin
from ldap3 import Server, Connection, SAFE_SYNC, SUBTREE, ALL
from ldap3.core.exceptions import LDAPBindError

LDAP_PORT = 389
LDAPS_PORT = 636
MSRPC_UUID_ENDPOINT = uuidtup_to_bin(('F6BEAFF7-1E19-4FBB-9F8F-B89E2018337C', '1.0'))
CREDENTIAL_REGEX = r"(?:(?:([^/:]*)/)?([^:]*)(?::(.*))?)?"
DN_REGEX = '^((CN=([^,]*)),)?(((?:CN|OU)=[^,]+,?)+)$'


def parse_credentials(credentials):
    """ Helper function to parse credentials information. The expected format is:
    <DOMAIN></USERNAME><:PASSWORD>
    :param credentials: credentials to parse
    :type credentials: string
    :return: tuple of domain, username and password
    :rtype: (string, string, string)
    """
    credential_regex = re.compile(CREDENTIAL_REGEX)
    domain, username, password = credential_regex.match(credentials).groups('')

    return domain, username, password


def evtx_query_builder(log_num, path, start_date, suppress_query=None) -> str:
    query_tree = ET.Element('QueryList')
    query = ET.SubElement(query_tree, "Query")
    query.set("Id", "0")
    query.set("Path", path)
    select_query = ET.SubElement(query, "Select")
    select_query.set("Path", path)
    select_query.text = f"*[System[(EventID={log_num})"
    if start_date:
        zulutime = start_date.isoformat() + '.000Z'
        select_query.text += f" and TimeCreated[@SystemTime&gt;='{zulutime}']"
    select_query.text += ']]'
    if suppress_query:
        suppress_element = ET.SubElement(query, "Suppress")
        suppress_element.set("Path", path)
        suppress_element.text = suppress_query
    return ET.tostring(query_tree, encoding='unicode').replace("&amp;", "&")


def domain_to_dn(domain: str) -> str:
    """
    Convert a domain to a DN format
    :param domain: fqdn
    :return: DN formatted fqdn
    """
    return ",".join(f"dc={dc_part}" for dc_part in domain.split("."))


def is_arg_dn(argument: str) -> bool:
    """
    Validate if string is in a Distinguished Name format without trailing DC.
    :param argument: string
    :return: bool
    """
    return bool(re.search(pattern=DN_REGEX, string=argument))


def test_connection(host):
    """
    Tests a connection to a windows machine.
    Pings a host, if ping is unavailable, it will tcp syn SMB port.
    :param host:
    :return: Bool, True for dc is alive and False if DC is down
    """
    string_binding = None
    try:
        string_binding = epm.hept_map(host, MSRPC_UUID_ENDPOINT, protocol='ncacn_ip_tcp')
    except DCERPCException as e:
        if "10060" in e.__str__():
            logging.error(f"{host} is unreachable")
            return False
    if string_binding is None:
        logging.error(f"Unable to contact {host} in rpc port 135.")
        return False
    string_binding_parsed = transport.DCERPCStringBinding(string_binding)
    socket_session = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socket_session.settimeout(3)
    conn_result = socket_session.connect_ex((host, int(string_binding_parsed.get_endpoint())))
    socket_session.close()
    if conn_result == 0:
        return True
    else:
        logging.error(f"{host} is up, RPC is unavailable.")
        return False


class Credentials:
    def __init__(self, user_name, admin_password, domain):
        self.username = user_name
        self.password = admin_password
        self.domain = domain


class Ldap:
    def __init__(self, domain, username, password, use_ldap):
        self.domain = domain
        port = LDAPS_PORT
        use_ldaps = True
        if use_ldap:
            logging.info("Using LDAP")
            port = LDAP_PORT
            use_ldaps = False
        try:
            server = Server(host=self.domain, port=port, use_ssl=use_ldaps, get_info=ALL)
            self.conn = Connection(server, user=f"{os.environ['userdomain']}\\{username}", password=password,
                                   client_strategy=SAFE_SYNC, auto_bind=True)
            if use_ldaps is True:
                self.conn.start_tls()
        except LDAPBindError as e:
            logging.error(f"Unable to bind due to: {e}")
            sys.exit(0)

        except Exception as e:
            logging.exception(f'Unable to connect LDAP due to: ')
            sys.exit(0)

    def get_workstations(self, search_filter, base_filter=None):
        """
        Get all workstations list from domain using LDAP
        :param base_filter: will filter search base by RDN
        :param search_filter: search filter query
        :return: workstation list
        """
        workstation_list = []
        ou_list = [domain_to_dn(self.domain)]
        attrs = ["name", "dNSHostName", "operatingSystem"]
        if base_filter is not None:
            ou_list = base_filter.split(';')
        for ou in ou_list:
            try:
                status, result, response, _ = self.conn.search(ou, search_filter, attributes=attrs,
                                                               search_scope=SUBTREE)
                workstation_list.extend(response)
            except AttributeError as e:
                logging.exception("Unable to query LDAP: ")
                return []
        return workstation_list
