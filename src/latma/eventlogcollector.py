import argparse
import concurrent.futures
import csv
from datetime import datetime, timezone
from queue import Queue
from threading import Thread
from time import sleep
import pywintypes
import win32evtlog
from bs4 import BeautifulSoup
from latma.utils import *
import os

EVENT_BULK_NUM = 1024
DUMP_CHUNK_SIZE = 20
OUTPUT_FILE_NAME = "logs.csv"
KERBEROS = 'KERBEROS'
NTLM = 'NTLM'
SUPPORTED_OS = 'windows'


class Collector:
    def __init__(self, admin_credentials: Credentials, start_date, search_base_filter, threads, use_ldap):
        self.use_ldap = use_ldap
        self.start_date = start_date
        self.evtx_path = None
        self.evtx_query = None
        self.type = None
        self.csv_output_file = None
        self.workstation_list_size = 0
        self.credentials = admin_credentials
        self.thread_num = threads
        self.csv_handle = self.init_csv_output_file()
        self.workstation_list = []
        self.is_done = False
        self.authn_queue = Queue()
        self.search_base_filter = search_base_filter

    def init_csv_output_file(self):
        """
        initializes csv output file, adding a header if file doesn't exist.
        :return: csv file handle.
        """
        csv_buf_size = 1
        file_exists = os.path.isfile(OUTPUT_FILE_NAME)
        self.csv_output_file = open(OUTPUT_FILE_NAME, "a", csv_buf_size, newline='', encoding='utf-8')
        csv_writer = csv.writer(self.csv_output_file)
        if not file_exists:
            csv_writer.writerow(
                ["username", "source host", "destination", "spn", "timestamp", "auth type"])
        return csv_writer

    def connect_to_evtx(self, host):
        """
        Connect and authenticate a host to a remote event viewer.
        :param host: NETBIOS name or ip
        :return: rpc session handle
        """
        try:
            handle = win32evtlog.EvtOpenSession(
                Login=(host, self.credentials.username, self.credentials.domain, self.credentials.password,
                       win32evtlog.EvtRpcLoginAuthDefault),
                Timeout=0, Flags=0)
            return handle
        except Exception as e:
            logging.exception(f"Unable to open session to {host}: ")

    def query_evtx(self, session_handle, workstation):
        """
        Query event viewer according to the required filter.
        :param workstation:
        :param session_handle: RPC authenticated Session handle
        :return: Handle to query results.
        """
        try:
            handle = win32evtlog.EvtQuery(self.evtx_path, win32evtlog.EvtQueryReverseDirection,
                                          self.evtx_query, Session=session_handle)
        except pywintypes.error as e:
            logging.error(f"Unable to query {workstation}: {e.strerror}")
            return None
        return handle

    def query_workstations(self, ldap_filter):
        """
        Retrieve Kerberos event logs algorithm.
        """
        ldap_conn = Ldap(self.credentials.domain, self.credentials.username, self.credentials.password, self.use_ldap, self.credentials.ldap_domain)

        for workstation in ldap_conn.get_workstations(ldap_filter, self.search_base_filter):
            if workstation.get('raw_dn') and workstation['attributes']['dNSHostName'] and workstation['attributes'][
                'operatingSystem']:
                if SUPPORTED_OS in workstation['attributes'].get('operatingSystem').lower():
                    self.workstation_list.append(workstation)
        self.workstation_list_size = len(self.workstation_list)

    def parse_events(self):
        events = []
        while True:
            if self.authn_queue.empty():
                if self.is_done:
                    break
                sleep(1)
                continue
            event = self.authn_queue.get()
            system_time = None
            tree = BeautifulSoup(event, 'xml')
            data = tree.find_all("Data")
            for time in tree.find_all("TimeCreated"):
                system_time = datetime.fromisoformat(time['SystemTime'][:23]).astimezone(timezone.utc).strftime(
                    '%d/%m/%Y %H:%M')
            user_name, source, dest, spn, auth_type = self.parse_protocol(data, tree)
            events.append([user_name, source, dest, spn, system_time, auth_type])
            if len(events) == DUMP_CHUNK_SIZE:
                self.csv_handle.writerows(events)
                events = []
            self.authn_queue.task_done()

    def parse_protocol(self, data, tree=None):
        """
        Parse protocol specific event.
        :param data: BS4 type sub tree "data"
        :param tree: BS4 type tree, xml formatted
        """
        pass

    def get_evtx_logs(self):
        """
        Iterate over all remote hosts and get event logs using multithreading.
        """
        logging.info(f"Collecting authentication logs type: {self.type} from {len(self.workstation_list)} Hosts ")
        parser_thread = Thread(target=self.parse_events)
        parser_thread.start()

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.thread_num) as executor:
            executor.map(self.get_single_workstation, self.workstation_list)
        self.is_done = True
        parser_thread.join()

    def _collect_events(self, handle, workstation):
        """
        Collect event logs using pywin32. Run over all logs in bulks of 1024 messages (maximum)
        :param handle: handle to a remote host-  authenticated and queried event viewer .
        """
        offset = 0
        while True:
            try:
                events = win32evtlog.EvtNext(handle, EVENT_BULK_NUM, -1, 0)
            except pywintypes.error as e:
                logging.error(f"Unable to collect events from {workstation}: {e.strerror}")
                break
            for event in events:
                self.authn_queue.put(win32evtlog.EvtRender(event, 1))

            offset += EVENT_BULK_NUM
            win32evtlog.EvtSeek(handle, offset, win32evtlog.EvtSeekRelativeToFirst)
            if not events:
                return

    def get_single_workstation(self, workstation):
        """
        Authenticate and query a remote host.
        :param workstation: remote hostname fqdn string
        :return:
        """
        workstation = workstation['attributes']['dNSHostName']
        logging.debug(f"Connecting to {workstation}")
        if not test_connection(workstation):
            return
        session_handle = self.connect_to_evtx(workstation)
        query_handle = self.query_evtx(session_handle, workstation)
        if query_handle is None:
            return

        self._collect_events(query_handle, workstation)


class NTLMCollector(Collector):
    def __init__(self, admin_credentials: Credentials, start_date, search_base_filter, threads, use_ldap):
        super().__init__(admin_credentials, start_date, search_base_filter, threads, use_ldap)
        evt_log_num = '8004'
        self.evtx_path = "Microsoft-Windows-NTLM/Operational"
        if search_base_filter is not None:
            if input("NTLM reaches for domain controllers only. Do you want to limit ldap RDN for NTLM? (y/n)") != "y":
                self.search_base_filter = None
        self.evtx_query = evtx_query_builder(evt_log_num, self.evtx_path, start_date=start_date)
        self.type = NTLM
        ldap_dc_filter = "(&(objectCategory=computer)(|(userAccountControl:1.2.840.113556.1.4.803:=8192)(primaryGroupID=521)))"
        self.query_workstations(ldap_dc_filter)

    def parse_protocol(self, data, tree=None):
        dest = f"{data[0].get_text()}@{self.credentials.domain}".lower()
        user_name = data[1].get_text().lower()
        source = f"{data[3].get_text()}@{self.credentials.domain}".lower()
        spn = "-"
        return user_name, source, dest, spn, self.type


class KerberosCollector(Collector):
    def __init__(self, admin_credentials: Credentials, start_date, search_base_filter, threads, use_ldap):
        super().__init__(admin_credentials, start_date, search_base_filter, threads, use_ldap)
        evt_log_num = '4648'
        supress_query = "*[EventData[Data[@Name='TargetServerName'] and (Data='localhost')]]"
        self.search_base_filter = search_base_filter
        self.evtx_path = 'Security'
        self.evtx_query = evtx_query_builder(evt_log_num, self.evtx_path, start_date=start_date,
                                             suppress_query=supress_query)
        self.type = KERBEROS
        ldap_workstations_filter = "(&(objectCategory=Computer))"
        self.query_workstations(ldap_workstations_filter)

    def parse_protocol(self, data, tree=None):
        dest = data[8].get_text().lower()
        user_name = data[5].get_text().lower()
        source = tree.find("Computer").get_text().lower()
        spn = data[9].get_text().lower()
        return user_name, source, dest, spn, self.type


def main():
    parser = argparse.ArgumentParser(add_help=True,
                                     description="The Event Log Collector module scans domain controllers for "
                                                 "successful NTLM authentication logs and endpoints for successful "
                                                 "Kerberos authentication logs.")
    parser.add_argument('credentials', action='store', help='credentials [domain/]username[:password] credentials format.\n'
                                                            'alternatively [domain/]username and then password will '
                                                            'be prompted securely. '
                        )
    parser.add_argument('-ntlm', action='store_true', help='Retrieve ntlm authentication logs from DC')
    parser.add_argument('-kerberos', action='store_true',
                        help='Retrieve kerberos authentication logs from all computers in the domain')
    parser.add_argument('-threads', action='store', type=int,
                        help='Amount of working threads to use. Default is 5 threads', default=5)
    parser.add_argument("-date", type=lambda s: datetime.strptime(s, '%m-%d-%Y'),
                        help="Starting date to collect event logs from. month-day-year format", default=None)
    parser.add_argument("-filter", action='store',
                        help="Query specific ou or container in the domain, will result all workstations in the sub "
                             "OU as well.\n "
                             "Each OU will be in format of DN (Distinguished Name).\n"
                             "Supports multiple OUs with a semicolon delimiter.\n"
                             "Example: OU=subunit,OU=unit;OU=anotherUnit,DC=domain,DC=com\n"
                             "Example: CN=container,OU=unit;OU=anotherUnit,DC=domain,DC=com")
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')
    parser.add_argument('-ldap', action='store_true', help='Use unsecured LDAP instead of LDAP/s.')
    parser.add_argument('-ldap_domain', action='store', help='Custom domain on ldap login credentials. If empty, '
                                                             'will use current user\'s session domain')

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        logging.getLogger().setLevel(logging.INFO)

    domain, username, password = parse_credentials(options.credentials)

    if not options.ntlm and not options.kerberos:
        logging.error("No authentication method was chosen.")
        sys.exit()
    if password == '':
        from getpass import getpass

        password = getpass("Password:")

    if options.ldap_domain is None:
        options.ldap_domain = os.environ['userdomain']
    credentials = Credentials(username, password, domain, options.ldap_domain)

    ntlm_collector = None
    kerberos_collector = None

    if (options.filter is not None) and (not is_arg_dn(options.filter)):
        logging.error("Filter is not in the correct format. Please enter filter in a DistinguishedName format without trailing DC.")
        sys.exit(1)

    print(f"Welcome to Silverfort Event log collector.")
    if options.ntlm is True:
        ntlm_collector = NTLMCollector(credentials, threads=options.threads, start_date=options.date,
                                       search_base_filter=options.filter, use_ldap=options.ldap)
        print(f"\t{ntlm_collector.workstation_list_size} Domain controllers (NTLM).")

    if options.kerberos:
        kerberos_collector = KerberosCollector(credentials, threads=options.threads, start_date=options.date,
                                               search_base_filter=options.filter, use_ldap=options.ldap)
        print(f"\t{kerberos_collector.workstation_list_size} Endpoints (Kerberos).")
    if input("Do you wish to proceed? (y/N)").lower() != "y":
        sys.exit()
    logging.info("Collecting events...")
    try:
        ntlm_collector.get_evtx_logs()
    except AttributeError:
        pass
    except Exception:
        logging.exception("Error: ")
        sys.exit()

    try:
        kerberos_collector.get_evtx_logs()
    except AttributeError:
        pass
    except Exception:
        logging.exception("Error: ")
        sys.exit()


if __name__ == '__main__':
    main()
