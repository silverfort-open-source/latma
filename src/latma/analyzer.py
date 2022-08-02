import pandas as pd
import datetime as dt
import argparse
import networkx as nx
import logging

from latma.configuration.latma_config import COLOR_MAP, LW_MAP, NodeType, EdgeType, LatmaParams, OutputFiles
from latma.event_utils import find_progression_in_graph, update_edge_properties, find_weight_shift, \
    find_special_events
from latma.visualization_utils import visualize_suspected_lateral_movements, save_graph_to_file
from latma.gant_maker import GantMaker
from latma.gif_maker import GifMaker
from latma.report_maker import LateralMovementReport


class Latma:
    # df is a dataframe of the form hostname, server, user_identifier, SPN, timestamp
    def __init__(self, input_file, learning_period=None, blast_node_threshold=None,
                 white_cane_threshold=LatmaParams.WHITE_CANE_THRESHOLD, blast_period=LatmaParams.BLAST_PERIOD,
                 white_can_period=LatmaParams.WHITE_CANE_PERIOD, bridge_diff=LatmaParams.MINIMUM_TIME_FOR_BRIDGE):
        self.df = pd.read_csv(input_file)
        # convert timestamp to datetime object
        try:
            self.df['timestamp'] = pd.to_datetime(self.df['timestamp'], format='%d/%m/%Y %H:%M')
        except:
            self.df['timestamp'] = pd.to_datetime(self.df['timestamp'])

        self.df['username'] = self.df['username'].apply(lambda x: str(x))
        self.df['destination'] = self.df['destination'].apply(lambda x: str(x))
        self.df['source host'] = self.df['source host'].apply(lambda x: str(x))
        self.df.sort_values(by='timestamp')
        self.enrich_df()
        self.sinks = []
        self.hubs = []
        self.n_users = self.df['username'].nunique()
        self.n_machines = len(set(self.df['source host'].unique()) | set(self.df['destination'].unique()))

        if blast_node_threshold is None:
            self.blast_node_threshold = self.n_machines / 3
        else:
            self.blast_node_threshold = blast_node_threshold
        self.white_cane_threshold = white_cane_threshold
        self.blast_period = dt.timedelta(minutes=blast_period)
        self.white_cane_period = dt.timedelta(minutes=white_can_period)
        self.bridge_diff = dt.timedelta(minutes=bridge_diff)

        self.sink_threshold = self.find_sink_threshold()
        self.hub_threshold = self.find_hub_threshold()
        self.first_auth = min(self.df['timestamp'])
        self.auth_graph = nx.MultiDiGraph()
        if learning_period is None:
            learning_period = LatmaParams.LEARNING_PERIOD

        self.pre_learning_period_df = self.df[
            self.df['timestamp'] < self.first_auth + dt.timedelta(days=learning_period)]
        self.post_learning_period_df = self.df[
            self.df['timestamp'] >= self.first_auth + dt.timedelta(days=learning_period)]
        if len(self.post_learning_period_df) == 0:
            logging.info(
                "All data belongs to learning period, please provide more data or make the learning period shorter")
            exit()
        self.user_machine_matches = dict()
        self.pos = None

    def enrich_df(self):
        """
        add the date to the graph without the hour, minutes and seconds
        :return:
        """
        self.df['date'] = self.df.timestamp.apply(lambda x: x.strftime("%m/%d/%Y"))

    def find_sinks(self):
        """
        find machines that many different users authenticate within the learning period
        :return:
        """
        self.sinks = set(self.pre_learning_period_df[
                             self.pre_learning_period_df.groupby('destination')['username'].transform(
                                 'nunique') > self.sink_threshold]['destination'])
        logging.info("sinks are {0}".format(self.sinks))

    def find_hubs(self):
        """
        find machines that many different users authenticate from in the learning period
        :return:
        """
        self.hubs = set(self.pre_learning_period_df[
                            self.pre_learning_period_df.groupby('source host')['username'].transform(
                                'nunique') > self.hub_threshold]['source host'])
        logging.info(f"hubs are {self.hubs}")

    def find_sink_threshold(self) -> int:
        """
        find a threshold from which an account is considered a sink, this parameter was tuned based on data from live environments
        :return:
        """
        if self.n_users < LatmaParams.MAX_USERS_TO_APPLY_DEFAULT_PARAMS:
            return LatmaParams.SINK_MINIMUM_USERS
        else:
            # threshold according to exploration in real environment
            return int(self.n_users // 3 - 5)

    def find_hub_threshold(self) -> int:
        """
        find a threshold from which an account is considered a sink, this parameter was tuned based on data from live environments
        :return:
        """
        if self.n_users < LatmaParams.MAX_USERS_TO_APPLY_DEFAULT_PARAMS:
            return LatmaParams.HUB_MINIMUM_USERS
        else:
            # threshold according to exploration in real environment
            return int(self.n_users // 3 + 30)

    def match_users_to_machine(self):
        """
        find which machines are owned by which accounts
        :return:
        """
        partial_df = self.df.groupby(['source host', 'username']).filter(
            lambda x: x['date'].nunique() > LatmaParams.MINIMUM_DAYS_FOR_MATCH)
        self.user_machine_matches = partial_df.groupby('source host')['username'].apply(set).to_dict()

    def process_data(self):
        """
        analyze the data after the learning period - build the authentication graph based on post learning period data
        :return:
        """
        partial_df = self.post_learning_period_df.groupby(['source host', 'destination', 'username'])[
            'timestamp'].apply(list)

        self.find_sinks()
        self.find_hubs()

        # add edges to the graph
        for e, v in partial_df.items():
            # add only suspicious edges
            if e[1] in self.sinks or e[0] in self.hubs:
                continue

            if e[2] not in self.user_machine_matches.get(e[0], []) and e[0] != e[1]:
                if e[0] not in self.auth_graph.nodes:
                    self.auth_graph.add_node(e[0], node_type=set())
                if e[1] not in self.auth_graph.nodes:
                    self.auth_graph.add_node(e[1], node_type=set())

                user = e[2]
                ts = min(v)
                title = f"At {ts} account {user} advanced from {e[0]} to {e[1]}"
                self.auth_graph.add_edge(e[0], e[1], username=user, timestamp=v,
                                         color=COLOR_MAP[EdgeType.ABNORMAL_EDGE], authentication_type=set(),
                                         lw=LW_MAP[EdgeType.ABNORMAL_EDGE], label=EdgeType.ABNORMAL_EDGE, path_id=set(),
                                         title=title)

    def bfs_auth_graph(self, node: str, visited_nodes: set, edges: set, last_date_seen=None, last_user=None,
                       last_machine=None, previous_curv=0):
        """
        iterate over the authentication graph and finds paths consistent with time that suspected as lateral movement
        sub-graphs
        :param previous_curv:
        :param node: node to start the bfs process from
        :param visited_nodes: the graph nodes visited during the run
        :param edges: the visited edges during the run
        :param last_date_seen: the last minimal timestamp seen that is consistent with the path
        :param last_user: the last user that performed the authentication
        :param last_machine: the machine from which the account authenticated in the previous step
        :return:
        """
        visited_nodes.add(node)
        diff = None
        for neighbor in self.auth_graph[node]:
            # don't visit the same node twice

            if neighbor in visited_nodes:
                continue

            # there might be several edges from the same source to the same destination since it is a multi-graph
            for k, v in self.auth_graph[node][neighbor].items():
                if not last_date_seen or last_date_seen <= max(v['timestamp']):
                    # take the minimal timestamp that is consistent with the path
                    if not last_date_seen:
                        last_date_seen = min(v['timestamp'])
                    else:
                        diff = min(t for t in v['timestamp'] if t >= last_date_seen) - last_date_seen
                        last_date_seen = min(t for t in v['timestamp'] if t >= last_date_seen)

                    # add tags
                    if last_user is None:
                        pass

                    elif last_user == v['username']:
                        if diff <= self.bridge_diff:
                            update_edge_properties(v, EdgeType.BRIDGE)
                            self.auth_graph.nodes[node]['node_type'].add(NodeType.BRIDGE)
                            self.auth_graph.nodes[last_machine]['node_type'].add(NodeType.BRIDGE)
                            v['title'] = f"At {last_date_seen} account {v['username']} performed a bridge" \
                                f" advance from {last_machine} via {node} to {neighbor}"
                            v['bridge_info'] = {"source": last_machine, "middle": node, "dest": neighbor,
                                                "first_curv": previous_curv, "second_curv": k}

                    else:
                        if diff <= self.bridge_diff:
                            update_edge_properties(v, EdgeType.BRIDGE_SWITCH)
                            self.auth_graph.nodes[node]['node_type'].add(NodeType.BRIDGE_SWITCH)
                            self.auth_graph.nodes[last_machine]['node_type'].add(NodeType.BRIDGE_SWITCH)
                            v['title'] = f"At {last_date_seen} account {last_user} and account {v['username']} " \
                                f"performed switched bridge from {last_machine} to {neighbor} via {node}"
                            v['bridge_info'] = {"source": last_machine, "middle": node, "dest": neighbor,
                                                "first_curv": previous_curv, "second_curv": k}

                    edges.add((node, neighbor, k))
                    # tag edge
                    self.bfs_auth_graph(neighbor, visited_nodes, edges, last_date_seen, v['username'], node, k)

                # time is not consistent
                else:
                    continue

        return self.auth_graph.edge_subgraph(edges).copy()

    def find_suspected_lateral_movement_sub_graphs(self):
        """
        find all the sub-graphs that represent suspected lateral movement
        :return:
        """
        path_id = 1
        for node in self.auth_graph.nodes():
            path = self.bfs_auth_graph(node, set(), set(), None, None, None)
            # add only length 2 or more paths
            if nx.dag_longest_path_length(path) >= LatmaParams.MINIMAL_LATERAL_MOVEMENT_PATH_LENGTH:
                for e in path.edges:
                    path.get_edge_data(*e)['path_id'].add(path_id)
                path_id += 1


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("authentication_file",
                        help="authentication file should contain list of NTLM and Kerberos requests")
    parser.add_argument("-of", "--output_file",
                        help="The location the csv with the all the IOCs is going to be saved to",
                        default=OutputFiles.ALL_AUTHENTICATION_CSV)
    parser.add_argument("-pof", "--progression_output_file",
                        help="The location the csv with the the IOCs of the lateral movements is going to be save to",
                        default=OutputFiles.PROPAGATION_CSV)
    parser.add_argument("-st", "--sink_threshold", help="number of accounts from which a machine is considered sink",
                        default=50, type=int)
    parser.add_argument("-ht", "--hub_threshold", help="number of accounts from which a machine is considered hub",
                        default=20, type=int)
    parser.add_argument("-lp", "--learning_period", help="learning period in days", default=7, type=int)
    parser.add_argument("-sai", "--show_all_iocs", action='store_true',
                        help="If true, show all the IoC even if they are not connected to each other")
    parser.add_argument("-sg", "--show_gant", action='store_true',
                        help="If true, output the events in a gant format")

    args = parser.parse_args()
    logging.getLogger().setLevel(logging.INFO)
    logging.info("Initializing objects")
    ltm = Latma(args.authentication_file, args.learning_period)
    logging.info("matching users to machines")
    ltm.match_users_to_machine()
    logging.info("processing authentications...")
    ltm.process_data()
    logging.info("find white canes")
    find_special_events(ltm.auth_graph, ltm.white_cane_period, ltm.white_cane_threshold, EdgeType.WHITE_CANE)
    logging.info("find blasts")
    find_special_events(ltm.auth_graph, ltm.blast_period, ltm.blast_node_threshold, EdgeType.BLAST)
    logging.info("finding lateral movement graphs...")
    ltm.find_suspected_lateral_movement_sub_graphs()
    logging.info("find weight shifts")
    find_weight_shift(ltm.auth_graph)
    logging.info("analyzing lateral movement graphs...")
    progression_graph = find_progression_in_graph(ltm.auth_graph)
    logging.info("progression graph has {} nodes and {} edges".format(len(progression_graph.nodes),
                                                                      len(progression_graph.edges)))
    logging.info("creating progression GIF")
    gif_maker = GifMaker(args.show_all_iocs)
    report_maker = LateralMovementReport(OutputFiles.TIMELINE_FILE)
    gant_maker = None
    if args.show_gant:
        gant_maker = GantMaker()

    visualize_suspected_lateral_movements(progression_graph, report_maker, gif_maker, gant_maker)
    logging.info("Saving results to a file")
    save_graph_to_file(ltm.auth_graph, args.output_file)
    save_graph_to_file(progression_graph, args.progression_output_file)


if __name__ == '__main__':
    main()
