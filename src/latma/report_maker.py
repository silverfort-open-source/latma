import networkx as nx
from latma.configuration.latma_config import EdgeType, EMPTY_COMPONENT


class LateralMovementReport:
    def __init__(self, timeline_output_file):
        self.timeline_output_file = timeline_output_file
        self.suspected_compromised_accounts = set()
        self.suspected_compromised_machines = set()
        self.edge_titles = dict()
        self.suspicious_for_lateral_movement = False
        self.users = {}
        self.edge_titles = {}

    def prepare_metadata_for_report(self, g, orders, connected_component_id, types):
        self.users = nx.get_edge_attributes(g, 'username')
        self.edge_titles = nx.get_edge_attributes(g, 'title')
        for e, order in orders.items():
            if connected_component_id[e[0]] == EMPTY_COMPONENT:
                continue

            if (types[e] == EdgeType.BLAST) or (types[e] == EdgeType.WHITE_CANE):
                # Report preparations
                self.suspected_compromised_accounts.add(self.users[e])
                self.suspected_compromised_machines.add(e[0])
                self.suspicious_for_lateral_movement = True

    def generate_lateral_movement_timeline(self, orders: dict, connected_component_id: dict):
        """
        Takes some of the outputs of the lateral movement funcs and summarizes them in a report
        :param timeline_output_file: output file
        :param users: dictionary from edge to user
        :param connected_component_id: dict from an edge to its connected component
        :param compromised_accounts: list of compromised accounts
        :param compromised_machines: list of compromised machine
        :param orders: dict that maps edges to their order in the presentation
        :param edge_titles: dictionary that maps edges to the titles they have
        :param suspicious_for_lateral_movement: whether the movement is suspicious or not
        :return:
        """
        connected_components = sorted(set(connected_component_id.values()))
        index = 1
        if self.timeline_output_file:
            f = open(self.timeline_output_file, 'w')
            f.write("-------- Lateral Movement Analyzer Conclusions --------\n")

            if not self.suspicious_for_lateral_movement:
                f.write("The detected events do not indicate presence of lateral movement in the environment \n\n")

            else:
                f.write("The detected events indicate presence of lateral movement in the environment \n\n")

            if self.suspected_compromised_accounts:
                f.write("The following accounts are suspected to be compromised:\n")
                for account in self.suspected_compromised_accounts:
                    f.write(account)
                    f.write('\n')

            f.write('\n')
            if self.suspected_compromised_machines:
                f.write("The following machines are suspected to be the lateral movement’s main advance path:\n")
                for machine in self.suspected_compromised_machines:
                    f.write(machine)
                    f.write('\n')

                f.write(
                    "\nIf your investigation validates that these machines are indeed compromised refer to the full "
                    "list of machines in propagation.csv\n")
            f.write("\n")
            for c in connected_components:
                if c == EMPTY_COMPONENT:
                    continue

                f.write(f"{index}: Lateral movement chain of events \n")
                f.write("-------------\n")

                index += 1
                previous_user = None
                for e, order in orders.items():
                    if connected_component_id[e[0]] != c:
                        continue

                    if previous_user and previous_user != self.users[e]:
                        f.write("USER CHANGED \n")

                    f.write(self.edge_titles[e])
                    f.write('\n')
                    previous_user = self.users[e]

                f.write("\n")
            f.close()
