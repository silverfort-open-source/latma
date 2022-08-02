import networkx as nx
import datetime as dt
from latma.configuration.latma_config import NodeType, EdgeType, COLOR_MAP, LW_MAP


def get_type_for_presentation(types: list) -> EdgeType:
    """
    take all the type of an edge and return the most relevant one
    :param types: type of authentication
    :return: most relevant authentication type
    """
    if EdgeType.BLAST in types:
        return EdgeType.BLAST

    if EdgeType.WEIGHT_SHIFT in types:
        return EdgeType.WEIGHT_SHIFT

    if EdgeType.WHITE_CANE in types:
        return EdgeType.WHITE_CANE

    if EdgeType.BRIDGE_SWITCH in types:
        return EdgeType.BRIDGE_SWITCH

    if EdgeType.BRIDGE in types:
        return EdgeType.BRIDGE

    return EdgeType.ABNORMAL_EDGE


def update_edge_properties(e: dict, edge_type: str):
    """
    Update the edge properties by its type
    :param e: edge
    :param edge_type: IoC associated with the edge
    :return:
    """
    e['authentication_type'].add(edge_type)
    e['color'] = COLOR_MAP[get_type_for_presentation(e['authentication_type'])]
    e['lw'] = LW_MAP[edge_type]
    e['label'] = edge_type


def set_node_title(u: str, source: str, e_type: str, n: int, t: str) -> str:
    """
    Setting title on an edge
    :param t:
    :param u: user
    :param source: source machine
    :param e_type: type of event
    :param n: number of event
    :return:
    """
    if e_type == EdgeType.BLAST:
        return f"At {t} account {u} performed a blast advance from {source} to {n} machines"
    if e_type == EdgeType.WHITE_CANE:
        return f"At {t} account {u} performed white cane search from {source} to {n} machines"
    return ""


def find_weight_shift(g: nx.Graph):
    """
    Find edges that connects two white canes, or a white cane and a blast
    :param g: A graph in which the weight shifts are searched in
    :return:
    """
    node_types = nx.get_node_attributes(g, 'node_type')
    events_times = nx.get_node_attributes(g, 'event_time')
    timestamps = nx.get_edge_attributes(g, 'timestamp')

    for e in g.edges:
        if (len({NodeType.WHITE_CANE, NodeType.BLAST} & node_types[e[0]]) > 0) and (
                (len({NodeType.WHITE_CANE, NodeType.BLAST} & node_types[e[1]])) > 0):
            if any([t for t in timestamps[e] if events_times[e[0]] <= t <= events_times[e[1]]]):
                event_time = min([t for t in timestamps[e] if events_times[e[0]] <= t <= events_times[e[1]]])
                update_edge_properties(g.get_edge_data(*e), EdgeType.WEIGHT_SHIFT)
                g.get_edge_data(*e)['title'] = f"At {event_time} account " \
                    f"{g.get_edge_data(*e)['username']} performed weight shift advance from {e[0]} to {e[1]}"


def find_consecutive_events_in_window(arr: list, max_window_size: dt.timedelta, minimum_number_of_edges: int,
                                      minimum_number_of_events: int) -> (list, dt.datetime):
    """
    finds number of occurrences of different event in a time window
    :param minimum_number_of_edges: minimum number of edges for the event
    :param arr: array of (timestamp, edge_id) sorted by timestamp
    :param max_window_size: max window size
    :param minimum_number_of_events: number of distinct events in the window
    :return:
    """
    indices_to_remove = []
    first_timestamp = None
    if len(arr) < minimum_number_of_edges:
        return indices_to_remove, first_timestamp

    # pre-processing - eliminate edges that cannot be in any time window with other edges
    index_can_be_removed = True
    for i in range(len(arr) - 1):
        if arr[i + 1][0] - arr[i][0] > max_window_size and index_can_be_removed:
            indices_to_remove.append(i)

        if arr[i + 1][0] - arr[i][0] > max_window_size:
            index_can_be_removed = True

        else:
            index_can_be_removed = False

    # split to buckets by timestamp and count distinct edges in each bucket
    buckets = {}
    for i in range(len(arr)):
        if i in indices_to_remove:
            first_timestamp = None
            continue

        if first_timestamp is None:
            first_timestamp = arr[i][0]
            buckets[first_timestamp] = [arr[i]]

        else:
            if arr[i][0] - first_timestamp <= max_window_size * 2:
                buckets[first_timestamp].append(arr[i])

            else:
                first_timestamp = None

    edges_to_mark = []
    for bucket in buckets.values():
        if len(bucket) >= minimum_number_of_events:
            if len(set([element[1] for element in bucket])) >= minimum_number_of_events:
                edges_to_mark.extend(bucket)

    return edges_to_mark, first_timestamp


# find blast_nodes and mark the edges that belong to the blast
def find_special_events(g: nx.MultiDiGraph, max_duration: dt.timedelta, minimum_number_of_edges: int,
                        event_type: EdgeType):
    """
    find many abnormal authentications from specific node within a short period
    :return:
    """
    # candidates of nodes that cam be associated with the event
    candidates = [node for node in g.nodes if g.out_degree(node) > minimum_number_of_edges]

    for node in candidates:
        # check who are the users that might be responsible for the event
        relevant_users = set([g.get_edge_data(*e)['username'] for e in g.edges if e[0] == node])
        for user in relevant_users:
            filtered_edges = []
            # prepare edges for algorithm
            for e in g.edges:
                # go over all the action done by this user
                edge_data = g.get_edge_data(*e)
                if (edge_data['username']) == user and (e[0] == node):
                    # go over all the timestanps
                    for t in edge_data['timestamp']:
                        filtered_edges.append((t, e))

            filtered_edges.sort(key=lambda x: x[0])
            # mark all the edges that are part of the events
            marked_edges, ts = find_consecutive_events_in_window(filtered_edges, max_duration, minimum_number_of_edges,
                                                                 minimum_number_of_edges)

            # find the biggest possible window in the data
            for e in marked_edges:
                update_edge_properties(g.get_edge_data(*e[1]), event_type)
                g.get_edge_data(*e[1])['title'] = set_node_title(user, node, event_type, len(marked_edges), ts)

            # mark the edges
            if len(marked_edges) > 0:
                if event_type == EdgeType.BLAST:
                    g.nodes[node]['node_type'].add(NodeType.BLAST)
                    g.nodes[node]['event_time'] = ts

                if event_type == EdgeType.WHITE_CANE:
                    g.nodes[node]['node_type'].add(NodeType.WHITE_CANE)
                    g.nodes[node]['event_time'] = ts
                g.nodes[node]['title'] = set_node_title(user, node, event_type, len(marked_edges), ts)


def find_progression_in_graph(g: nx.Graph) -> nx.Graph:
    """
    look for weight shift, bridges, bridge switch and edges edges that are connected to those edges and put them on
    the same graph
    :return: sub-graph the contains the progression
    """
    progression_edges = set()
    # create a sub-graph
    for e in g.edges:
        auth_types = g.get_edge_data(*e)['authentication_type']
        dest_types = g.nodes[e[1]]['node_type']
        g.get_edge_data(*e)['type_for_presentation'] = get_type_for_presentation(auth_types)
        if (auth_types & {EdgeType.WEIGHT_SHIFT, EdgeType.BRIDGE_SWITCH, EdgeType.BRIDGE, EdgeType.BLAST,
                          EdgeType.WHITE_CANE}) or (
                dest_types & {NodeType.BRIDGE, NodeType.BRIDGE_SWITCH, NodeType.BLAST, NodeType.WHITE_CANE}):
            progression_edges.add(e)

    sub_g = g.edge_subgraph(progression_edges).copy()

    # order edges
    order = 0
    for i in range(len(sub_g.edges)):
        min_ts = None
        current_edge = None
        last_type = None

        for e in sub_g.edges:
            edge_data = sub_g.get_edge_data(*e)
            if 'order' not in edge_data:
                # give less priority yo weight shift when choosing the order
                if edge_data['type_for_presentation'] == EdgeType.WEIGHT_SHIFT:
                    if min_ts is None or min(edge_data['timestamp']) < min_ts:
                        current_edge = e
                        min_ts = min(edge_data['timestamp'])
                        last_type = edge_data['type_for_presentation']
                else:
                    # blast has priority
                    if (last_type is not None) and (min_ts is not None) and (
                            min(edge_data['timestamp']) == min_ts) and last_type == EdgeType.BLAST:
                        continue

                    if min_ts is None or min(edge_data['timestamp']) <= min_ts:
                        current_edge = e
                        min_ts = min(edge_data['timestamp'])
                        last_type = edge_data['type_for_presentation']
        sub_g.get_edge_data(*current_edge)['order'] = order

        order += 1
    return sub_g
