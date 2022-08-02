import networkx as nx
from distinctipy import distinctipy
from latma.configuration.latma_config import EdgeType, EMPTY_COMPONENT, LatmaParams, GifParams
import pandas as pd


def set_edge_title(g: nx.Graph, e: tuple, user: str, ts: str):
    """
    Set a title on the edge
    :param g: The authentication graph
    :param e: The edge to modify
    :param user: The user who performed the authentications
    :param ts: The timestamp the authentication was performed
    :return:
    """
    g.get_edge_data(*e)['title'] = f"At {ts} account {user} advanced from {e[0]} to {e[1]}"


def find_edges_for_presentation(g: nx.Graph) -> nx.Graph:
    """
    Go over all the edges in the graph and take only the ones that need to be presented
    :param g: The authentication graph
    :return: sub graph which contains only the edges that needed to be presented
    """
    orders = {k: v for k, v in sorted(nx.get_edge_attributes(g, 'order').items(), key=lambda item: item[1])}
    last_edge = None
    edges_for_presentation = []
    types = nx.get_edge_attributes(g, 'type_for_presentation')
    node_types = nx.get_node_attributes(g, 'node_type')
    edge_titles = nx.get_edge_attributes(g, 'title')
    node_titles = nx.get_node_attributes(g, 'title')
    users = nx.get_edge_attributes(g, 'username')
    event_times = nx.get_node_attributes(g, 'event_time')
    existing_titles = []
    timestamps = nx.get_edge_attributes(g, 'timestamp')

    for e, order in orders.items():
        # don't show abnormal edges to blast and white canes after they occurred
        if ((types[e] == EdgeType.ABNORMAL_EDGE) and (
                len(node_types[e[1]] & {EdgeType.BLAST, EdgeType.WHITE_CANE, EdgeType.BRIDGE_SWITCH}) == 0)) or (
                (len(node_types[e[1]] & {EdgeType.BLAST, EdgeType.WHITE_CANE}) > 0) and
                min(timestamps[e]) > event_times[e[1]]):
            continue

        # don't show the same event twice
        if edge_titles[e] in existing_titles:
            continue

        # don't show the same event twice
        if (types[e] in [EdgeType.BLAST, EdgeType.WHITE_CANE]) and (node_titles[e[0]] in existing_titles):
            continue

        # don't show several blast or white cane edges
        if (last_edge is not None) and (
                types[last_edge] in [EdgeType.BLAST, EdgeType.WHITE_CANE]) and (last_edge[0] == e[0] and (
                types[e] in [EdgeType.BLAST, EdgeType.WHITE_CANE])) and types[e] == types[last_edge] and (
                node_types[e[1]] not in [EdgeType.BRIDGE_SWITCH, EdgeType.BRIDGE]):
            continue

        # don't show white cane right after blast
        if (last_edge is not None) and (
                types[last_edge] == EdgeType.BLAST) and (types[e] == EdgeType.WHITE_CANE) and last_edge[0] == e[0]:
            continue

        # update abnormal edge title if relevant
        if (types[e] == EdgeType.ABNORMAL_EDGE) and (
                (len(node_types[e[1]] & {EdgeType.BLAST, EdgeType.WHITE_CANE}) > 0) and min(timestamps[e]) <
                event_times[e[1]]):
            ts = max([t for t in timestamps[e] if t < event_times[e[1]]])
            set_edge_title(g, (e[0], e[1], e[2]), users[e], ts)

        existing_titles.append(edge_titles[e])
        if types[e] in [EdgeType.BLAST, EdgeType.WHITE_CANE]:
            existing_titles.append(node_titles[e[0]])
        last_edge = e
        edges_for_presentation.append(e)

    return nx.edge_subgraph(g, edges_for_presentation).copy()


def save_graph_to_file(g: nx.Graph, output_file: str):
    """
    The function saves the graph edges with and their attributes
    :param g: The graph to save
    :param output_file: the place to save
    :return:
    """
    output_list = []
    for e in g.edges:
        edge_data = g.get_edge_data(*e)
        user = edge_data['username']
        auth_types = edge_data['authentication_type']
        times = edge_data['timestamp']
        path_ids = list(edge_data['path_id'])
        for t in times:
            output_list.append(
                {
                    "source": e[0],
                    "dest": e[1],
                    "user": user,
                    "blast": EdgeType.BLAST in auth_types,
                    "white cane": EdgeType.WHITE_CANE in auth_types,
                    "bridge": EdgeType.BRIDGE in auth_types,
                    "bridge switch": EdgeType.BRIDGE_SWITCH in auth_types,
                    "weight shift": EdgeType.WEIGHT_SHIFT in auth_types,
                    "path_ids": path_ids,
                    "time": t
                }
            )
    if len(output_list) > 0:
        output_df = pd.DataFrame(output_list)
        output_df.sort_values(by=['time'], inplace=True)
        output_df.to_csv(output_file, index=False)


def find_connected_components_and_colors(g: nx.Graph, show_all_iocs: bool) -> tuple:
    """
    Devide all the nodes to connected components - all the nodes that are part of a lateral movement will be part of
    the same component
    :param g: The authentication graph
    :param show_all_iocs: If True, show all the events event if they are not connected, if false, show only connected
    events
    :return: return a dict of all the connected components and their colors for presentation
    """
    colors = distinctipy.get_colors(GifParams.MAX_NUMBER_OF_COLORS)
    node2colors = {}
    connected_component_id = {}
    for node in g.nodes:
        connected_component_id[node] = EMPTY_COMPONENT

    for i, component in enumerate(nx.weakly_connected_components(g)):

        if not show_all_iocs and (len(component) < LatmaParams.MAXIMUM_NODES_IN_COMPONENT):
            continue

        for node in component:
            connected_component_id[node] = str(i)
            node2colors[node] = colors[i % GifParams.MAX_NUMBER_OF_COLORS]

    return connected_component_id, node2colors


def visualize_suspected_lateral_movements(g: nx.Graph, report_maker, gif_maker, gant_maker=None, show_all_iocs=False):
    """
    Takes the edges by their order and plot them on the same timeline
    :param gant_maker:
    :param gif_maker:
    :param report_maker:
    :param g: propagation graph for presentation
    :param show_all_iocs: show all the IoCs found even if they are not connected
    :return:
    """
    types = nx.get_edge_attributes(g, 'type_for_presentation')
    timestamps = nx.get_edge_attributes(g, 'timestamp')
    edge_titles = nx.get_edge_attributes(g, 'title')
    node_titles = nx.get_node_attributes(g, 'title')

    sub_g = find_edges_for_presentation(g)
    orders = {k: v for k, v in sorted(nx.get_edge_attributes(sub_g, 'order').items(), key=lambda item: item[1])}
    connected_component_id, node2colors = find_connected_components_and_colors(sub_g, show_all_iocs)

    if gant_maker:
        gant_maker.build_gant(orders, connected_component_id, types, timestamps, node_titles, edge_titles)
        gant_maker.show_events_on_gant()

    if gif_maker:
        gif_maker.prepare_data_for_gif(sub_g, orders, connected_component_id, types, node2colors)
        gif_maker.generate_progression_gif(node2colors)

    if report_maker:
        report_maker.prepare_metadata_for_report(sub_g, orders, connected_component_id, types)
        report_maker.generate_lateral_movement_timeline(orders, connected_component_id)

