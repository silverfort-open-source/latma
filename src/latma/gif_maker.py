from matplotlib.legend import Legend
from matplotlib.animation import FuncAnimation
import matplotlib.pyplot as plt
from matplotlib.lines import Line2D
from moviepy.video.io.VideoFileClip import VideoFileClip
from networkx.classes.reportviews import NodeView
from latma.configuration.latma_config import GifParams as GP, OutputFiles, LW_MAP, EdgeType, EMPTY_COMPONENT
import networkx as nx


class GifMaker:
    def __init__(self, show_all_iocs=False):
        self.fig_size = GP.FIG_SIZE
        self.interval = GP.INTERVAL
        self.gif_output = OutputFiles.PROPAGATION_GIF
        self.mp4output = OutputFiles.PROPAGATION_MP4
        self.gif_titles = []
        self.gif_recent_edges = []
        self.recent_event = []
        self.blast_nodes = [[]]
        self.white_cane_nodes = [[]]
        self.gs = []
        self.show_all_iocs = show_all_iocs

    @staticmethod
    def draw_graph_nodes(g: nx.Graph, relevant_nodes: NodeView, pos: dict, blast_nodes: list, white_cane_nodes: list,
                         last_active_nodes: set, labels: dict, ax: plt.axes, show_legend: bool):
        """
        draw the graph filtered on specific nodes and labels
        :param g: authentication graph
        :param relevant_nodes: which nodes to draw
        :param pos: position of the nodes
        :param blast_nodes:
        :param white_cane_nodes:
        :param last_active_nodes:
        :param labels: dictionary that maps nodes to labels
        :param ax: the desired sub-figure
        :param show_legend: whether to show the legend or not
        :return:
        """
        if blast_nodes is None:
            blast_nodes = [node for node in g.nodes if EdgeType.BLAST in g.nodes[node]['node_type']]

        if white_cane_nodes is None:
            white_cane_nodes = [node for node in g.nodes if EdgeType.WHITE_CANE in g.nodes[node]['node_type']]

        nx.draw_networkx_nodes(g.subgraph(relevant_nodes), pos, node_color=GP.DEFAULT_NODE_COLOR,
                               node_size=GP.DEFAULT_NODE_SIZE, alpha=1, label=GP.MACHINE_LABEL, ax=ax)
        nx.draw_networkx_nodes(g.subgraph(blast_nodes), pos, node_color=GP.DEFAULT_BLAST_NODE_COLOR,
                               node_size=GP.BLAST_NODE_SIZE, alpha=1, label=GP.BLAST_LABEL, ax=ax)
        nx.draw_networkx_nodes(g.subgraph(set(white_cane_nodes) - set(blast_nodes)), pos,
                               node_color=GP.DEFAULT_WHITE_CANE_NODE_COLOR,
                               node_size=GP.WHITE_CANE_NODE_SIZE, alpha=1, label=GP.WHITE_CANE_LABEL, ax=ax)

        filtered_labels = dict([(k, v) for k, v in labels.items() if
                                v in set(relevant_nodes) | set(blast_nodes) | set(white_cane_nodes)])

        nx.draw_networkx_nodes(g.subgraph(last_active_nodes), pos, node_color=GP.DEFAULT_NODE_COLOR,
                               node_size=GP.DEFAULT_NODE_SIZE * 4, alpha=1, ax=ax)

        # draw blast
        nx.draw_networkx_nodes(g.subgraph(set(blast_nodes) & set(last_active_nodes)), pos,
                               node_color=GP.DEFAULT_BLAST_NODE_COLOR, node_size=GP.BLAST_NODE_SIZE * 4, alpha=1, ax=ax)

        nx.draw_networkx_nodes(g.subgraph(set(blast_nodes) & set(last_active_nodes)), pos,
                               node_color=GP.DEFAULT_BLAST_NODE_COLOR, node_size=GP.BLAST_NODE_SIZE * 12, alpha=0.5,
                               ax=ax)

        nx.draw_networkx_nodes(g.subgraph(set(blast_nodes) & set(last_active_nodes)), pos,
                               node_color=GP.DEFAULT_BLAST_NODE_COLOR, node_size=GP.BLAST_NODE_SIZE * 24, alpha=0.25,
                               ax=ax)

        # draw white cane
        nx.draw_networkx_nodes(g.subgraph(set(white_cane_nodes) - set(blast_nodes) & set(last_active_nodes)), pos,
                               node_color=GP.DEFAULT_WHITE_CANE_NODE_COLOR, node_size=GP.WHITE_CANE_NODE_SIZE * 4,
                               alpha=1, ax=ax)

        nx.draw_networkx_nodes(g.subgraph(set(white_cane_nodes) - set(blast_nodes) & set(last_active_nodes)), pos,
                               node_color=GP.DEFAULT_WHITE_CANE_NODE_COLOR, node_size=GP.WHITE_CANE_NODE_SIZE * 12,
                               alpha=0.5, ax=ax)

        nx.draw_networkx_labels(g.subgraph(set(blast_nodes) | set(white_cane_nodes)), pos, filtered_labels,
                                font_size=16, ax=ax)

        def make_edge_proxy(clr, mappable, **kwargs):
            return Line2D([0, 1], [0, 1], color=clr, **kwargs)

        proxies = [
            make_edge_proxy('blue', ax, lw=LW_MAP[EdgeType.ABNORMAL_EDGE]),
            make_edge_proxy('red', ax, lw=LW_MAP[EdgeType.BLAST]),
            make_edge_proxy('green', ax, lw=LW_MAP[EdgeType.WEIGHT_SHIFT]),
            make_edge_proxy('yellow', ax, lw=LW_MAP[EdgeType.WHITE_CANE]),
            make_edge_proxy('black', ax, lw=LW_MAP[EdgeType.BRIDGE_SWITCH]),
            make_edge_proxy('pink', ax, lw=LW_MAP[EdgeType.BRIDGE])
        ]

        if show_legend:
            edge_labels = [EdgeType.ABNORMAL_EDGE, EdgeType.BLAST, EdgeType.WEIGHT_SHIFT, EdgeType.WHITE_CANE,
                           EdgeType.BRIDGE_SWITCH, EdgeType.BRIDGE]
            leg = Legend(ax, proxies, edge_labels, loc='upper left', fontsize='large')
            ax.add_artist(leg)

        ax.legend(scatterpoints=1, prop={"size": 30})

    def show_frame(self, g: nx.Graph, pos: dict, title: str, ax: plt.axes, blast_nodes=None,
                   white_cane_nodes=None, last_active_edges=None, show_legend=True, node2colors=None):
        """
        draw the abnormal authentication graph, the lateral movement progression, lateral movement done by single
        attacker and the blasts and white canes
        :param node2colors:
        :param blast_nodes:
        :param white_cane_nodes:
        :param g: The authentication graph
        :param pos: The position of all the nodes
        :param title: the figure's title
        :param ax: on which sub_figure to draw the image
        :param last_active_edges: The edgeS with the latest timestamp, will be colored in a different color
        :param show_legend: whether to show the legend or not
        :return:
        """
        if pos is None:
            pos = nx.spring_layout(g)

        ax.set_title(title, fontdict={'fontsize': GP.DEFAULT_FONT_SIZE})

        # initialize local variables
        machine_names = dict()
        entire_graph_relevant_nodes = set()

        for e in g.edges:
            # extract info from edges
            source = e[0]
            dest = e[1]
            curv = e[2]
            edge_data = g.get_edge_data(*e)
            if node2colors is None:
                color = edge_data['color']
            else:
                color = node2colors[e[0]]
            label = edge_data['label']
            lw = edge_data['lw']

            machine_names[e[0]] = e[0]
            machine_names[e[1]] = e[1]

            line_style = GP.DEFAULT_LINE_STYLE
            if last_active_edges is not None:
                if e in last_active_edges:
                    line_style = GP.SPECIAL_LINE_STYLE

                else:
                    color = node2colors[e[0]]

            # update relevant nodes
            entire_graph_relevant_nodes.add(source)
            entire_graph_relevant_nodes.add(dest)

            # show colored graph
            ax.annotate("", xy=pos[dest], xycoords='data', xytext=pos[source], textcoords='data',
                        arrowprops=dict(arrowstyle='->', color=color, label=label, lw=lw,
                                        shrinkA=5, shrinkB=5, linestyle=line_style,
                                        patchA=None, patchB=None,
                                        connectionstyle="arc3,rad=rrr".replace('rrr', str(
                                            0.3 * curv)
                                                                               ),
                                        ),
                        )
        last_active_nodes = set()
        if last_active_edges:
            for e in last_active_edges:
                last_active_nodes.add(e[0])
                last_active_nodes.add(e[1])

        if blast_nodes:
            for node in blast_nodes:
                last_active_nodes.add(node)

        if white_cane_nodes:
            for node in white_cane_nodes:
                last_active_nodes.add(node)

        self.draw_graph_nodes(g, g.nodes, pos, blast_nodes, white_cane_nodes, last_active_nodes, machine_names, ax,
                              show_legend)

    def generate_progression_gif(self, node2colors):
        """
        :param node2colors: dictionary of nodes->colors
        :return:
        """
        if len(self.gs) > 0:
            plt.rcParams["figure.figsize"] = (self.fig_size, self.fig_size)
            fig = plt.figure()
            ax1 = plt.axes()
            pos = nx.random_layout(self.gs[-1])

            def update(i):
                ax1.clear()
                self.show_frame(self.gs[i], pos=pos, title=self.gif_titles[i], ax=ax1,
                                blast_nodes=self.blast_nodes[i + 1], white_cane_nodes=self.white_cane_nodes[i + 1],
                                last_active_edges=self.gif_recent_edges[i], show_legend=False, node2colors=node2colors)

            def init_func() -> nx.Graph:
                return nx.MultiDiGraph()

            # create the gif
            ani = FuncAnimation(fig, update, interval=self.interval, init_func=init_func, frames=len(self.gs),
                                blit=False)
            ani.save(self.gif_output, writer='imagemagick')
            clip = VideoFileClip(self.gif_output)
            clip.write_videofile(self.mp4output)
            clip.close()

    def prepare_data_for_gif(self, g, orders, connected_component_id, types, node2colors):
        edges_for_presentation = []
        edge_titles = nx.get_edge_attributes(g, 'title')
        node_titles = nx.get_node_attributes(g, 'title')

        for e, order in orders.items():
            if connected_component_id[e[0]] == EMPTY_COMPONENT:
                continue

            if (types[e] == EdgeType.BLAST) or (types[e] == EdgeType.WHITE_CANE):

                # GIF preparations
                self.gif_titles.append(node_titles[e[0]])
                self.gif_recent_edges.append([])
                if types[e] == EdgeType.BLAST:
                    self.blast_nodes.append(self.blast_nodes[-1] + [e[0]])
                    self.white_cane_nodes.append(self.white_cane_nodes[-1])

                else:
                    self.white_cane_nodes.append(self.white_cane_nodes[-1] + [e[0]])
                    self.blast_nodes.append(self.blast_nodes[-1])

            else:
                # GIF preparations
                self.gif_titles.append(edge_titles[e])
                if types[e] in [EdgeType.BRIDGE_SWITCH, EdgeType.BRIDGE]:

                    bridge_info = g.get_edge_data(*e)['bridge_info']
                    first_edge = (bridge_info['source'], bridge_info['middle'], bridge_info['first_curv'])
                    second_edge = (bridge_info['middle'], bridge_info['dest'], bridge_info['second_curv'])
                    self.gif_recent_edges.append([first_edge, second_edge])
                    edges_for_presentation.append(first_edge)
                    edges_for_presentation.append(second_edge)

                    # adjust colors accordingly
                    node2colors[first_edge[0]] = node2colors[first_edge[1]]
                    node2colors[second_edge[0]] = node2colors[second_edge[1]]

                # Weight shift
                else:
                    edges_for_presentation.append(e)
                    self.gif_recent_edges.append([e])

                self.blast_nodes.append(self.blast_nodes[-1])
                self.white_cane_nodes.append(self.white_cane_nodes[-1])

            self.gs.append(g.edge_subgraph(edges_for_presentation).copy(edges_for_presentation))
