import plotly.express as px
from latma.configuration.latma_config import EMPTY_COMPONENT, EdgeType, GantParams
import datetime as dt


class GantMaker:
    def __init__(self):
        self.show_description = True
        self.title = GantParams.TITLE
        self.color_key = GantParams.COLOR_KEY
        self.df = []

    def build_gant(self, orders, connected_component_id, types, timestamps, node_titles, edge_titles):
        for e, order in orders.items():
            if connected_component_id[e[0]] == EMPTY_COMPONENT:
                continue

            # Timeline preparations
            if (types[e] == EdgeType.BLAST) or (types[e] == EdgeType.WHITE_CANE):
                self.df.append(
                    dict(Task=types[e], Start=str(timestamps[e][0]),
                         Finish=str(timestamps[e][0] + dt.timedelta(minutes=60)),
                         Event_type=types[e], Description=node_titles[e[0]],
                         connected_component_id=connected_component_id[e[0]]))

            else:
                # Timeline preparations
                self.df.append(
                    dict(Task=types[e], Start=str(timestamps[e][0]),
                         Finish=str(timestamps[e][0] + dt.timedelta(minutes=60)),
                         Event_type=types[e], Description=edge_titles[e],
                         connected_component_id=connected_component_id[e[0]]))

    def show_events_on_gant(self):
        if len(self.df) != 0:
            fig = px.timeline(self.df, x_start="Start", x_end="Finish", title=self.title, y="Event_type",
                              hover_data={'Description': self.show_description, 'Finish': False}, color=self.color_key)
            fig.show()
