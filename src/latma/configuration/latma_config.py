from enum import Enum


class LatmaParams(str):
    MINIMAL_LATERAL_MOVEMENT_PATH_LENGTH = 3
    MAXIMUM_NODES_IN_COMPONENT = 4
    MINIMUM_DAYS_FOR_MATCH = 3
    LEARNING_PERIOD = 7
    MINIMUM_TIME_FOR_BRIDGE = 30
    WHITE_CANE_THRESHOLD = 12
    WHITE_CANE_PERIOD = 20
    BLAST_THRESHOLD = 30
    BLAST_PERIOD = 2
    MAX_USERS_TO_APPLY_DEFAULT_PARAMS = 60
    HUB_MINIMUM_USERS = 50
    SINK_MINIMUM_USERS = 20


EMPTY_COMPONENT = "-1"


class OutputFiles(str):
    TIMELINE_FILE = "timeline.txt"
    PROPAGATION_GIF = "propagation.gif"
    PROPAGATION_MP4 = "propagation.mp4"
    PROPAGATION_CSV = "propagation.csv"
    ALL_AUTHENTICATION_CSV = "all_authentications.csv"


class NodeType(str, Enum):
    BLAST = "Blast"
    SOLO_ATTACKER = "Solo Attacker"
    WHITE_CANE = "White Cane"
    SUSPECTED_LATERAL_MOVEMENT = "Suspected Lateral Movement"
    ABNORMAL_EDGE = "Abnormal Edge"
    SERVICE_ACCOUNT = "Service Account"
    BRIDGE = "Bridge"
    BRIDGE_SWITCH = "Bridge Switch"
    WEIGHT_SHIFT = "Weight Shift"


class EdgeType(str, Enum):
    BLAST = "Blast"
    SOLO_ATTACKER = "Solo Attacker"
    WHITE_CANE = "White Cane"
    SUSPECTED_LATERAL_MOVEMENT = "Suspected Lateral Movement"
    ABNORMAL_EDGE = "Abnormal Edge"
    SERVICE_ACCOUNT = "Service Account"
    BRIDGE = "Bridge"
    BRIDGE_SWITCH = "Bridge Switch"
    WEIGHT_SHIFT = "Weight Shift"
    BRIDGE_FIRST_EDGE = "first_edge"


class GantParams(str):
    TITLE = 'Progression'
    COLOR_KEY = 'connected_component_id'


class GifParams(str):
    MACHINE_LABEL = 'machine'
    BLAST_LABEL = 'blast node'
    WHITE_CANE_LABEL = 'white-cane node'
    DEFAULT_NODE_COLOR = 'orange'
    DEFAULT_WHITE_CANE_NODE_COLOR = 'green'
    DEFAULT_BLAST_NODE_COLOR = 'red'
    MAX_NUMBER_OF_COLORS = 30
    FIG_SIZE = 16
    DEFAULT_NODE_SIZE = 200
    BLAST_NODE_SIZE = 300
    WHITE_CANE_NODE_SIZE = 300
    FADE_OUT_COLOR = 'lightgray'
    DEFAULT_FONT_SIZE = 17.5
    INTERVAL = 1500
    DEFAULT_LINE_STYLE = '-'
    SPECIAL_LINE_STYLE = '--'


COLOR_MAP = {
    EdgeType.BLAST: 'red',
    EdgeType.WHITE_CANE: 'yellow',
    EdgeType.WEIGHT_SHIFT: 'green',
    EdgeType.ABNORMAL_EDGE: 'blue',
    EdgeType.BRIDGE: 'pink',
    EdgeType.BRIDGE_SWITCH: 'black'
}

LW_MAP = {
    EdgeType.BLAST: 2,
    EdgeType.WHITE_CANE: 2,
    EdgeType.WEIGHT_SHIFT: 2,
    EdgeType.ABNORMAL_EDGE: 2,
    EdgeType.BRIDGE: 2,
    EdgeType.BRIDGE_SWITCH: 2
}
