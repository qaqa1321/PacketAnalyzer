from dataclasses import dataclass, field
from collections import deque

@dataclass
class Flow:

    flow_id: str

    src_ip: str
    dst_ip: str

    src_port: int
    dst_port: int

    protocol: str

    start_time: float
    last_seen: float

    packet_count: int = 0
    byte_count: int = 0

    syn_count: int = 0
    ack_count: int = 0
    fin_count: int = 0
    rst_count: int = 0

    recent_packets: deque = field(default_factory=lambda: deque(maxlen=30))