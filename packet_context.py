from dataclasses import dataclass

@dataclass
class PacketContext:

    packet: object
    flow: object