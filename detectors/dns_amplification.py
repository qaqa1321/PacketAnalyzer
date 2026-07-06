from engine import PacketData, Flow
from detectors.amplification_common import AmplificationDetector

TIME_WINDOW = 5

PACKET_THRESHOLD = 100
BYTE_THRESHOLD = 5_000_000
SERVER_THRESHOLD = 20

detector = AmplificationDetector(TIME_WINDOW)


def detect(packet: PacketData, flow: Flow):

    if flow.protocol != "UDP":
        return

    # DNS Response
    if packet.src_port != 53:
        return

    result = detector.add_packet(packet)

    if (
        result.packet_count >= PACKET_THRESHOLD
        or result.total_bytes >= BYTE_THRESHOLD
        or result.unique_servers >= SERVER_THRESHOLD
    ):

        print("\n[DNS Amplification 의심됨]")
        print(f"{result}")

        print("Top DNS Servers")

        for ip, count in result.top_servers:
            print(f"  {ip:<15} {count} packets")