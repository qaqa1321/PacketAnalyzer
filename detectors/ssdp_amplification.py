from engine import PacketData, Flow
from detectors.amplification_common import AmplificationDetector

detector = AmplificationDetector(5)


def detect(packet: PacketData, flow: Flow):

    if flow.protocol != "UDP":
        return

    if packet.src_port != 1900:
        return

    result = detector.add_packet(packet)

    if (
        result.packet_count >= 80
        or result.total_bytes >= 2_000_000
    ):

        print("\n[SSDP Amplification 의심됨]")
        print(f"{result}")

        for ip, count in result.top_servers:
            print(f"  {ip:<15} {count} packets")