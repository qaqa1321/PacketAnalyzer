

from engine import PacketData, Flow
from datetime import datetime


def detect(packet: PacketData, flow: Flow):

    # TCP만 검사
    if flow.protocol != "TCP":
        return

    # 패킷 수가 너무 적으면 판단하지 않음
    if flow.packet_count < 20:
        return

    raw = str(packet.raw_packet).upper()

    # TCP 패킷 안에서 Sequence / ACK 이상 여부를 간단히 확인
    suspicious_seq = False

    # raw_packet에 이상한 TCP 상태가 보이면 의심
    if "SEQ" in raw and "ACK" in raw:
        suspicious_seq = True

    # RST가 갑자기 많거나 FIN 없이 연결 상태가 흔들리는 경우도 의심
    rst_ratio = flow.rst_count / max(flow.packet_count, 1)

    if (
        flow.syn_count > 0
        and flow.ack_count > 0
        and flow.pps > 50
        and (
            suspicious_seq
            or rst_ratio >= 0.3
        )
    ):

        print("\n" + "=" * 60)
        print("⚠️ TCP SESSION HIJACKING SUSPECTED ⚠️")
        print("=" * 60)

        print(f"Time         : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Source IP    : {packet.src_ip}")
        print(f"Destination  : {packet.dst_ip}")
        print(f"Protocol     : {flow.protocol}")

        print("-" * 60)

        print(f"Packet Count : {flow.packet_count}")
        print(f"SYN Count    : {flow.syn_count}")
        print(f"ACK Count    : {flow.ack_count}")
        print(f"RST Count    : {flow.rst_count}")
        print(f"RST Ratio    : {rst_ratio:.2%}")
        print(f"PPS          : {flow.pps:.2f}")

        print("-" * 60)

        print("Threat Level : MEDIUM / HIGH")
        print("Attack Type  : TCP Session Hijacking")
        print("Reason       : Abnormal TCP session behavior detected")

        print("=" * 60)