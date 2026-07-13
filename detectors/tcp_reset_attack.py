#  RST 개수만으로 공격을 판단하지 않았습니다. 
#  정상적인 TCP 통신에서도 RST가 발생할 수 있기 때문입니다. 
#  따라서 TCP 여부, 전체 패킷 대비 RST 비율(RST Ratio), 초당 패킷 수(PPS),   
#  그리고 정상적인 TCP 연결(SYN)이 있었는지를 함께 확인하여 TCP Reset Attack을 탐지하도록 구현했습니다.


from engine import PacketData, Flow
from datetime import datetime


def detect(packet: PacketData, flow: Flow):

    # TCP만 검사
    if flow.protocol != "TCP":
        return

    # 패킷이 너무 적으면 판단하지 않음
    if flow.packet_count < 20:
        return

    # RST 비율 계산
    rst_ratio = flow.rst_count / flow.packet_count

    # 탐지 조건
    if (
        flow.syn_count > 0          # 정상 연결이 존재했고
        and flow.pps > 50           # 짧은 시간에 많은 패킷이 발생했으며
        and rst_ratio >= 0.6        # RST 비율이 60% 이상이면
    ):

        print("\n" + "=" * 60)
        print("🚨 TCP RESET ATTACK DETECTED 🚨")
        print("=" * 60)

        print(f"Time         : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Source IP    : {packet.src_ip}")
        print(f"Destination  : {packet.dst_ip}")
        print(f"Protocol     : {flow.protocol}")

        print("-" * 60)

        print(f"Packets      : {flow.packet_count}")
        print(f"SYN Count    : {flow.syn_count}")
        print(f"RST Count    : {flow.rst_count}")
        print(f"RST Ratio    : {rst_ratio:.2%}")
        print(f"PPS          : {flow.pps:.2f}")

        print("-" * 60)

        print("Threat Level : HIGH")
        print("Status       : TCP Reset Attack Suspected")

        print("=" * 60)


# sudo hping3 -R -p <타깃_포트> <타깃_IP> --fast --count 1000
# sudo hping3 -R -p 443 192.168.72.129 --fast --count 1000