from engine import PacketData, Flow


def detect(packet: PacketData, flow: Flow):

    print('rst_flood 테스트중')
    # 임계점 설정이라 변경가능.
    
    RST_THRESHOLD = 50

    flags = packet.tcp_flags or ""
    if "R" not in flags:
        return False

    if flow.rst_count >= RST_THRESHOLD:
        print(
            "rst flooding",
            packet.src_ip)


# rst_flood_alert = flow.rst_count >= RST_THRESHOLD
# #log_record = {
#         "timestamp": packet.timestamp,       # 탐지된 시점
#         "attack_type": "rst_flood",          # 어떤 공격 유형인지 (다른 DoS와 구분용)
#         "src_ip": packet.src_ip,             # 공격 출발지로 의심되는 IP
#         "dst_ip": packet.dst_ip,             # 공격 대상 IP
#         "src_port": packet.src_port,
#         "dst_port": packet.dst_port,
#         "flags": flags,                       # 판단 근거가 된 flags 값
#         "rst_count": flow.rst_count,          # 판단 근거가 된 카운트
#         "threshold": RST_THRESHOLD,           # 당시 기준값 (나중에 threshold 바뀌어도 기록엔 남게)
#         "is_flood": is_flood,                 # 최종 판단 결과
#     }

#     if rst_flood_alert:
#         save_log(log_record)
#         # 실제 DB 저장 로직은 아직 미정 -> 지금은 함수만 자리 잡아둠 (아래 참고)

#     return is_flood
    

