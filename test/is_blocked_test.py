# test_firewall.py
import subprocess
import pytest
import engine.firewall_worker as firewall

# 여기 원하는 IP를 넣어서 테스트
TEST_IPS = [
    "192.168.1.2",
    "192.168.110.129",
]


@pytest.mark.parametrize("ip", TEST_IPS)
def test_is_blocked(ip):
    result = firewall.is_blocked(ip)
    print(f"\n{ip} -> {'차단됨(DROP)' if result else '허용됨(ACCEPT)'}")
    # 지금은 결과를 눈으로 확인하는 목적이라 assert는 생략
    # 특정 IP가 반드시 허용/차단되어야 한다면 아래처럼 명시
    # assert result is True   # 차단되어야 하는 경우
    assert result is False  # 허용되어야 하는 경우