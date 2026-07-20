
class AutoBlock:
    def __init__(self):
        pass

    # 어디서부터 막을지 가져오기
    # 점수가 데이터 이상이면 iptables 차단하고 블랙리스트에 넣기

    def get_threshold(self):
        """
        어디서부터 자동차단할지 가져오는 함수
        """