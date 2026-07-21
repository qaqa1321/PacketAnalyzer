from engine.iptables import add_black

class AutoBlock:
    def __init__(self, db):
        self.th_dict = {
            "low": 0.1,
            "medium": 4,
            "high": 7,
            "critical": 9,
        }
        self.db = db

    def get_threshold(self):
        """
        어디서부터 자동차단할지 가져오는 함수
        """
        # select 해서 가져오기
        # 
        return "Medium"

    def auto_block(self, score, src_ip):
        """
        자동 차단
        """
        threshold = self.get_threshold().lower()
        if score >= self.th_dict[threshold]:
            add_black(src_ip)
            self.db.insert_black_list(src_ip, True)