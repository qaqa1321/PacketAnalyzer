import sqlite3

class DBModule:
    def __init__(self):
        self.conn = sqlite3.connect("packets.db")
        self.cursor = self.conn.cursor()
        self.create_table()
        self.packet_buffer = []

    def create_table(self):
        # 들어오는 패킷 전부 저장하는 테이블
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS packets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp INTEGER,
                src_ip TEXT,
                dst_ip TEXT,
                src_port INTEGER,
                dst_port INTEGER,
                protocol TEXT,
                packet_size INTEGER,
                payload_size INTEGER,
                tcp_flags TEXT
            );
        ''')

        self.cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_packets_timestamp
        ON packets(timestamp)
        """)
        self.cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_packets_src_ip
        ON packets(src_ip)
        """)
        # 경고 메시지만 저장하는 테이블
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS warnings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                first_timestamp INTEGER,
                last_timestamp INTEGER,
                src_ip TEXT,
                attack_type TEXT,
                counter INTEGER,
                            
            
                UNIQUE(src_ip, attack_type)
            );
        ''')
        self.conn.commit()


    def insert_packet_table(self, timestamp, src_ip, dst_ip, src_port, dst_port, protocol, packet_size, payload_size, tcp_flags):
        # print("DB모듈 들어옴")
        self.packet_buffer.append(
            (timestamp, src_ip, dst_ip, src_port, dst_port, protocol, packet_size, payload_size, tcp_flags)
        )

        if len(self.packet_buffer) >= 100:  # 버퍼가 100개 이상이면 한 번에 커밋
            self.cursor.executemany('''
                INSERT INTO packets (timestamp, src_ip, dst_ip, src_port, dst_port, protocol, packet_size, payload_size, tcp_flags)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', self.packet_buffer)
            self.conn.commit()
            self.packet_buffer.clear()
            self.cleanup_packets()
            # print("100개의 패킷이 DB에 저장되었습니다.")
  

    def cleanup_packets(self):
        self.cursor.execute("SELECT COUNT(*) FROM packets")
        count = self.cursor.fetchone()[0]

        if count > 1500:
            self.cursor.execute("""
                DELETE FROM packets
                WHERE id NOT IN (
                    SELECT id
                    FROM packets
                    ORDER BY id DESC
                    LIMIT 1500
                )
            """)
            self.conn.commit()


    def insert_warning_table(self, timestamp, src_ip, attack_type, counter):
        self.cursor.execute('''
            INSERT INTO warnings (first_timestamp, last_timestamp, src_ip, attack_type, counter)
            VALUES (?, ?, ?, ?, ?)
                            
            ON CONFLICT(src_ip, attack_type)
            DO UPDATE SET
            counter = counter + excluded.counter,
            last_timestamp = excluded.last_timestamp
        ''', (timestamp, timestamp, src_ip, attack_type, counter))
        self.conn.commit()

    def flush(self):
        if not self.packet_buffer:
            return

        self.cursor.executemany("""
            INSERT INTO packets (timestamp, src_ip, dst_ip, src_port, dst_port, protocol, packet_size, payload_size, tcp_flags)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, self.packet_buffer)

        self.conn.commit()
        self.packet_buffer.clear()


    def close(self):
        self.flush()
        self.conn.close()