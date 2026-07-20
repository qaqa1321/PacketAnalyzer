import streamlit as st

from accountdb import get_db

st.title("🔔 회원가입 승인 관리")

# index.py의 로그인 게이트를 통과한 사용자만 이 코드까지 도달하지만,
# 혹시 모를 상황(직접 접근 등)을 대비해 한 번 더 admin 권한 체크
if not st.session_state.get("logged_in") or st.session_state.user["role"] != "admin":
    st.error("관리자만 접근할 수 있습니다.")
    st.stop()

conn = get_db()
pending_users = conn.execute(
    "SELECT id, email, created_at FROM users WHERE status = 'pending' ORDER BY created_at"
).fetchall()
conn.close()

if not pending_users:
    st.info("승인 대기중인 가입 신청이 없습니다.")
else:
    st.write(f"총 **{len(pending_users)}건**의 승인 대기 신청이 있습니다.")
    st.divider()

    for u in pending_users:
        col1, col2, col3 = st.columns([3, 1, 1])
        col1.write(f"**{u['email']}**")
        col1.caption(f"신청일: {u['created_at']}")

        if col2.button("✅ 승인", key=f"approve_{u['id']}", width="stretch"):
            conn = get_db()
            conn.execute("UPDATE users SET status = 'approved' WHERE id = ?", (u["id"],))
            conn.execute(
                "UPDATE notifications SET is_read = 1 "
                "WHERE related_user_id = ? AND type = 'signup_pending'",
                (u["id"],),
            )
            conn.commit()
            conn.close()
            st.rerun()

        if col3.button("❌ 거절", key=f"reject_{u['id']}", width="stretch"):
            conn = get_db()
            conn.execute("UPDATE users SET status = 'rejected' WHERE id = ?", (u["id"],))
            conn.execute(
                "UPDATE notifications SET is_read = 1 "
                "WHERE related_user_id = ? AND type = 'signup_pending'",
                (u["id"],),
            )
            conn.commit()
            conn.close()
            st.rerun()

        st.divider()

st.caption("승인된 사용자만 로그인할 수 있습니다. 거절된 사용자는 다시 로그인을 시도하면 거절 안내를 보게 됩니다.")