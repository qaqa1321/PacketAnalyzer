import streamlit as st

from webpages.login.accountdb import get_audit_log

from  webpages.css.st_header import _setting
_setting()


# st.title("📜 감사 로그")
st.markdown(
        """
    <h1 style="font-size:28px; margin:0;">📜 감사 로그</h1>
    """,
        unsafe_allow_html=True,
    )

if not st.session_state.get("logged_in") or st.session_state.user["role"] != "admin":
    st.error("관리자만 접근할 수 있습니다.")
    st.stop()

logs = get_audit_log(limit=300)

if not logs:
    st.info("기록된 로그가 없습니다.")
else:
    st.caption(f"최근 {len(logs)}건 (최신순)")
    st.dataframe(
        [
            {
                "시각": l["created_at"],
                "행동": l["action"],
                "행위자": l["actor_email"],
                "대상 user_id": l["target_user_id"],
                "상세": l["detail"],
            }
            for l in logs
        ],
        width="stretch",
        hide_index=True,
    )