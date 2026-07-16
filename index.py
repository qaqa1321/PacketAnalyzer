import re

import streamlit as st
from werkzeug.security import generate_password_hash, check_password_hash

from accountdb import get_db, init_db

st.set_page_config(page_title="Login", page_icon="🔐", layout="centered")

init_db()

EMAIL_REGEX = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

# ---------------------------------------------------------
# 세션 상태 초기값
# ---------------------------------------------------------
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
if "user" not in st.session_state:
    st.session_state.user = None
if "mode" not in st.session_state:
    st.session_state.mode = "login"  # "login" 또는 "signup"


# ---------------------------------------------------------
# DB 접근 함수
# ---------------------------------------------------------
def signup_user(email: str, password: str, password_confirm: str):
    if not EMAIL_REGEX.match(email):
        return False, "올바른 이메일 형식이 아닙니다."
    if len(password) < 8:
        return False, "비밀번호는 8자 이상이어야 합니다."
    if password != password_confirm:
        return False, "비밀번호가 일치하지 않습니다."

    conn = get_db()
    existing = conn.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()
    if existing:
        conn.close()
        return False, "이미 가입된 이메일입니다."

    conn.execute(
        "INSERT INTO users (email, password_hash, role) VALUES (?, ?, ?)",
        (email, generate_password_hash(password), "user"),
    )
    conn.commit()
    conn.close()
    return True, "회원가입이 완료되었습니다. 로그인해주세요."


def login_user(email: str, password: str):
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
    conn.close()

    if user is None or not check_password_hash(user["password_hash"], password):
        return False, None
    return True, {"id": user["id"], "email": user["email"], "role": user["role"]}


# ---------------------------------------------------------
# 로그인 / 회원가입 화면
# ---------------------------------------------------------
def render_login():
    st.title("🔐 로그인")
    email = st.text_input("ID (이메일)", key="login_email")
    password = st.text_input("PW (비밀번호)", type="password", key="login_pw")

    col1, col2 = st.columns(2)
    with col1:
        if st.button("확인", use_container_width=True):
            if not email or not password:
                st.warning("ID와 PW를 모두 입력해주세요.")
            else:
                ok, user = login_user(email.strip().lower(), password)
                if ok:
                    st.session_state.logged_in = True
                    st.session_state.user = user
                    st.rerun()
                else:
                    st.error("이메일 또는 비밀번호가 올바르지 않습니다.")
    with col2:
        if st.button("회원가입", use_container_width=True):
            st.session_state.mode = "signup"
            st.rerun()


def render_signup():
    st.title("📝 회원가입")
    email = st.text_input("ID (이메일)", key="signup_email")
    password = st.text_input("PW (8자 이상)", type="password", key="signup_pw")
    password_confirm = st.text_input("PW 확인", type="password", key="signup_pw_confirm")

    col1, col2 = st.columns(2)
    with col1:
        if st.button("가입하기", use_container_width=True):
            ok, message = signup_user(email.strip().lower(), password, password_confirm)
            if ok:
                st.success(message)
                st.session_state.mode = "login"
            else:
                st.error(message)
    with col2:
        if st.button("로그인으로 돌아가기", use_container_width=True):
            st.session_state.mode = "login"
            st.rerun()


# ===========================================================
# 1) 로그인 게이트: 로그인 안 됐으면 여기서 멈추고 아래 네비게이션은 실행 안 함
# ===========================================================
if not st.session_state.logged_in:
    if st.session_state.mode == "signup":
        render_signup()
    else:
        render_login()
    st.stop()  # 핵심! 이 아래 코드(st.navigation, pg.run())는 로그인 전엔 절대 실행되지 않음


# ===========================================================
# 2) 로그인 성공한 사용자만 도달하는 영역
# ===========================================================
with st.sidebar:
    st.write(f"👤 {st.session_state.user['email']}")
    st.write(f"권한: **{st.session_state.user['role']}**")
    if st.button("로그아웃"):
        st.session_state.logged_in = False
        st.session_state.user = None
        st.session_state.mode = "login"
        st.rerun()
    st.divider()

# 기본 페이지 (모든 로그인 사용자 공통)
pages = [
    st.Page('webpages/pages/home.py', title='🏠 Home'),
    st.Page('webpages/pages/warning_list.py', title='⚠️ warnings'),
    st.Page('webpages/pages/details.py', title='details'),
]

# admin 역할만 볼 수 있는 페이지는 조건부로 추가
if st.session_state.user["role"] == "admin":
    pages.append(st.Page('webpages/pages/settings.py', title='settings'))

pg = st.navigation(pages)
pg.run()