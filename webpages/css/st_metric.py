import streamlit as st

def metric_cards():
    st.markdown("""
.metric-card {
    background: dimgrey;
    border: 1px solid #e6e8eb;
    border-left: 4px solid #1100ff;
    border-radius: 10px;
    padding: 14px 18px;
    margin-bottom: 4px;
}
.metric-label {
    font-size: 15px;
    color: #FFFFFF;
    margin-bottom: 4px;
}
.metric-value {
    font-size: 30px;
    font-weight: 700;
    color: #1100ff;
}
.section-title {
    font-size: 22px;
    font-weight: 700;
    margin-top: 6px;
    margin-bottom: 10px;
}
""")