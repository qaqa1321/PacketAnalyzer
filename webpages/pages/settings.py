import sqlite3
import pandas as pd
import streamlit as st
import plotly.express as px
from datetime import datetime, timedelta

from streamlit_autorefresh import st_autorefresh

from webpages.functions.titles  import get_h2

# header
st.markdown("""
<h1 style="
    font-size:28px;
    margin:0;
">
Settings
</h1>
""", unsafe_allow_html=True)