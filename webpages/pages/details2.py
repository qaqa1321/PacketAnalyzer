import importlib
import os
import sys
from pathlib import Path

import pandas as pd
import plotly.graph_objects as go
import pycountry
import streamlit as st
from streamlit_autorefresh import st_autorefresh


# ============================================================================
# 프로젝트 루트 경로 등록 + 공용 모듈 import (_dbsource.py, _geoprocess.py)
# ----------------------------------------------------------------------------
# 이 페이지 자신 / 부모 / 조부모 폴더까지 뒤져서 모듈을 찾는다.
# 예) webpages/_dbsource.py, webpages/_geoprocess.py 를
#     webpages/pages/details.py 에서 사용하는 구조
# ============================================================================
def _import_project_module(candidates: list[str]):
    here = os.path.dirname(os.path.abspath(__file__))
    search_dirs = [here, os.path.dirname(here), os.path.dirname(os.path.dirname(here))]

    last_error = None
    for d in search_dirs:
        if d and d not in sys.path:
            sys.path.insert(0, d)
        for module_name in candidates:
            try:
                return importlib.import_module(module_name)
            except ModuleNotFoundError as e:
                last_error = e
                continue
    raise last_error or ModuleNotFoundError(f"{candidates} 모듈을 찾을 수 없습니다.")


_dbsource_mod = _import_project_module(["_dbsource", "dbsource"])
_geoprocess_mod = _import_project_module(["_geoprocess", "geoprocess"])

dbsource = _dbsource_mod.dbsource
build_index = _geoprocess_mod.build_index
lookup_ips = _geoprocess_mod.lookup_ips
STATUS_LABELS = _geoprocess_mod.STATUS_LABELS
ANOMALOUS_SOURCE_STATUSES = _geoprocess_mod.ANOMALOUS_SOURCE_STATUSES


# ============================================================================
# 페이지 설정 (반드시 한 번만 호출)
# ============================================================================
st.set_page_config(
    page_title="Packet Analyzer Dashboard",
    page_icon="🛡️",
    layout="wide",
)

REFRESH_INTERVAL_SECONDS = 5
st_autorefresh(interval=REFRESH_INTERVAL_SECONDS * 1000, key="auto_refresh")


# ============================================================================
# 다크 모드 스타일
# ============================================================================
PROTOCOL_COLORS = {
    "TCP": {"bg": "rgba(59,130,246,0.16)", "fg": "#60a5fa", "accent": "#3b82f6"},
    "UDP": {"bg": "rgba(245,158,11,0.16)", "fg": "#fbbf24", "accent": "#f59e0b"},
    "ICMP": {"bg": "rgba(16,185,129,0.16)", "fg": "#34d399", "accent": "#10b981"},
}
DEFAULT_COLOR = {"bg": "rgba(148,163,184,0.16)", "fg": "#94a3b8", "accent": "#64748b"}

CUSTOM_CSS = """
<style>
:root {
    --bg-app: #0b1120;
    --bg-surface: #111827;
    --bg-surface-2: #0f172a;
    --border-subtle: #1f2937;
    --text-primary: #e5e7eb;
    --text-muted: #94a3b8;
    --accent: #3b82f6;
}

html, body, [class*="css"] {
    font-size: 16px;
    color: var(--text-primary);
}

.stApp,
[data-testid="stAppViewContainer"],
[data-testid="stHeader"] {
    background-color: var(--bg-app);
}
[data-testid="stHeader"] { background: transparent; }
.block-container { padding-left: 1.2rem; padding-right: 1.2rem; }

h1, h2, h3, h4, h5, h6, p, span, label, .stMarkdown { color: var(--text-primary); }
.stCaption, [data-testid="stCaptionContainer"] { color: var(--text-muted) !important; }

.metric-card {
    background: var(--bg-surface);
    border: 1px solid var(--border-subtle);
    border-left: 4px solid var(--accent);
    border-radius: 10px;
    padding: 14px 18px;
    margin-bottom: 4px;
}
.metric-label {
    font-size: 15px;
    color: var(--text-muted);
    margin-bottom: 4px;
}
.metric-value {
    font-size: 30px;
    font-weight: 700;
    color: #60a5fa;
}
.section-title {
    font-size: 22px;
    font-weight: 700;
    margin-top: 6px;
    margin-bottom: 10px;
    color: var(--text-primary);
}
.section-sub {
    font-size: 14px;
    color: var(--text-muted);
    margin-top: -6px;
    margin-bottom: 14px;
}
.detail-empty {
    background: linear-gradient(135deg, #16213a 0%, #1c1a3a 100%);
    border: 1px solid var(--border-subtle);
    border-radius: 12px;
    padding: 24px;
    color: #93c5fd;
    font-size: 18px;
    min-height: 120px;
    display: flex;
    align-items: center;
    justify-content: center;
    text-align: center;
}
.detail-card {
    background: var(--bg-surface);
    border: 1px solid var(--border-subtle);
    border-radius: 14px;
    padding: 0;
    overflow: hidden;
    box-shadow: 0 2px 10px rgba(0,0,0,0.35);
}
.detail-header {
    padding: 18px 24px;
    color: #ffffff;
    background: linear-gradient(135deg, var(--accent-a) 0%, var(--accent-b) 100%);
}
.detail-id-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-bottom: 8px;
}
.detail-id {
    font-size: 14px;
    opacity: 0.85;
    font-weight: 600;
    letter-spacing: 0.5px;
}
.kind-badge {
    display: inline-flex;
    align-items: center;
    gap: 5px;
    padding: 4px 12px;
    border-radius: 20px;
    font-size: 13px;
    font-weight: 800;
    letter-spacing: 0.5px;
    color: #ffffff;
    text-transform: uppercase;
}
.kind-badge-packet { background: #1d4ed8; }
.kind-badge-flow { background: #7c3aed; }
.detail-flow-line {
    display: flex;
    align-items: center;
    gap: 10px;
    font-size: 19px;
    font-weight: 700;
    font-family: "SFMono-Regular", Consolas, monospace;
    flex-wrap: wrap;
}
.detail-flow-arrow { opacity: 0.8; font-size: 18px; }
.detail-body { padding: 20px 24px 24px 24px; }
.detail-group-title {
    font-size: 14px;
    font-weight: 700;
    color: var(--text-muted);
    margin: 18px 0 10px 0;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    display: flex;
    align-items: center;
    gap: 6px;
}
.detail-group-title:first-of-type { margin-top: 0; }
.detail-group {
    display: grid;
    grid-template-columns: 1fr 1fr;
    column-gap: 28px;
}
.detail-row {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 11px 0;
    border-bottom: 1px solid var(--border-subtle);
}
.detail-row:last-child { border-bottom: none; }
.detail-key { font-size: 16px; color: var(--text-muted); font-weight: 500; }
.detail-val {
    font-size: 19px;
    color: var(--text-primary);
    font-weight: 700;
    font-family: "SFMono-Regular", Consolas, monospace;
    text-align: right;
}
.badge {
    display: inline-block;
    padding: 5px 16px;
    border-radius: 20px;
    font-size: 15px;
    font-weight: 700;
    font-family: inherit;
}
.badge-flag-empty { background: rgba(148,163,184,0.16); color: var(--text-muted); }
.badge-ttl { background: rgba(124,58,237,0.18); color: #c4b5fd; }
.detail-raw {
    background: var(--bg-surface-2);
    color: #67e8f9;
    font-family: "SFMono-Regular", Consolas, monospace;
    font-size: 13.5px;
    padding: 14px 16px;
    border-radius: 10px;
    max-height: 160px;
    overflow: auto;
    word-break: break-all;
    line-height: 1.6;
    border: 1px solid var(--border-subtle);
}
.geo-note {
    font-size: 13px;
    color: var(--text-muted);
    margin-top: 6px;
}
hr {
    margin: 8px 0 18px 0;
    border-color: var(--border-subtle);
}
</style>
"""
st.markdown(CUSTOM_CSS, unsafe_allow_html=True)


def _protocol_color(proto: str) -> dict:
    return PROTOCOL_COLORS.get(str(proto).upper(), DEFAULT_COLOR)


def _flatten_html(html: str) -> str:
    """
    st.markdown()은 줄 앞에 공백 4칸 이상이 있으면 마크다운 코드블록으로 인식해서
    HTML을 렌더링하지 않고 그대로 텍스트로 보여준다.
    보기 좋게 들여쓴 멀티라인 f-string을 한 줄씩 lstrip 해서 이 문제를 막는다.
    """
    return "\n".join(line.lstrip() for line in html.strip("\n").splitlines())


def _format_ts(value) -> str:
    """나노초 없이 초 단위까지만 보여주는 타임스탬프 포맷"""
    if isinstance(value, pd.Timestamp):
        if pd.isna(value):
            return "-"
        return value.strftime("%Y-%m-%d %H:%M:%S")
    if value in (None, "", "nan"):
        return "-"
    return str(value)[:19]


def render_detail(row: pd.Series, kind: str = "packet") -> str:
    """선택된 packet/flow row를 컴팩트한 2열 카드 HTML로 렌더링"""
    d = row.to_dict()

    kind_badge = (
        '<span class="kind-badge kind-badge-packet">📦 Packet</span>'
        if kind == "packet"
        else '<span class="kind-badge kind-badge-flow">🔀 Flow</span>'
    )

    def badge(value, bg, fg):
        if value in (None, "", "nan"):
            return '<span class="badge badge-flag-empty">-</span>'
        return f'<span class="badge" style="background:{bg};color:{fg};">{value}</span>'

    def add_row(rows_list, label, value_html):
        rows_list.append(
            f'<div class="detail-row"><span class="detail-key">{label}</span>'
            f'<span class="detail-val">{value_html}</span></div>'
        )

    proto = d.get("protocol", "-")
    colors = _protocol_color(proto)
    proto_badge = badge(proto, colors["bg"], colors["fg"])
    flag_badge = badge(d.get("tcp_flags", ""), "rgba(79,70,229,0.18)", "#a5b4fc")

    ts_display = _format_ts(d.get("timestamp"))
    src_ip = d.get("src_ip", "-")
    dst_ip = d.get("dst_ip", "-")
    src_port = d.get("src_port")
    dst_port = d.get("dst_port")
    src_label = f"{src_ip}:{src_port}" if src_port not in (None, "", "nan") else f"{src_ip}"
    dst_label = f"{dst_ip}:{dst_port}" if dst_port not in (None, "", "nan") else f"{dst_ip}"

    header = f"""
    <div class="detail-header" style="--accent-a:{colors['accent']}; --accent-b:{colors['accent']}cc;">
        <div class="detail-id-row">
            <span class="detail-id">#{d.get('id', '-')} · {ts_display}</span>
            {kind_badge}
        </div>
        <div class="detail-flow-line">
            <span>{src_label}</span>
            <span class="detail-flow-arrow">→</span>
            <span>{dst_label}</span>
        </div>
    </div>
    """

    body_rows = []
    if kind == "packet":
        add_row(body_rows, "들어온 시간", ts_display)
        add_row(body_rows, "타입", proto_badge)
        add_row(body_rows, "출발지 IP", src_ip)
        add_row(body_rows, "목적지 IP", dst_ip)
        add_row(body_rows, "출발지 포트", src_port if src_port not in (None, "", "nan") else "-")
        add_row(body_rows, "목적지 포트", dst_port if dst_port not in (None, "", "nan") else "-")
        add_row(body_rows, "Packet 크기", f"{d.get('packet_size', 0):,} B")
        add_row(body_rows, "Payload 크기", f"{d.get('payload_size', 0):,} B")
        add_row(body_rows, "TCP Flags", flag_badge)
    else:
        add_row(body_rows, "타입", proto_badge)
        add_row(body_rows, "출발지 IP", src_ip)
        add_row(body_rows, "목적지 IP", dst_ip)
        add_row(body_rows, "출발지 Port", src_port if src_port not in (None, "", "nan") else "-")
        add_row(body_rows, "목적지 Port", dst_port if dst_port not in (None, "", "nan") else "-")
        if "packet_count" in d:
            add_row(body_rows, "Packet 수", f'{d["packet_count"]:,}')
        if "total_bytes" in d:
            add_row(body_rows, "Total Bytes", f'{d["total_bytes"]:,} B')
        if "first_seen" in d:
            add_row(body_rows, "First Seen", _format_ts(d.get("first_seen")))
        if "last_seen" in d:
            add_row(body_rows, "Last Seen", _format_ts(d.get("last_seen")))

    body_html = f'<div class="detail-group">{"".join(body_rows)}</div>'

    raw_html = ""
    if kind == "packet" and d.get("raw_packet") not in (None, "", "nan"):
        raw_html = f"""
        <div class="detail-group-title">🧬 Raw Packet</div>
        <div class="detail-raw">{d['raw_packet']}</div>
        """

    html = f"""
    <div class="detail-card">
        {header}
        <div class="detail-body">
            {body_html}
            {raw_html}
        </div>
    </div>
    """
    return _flatten_html(html)


# ============================================================================
# 데이터 로딩 (DB 조회는 여기 한 곳에서만 수행 -> 중복 조회 제거)
# ============================================================================
def _parse_timestamp_column(series: pd.Series) -> pd.Series:
    """
    timestamp 컬럼이 문자열(ISO 포맷 등)이면 그대로 파싱하고,
    숫자(유닉스 타임스탬프)면 자릿수를 보고 s/ms/us/ns 단위를 자동 판별해서 변환한다.
    (숫자를 무작정 ns로 해석하면 1970년 근처로 잘못 나오는 문제를 방지)
    """
    if pd.api.types.is_numeric_dtype(series):
        sample = series.dropna()
        if sample.empty:
            return pd.to_datetime(series, errors="coerce")
        magnitude = abs(float(sample.iloc[0]))
        if magnitude >= 1e17:
            unit = "ns"
        elif magnitude >= 1e14:
            unit = "us"
        elif magnitude >= 1e11:
            unit = "ms"
        else:
            unit = "s"
        return pd.to_datetime(series, unit=unit, errors="coerce")
    return pd.to_datetime(series, errors="coerce")


def _load_from_db() -> pd.DataFrame:
    db = dbsource()
    rows = db.fetch("packets")
    if not rows:
        raise ValueError("packets 테이블에 데이터가 없습니다.")

    df = pd.DataFrame(rows)
    if "timestamp" in df.columns:
        df["timestamp"] = _parse_timestamp_column(df["timestamp"])
    if "id" not in df.columns:
        df.insert(0, "id", range(1, len(df) + 1))
    return df.sort_values("timestamp" if "timestamp" in df.columns else "id").reset_index(drop=True)


@st.cache_data(ttl=REFRESH_INTERVAL_SECONDS)
def load_packets() -> pd.DataFrame:
    """
    _dbsource.py를 통해 실제 DB에서 패킷을 가져오는 유일한 지점.
    아래에서 필요한 src_ip 목록(지도용) 등은 전부 이 결과에서 파생시켜 사용하고,
    DB를 다시 조회하지 않는다.
    실패하면 예외를 그대로 올려서 화면에 에러로 표시한다 (mock 대체 없음).
    """
    return _load_from_db()


def build_flows(df: pd.DataFrame) -> pd.DataFrame:
    """DB 컬럼 유무에 따라 유연하게 flow(5-tuple 기준) 집계"""
    group_cols = [c for c in ["src_ip", "dst_ip", "src_port", "dst_port", "protocol"] if c in df.columns]
    if not group_cols:
        return pd.DataFrame()

    agg_kwargs = {}
    count_base = "id" if "id" in df.columns else group_cols[0]
    agg_kwargs["packet_count"] = (count_base, "count")
    if "packet_size" in df.columns:
        agg_kwargs["total_bytes"] = ("packet_size", "sum")
    if "timestamp" in df.columns:
        agg_kwargs["first_seen"] = ("timestamp", "min")
        agg_kwargs["last_seen"] = ("timestamp", "max")
    if "protocol" not in group_cols and "protocol" in df.columns:
        agg_kwargs["protocol"] = ("protocol", "first")

    flow = df.groupby(group_cols, dropna=False).agg(**agg_kwargs).reset_index()
    flow.insert(0, "id", range(1, len(flow) + 1))
    return flow


# ============================================================================
# Geo 조회 (ipcountry.py 로직 이식) — packets_df에서 파생된 IP 목록만 사용
# ============================================================================
@st.cache_resource
def get_geo_index():
    """ipv4.csv / countries.csv 기반 조회 인덱스. 무거운 작업이라 앱 당 한 번만 생성."""
    return build_index()


@st.cache_data(ttl=REFRESH_INTERVAL_SECONDS)
def load_geo_data(ip_tuple: tuple) -> pd.DataFrame:
    """IP 목록 -> status/국가/위경도가 붙은 DataFrame. packets_df에서 파생된 IP만 입력으로 받는다."""
    index = get_geo_index()
    return lookup_ips(index, list(ip_tuple))


def _safe_iso3(iso2):
    try:
        return pycountry.countries.get(alpha_2=iso2).alpha_3
    except (LookupError, AttributeError):
        return None


def px_dark_palette(n: int) -> list[str]:
    """다크 배경에서 잘 보이는 채도 높은 팔레트를 순환시켜 반환."""
    base = [
        "#3b82f6", "#ef4444", "#10b981", "#f59e0b", "#8b5cf6",
        "#06b6d4", "#ec4899", "#84cc16", "#f97316", "#14b8a6",
    ]
    return [base[i % len(base)] for i in range(n)]


def build_geo_figures(ok_df: pd.DataFrame):
    """공인 IP(ok 상태)만으로 국가별 집계 + 코로플레스 지도 / 도넛 차트를 생성 (다크 테마)."""
    count_df = (
        ok_df.groupby(["country_code", "country_name", "latitude", "longitude"])
        .size()
        .reset_index(name="count")
        .sort_values("count", ascending=False)
        .reset_index(drop=True)
    )
    count_df["iso3_code"] = count_df["country_code"].apply(_safe_iso3)

    fig_geo = go.Figure(
        data=go.Choropleth(
            locations=count_df["iso3_code"],
            locationmode="ISO-3",
            z=count_df["count"],
            text=count_df["country_name"],
            colorscale=[
                [0.0, "#1e293b"],
                [0.3, "#7f1d1d"],
                [0.6, "#b91c1c"],
                [1.0, "#ef4444"],
            ],
            marker_line_color="rgba(15,23,42,0.9)",
            marker_line_width=0.5,
            colorbar=dict(
                title=dict(text="Packets", side="top", font=dict(color="#94a3b8")),
                thickness=10,
                len=0.28,
                outlinewidth=0,
                orientation="v",
                x=0.02,
                xanchor="left",
                y=0.04,
                yanchor="bottom",
                tickfont=dict(color="#94a3b8"),
            ),
            hovertemplate="<b>%{text}</b><br>Packets: %{z:,}<extra></extra>",
        )
    )
    fig_geo.update_geos(
        showframe=False,
        showcoastlines=False,
        lataxis_range=[-58, 85],
        domain=dict(x=[0, 0.9], y=[0, 1]),
        projection_type="equirectangular",
        showland=True,
        landcolor="#1e293b",
        showocean=True,
        oceancolor="#0b1120",
        showcountries=True,
        countrycolor="rgba(148,163,184,0.25)",
        bgcolor="rgba(0,0,0,0)",
    )
    fig_geo.update_layout(
        margin=dict(l=0, r=0, t=0, b=0),
        height=460,
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(family="Inter, sans-serif", size=12, color="#e5e7eb"),
    )

    pie_df = count_df[["country_name", "count"]].copy()
    total_count = pie_df["count"].sum()
    pie_df["ratio"] = pie_df["count"] / total_count

    major_df = pie_df[pie_df["ratio"] >= 0.01]
    minor_sum = pie_df[pie_df["ratio"] < 0.01]["count"].sum()

    if minor_sum > 0:
        pie_df = pd.concat(
            [
                major_df[["country_name", "count"]],
                pd.DataFrame([{"country_name": "Others", "count": minor_sum}]),
            ],
            ignore_index=True,
        )
    else:
        pie_df = major_df[["country_name", "count"]]

    fig_pie = go.Figure(
        data=go.Pie(
            labels=pie_df["country_name"],
            values=pie_df["count"],
            hole=0.55,
            marker=dict(
                colors=px_dark_palette(len(pie_df)),
                line=dict(color="#0b1120", width=2),
            ),
            textinfo="none",
            hovertemplate="<b>%{label}</b><br>%{value:,}건 (%{percent})<extra></extra>",
        )
    )
    fig_pie.update_layout(
        title=dict(text="Top Countries", font=dict(size=13, color="#e5e7eb")),
        margin=dict(l=0, r=0, t=30, b=0),
        height=460,
        showlegend=True,
        legend=dict(orientation="v", font=dict(size=11, color="#cbd5e1")),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(family="Inter, sans-serif", color="#e5e7eb"),
    )

    return fig_geo, fig_pie, count_df


# ============================================================================
# Header
# ============================================================================
st.markdown("## 🛡️ 상세정보")
st.caption("Real-Time Network Traffic Monitoring")

try:
    packets_df = load_packets()
except Exception as e:
    st.error(
        f"❌ DB에서 패킷을 불러오지 못했습니다: {e}\n\n"
        "_dbsource.py 위치와 packets.db 경로를 확인해주세요."
    )
    st.stop()

flows_df = build_flows(packets_df)

TOTAL_PACKETS = len(packets_df)
TOTAL_FLOWS = len(flows_df)
TCP_PACKETS = int((packets_df.get("protocol", pd.Series(dtype=str)) == "TCP").sum())
UDP_PACKETS = int((packets_df.get("protocol", pd.Series(dtype=str)) == "UDP").sum())
UNIQUE_IP = packets_df["src_ip"].nunique() if "src_ip" in packets_df.columns else 0
AVG_PACKET_SIZE = packets_df["packet_size"].mean() if "packet_size" in packets_df.columns else 0
AVG_FLOW_PACKETS = flows_df["packet_count"].mean() if "packet_count" in flows_df.columns else 0

# ----------------------------------------------------------------------
# 상단 요약 카드
# ----------------------------------------------------------------------
c1, c2, c3, c4, c5 = st.columns(5)
card_data = [
    (c1, "총 Packets", f"{TOTAL_PACKETS:,}"),
    (c2, "총 Flows", f"{TOTAL_FLOWS:,}"),
    (c3, "TCP Packets 수", f"{TCP_PACKETS:,}"),
    (c4, "UDP Packets 수", f"{UDP_PACKETS:,}"),
    (c5, "Unique IP", f"{UNIQUE_IP:,}"),
]
for col, label, value in card_data:
    with col:
        st.markdown(
            f"""<div class="metric-card">
                    <div class="metric-label">{label}</div>
                    <div class="metric-value">{value}</div>
                </div>""",
            unsafe_allow_html=True,
        )

st.markdown("<hr/>", unsafe_allow_html=True)

# ----------------------------------------------------------------------
# 요약 통계 카드
# ----------------------------------------------------------------------
s1, s2 = st.columns(2)
with s1:
    st.markdown(
        f"""<div class="metric-card">
                <div class="metric-label">평균 Packet 크기</div>
                <div class="metric-value">{AVG_PACKET_SIZE:.1f} B</div>
            </div>""",
        unsafe_allow_html=True,
    )
with s2:
    st.markdown(
        f"""<div class="metric-card">
                <div class="metric-label">평균 Flow Packets</div>
                <div class="metric-value">{AVG_FLOW_PACKETS:.1f}</div>
            </div>""",
        unsafe_allow_html=True,
    )


# 지도 piechart ui 
if "src_ip" not in packets_df.columns:
    st.info("src_ip 컬럼이 없어 지도를 표시할 수 없습니다.")
else:
    geo_ip_tuple = tuple(packets_df["src_ip"].dropna().tolist())
    geo_df = load_geo_data(geo_ip_tuple)
    geo_df["status_label"] = geo_df["status"].map(STATUS_LABELS).fillna(geo_df["status"])

    ok_df = geo_df[geo_df["status"] == "ok"]
    private_df = geo_df[geo_df["status"] == "private"]
    anomalous_df = geo_df[geo_df["status"].isin(ANOMALOUS_SOURCE_STATUSES)]

    if ok_df.empty:
        st.info("지도에 표시할 IP 위치 정보가 없습니다.")
    else:
        fig_geo, fig_pie, count_df = build_geo_figures(ok_df)

        col_map, col_pie = st.columns([3, 1], gap="small")
        with col_map:
            st.plotly_chart(fig_geo, width="stretch", config={"displayModeBar": False})
        with col_pie:
            st.plotly_chart(fig_pie, width="stretch", config={"displayModeBar": False})

    st.markdown(
        f'<div class="geo-note">🏠 사설 IP {len(private_df):,}건 · '
        f'⚠️ 비정상 출발지(멀티캐스트/예약대역) {len(anomalous_df):,}건</div>',
        unsafe_allow_html=True,
    )

st.markdown("<hr/>", unsafe_allow_html=True)

# ----------------------------------------------------------------------
# Traffic Monitor  (Packets / Flows 탭 + Detail 패널)
# ----------------------------------------------------------------------
st.markdown('<div class="section-title">📦 Traffic Monitor</div>', unsafe_allow_html=True)

left, right = st.columns([1, 1])

# ---- 탭 간 선택 상호배타 처리 (한쪽 선택 시 반대쪽 자동 해제) ----
if "prev_packets_sel" not in st.session_state:
    st.session_state.prev_packets_sel = ()
if "prev_flows_sel" not in st.session_state:
    st.session_state.prev_flows_sel = ()

_packets_state = st.session_state.get("packets_table")
_flows_state = st.session_state.get("flows_table")

_packets_rows_now = tuple(_packets_state["selection"]["rows"]) if _packets_state else ()
_flows_rows_now = tuple(_flows_state["selection"]["rows"]) if _flows_state else ()

_packets_changed = _packets_rows_now != st.session_state.prev_packets_sel
_flows_changed = _flows_rows_now != st.session_state.prev_flows_sel

if _packets_changed and _packets_rows_now:
    st.session_state["flows_table"] = {"selection": {"rows": [], "columns": []}}
elif _flows_changed and _flows_rows_now:
    st.session_state["packets_table"] = {"selection": {"rows": [], "columns": []}}

selected_rows = []
selected_df = pd.DataFrame()
selected_kind = "packet"

filtered = packets_df.copy()
st.caption(f"Packets : {len(filtered):,} | Flows : {TOTAL_FLOWS:,}")

with left:
    tab_packets, tab_flows = st.tabs(["📄 Packets", "🔀 Flows"])

    with tab_packets:
        packets_full = filtered.reset_index(drop=True)
        show_cols = [c for c in ["id", "timestamp", "src_ip", "protocol", "tcp_flags"] if c in packets_full.columns]
        display_df = packets_full[show_cols]

        event = st.dataframe(
            display_df,
            width='stretch',
            height=380,
            hide_index=True,
            on_select="rerun",
            selection_mode="single-row",
            key="packets_table",
        )
        if event is not None and event.selection.rows:
            selected_rows = event.selection.rows
            selected_df = packets_full
            selected_kind = "packet"

    with tab_flows:
        if flows_df.empty:
            st.info("Flow 데이터를 만들 수 있는 컬럼(src_ip, dst_ip 등)이 부족합니다.")
        else:
            flow_display = flows_df.reset_index(drop=True)
            flow_event = st.dataframe(
                flow_display,
                width='stretch',
                height=380,
                hide_index=True,
                on_select="rerun",
                selection_mode="single-row",
                key="flows_table",
            )
            if flow_event is not None and flow_event.selection.rows:
                selected_rows = flow_event.selection.rows
                selected_df = flow_display
                selected_kind = "flow"

# 이번 런의 최종 선택 상태를 다음 비교용으로 저장
st.session_state.prev_packets_sel = tuple(
    st.session_state.get("packets_table", {}).get("selection", {}).get("rows", [])
)
st.session_state.prev_flows_sel = tuple(
    st.session_state.get("flows_table", {}).get("selection", {}).get("rows", [])
)

with right:
    st.markdown('<div class="section-title">📄 상세정보 </div>', unsafe_allow_html=True)
    if selected_rows:
        row = selected_df.iloc[selected_rows[0]]
        st.markdown(render_detail(row, kind=selected_kind), unsafe_allow_html=True)
    else:
        st.markdown(
            '<div class="detail-empty">Packet 또는 Flow를 선택하세요.</div>',
            unsafe_allow_html=True,
        )