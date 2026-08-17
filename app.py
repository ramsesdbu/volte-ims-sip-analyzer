import os
import re
import tempfile
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st
from parser.pcap_reader import PcapReader
from parser.sip_parser import SIPParser

st.set_page_config(
    page_title="VoLTE / IMS NOC & SIP Analyzer",
    page_icon="📞",
    layout="wide",
    initial_sidebar_state="expanded",
)

# =========================
# DARK TELECOM DASHBOARD UI
# =========================
st.markdown("""
<style>
html, body, [class*="css"] {
    font-family: Inter, Arial, sans-serif;
}
.stApp {
    background: #080b10;
    color: #e7edf5;
}
[data-testid="stHeader"] {
    background: rgba(8,11,16,0.96);
}
[data-testid="stSidebar"] {
    background: #0d1118;
    border-right: 1px solid #1d2633;
}
[data-testid="stSidebar"] * {
    color: #dce5ef !important;
}
.block-container {
    padding-top: 3.5rem !important;
    padding-bottom: 3rem;
    max-width: 1600px;
}
.main-title {
    font-size: 34px;
    font-weight: 800;
    color: #f4f7fb;
    letter-spacing: -0.5px;
    margin-bottom: 2px;
}
.subtitle {
    color: #8e9aaa;
    font-size: 14px;
    margin-bottom: 18px;
}
.section-title {
    font-size: 21px;
    font-weight: 800;
    color: #ffffff;
    margin-top: 18px;
    margin-bottom: 10px;
}
.kpi {
    background: linear-gradient(145deg,#101722,#0c1118);
    border: 1px solid #202b39;
    border-radius: 12px;
    padding: 13px 15px;
    min-height: 92px;
}
.kpi-label { color:#8f9baa; font-size:12px; text-transform:uppercase; letter-spacing:.6px; }
.kpi-value { color:#f4f7fb; font-size:27px; font-weight:800; margin-top:5px; }
.kpi-sub { color:#6f7c8c; font-size:11px; margin-top:3px; }
.status-ok { color:#31d07c; font-weight:800; }
.status-reject { color:#ffb84d; font-weight:800; }
.status-error { color:#ff5f6d; font-weight:800; }
.status-drop { color:#ff7b72; font-weight:800; }
.status-unknown { color:#9aa7b5; font-weight:800; }
.card {
    background:#0d131c;
    border:1px solid #202b39;
    border-radius:12px;
    padding:14px 16px;
}
.small-muted { color:#7f8b9a; font-size:12px; }
.noc-hero {
    border-radius: 16px; padding: 18px 20px; border: 1px solid #263244;
    background: linear-gradient(135deg,#101722,#0b1017); margin-bottom: 12px;
}
.noc-hero.healthy { border-left: 6px solid #31d07c; }
.noc-hero.warning, .noc-hero.observe, .noc-hero.degraded { border-left: 6px solid #ffb84d; }
.noc-hero.critical { border-left: 6px solid #ff5f6d; }
.noc-hero.no-data { border-left: 6px solid #7f8b9a; }
.noc-state { font-size: 27px; font-weight: 850; margin-bottom: 4px; }
.noc-action { font-size: 15px; color:#f4f7fb; margin-top:8px; }
.noc-reason { font-size:12px; color:#8f9baa; margin-top:5px; }
.noc-check {
    background:#0d131c; border:1px solid #202b39; border-radius:10px;
    padding:10px 12px; margin-bottom:7px;
}
.noc-kpi {
    background:#0d131c;
    border:1px solid #202b39;
    border-radius:12px;
    padding:14px 16px;
    min-height:92px;
}
.noc-kpi-label {
    color:#8f9baa;
    font-size:12px;
    text-transform:uppercase;
    letter-spacing:.4px;
}
.noc-kpi-value {
    font-size:30px;
    font-weight:850;
    margin-top:6px;
}
.kpi-total .noc-kpi-value { color:#35a7ff; }
.kpi-ok .noc-kpi-value { color:#31d07c; }
.kpi-reject .noc-kpi-value { color:#ffb84d; }
.kpi-drop .noc-kpi-value { color:#ff7b72; }
.kpi-error .noc-kpi-value { color:#ff5f6d; }
.kpi-success .noc-kpi-value { color:#31d07c; }
.kpi-4xx .noc-kpi-value { color:#ffb84d; }
.kpi-5xx .noc-kpi-value { color:#ff5f6d; }
.kpi-6xx .noc-kpi-value { color:#b28cff; }
.kpi-sip-error .noc-kpi-value { color:#ff5f6d; }
hr { border-color:#202b39 !important; }
div[data-testid="stMetric"] {
    background:#0d131c;
    border:1px solid #202b39;
    border-radius:12px;
    padding:12px 14px;
}
div[data-testid="stMetricLabel"] {
    color:#b8c4d3 !important;
    font-size:13px !important;
    font-weight:600 !important;
}
div[data-testid="stMetricValue"] {
    color:#ffffff !important;
    font-size:30px !important;
    font-weight:850 !important;
}
.stDataFrame { border:1px solid #202b39; border-radius:10px; }

/* =========================
   HIGH-CONTRAST CONTROLS
   ========================= */

/* Streamlit select / multiselect: dark text on the existing light control */
[data-baseweb="select"] > div {
    background:#f3f5f8 !important;
    border:1px solid #cbd5e1 !important;
    border-radius:9px !important;
}
[data-baseweb="select"] span,
[data-baseweb="select"] input,
[data-baseweb="select"] [role="option"] {
    color:#111827 !important;
    -webkit-text-fill-color:#111827 !important;
}
[data-baseweb="select"] input::placeholder {
    color:#475569 !important;
    -webkit-text-fill-color:#475569 !important;
}
[data-baseweb="select"] svg {
    fill:#334155 !important;
}
[data-baseweb="popover"] {
    background:#ffffff !important;
}
[data-baseweb="popover"] [role="option"] {
    color:#111827 !important;
    background:#ffffff !important;
}
[data-baseweb="popover"] [role="option"]:hover {
    background:#e5e7eb !important;
}

/* File uploader: dark readable text on white/light uploader */
[data-testid="stFileUploader"] section {
    background:#f3f5f8 !important;
    border:1px dashed #94a3b8 !important;
    border-radius:10px !important;
}
[data-testid="stFileUploader"] section * {
    color:#1f2937 !important;
    -webkit-text-fill-color:#1f2937 !important;
}
[data-testid="stFileUploader"] button {
    background:#ffffff !important;
    color:#111827 !important;
    border:1px solid #94a3b8 !important;
}
[data-testid="stFileUploader"] small {
    color:#475569 !important;
}

/* Captions / helper text must remain readable on dark background */
.stCaption, [data-testid="stCaptionContainer"] {
    color:#b7c3d1 !important;
    font-size:13px !important;
}

/* General Streamlit labels */
[data-testid="stWidgetLabel"] p,
[data-testid="stWidgetLabel"] label {
    color:#e7edf5 !important;
    font-weight:600 !important;
}

/* Plotly tooltip / modebar */
.js-plotly-plot .plotly .modebar-btn path {
    fill:#cbd5e1 !important;
}

.stPlotlyChart { overflow: visible !important; }
</style>
""", unsafe_allow_html=True)

PLOT_LAYOUT = dict(
    paper_bgcolor="#0d131c",
    plot_bgcolor="#0d131c",
    font=dict(color="#dce5ef"),
    margin=dict(l=15, r=15, t=55, b=15),
    xaxis=dict(gridcolor="#1d2633", zerolinecolor="#1d2633", tickfont=dict(color="#cbd5e1", size=11)),
    yaxis=dict(gridcolor="#1d2633", zerolinecolor="#1d2633", tickfont=dict(color="#cbd5e1", size=11)),
    legend=dict(bgcolor="#0d131c", font=dict(color="#f8fafc", size=12)),
)

def make_donut(labels, values, title, center_text="", colors=None, height=320):
    """Dark-theme donut chart for the NOC dashboard."""
    fig = go.Figure(go.Pie(
        labels=labels,
        values=values,
        hole=0.68,
        domain=dict(x=[0.0, 1.0], y=[0.18, 1.0]),
        textinfo="percent",
        textposition="inside",
        insidetextorientation="horizontal",
        textfont=dict(color="#ffffff", size=13, family="Arial"),
        sort=False,
        marker=dict(
            colors=colors,
            line=dict(color="#0d131c", width=3)
        ) if colors else None,
        hovertemplate="<b>%{label}</b><br>Count: %{value:,}<br>%{percent}<extra></extra>",
    ))
    fig.update_layout(
        title=dict(text=title, x=0.02, font=dict(size=15, color="#e7edf5")),
        paper_bgcolor="#0d131c",
        plot_bgcolor="#0d131c",
        font=dict(color="#dce5ef"),
        height=height,
        margin=dict(l=10, r=10, t=55, b=62),
        legend=dict(
            orientation="h",
            yanchor="bottom",
            y=-0.13,
            xanchor="center",
            x=0.5,
            bgcolor="#0d131c",
            bordercolor="#202b39",
            borderwidth=0,
            font=dict(color="#f8fafc", size=12, family="Arial"),
            itemsizing="constant",
        ),
        annotations=[dict(
            text=center_text, x=0.5, y=0.59,
            font=dict(size=22, color="#ffffff", family="Arial"),
            showarrow=False
        )],
    )
    return fig


# =========================
# SIP HELPERS
# =========================
SIP_ERROR_TEXT = {
    400:"Bad Request", 401:"Unauthorized", 402:"Payment Required",
    403:"Forbidden", 404:"Not Found", 405:"Method Not Allowed",
    406:"Not Acceptable", 407:"Proxy Authentication Required",
    408:"Request Timeout", 409:"Conflict", 410:"Gone",
    412:"Conditional Request Failed", 413:"Request Entity Too Large",
    414:"Request-URI Too Long", 415:"Unsupported Media Type",
    416:"Unsupported URI Scheme", 420:"Bad Extension",
    421:"Extension Required", 422:"Session Interval Too Small",
    423:"Interval Too Brief", 480:"Temporarily Unavailable",
    481:"Call/Transaction Does Not Exist", 482:"Loop Detected",
    483:"Too Many Hops", 484:"Address Incomplete", 485:"Ambiguous",
    486:"Busy Here", 487:"Request Terminated", 488:"Not Acceptable Here",
    489:"Bad Event", 491:"Request Pending", 494:"Security Agreement Required",
    500:"Server Internal Error", 501:"Not Implemented", 502:"Bad Gateway",
    503:"Service Unavailable", 504:"Server Time-out", 505:"Version Not Supported",
    513:"Message Too Large", 580:"Precondition Failure",
    600:"Busy Everywhere", 603:"Decline", 604:"Does Not Exist Anywhere",
    606:"Not Acceptable",
}

REJECT_CODES = {480, 486, 487, 600, 603, 604, 606}
DROP_CODES = {408, 481, 500, 502, 503, 504}

def clean_df(df):
    if df is None:
        return pd.DataFrame()
    df = df.copy()
    df.columns = [str(c).strip() for c in df.columns]
    aliases = {
        "CallID":"Call-ID", "Call Id":"Call-ID", "call_id":"Call-ID",
        "call-id":"Call-ID", "Source IP":"Source", "Destination IP":"Destination",
        "UserAgent":"User-Agent"
    }
    for old, new in aliases.items():
        if old in df.columns and new not in df.columns:
            df.rename(columns={old:new}, inplace=True)
    for col in [
        "Frame","Time","Source","Destination","Method","Call-ID",
        "From","To","Via","CSeq","User-Agent"
    ]:
        if col not in df.columns:
            df[col] = ""
    for col in df.columns:
        df[col] = df[col].fillna("").astype(str)
    return df

def methods(df):
    if "Method" not in df:
        return pd.Series("", index=df.index)
    return df["Method"].fillna("").astype(str).str.strip()

def response_codes(df):
    s = methods(df)
    x = s.str.extract(r"^\s*SIP/2\.0\s+([1-6]\d\d)", expand=False)
    x = x.fillna(s.str.extract(r"^\s*([1-6]\d\d)\b", expand=False))
    return pd.to_numeric(x, errors="coerce").astype("Int64")


def enrich_sip_from_raw_packets(df, packets):
    """Fallback SIP first-line parser for packets not decoded by SIPParser.

    This is especially useful when a PCAP contains a SIP 4xx/5xx/6xx response
    but the parser did not place the response line into the Method column.
    """
    if df.empty or not packets:
        return df

    out = df.copy()
    if "Frame" not in out.columns:
        return out

    frame_to_text = {}
    frame_to_raw = {}
    for idx, packet in enumerate(packets, start=1):
        try:
            if not packet.haslayer("Raw"):
                continue
            raw = bytes(packet["Raw"].load)
            if not raw:
                continue
            first = raw.split(b"\\r\\n", 1)[0].split(b"\\n", 1)[0]
            decoded = raw.decode("utf-8", errors="ignore")
            line = first.decode("utf-8", errors="ignore").strip()
            if line:
                frame_to_text[str(idx)] = line
                frame_to_raw[str(idx)] = decoded
        except Exception:
            continue

    if not frame_to_text:
        return out

    if "Raw SIP" not in out.columns:
        out["Raw SIP"] = ""

    for i in out.index:
        frame = str(out.at[i, "Frame"])
        line = frame_to_text.get(frame, "")
        if not line:
            continue

        out.at[i, "Raw SIP"] = frame_to_raw.get(frame, "")

        current = str(out.at[i, "Method"]).strip()
        if not current:
            out.at[i, "Method"] = line
        elif not re.match(r"^\\s*SIP/2\\.0\\s+[1-6]\\d\\d\\b", current, re.I):
            # Preserve a request method if the parser already decoded it.
            pass

    return out

def count_class(df, first):
    c = response_codes(df)
    return int((c // 100 == first).fillna(False).sum())

def values(df, col):
    if col not in df:
        return []
    return sorted([x for x in df[col].fillna("").astype(str).str.strip().unique() if x])

def fmt_time(value):
    try:
        if value is None or value == "":
            return ""
        return pd.to_datetime(float(value), unit="s").strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    except Exception:
        return str(value)

def rtp_detect(packets):
    rows = []
    for i, p in enumerate(packets):
        try:
            if not p.haslayer("IP") or not p.haslayer("UDP"):
                continue
            ip = p["IP"]; udp = p["UDP"]
            sp, dp = int(udp.sport), int(udp.dport)
            if sp in (5060, 5061) or dp in (5060, 5061):
                continue
            raw = bytes(udp.payload)
            if len(raw) < 12 or (raw[0] >> 6) != 2:
                continue
            pt = raw[1] & 0x7f
            if pt >= 128:
                continue
            rows.append({
                "Packet": i+1, "Source": ip.src, "Destination": ip.dst,
                "Source Port": sp, "Destination Port": dp, "Payload Type": pt,
                "Sequence": int.from_bytes(raw[2:4], "big"),
                "Timestamp": int.from_bytes(raw[4:8], "big"),
                "SSRC": int.from_bytes(raw[8:12], "big")
            })
        except Exception:
            pass
    return pd.DataFrame(rows)

def classify_call(codes, has_bye):
    """Classify a dialog from SIP response codes."""
    if not codes:
        return "INCOMPLETE", "No final SIP response captured for this Call-ID", None
    invite_final = None
    for c in codes:
        if c >= 200:
            invite_final = c
    errors = sorted(set(c for c in codes if 400 <= c <= 699))

    if invite_final == 200:
        if any(c in DROP_CODES for c in errors) and has_bye:
            return "DROPPED", "Established call later showed abnormal termination: " + ", ".join(map(str, errors)), invite_final
        return "OK", "INVITE completed with SIP 200 OK", invite_final

    if invite_final in REJECT_CODES:
        return "REJECTED", f"Call rejected by SIP {invite_final} {SIP_ERROR_TEXT.get(invite_final,'')}".strip(), invite_final

    if invite_final and invite_final >= 500:
        return "ERROR", f"SIP server error {invite_final} {SIP_ERROR_TEXT.get(invite_final,'')}".strip(), invite_final

    if invite_final and invite_final >= 400:
        return "ERROR", f"SIP error {invite_final} {SIP_ERROR_TEXT.get(invite_final,'')}".strip(), invite_final

    return "INCOMPLETE", "No final INVITE response captured for this Call-ID", invite_final


def extract_sip_number(value):
    """Extract a telephone/user part from common SIP URI/header formats."""
    s = str(value or "").strip()
    if not s:
        return ""
    # Prefer tel:+... or sip:+... / sip:user@...
    m = re.search(r"(?:tel:|sip:)?(\+?\d{6,15})", s, re.I)
    if m:
        return m.group(1)
    # Fallback: user part before @ when numeric
    m = re.search(r"sip:([^@;>\s]+)", s, re.I)
    if m:
        candidate = m.group(1)
        if re.fullmatch(r"\+?\d{6,15}", candidate):
            return candidate
    return ""


def extract_party_numbers(group):
    """Return calling (A) and called (B) numbers from the first INVITE."""
    g = group.copy()
    m = methods(g)
    invite_rows = g[m.eq("INVITE")]
    row = invite_rows.iloc[0] if not invite_rows.empty else g.iloc[0]

    a_number = extract_sip_number(row.get("From", ""))
    b_number = extract_sip_number(row.get("To", ""))

    # Fallback to raw SIP headers when parser columns are empty.
    raw = str(row.get("Raw SIP", "") or "")
    if not a_number:
        fm = re.search(r"(?im)^From:\s*.*?(?:sip:|tel:)(\+?\d{6,15})", raw)
        if fm:
            a_number = fm.group(1)
    if not b_number:
        tm = re.search(r"(?im)^To:\s*.*?(?:sip:|tel:)(\+?\d{6,15})", raw)
        if tm:
            b_number = tm.group(1)

    return a_number, b_number


def provisioning_target(group):
    """Determine provisioning target from explicit SIP evidence.

    Generic NOT_PROVISIONED evidence is not proof of B-number failure.
    When A/B is not explicitly identified, B-number is marked as
    CHECK-FIRST only when a called-party number is available.
    """
    raw = " ".join(group.get("Raw SIP", pd.Series(dtype=str)).astype(str).tolist()).lower()
    if not raw:
        return "UNKNOWN"

    if any(x in raw for x in [
        "called_party", "called party", "terminating_subscriber",
        "terminating subscriber", "b-number", "b number", "b_number"
    ]):
        return "B-NUMBER"

    if any(x in raw for x in [
        "calling_party", "calling party", "originating_subscriber",
        "originating subscriber", "a-number", "a number", "a_number"
    ]):
        return "A-NUMBER"

    if "called subscriber" in raw or "called party" in raw:
        return "B-NUMBER"
    if "calling subscriber" in raw or "calling party" in raw:
        return "A-NUMBER"

    return "B-NUMBER-CHECK-FIRST"


def call_analysis(df, rtp):
    if df.empty or "Call-ID" not in df:
        return pd.DataFrame()

    rows = []
    for cid, g in df.groupby("Call-ID", dropna=False):
        cid = str(cid).strip()
        if not cid:
            continue

        g = g.copy()
        g["_t"] = pd.to_numeric(g["Time"], errors="coerce")
        g = g.sort_values("_t", kind="stable")
        m = methods(g)
        c = response_codes(g)
        invites = g[m.eq("INVITE")]
        byes = g[m.eq("BYE")]
        times = pd.to_numeric(g["Time"], errors="coerce").dropna()
        allcodes = [int(x) for x in c.dropna().tolist()]

        status, reason, final_response = classify_call(allcodes, len(byes) > 0)
        errors = sorted(set(x for x in allcodes if 400 <= x <= 699))
        raw_text = " ".join(g.get("Raw SIP", pd.Series(dtype=str)).astype(str).tolist()).lower() if "Raw SIP" in g else ""
        provisioning_terms = [
            "not provisioned", "not_provisioned", "provisioning",
            "service not provisioned", "ims_voice_service_not_provisioned",
            "subscriber not provisioned", "subscriber service not provisioned",
        ]
        provisioning_evidence = any(term in raw_text for term in provisioning_terms)
        a_number, b_number = extract_party_numbers(g)
        prov_target = provisioning_target(g)

        # If explicit B-number evidence exists, mark B as the affected party.
        # Otherwise keep the target UNKNOWN rather than guessing from a 403 alone.
        if provisioning_evidence and prov_target == "UNKNOWN":
            prov_target = "B-NUMBER-CHECK-FIRST" if b_number else "UNKNOWN"

        start = float(times.min()) if len(times) else None
        end = float(times.max()) if len(times) else None
        duration = round(end - start, 3) if start is not None and end is not None else 0

        first_src = str(g.iloc[0].get("Source",""))
        last_dst = str(g.iloc[-1].get("Destination",""))

        rows.append({
            "Call-ID": cid,
            "Status": status,
            "Reason": reason,
            "Timestamp": fmt_time(start),
            "_StartEpoch": start,
            "Duration (s)": duration,
            "Source": first_src,
            "Destination": last_dst,
            "INVITE": int(len(invites)),
            "BYE": int(len(byes)),
            "Final Response": final_response if final_response is not None else "",
            "SIP Error": ", ".join(map(str, errors)),
            "SIP Error Detail": "; ".join(
                f"{x} {SIP_ERROR_TEXT.get(x,'SIP response')}" for x in errors
            ),
            "A-Number": a_number,
            "B-Number": b_number,
            "Provisioning Evidence": "YES" if provisioning_evidence else "NO",
            "Provisioning Target": prov_target if provisioning_evidence else "NONE",
            "RTP Present": "YES" if not rtp.empty else "NO",
        })
    return pd.DataFrame(rows)

def health(call_df, e4, e5):
    # NOC/L1 health: severity is based on service-impact rate, not one isolated error.
    if call_df.empty:
        return "NO DATA", "⚪"
    total = len(call_df)
    ok = int((call_df.Status == "OK").sum())
    rejected = int((call_df.Status == "REJECTED").sum())
    dropped = int((call_df.Status == "DROPPED").sum())
    errors = int((call_df.Status == "ERROR").sum())
    rate = ok / total * 100 if total else 0
    bad_rate = (rejected + dropped + errors) / total * 100 if total else 0

    if rate >= 98 and bad_rate <= 2 and e5 == 0:
        return "HEALTHY", "🟢"
    if rate >= 95 and bad_rate <= 5:
        return "HEALTHY", "🟢"
    if rate >= 85 and bad_rate <= 15:
        return "WARNING", "🟠"
    return "CRITICAL", "🔴"


def noc_decision(call_df, sip_df, rtp_df, provisioning_detected=False):
    if call_df.empty:
        if not sip_df.empty:
            return {
                "state": "OBSERVE", "icon": "🟠",
                "headline": "SIGNALING PRESENT / CALL KPI NOT AVAILABLE",
                "action": "Check Call-ID correlation and INVITE transaction completeness.",
                "reason": "SIP packets exist, but no complete call dialog was built.",
                "priority": "MEDIUM",
                "checks": [
                    "Validate Call-ID and CSeq continuity.",
                    "Check whether INVITE and final response are both captured.",
                    "Verify the capture point sees both directions.",
                ],
            }
        return {
            "state": "NO DATA", "icon": "⚪", "headline": "NO DATA",
            "action": "Upload a PCAP/PCAPNG containing SIP traffic.",
            "reason": "No call/session data is available.", "priority": "INFO",
            "checks": []
        }

    total = len(call_df)
    ok = int((call_df.Status == "OK").sum())
    rejected = int((call_df.Status == "REJECTED").sum())
    dropped = int((call_df.Status == "DROPPED").sum())
    errors = int((call_df.Status == "ERROR").sum())
    unknown = int((call_df.Status == "INCOMPLETE").sum())

    success = ok / total * 100
    reject_rate = rejected / total * 100
    drop_rate = dropped / total * 100
    error_rate = errors / total * 100
    unknown_rate = unknown / total * 100

    codes = response_codes(sip_df).dropna().astype(int)
    c5 = int((codes >= 500).sum())
    c503 = int((codes == 503).sum())
    c504 = int((codes == 504).sum())

    # Provisioning-specific decision: explicit SIP evidence such as
    # "Subscriber not provisioned" takes precedence over generic Core/IMS escalation.
    if provisioning_detected:
        prov_rows = call_df[call_df["Provisioning Evidence"] == "YES"].copy() if "Provisioning Evidence" in call_df.columns else pd.DataFrame()
        b_nums = sorted([x for x in prov_rows.get("B-Number", pd.Series(dtype=str)).astype(str).unique() if x])
        a_nums = sorted([x for x in prov_rows.get("A-Number", pd.Series(dtype=str)).astype(str).unique() if x])
        targets = sorted([x for x in prov_rows.get("Provisioning Target", pd.Series(dtype=str)).astype(str).unique() if x and x != "NONE"])

        if "B-NUMBER" in targets and b_nums:
            affected_party = f"B-NUMBER / CALLED PARTY: {', '.join(b_nums[:3])}"
            target_reason = "Explicit SIP provisioning evidence identifies the called party."
            priority_text = "CHECK B-NUMBER"
        elif "A-NUMBER" in targets and a_nums:
            affected_party = f"A-NUMBER / CALLING PARTY: {', '.join(a_nums[:3])}"
            target_reason = "Explicit SIP provisioning evidence identifies the calling party."
            priority_text = "CHECK A-NUMBER"
        elif "B-NUMBER-CHECK-FIRST" in targets and b_nums:
            affected_party = f"B-NUMBER / CALLED PARTY: {', '.join(b_nums[:3])}"
            target_reason = (
                "The capture has generic subscriber/service provisioning evidence without an explicit A/B target. "
                "For this INVITE, check the called subscriber (B-number) FIRST. This is a troubleshooting priority, "
                "not proof that B is the root cause."
            )
            priority_text = "CHECK B-NUMBER FIRST"
        else:
            affected_party = "A/B NUMBER NOT DETERMINED FROM CAPTURE"
            target_reason = "Provisioning evidence exists, but the capture does not safely identify whether A or B is affected."
            priority_text = "A/B UNKNOWN"

        decision = {
            "state": "ACTION REQUIRED", "icon": "🔴",
            "headline": "PROVISIONING ISSUE DETECTED",
            "action": f"Escalate to Provisioning team — {priority_text}. Verify IMS/VoLTE provisioning for the identified subscriber.",
            "reason": f"{target_reason} {affected_party}",
            "priority": "HIGH",
            "checks": [
                affected_party,
                "Verify IMS/VoLTE voice-service entitlement for the identified subscriber.",
                "Check subscriber profile synchronization between provisioning and IMS.",
                "Check HSS/UDM/UDR subscriber data and provisioning transaction status.",
                "After correction, re-test IMS registration and the affected call.",
            ],
        }
    elif error_rate >= 10 or drop_rate >= 5 or c503 >= 3 or c504 >= 3:
        decision = {
            "state": "CRITICAL", "icon": "🔴", "headline": "ACTION REQUIRED",
            "action": "Escalate to Core/IMS team and identify the failing SIP node/interface.",
            "reason": f"Service-impacting failures: {error_rate:.1f}% errors, {drop_rate:.1f}% drops, {c5} SIP 5xx.",
            "priority": "HIGH",
            "checks": [
                "Identify the Source/Destination pair producing the 5xx/timeout.",
                "Inspect the SIP ladder for the first failing transaction.",
                "Check node alarms, CPU/memory, transport reachability and recent changes.",
                "If isolated to one node, follow the approved drain/routing procedure.",
            ],
        }
    elif error_rate > 0 or drop_rate > 0 or reject_rate >= 10 or c5 > 0:
        decision = {
            "state": "WARNING", "icon": "🟠", "headline": "INVESTIGATE",
            "action": "Investigate the dominant SIP error/reject before escalating.",
            "reason": f"Degradation indicators: {error_rate:.1f}% errors, {reject_rate:.1f}% rejects, {drop_rate:.1f}% drops.",
            "priority": "MEDIUM",
            "checks": [
                "Sort SIP errors by code and confirm the dominant code.",
                "Check whether the problem is isolated to one Source/Destination.",
                "Inspect a failed Call-ID and its SIP ladder.",
                "Correlate failure timestamps with alarms/change activity.",
            ],
        }
    elif unknown_rate > 5:
        decision = {
            "state": "WARNING", "icon": "🟠", "headline": "CHECK CAPTURE",
            "action": "Validate packet-capture completeness before declaring the network healthy.",
            "reason": f"{unknown_rate:.1f}% of calls cannot be classified from captured SIP signaling.",
            "priority": "MEDIUM",
            "checks": [
                "Confirm both call directions are present.",
                "Check for missing INVITE/final response packets.",
                "Verify capture filters are not removing critical SIP messages.",
            ],
        }
    elif success >= 95:
        decision = {
            "state": "HEALTHY", "icon": "🟢", "headline": "NETWORK HEALTHY",
            "action": "No immediate NOC action. Continue monitoring.",
            "reason": f"Call success is {success:.2f}% with no material service-impacting pattern.",
            "priority": "LOW",
            "checks": [
                "Continue monitoring success rate and SIP 4xx/5xx trend.",
                "Watch for recurring errors by node or destination.",
            ],
        }
    else:
        decision = {
            "state": "WARNING", "icon": "🟠", "headline": "DEGRADED",
            "action": "Investigate the failed-call population and dominant SIP response.",
            "reason": f"Call success is {success:.2f}%, below the healthy target.",
            "priority": "MEDIUM",
            "checks": [
                "Identify the top SIP error/reject code.",
                "Inspect affected Call-IDs and SIP ladder.",
                "Correlate failure timestamps with network alarms.",
            ],
        }

    if not rtp_df.empty:
        dirs = rtp_df.groupby(["Source", "Destination"]).size()
        if len(dirs) == 1:
            decision["checks"].append("One-way RTP indication: check media path/anchor.")
        else:
            decision["checks"].append("Bidirectional RTP detected in the capture.")
    else:
        decision["checks"].append("RTP not present; media health cannot be concluded from this capture.")

    return decision


def top_sip_issues(sip_df, limit=5):
    if sip_df.empty:
        return pd.DataFrame(columns=["SIP Code", "Count", "Description", "Class"])
    codes = response_codes(sip_df).dropna().astype(int)
    codes = codes[codes >= 400]
    if codes.empty:
        return pd.DataFrame(columns=["SIP Code", "Count", "Description", "Class"])
    out = codes.value_counts().head(limit).rename_axis("SIP Code").reset_index(name="Count")
    out["Description"] = out["SIP Code"].map(lambda x: SIP_ERROR_TEXT.get(int(x), "SIP response"))
    out["Class"] = out["SIP Code"].map(lambda x: f"{int(x)//100}xx")
    return out


def affected_endpoints(call_df, limit=8):
    if call_df.empty:
        return pd.DataFrame(columns=["Source", "Destination", "Calls", "Bad Calls", "Bad %"])
    x = call_df.copy()
    x["Bad"] = x["Status"].isin(["REJECTED", "ERROR", "DROPPED"])
    out = x.groupby(["Source", "Destination"], dropna=False).agg(
        Calls=("Call-ID", "count"), Bad_Calls=("Bad", "sum")
    ).reset_index()
    out["Bad %"] = (out["Bad_Calls"] / out["Calls"] * 100).round(2)
    return out.sort_values(["Bad_Calls", "Bad %"], ascending=False).head(limit)


def message_label(row):
    """Create a compact SIP message label for the ladder diagram."""
    method = str(row.get("Method", "")).strip()
    code = response_codes(pd.DataFrame([row])).iloc[0]
    if pd.notna(code):
        code = int(code)
        desc = SIP_ERROR_TEXT.get(code, "")
        return f"SIP/2.0 {code}" + (f" {desc}" if desc else "")
    return method or "SIP"


def message_short_label(row):
    """Short label used inside the ladder diagram."""
    method = str(row.get("Method", "")).strip()
    code = response_codes(pd.DataFrame([row])).iloc[0]
    if pd.notna(code):
        code = int(code)
        return f"{code} {SIP_ERROR_TEXT.get(code, '')}".strip()
    return method or "SIP"


def sip_ladder_data(df, call_id):
    """Return ordered SIP messages for one Call-ID."""
    if df.empty or not call_id:
        return pd.DataFrame()
    g = df[df["Call-ID"].astype(str) == str(call_id)].copy()
    if g.empty:
        return g
    g["_t"] = pd.to_numeric(g["Time"], errors="coerce")
    g = g.sort_values(["_t", "Frame"], kind="stable").reset_index(drop=True)
    g["Timestamp"] = g["_t"].apply(fmt_time)
    g["Message"] = g.apply(message_label, axis=1)
    g["Short Message"] = g.apply(message_short_label, axis=1)
    g["Code"] = response_codes(g).astype("Int64")
    g["Direction"] = g["Source"].astype(str) + " → " + g["Destination"].astype(str)
    return g


def render_sip_ladder(df, call_id):
    """Render a SIP ladder / sequence diagram for a single Call-ID."""
    g = sip_ladder_data(df, call_id)
    if g.empty:
        st.info("Tidak ada SIP message untuk Call-ID tersebut.")
        return

    # Keep participant count manageable while preserving the actual endpoints.
    participants = []
    for ip in list(g["Source"]) + list(g["Destination"]):
        ip = str(ip).strip()
        if ip and ip not in participants:
            participants.append(ip)
    if len(participants) < 2:
        st.warning("Participant SIP tidak cukup untuk membuat ladder diagram.")
        return

    x_map = {ip: i for i, ip in enumerate(participants)}
    y_vals = list(range(len(g), 0, -1))

    fig = go.Figure()

    # Lifelines
    for ip, x in x_map.items():
        fig.add_trace(go.Scatter(
            x=[x, x], y=[0.5, len(g) + 0.7],
            mode="lines",
            line=dict(color="#334155", width=1, dash="dot"),
            hoverinfo="skip",
            showlegend=False,
        ))
        fig.add_annotation(
            x=x, y=len(g) + 0.95,
            text=f"<b>{ip}</b>",
            showarrow=False,
            font=dict(color="#e5edf6", size=12),
            bgcolor="#111827",
            bordercolor="#334155",
            borderwidth=1,
            borderpad=5,
        )

    # SIP messages / arrows
    for idx, row in g.iterrows():
        src = str(row.get("Source", "")).strip()
        dst = str(row.get("Destination", "")).strip()
        if src not in x_map or dst not in x_map:
            continue
        x0, x1 = x_map[src], x_map[dst]
        y = y_vals[idx]
        code = row.get("Code")
        code_int = int(code) if pd.notna(code) else None
        method = str(row.get("Method", "")).strip()

        if code_int is not None:
            if code_int >= 500:
                line_color = "#ff5f6d"
            elif code_int >= 400:
                line_color = "#ffb84d"
            elif code_int >= 300:
                line_color = "#b28cff"
            else:
                line_color = "#35a7ff"
        else:
            line_color = "#31d07c" if method in {"ACK", "BYE", "CANCEL"} else "#35a7ff"

        fig.add_annotation(
            x=x1, y=y,
            ax=x0, ay=y,
            xref="x", yref="y", axref="x", ayref="y",
            text="",
            showarrow=True,
            arrowhead=3,
            arrowsize=1.05,
            arrowwidth=1.8,
            arrowcolor=line_color,
        )

        # Put the message text near the midpoint of the arrow.
        mid = (x0 + x1) / 2
        side = 0.10 if x1 >= x0 else -0.10
        fig.add_annotation(
            x=mid + side,
            y=y + 0.13,
            text=f"<b>{message_short_label(row)}</b>",
            showarrow=False,
            font=dict(color=line_color, size=10),
            bgcolor="#0d131c",
            bordercolor="#273449",
            borderwidth=1,
            borderpad=3,
        )

        fig.add_annotation(
            x=min(x0, x1) - 0.03,
            y=y - 0.17,
            text=str(row.get("Timestamp", "")),
            showarrow=False,
            xanchor="right",
            font=dict(color="#718096", size=8),
        )

    fig.update_xaxes(
        tickmode="array",
        tickvals=list(x_map.values()),
        ticktext=participants,
        showgrid=False,
        zeroline=False,
        showticklabels=False,
        range=[-0.65, max(x_map.values()) + 0.65],
    )
    fig.update_yaxes(showgrid=False, zeroline=False, showticklabels=False, range=[0, len(g) + 1.35])
    fig.update_layout(
        paper_bgcolor="#0d131c",
        plot_bgcolor="#0d131c",
        font=dict(color="#dce5ef"),
        height=max(500, 145 + len(g) * 65),
        margin=dict(l=90, r=40, t=75, b=25),
        title=dict(text=f"SIP Ladder — {call_id}", x=0.01),
        hovermode=False,
    )
    st.plotly_chart(fig, use_container_width=True)

    ladder_display = g[[
        "Timestamp", "Frame", "Source", "Destination", "Short Message",
        "Call-ID", "CSeq", "From", "To", "Via", "User-Agent"
    ]].copy()
    ladder_display.columns = [
        "Timestamp", "Frame", "Source", "Destination", "SIP Message",
        "Call-ID", "CSeq", "From", "To", "Via", "User-Agent"
    ]
    st.dataframe(ladder_display, use_container_width=True, height=360, hide_index=True)

    # Selected-message detail
    msg_idx = st.selectbox(
        "🔬 Inspect SIP message",
        range(len(g)),
        format_func=lambda i: f"Frame {g.iloc[i]['Frame']} • {g.iloc[i]['Timestamp']} • {g.iloc[i]['Short Message']}",
        key=f"msg_{call_id}",
    )
    msg = g.iloc[msg_idx]
    st.json({
        k: msg.get(k, "")
        for k in [
            "Frame", "Time", "Timestamp", "Source", "Destination", "Method",
            "Call-ID", "CSeq", "From", "To", "Via", "User-Agent"
        ]
    })


# =========================
# HEADER
# =========================
st.markdown('<div class="main-title">📡 VoLTE / IMS NOC & SIP Analyzer</div>', unsafe_allow_html=True)
st.markdown(
    '<div class="subtitle">Network Health • Call KPI • SIP Errors • NOC Action • SIP Ladder • RTP</div>',
    unsafe_allow_html=True
)

# =========================
# SIDEBAR
# =========================
with st.sidebar:
    st.markdown("## 🔎 NOC Analysis Filter")
    uploaded = st.file_uploader("Upload PCAP / PCAPNG", type=["pcap", "pcapng"])

    st.divider()
    method_filter = st.multiselect(
        "SIP Method",
        ["INVITE","ACK","BYE","CANCEL","REGISTER","OPTIONS","PRACK","UPDATE","INFO","MESSAGE","SUBSCRIBE","NOTIFY"]
    )
    response_filter = st.multiselect(
        "Response Code",
        ["100","180","183","200","202","300","301","302","400","401","403","404","408",
         "480","481","486","487","488","500","502","503","504","580","600","603","604","606"]
    )
    st.caption("Filter hanya untuk mempersempit bukti. Health tetap dihitung dari traffic yang dianalisis.")

if not uploaded:
    st.info("Upload file PCAP/PCAPNG untuk memulai analisis.")
    st.stop()

filename = None
try:
    with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as f:
        f.write(uploaded.read())
        filename = f.name

    reader = PcapReader(filename)
    reader.load()
    sip_df = clean_df(SIPParser().parse(reader.packets))
    sip_df = enrich_sip_from_raw_packets(sip_df, reader.packets)
except Exception as exc:
    st.error("Gagal membaca atau menganalisis PCAP.")
    st.exception(exc)
    if filename and os.path.exists(filename):
        os.remove(filename)
    st.stop()

# Keep the complete parsed capture for NOC KPIs.
# Filters are applied only to the troubleshooting/display dataset.
all_sip_df = sip_df.copy()
rtp_df = rtp_detect(reader.packets)

# Diagnostic: response lines found by the SIP parser / raw fallback.
parsed_response_count = int(response_codes(all_sip_df).notna().sum())

view_sip_df = all_sip_df.copy()
if method_filter:
    view_sip_df = view_sip_df[methods(view_sip_df).isin(method_filter)].copy()
if response_filter:
    view_sip_df = view_sip_df[
        response_codes(view_sip_df).isin([int(x) for x in response_filter])
    ].copy()

# Source / destination selectors use actual file values.
with st.sidebar:
    source_options = values(all_sip_df, "Source")
    destination_options = values(all_sip_df, "Destination")
    source_filter = st.multiselect("Source IP", source_options)
    destination_filter = st.multiselect("Destination IP", destination_options)

if source_filter:
    view_sip_df = view_sip_df[view_sip_df.Source.isin(source_filter)].copy()
if destination_filter:
    view_sip_df = view_sip_df[view_sip_df.Destination.isin(destination_filter)].copy()

# NOC metrics ALWAYS use the complete capture.
e2 = count_class(all_sip_df, 2)
e4 = count_class(all_sip_df, 4)
e5 = count_class(all_sip_df, 5)
ms = methods(all_sip_df)
register = int(ms.eq("REGISTER").sum())
invite = int(ms.eq("INVITE").sum())
bye = int(ms.eq("BYE").sum())
unique = int(all_sip_df["Call-ID"].replace("", pd.NA).dropna().nunique())
call_df = call_analysis(all_sip_df, rtp_df)
provisioning_detected = False
if "Raw SIP" in all_sip_df.columns:
    raw_capture_text = " ".join(all_sip_df["Raw SIP"].astype(str).tolist()).lower()
    provisioning_terms = [
        "not provisioned", "not_provisioned", "provisioning",
        "service not provisioned", "ims_voice_service_not_provisioned",
        "subscriber not provisioned", "subscriber service not provisioned",
        "called_party", "called party", "called subscriber",
        "b-number", "b number", "b_number",
        "calling_party", "calling party", "calling subscriber",
        "a-number", "a number", "a_number",
    ]
    provisioning_detected = any(term in raw_capture_text for term in provisioning_terms)
sip_df = view_sip_df

total_calls = len(call_df)
ok_calls = int((call_df.Status == "OK").sum()) if total_calls else 0
rejected_calls = int((call_df.Status == "REJECTED").sum()) if total_calls else 0
error_calls = int((call_df.Status == "ERROR").sum()) if total_calls else 0
dropped_calls = int((call_df.Status == "DROPPED").sum()) if total_calls else 0
unknown_calls = int((call_df.Status == "INCOMPLETE").sum()) if total_calls else 0
success_rate = ok_calls / total_calls * 100 if total_calls else 0
health_name, health_icon = health(call_df, e4, e5)

# File banner
st.markdown(
    f'<div class="card">📁 <b>{uploaded.name}</b> • '
    f'{reader.packet_count():,} packets • {len(all_sip_df):,} SIP • {len(rtp_df):,} RTP</div>',
    unsafe_allow_html=True
)

# =========================
# SIMPLE NOC OVERVIEW
# =========================
decision = noc_decision(call_df, all_sip_df, rtp_df, provisioning_detected)

st.markdown('<div class="section-title">🟢 NETWORK STATUS</div>', unsafe_allow_html=True)

state = decision["state"]
icon = decision["icon"]
headline = decision["headline"]

if state == "HEALTHY":
    status_color = "#31d07c"
elif state in ("WARNING", "OBSERVE"):
    status_color = "#ffb84d"
elif state == "CRITICAL":
    status_color = "#ff5f6d"
else:
    status_color = "#9aa7b5"

st.markdown(
    f'''
    <div style="
        background:#0d131c;border:2px solid {status_color};
        border-radius:14px;padding:20px 24px;margin-bottom:14px;">
        <div style="font-size:32px;font-weight:850;color:{status_color};">
            {icon} {headline}
        </div>
        <div style="font-size:15px;color:#e7edf5;margin-top:8px;">
            <b>Action:</b> {decision["action"]}
        </div>
        <div style="font-size:12px;color:#8f9baa;margin-top:6px;">
            {decision["reason"]}
        </div>
    </div>
    ''',
    unsafe_allow_html=True
)


# =========================
# PROVISIONING EVIDENCE
# =========================
if provisioning_detected and not call_df.empty:
    prov_calls = call_df[call_df["Provisioning Evidence"] == "YES"].copy()
    if not prov_calls.empty:
        st.markdown('<div class="section-title">🔐 PROVISIONING EVIDENCE</div>', unsafe_allow_html=True)

        show_cols = [
            "Timestamp", "Status", "Call-ID", "A-Number", "B-Number",
            "Final Response", "Provisioning Target", "Provisioning Evidence",
            "SIP Error Detail"
        ]
        show_cols = [c for c in show_cols if c in prov_calls.columns]

        st.dataframe(
            prov_calls[show_cols],
            use_container_width=True,
            hide_index=True,
            height=250
        )

        # Highlight the affected party explicitly.
        b_targets = prov_calls[prov_calls["Provisioning Target"] == "B-NUMBER"] if "Provisioning Target" in prov_calls.columns else pd.DataFrame()
        a_targets = prov_calls[prov_calls["Provisioning Target"] == "A-NUMBER"] if "Provisioning Target" in prov_calls.columns else pd.DataFrame()
        b_first = prov_calls[prov_calls["Provisioning Target"] == "B-NUMBER-CHECK-FIRST"] if "Provisioning Target" in prov_calls.columns else pd.DataFrame()

        if not b_targets.empty:
            b_list = ", ".join(sorted(set(b_targets["B-Number"].astype(str))))
            st.error(
                f"🔴 B-NUMBER IDENTIFIED AS NOT PROVISIONED — Called Party: {b_list}. "
                f"**Escalate to Provisioning Team and check this B-number.**"
            )
        elif not a_targets.empty:
            a_list = ", ".join(sorted(set(a_targets["A-Number"].astype(str))))
            st.error(
                f"🔴 A-NUMBER IDENTIFIED AS NOT PROVISIONED — Calling Party: {a_list}. "
                f"**Escalate to Provisioning Team and check this A-number.**"
            )
        elif not b_first.empty and b_first["B-Number"].astype(str).str.len().gt(0).any():
            b_list = ", ".join(sorted(set(x for x in b_first["B-Number"].astype(str) if x)))
            st.warning(
                f"🟠 PROVISIONING CHECK PRIORITY: B-NUMBER / CALLED PARTY — {b_list}. "
                f"The capture says subscriber/service is not provisioned but does not explicitly identify A or B. "
                f"**Check B-number provisioning FIRST**, then verify A-number if B is provisioned."
            )
        else:
            st.warning(
                "🟠 PROVISIONING EVIDENCE DETECTED — A/B NUMBER CANNOT BE DETERMINED. "
                "Inspect the failed Call-ID, From/To and raw SIP provisioning headers."
            )

# Core NOC numbers: deliberately limited to the values L1 needs first.
total_sip_codes = response_codes(all_sip_df).dropna().astype(int)
sip_4xx = int(((total_sip_codes >= 400) & (total_sip_codes < 500)).sum())
sip_5xx = int(((total_sip_codes >= 500) & (total_sip_codes < 600)).sum())
sip_6xx = int(((total_sip_codes >= 600) & (total_sip_codes < 700)).sum())


# =========================
# SERVICE PERFORMANCE CHARTS
# =========================
st.markdown('<div class="section-title">📈 SERVICE PERFORMANCE</div>', unsafe_allow_html=True)

chart_left, chart_mid, chart_right = st.columns([1, 1.35, 1])

with chart_left:
    status_labels = ["Call OK", "Reject", "Call Error", "Dropped", "Incomplete"]
    status_values = [ok_calls, rejected_calls, error_calls, dropped_calls, unknown_calls]
    status_colors = ["#31d07c", "#ffb84d", "#ff5f6d", "#ff7b72", "#64748b"]
    if sum(status_values) > 0:
        fig_status = make_donut(
            status_labels, status_values, "CALL STATUS DISTRIBUTION",
            f"<b>{total_calls:,}</b><br><span style='font-size:11px'>Total Calls</span>",
            status_colors, 350
        )
        st.plotly_chart(fig_status, use_container_width=True, config={"displayModeBar": False})

with chart_mid:
    if not call_df.empty:
        trend = call_df.copy()
        trend["Start"] = pd.to_datetime(trend["_StartEpoch"], unit="s", errors="coerce")
        trend = trend.dropna(subset=["Start"]).sort_values("Start")
        trend["Bucket"] = trend["Start"].dt.floor("5min") if len(trend) > 30 else trend["Start"]
        trend_counts = trend.groupby(["Bucket", "Status"]).size().reset_index(name="Calls")
        fig_trend = px.line(
            trend_counts, x="Bucket", y="Calls", color="Status",
            markers=True, title="CALL TREND",
            color_discrete_map={
                "OK": "#31d07c", "REJECTED": "#ffb84d",
                "ERROR": "#ff5f6d", "DROPPED": "#ff7b72",
                "INCOMPLETE": "#64748b",
            }
        )
        fig_trend.update_layout(
            **PLOT_LAYOUT, height=330,
            xaxis_title="Timestamp", yaxis_title="Calls"
        )
        fig_trend.update_traces(line=dict(width=2))
        fig_trend.update_layout(
            legend=dict(
                bgcolor="#0d131c",
                font=dict(color="#f8fafc", size=12, family="Arial"),
            )
        )
        st.plotly_chart(fig_trend, use_container_width=True, config={"displayModeBar": False})

with chart_right:
    response_labels = ["2xx Success", "4xx Client", "5xx Server", "6xx Global"]
    response_values = [e2, sip_4xx, sip_5xx, sip_6xx]
    response_colors = ["#31d07c", "#ffb84d", "#ff5f6d", "#b28cff"]
    if sum(response_values) > 0:
        fig_response = make_donut(
            response_labels, response_values, "SIP RESPONSE CLASS",
            f"<b>{sum(response_values):,}</b><br><span style='font-size:11px'>SIP Responses</span>",
            response_colors, 350
        )
        st.plotly_chart(fig_response, use_container_width=True, config={"displayModeBar": False})

st.markdown('<div class="section-title">📊 KEY KPI</div>', unsafe_allow_html=True)
def noc_kpi(label, value, css_class):
    st.markdown(
        f'''
        <div class="noc-kpi {css_class}">
            <div class="noc-kpi-label">{label}</div>
            <div class="noc-kpi-value">{value}</div>
        </div>
        ''',
        unsafe_allow_html=True
    )

k = st.columns(6)
with k[0]:
    noc_kpi("Total Calls", f"{total_calls:,}", "kpi-total")
with k[1]:
    noc_kpi("Call OK", f"{ok_calls:,}", "kpi-ok")
with k[2]:
    noc_kpi("Reject", f"{rejected_calls:,}", "kpi-reject")
with k[3]:
    noc_kpi("Dropped", f"{dropped_calls:,}", "kpi-drop")
with k[4]:
    noc_kpi("Call Error", f"{error_calls:,}", "kpi-error")
with k[5]:
    noc_kpi("Success Rate", f"{success_rate:.2f}%", "kpi-success")

st.markdown('<div class="section-title">🚨 SIP ERROR</div>', unsafe_allow_html=True)
e = st.columns(4)
with e[0]:
    noc_kpi("4xx", f"{sip_4xx:,}", "kpi-4xx")
with e[1]:
    noc_kpi("5xx", f"{sip_5xx:,}", "kpi-5xx")
with e[2]:
    noc_kpi("6xx", f"{sip_6xx:,}", "kpi-6xx")
with e[3]:
    noc_kpi("SIP Errors", f"{sip_4xx + sip_5xx + sip_6xx:,}", "kpi-sip-error")

# Explicitly expose 500/503/504 so an L1 engineer cannot miss them.
error_codes = total_sip_codes[total_sip_codes >= 400]
if len(error_codes):
    error_summary = (
        error_codes.value_counts()
        .rename_axis("SIP Code")
        .reset_index(name="Count")
    )
    error_summary["Meaning"] = error_summary["SIP Code"].map(
        lambda x: SIP_ERROR_TEXT.get(int(x), "SIP response")
    )
    error_summary["Class"] = error_summary["SIP Code"].map(lambda x: f"{int(x)//100}xx")

    st.dataframe(
        error_summary[["SIP Code", "Class", "Count", "Meaning"]],
        use_container_width=True,
        hide_index=True,
        height=230
    )
else:
    st.success("✅ No SIP 4xx / 5xx / 6xx response detected.")


# =========================
# SECONDARY KPI
# =========================
st.markdown('<div class="section-title">🎯 KEY PERFORMANCE INDICATORS</div>', unsafe_allow_html=True)

durations = pd.to_numeric(call_df.get("Duration (s)", pd.Series(dtype=float)), errors="coerce").dropna()
avg_duration = durations.mean() if len(durations) else 0
p95_duration = durations.quantile(0.95) if len(durations) else 0
sip_total = len(total_sip_codes)
sip_error_rate = ((sip_4xx + sip_5xx + sip_6xx) / sip_total * 100) if sip_total else 0
sip_5xx_rate = (sip_5xx / sip_total * 100) if sip_total else 0

kpi2 = st.columns(6)
secondary = [
    ("AVG CALL DURATION", f"{avg_duration:.2f}s", "kpi-total"),
    ("P95 CALL DURATION", f"{p95_duration:.2f}s", "kpi-total"),
    ("SIP ERROR RATE", f"{sip_error_rate:.2f}%", "kpi-error"),
    ("SIP 5XX RATE", f"{sip_5xx_rate:.2f}%", "kpi-5xx"),
    ("SIP MESSAGES", f"{len(all_sip_df):,}", "kpi-total"),
    ("RTP PACKETS", f"{len(rtp_df):,}", "kpi-ok"),
]
for col, (label, value, cls) in zip(kpi2, secondary):
    with col:
        noc_kpi(label, value, cls)

st.markdown('<div class="section-title">🕒 RECENT CALL EVENTS</div>', unsafe_allow_html=True)
st.caption(
    "INCOMPLETE berarti Call-ID ditemukan tetapi final response INVITE tidak terlihat pada capture. "
    "Ini bukan otomatis call failure; periksa kelengkapan capture terlebih dahulu."
)
if not call_df.empty:
    recent = call_df.sort_values("_StartEpoch", ascending=False).head(15).copy()
    st.dataframe(
        recent[[
            "Timestamp", "Status", "Call-ID", "A-Number", "B-Number",
            "Source", "Destination", "Final Response", "Provisioning Target",
            "SIP Error Detail"
        ]],
        use_container_width=True,
        hide_index=True,
        height=330
    )
else:
    st.info("No complete Call-ID is available in this capture.")

st.markdown('<div class="section-title">🛠️ L1 NEXT STEP</div>', unsafe_allow_html=True)
for item in decision["checks"][:4]:
    st.markdown(f"**• {item}**")

# =========================
# CALL TIMELINE

# =========================
st.markdown('<div class="section-title">🕒 Call Timeline — Timestamp & Status</div>', unsafe_allow_html=True)

if not call_df.empty:
    timeline = call_df.copy()
    timeline["Start"] = pd.to_datetime(timeline["_StartEpoch"], unit="s", errors="coerce")
    timeline = timeline.sort_values("Start")

    fig = px.scatter(
        timeline,
        x="Start",
        y="Status",
        hover_data={
            "Call-ID": True,
            "Source": True,
            "Destination": True,
            "Final Response": True,
            "SIP Error": True,
            "Duration (s)": True,
            "Start": True,
        },
        title="Call Events by Timestamp"
    )
    fig.update_traces(marker=dict(size=11))
    fig.update_layout(
        **PLOT_LAYOUT,
        height=430,
        xaxis_title="Timestamp",
        yaxis_title="Call Status"
    )
    st.plotly_chart(fig, use_container_width=True)

    timeline_display = timeline[
        ["Timestamp","Status","Call-ID","Source","Destination","Duration (s)","Final Response","SIP Error Detail"]
    ].copy()
    st.dataframe(timeline_display, use_container_width=True, height=330, hide_index=True)
else:
    st.info("Belum ada Call-ID yang cukup untuk membuat call timeline.")

# =========================
# SIP RESPONSE STATISTICS
# =========================
st.markdown('<div class="section-title">🚨 SIP ERROR MESSAGE ANALYSIS</div>', unsafe_allow_html=True)
allcodes = response_codes(all_sip_df).dropna().astype(int)

if len(allcodes):
    code_df = allcodes.value_counts().sort_index().rename_axis("Response").reset_index(name="Count")
    code_df["Response"] = code_df["Response"].astype(int)
    code_df["Description"] = code_df["Response"].map(
        lambda x: SIP_ERROR_TEXT.get(x, "SIP Success / Provisional Response")
    )
    code_df["Class"] = code_df["Response"].map(lambda x: f"{x//100}xx")

    left, right = st.columns([1.35, 1])

    with left:
        error_only = code_df[code_df.Response >= 400].copy()
        if not error_only.empty:
            error_only["Label"] = error_only.apply(
                lambda r: f"{int(r['Response'])} — {r['Description']}", axis=1
            )
            fig_errors = px.bar(
                error_only.sort_values("Count"),
                x="Count", y="Label", orientation="h",
                text="Count", title="TOP SIP ERROR MESSAGES"
            )
            fig_errors.update_traces(textposition="outside", marker_color="#ff5f6d")
            fig_errors.update_layout(
                **PLOT_LAYOUT, height=360,
                xaxis_title="Occurrences", yaxis_title=""
            )
            st.plotly_chart(fig_errors, use_container_width=True, config={"displayModeBar": False})
        else:
            st.success("✅ No SIP 4xx / 5xx / 6xx response detected.")

    with right:
        error_only = code_df[code_df.Response >= 400].copy()
        if not error_only.empty:
            error_only["Label"] = error_only.apply(
                lambda r: f"{int(r['Response'])} {r['Class']}", axis=1
            )
            colors = []
            for _, r in error_only.iterrows():
                c = int(r["Response"])
                colors.append("#b28cff" if c >= 600 else "#ff5f6d" if c >= 500 else "#ffb84d")

            fig_error_donut = go.Figure(go.Pie(
                labels=error_only["Label"],
                values=error_only["Count"],
                hole=0.65,
                textinfo="percent",
                marker=dict(colors=colors, line=dict(color="#0d131c", width=3)),
                hovertemplate="<b>%{label}</b><br>Count: %{value:,}<br>%{percent}<extra></extra>",
            ))
            fig_error_donut.update_layout(
                title=dict(text="SIP ERROR DISTRIBUTION", x=0.02,
                           font=dict(size=15, color="#e7edf5")),
                paper_bgcolor="#0d131c", plot_bgcolor="#0d131c",
                font=dict(color="#dce5ef"), height=360,
                margin=dict(l=10, r=10, t=55, b=62),
                legend=dict(
                    orientation="h",
                    yanchor="bottom",
                    y=-0.13,
                    xanchor="center",
                    x=0.5,
                    bgcolor="#0d131c",
                    font=dict(color="#f8fafc", size=12, family="Arial"),
                ),
                annotations=[dict(
                    text=f"<b>{int(error_only['Count'].sum()):,}</b><br><span style='font-size:11px'>SIP Errors</span>",
                    x=0.5, y=0.5, font=dict(size=20, color="#f4f7fb"),
                    showarrow=False
                )],
            )
            st.plotly_chart(fig_error_donut, use_container_width=True, config={"displayModeBar": False})
        else:
            st.info("No SIP error distribution available.")

    st.dataframe(
        code_df.rename(columns={"Response": "SIP Code"}),
        use_container_width=True, hide_index=True, height=280
    )
else:
    st.info("Tidak ada SIP response code yang dapat dianalisis.")

# =========================
# NOC ALARMS / TOP PROBLEMS
# =========================
st.markdown('<div class="section-title">🚨 NOC Alarm View — What should L1 investigate first?</div>', unsafe_allow_html=True)
issue_df = top_sip_issues(sip_df, 5)
ep_df = affected_endpoints(call_df, 8)

left, right = st.columns([1.1, 1.4])
with left:
    if issue_df.empty:
        st.success("✅ No SIP 4xx/5xx/6xx issue detected in the captured signaling.")
    else:
        st.dataframe(
            issue_df.rename(columns={"SIP Code":"SIP", "Description":"Meaning"}),
            use_container_width=True, hide_index=True, height=260
        )

with right:
    if ep_df.empty:
        st.info("No endpoint pair can be ranked yet.")
    else:
        st.dataframe(
            ep_df.rename(columns={"Bad_Calls":"Bad Calls"}),
            use_container_width=True, hide_index=True, height=260
        )

st.markdown('<div class="section-title">🛠️ L1 Quick Action Guide</div>', unsafe_allow_html=True)
guide = [
    ("408 / 504", "Timeout", "Check transport/reachability, latency, routing, overloaded node, or missing response."),
    ("500 / 503", "Server error / unavailable", "Check IMS/SIP node health, CPU/memory, service status and recent changes."),
    ("401 / 407", "Authentication", "Check IMS authentication/credentials, proxy path and registration state."),
    ("403 + NOT_PROVISIONED", "Provisioning", "Check A/B subscriber profile and IMS/VoLTE entitlement; escalate to Provisioning Team when explicit provisioning evidence is present."),
    ("403", "Forbidden", "Do not classify every 403 as provisioning; check policy, authorization, SIP headers and subscriber profile."),
    ("404 / 480", "Destination unavailable", "Check routing, subscriber reachability, TAS/AS or terminating-side registration."),
    ("486 / 603", "User/service rejection", "Usually not a network outage; verify busy/decline pattern and affected subscriber population."),
]
guide_df = pd.DataFrame(guide, columns=["SIP", "Meaning", "First L1 Check"])
st.dataframe(guide_df, use_container_width=True, hide_index=True, height=270)

# =========================
# SIP LADDER / SEQUENCE DIAGRAM
# =========================
st.markdown('<div class="section-title">📡 SIP Ladder / Sequence Diagram</div>', unsafe_allow_html=True)

if not call_df.empty:
    ladder_options = call_df.sort_values("_StartEpoch", na_position="last")["Call-ID"].astype(str).tolist()
    default_ladder = 0
    selected_ladder_call = st.selectbox(
        "Select Call-ID for SIP ladder",
        ladder_options,
        index=default_ladder,
        format_func=lambda cid: (
            f"{cid}  |  "
            f"{call_df.loc[call_df['Call-ID'].astype(str).eq(cid), 'Status'].iloc[0]}  |  "
            f"{call_df.loc[call_df['Call-ID'].astype(str).eq(cid), 'Final Response'].iloc[0]}"
        ),
        key="ladder_call_id",
    )

    selected_summary = call_df[call_df["Call-ID"].astype(str) == str(selected_ladder_call)]
    if not selected_summary.empty:
        srow = selected_summary.iloc[0]
        c1, c2, c3, c4, c5 = st.columns(5)
        c1.metric("Status", str(srow["Status"]))
        c2.metric("Start", str(srow["Timestamp"]))
        c3.metric("Duration", f"{float(srow['Duration (s)']):.3f} s")
        c4.metric("Final SIP", str(srow["Final Response"]) if str(srow["Final Response"]) else "-")
        c5.metric("SIP Error", str(srow["SIP Error"]) if str(srow["SIP Error"]) else "None")

        render_sip_ladder(sip_df, selected_ladder_call)
else:
    st.info("Upload PCAP dengan Call-ID untuk menampilkan SIP ladder / sequence diagram.")

# =========================
# CALL TROUBLESHOOTING
# =========================
st.markdown('<div class="section-title">🛠️ Call Troubleshooting</div>', unsafe_allow_html=True)

if not call_df.empty:
    problems = call_df[call_df.Status.isin(["REJECTED","ERROR","DROPPED","INCOMPLETE"])].copy()

    display_cols = [
        "Timestamp","Status","Call-ID","A-Number","B-Number","Source","Destination",
        "Duration (s)","Final Response","Provisioning Target","SIP Error Detail","Reason"
    ]
    st.dataframe(call_df[display_cols], use_container_width=True, height=360, hide_index=True)

    if not problems.empty:
        cid = st.selectbox(
            "🔍 Inspect problematic Call-ID",
            problems["Call-ID"].tolist()
        )
        row = problems[problems["Call-ID"] == cid].iloc[0]

        if row.Status == "REJECTED":
            st.warning(f"🟠 CALL REJECTED — {row.Reason}")
        elif row.Status == "ERROR":
            st.error(f"🔴 CALL ERROR — {row.Reason}")
        elif row.Status == "DROPPED":
            st.error(f"⚠️ CALL DROPPED — {row.Reason}")
        else:
            st.info(f"⚪ CALL INCOMPLETE — {row.Reason}")

        detail = {
            "Timestamp": row["Timestamp"],
            "Call-ID": row["Call-ID"],
            "Source": row["Source"],
            "Destination": row["Destination"],
            "Status": row["Status"],
            "Final SIP Response": row["Final Response"],
            "SIP Error": row["SIP Error Detail"],
            "A-Number": row.get("A-Number", ""),
            "B-Number": row.get("B-Number", ""),
            "Provisioning Target": row.get("Provisioning Target", ""),
            "Provisioning Evidence": row.get("Provisioning Evidence", ""),
            "Duration": row["Duration (s)"],
            "Reason": row["Reason"],
        }
        st.json(detail)
else:
    st.info("Belum ada Call-ID yang cukup untuk troubleshooting.")

# =========================
# REGISTER ANALYSIS
# =========================
st.markdown('<div class="section-title">📝 REGISTER / Registration Statistics</div>', unsafe_allow_html=True)
if not sip_df.empty:
    reg = sip_df[methods(sip_df).isin(["REGISTER"])].copy()
    if not reg.empty:
        reg_codes = response_codes(reg).dropna().astype(int)
        reg_summary = (
            reg_codes.value_counts().sort_index()
            .rename_axis("Response").reset_index(name="Count")
        )
        reg_summary["Description"] = reg_summary["Response"].map(
            lambda x: SIP_ERROR_TEXT.get(x, "SIP response")
        )
        st.dataframe(reg_summary, use_container_width=True, hide_index=True)
    else:
        st.info("Tidak ada REGISTER message.")

# =========================
# RTP / MEDIA
# =========================
st.markdown('<div class="section-title">🎙️ RTP / Media Analysis</div>', unsafe_allow_html=True)
if rtp_df.empty:
    st.warning("No RTP detected in this PCAP.")
else:
    a = st.columns(4)
    a[0].metric("RTP Packets", f"{len(rtp_df):,}")
    a[1].metric("RTP Sources", f"{rtp_df.Source.nunique():,}")
    a[2].metric("RTP Destinations", f"{rtp_df.Destination.nunique():,}")
    a[3].metric("SSRC", f"{rtp_df.SSRC.nunique():,}")

    dirs = (
        rtp_df.groupby(["Source","Destination"])
        .size()
        .reset_index(name="RTP Packets")
        .sort_values("RTP Packets", ascending=False)
    )
    st.dataframe(dirs, use_container_width=True, hide_index=True)
    if len(dirs) == 1:
        st.warning("⚠️ One-way RTP indication: only one RTP direction was detected.")
    else:
        st.success("✅ RTP traffic detected in multiple directions.")

# =========================
# ANALYSIS SCOPE
# =========================
st.markdown('<div class="section-title">ℹ️ Analysis Scope</div>', unsafe_allow_html=True)
st.caption(
    "Health status is calculated from the complete uploaded PCAP/PCAPNG. "
    "It is an evidence-based NOC view of the captured traffic, not a live network-wide assurance status. "
    "RTP absence is not treated as a network failure because a signaling-only capture may legitimately contain no media packets."
)

# =========================
# PACKET + SIP EXPLORER
# =========================
st.markdown('<div class="section-title">📦 Packet Summary</div>', unsafe_allow_html=True)
st.dataframe(reader.summary(), use_container_width=True, height=300)

st.markdown('<div class="section-title">📨 SIP Packets</div>', unsafe_allow_html=True)
st.dataframe(sip_df, use_container_width=True, height=420, hide_index=True)

st.markdown('<div class="section-title">🔬 SIP Message Explorer</div>', unsafe_allow_html=True)
if not sip_df.empty:
    frame = str(st.selectbox("Select Frame", sip_df.Frame.astype(str).tolist()))
    rows = sip_df[sip_df.Frame.astype(str) == frame]
    if not rows.empty:
        row = rows.iloc[0]
        st.markdown(
            f'<div class="card"><b>Frame {frame}</b> '
            f'• {fmt_time(row.get("Time",""))} '
            f'• {row.get("Source","")} → {row.get("Destination","")} '
            f'• <b>{row.get("Method","")}</b></div>',
            unsafe_allow_html=True
        )
        st.json({
            k: row.get(k, "")
            for k in [
                "Frame","Time","Source","Destination","Method",
                "Call-ID","CSeq","User-Agent","From","To","Via"
            ]
        })

if filename and os.path.exists(filename):
    try:
        os.remove(filename)
    except Exception:
        pass
