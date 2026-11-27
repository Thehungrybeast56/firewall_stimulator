"""
SAFE SIMULATION: no real packets are sent, captured or scanned. Every packet
is just a few typed-in or randomly generated values.
"""

import pandas as pd
import plotly.express as px
import streamlit as st

from firewall import (
    ACTIONS,
    ANY,
    PROTOCOLS,
    RULE_PROTOCOLS,
    FirewallEngine,
    ValidationError,
    blocked_by_rule,
    generate_sample_packets,
    make_packet,
    security_observations,
)
from test_firewall import run_test_cases

# ---------------------------------------------------------------------------
# Page setup and theme
# ---------------------------------------------------------------------------
st.set_page_config(page_title="Firewall Rule Simulator", page_icon="🛡️", layout="wide")

GREEN = "#22c55e"
RED = "#ef4444"
BLUE = "#38bdf8"
COLOR_MAP = {"ALLOW": GREEN, "DENY": RED}
ICONS = {"ALLOW": "🟢 ALLOW", "DENY": "🔴 DENY"}
PAGES = [
    "📊 Overview Dashboard",
    "⚙️ Firewall Rules",
    "📡 Packet Simulator",
    "🔍 Security Analysis",
    "✅ Test Cases",
]

st.markdown(
    """
<style>
.stApp { background-color: #0b1426; }
[data-testid="stSidebar"] { background-color: #0f1b33; border-right: 1px solid #1f3358; }
h1, h2, h3, h4 { color: #e5edf9; }
.metric-card { background: #111d36; border: 1px solid #1f3358; border-radius: 12px; padding: 16px 18px; margin-bottom: 8px; }
.metric-label { color: #8fa3c4; font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.05em; }
.metric-value { font-size: 2.1rem; font-weight: 700; line-height: 1.2; }
.verdict { border: 2px solid; border-radius: 12px; padding: 18px; text-align: center; font-size: 2.2rem; font-weight: 800; background: #111d36; margin: 8px 0 14px 0; }
.obs { border-radius: 8px; padding: 10px 14px; margin-bottom: 8px; background: #111d36; border-left: 5px solid #38bdf8; color: #e5edf9; }
.obs-good { border-left-color: #22c55e; }
.obs-warning { border-left-color: #f59e0b; }
.obs-info { border-left-color: #38bdf8; }
.brand { font-size: 1.3rem; font-weight: 700; color: #e5edf9; }
.brand-sub { color: #8fa3c4; font-size: 0.8rem; margin-bottom: 10px; }
</style>
""",
    unsafe_allow_html=True,
)


# ---------------------------------------------------------------------------
# Session state and callbacks
# ---------------------------------------------------------------------------
def init_state():
    if "engine" not in st.session_state:
        engine = FirewallEngine("DENY")
        engine.load_example_rules()
        st.session_state.engine = engine
    st.session_state.setdefault("policy_choice", "DENY")


def flash(kind, message):
    st.session_state["flash"] = (kind, message)


def show_flash():
    item = st.session_state.pop("flash", None)
    if item:
        kind, message = item
        (st.success if kind == "success" else st.error)(message)


def add_rule_cb():
    s = st.session_state
    try:
        source = ANY if s.rule_src_mode == "ANY" else s.rule_src_value
        port = ANY if s.rule_port_mode == "ANY" else s.rule_port_value
        rule = s.engine.add_rule(
            s.rule_action, source, port, s.rule_proto, s.rule_priority, s.rule_desc
        )
        flash("success", f"Added Rule #{rule.rule_id}: {rule.summary()} (priority {rule.priority})")
    except ValidationError as err:
        flash("error", str(err))


def delete_rule_cb():
    s = st.session_state
    rule_id = s.get("delete_choice")
    if rule_id is not None and s.engine.delete_rule(rule_id):
        flash("success", f"Deleted Rule #{rule_id}.")
    else:
        flash("error", "No rule selected to delete.")


def sample_traffic_cb():
    for packet in generate_sample_packets(50):
        st.session_state.engine.evaluate(packet)


def clear_log_cb():
    st.session_state.engine.clear_log()
    st.session_state.pop("last_result", None)


def reset_rules_cb():
    st.session_state.engine.load_example_rules()


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------
def metric_card(column, label, value, color=BLUE):
    column.markdown(
        f'<div class="metric-card"><div class="metric-label">{label}</div>'
        f'<div class="metric-value" style="color:{color}">{value}</div></div>',
        unsafe_allow_html=True,
    )


def log_dataframe(engine):
    columns = ["Time", "Source IP", "Destination IP", "Port", "Protocol",
               "Action", "Matched Rule", "Reason"]
    return pd.DataFrame([d.to_record() for d in engine.log], columns=columns)


def style_figure(fig):
    fig.update_layout(
        template="plotly_dark",
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        margin=dict(l=10, r=10, t=50, b=10),
        font=dict(color="#e5edf9"),
    )
    return fig


def rules_dataframe(engine):
    rows = []
    for position, rule in enumerate(engine.ordered_rules(), start=1):
        rows.append({
            "Order": position,
            "Rule ID": rule.rule_id,
            "Priority": rule.priority,
            "Action": ICONS[rule.action],
            "Source": rule.source,
            "Port": rule.port_text,
            "Protocol": rule.protocol,
            "Description": rule.description,
        })
    return pd.DataFrame(rows, columns=["Order", "Rule ID", "Priority", "Action",
                                       "Source", "Port", "Protocol", "Description"])


# ---------------------------------------------------------------------------
# Pages
# ---------------------------------------------------------------------------
def page_overview(engine):
    st.title("📊 Overview Dashboard")
    st.caption("Fictional network traffic only. No real packets are sent or scanned.")
    df = log_dataframe(engine)
    total = len(df)
    allowed = int((df["Action"] == "ALLOW").sum())
    denied = int((df["Action"] == "DENY").sum())
    block_pct = (100 * denied / total) if total else 0.0

    cols = st.columns(4)
    metric_card(cols[0], "Total packets", total, BLUE)
    metric_card(cols[1], "Allowed", allowed, GREEN)
    metric_card(cols[2], "Denied", denied, RED)
    metric_card(cols[3], "Block percentage", f"{block_pct:.1f}%", "#f59e0b")

    if total == 0:
        st.info("No packets yet. Use the **Packet Simulator** page, or click "
                "**Generate 50 sample packets** in the sidebar.")
        return

    left, right = st.columns([1, 2])
    with left:
        fig = px.pie(
            names=["ALLOW", "DENY"], values=[allowed, denied],
            color=["ALLOW", "DENY"], color_discrete_map=COLOR_MAP,
            hole=0.5, title="ALLOW vs DENY",
        )
        st.plotly_chart(style_figure(fig), key="overview_pie")
    with right:
        st.subheader("Recent packet activity")
        recent = df.tail(15).iloc[::-1].copy()
        recent["Action"] = recent["Action"].map(ICONS)
        st.dataframe(
            recent[["Time", "Source IP", "Destination IP", "Port", "Protocol", "Action", "Matched Rule"]],
            hide_index=True,
        )


def page_rules(engine):
    st.title("⚙️ Firewall Rules Configuration")
    show_flash()
    st.subheader("Add a new rule")
    with st.container(border=True):
        c1, c2, c3 = st.columns(3)
        with c1:
            st.selectbox("Action", ACTIONS, key="rule_action")
            st.number_input("Priority (lower number = checked first)",
                            min_value=1, max_value=9999, value=50, step=1, key="rule_priority")
        with c2:
            st.radio("Source IP", ["ANY", "Specific IP / CIDR"], key="rule_src_mode", horizontal=True)
            if st.session_state.rule_src_mode != "ANY":
                st.text_input("IP address or network", placeholder="192.168.1.10 or 192.168.1.0/24",
                              key="rule_src_value")
        with c3:
            st.radio("Destination port", ["ANY", "Specific port"], key="rule_port_mode", horizontal=True)
            if st.session_state.rule_port_mode != "ANY":
                st.number_input("Port number", min_value=1, max_value=65535, value=80, step=1,
                                key="rule_port_value")
        c4, c5 = st.columns([1, 2])
        c4.selectbox("Protocol", RULE_PROTOCOLS, index=RULE_PROTOCOLS.index(ANY), key="rule_proto")
        c5.text_input("Description (optional)", key="rule_desc")
        st.button("Add rule", on_click=add_rule_cb, type="primary")

    st.subheader("Rules in execution order")
    st.caption(
        f"Rules run top to bottom (lowest priority number first). The FIRST match decides. "
        f"If nothing matches, the default policy applies: **{engine.default_policy}**."
    )
    rules = engine.ordered_rules()
    if not rules:
        st.warning("There are no rules. Every packet will follow the default policy.")
    else:
        st.dataframe(rules_dataframe(engine), hide_index=True)
        labels = {r.rule_id: r.label() for r in rules}
        d1, d2 = st.columns([3, 1])
        d1.selectbox("Rule to delete", list(labels.keys()),
                     format_func=lambda rule_id: labels.get(rule_id, str(rule_id)), key="delete_choice")
        d2.markdown("<div style='height:1.8rem'></div>", unsafe_allow_html=True)
        d2.button("Delete selected rule", on_click=delete_rule_cb)


def page_simulator(engine):
    st.title("📡 Packet Simulator")
    st.caption("Enter a fictional packet. It is compared with the rules in priority order.")
    with st.form("packet_form"):
        c1, c2, c3, c4 = st.columns(4)
        src = c1.text_input("Source IP", value="192.168.1.10")
        dst = c2.text_input("Destination IP", value="10.0.0.10")
        port = c3.number_input("Destination port", min_value=1, max_value=65535, value=23, step=1)
        proto = c4.selectbox("Protocol", PROTOCOLS)
        submitted = st.form_submit_button("Simulate Packet", type="primary")
    st.caption("ICMP has no ports, so the port value is ignored when ICMP is selected.")

    if submitted:
        try:
            packet = make_packet(src, dst, port, proto)
            decision = engine.evaluate(packet)
            st.session_state["last_result"] = (decision, engine.trace(packet))
        except ValidationError as err:
            st.session_state.pop("last_result", None)
            st.error(str(err))

    result = st.session_state.get("last_result")
    if result:
        decision, trace = result
        color = GREEN if decision.action == "ALLOW" else RED
        st.markdown(
            f'<div class="verdict" style="border-color:{color};color:{color}">'
            f'{ICONS[decision.action]}</div>',
            unsafe_allow_html=True,
        )
        st.markdown(f"**Packet:** {decision.packet.describe()}")
        st.markdown(f"**Matched rule:** {decision.rule_label}")
        st.info(decision.reason)
        st.subheader("Rule-by-rule check")
        st.dataframe(pd.DataFrame(trace), hide_index=True)


def page_analysis(engine):
    st.title("🔍 Security Analysis")
    df = log_dataframe(engine)

    if df.empty:
        st.info("No traffic to analyse yet. Simulate packets or generate sample traffic first.")
    else:
        denied = df[df["Action"] == "DENY"]
        top_row = st.columns(2)
        with top_row[0]:
            if denied.empty:
                st.info("No blocked packets yet.")
            else:
                top = (denied["Source IP"].value_counts().head(8)
                       .rename_axis("Source IP").reset_index(name="Blocked packets"))
                fig = px.bar(top, x="Source IP", y="Blocked packets", title="Most frequently blocked source IPs",
                             color_discrete_sequence=[RED])
                st.plotly_chart(style_figure(fig), key="top_blocked")
        with top_row[1]:
            ports = df[df["Port"] != "-"]["Port"]
            if ports.empty:
                st.info("Only ICMP traffic so far (no ports).")
            else:
                top_ports = (ports.value_counts().head(8)
                             .rename_axis("Port").reset_index(name="Packets"))
                fig = px.bar(top_ports, x="Port", y="Packets", title="Most frequently accessed ports",
                             color_discrete_sequence=[BLUE])
                fig.update_xaxes(type="category")
                st.plotly_chart(style_figure(fig), key="top_ports")

        bottom_row = st.columns(2)
        with bottom_row[0]:
            counts = blocked_by_rule(engine)
            rule_df = pd.DataFrame({
                "Rule": [label.split(":")[0] if label.startswith("Rule") else label for label in counts],
                "Details": list(counts.keys()),
                "Blocked": list(counts.values()),
            })
            fig = px.bar(rule_df, x="Blocked", y="Rule", orientation="h", hover_data=["Details"],
                         title="Packets blocked by each rule", color_discrete_sequence=[RED])
            st.plotly_chart(style_figure(fig), key="blocked_by_rule")
        with bottom_row[1]:
            fig = px.histogram(df, x="Protocol", color="Action", barmode="group",
                               color_discrete_map=COLOR_MAP, title="Traffic distribution by protocol")
            st.plotly_chart(style_figure(fig), key="protocol_dist")

        with st.expander("Blocked packets per rule (full rule text)"):
            st.dataframe(rule_df[["Details", "Blocked"]].rename(columns={"Details": "Rule"}),
                         hide_index=True)

    st.subheader("Security observations")
    for level, message in security_observations(engine):
        st.markdown(f'<div class="obs obs-{level}">{message}</div>', unsafe_allow_html=True)


def page_tests():
    st.title("✅ Independent Verification: Test Cases")
    st.caption("Each case builds its own fresh rule set, so these results do not depend on "
               "the rules you edited in the dashboard. Command-line version: "
               "`python -m unittest -v test_firewall`")
    results = run_test_cases()
    passed = sum(1 for r in results if r["Result"] == "PASS")
    cols = st.columns(3)
    metric_card(cols[0], "Test cases", len(results), BLUE)
    metric_card(cols[1], "Passed", passed, GREEN)
    metric_card(cols[2], "Failed", len(results) - passed, RED if len(results) - passed else GREEN)
    table = pd.DataFrame(results)
    table["Result"] = table["Result"].map({"PASS": "✅ PASS", "FAIL": "❌ FAIL"})
    st.dataframe(table, hide_index=True)


# ---------------------------------------------------------------------------
# Main layout
# ---------------------------------------------------------------------------
init_state()
engine = st.session_state.engine

with st.sidebar:
    st.markdown('<div class="brand">🛡️ Firewall Simulator</div>'
                '<div class="brand-sub">Packet filtering and security analysis</div>',
                unsafe_allow_html=True)
    page = st.radio("Navigation", PAGES, label_visibility="collapsed", key="nav")
    st.divider()
    st.selectbox("Default policy (no rule matches)", ACTIONS, key="policy_choice")
    engine.set_default_policy(st.session_state.policy_choice)
    st.caption("A change applies to new packets only.")
    st.button("Generate 50 sample packets", on_click=sample_traffic_cb)
    st.button("Clear packet log", on_click=clear_log_cb)
    st.button("Reset rules to examples", on_click=reset_rules_cb)
    st.divider()
    st.caption("Simulation only. No real network traffic is created or analysed.")

if page == PAGES[0]:
    page_overview(engine)
elif page == PAGES[1]:
    page_rules(engine)
elif page == PAGES[2]:
    page_simulator(engine)
elif page == PAGES[3]:
    page_analysis(engine)
else:
    page_tests()
