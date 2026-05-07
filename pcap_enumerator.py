"""
IT/OT PCAP Enumerator
Upload a PCAP file → instant asset discovery, protocol segregation,
Purdue zone mapping, and risk scoring — all local, no cloud.
"""

import streamlit as st
import pandas as pd
import json
import io
import csv
import tempfile
import os
from collections import defaultdict
from datetime import datetime

# ── Try importing scapy ───────────────────────────────────────────────────────
try:
    from scapy.all import rdpcap, IP, TCP, UDP, ARP, Ether, Raw
    SCAPY_OK = True
except ImportError:
    SCAPY_OK = False

# ─────────────────────────────────────────────────────────────────────────────
#  PROTOCOL & VENDOR TABLES
# ─────────────────────────────────────────────────────────────────────────────
OT_PORTS = {
    502:   "Modbus TCP",
    20000: "DNP3",
    44818: "EtherNet/IP",
    102:   "Siemens S7 (ISO-TSAP)",
    2222:  "EtherNet/IP UDP",
    4840:  "OPC-UA",
    1962:  "PCWorx",
    9600:  "OMRON FINS",
    20547: "ProConOS",
    1089:  "FF Annunciation",
    34962: "PROFINET RT",
    34964: "PROFINET DCP",
    2404:  "IEC 60870-5-104",
    4000:  "Emerson DeltaV",
    18245: "GE SRTP",
    18246: "GE SRTP",
}

IT_PORTS = {
    21:   "FTP",
    22:   "SSH",
    23:   "Telnet",
    25:   "SMTP",
    53:   "DNS",
    80:   "HTTP",
    110:  "POP3",
    139:  "NetBIOS",
    143:  "IMAP",
    161:  "SNMP",
    389:  "LDAP",
    443:  "HTTPS",
    445:  "SMB",
    636:  "LDAPS",
    1433: "MSSQL",
    3306: "MySQL",
    3389: "RDP",
    5900: "VNC",
    5985: "WinRM",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
}

OT_VENDORS = {
    "00:0e:8c": "Siemens",
    "00:1b:1b": "Schneider Electric",
    "00:00:bc": "Rockwell / Allen-Bradley",
    "00:80:f4": "Moxa",
    "00:0a:e4": "Hirschmann",
    "00:30:48": "Advantech",
    "00:1d:9c": "GE Automation",
    "00:60:35": "Phoenix Contact",
    "00:80:f4": "Moxa",
    "00:a0:45": "Phoenix Contact",
    "00:e0:4b": "Beckhoff",
    "08:00:06": "Siemens",
    "00:1b:a9": "Brother",
    "de:ad:be": "Unknown/Spoofed",
}

PURDUE_OT_VENDORS = {"Siemens","Rockwell / Allen-Bradley","Phoenix Contact",
                      "Advantech","GE Automation","Schneider Electric",
                      "Hirschmann","Moxa","Beckhoff"}

RISK_ORDER = ["CRITICAL","HIGH","MEDIUM","LOW","UNKNOWN"]
RISK_ICON  = {"CRITICAL":"🔴","HIGH":"🟠","MEDIUM":"🟡","LOW":"🟢","UNKNOWN":"⚪"}

PURDUE_ZONES = [
    "Level 0 — Field Devices",
    "Level 1 — Controllers",
    "Level 2 — Supervisory",
    "Level 3 — Operations",
    "Level 3.5 — DMZ",
    "Level 4 — Business Network",
    "Unclassified",
]

# ─────────────────────────────────────────────────────────────────────────────
#  CORE PARSER
# ─────────────────────────────────────────────────────────────────────────────
def get_vendor(mac: str) -> str:
    if not mac or mac == "Unknown":
        return "Unknown Vendor"
    prefix = mac[:8].lower()
    return OT_VENDORS.get(prefix, "Unknown Vendor")


def classify_risk(ot_p, it_p, vendor, ip):
    risk = "LOW"
    reasons = []
    actions = []

    has_ot = bool(ot_p)
    has_it = bool(it_p)

    # Rogue: unknown vendor speaking OT from IT subnet
    if vendor == "Unknown Vendor" and has_ot and ip.startswith("192.168."):
        risk = "CRITICAL"
        reasons.append("Unknown vendor device sending OT protocol traffic from IT subnet — possible rogue/pivot")
        actions.append("IMMEDIATELY isolate at switch port level")
        actions.append("Capture full packet trace for forensic analysis")
        actions.append("Escalate to incident response team")
        return risk, reasons, actions

    # Spoofed / unusual MAC
    if "de:ad:be" in ip.lower() or (ot_p and vendor == "Unknown/Spoofed"):
        risk = "CRITICAL"
        reasons.append("Suspicious MAC OUI — potential address spoofing")
        actions.append("Investigate device identity — MAC may be spoofed")

    # OT + IT combo = Level 2 bridge risk
    if has_ot and has_it:
        risk = "CRITICAL"
        reasons.append(f"Device bridges OT ({', '.join(ot_p)}) and IT ({', '.join(it_p)}) protocols")
        actions.append("Review firewall rules — ensure IT access to this device is restricted")

    # High-risk remote access on OT devices
    if "VNC" in it_p:
        risk = "CRITICAL"
        reasons.append("VNC (port 5900) open — unauthenticated remote desktop risk")
        actions.append("Disable VNC immediately or require strong authentication")

    if "RDP" in it_p and has_ot:
        risk = "CRITICAL"
        reasons.append("RDP on OT-speaking device — remote code execution attack surface")
        actions.append("Disable RDP — use jump server with MFA instead")

    if "Telnet" in it_p:
        risk = "HIGH" if risk not in ["CRITICAL"] else risk
        reasons.append("Telnet in use — credentials transmitted in cleartext")
        actions.append("Replace Telnet with SSH immediately")

    if "SMB" in it_p and has_ot:
        risk = "CRITICAL" if risk not in ["CRITICAL"] else risk
        reasons.append("SMB (445) on OT device — lateral movement risk")
        actions.append("Block SMB at OT zone perimeter firewall")

    if has_ot and not has_it and not reasons:
        risk = "MEDIUM"
        reasons.append("OT device with no authentication layer observed in traffic")
        actions.append("Verify device is behind industrial firewall")
        actions.append("Monitor for unexpected write commands")

    if not reasons:
        actions.append("Routine — maintain passive monitoring and patch schedule")

    return risk, reasons, actions


def assign_purdue_zone(ot_p, it_p, vendor, ip):
    has_ot = bool(ot_p)
    has_it = bool(it_p)

    if has_ot and has_it:
        return "Level 2 — Supervisory"

    if has_ot:
        if vendor in PURDUE_OT_VENDORS:
            field_protos = {"Modbus TCP","Siemens S7 (ISO-TSAP)","EtherNet/IP",
                            "DNP3","PROFINET RT","PROFINET DCP","OMRON FINS"}
            if any(p in field_protos for p in ot_p):
                return "Level 0 — Field Devices"
            return "Level 1 — Controllers"
        return "Level 1 — Controllers"

    if ip.startswith("192.168."):
        return "Level 4 — Business Network"

    if has_it:
        if "SSH" in it_p or "HTTPS" in it_p:
            return "Level 3.5 — DMZ"
        return "Level 4 — Business Network"

    return "Unclassified"


def infer_device_type(ot_p, it_p, vendor, zone):
    if "Siemens S7 (ISO-TSAP)" in ot_p:
        return f"Siemens PLC ({vendor})"
    if "Modbus TCP" in ot_p and vendor == "Rockwell / Allen-Bradley":
        return "Allen-Bradley PLC"
    if "Modbus TCP" in ot_p and vendor == "Schneider Electric":
        return "Schneider Modicon Controller"
    if "DNP3" in ot_p:
        return "DNP3 Controller / RTU"
    if "EtherNet/IP" in ot_p:
        return "EtherNet/IP Device"
    if "OPC-UA" in ot_p and "RDP" in it_p:
        return "SCADA Server"
    if "OPC-UA" in ot_p and "VNC" in it_p:
        return "HMI Workstation"
    if "OPC-UA" in ot_p and "HTTPS" in it_p:
        return "Historian Server"
    if "OPC-UA" in ot_p:
        return "OPC-UA Server"
    if "VNC" in it_p:
        return "HMI / Operator Workstation"
    if "RDP" in it_p and "SMB" in it_p:
        return "Windows Server"
    if "SSH" in it_p and not ot_p:
        return "Jump Server / Linux Host"
    if "HTTPS" in it_p and not ot_p:
        return "Web Server / Firewall"
    if "SMB" in it_p:
        return "Windows Workstation"
    if vendor != "Unknown Vendor" and ot_p:
        return f"{vendor} Device"
    if not ot_p and not it_p:
        return "Passive Device (ARP only)"
    return "Unidentified Device"


def parse_pcap_bytes(raw_bytes: bytes) -> list[dict]:
    """Parse PCAP from raw bytes, return list of asset dicts."""
    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
        f.write(raw_bytes)
        tmp_path = f.name

    try:
        pkts = rdpcap(tmp_path)
    finally:
        os.unlink(tmp_path)

    assets = defaultdict(lambda: {
        "mac": "", "vendor": "Unknown Vendor",
        "ot_protocols": set(), "it_protocols": set(),
        "open_ports": set(), "packet_count": 0,
    })

    total_packets = len(pkts)

    for pkt in pkts:
        # ARP — reveals devices with no open ports
        if ARP in pkt and IP not in pkt:
            ip = pkt[ARP].psrc
            mac = pkt[ARP].hwsrc
            if ip and not ip.startswith("0."):
                assets[ip]["mac"] = mac
                assets[ip]["vendor"] = get_vendor(mac)
                assets[ip]["packet_count"] += 1
            continue

        if IP not in pkt:
            continue

        src = pkt[IP].src
        dst = pkt[IP].dst

        # Skip multicast / broadcast
        for ip in [src, dst]:
            if ip.startswith("224.") or ip.startswith("239.") or ip.endswith(".255"):
                continue

        mac = pkt[Ether].src if Ether in pkt else ""

        # Count packets for source
        if not src.startswith("224.") and not src.endswith(".255"):
            assets[src]["packet_count"] += 1
            if mac:
                assets[src]["mac"] = mac
                v = get_vendor(mac)
                if v != "Unknown Vendor":
                    assets[src]["vendor"] = v

        if TCP in pkt:
            dport = pkt[TCP].dport
            sport = pkt[TCP].sport

            # Check destination port — service is at dst
            if dport in OT_PORTS:
                assets[dst]["ot_protocols"].add(OT_PORTS[dport])
                assets[dst]["open_ports"].add(dport)
                # Source is also using OT
                assets[src]["ot_protocols"].add(OT_PORTS[dport])

            elif dport in IT_PORTS:
                assets[dst]["it_protocols"].add(IT_PORTS[dport])
                assets[dst]["open_ports"].add(dport)

            # Check source port — server responding
            if sport in OT_PORTS:
                assets[src]["ot_protocols"].add(OT_PORTS[sport])
                assets[src]["open_ports"].add(sport)

            elif sport in IT_PORTS:
                assets[src]["it_protocols"].add(IT_PORTS[sport])
                assets[src]["open_ports"].add(sport)

        if UDP in pkt:
            dport = pkt[UDP].dport
            sport = pkt[UDP].sport
            for port in [dport, sport]:
                if port in OT_PORTS:
                    assets[dst]["ot_protocols"].add(OT_PORTS[port])
                    assets[dst]["open_ports"].add(port)

    # Build final list
    results = []
    for ip, data in assets.items():
        if not ip or ip.startswith("224.") or ip.endswith(".255") or ip == "0.0.0.0":
            continue

        ot_p = sorted(data["ot_protocols"])
        it_p = sorted(data["it_protocols"])
        ports = sorted(data["open_ports"])
        vendor = data["vendor"]

        risk, reasons, actions = classify_risk(ot_p, it_p, vendor, ip)
        zone = assign_purdue_zone(ot_p, it_p, vendor, ip)
        device_type = infer_device_type(ot_p, it_p, vendor, zone)

        results.append({
            "ip":            ip,
            "mac":           data["mac"] or "—",
            "vendor":        vendor,
            "device_type":   device_type,
            "purdue_zone":   zone,
            "risk_level":    risk,
            "ot_protocols":  ot_p,
            "it_protocols":  it_p,
            "open_ports":    ports,
            "packet_count":  data["packet_count"],
            "risk_reasons":  reasons,
            "recommended_actions": actions,
        })

    results.sort(key=lambda x: RISK_ORDER.index(x["risk_level"])
                 if x["risk_level"] in RISK_ORDER else 99)
    return results, total_packets


# ─────────────────────────────────────────────────────────────────────────────
#  EXPORT HELPERS
# ─────────────────────────────────────────────────────────────────────────────
def to_csv_bytes(assets: list[dict]) -> bytes:
    buf = io.StringIO()
    fields = ["ip","mac","vendor","device_type","purdue_zone","risk_level",
              "ot_protocols","it_protocols","open_ports","packet_count",
              "risk_reasons","recommended_actions"]
    w = csv.DictWriter(buf, fieldnames=fields)
    w.writeheader()
    for a in assets:
        row = {}
        for k, v in a.items():
            if k not in fields:
                continue
            if isinstance(v, list):
                # Convert every item to string before joining
                row[k] = ", ".join(str(i) for i in v)
            else:
                row[k] = v
        w.writerow(row)
    return buf.getvalue().encode()


# ─────────────────────────────────────────────────────────────────────────────
#  PAGE CONFIG & STYLES
# ─────────────────────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="IT/OT PCAP Enumerator",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700&family=Syne:wght@400;500;700;800&display=swap');

html, body, [class*="css"] { font-family: 'Syne', sans-serif; }
code, .monospace { font-family: 'JetBrains Mono', monospace !important; }

.hero {
    background: linear-gradient(135deg, #0a0f1e 0%, #0d1f3c 50%, #071428 100%);
    border: 1px solid #1a3a6b;
    border-radius: 16px;
    padding: 2.5rem 2rem 2rem;
    margin-bottom: 2rem;
    position: relative;
    overflow: hidden;
}
.hero::before {
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0; bottom: 0;
    background: repeating-linear-gradient(
        0deg, transparent, transparent 30px,
        rgba(26,58,107,0.15) 30px, rgba(26,58,107,0.15) 31px
    ),
    repeating-linear-gradient(
        90deg, transparent, transparent 30px,
        rgba(26,58,107,0.15) 30px, rgba(26,58,107,0.15) 31px
    );
    pointer-events: none;
}
.hero-title {
    font-size: 2.2rem; font-weight: 800;
    color: #ffffff; margin: 0 0 0.25rem;
    letter-spacing: -0.02em;
}
.hero-title span { color: #38bdf8; }
.hero-sub {
    font-size: 0.95rem; color: #7fb3d3;
    margin: 0; font-family: 'JetBrains Mono', monospace;
}

.metric-card {
    background: #0d1f3c;
    border: 1px solid #1a3a6b;
    border-radius: 12px;
    padding: 1rem 1.25rem;
    text-align: center;
}
.metric-val { font-size: 2rem; font-weight: 800; margin: 0; line-height: 1; }
.metric-lbl { font-size: 0.75rem; color: #7fb3d3; margin: 4px 0 0;
              font-family: 'JetBrains Mono', monospace; letter-spacing: 0.05em; }

.asset-card {
    background: #0a0f1e;
    border: 1px solid #1a3a6b;
    border-radius: 12px;
    padding: 1rem 1.25rem;
    margin-bottom: 0.6rem;
    transition: border-color 0.2s;
}
.asset-card:hover { border-color: #38bdf8; }
.asset-card.critical { border-left: 4px solid #ef4444; }
.asset-card.high     { border-left: 4px solid #f97316; }
.asset-card.medium   { border-left: 4px solid #eab308; }
.asset-card.low      { border-left: 4px solid #22c55e; }

.ip-mono { font-family: 'JetBrains Mono', monospace; font-size: 1rem;
           font-weight: 700; color: #38bdf8; }
.device-name { font-size: 0.85rem; color: #94a3b8; margin: 2px 0 0; }
.risk-badge {
    display: inline-block;
    font-size: 0.7rem; font-weight: 700;
    padding: 2px 10px; border-radius: 20px;
    font-family: 'JetBrains Mono', monospace;
    letter-spacing: 0.08em;
}
.badge-CRITICAL { background: #450a0a; color: #fca5a5; border: 1px solid #ef4444; }
.badge-HIGH     { background: #431407; color: #fdba74; border: 1px solid #f97316; }
.badge-MEDIUM   { background: #422006; color: #fde047; border: 1px solid #eab308; }
.badge-LOW      { background: #052e16; color: #86efac; border: 1px solid #22c55e; }

.proto-tag {
    display: inline-block;
    font-size: 0.68rem; font-weight: 500;
    padding: 2px 8px; border-radius: 4px;
    margin: 2px 3px 2px 0;
    font-family: 'JetBrains Mono', monospace;
}
.proto-ot { background: #1e1b4b; color: #a5b4fc; border: 1px solid #4338ca; }
.proto-it { background: #0c2a4a; color: #7dd3fc; border: 1px solid #0369a1; }

.zone-header {
    font-size: 0.7rem; font-weight: 700;
    letter-spacing: 0.1em; text-transform: uppercase;
    color: #38bdf8; margin: 1.5rem 0 0.75rem;
    font-family: 'JetBrains Mono', monospace;
    border-bottom: 1px solid #1a3a6b;
    padding-bottom: 0.4rem;
}

.upload-box {
    background: #0a0f1e;
    border: 2px dashed #1a3a6b;
    border-radius: 16px;
    padding: 3rem 2rem;
    text-align: center;
    margin: 2rem 0;
}
.upload-title { font-size: 1.3rem; font-weight: 700; color: #e2e8f0; margin: 0 0 0.5rem; }
.upload-sub { font-size: 0.85rem; color: #64748b; font-family: 'JetBrains Mono', monospace; }

.stat-row {
    display: flex; gap: 8px; flex-wrap: wrap; margin: 8px 0 0;
}
.stat-chip {
    font-size: 0.7rem; padding: 2px 8px; border-radius: 4px;
    background: #0d1f3c; color: #7fb3d3;
    border: 1px solid #1a3a6b;
    font-family: 'JetBrains Mono', monospace;
}

[data-testid="stFileUploader"] { background: transparent !important; }
.stTabs [data-baseweb="tab-list"] { background: #0a0f1e; border-radius: 8px; }
.stTabs [data-baseweb="tab"] { color: #64748b; }
.stTabs [aria-selected="true"] { color: #38bdf8 !important; }

.reason-item { font-size: 0.8rem; color: #fca5a5; margin: 3px 0;
               font-family: 'JetBrains Mono', monospace; }
.action-item { font-size: 0.8rem; color: #86efac; margin: 3px 0; }
</style>
""", unsafe_allow_html=True)


# ─────────────────────────────────────────────────────────────────────────────
#  HERO HEADER
# ─────────────────────────────────────────────────────────────────────────────
st.markdown("""
<div class="hero">
  <div class="hero-title">IT/OT <span>PCAP Enumerator</span></div>
  <div class="hero-sub">
    passive asset discovery · protocol segregation · purdue zone mapping · risk scoring
  </div>
</div>
""", unsafe_allow_html=True)

if not SCAPY_OK:
    st.error("Scapy is not installed. Run: `pip install scapy` then restart the app.")
    st.stop()


# ─────────────────────────────────────────────────────────────────────────────
#  FILE UPLOAD
# ─────────────────────────────────────────────────────────────────────────────
uploaded = st.file_uploader(
    "Upload PCAP file",
    type=["pcap","pcapng","cap"],
    help="Supports .pcap, .pcapng, .cap — captured from Wireshark, tcpdump, or any standard tool",
    label_visibility="collapsed"
)

if not uploaded:
    st.markdown("""
    <div class="upload-box">
      <div class="upload-title">🛡️ Drop your PCAP file above</div>
      <div class="upload-sub">
        .pcap &nbsp;·&nbsp; .pcapng &nbsp;·&nbsp; .cap<br><br>
        Supports Modbus · DNP3 · EtherNet/IP · Siemens S7 · OPC-UA · Profinet<br>
        RDP · VNC · SMB · SSH · Telnet · HTTP/S · and more
      </div>
    </div>
    """, unsafe_allow_html=True)

    st.info("💡 No PCAP? Generate a sample one using the `make_test_pcap.py` script included in this project, or capture live traffic with `tcpdump -i eth0 -w capture.pcap`")
    st.stop()


# ─────────────────────────────────────────────────────────────────────────────
#  PARSE
# ─────────────────────────────────────────────────────────────────────────────
with st.spinner(f"Parsing `{uploaded.name}`..."):
    raw = uploaded.read()
    try:
        assets, total_packets = parse_pcap_bytes(raw)
    except Exception as e:
        st.error(f"Failed to parse PCAP: {e}")
        st.stop()

if not assets:
    st.warning("No assets discovered — the PCAP may be empty or contain no IP traffic.")
    st.stop()


# ─────────────────────────────────────────────────────────────────────────────
#  SUMMARY METRICS
# ─────────────────────────────────────────────────────────────────────────────
n_critical = sum(1 for a in assets if a["risk_level"] == "CRITICAL")
n_high     = sum(1 for a in assets if a["risk_level"] == "HIGH")
n_medium   = sum(1 for a in assets if a["risk_level"] == "MEDIUM")
n_low      = sum(1 for a in assets if a["risk_level"] == "LOW")
n_ot       = sum(1 for a in assets if a["ot_protocols"])
n_it       = sum(1 for a in assets if a["it_protocols"] and not a["ot_protocols"])

c1,c2,c3,c4,c5,c6,c7 = st.columns(7)
metrics = [
    (c1, str(len(assets)),    "#e2e8f0", "ASSETS"),
    (c2, str(total_packets),  "#7fb3d3", "PACKETS"),
    (c3, str(n_critical),     "#ef4444", "CRITICAL"),
    (c4, str(n_high),         "#f97316", "HIGH"),
    (c5, str(n_medium),       "#eab308", "MEDIUM"),
    (c6, str(n_ot),           "#a5b4fc", "OT DEVICES"),
    (c7, str(n_it),           "#7dd3fc", "IT DEVICES"),
]
for col, val, color, label in metrics:
    col.markdown(f"""
    <div class="metric-card">
      <div class="metric-val" style="color:{color}">{val}</div>
      <div class="metric-lbl">{label}</div>
    </div>""", unsafe_allow_html=True)

st.markdown("<br>", unsafe_allow_html=True)


# ─────────────────────────────────────────────────────────────────────────────
#  EXPORT BUTTONS
# ─────────────────────────────────────────────────────────────────────────────
ts = datetime.now().strftime("%Y%m%d_%H%M%S")
ex1, ex2, ex3 = st.columns([1,1,5])
with ex1:
    st.download_button("⬇ Export CSV", to_csv_bytes(assets),
                       f"ot_enum_{ts}.csv", "text/csv", use_container_width=True)
with ex2:
    st.download_button("⬇ Export JSON", to_json_bytes(assets),
                       f"ot_enum_{ts}.json", "application/json", use_container_width=True)

st.divider()


# ─────────────────────────────────────────────────────────────────────────────
#  TABS
# ─────────────────────────────────────────────────────────────────────────────
tab1, tab2, tab3, tab4 = st.tabs([
    "🗂️  Asset Inventory",
    "🏗️  Purdue Zone View",
    "⚙️  OT Traffic",
    "🚨  Risk Summary",
])


# ── TAB 1: Asset Inventory ────────────────────────────────────────────────────
with tab1:
    # Search + filter row
    s1, s2 = st.columns([3,1])
    with s1:
        search = st.text_input("Search IP, vendor, protocol...", placeholder="e.g. 10.0.0 or Siemens or Modbus",
                               label_visibility="collapsed")
    with s2:
        risk_filter = st.selectbox("Risk", ["All","CRITICAL","HIGH","MEDIUM","LOW"],
                                   label_visibility="collapsed")

    filtered = assets
    if search:
        q = search.lower()
        filtered = [a for a in filtered if
                    q in a["ip"] or q in a["vendor"].lower() or
                    q in a["device_type"].lower() or
                    any(q in p.lower() for p in a["ot_protocols"]+a["it_protocols"])]
    if risk_filter != "All":
        filtered = [a for a in filtered if a["risk_level"] == risk_filter]

    st.caption(f"Showing {len(filtered)} of {len(assets)} assets")

    for a in filtered:
        rl = a["risk_level"]
        rl_cls = rl.lower()

        ot_tags = "".join(f'<span class="proto-tag proto-ot">{p}</span>' for p in a["ot_protocols"])
        it_tags = "".join(f'<span class="proto-tag proto-it">{p}</span>' for p in a["it_protocols"])
        ports_str = ", ".join(str(p) for p in a["open_ports"]) or "—"

        with st.expander(
            f"{RISK_ICON.get(rl,'⚪')}  {a['ip']}  —  {a['device_type']}  [{a['vendor']}]",
            expanded=(rl == "CRITICAL")
        ):
            cc1, cc2 = st.columns(2)
            with cc1:
                st.markdown(f"""
                <span class="ip-mono">{a['ip']}</span>&nbsp;&nbsp;
                <span class="risk-badge badge-{rl}">{rl}</span><br>
                <div class="device-name">{a['device_type']} · {a['vendor']}</div>
                <div class="stat-row">
                  <span class="stat-chip">MAC: {a['mac']}</span>
                  <span class="stat-chip">Packets: {a['packet_count']}</span>
                  <span class="stat-chip">Ports: {ports_str}</span>
                </div>
                <br>
                <b style="font-size:0.75rem;color:#64748b;">OT PROTOCOLS</b><br>
                {ot_tags if ot_tags else '<span style="color:#475569;font-size:0.8rem">None detected</span>'}
                <br><br>
                <b style="font-size:0.75rem;color:#64748b;">IT PROTOCOLS</b><br>
                {it_tags if it_tags else '<span style="color:#475569;font-size:0.8rem">None detected</span>'}
                """, unsafe_allow_html=True)

            with cc2:
                st.markdown(f'<b style="font-size:0.75rem;color:#64748b;">PURDUE ZONE</b><br>'
                            f'<span style="color:#38bdf8;font-size:0.85rem">{a["purdue_zone"]}</span>',
                            unsafe_allow_html=True)
                if a["risk_reasons"]:
                    st.markdown('<br><b style="font-size:0.75rem;color:#64748b;">RISK FACTORS</b>', unsafe_allow_html=True)
                    for r in a["risk_reasons"]:
                        st.markdown(f'<div class="reason-item">⚠ {r}</div>', unsafe_allow_html=True)
                if a["recommended_actions"]:
                    st.markdown('<br><b style="font-size:0.75rem;color:#64748b;">RECOMMENDED ACTIONS</b>', unsafe_allow_html=True)
                    for r in a["recommended_actions"]:
                        st.markdown(f'<div class="action-item">→ {r}</div>', unsafe_allow_html=True)


# ── TAB 2: Purdue Zone View ───────────────────────────────────────────────────
with tab2:
    for zone in PURDUE_ZONES:
        zone_assets = [a for a in assets if a["purdue_zone"] == zone]
        if not zone_assets:
            continue

        count = len(zone_assets)
        crit  = sum(1 for a in zone_assets if a["risk_level"] == "CRITICAL")
        st.markdown(f'<div class="zone-header">{zone} — {count} device{"s" if count!=1 else ""}'
                    f'{f" · 🔴 {crit} CRITICAL" if crit else ""}</div>',
                    unsafe_allow_html=True)

        cols = st.columns(min(count, 3))
        for i, a in enumerate(zone_assets):
            rl = a["risk_level"]
            with cols[i % 3]:
                ot_tags = "".join(f'<span class="proto-tag proto-ot">{p}</span>' for p in a["ot_protocols"])
                it_tags = "".join(f'<span class="proto-tag proto-it">{p}</span>' for p in a["it_protocols"])
                st.markdown(f"""
                <div class="asset-card {rl.lower()}">
                  <span class="ip-mono">{a['ip']}</span>&nbsp;
                  <span class="risk-badge badge-{rl}">{rl}</span><br>
                  <div class="device-name">{a['device_type']}</div>
                  <div class="device-name" style="color:#475569">{a['vendor']}</div>
                  <div style="margin-top:8px">{ot_tags}{it_tags}</div>
                  <div class="stat-row" style="margin-top:6px">
                    <span class="stat-chip">📦 {a['packet_count']} pkts</span>
                    <span class="stat-chip">MAC: {a['mac'][:14]}...</span>
                  </div>
                </div>
                """, unsafe_allow_html=True)


# ── TAB 3: OT Traffic ────────────────────────────────────────────────────────
with tab3:
    ot_assets = [a for a in assets if a["ot_protocols"]]
    if not ot_assets:
        st.info("No OT protocol traffic detected in this PCAP.")
    else:
        st.caption(f"{len(ot_assets)} devices with OT protocol traffic")

        # Protocol distribution
        from collections import Counter
        all_ot_protos = []
        for a in ot_assets:
            all_ot_protos.extend(a["ot_protocols"])
        proto_counts = Counter(all_ot_protos)

        df_proto = pd.DataFrame(proto_counts.items(), columns=["Protocol","Count"]).sort_values("Count", ascending=False)
        st.bar_chart(df_proto.set_index("Protocol"))

        st.divider()

        # OT asset table
        rows = []
        for a in ot_assets:
            rows.append({
                "IP": a["ip"],
                "Vendor": a["vendor"],
                "Device Type": a["device_type"],
                "OT Protocols": ", ".join(a["ot_protocols"]),
                "IT Protocols": ", ".join(a["it_protocols"]) or "—",
                "Open Ports": ", ".join(str(p) for p in a["open_ports"]),
                "Risk": a["risk_level"],
                "Zone": a["purdue_zone"],
                "Packets": a["packet_count"],
            })
        df = pd.DataFrame(rows)
        st.dataframe(df, use_container_width=True, hide_index=True)


# ── TAB 4: Risk Summary ───────────────────────────────────────────────────────
with tab4:
    crit_assets = [a for a in assets if a["risk_level"] in ["CRITICAL","HIGH"]]

    if not crit_assets:
        st.success("✅ No CRITICAL or HIGH risk devices found in this PCAP.")
    else:
        st.error(f"⚠️ {len(crit_assets)} devices require immediate attention")
        st.markdown("<br>", unsafe_allow_html=True)

        for a in crit_assets:
            rl = a["risk_level"]
            icon = RISK_ICON.get(rl,"⚪")
            st.markdown(f"""
            <div class="asset-card {rl.lower()}">
              <span class="ip-mono">{icon} {a['ip']}</span>&nbsp;
              <span class="risk-badge badge-{rl}">{rl}</span><br>
              <div class="device-name">{a['device_type']} · {a['vendor']} · {a['purdue_zone']}</div>
            </div>
            """, unsafe_allow_html=True)

            with st.expander("View details & remediation"):
                r1, r2 = st.columns(2)
                with r1:
                    st.markdown("**Risk Factors**")
                    for r in a["risk_reasons"]:
                        st.markdown(f'<div class="reason-item">⚠ {r}</div>', unsafe_allow_html=True)
                with r2:
                    st.markdown("**Recommended Actions**")
                    for r in a["recommended_actions"]:
                        st.markdown(f'<div class="action-item">→ {r}</div>', unsafe_allow_html=True)

                st.markdown(f"""
                **OT Protocols:** {', '.join(a['ot_protocols']) or 'None'}  
                **IT Protocols:** {', '.join(a['it_protocols']) or 'None'}  
                **Open Ports:** {', '.join(str(p) for p in a['open_ports']) or 'None'}  
                **Packet Count:** {a['packet_count']}  
                **MAC:** `{a['mac']}`
                """)

    st.divider()
    st.markdown("**All assets by risk level**")
    rows = []
    for a in assets:
        rows.append({
            "Risk": f"{RISK_ICON.get(a['risk_level'],'')} {a['risk_level']}",
            "IP": a["ip"],
            "Device": a["device_type"],
            "Zone": a["purdue_zone"],
            "OT": ", ".join(a["ot_protocols"]) or "—",
            "IT": ", ".join(a["it_protocols"]) or "—",
            "Pkts": a["packet_count"],
        })
    st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)
