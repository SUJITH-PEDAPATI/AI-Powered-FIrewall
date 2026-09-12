"""
dashboard/app.py
AI-Based Firewall — Professional Gradio Network Security Monitor
================================================================
Run with:
    python dashboard/app.py

Architecture
------------
Gradio Blocks UI runs on the main thread (always alive).
Packet capture runs in a background daemon thread using:
    - capture.packet_capture.PacketCapture  (existing class, unchanged)
    - Scapy's  stop_filter=lambda p: _stop_event.is_set()

When STOP is clicked, threading.Event signals Scapy to exit its
sniff() loop.  The Gradio server is NEVER touched.

State machine:
    IDLE -> CAPTURING -> CAPTURE_STOPPED -> ANALYZING -> ANALYSIS_COMPLETE
              ^______________________________________________|  (New Capture)

CRITICAL SAFETY GUARANTEES
---------------------------
- sys.exit / os._exit / exit / quit are not called anywhere.
- The Gradio server process continues running through every state
  transition, including Stop Capture.
- Firewall errors (netsh permission denied) are caught silently.
"""

import json
import os
import sys
import threading
import traceback
from datetime import datetime

import gradio as gr
import pandas as pd

# -- Ensure project root is importable -----------------------------------------
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from capture.packet_capture import PacketCapture
from dashboard.analyzer import run_analysis
from firewall.windows_firewall import WindowsFirewall

# -- File paths ----------------------------------------------------------------
PACKET_LOG  = "logs/security.jsonl"
EVENTS_FILE = "data/security_events.jsonl"
INTERFACE   = "Wi-Fi"

# ==============================================================================
# MODULE-LEVEL APPLICATION STATE
# Single-user desktop tool -- globals are intentional.
# ==============================================================================
_lock           = threading.Lock()
_stop_event     = threading.Event()
_capture_thread = None
_app_state      = "IDLE"      # IDLE | CAPTURING | CAPTURE_STOPPED | ANALYZING | ANALYSIS_COMPLETE
_capture_start  = None
_analysis_res   = None
_capture_error  = None


# ==============================================================================
# UTILITY HELPERS
# ==============================================================================

def _count_lines(path: str) -> int:
    if not os.path.exists(path):
        return 0
    n = 0
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            n += chunk.count(b"\n")
    return n


def _fmt_dur(secs: float) -> str:
    s = max(0, int(secs))
    return f"{s // 3600:02d}:{(s % 3600) // 60:02d}:{s % 60:02d}"


def _fmt_bytes(b) -> str:
    b = int(b or 0)
    if b >= 1_073_741_824: return f"{b / 1_073_741_824:.2f} GB"
    if b >= 1_048_576:     return f"{b / 1_048_576:.2f} MB"
    if b >= 1_024:         return f"{b / 1_024:.1f} KB"
    return f"{b} B"


def _proto(p) -> str:
    if p in (6, "6"):   return "TCP"
    if p in (17, "17"): return "UDP"
    if p == "ICMP":      return "ICMP"
    return str(p) if p is not None else ""


def _live_stats():
    pkt = _count_lines(PACKET_LOG)
    if _capture_start:
        elapsed = (datetime.now() - _capture_start).total_seconds()
        dur = _fmt_dur(elapsed)
        pps = f"{pkt / max(elapsed, 1):.1f}" if pkt else "0.0"
    else:
        dur, pps = "00:00:00", "0.0"
    return pkt, dur, pps


# ==============================================================================
# BACKGROUND CAPTURE WORKER
# ==============================================================================

def _worker() -> None:
    """
    Run Scapy packet capture in a background daemon thread.
    Exits when _stop_event is set or an exception occurs.
    The Gradio server is never affected by this thread's lifecycle.
    """
    global _app_state, _capture_error
    _stop_event.clear()
    pc = None
    try:
        from scapy.all import sniff
        pc = PacketCapture()
        sniff(
            iface=INTERFACE,
            prn=pc.process_packet,
            store=False,
            stop_filter=lambda _pkt: _stop_event.is_set(),
        )
    except Exception:
        err = traceback.format_exc()
        with _lock:
            _capture_error = (
                "Packet capture failed.\n\n"
                "Possible causes:\n"
                "  - Invalid network interface name (configured: Wi-Fi)\n"
                "  - Npcap not installed  ->  https://npcap.com\n"
                "  - Application not running as Administrator\n\n"
                f"Technical detail:\n{err}"
            )
    finally:
        if pc is not None:
            try:
                pc.close()
            except Exception:
                pass
        with _lock:
            if _app_state == "CAPTURING":
                _app_state = "CAPTURE_STOPPED"


# ==============================================================================
# UNIFIED UI STATE BUILDER
# Returns a 32-element tuple — one value per output component.
# Index order MUST match _OUTPUTS list defined in the Blocks layout.
#
#  0  status_md        HTML status badge
#  1  start_box        start time text
#  2  dur_box          duration text
#  3  pkts_box         packet count text
#  4  pps_box          packets/sec text
#  5  btn_start        interactive bool
#  6  btn_stop         interactive bool
#  7  btn_analyze      interactive bool
#  8  btn_new          interactive bool
#  9  error_md         capture error HTML
# 10  cap_group        visible bool
# 11  sum_pkts         text
# 12  sum_flows        text
# 13  sum_bytes        text
# 14  sum_dur          text
# 15  sum_pps          text
# 16  an_group         visible bool
# 17  an_flows         text
# 18  an_normal        text
# 19  an_susp          text
# 20  an_mal           text
# 21  an_score         text
# 22  an_label         text
# 23  threat_table     Dataframe
# 24  src_table        Dataframe
# 25  fw_group         visible bool
# 26  fw_blocked       text
# 27  fw_monitored     text
# 28  fw_table         Dataframe
# 29  err_group        visible bool
# 30  err_text         text
# 31  evlog_table      Dataframe
# ==============================================================================

def _all_outputs() -> tuple:
    state = _app_state
    pkt, dur, pps = _live_stats()

    # Button states
    capturing   = state == "CAPTURING"
    can_analyze = state in ("CAPTURE_STOPPED", "ANALYSIS_COMPLETE")
    busy        = state == "ANALYZING"

    # Status HTML badge (pulsing glow dot + label — purely cosmetic markup)
    _STATUS_CFG = {
        "IDLE":              ("IDLE",             "#64748b", False),
        "CAPTURING":         ("CAPTURING",        "#22d3ee", True),
        "CAPTURE_STOPPED":   ("CAPTURE STOPPED",  "#f59e0b", False),
        "ANALYZING":         ("ANALYZING",        "#818cf8", True),
        "ANALYSIS_COMPLETE": ("ANALYSIS COMPLETE","#34d399", False),
    }
    slabel, scolor, spulse = _STATUS_CFG.get(state, (state, "#64748b", False))
    pulse_cls = "status-dot pulse" if spulse else "status-dot"
    status_html = (
        f'<div class="status-pill" style="border-color:{scolor}55;'
        f'background:{scolor}14;color:{scolor};box-shadow:0 0 16px {scolor}33, '
        f'inset 0 1px 0 rgba(255,255,255,0.04);">'
        f'<span class="{pulse_cls}" style="background:{scolor};'
        f'box-shadow:0 0 8px 2px {scolor}aa;"></span>'
        f'{slabel}</div>'
    )

    start_str = _capture_start.strftime("%H:%M:%S") if _capture_start else "--"

    err_html = ""
    if _capture_error:
        err_html = (
            '<div class="error-box">'
            f'{_capture_error}</div>'
        )

    cap_visible = pkt > 0
    res = _analysis_res or {}
    an_visible  = state == "ANALYSIS_COMPLETE" and bool(res) and not res.get("error")
    fw_visible  = an_visible
    err_visible = (
        state in ("CAPTURE_STOPPED", "ANALYSIS_COMPLETE")
        and bool(res.get("error"))
    )

    events      = res.get("events", [])
    threats     = [e for e in events if e.get("decision") != "ALLOW"]
    src_stats   = res.get("source_ip_stats", [])
    blocked_ips = res.get("blocked_ips", [])
    mon_ips     = res.get("monitored_ips", [])

    # Threat table
    _TC = ["Timestamp", "Source IP", "Dest IP", "Src Port", "Dst Port",
           "Protocol", "Attack Type", "Risk Score", "Decision"]
    if threats:
        df_threats = pd.DataFrame([{
            "Timestamp":   e.get("timestamp", "")[:19],
            "Source IP":   e.get("source_ip", ""),
            "Dest IP":     e.get("destination_ip", ""),
            "Src Port":    str(e.get("source_port", "")),
            "Dst Port":    str(e.get("destination_port", "")),
            "Protocol":    _proto(e.get("protocol")),
            "Attack Type": e.get("attack_type", ""),
            "Risk Score":  round(float(e.get("risk_score", 0)), 3),
            "Decision":    e.get("decision", ""),
        } for e in sorted(threats, key=lambda x: x.get("risk_score", 0), reverse=True)])
    else:
        df_threats = pd.DataFrame(columns=_TC)

    # Source IP table
    _SC = ["IP Address", "Packets", "SYN Count", "Flows",
           "Unique Ports", "Risk Score", "Status"]
    if src_stats:
        df_src = pd.DataFrame([{
            "IP Address":   s.get("ip", ""),
            "Packets":      s.get("packet_count", 0),
            "SYN Count":    s.get("syn_count", 0),
            "Flows":        s.get("flows", 0),
            "Unique Ports": s.get("unique_ports", 0),
            "Risk Score":   round(float(s.get("risk_score", 0)), 3),
            "Status":       s.get("status", ""),
        } for s in src_stats])
    else:
        df_src = pd.DataFrame(columns=_SC)

    # Firewall table
    fw_rows = (
        [{"IP Address": ip, "Action": "BLOCK"}   for ip in blocked_ips[:15]] +
        [{"IP Address": ip, "Action": "MONITOR"} for ip in mon_ips[:10]]
    )
    df_fw = pd.DataFrame(fw_rows) if fw_rows else pd.DataFrame(columns=["IP Address", "Action"])

    # Event log
    ev_rows = []
    if os.path.exists(EVENTS_FILE):
        try:
            with open(EVENTS_FILE, "r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        e = json.loads(line)
                        ev_rows.append({
                            "Timestamp":   e.get("timestamp", "")[:19],
                            "Source IP":   e.get("source_ip", ""),
                            "Attack Type": e.get("attack_type", ""),
                            "Risk Score":  round(float(e.get("risk_score", 0)), 3),
                            "Decision":    e.get("decision", ""),
                        })
                    except Exception:
                        pass
        except Exception:
            pass
    _EC = ["Timestamp", "Source IP", "Attack Type", "Risk Score", "Decision"]
    df_ev = pd.DataFrame(ev_rows[-100:]) if ev_rows else pd.DataFrame(columns=_EC)

    return (
        status_html,                                                         #  0
        start_str,                                                           #  1
        dur,                                                                 #  2
        str(pkt),                                                            #  3
        pps,                                                                 #  4
        gr.update(interactive=not capturing and not busy),                   #  5
        gr.update(interactive=capturing),                                    #  6
        gr.update(interactive=can_analyze and not busy),                     #  7
        gr.update(interactive=                                               #  8
                  state in ("CAPTURE_STOPPED", "ANALYSIS_COMPLETE") and not busy),
        err_html,                                                            #  9
        gr.update(visible=cap_visible),                                      # 10
        str(pkt),                                                            # 11
        str(res.get("total_flows", 0)),                                      # 12
        _fmt_bytes(res.get("total_bytes", 0)) if res else "0 B",            # 13
        dur,                                                                 # 14
        str(round(res.get("avg_pps", 0.0), 1)) if res else "0.0",          # 15
        gr.update(visible=an_visible),                                       # 16
        str(res.get("total_flows", 0)),                                      # 17
        str(res.get("normal_count", 0)),                                     # 18
        str(res.get("suspicious_count", 0)),                                 # 19
        str(res.get("malicious_count", 0)),                                  # 20
        str(round(res.get("overall_risk_score", 0.0), 3)),                  # 21
        res.get("overall_risk_label", "LOW"),                                # 22
        df_threats,                                                          # 23
        df_src,                                                              # 24
        gr.update(visible=fw_visible),                                       # 25
        str(len(blocked_ips)),                                               # 26
        str(len(mon_ips)),                                                   # 27
        df_fw,                                                               # 28
        gr.update(visible=err_visible),                                      # 29
        res.get("error", "") or "",                                          # 30
        df_ev,                                                               # 31
    )


# ==============================================================================
# EVENT HANDLERS
# ==============================================================================

def on_start() -> tuple:
    global _capture_thread, _capture_start, _app_state, _capture_error, _analysis_res

    with _lock:
        if _app_state == "CAPTURING":
            return _all_outputs()
        _capture_error = None
        _analysis_res  = None
        _capture_start = datetime.now()
        _app_state     = "CAPTURING"

    # Truncate previous session log
    os.makedirs("logs", exist_ok=True)
    with open(PACKET_LOG, "w", encoding="utf-8"):
        pass

    _stop_event.clear()
    _capture_thread = threading.Thread(target=_worker, daemon=True, name="scapy-capture")
    _capture_thread.start()
    return _all_outputs()


def on_stop() -> tuple:
    """
    Stop ONLY the Scapy capture thread.
    Sets threading.Event -> sniff() stop_filter returns True -> sniff() exits.
    The Gradio process is NOT terminated.
    """
    global _app_state

    _stop_event.set()
    if _capture_thread is not None and _capture_thread.is_alive():
        _capture_thread.join(timeout=3.0)

    with _lock:
        _app_state = "CAPTURE_STOPPED"

    return _all_outputs()


def on_analyze() -> tuple:
    global _app_state, _analysis_res

    with _lock:
        _app_state = "ANALYZING"

    results = {}
    try:
        results = run_analysis(PACKET_LOG)
    except Exception:
        results = {
            "error":             traceback.format_exc(),
            "total_packets":     0, "total_flows":    0,
            "total_bytes":       0, "capture_duration": 0.0,
            "avg_pps":           0.0, "normal_count":  0,
            "suspicious_count":  0, "malicious_count": 0,
            "overall_risk_score": 0.0, "overall_risk_label": "LOW",
            "events": [], "blocked_ips": [], "monitored_ips": [],
            "source_ip_stats": [],
        }

    # Apply Windows Firewall rules (errors must not crash the app)
    if not results.get("error"):
        fw = WindowsFirewall()
        for ip in results.get("blocked_ips", []):
            try:
                fw.block_ip(ip)
            except Exception:
                pass

    with _lock:
        _analysis_res = results
        _app_state    = "ANALYSIS_COMPLETE"

    return _all_outputs()


def on_new() -> tuple:
    global _app_state, _capture_start, _analysis_res, _capture_error

    _stop_event.set()
    if _capture_thread is not None and _capture_thread.is_alive():
        _capture_thread.join(timeout=2.0)

    with _lock:
        _app_state     = "IDLE"
        _capture_start = None
        _analysis_res  = None
        _capture_error = None

    return _all_outputs()


def on_refresh() -> tuple:
    return _all_outputs()


# ==============================================================================
# CSS — professional cybersecurity dark theme (Gradio 6.x: passed to launch())
# ==============================================================================
_CSS = """
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600;700&family=Inter:wght@300;400;500;600;700;800&family=Space+Grotesk:wght@500;600;700&display=swap');

:root {
    --bg-deep:      #05070d;
    --bg-panel:     rgba(17, 24, 39, 0.55);
    --bg-panel-solid: #0d1220;
    --border-glass: rgba(148, 163, 184, 0.14);
    --border-glow-blue: rgba(56, 189, 248, 0.35);
    --border-glow-purple: rgba(167, 139, 250, 0.30);
    --cyan:   #22d3ee;
    --blue:   #3b82f6;
    --purple: #a78bfa;
    --text-hi: #e5edf7;
    --text-mid: #94a3b8;
    --text-low: #5b6b84;
}

/* ---------------------------------------------------------------------- */
/* Base canvas — deep space background with soft glowing blobs + grid      */
/* ---------------------------------------------------------------------- */
body, .gradio-container {
    background: var(--bg-deep) !important;
}

.gradio-container {
    font-family: 'Inter', sans-serif !important;
    max-width: 1480px !important;
    margin: 0 auto !important;
    padding: 1.25rem 1.25rem 3rem 1.25rem !important;
    position: relative !important;
    background-image:
        radial-gradient(ellipse 900px 480px at 12% -10%, rgba(59,130,246,0.16), transparent 60%),
        radial-gradient(ellipse 800px 500px at 100% 0%, rgba(167,139,250,0.13), transparent 55%),
        radial-gradient(ellipse 700px 400px at 50% 100%, rgba(34,211,238,0.07), transparent 60%),
        linear-gradient(rgba(148,163,184,0.045) 1px, transparent 1px),
        linear-gradient(90deg, rgba(148,163,184,0.045) 1px, transparent 1px) !important;
    background-size: auto, auto, auto, 42px 42px, 42px 42px !important;
    background-repeat: no-repeat, no-repeat, no-repeat, repeat, repeat !important;
}

/* ---------------------------------------------------------------------- */
/* Header                                                                   */
/* ---------------------------------------------------------------------- */
.app-header {
    position: relative;
    background: linear-gradient(160deg, rgba(15,23,42,0.85) 0%, rgba(13,18,32,0.85) 100%);
    border: 1px solid var(--border-glass);
    border-radius: 16px;
    padding: 1.6rem 2rem;
    margin-bottom: 1.4rem;
    backdrop-filter: blur(18px);
    -webkit-backdrop-filter: blur(18px);
    box-shadow:
        0 1px 0 rgba(255,255,255,0.05) inset,
        0 24px 60px -20px rgba(0,0,0,0.65),
        0 0 0 1px rgba(56,189,248,0.05);
    display: flex;
    align-items: center;
    justify-content: space-between;
    flex-wrap: wrap;
    gap: 1rem;
    overflow: hidden;
}
.app-header::before {
    content: "";
    position: absolute;
    top: -60%; left: -10%;
    width: 55%; height: 220%;
    background: linear-gradient(120deg, rgba(56,189,248,0.10), transparent 60%);
    transform: rotate(8deg);
    pointer-events: none;
}
.app-title-wrap { display: flex; align-items: center; gap: 14px; position: relative; z-index: 1; }
.app-logo {
    width: 46px; height: 46px; flex-shrink: 0;
    display: flex; align-items: center; justify-content: center;
    border-radius: 12px;
    background: linear-gradient(145deg, rgba(59,130,246,0.25), rgba(167,139,250,0.20));
    border: 1px solid rgba(96,165,250,0.4);
    box-shadow: 0 0 22px rgba(59,130,246,0.35), inset 0 1px 0 rgba(255,255,255,0.12);
}
.app-title { 
    font-family: 'Space Grotesk', 'IBM Plex Mono', monospace !important;
    font-size: 1.55rem !important;
    font-weight: 700 !important;
    letter-spacing: 0.04em !important;
    margin: 0 !important;
    background: linear-gradient(90deg, #f1f5f9 0%, #bfdbfe 45%, #c4b5fd 100%);
    -webkit-background-clip: text;
    background-clip: text;
    color: transparent;
}
.app-subtitle {
    font-family: 'Inter', sans-serif !important;
    font-size: 0.72rem !important;
    color: var(--text-low) !important;
    letter-spacing: 0.14em !important;
    text-transform: uppercase !important;
    margin: 3px 0 0 0 !important;
}
.system-active {
    display: flex; align-items: center; gap: 8px;
    font-family: 'IBM Plex Mono', monospace !important;
    font-size: 0.72rem; font-weight: 700; letter-spacing: 0.12em;
    color: #6ee7b7;
    background: rgba(16,185,129,0.08);
    border: 1px solid rgba(52,211,153,0.35);
    padding: 7px 16px; border-radius: 999px;
    box-shadow: 0 0 18px rgba(16,185,129,0.18), inset 0 1px 0 rgba(255,255,255,0.06);
    position: relative; z-index: 1;
}

/* Status pill (capture state) */
.status-pill {
    display: inline-flex; align-items: center; gap: 8px;
    padding: 6px 16px; border-radius: 999px;
    border: 1px solid; 
    font-family: 'IBM Plex Mono', monospace !important;
    font-weight: 700; font-size: 0.8rem; letter-spacing: 0.08em;
    backdrop-filter: blur(6px);
}
.status-dot {
    width: 8px; height: 8px; border-radius: 50%; display: inline-block;
}
.status-dot.pulse { animation: pulseDot 1.6s ease-in-out infinite; }
@keyframes pulseDot {
    0%, 100% { opacity: 1; transform: scale(1); }
    50%      { opacity: 0.45; transform: scale(0.75); }
}

/* ---------------------------------------------------------------------- */
/* Section labels (card headers)                                           */
/* ---------------------------------------------------------------------- */
.sec-label {
    font-family: 'IBM Plex Mono', monospace !important;
    font-size: 0.68rem !important;
    font-weight: 700 !important;
    letter-spacing: 0.20em !important;
    text-transform: uppercase !important;
    color: var(--cyan) !important;
    display: flex; align-items: center; gap: 8px;
    padding-bottom: 0.55rem !important;
    margin: 0 0 0.9rem 0 !important;
    border-bottom: 1px solid var(--border-glass) !important;
}
.sec-label::before {
    content: "";
    width: 3px; height: 13px; border-radius: 2px;
    background: linear-gradient(180deg, var(--cyan), var(--purple));
    box-shadow: 0 0 8px rgba(34,211,238,0.7);
    display: inline-block;
}
.sec-sub {
    font-family: 'Inter', sans-serif !important;
    font-size: 0.62rem !important;
    text-transform: uppercase !important;
    letter-spacing: 0.14em !important;
    color: var(--text-low) !important;
    margin: 1rem 0 0.5rem 0 !important;
}

/* ---------------------------------------------------------------------- */
/* Glass 3D cards — wraps gr.Group / sections                              */
/* ---------------------------------------------------------------------- */
.card, .gradio-group, .block.gr-group, div[class*="group"] {
    background: var(--bg-panel) !important;
    border: 1px solid var(--border-glass) !important;
    border-radius: 14px !important;
    backdrop-filter: blur(16px) !important;
    -webkit-backdrop-filter: blur(16px) !important;
}

.card {
    padding: 1.3rem 1.5rem 1.5rem 1.5rem !important;
    margin-bottom: 1.2rem !important;
    box-shadow:
        0 1px 0 rgba(255,255,255,0.05) inset,
        0 18px 40px -18px rgba(0,0,0,0.7) !important;
    transition: box-shadow 0.25s ease, transform 0.25s ease, border-color 0.25s ease !important;
    position: relative;
}
.card:hover {
    border-color: rgba(96,165,250,0.28) !important;
    box-shadow:
        0 1px 0 rgba(255,255,255,0.06) inset,
        0 24px 50px -16px rgba(0,0,0,0.75),
        0 0 0 1px rgba(56,189,248,0.10) !important;
    transform: translateY(-2px);
}
.card-accent-cyan   { border-top: 2px solid rgba(34,211,238,0.55) !important; }
.card-accent-blue   { border-top: 2px solid rgba(59,130,246,0.55) !important; }
.card-accent-purple { border-top: 2px solid rgba(167,139,250,0.55) !important; }
.card-accent-amber  { border-top: 2px solid rgba(245,158,11,0.55) !important; }

/* Labels on textbox components */
label span {
    font-family: 'Inter', sans-serif !important;
    font-size: 0.64rem !important;
    text-transform: uppercase !important;
    letter-spacing: 0.10em !important;
    color: var(--text-low) !important;
    font-weight: 600 !important;
}

/* Textbox inputs (read-only info display) — glassy inset "gauges" */
textarea, input[type="text"] {
    background: rgba(5,8,15,0.55) !important;
    border: 1px solid var(--border-glass) !important;
    color: var(--text-hi) !important;
    font-family: 'IBM Plex Mono', monospace !important;
    font-size: 0.95rem !important;
    font-weight: 600 !important;
    border-radius: 8px !important;
    box-shadow: inset 0 1px 4px rgba(0,0,0,0.4) !important;
}
textarea:focus, input[type="text"]:focus {
    border-color: rgba(56,189,248,0.5) !important;
    box-shadow: inset 0 1px 4px rgba(0,0,0,0.4), 0 0 0 3px rgba(56,189,248,0.12) !important;
}

/* ---------------------------------------------------------------------- */
/* Buttons — gradient, glowing on hover, elevated                         */
/* ---------------------------------------------------------------------- */
button.primary {
    background: linear-gradient(135deg, #1d4ed8 0%, #2563eb 45%, #4f46e5 100%) !important;
    border: 1px solid rgba(96,165,250,0.55) !important;
    color: #eaf2ff !important;
    font-family: 'IBM Plex Mono', monospace !important;
    font-size: 0.74rem !important;
    font-weight: 700 !important;
    letter-spacing: 0.10em !important;
    text-transform: uppercase !important;
    border-radius: 9px !important;
    box-shadow: 0 8px 20px -8px rgba(37,99,235,0.6), inset 0 1px 0 rgba(255,255,255,0.15) !important;
    transition: all 0.2s ease !important;
}
button.primary:hover:not(:disabled) {
    filter: brightness(1.12);
    box-shadow: 0 10px 28px -6px rgba(37,99,235,0.75), 0 0 0 1px rgba(96,165,250,0.4), inset 0 1px 0 rgba(255,255,255,0.2) !important;
    transform: translateY(-1px);
}

/* Stop button */
button.stop {
    background: linear-gradient(135deg, #7f1d1d 0%, #b91c1c 60%, #dc2626 100%) !important;
    border: 1px solid rgba(248,113,113,0.55) !important;
    color: #ffe4e4 !important;
    font-family: 'IBM Plex Mono', monospace !important;
    font-size: 0.74rem !important;
    font-weight: 700 !important;
    letter-spacing: 0.10em !important;
    text-transform: uppercase !important;
    border-radius: 9px !important;
    box-shadow: 0 8px 20px -8px rgba(220,38,38,0.55), inset 0 1px 0 rgba(255,255,255,0.12) !important;
    transition: all 0.2s ease !important;
}
button.stop:hover:not(:disabled) {
    filter: brightness(1.12);
    box-shadow: 0 10px 26px -6px rgba(220,38,38,0.7), 0 0 0 1px rgba(248,113,113,0.4) !important;
    transform: translateY(-1px);
}

/* Secondary / neutral buttons */
button.secondary {
    background: rgba(30,41,59,0.65) !important;
    border: 1px solid var(--border-glass) !important;
    color: var(--text-mid) !important;
    font-family: 'IBM Plex Mono', monospace !important;
    font-size: 0.74rem !important;
    font-weight: 600 !important;
    letter-spacing: 0.10em !important;
    text-transform: uppercase !important;
    border-radius: 9px !important;
    transition: all 0.2s ease !important;
}
button.secondary:hover:not(:disabled) {
    border-color: rgba(148,163,184,0.4) !important;
    color: var(--text-hi) !important;
    background: rgba(51,65,85,0.65) !important;
    transform: translateY(-1px);
}

button:disabled {
    opacity: 0.30 !important;
    cursor: not-allowed !important;
    transform: none !important;
}

/* ---------------------------------------------------------------------- */
/* Dataframe tables — dark glass grid                                      */
/* ---------------------------------------------------------------------- */
table {
    font-family: 'IBM Plex Mono', monospace !important;
    font-size: 0.79rem !important;
    border-collapse: collapse !important;
}
th {
    background: rgba(8,12,22,0.75) !important;
    color: var(--cyan) !important;
    font-size: 0.63rem !important;
    font-weight: 700 !important;
    letter-spacing: 0.12em !important;
    text-transform: uppercase !important;
    border-bottom: 1px solid var(--border-glass) !important;
    padding: 9px 12px !important;
}
td {
    color: #cbd5e1 !important;
    border-bottom: 1px solid rgba(148,163,184,0.08) !important;
    padding: 7px 12px !important;
}
tr:hover td { background: rgba(56,189,248,0.06) !important; }

/* Error box */
.error-box {
    background: rgba(28,5,5,0.7);
    border: 1px solid rgba(220,38,38,0.4);
    border-radius: 10px;
    padding: 0.9rem 1.1rem;
    color: #fca5a5;
    font-family: 'IBM Plex Mono', monospace;
    font-size: 0.8rem;
    white-space: pre-wrap;
    line-height: 1.6;
    backdrop-filter: blur(10px);
    box-shadow: 0 0 24px rgba(220,38,38,0.12), inset 0 1px 0 rgba(255,255,255,0.04);
}

/* Decision chip (Allow / Block / Monitor) */
.decision-chip {
    display: inline-flex; align-items: center; gap: 8px;
    font-family: 'IBM Plex Mono', monospace !important;
    font-weight: 700; font-size: 0.85rem; letter-spacing: 0.08em;
    padding: 8px 18px; border-radius: 10px; border: 1px solid;
}

/* Dividers */
hr {
    border: none !important;
    border-top: 1px solid var(--border-glass) !important;
    margin: 1rem 0 !important;
}

/* Scrollbars */
::-webkit-scrollbar { width: 8px; height: 8px; }
::-webkit-scrollbar-track { background: transparent; }
::-webkit-scrollbar-thumb { background: rgba(148,163,184,0.25); border-radius: 8px; }
::-webkit-scrollbar-thumb:hover { background: rgba(148,163,184,0.4); }

/* Hide Gradio branding */
footer { display: none !important; }
.built-with { display: none !important; }

/* Responsive tightening on small screens */
@media (max-width: 760px) {
    .app-header { padding: 1.1rem 1.2rem; }
    .app-title { font-size: 1.15rem !important; }
    .card { padding: 1rem 1.1rem 1.2rem 1.1rem !important; }
}
"""

_THEME = gr.themes.Base(
    primary_hue=gr.themes.colors.blue,
    neutral_hue=gr.themes.colors.slate,
    font=[gr.themes.GoogleFont("Inter"), "ui-sans-serif"],
    font_mono=[gr.themes.GoogleFont("IBM Plex Mono"), "ui-monospace"],
)

# ==============================================================================
# GRADIO BLOCKS LAYOUT  (Gradio 6.x: only title/fill params in Blocks)
# ==============================================================================
with gr.Blocks(title="AI Firewall — AI-Powered Network Threat Detection & Response") as demo:

    # -- Header ----------------------------------------------------------------
    gr.HTML("""
    <div class="app-header">
      <div class="app-title-wrap">
        <div class="app-logo">
          <svg width="24" height="24" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
            <path d="M12 2L4 5v6c0 5.2 3.4 9.7 8 11 4.6-1.3 8-5.8 8-11V5l-8-3z"
                  stroke="#93c5fd" stroke-width="1.6" fill="rgba(59,130,246,0.15)" stroke-linejoin="round"/>
            <path d="M9 12.2l2 2 4-4.4" stroke="#7dd3fc" stroke-width="1.7"
                  stroke-linecap="round" stroke-linejoin="round"/>
          </svg>
        </div>
        <div>
          <p class="app-title">AI FIREWALL</p>
          <p class="app-subtitle">AI-Powered Network Threat Detection &amp; Response</p>
        </div>
      </div>
      <div class="system-active">
        <span class="status-dot pulse" style="background:#34d399;box-shadow:0 0 8px 2px #34d399aa;"></span>
        SYSTEM ACTIVE
      </div>
    </div>
    """)

    # ==========================================================================
    # SECTION 1 — Network Monitoring  (capture status / controls)
    # ==========================================================================
    with gr.Group(elem_classes=["card", "card-accent-cyan"]):
        gr.HTML('<p class="sec-label">Network Monitoring</p>')

        with gr.Row():
            with gr.Column(scale=1, min_width=150):
                gr.HTML('<div style="font-family:monospace;font-size:0.62rem;'
                        'text-transform:uppercase;letter-spacing:0.10em;'
                        'color:#5b6b84;margin-bottom:6px;">Capture Status</div>')
                status_md = gr.HTML(
                    '<div class="status-pill" style="border-color:#64748b55;'
                    'background:#64748b14;color:#64748b;">'
                    '<span class="status-dot" style="background:#64748b;"></span>IDLE</div>'
                )
            with gr.Column(scale=1, min_width=130):
                gr.HTML('<div style="font-family:monospace;font-size:0.62rem;'
                        'text-transform:uppercase;letter-spacing:0.10em;'
                        'color:#5b6b84;margin-bottom:4px;">Interface</div>'
                        '<div style="font-family:IBM Plex Mono,monospace;'
                        'font-size:0.9rem;font-weight:600;color:#e2e8f0;">Wi-Fi</div>')
            with gr.Column(scale=1, min_width=130):
                start_box = gr.Textbox(value="--", label="Start Time", interactive=False)
            with gr.Column(scale=1, min_width=130):
                dur_box = gr.Textbox(value="00:00:00", label="Duration", interactive=False)
            with gr.Column(scale=1, min_width=150):
                pkts_box = gr.Textbox(value="0", label="Packets Captured", interactive=False)
            with gr.Column(scale=1, min_width=130):
                pps_box = gr.Textbox(value="0.0", label="Packets / sec (Activity)", interactive=False)

        with gr.Row():
            btn_start   = gr.Button("Start Packet Capture", variant="primary",   interactive=True,  scale=1)
            btn_stop    = gr.Button("Stop Packet Capture",  variant="stop",      interactive=False, scale=1)
            btn_analyze = gr.Button("Analyze Results",      variant="primary",   interactive=False, scale=1)
            btn_new     = gr.Button("New Capture",          variant="secondary", interactive=False, scale=1)

        error_md = gr.HTML(value="")

    # ==========================================================================
    # SECTION 2 — Capture Summary  (hidden until packets > 0)
    # ==========================================================================
    with gr.Group(visible=False, elem_classes=["card", "card-accent-blue"]) as cap_group:
        gr.HTML('<p class="sec-label">Capture Summary</p>')
        with gr.Row():
            sum_pkts  = gr.Textbox(value="0",        label="Total Packets",   interactive=False)
            sum_flows = gr.Textbox(value="0",        label="Total Flows",     interactive=False)
            sum_bytes = gr.Textbox(value="0 B",      label="Total Bytes",     interactive=False)
            sum_dur   = gr.Textbox(value="00:00:00", label="Duration",        interactive=False)
            sum_pps   = gr.Textbox(value="0.0",      label="Avg Pkts / sec",  interactive=False)

    # ==========================================================================
    # SECTION 3 — AI Threat Detection + Risk Analysis  (hidden until ANALYSIS_COMPLETE)
    # ==========================================================================
    with gr.Group(visible=False, elem_classes=["card", "card-accent-purple"]) as an_group:
        gr.HTML('<p class="sec-label">AI Threat Detection &amp; Risk Analysis</p>')

        gr.HTML('<p class="sec-sub">Threat Detection</p>')
        with gr.Row():
            an_flows  = gr.Textbox(value="0",     label="Flows Analyzed", interactive=False)
            an_normal = gr.Textbox(value="0",     label="Normal",         interactive=False)
            an_susp   = gr.Textbox(value="0",     label="Suspicious",     interactive=False)
            an_mal    = gr.Textbox(value="0",     label="Malicious",      interactive=False)

        gr.HTML('<p class="sec-sub">Risk Analysis</p>')
        with gr.Row():
            an_score  = gr.Textbox(value="0.000", label="Overall Risk Score", interactive=False)
            an_label  = gr.Textbox(value="LOW",   label="Overall Risk Level", interactive=False)

        gr.HTML('<p class="sec-sub">Detected Threats</p>')
        threat_table = gr.Dataframe(
            headers=["Timestamp", "Source IP", "Dest IP",
                     "Src Port", "Dst Port", "Protocol",
                     "Attack Type", "Risk Score", "Decision"],
            datatype=["str","str","str","str","str","str","str","number","str"],
            interactive=False,
            wrap=False,
        )

        gr.HTML('<p class="sec-sub">Source IP Analysis</p>')
        src_table = gr.Dataframe(
            headers=["IP Address", "Packets", "SYN Count",
                     "Flows", "Unique Ports", "Risk Score", "Status"],
            datatype=["str","number","number","number","number","number","str"],
            interactive=False,
            wrap=False,
        )

    # ==========================================================================
    # SECTION 4 — Decision / Response  (Firewall status, hidden until ANALYSIS_COMPLETE)
    # ==========================================================================
    with gr.Group(visible=False, elem_classes=["card", "card-accent-amber"]) as fw_group:
        gr.HTML('<p class="sec-label">Decision &amp; Response</p>')
        with gr.Row():
            gr.HTML(
                '<div class="decision-chip" style="color:#6ee7b7;border-color:rgba(52,211,153,0.4);'
                'background:rgba(16,185,129,0.08);box-shadow:0 0 16px rgba(16,185,129,0.18);'
                'margin-top:6px;">'
                '<span class="status-dot" style="background:#34d399;box-shadow:0 0 8px 2px #34d399aa;"></span>'
                'FIREWALL ACTIVE</div>'
            )
            fw_blocked   = gr.Textbox(value="0", label="Blocked IPs",   interactive=False)
            fw_monitored = gr.Textbox(value="0", label="Monitored IPs", interactive=False)

        gr.HTML('<p class="sec-sub">Recent Firewall Actions</p>')
        fw_table = gr.Dataframe(
            headers=["IP Address", "Action"],
            datatype=["str", "str"],
            interactive=False,
            wrap=False,
        )

    # -- Analysis pipeline error (hidden unless error occurred) ----------------
    with gr.Group(visible=False, elem_classes=["card", "card-accent-amber"]) as err_group:
        gr.HTML('<p class="sec-label">Analysis Error</p>')
        err_text = gr.Textbox(
            value="", label="", interactive=False, lines=8,
        )

    # ==========================================================================
    # SECTION 5 — Packet / Detection Table & Logs / Activity
    # ==========================================================================
    with gr.Group(elem_classes=["card", "card-accent-cyan"]):
        gr.HTML('<p class="sec-label">Security Event Log &amp; Activity</p>')
        evlog_table = gr.Dataframe(
            headers=["Timestamp", "Source IP", "Attack Type", "Risk Score", "Decision"],
            datatype=["str", "str", "str", "number", "str"],
            interactive=False,
            wrap=False,
        )

    # ==========================================================================
    # OUTPUT COMPONENT LIST  — MUST match _all_outputs() index map exactly
    # ==========================================================================
    _OUTPUTS = [
        status_md, start_box, dur_box, pkts_box, pps_box,            # 0-4
        btn_start, btn_stop, btn_analyze, btn_new,                    # 5-8
        error_md,                                                      # 9
        cap_group, sum_pkts, sum_flows, sum_bytes, sum_dur, sum_pps,  # 10-15
        an_group, an_flows, an_normal, an_susp, an_mal,               # 16-20
        an_score, an_label,                                            # 21-22
        threat_table, src_table,                                       # 23-24
        fw_group, fw_blocked, fw_monitored, fw_table,                 # 25-28
        err_group, err_text,                                           # 29-30
        evlog_table,                                                   # 31
    ]

    # ==========================================================================
    # EVENT BINDINGS
    # ==========================================================================
    btn_start.click(   fn=on_start,   outputs=_OUTPUTS)
    btn_stop.click(    fn=on_stop,    outputs=_OUTPUTS)
    btn_analyze.click( fn=on_analyze, outputs=_OUTPUTS)
    btn_new.click(     fn=on_new,     outputs=_OUTPUTS)

    # Initial state sync on page load
    demo.load(fn=on_refresh, outputs=_OUTPUTS)

    # Live stats refresh every 3 seconds while app is open
    timer = gr.Timer(value=3)
    timer.tick(fn=on_refresh, outputs=_OUTPUTS)


# ==============================================================================
# ENTRY POINT
# ==============================================================================
if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser(description="AI Firewall - Gradio Dashboard")
    ap.add_argument("--host",  default="127.0.0.1")
    ap.add_argument("--port",  type=int, default=7860)
    ap.add_argument("--share", action="store_true")
    args = ap.parse_args()

    print("=" * 60)
    print("  AI-BASED FIREWALL - Gradio Dashboard")
    print("=" * 60)
    print(f"  URL      : http://{args.host}:{args.port}")
    print(f"  Interface: {INTERFACE}")
    print(f"  Model    : {os.path.abspath('ai/firewall_model.pkl')}")
    print("=" * 60)
    print("  NOTE: Run as Administrator for Windows Firewall integration.")
    print("=" * 60)

    demo.queue()
    demo.launch(
        server_name=args.host,
        server_port=args.port,
        share=args.share,
        inbrowser=True,
        show_error=True,
        theme=_THEME,
        css=_CSS,
    )