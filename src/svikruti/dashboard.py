"""Interactive local Svikruti privacy engineering dashboard."""

from __future__ import annotations

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List

from svikruti.scanner.runner import run_scan
from svikruti.store import load_latest_scan, load_report_json, list_scans, save_scan_result


SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}


def main() -> None:
    import streamlit as st

    try:
        import pandas as pd
    except ImportError:  # pragma: no cover - dashboard optional dependency
        pd = None

    try:
        import plotly.graph_objects as go
    except ImportError:  # pragma: no cover - dashboard optional dependency
        go = None

    st.set_page_config(
        page_title="Svikruti Control Room",
        page_icon="SV",
        layout="wide",
        initial_sidebar_state="collapsed",
    )
    _style(st)

    db_path = os.environ.get("SVIKRUTI_DASHBOARD_DB", ".svikruti/evidence.db")
    report_path = os.environ.get("SVIKRUTI_DASHBOARD_REPORT")

    scans = list_scans(db_path, limit=100)
    report = _load_initial_report(report_path, db_path)

    st.sidebar.markdown("## Svikruti")
    st.sidebar.caption("Local-first privacy engineering control room")
    selected_scan = st.sidebar.selectbox(
        "Scan history",
        options=["Latest"] + [f"{scan['generated_at']} | {scan['risk_level']} | {scan['id']}" for scan in scans],
        index=0,
    )
    if selected_scan != "Latest":
        scan_id = selected_scan.rsplit("|", 1)[-1].strip()
        from svikruti.store import load_scan

        report = load_scan(scan_id, db_path) or report

    with st.sidebar.expander("Run a fresh scan", expanded=report is None):
        repo = st.text_input("Repository path", value=".")
        url = st.text_input("Website URL", value="")
        privacy_url = st.text_input("Privacy notice URL", value="")
        privacy_file = st.text_input("Privacy notice file", value="")
        security_evidence_raw = st.text_area("Security evidence files", placeholder="semgrep.sarif\ntrivy.json\ngitleaks.json")
        run_ai = st.checkbox("Run AI synthesis", value=False)
        if st.button("Scan and save", type="primary", width="stretch"):
            evidence_files = [line.strip() for line in security_evidence_raw.replace(",", "\n").splitlines() if line.strip()]
            try:
                with st.spinner("Scanning repository, evidence, notices, and controls..."):
                    scan = run_scan(
                        repo=repo or None,
                        url=url or None,
                        privacy_url=privacy_url or None,
                        privacy_file=privacy_file or None,
                        security_evidence=evidence_files,
                        ai_enabled=run_ai,
                    )
                    scan_id = save_scan_result(scan, db_path)
                    st.session_state["svikruti_report"] = scan.to_dict()
                    st.success(f"Saved scan {scan_id}")
                    st.rerun()
            except Exception as exc:  # pragma: no cover - UI path
                st.error(f"Scan failed: {exc}")

    if "svikruti_report" in st.session_state:
        report = st.session_state["svikruti_report"]

    if not report:
        _empty_state(st, db_path)
        return

    _header(st, report)
    _top_metrics(st, report)

    tabs = st.tabs(
        [
            "Command Center",
            "Assurance",
            "Control Plane",
            "Evidence Flow",
            "Breach Readiness",
            "Evidence Explorer",
            "AI Workbench",
            "Exports",
        ]
    )
    with tabs[0]:
        _command_center(st, report, go)
    with tabs[1]:
        _assurance(st, report, pd, go)
    with tabs[2]:
        _control_plane(st, report, pd, go)
    with tabs[3]:
        _evidence_flow(st, report, pd, go)
    with tabs[4]:
        _breach_readiness(st, report, pd, go)
    with tabs[5]:
        _evidence_explorer(st, report, pd)
    with tabs[6]:
        _ai_workbench(st, report)
    with tabs[7]:
        _exports(st, report)


def _load_initial_report(report_path: str | None, db_path: str) -> Dict[str, Any] | None:
    if report_path:
        return load_report_json(report_path)
    return load_latest_scan(db_path)


def _style(st: Any) -> None:
    st.markdown(
        """
        <style>
        :root {
          --sv-ink: #111827;
          --sv-muted: #667085;
          --sv-bg: #f5f7fb;
          --sv-panel: #ffffff;
          --sv-line: #d9e2ef;
          --sv-soft-line: #edf2f7;
          --sv-teal: #00a39b;
          --sv-navy: #0b1220;
          --sv-navy-2: #152642;
          --sv-blue: #1d4ed8;
          --sv-rose: #c1261a;
          --sv-amber: #c47a10;
          --sv-green: #087f5b;
          --sv-purple: #6741d9;
          --sv-cyan: #0891b2;
        }
        .stApp {
          background:
            linear-gradient(180deg, #eef4fb 0%, #f7f9fc 280px, #f5f7fb 100%);
          color: var(--sv-ink);
        }
        .block-container { padding-top: 4.25rem; padding-bottom: 4rem; max-width: 1520px; }
        [data-testid="stHeader"] { background: rgba(245, 247, 251, 0.74); backdrop-filter: blur(12px); }
        [data-testid="stToolbar"] { display: none; }
        [data-testid="stSidebarCollapsedControl"] {
          color: #526178 !important;
          background: rgba(255,255,255,0.85);
          border: 1px solid var(--sv-line);
          border-radius: 10px;
          margin: 8px;
        }
        [data-testid="stSidebar"] { background: #0d1725; color: white; border-right: 1px solid #223149; }
        [data-testid="stSidebar"] * { color: inherit; }
        [data-testid="stSidebar"] input, [data-testid="stSidebar"] textarea {
          color: #101828 !important;
          background: #ffffff !important;
        }
        [data-testid="stSidebar"] div[data-baseweb="select"] > div {
          background: #ffffff !important;
          color: #101828 !important;
          border-color: #cbd5e1 !important;
        }
        #MainMenu, footer, .stDeployButton { visibility: hidden; }
        h1, h2, h3, h4, h5, h6, p, li, label, span { letter-spacing: 0; }
        p, li { color: #526178; }
        label, [data-testid="stWidgetLabel"] p {
          color: #344054 !important;
          font-weight: 800 !important;
        }
        div[data-baseweb="select"] > div,
        div[data-baseweb="input"] > div,
        textarea {
          background: #ffffff !important;
          color: #101828 !important;
          border: 1px solid #cbd5e1 !important;
          border-radius: 10px !important;
        }
        div[data-baseweb="select"] span,
        div[data-baseweb="select"] div,
        div[data-baseweb="input"] input,
        div[data-baseweb="input"] input::placeholder,
        textarea,
        textarea::placeholder {
          color: #101828 !important;
          opacity: 1 !important;
        }
        div[data-baseweb="popover"],
        div[data-baseweb="menu"] {
          background: #ffffff !important;
          color: #101828 !important;
        }
        div[data-baseweb="option"] {
          background: #ffffff !important;
          color: #101828 !important;
        }
        .sv-topbar {
          display: flex;
          align-items: center;
          justify-content: space-between;
          gap: 18px;
          margin: 0 0 18px;
          min-height: 48px;
        }
        .sv-brand {
          display: flex;
          align-items: center;
          gap: 12px;
        }
        .sv-logo {
          width: 38px;
          height: 38px;
          border-radius: 12px;
          display: grid;
          place-items: center;
          color: #ffffff;
          font-weight: 950;
          background: linear-gradient(135deg, #0b1220, #14514d);
          box-shadow: 0 14px 32px rgba(11, 18, 32, 0.20);
        }
        .sv-brand-title { font-weight: 900; color: #111827; font-size: 18px; line-height: 1.1; }
        .sv-brand-sub { color: #667085; font-size: 12px; font-weight: 750; margin-top: 2px; }
        .sv-topbar-actions {
          display: flex;
          gap: 8px;
          flex-wrap: wrap;
          justify-content: flex-end;
        }
        .sv-hero {
          border: 1px solid rgba(255,255,255,0.10);
          border-radius: 20px;
          padding: 26px;
          background:
            radial-gradient(circle at 82% 10%, rgba(0, 163, 155, 0.32), transparent 28%),
            radial-gradient(circle at 30% 0%, rgba(29, 78, 216, 0.24), transparent 34%),
            linear-gradient(135deg, #080f1f 0%, #10233f 48%, #0e3f46 100%);
          margin-bottom: 14px;
          box-shadow: 0 26px 70px rgba(11, 18, 32, 0.24);
          color: #ffffff;
          overflow: hidden;
          position: relative;
        }
        .sv-hero:after {
          content: "";
          position: absolute;
          inset: 0;
          background-image:
            linear-gradient(rgba(255,255,255,0.04) 1px, transparent 1px),
            linear-gradient(90deg, rgba(255,255,255,0.04) 1px, transparent 1px);
          background-size: 32px 32px;
          mask-image: linear-gradient(90deg, transparent, #000 22%, #000 84%, transparent);
          pointer-events: none;
        }
        .sv-hero-grid {
          display: grid;
          grid-template-columns: minmax(0, 1.25fr) minmax(320px, 0.75fr);
          gap: 24px;
          align-items: stretch;
          position: relative;
          z-index: 1;
        }
        .sv-eyebrow {
          color: #9be3dc;
          text-transform: uppercase;
          font-size: 12px;
          font-weight: 850;
          letter-spacing: 0;
          margin-bottom: 8px;
        }
        .sv-hero h1 {
          margin: 0;
          font-size: 42px;
          line-height: 1.05;
          color: #ffffff;
          max-width: 980px;
        }
        .sv-hero p { color: #d8e5ee; max-width: 980px; font-size: 15px; line-height: 1.7; }
        .sv-hero-side {
          border: 1px solid rgba(255,255,255,0.16);
          background: rgba(255,255,255,0.08);
          border-radius: 16px;
          padding: 18px;
          backdrop-filter: blur(14px);
          box-shadow: inset 0 1px 0 rgba(255,255,255,0.08);
        }
        .sv-hero-side p { margin: 0 0 8px; }
        .sv-score-layout {
          display: grid;
          grid-template-columns: 130px minmax(0, 1fr);
          gap: 18px;
          align-items: center;
        }
        .sv-score-ring {
          width: 126px;
          height: 126px;
          border-radius: 50%;
          display: grid;
          place-items: center;
          background: conic-gradient(var(--ring-color) calc(var(--score) * 1%), rgba(255,255,255,0.16) 0);
          box-shadow: 0 20px 44px rgba(0,0,0,0.22);
        }
        .sv-score-ring-inner {
          width: 92px;
          height: 92px;
          border-radius: 50%;
          background: #0b1220;
          display: grid;
          place-items: center;
          text-align: center;
          border: 1px solid rgba(255,255,255,0.14);
        }
        .sv-score-ring-inner strong { display: block; font-size: 27px; color: #ffffff; line-height: 1; }
        .sv-score-ring-inner span { display: block; color: #a7bdd4; font-size: 10px; font-weight: 850; text-transform: uppercase; margin-top: 6px; }
        .sv-hero-mini-grid {
          display: grid;
          grid-template-columns: repeat(2, minmax(0, 1fr));
          gap: 10px;
          margin-top: 16px;
        }
        .sv-hero-mini {
          border: 1px solid rgba(255,255,255,0.13);
          border-radius: 12px;
          padding: 12px;
          background: rgba(255,255,255,0.07);
        }
        .sv-hero-mini b { display: block; color: #ffffff; font-size: 18px; line-height: 1.1; }
        .sv-hero-mini span { display: block; color: #b8cadb; font-size: 11px; font-weight: 800; margin-top: 4px; text-transform: uppercase; }
        .sv-card {
          border: 1px solid var(--sv-line);
          border-radius: 16px;
          background: var(--sv-panel);
          padding: 18px;
          min-height: 100%;
          box-shadow: 0 18px 42px rgba(15, 23, 42, 0.07);
        }
        .sv-card h3 { margin: 0 0 8px; font-size: 17px; }
        .sv-card p { color: var(--sv-muted); margin: 6px 0; }
        .sv-card + .sv-card { margin-top: 12px; }
        .sv-metric {
          border: 1px solid var(--sv-line);
          border-radius: 16px;
          background:
            linear-gradient(180deg, rgba(255,255,255,0.98), rgba(255,255,255,0.92)),
            #ffffff;
          padding: 16px 18px;
          box-shadow: 0 16px 38px rgba(15, 23, 42, 0.07);
          position: relative;
          overflow: hidden;
        }
        .sv-metric:before {
          content: "";
          position: absolute;
          left: 0;
          top: 0;
          height: 100%;
          width: 5px;
          background: var(--sv-teal);
        }
        .sv-metric-critical:before, .sv-metric-fail:before { background: var(--sv-rose); }
        .sv-metric-high:before, .sv-metric-missing:before { background: var(--sv-amber); }
        .sv-metric-pass:before { background: var(--sv-green); }
        .sv-label {
          color: #667085;
          font-size: 12px;
          font-weight: 850;
          text-transform: uppercase;
          letter-spacing: 0;
          margin-bottom: 7px;
        }
        .sv-chip {
          display: inline-flex;
          border: 1px solid var(--sv-line);
          border-radius: 999px;
          padding: 4px 9px;
          margin: 3px 5px 3px 0;
          font-size: 12px;
          font-weight: 750;
          background: #f8fafc;
          color: #344054;
        }
        .sv-chip-dark {
          border-color: rgba(255,255,255,0.18);
          background: rgba(255,255,255,0.10);
          color: #ffffff;
        }
        .sv-pill-critical, .sv-pill-fail {
          border-color: #f2b8b5;
          background: #fff3f2;
          color: #991b1b;
        }
        .sv-pill-pass {
          border-color: #b8e5c7;
          background: #f0fbf4;
          color: #12643b;
        }
        .sv-pill-missing {
          border-color: #f3d59b;
          background: #fff8eb;
          color: #915b0d;
        }
        .sv-status-pass { border-left: 5px solid var(--sv-green); }
        .sv-status-fail { border-left: 5px solid var(--sv-rose); }
        .sv-status-missing { border-left: 5px solid var(--sv-amber); }
        .sv-big-number {
          font-size: 28px;
          font-weight: 850;
          color: var(--sv-ink);
          line-height: 1.12;
          overflow-wrap: normal;
          word-break: keep-all;
        }
        .sv-hero .sv-big-number { color: #ffffff; font-size: 34px; }
        .sv-section-title { margin: 22px 0 10px; font-size: 20px; font-weight: 900; color: #111827; }
        .sv-section-kicker {
          color: #667085;
          font-size: 13px;
          font-weight: 750;
          margin: -6px 0 12px;
        }
        .sv-kpi-grid {
          display: grid;
          grid-template-columns: repeat(6, minmax(0, 1fr));
          gap: 10px;
          margin: 0 0 18px;
        }
        .sv-kpi {
          border: 1px solid var(--sv-line);
          border-radius: 14px;
          background: #ffffff;
          padding: 13px 14px;
          box-shadow: 0 12px 30px rgba(15,23,42,0.055);
          min-height: 106px;
          position: relative;
          overflow: hidden;
        }
        .sv-kpi:after {
          content: "";
          position: absolute;
          right: -18px;
          top: -18px;
          width: 58px;
          height: 58px;
          border-radius: 50%;
          background: rgba(0,163,155,0.08);
        }
        .sv-kpi-critical:after, .sv-kpi-fail:after { background: rgba(193,38,26,0.10); }
        .sv-kpi-missing:after { background: rgba(196,122,16,0.12); }
        .sv-kpi-pass:after { background: rgba(8,127,91,0.10); }
        .sv-kpi-value { font-size: 27px; font-weight: 950; color: #111827; line-height: 1; margin: 12px 0 6px; }
        .sv-kpi-help { font-size: 12px; color: #667085; font-weight: 750; }
        .sv-command-grid {
          display: grid;
          grid-template-columns: minmax(320px, 0.88fr) minmax(0, 1.42fr);
          gap: 16px;
          align-items: start;
        }
        .sv-command-panel {
          border: 1px solid rgba(217,226,239,0.95);
          border-radius: 18px;
          background: #ffffff;
          box-shadow: 0 24px 70px rgba(15,23,42,0.08);
          overflow: hidden;
        }
        .sv-panel-head {
          display: flex;
          align-items: center;
          justify-content: space-between;
          gap: 10px;
          padding: 16px 18px;
          border-bottom: 1px solid var(--sv-soft-line);
          background: linear-gradient(180deg, #ffffff, #f8fafc);
        }
        .sv-panel-title { font-weight: 950; color: #111827; font-size: 15px; }
        .sv-panel-body { padding: 16px 18px; }
        .sv-release-card {
          background:
            radial-gradient(circle at 86% 10%, rgba(193,38,26,0.12), transparent 32%),
            linear-gradient(180deg, #ffffff, #fbfdff);
        }
        .sv-release-verdict {
          display: flex;
          align-items: center;
          justify-content: space-between;
          gap: 16px;
          margin-bottom: 14px;
        }
        .sv-verdict-word { font-size: 30px; font-weight: 950; color: #111827; line-height: 1; }
        .sv-verdict-sub { color: #667085; font-weight: 750; margin-top: 8px; line-height: 1.45; }
        .sv-gate-list { display: grid; gap: 10px; margin-top: 16px; }
        .sv-gate-item {
          display: grid;
          grid-template-columns: 12px minmax(0, 1fr) auto;
          gap: 10px;
          align-items: center;
          padding: 10px 0;
          border-top: 1px solid var(--sv-soft-line);
        }
        .sv-gate-dot {
          width: 10px;
          height: 10px;
          border-radius: 999px;
          background: var(--sv-green);
          box-shadow: 0 0 0 5px rgba(8,127,91,0.10);
        }
        .sv-gate-dot.fail { background: var(--sv-rose); box-shadow: 0 0 0 5px rgba(193,38,26,0.10); }
        .sv-gate-dot.warn { background: var(--sv-amber); box-shadow: 0 0 0 5px rgba(196,122,16,0.12); }
        .sv-gate-name { font-weight: 850; color: #243044; }
        .sv-action-list { display: grid; gap: 10px; }
        .sv-action-row {
          display: grid;
          grid-template-columns: 34px minmax(0, 1fr) auto;
          gap: 12px;
          align-items: start;
          padding: 14px;
          border: 1px solid var(--sv-soft-line);
          border-radius: 14px;
          background: #ffffff;
          box-shadow: 0 10px 26px rgba(15,23,42,0.045);
        }
        .sv-action-row h3 { margin: 1px 0 5px; font-size: 15px; color: #111827; }
        .sv-action-row p { margin: 0; font-size: 13px; line-height: 1.55; }
        .sv-action-meta { display: flex; flex-wrap: wrap; gap: 5px; }
        .sv-signal-grid {
          display: grid;
          grid-template-columns: repeat(3, minmax(0, 1fr));
          gap: 12px;
          margin-top: 16px;
        }
        .sv-signal-card {
          border: 1px solid var(--sv-soft-line);
          border-radius: 14px;
          padding: 14px;
          background: #fbfdff;
        }
        .sv-signal-card h3 { margin: 0 0 8px; font-size: 14px; color: #111827; }
        .sv-signal-card p { font-size: 13px; line-height: 1.55; margin: 0; }
        .sv-domain-card {
          border: 1px solid var(--sv-line);
          border-radius: 16px;
          padding: 16px;
          background: linear-gradient(180deg, #ffffff, #fbfdff);
          box-shadow: 0 14px 32px rgba(15,23,42,0.06);
          min-height: 172px;
          margin-bottom: 12px;
        }
        .sv-domain-score {
          display: flex;
          justify-content: space-between;
          align-items: baseline;
          gap: 10px;
          margin: 10px 0;
        }
        .sv-domain-score strong { font-size: 30px; line-height: 1; color: #111827; }
        .sv-domain-score span { color: #667085; font-weight: 850; font-size: 12px; }
        .sv-progress {
          height: 8px;
          border-radius: 999px;
          background: #edf2f7;
          overflow: hidden;
          margin-top: 10px;
        }
        .sv-progress > span {
          display: block;
          height: 100%;
          width: var(--value);
          background: linear-gradient(90deg, var(--bar-color), rgba(0,163,155,0.82));
          border-radius: inherit;
        }
        .sv-flow-card {
          border: 1px solid var(--sv-line);
          border-radius: 18px;
          background: #ffffff;
          box-shadow: 0 18px 44px rgba(15,23,42,0.07);
          padding: 18px;
          margin: 14px 0 18px;
        }
        .sv-flow-stage {
          display: grid;
          grid-template-columns: repeat(5, minmax(0, 1fr));
          gap: 12px;
          align-items: stretch;
        }
        .sv-flow-box {
          border: 1px solid var(--sv-soft-line);
          border-radius: 14px;
          padding: 14px;
          background: linear-gradient(180deg, #ffffff, #fbfdff);
          min-height: 116px;
          position: relative;
        }
        .sv-flow-box:after {
          content: "";
          position: absolute;
          top: 50%;
          right: -15px;
          width: 16px;
          height: 2px;
          background: #cbd5e1;
        }
        .sv-flow-box:last-child:after { display: none; }
        .sv-flow-box h3 { margin: 0 0 8px; color: #111827; font-size: 14px; }
        .sv-flow-box p { margin: 0; font-size: 13px; line-height: 1.55; }
        .sv-flow-list {
          display: flex;
          flex-wrap: wrap;
          gap: 6px;
          margin-top: 10px;
        }
        .sv-chart-card {
          border: 1px solid var(--sv-line);
          border-radius: 18px;
          background: #ffffff;
          box-shadow: 0 18px 44px rgba(15,23,42,0.07);
          padding: 10px;
          margin-top: 10px;
          overflow: hidden;
        }
        .sv-board {
          display: grid;
          grid-template-columns: repeat(2, minmax(0, 1fr));
          gap: 14px;
        }
        .sv-action {
          border: 1px solid var(--sv-line);
          background: #ffffff;
          border-radius: 14px;
          padding: 16px;
          min-height: 158px;
          box-shadow: 0 12px 28px rgba(16, 36, 58, 0.05);
        }
        .sv-action h3 { margin: 10px 0 6px; font-size: 16px; }
        .sv-action p { margin: 0; color: var(--sv-muted); }
        .sv-rank {
          display: inline-grid;
          place-items: center;
          width: 26px;
          height: 26px;
          border-radius: 999px;
          background: var(--sv-navy);
          color: #ffffff;
          font-weight: 850;
          font-size: 12px;
        }
        .sv-control-row {
          border: 1px solid var(--sv-line);
          border-radius: 14px;
          background: #ffffff;
          padding: 16px;
          margin-bottom: 12px;
          display: grid;
          grid-template-columns: minmax(220px, 0.9fr) minmax(0, 1.3fr) minmax(180px, 0.45fr);
          gap: 16px;
          align-items: start;
        }
        .sv-control-row h3 { margin: 7px 0 0; font-size: 17px; }
        .sv-control-row p { margin: 0; color: var(--sv-muted); }
        .sv-decision {
          border: 1px solid #b9d9d6;
          border-radius: 16px;
          padding: 20px;
          background: linear-gradient(135deg, #ffffff, #f0faf8);
        }
        .sv-decision h2 { margin: 0 0 8px; font-size: 26px; }
        .sv-readiness-grid {
          display: grid;
          grid-template-columns: repeat(4, minmax(0, 1fr));
          gap: 12px;
        }
        .stTabs [data-baseweb="tab-list"] {
          gap: 4px;
          border: 1px solid var(--sv-line);
          background: rgba(255,255,255,0.72);
          border-radius: 14px;
          padding: 5px;
          box-shadow: 0 12px 32px rgba(15,23,42,0.055);
        }
        .stTabs [data-baseweb="tab"] {
          font-weight: 850;
          color: #526178;
          border-radius: 10px;
          padding: 10px 13px;
        }
        .stTabs [aria-selected="true"] {
          color: #ffffff !important;
          background: linear-gradient(135deg, var(--sv-navy), var(--sv-navy-2)) !important;
          box-shadow: 0 10px 22px rgba(11,18,32,0.18);
        }
        .stTabs [aria-selected="true"] *,
        .stTabs [aria-selected="true"] p {
          color: #ffffff !important;
        }
        .stDataFrame { border: 1px solid var(--sv-line); border-radius: 10px; overflow: hidden; }
        .sv-table-wrap {
          border: 1px solid var(--sv-line);
          border-radius: 14px;
          overflow: auto;
          background: #ffffff;
          box-shadow: 0 14px 30px rgba(16, 36, 58, 0.05);
        }
        .sv-table {
          border-collapse: collapse;
          width: 100%;
          min-width: 1100px;
          font-size: 13px;
        }
        .sv-table th {
          position: sticky;
          top: 0;
          z-index: 1;
          background: #f8fafc;
          color: #344054;
          text-align: left;
          text-transform: uppercase;
          font-size: 11px;
          font-weight: 850;
          padding: 12px;
          border-bottom: 1px solid var(--sv-line);
        }
        .sv-table td {
          color: #243044;
          padding: 12px;
          border-bottom: 1px solid var(--sv-soft-line);
          vertical-align: top;
        }
        .sv-table tr:hover td { background: #f8fbff; }
        .sv-table-caption {
          color: #667085;
          font-size: 13px;
          margin: 8px 0 10px;
        }
        div[data-testid="stDownloadButton"] button, div[data-testid="stButton"] button {
          border-radius: 10px;
          font-weight: 850;
          border: 1px solid #10243a !important;
          background: #10243a !important;
          color: #ffffff !important;
          min-height: 44px;
        }
        div[data-testid="stDownloadButton"] button *,
        div[data-testid="stButton"] button * {
          color: #ffffff !important;
        }
        div[data-testid="stDownloadButton"] button:hover,
        div[data-testid="stButton"] button:hover {
          background: #193754 !important;
          border-color: #193754 !important;
        }
        @media (max-width: 900px) {
          .sv-hero-grid, .sv-board, .sv-control-row, .sv-readiness-grid, .sv-command-grid, .sv-kpi-grid, .sv-signal-grid, .sv-score-layout, .sv-flow-stage { grid-template-columns: 1fr; }
          .sv-flow-box:after { display: none; }
          .sv-hero h1 { font-size: 30px; }
          .sv-topbar { align-items: flex-start; flex-direction: column; }
        }
        </style>
        """,
        unsafe_allow_html=True,
    )


def _empty_state(st: Any, db_path: str) -> None:
    st.markdown(
        f"""
        <div class="sv-hero">
          <div class="sv-eyebrow">Local-first Privacy Engineering</div>
          <h1>No scan loaded yet.</h1>
          <p>Run a scan from the sidebar or import a JSON report. Scan history will be stored in <code>{db_path}</code>.</p>
        </div>
        """,
        unsafe_allow_html=True,
    )
    st.code(
        "svikruti scan --repo . --json-out svikruti-report.json --save-history\n"
        "svikruti dashboard",
        language="bash",
    )


def _header(st: Any, report: Dict[str, Any]) -> None:
    summary = report.get("summary", {})
    generated = _format_dt(str(report.get("generated_at", "")))
    breach = report.get("breach_readiness", {})
    controls = report.get("technical_controls", [])
    evidence = report.get("evidence", [])
    quality = report.get("scan_quality", {})
    scope = report.get("repo_path") or report.get("url") or "local scan"
    risk = str(summary.get("risk_level", "UNKNOWN"))
    risk_class = _pill_tone(risk)
    risk_score = int(summary.get("risk_score", 0) or 0)
    failed_controls = sum(1 for item in controls if item.get("status") == "fail")
    high_evidence = sum(1 for item in evidence if item.get("severity") in {"CRITICAL", "HIGH"})
    parser_coverage = int(quality.get("parser_coverage_percent", 0) or 0)
    st.markdown(
        f"""
        <div class="sv-topbar">
          <div class="sv-brand">
            <div class="sv-logo">SV</div>
            <div>
              <div class="sv-brand-title">Svikruti Control Room</div>
              <div class="sv-brand-sub">Privacy engineering evidence, release gates, and DPDPA technical controls</div>
            </div>
          </div>
          <div class="sv-topbar-actions">
            <span class="sv-chip">Local-first</span>
            <span class="sv-chip">Open source</span>
            <span class="sv-chip">AI-ready evidence packet</span>
          </div>
        </div>
        <div class="sv-hero">
          <div class="sv-hero-grid">
            <div>
              <div class="sv-eyebrow">Privacy Engineering Control Room</div>
              <h1>Evidence-backed DPDPA posture for engineering-led teams.</h1>
              <p>Loaded scan generated <strong>{generated}</strong> for <strong>{_escape(scope)}</strong>. Svikruti connects source code, website signals, notices, technical controls, vulnerability evidence, and breach readiness into one release-review cockpit.</p>
              <span class="sv-chip sv-chip-dark">Code evidence</span>
              <span class="sv-chip sv-chip-dark">Security imports</span>
              <span class="sv-chip sv-chip-dark">Breach posture</span>
              <span class="sv-chip sv-chip-dark">Control plane</span>
            </div>
            <div class="sv-hero-side">
              <div class="sv-score-layout">
                {_score_ring(risk_score, "#ff6b5f")}
                <div>
                  <p class="sv-label" style="color:#b8d8e6">Current decision signal</p>
                  <div class="sv-big-number">{_escape(risk)}</div>
                  <span class="sv-chip {_escape(risk_class)}">{risk_score}/100 risk score</span>
                  <span class="sv-chip sv-chip-dark">{_escape(str(breach.get('posture', 'unknown')).replace('_', ' ').title())}</span>
                </div>
              </div>
              <div class="sv-hero-mini-grid">
                <div class="sv-hero-mini"><b>{failed_controls}</b><span>failed controls</span></div>
                <div class="sv-hero-mini"><b>{high_evidence}</b><span>high evidence</span></div>
                <div class="sv-hero-mini"><b>{parser_coverage}%</b><span>parser coverage</span></div>
                <div class="sv-hero-mini"><b>{len(summary.get('third_parties', []))}</b><span>vendors</span></div>
              </div>
            </div>
          </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def _top_metrics(st: Any, report: Dict[str, Any]) -> None:
    summary = report.get("summary", {})
    breach = report.get("breach_readiness", {})
    controls = report.get("technical_controls", [])
    failing = sum(1 for item in controls if item.get("status") == "fail")
    missing = sum(1 for item in controls if item.get("status") == "missing")
    metrics = [
        ("Risk", summary.get("risk_level", "UNKNOWN"), f"{summary.get('risk_score', 0)}/100", _metric_tone(str(summary.get("risk_level", "")))),
        ("Breach", str(breach.get("posture", "unknown")).replace("_", " ").title(), f"{breach.get('score', 'n/a')}/100", "sv-metric-fail" if breach.get("posture") != "ready" else "sv-metric-pass"),
        ("Controls", len(controls), f"{failing} fail / {missing} missing", "sv-metric-fail" if failing else "sv-metric-missing" if missing else "sv-metric-pass"),
        ("Evidence", len(report.get("evidence", [])), "items", "sv-metric-pass"),
        ("Parser", f"{report.get('scan_quality', {}).get('parser_coverage_percent', 0)}%", "semantic coverage", "sv-metric-pass" if report.get("scan_quality", {}).get("parser_coverage_percent", 0) >= 60 else "sv-metric-missing"),
        ("Vendors", len(summary.get("third_parties", [])), "third parties", "sv-metric"),
    ]
    cards = []
    for label, value, help_text, tone in metrics:
        cards.append(
            f'<div class="sv-kpi {_escape(tone.replace("sv-metric", "sv-kpi"))}"><div class="sv-label">{_escape(label)}</div><div class="sv-kpi-value">{_escape(value)}</div><div class="sv-kpi-help">{_escape(help_text)}</div></div>'
        )
    st.markdown(f'<div class="sv-kpi-grid">{"".join(cards)}</div>', unsafe_allow_html=True)


def _command_center(st: Any, report: Dict[str, Any], go: Any) -> None:
    summary = report.get("summary", {})
    actions = report.get("evidence_graph", {}).get("proof_pack", [])
    controls = report.get("technical_controls", [])
    evidence = report.get("evidence", [])
    graph = report.get("evidence_graph", {})
    flows = graph.get("data_flows", [])
    breach = report.get("breach_readiness", {})
    assurance = report.get("assurance_profile", {})
    high = [item for item in evidence if item.get("severity") in {"CRITICAL", "HIGH"}]
    fail_controls = [item for item in controls if item.get("status") == "fail"]
    notice_gaps = report.get("notice_gaps", [])
    logging_risks = sum(1 for flow in flows if flow.get("logging_risks"))
    missing_notice = sum(1 for flow in flows if str(flow.get("notice_status", "")).lower() == "missing")
    verified = int((assurance.get("counts") or {}).get("verified", 0) or 0)
    inferred = int((assurance.get("counts") or {}).get("inferred", 0) or 0)

    decision = "Block release" if summary.get("risk_level") in {"CRITICAL", "HIGH"} or fail_controls else "Review before launch"
    decision_detail = (
        "Do not treat this as production-ready until failed technical controls and high-severity evidence have owners."
        if decision == "Block release"
        else "No blocking technical signal was detected, but owner review is still required before launch."
    )
    st.markdown(
        f"""
        <div class="sv-command-grid">
          <div class="sv-command-panel sv-release-card">
            <div class="sv-panel-head">
              <div>
                <div class="sv-label">Release gate</div>
                <div class="sv-panel-title">Decision brief</div>
              </div>
              <span class="sv-chip {_pill_tone(str(summary.get('risk_level', '')))}">{_escape(str(summary.get('risk_level', 'UNKNOWN')))}</span>
            </div>
            <div class="sv-panel-body">
              <div class="sv-release-verdict">
                <div>
                  <div class="sv-verdict-word">{_escape(decision)}</div>
                  <div class="sv-verdict-sub">{_escape(decision_detail)}</div>
                </div>
                {_score_ring(int(summary.get('risk_score', 0) or 0), "#c1261a")}
              </div>
              <div class="sv-gate-list">
                {_gate_item("Owners", "P0/P1 actions need accountable owners", "fail" if actions else "warn", f"{len(actions)} actions")}
                {_gate_item("Controls", "Technical controls must pass or carry exceptions", "fail" if fail_controls else "pass", f"{len(fail_controls)} failing")}
                {_gate_item("Notice", "Code-collected categories must be covered in notices", "fail" if notice_gaps or missing_notice else "pass", f"{missing_notice} gaps")}
                {_gate_item("Evidence", "Breach, monitoring, encryption, and vulnerability proof", "warn" if (breach.get("posture") != "ready") else "pass", str(breach.get("posture", "unknown")).replace("_", " ").title())}
              </div>
            </div>
          </div>
          <div class="sv-command-panel">
            <div class="sv-panel-head">
              <div>
                <div class="sv-label">Executive queue</div>
                <div class="sv-panel-title">Highest-impact fixes before release</div>
              </div>
              <span class="sv-chip">{len(actions)} generated actions</span>
            </div>
            <div class="sv-panel-body">
              <div class="sv-action-list">
                {"".join(_action_row_html(index, action) for index, action in enumerate(actions[:6], start=1))}
              </div>
            </div>
          </div>
        </div>
        <div class="sv-signal-grid">
          {_signal_card("Evidence fabric", f"{len(evidence)} signals mapped from code, cloud, notices, security imports, and website surface.", len(evidence), 250, "#00a39b")}
          {_signal_card("Assurance mix", f"{verified} verified dimensions, {inferred} inferred dimensions, {assurance.get('score', 0)} overall assurance score.", int(assurance.get("score", 0) or 0), 100, "#1d4ed8")}
          {_signal_card("Breach readiness", f"{breach.get('score', 'n/a')}/100 readiness with {logging_risks} logging-risk paths and {len(fail_controls)} failed controls.", int(breach.get("score", 0) or 0), 100, "#c47a10")}
        </div>
        """,
        unsafe_allow_html=True,
    )

    if go:
        st.markdown('<div class="sv-section-title">Signal Distribution</div><div class="sv-section-kicker">Severity and control status grouped for release review.</div>', unsafe_allow_html=True)
        severities = _counts([item.get("severity", "LOW") for item in evidence])
        control_status = _counts([item.get("status", "missing") for item in controls])
        fig = go.Figure()
        fig.add_trace(go.Bar(x=list(severities), y=list(severities.values()), name="Evidence severity", marker_color="#c1261a", marker_line_width=0))
        fig.add_trace(go.Bar(x=list(control_status), y=list(control_status.values()), name="Control status", marker_color="#00a39b", marker_line_width=0))
        fig.update_traces(hovertemplate="%{x}: %{y}<extra></extra>")
        fig.update_layout(
            height=300,
            barmode="group",
            margin=dict(l=20, r=20, t=20, b=28),
            paper_bgcolor="#ffffff",
            plot_bgcolor="#ffffff",
            font=dict(color="#243044", size=12),
            xaxis=dict(gridcolor="#eef2f7", tickfont=dict(color="#526178", size=11), title=""),
            yaxis=dict(gridcolor="#e2e8f0", tickfont=dict(color="#526178", size=11), title=""),
            legend=dict(
                orientation="h",
                yanchor="bottom",
                y=1.02,
                xanchor="right",
                x=1,
                font=dict(color="#344054", size=12),
                bgcolor="rgba(255,255,255,0.86)",
            ),
            hoverlabel=dict(bgcolor="#111827", font=dict(color="#ffffff", size=12), bordercolor="#111827"),
        )
        st.plotly_chart(fig, width="stretch", config=_plot_config())


def _assurance(st: Any, report: Dict[str, Any], pd: Any, go: Any) -> None:
    profile = report.get("assurance_profile") or {}
    quality = report.get("scan_quality") or {}
    counts = profile.get("counts") or {}
    dimensions = profile.get("dimensions") or []
    st.markdown('<div class="sv-section-title">Production Assurance Profile</div>', unsafe_allow_html=True)
    st.markdown(
        f"""
        <div class="sv-decision">
          <div class="sv-label">What Svikruti can honestly claim from this scan</div>
          <h2>{_escape(str(profile.get('production_claim', 'insufficient evidence'))).title()}</h2>
          <p>This profile separates verified evidence, inferred signals, failing controls, and unknown production areas. It is designed for serious production codebases where overclaiming is dangerous.</p>
          <span class="sv-chip {_pill_tone('pass')}">{counts.get('verified', 0)} verified</span>
          <span class="sv-chip {_pill_tone('review')}">{counts.get('inferred', 0)} inferred</span>
          <span class="sv-chip {_pill_tone('critical')}">{counts.get('failing', 0)} failing</span>
          <span class="sv-chip">{counts.get('unknown', 0)} unknown</span>
        </div>
        """,
        unsafe_allow_html=True,
    )
    c1, c2, c3, c4 = st.columns(4)
    metric_items = [
        (c1, "Assurance", profile.get("score", 0), "overall evidence strength", _metric_tone("pass" if profile.get("score", 0) >= 80 else "missing")),
        (c2, "Verified", counts.get("verified", 0), "direct evidence", "sv-metric-pass"),
        (c3, "Failing", counts.get("failing", 0), "blocking evidence", "sv-metric-fail" if counts.get("failing", 0) else "sv-metric-pass"),
        (c4, "Unknown", counts.get("unknown", 0), "not verifiable from scan", "sv-metric-missing" if counts.get("unknown", 0) else "sv-metric-pass"),
    ]
    for col, label, value, help_text, tone in metric_items:
        with col:
            st.markdown(f'<div class="sv-metric {tone}"><div class="sv-label">{label}</div><div class="sv-big-number">{value}</div><p>{help_text}</p></div>', unsafe_allow_html=True)

    if go and dimensions:
        fig = go.Figure(
            data=[
                go.Bar(
                    x=[item.get("title") for item in dimensions],
                    y=[item.get("score", 0) for item in dimensions],
                    marker_color=[_status_color(str(item.get("status", ""))) for item in dimensions],
                    hovertemplate="%{x}: %{y}/100<extra></extra>",
                )
            ]
        )
        fig.update_layout(
            height=360,
            yaxis_range=[0, 100],
            margin=dict(l=20, r=20, t=30, b=140),
            paper_bgcolor="#ffffff",
            plot_bgcolor="#ffffff",
            font=dict(color="#243044", size=12),
            xaxis=dict(gridcolor="#eef2f7", tickfont=dict(color="#526178", size=11), title=""),
            yaxis=dict(gridcolor="#e2e8f0", tickfont=dict(color="#526178", size=11), title=""),
            hoverlabel=dict(bgcolor="#111827", font=dict(color="#ffffff", size=12), bordercolor="#111827"),
        )
        st.plotly_chart(fig, width="stretch", config=_plot_config())

    st.markdown('<div class="sv-section-title">Assurance Dimensions</div>', unsafe_allow_html=True)
    st.markdown(
        f"""
        <div class="sv-card">
          <h3>Scan quality</h3>
          <p><strong>{quality.get('parser_coverage_percent', 0)}%</strong> semantic parser coverage across <strong>{quality.get('parsed_files', 0)}</strong> parsed files. Engines: {_escape(', '.join((quality.get('parser_engines') or {}).keys()) or 'none')}.</p>
        </div>
        """,
        unsafe_allow_html=True,
    )
    for row in _chunks(dimensions, 2):
        cols = st.columns(len(row))
        for col, dimension in zip(cols, row):
            with col:
                status_value = str(dimension.get("status", "unknown"))
                st.markdown(
                    f"""
                    <div class="sv-card sv-status-{'pass' if status_value == 'verified' else 'fail' if status_value == 'failing' else 'missing'}">
                      <span class="sv-chip {_pill_tone(status_value)}">{_escape(status_value.title())}</span>
                      <span class="sv-chip">{_escape(str(dimension.get('score', 0)))}/100</span>
                      <h3>{_escape(dimension.get('title', 'Assurance dimension'))}</h3>
                      <p>{_escape(dimension.get('reason', ''))}</p>
                      <p><strong>Owner:</strong> {_escape(dimension.get('owner', ''))}</p>
                      <p><strong>Evidence:</strong> {_escape(str(dimension.get('evidence_count', 0)))} refs</p>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
    unknowns = profile.get("unknowns") or []
    if unknowns:
        st.markdown('<div class="sv-section-title">Unknowns To Close Before Production Claims</div>', unsafe_allow_html=True)
        for item in unknowns:
            st.markdown(f'<div class="sv-card sv-status-missing"><p>{_escape(item)}</p></div>', unsafe_allow_html=True)
    if dimensions:
        _render_simple_table(
            st,
            [
                {
                    "Dimension": item.get("title"),
                    "Status": item.get("status"),
                    "Score": item.get("score"),
                    "Owner": item.get("owner"),
                    "Reason": item.get("reason"),
                }
                for item in dimensions
            ],
            ["Dimension", "Status", "Score", "Owner", "Reason"],
        )


def _control_plane(st: Any, report: Dict[str, Any], pd: Any, go: Any) -> None:
    controls = report.get("technical_controls", [])
    st.markdown('<div class="sv-section-title">Technical Control Plane</div>', unsafe_allow_html=True)
    if not controls:
        st.info("No technical controls generated.")
        return

    filters = st.columns([1, 1, 2])
    status = filters[0].multiselect("Status", sorted({item.get("status", "missing") for item in controls}), default=[])
    area = filters[1].multiselect("Area", sorted({item.get("area", "") for item in controls}), default=[])
    query = filters[2].text_input("Search controls")
    filtered = [
        item
        for item in controls
        if (not status or item.get("status") in status)
        and (not area or item.get("area") in area)
        and (not query or query.lower() in json.dumps(item).lower())
    ]

    st.markdown(
        """
        <div class="sv-card">
          <h3>Control objective</h3>
          <p>This view connects detected engineering evidence to DPDPA-relevant technical controls. Failed and missing controls should become release blockers or owner-backed exceptions.</p>
        </div>
        """,
        unsafe_allow_html=True,
    )
    for control in filtered:
        status_value = str(control.get("status", "missing"))
        css = f"sv-status-{status_value}"
        evidence_refs = control.get("evidence_refs", [])
        ref_preview = ", ".join(str(ref) for ref in evidence_refs[:3]) or "No direct evidence attached"
        st.markdown(
            f"""
            <div class="sv-control-row {css}">
              <div>
                <span class="sv-chip">{_escape(control.get('id', ''))}</span>
                <span class="sv-chip {_pill_tone(status_value)}">{_escape(status_value.title())}</span>
                <h3>{_escape(control.get('title', 'Control'))}</h3>
              </div>
              <div>
                <div class="sv-label">Required action</div>
                <p>{_escape(control.get('next_action', ''))}</p>
                <p style="margin-top:8px"><strong>Evidence:</strong> {_escape(ref_preview)}</p>
              </div>
              <div>
                <div class="sv-label">Owner</div>
                <p>{_escape(control.get('owner', 'Unassigned'))}</p>
                <p><strong>{_escape(str(control.get('evidence_count', 0)))}</strong> refs</p>
              </div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        with st.expander(f"Evidence refs and AI prompt: {control.get('id', 'control')}"):
            st.write(evidence_refs)
            st.code(control.get("ai_prompt", ""), language="text")

    st.markdown('<div class="sv-section-title">Control Register</div>', unsafe_allow_html=True)
    _render_simple_table(
        st,
        [
            {
                "ID": item.get("id"),
                "Control": item.get("title"),
                "Status": item.get("status"),
                "Severity": item.get("severity"),
                "Owner": item.get("owner"),
                "Next action": item.get("next_action"),
            }
            for item in controls
        ],
        ["ID", "Control", "Status", "Severity", "Owner", "Next action"],
    )


def _evidence_flow(st: Any, report: Dict[str, Any], pd: Any, go: Any) -> None:
    graph = report.get("evidence_graph", {})
    flows = graph.get("data_flows", [])
    st.markdown('<div class="sv-section-title">Data Flow Evidence</div>', unsafe_allow_html=True)
    if not flows:
        st.info("No data flows generated.")
        return
    missing_notice = sum(1 for flow in flows if str(flow.get("notice_status", "")).lower() == "missing")
    logging_risks = sum(1 for flow in flows if flow.get("logging_risks"))
    c1, c2, c3 = st.columns(3)
    with c1:
        st.markdown(f'<div class="sv-metric"><div class="sv-label">Mapped flows</div><div class="sv-big-number">{len(flows)}</div><p>code to notice to action</p></div>', unsafe_allow_html=True)
    with c2:
        st.markdown(f'<div class="sv-metric sv-metric-missing"><div class="sv-label">Notice gaps</div><div class="sv-big-number">{missing_notice}</div><p>categories not clearly covered</p></div>', unsafe_allow_html=True)
    with c3:
        st.markdown(f'<div class="sv-metric sv-metric-fail"><div class="sv-label">Logging risks</div><div class="sv-big-number">{logging_risks}</div><p>possible exposure paths</p></div>', unsafe_allow_html=True)
    st.markdown(_flow_overview_html(flows), unsafe_allow_html=True)
    table = []
    for flow in flows:
        table.append(
            {
                "Data category": flow.get("data_category"),
                "Notice": flow.get("notice_status"),
                "Collection": ", ".join(flow.get("collection_points", [])),
                "Storage": ", ".join(flow.get("storage_points", [])),
                "Logging": ", ".join(flow.get("logging_risks", [])),
                "DPDPA areas": ", ".join(flow.get("dpdpa_obligations", [])),
                "Action": "; ".join(flow.get("remediation", [])),
            }
        )
    _render_simple_table(st, table, ["Data category", "Notice", "Collection", "Storage", "Logging", "DPDPA areas", "Action"])


def _breach_readiness(st: Any, report: Dict[str, Any], pd: Any, go: Any) -> None:
    breach = report.get("breach_readiness", {})
    domains = breach.get("domains", {})
    c1, c2, c3 = st.columns(3)
    with c1:
        st.markdown(
            f'<div class="sv-metric sv-metric-fail"><div class="sv-label">Breach posture</div><div class="sv-big-number">{_escape(str(breach.get("posture", "unknown")).replace("_", " ").title())}</div><p>{breach.get("score", "n/a")}/100 readiness score</p></div>',
            unsafe_allow_html=True,
        )
    with c2:
        st.markdown(
            f'<div class="sv-metric sv-metric-fail"><div class="sv-label">Failed controls</div><div class="sv-big-number">{len(breach.get("failed_controls", []))}</div><p>need owner-backed remediation</p></div>',
            unsafe_allow_html=True,
        )
    with c3:
        st.markdown(
            f'<div class="sv-metric sv-metric-missing"><div class="sv-label">Missing controls</div><div class="sv-big-number">{len(breach.get("missing_controls", []))}</div><p>need evidence or exception</p></div>',
            unsafe_allow_html=True,
        )
    if domains:
        st.markdown('<div class="sv-section-title">Readiness Domains</div><div class="sv-section-kicker">Each domain is scored from direct evidence, inferred signals, and missing production proof.</div>', unsafe_allow_html=True)
        domain_items = [(key, value) for key, value in domains.items() if isinstance(value, dict)]
        for row in _chunks(domain_items, 4):
            cols = st.columns(len(row))
            for col, item in zip(cols, row):
                key, value = item
                status_value = str(value.get("status", "unknown"))
                score = int(value.get("score", 0) or 0)
                color = "#087f5b" if status_value in {"ready", "ok"} else "#c47a10"
                with col:
                    st.markdown(
                        f'<div class="sv-domain-card"><div class="sv-label">{_escape(key.replace("_", " ").title())}</div><div class="sv-domain-score"><strong>{score}</strong><span>/100</span></div><span class="sv-chip {_pill_tone(status_value)}">{_escape(status_value.replace("_", " ").title())}</span><div class="sv-progress"><span style="--value:{max(4, min(score, 100))}%;--bar-color:{color}"></span></div></div>',
                        unsafe_allow_html=True,
                    )
    st.markdown('<div class="sv-section-title">Priority Actions</div>', unsafe_allow_html=True)
    for action in breach.get("priority_actions", []) or ["Confirm production scope and attach evidence to the release record."]:
        st.markdown(f'<div class="sv-card"><p>{_escape(action)}</p></div>', unsafe_allow_html=True)
    rows = [{"Domain": k.replace("_", " ").title(), **v} for k, v in domains.items() if isinstance(v, dict)]
    if rows:
        _render_simple_table(st, rows, ["Domain", "status", "score", "reason"])
    if go and domains:
        fig = go.Figure(
            data=[
                go.Bar(
                    x=[k.replace("_", " ").title() for k in domains],
                    y=[v.get("score", 0) for v in domains.values()],
                    marker_color=["#b42318" if v.get("status") == "needs_action" else "#087b78" for v in domains.values()],
                    hovertemplate="%{x}: %{y}/100<extra></extra>",
                )
            ]
        )
        fig.update_layout(
            height=330,
            yaxis_range=[0, 100],
            margin=dict(l=20, r=20, t=30, b=80),
            paper_bgcolor="#ffffff",
            plot_bgcolor="#ffffff",
            font=dict(color="#243044", size=12),
            xaxis=dict(gridcolor="#eef2f7", tickfont=dict(color="#526178", size=11), title=""),
            yaxis=dict(gridcolor="#e2e8f0", tickfont=dict(color="#526178", size=11), title=""),
            hoverlabel=dict(bgcolor="#111827", font=dict(color="#ffffff", size=12), bordercolor="#111827"),
        )
        st.plotly_chart(fig, width="stretch", config=_plot_config())


def _evidence_explorer(st: Any, report: Dict[str, Any], pd: Any) -> None:
    evidence = report.get("evidence", [])
    st.markdown('<div class="sv-section-title">Evidence Explorer</div>', unsafe_allow_html=True)
    severities = st.multiselect("Severity", ["CRITICAL", "HIGH", "MEDIUM", "LOW"], default=[])
    query = st.text_input("Search evidence")
    rows = [
        {
            "Severity": item.get("severity"),
            "Finding": item.get("label"),
            "Kind": item.get("kind"),
            "File": f"{item.get('file') or item.get('source')}{':' + str(item.get('line')) if item.get('line') else ''}",
            "Detail": item.get("detail"),
            "Recommendation": item.get("recommendation"),
            "Evidence ref": item.get("metadata", {}).get("evidence_ref"),
        }
        for item in evidence
        if (not severities or item.get("severity") in severities)
        and (not query or query.lower() in json.dumps(item).lower())
    ]
    rows.sort(key=lambda item: SEVERITY_ORDER.get(item.get("Severity", "LOW"), 0), reverse=True)
    st.markdown(f'<div class="sv-table-caption">Showing {min(len(rows), 250)} of {len(rows)} evidence records. Use filters to narrow high-volume scans.</div>', unsafe_allow_html=True)
    _render_evidence_table(st, rows[:250])


def _ai_workbench(st: Any, report: Dict[str, Any]) -> None:
    st.markdown('<div class="sv-section-title">AI Workbench</div>', unsafe_allow_html=True)
    insights = report.get("ai_insights") or {}
    st.markdown(
        """
        <div class="sv-card">
          <h3>Grounded AI, not generic compliance text</h3>
          <p>The AI packet is intentionally constrained to scanner evidence: controls, breach posture, notice gaps, data flows, and source references. Use it to generate owner-facing summaries, tickets, and exception rationale.</p>
        </div>
        """,
        unsafe_allow_html=True,
    )
    if insights.get("status") == "generated":
        st.markdown(f'<div class="sv-card"><h3>AI Brief</h3><p>{_escape(insights.get("executive_brief", ""))}</p></div>', unsafe_allow_html=True)
    prompts = [
        "Explain the top privacy engineering risks in this scan for a CTO.",
        "Draft Jira tickets for failed technical controls with acceptance criteria.",
        "Summarize breach readiness gaps for legal and security leadership.",
        "Identify evidence missing for encryption, monitoring, vulnerability management, and incident response.",
        "Create a release gate policy from this Svikruti scan.",
    ]
    st.markdown('<div class="sv-section-title">Prompt Playbook</div>', unsafe_allow_html=True)
    for index, prompt in enumerate(prompts, start=1):
        st.markdown(f'<div class="sv-card"><span class="sv-rank">{index}</span><p>{_escape(prompt)}</p></div>', unsafe_allow_html=True)
    st.download_button(
        "Download AI evidence packet",
        data=json.dumps(_compact_ai_packet(report), indent=2),
        file_name="svikruti-ai-evidence-packet.json",
        mime="application/json",
    )


def _exports(st: Any, report: Dict[str, Any]) -> None:
    st.markdown('<div class="sv-section-title">Exports</div>', unsafe_allow_html=True)
    c1, c2, c3 = st.columns(3)
    with c1:
        st.markdown('<div class="sv-card"><h3>Complete evidence packet</h3><p>For CI, archival, and AI workflows.</p></div>', unsafe_allow_html=True)
        st.download_button("Download full JSON", json.dumps(report, indent=2), "svikruti-report.json", "application/json", width="stretch")
    with c2:
        st.markdown('<div class="sv-card"><h3>Technical controls</h3><p>For engineering owners and release gates.</p></div>', unsafe_allow_html=True)
        st.download_button(
            "Download controls JSON",
            json.dumps(report.get("technical_controls", []), indent=2),
            "svikruti-technical-controls.json",
            "application/json",
            width="stretch",
        )
    with c3:
        st.markdown('<div class="sv-card"><h3>Breach readiness</h3><p>For security, legal, and incident owners.</p></div>', unsafe_allow_html=True)
        st.download_button(
            "Download breach JSON",
            json.dumps(report.get("breach_readiness", {}), indent=2),
            "svikruti-breach-readiness.json",
            "application/json",
            width="stretch",
        )
    st.markdown(
        """
        <div class="sv-card">
          <h3>CLI exports still matter</h3>
          <p>Use HTML for offline sharing, SARIF for PR annotations, CSV for GRC/procurement workflows,
          Markdown for tickets and breach packs, and this dashboard for daily review.</p>
        </div>
        """,
        unsafe_allow_html=True,
    )


def _sankey(go: Any, flows: List[Dict[str, Any]]) -> Any:
    labels: List[str] = []
    index: Dict[str, int] = {}
    sources: List[int] = []
    targets: List[int] = []
    values: List[int] = []

    def node(label: str) -> int:
        if label not in index:
            index[label] = len(labels)
            labels.append(label)
        return index[label]

    for flow in flows[:25]:
        data = str(flow.get("data_category", "Data"))
        notice = "Notice: " + str(flow.get("notice_status", "unknown")).title()
        areas = flow.get("dpdpa_obligations", []) or ["DPDPA area"]
        action = "Action required" if flow.get("remediation") else "No immediate action"
        for source in flow.get("collection_points", []) or flow.get("storage_points", []) or ["Detected source"]:
            sources.append(node(str(source)[:42]))
            targets.append(node(data))
            values.append(1)
        sources.append(node(data))
        targets.append(node(notice))
        values.append(1)
        for area in areas:
            sources.append(node(notice))
            targets.append(node(str(area)))
            values.append(1)
            sources.append(node(str(area)))
            targets.append(node(action))
            values.append(1)
    fig = go.Figure(
        data=[
            go.Sankey(
                arrangement="snap",
                node=dict(
                    label=labels,
                    pad=20,
                    thickness=16,
                    line=dict(color="#cbd5e1", width=1),
                    color=[_palette(index) for index, _ in enumerate(labels)],
                ),
                link=dict(
                    source=sources,
                    target=targets,
                    value=values,
                    color="rgba(82, 97, 120, 0.28)",
                ),
            )
        ]
    )
    fig.update_layout(
        height=520,
        margin=dict(l=10, r=10, t=20, b=10),
        paper_bgcolor="#ffffff",
        plot_bgcolor="#ffffff",
        font=dict(color="#243044", size=12),
    )
    return fig


def _compact_ai_packet(report: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "summary": report.get("summary", {}),
        "notice_gaps": report.get("notice_gaps", [])[:20],
        "technical_controls": report.get("technical_controls", []),
        "breach_readiness": report.get("breach_readiness", {}),
        "data_flows": report.get("evidence_graph", {}).get("data_flows", [])[:20],
        "top_evidence": report.get("evidence", [])[:100],
    }


def _counts(values: Iterable[str]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for value in values:
        counts[str(value)] = counts.get(str(value), 0) + 1
    return counts


def _action_card_html(index: int, action: Dict[str, Any]) -> str:
    return (
        '<div class="sv-action">'
        f'<span class="sv-rank">{index}</span>'
        f'<span class="sv-chip">{_escape(action.get("priority", "P1"))}</span>'
        f'<span class="sv-chip">{_escape(action.get("control_area", "Privacy control"))}</span>'
        f'<h3>{_escape(action.get("title", "Review action"))}</h3>'
        f'<p>{_escape(action.get("why", ""))}</p>'
        "</div>"
    )


def _action_row_html(index: int, action: Dict[str, Any]) -> str:
    priority = _escape(action.get("priority", "P1"))
    area = _escape(action.get("control_area", "Privacy control"))
    title = _escape(action.get("title", "Review action"))
    why = _escape(action.get("why", ""))
    return (
        '<div class="sv-action-row">'
        f'<span class="sv-rank">{index}</span>'
        f'<div><div class="sv-action-meta"><span class="sv-chip">{priority}</span><span class="sv-chip">{area}</span></div><h3>{title}</h3><p>{why}</p></div>'
        '<span class="sv-chip sv-pill-missing">Owner needed</span>'
        "</div>"
    )


def _score_ring(score: int, color: str) -> str:
    safe_score = max(0, min(int(score or 0), 100))
    return (
        f'<div class="sv-score-ring" style="--score:{safe_score};--ring-color:{_escape(color)}">'
        f'<div class="sv-score-ring-inner"><strong>{safe_score}</strong><span>score</span></div>'
        "</div>"
    )


def _gate_item(title: str, text: str, status: str, meta: str) -> str:
    dot = "fail" if status == "fail" else "warn" if status == "warn" else ""
    pill = _pill_tone("fail" if status == "fail" else "missing" if status == "warn" else "pass")
    return (
        '<div class="sv-gate-item">'
        f'<span class="sv-gate-dot {dot}"></span>'
        f'<div><div class="sv-gate-name">{_escape(title)}</div><p>{_escape(text)}</p></div>'
        f'<span class="sv-chip {pill}">{_escape(meta)}</span>'
        "</div>"
    )


def _signal_card(title: str, text: str, value: int, max_value: int, color: str) -> str:
    denominator = max(max_value, 1)
    width = max(4, min(int((value / denominator) * 100), 100))
    return (
        '<div class="sv-signal-card">'
        f'<h3>{_escape(title)}</h3>'
        f'<p>{_escape(text)}</p>'
        f'<div class="sv-progress"><span style="--value:{width}%;--bar-color:{_escape(color)}"></span></div>'
        "</div>"
    )


def _flow_overview_html(flows: List[Dict[str, Any]]) -> str:
    sources: List[str] = []
    categories: List[str] = []
    notices: Dict[str, int] = {}
    obligations: List[str] = []
    actions = 0
    for flow in flows:
        categories.append(str(flow.get("data_category", "Data")))
        status = str(flow.get("notice_status", "unknown")).replace("_", " ").title()
        notices[status] = notices.get(status, 0) + 1
        sources.extend(str(item) for item in (flow.get("collection_points") or flow.get("storage_points") or []))
        obligations.extend(str(item) for item in flow.get("dpdpa_obligations", []) or [])
        if flow.get("remediation"):
            actions += 1
    source_count = len(set(sources))
    source_values = sorted(set(sources))
    category_values = sorted(set(categories))
    obligation_values = sorted(set(obligations))
    notice_chips = "".join(
        f'<span class="sv-chip {_pill_tone(key)}">{_escape(key)}: {value}</span>'
        for key, value in sorted(notices.items())
    )
    return (
        '<div class="sv-flow-card">'
        '<div class="sv-label">Evidence flow map</div>'
        '<div class="sv-flow-stage">'
        f'<div class="sv-flow-box"><h3>Sources</h3><p>{source_count} source surfaces linked to personal-data evidence.</p><div class="sv-flow-list">{_chip_list(source_values, limit=4)}</div></div>'
        f'<div class="sv-flow-box"><h3>Data categories</h3><p>{len(set(categories))} categories detected across the scan.</p><div class="sv-flow-list">{_chip_list(category_values, limit=5)}</div></div>'
        f'<div class="sv-flow-box"><h3>Notice posture</h3><p>Coverage status by detected category.</p><div class="sv-flow-list">{notice_chips}</div></div>'
        f'<div class="sv-flow-box"><h3>DPDPA areas</h3><p>{len(set(obligations))} obligation areas connected to evidence.</p><div class="sv-flow-list">{_chip_list(obligation_values, limit=5)}</div></div>'
        f'<div class="sv-flow-box"><h3>Actions</h3><p>{actions} flows require owner review or remediation.</p><div class="sv-flow-list"><span class="sv-chip sv-pill-missing">Action required</span><span class="sv-chip">Owner workflow</span></div></div>'
        "</div>"
        "</div>"
    )


def _chip_list(values: List[str], limit: int = 6) -> str:
    if not values:
        return '<span class="sv-chip">None detected</span>'
    visible = values[:limit]
    chips = "".join(f'<span class="sv-chip">{_escape(value)}</span>' for value in visible)
    if len(values) > limit:
        chips += f'<span class="sv-chip">+{len(values) - limit} more</span>'
    return chips


def _render_evidence_table(st: Any, rows: List[Dict[str, Any]]) -> None:
    if not rows:
        st.info("No evidence matches the current filters.")
        return
    columns = ["Severity", "Finding", "Kind", "File", "Detail", "Recommendation", "Evidence ref"]
    header = "".join(f"<th>{_escape(column)}</th>" for column in columns)
    body = []
    for row in rows:
        severity = str(row.get("Severity", "LOW"))
        cells = []
        for column in columns:
            value = row.get(column, "")
            if column == "Severity":
                value = f'<span class="sv-chip {_pill_tone(severity)}">{_escape(severity)}</span>'
            else:
                value = _escape(value)
            cells.append(f"<td>{value}</td>")
        body.append(f"<tr>{''.join(cells)}</tr>")
    st.markdown(
        f'<div class="sv-table-wrap"><table class="sv-table"><thead><tr>{header}</tr></thead><tbody>{"".join(body)}</tbody></table></div>',
        unsafe_allow_html=True,
    )


def _render_simple_table(st: Any, rows: List[Dict[str, Any]], columns: List[str]) -> None:
    if not rows:
        st.info("No records to display.")
        return
    header = "".join(f"<th>{_escape(column)}</th>" for column in columns)
    body = []
    for row in rows:
        cells = []
        for column in columns:
            value = row.get(column, "")
            if value is None:
                value = ""
            if column.lower() in {"status", "severity", "notice"}:
                value = f'<span class="sv-chip {_pill_tone(str(value))}">{_escape(value)}</span>'
            else:
                value = _escape(value)
            cells.append(f"<td>{value}</td>")
        body.append(f"<tr>{''.join(cells)}</tr>")
    st.markdown(
        f'<div class="sv-table-wrap"><table class="sv-table"><thead><tr>{header}</tr></thead><tbody>{"".join(body)}</tbody></table></div>',
        unsafe_allow_html=True,
    )


def _chunks(items: List[Any], size: int) -> Iterable[List[Any]]:
    for index in range(0, len(items), size):
        yield items[index : index + size]


def _plot_config() -> Dict[str, Any]:
    return {"displayModeBar": False, "responsive": True}


def _palette(index: int) -> str:
    colors = [
        "#0f766e",
        "#2563eb",
        "#7c3aed",
        "#b42318",
        "#b7791f",
        "#177245",
        "#475467",
        "#0b3b5a",
    ]
    return colors[index % len(colors)]


def _metric_tone(value: str) -> str:
    normalized = value.lower().replace("_", " ")
    if normalized in {"critical", "high", "fail", "not ready"}:
        return "sv-metric-critical"
    if normalized in {"missing", "medium", "needs action", "partial"}:
        return "sv-metric-missing"
    if normalized in {"low", "pass", "ready", "ok"}:
        return "sv-metric-pass"
    return "sv-metric"


def _pill_tone(value: str) -> str:
    normalized = value.lower().replace("_", " ")
    if normalized in {"critical", "high", "fail", "failed", "not ready"}:
        return "sv-pill-critical"
    if normalized in {"missing", "medium", "needs action", "partial", "review"}:
        return "sv-pill-missing"
    if normalized in {"low", "pass", "ready", "ok"}:
        return "sv-pill-pass"
    return ""


def _status_color(value: str) -> str:
    normalized = value.lower().replace("_", " ")
    if normalized in {"verified", "pass", "ready"}:
        return "#177245"
    if normalized in {"failing", "fail", "critical", "high"}:
        return "#b42318"
    if normalized in {"inferred", "unknown", "missing", "partial", "needs action"}:
        return "#b7791f"
    return "#087672"


def _format_dt(value: str) -> str:
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone().strftime("%d %b %Y, %H:%M")
    except ValueError:
        return value


def _escape(value: Any) -> str:
    return (
        str(value)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


if __name__ == "__main__":
    main()
