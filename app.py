"""
Svikruti.ai - DPDPA Compliance Automation Platform

A comprehensive, offline, rule-based compliance tool for automating
Digital Personal Data Protection Act (DPDPA) compliance in India.

Multi-user, multi-tenant version with authentication and RBAC.
Built with Streamlit and SQLite - no external APIs or dependencies.
Open source and free to use.
"""

import streamlit as st
from datetime import datetime, timedelta
import html
import json
from pathlib import Path
import os
import plotly.graph_objects as go

# Import local modules with graceful fallback
try:
    import config
except ImportError:
    st.error("Missing config.py module")
    st.stop()

try:
    from database import Database
except ImportError:
    st.error("Missing database.py module")
    st.stop()

try:
    from knowledge_base import (
        search_knowledge,
        DPDPA_SECTIONS,
        KEY_DEFINITIONS,
        COMPLIANCE_CHECKLIST,
        FAQ,
        PENALTY_MATRIX,
        SECTOR_GUIDANCE,
        TIMELINE,
        get_compliance_score_interpretation
    )
except ImportError:
    st.error("Missing knowledge_base.py module")
    st.stop()

try:
    from doc_generator import DocumentGenerator
    DOC_GENERATOR_AVAILABLE = True
except (ImportError, Exception):
    DOC_GENERATOR_AVAILABLE = False

try:
    from new_pages import (
        page_ropa,
        page_consent_manager,
        page_privacy_notices,
        page_rights_requests,
        page_vendor_management
    )
    NEW_PAGES_AVAILABLE = True
except (ImportError, Exception):
    NEW_PAGES_AVAILABLE = False

try:
    from ai_pages import (
        page_ai_chatbot,
        page_smart_doc_drafter,
        page_gap_assessment_advisor,
        page_breach_classifier,
        page_privacy_notice_reviewer,
        page_ai_settings
    )
    from ai_engine import init_ai_tables
    AI_PAGES_AVAILABLE = True
except (ImportError, Exception):
    AI_PAGES_AVAILABLE = False

# ==================== PAGE CONFIG ====================
st.set_page_config(
    page_title="Svikruti.ai - DPDPA Compliance",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ==================== CUSTOM STYLING ====================
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap');

* {
    font-family: 'Inter', sans-serif;
}

html, body, [class*="css"] {
    font-family: 'Inter', sans-serif;
    background: #0A0F1E;
    color: #E2E8F0;
}

/* Main container */
.main {
    background: #0A0F1E;
}

/* Remove Streamlit branding */
#MainMenu { visibility: hidden; }
footer { visibility: hidden; }
.stDeployButton { display: none; }

/* Metric cards with glass-morphism */
[data-testid="metric-container"] {
    background: rgba(17, 24, 39, 0.8);
    backdrop-filter: blur(12px);
    border: 1px solid rgba(30, 41, 59, 0.5);
    border-radius: 16px;
    padding: 20px;
    border-left: 4px solid #14B8A6;
    box-shadow: 0 8px 32px rgba(0, 0, 0, 0.2);
}

/* Sidebar styling */
[data-testid="stSidebar"] {
    background: #060A14;
    border-right: 1px solid rgba(30, 41, 59, 0.5);
}

/* Tabs */
.stTabs [data-baseweb="tab-list"] {
    gap: 8px;
    border-bottom: 1px solid rgba(30, 41, 59, 0.5);
}

.stTabs [data-baseweb="tab"] {
    background: transparent;
    border-radius: 12px 12px 0 0;
    padding: 12px 20px;
    color: #94A3B8;
    font-weight: 500;
    border: none;
}

.stTabs [aria-selected="true"] {
    background: rgba(20, 184, 166, 0.1) !important;
    color: #14B8A6 !important;
    border-bottom: 2px solid #14B8A6 !important;
}

/* Expander */
.streamlit-expanderHeader {
    background: rgba(17, 24, 39, 0.8);
    border-radius: 12px;
    border: 1px solid rgba(30, 41, 59, 0.5);
    color: #E2E8F0;
}

.streamlit-expanderHeader:hover {
    background: rgba(20, 184, 166, 0.1);
}

/* Buttons */
.stButton > button {
    border-radius: 12px;
    font-weight: 600;
    font-size: 14px;
    padding: 10px 24px;
    transition: all 0.3s ease;
    border: none;
}

.stButton > button[kind="primary"] {
    background: linear-gradient(135deg, #14B8A6, #06B6D4);
    color: #0A0F1E;
}

.stButton > button[kind="primary"]:hover {
    box-shadow: 0 8px 24px rgba(20, 184, 166, 0.3);
    transform: translateY(-2px);
}

.stButton > button[kind="secondary"] {
    background: transparent;
    border: 1px solid #14B8A6;
    color: #14B8A6;
}

.stButton > button[kind="secondary"]:hover {
    background: rgba(20, 184, 166, 0.1);
}

/* Cards */
.card {
    background: rgba(17, 24, 39, 0.8);
    backdrop-filter: blur(12px);
    border: 1px solid rgba(30, 41, 59, 0.5);
    border-radius: 16px;
    padding: 24px;
    margin-bottom: 16px;
    box-shadow: 0 8px 32px rgba(0, 0, 0, 0.2);
}

.card-header {
    color: #14B8A6;
    font-size: 18px;
    font-weight: 700;
    margin-bottom: 16px;
}

.card-body {
    color: #CBD5E1;
    font-size: 14px;
    line-height: 1.6;
}

/* Text inputs and forms */
.stTextInput > div > div > input,
.stTextArea > div > div > textarea,
.stSelectbox > div > div > select,
.stNumberInput > div > div > input {
    background: #0F172A !important;
    border: 1px solid rgba(30, 41, 59, 0.8) !important;
    color: #E2E8F0 !important;
    border-radius: 12px !important;
    font-size: 14px !important;
    padding: 12px 16px !important;
}

.stTextInput > div > div > input:focus,
.stTextArea > div > div > textarea:focus,
.stSelectbox > div > div > select:focus,
.stNumberInput > div > div > input:focus {
    border: 2px solid #14B8A6 !important;
    box-shadow: 0 0 0 2px rgba(20, 184, 166, 0.3) !important;
}

/* Radio buttons */
.stRadio > div > label {
    color: #E2E8F0;
}

.stRadio > div > div {
    margin: 8px 0;
}

/* Progress bars */
.stProgress > div > div > div > div {
    background: linear-gradient(90deg, #14B8A6, #06B6D4);
    border-radius: 12px;
}

/* Dividers */
hr {
    border-color: rgba(30, 41, 59, 0.5);
}

/* Titles and headings */
h1, h2, h3, h4, h5, h6 {
    color: #E2E8F0;
    font-weight: 600;
}

h1 {
    font-size: 32px;
    font-weight: 700;
    margin-bottom: 24px;
    margin-top: 0;
}

/* Info/Warning/Error boxes */
.stAlert {
    border-radius: 12px;
    background: rgba(17, 24, 39, 0.8) !important;
    border: 1px solid rgba(30, 41, 59, 0.5) !important;
}

/* Caption text */
.stCaption {
    color: #94A3B8;
}

/* Dataframe styling */
[role="grid"] {
    background: rgba(17, 24, 39, 0.8) !important;
    border-radius: 12px;
    border: 1px solid rgba(30, 41, 59, 0.5) !important;
}

/* Container styles */
.stContainer {
    background: transparent;
}

/* Columns and layouts */
[data-testid="column"] {
    background: transparent;
}

/* Animations */
@keyframes fadeIn {
    from {
        opacity: 0;
        transform: translateY(8px);
    }
    to {
        opacity: 1;
        transform: translateY(0);
    }
}

.main {
    animation: fadeIn 0.4s ease-out;
}

/* Scrollbar */
::-webkit-scrollbar {
    width: 8px;
    height: 8px;
}

::-webkit-scrollbar-track {
    background: transparent;
}

::-webkit-scrollbar-thumb {
    background: rgba(20, 184, 166, 0.3);
    border-radius: 4px;
}

::-webkit-scrollbar-thumb:hover {
    background: rgba(20, 184, 166, 0.5);
}

/* Form styling */
.stForm {
    background: transparent;
    border: none;
}

/* Footer */
.footer {
    text-align: center;
    padding: 32px 0;
    color: #64748B;
    border-top: 1px solid rgba(30, 41, 59, 0.5);
    margin-top: 64px;
    font-size: 12px;
    font-weight: 400;
}

/* Login page specific */
.login-hero {
    background: linear-gradient(135deg, rgba(20, 184, 166, 0.1), rgba(6, 182, 212, 0.1));
    border-radius: 20px;
    padding: 48px;
    text-align: center;
    margin-bottom: 32px;
    border: 1px solid rgba(30, 41, 59, 0.5);
}

.login-logo {
    font-size: 48px;
    font-weight: 700;
    background: linear-gradient(135deg, #14B8A6, #06B6D4);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
    margin-bottom: 12px;
}

.login-tagline {
    color: #94A3B8;
    font-size: 14px;
    margin-bottom: 8px;
}

.login-subtitle {
    color: #CBD5E1;
    font-size: 16px;
}
</style>
""", unsafe_allow_html=True)

# ==================== SESSION STATE INITIALIZATION ====================
def init_session_state():
    """Initialize all required session state variables"""
    if "db" not in st.session_state:
        st.session_state.db = Database()

    # Initialize AI tables if AI module available
    if AI_PAGES_AVAILABLE:
        try:
            conn = st.session_state.db.get_connection()
            init_ai_tables(conn)
            conn.close()
        except Exception:
            pass

    # Authentication states
    if "authenticated" not in st.session_state:
        st.session_state.authenticated = False

    if "user_id" not in st.session_state:
        st.session_state.user_id = None

    if "org_id" not in st.session_state:
        st.session_state.org_id = None

    if "user_info" not in st.session_state:
        st.session_state.user_info = None

    if "page" not in st.session_state:
        st.session_state.page = "Dashboard"

    if "doc_generator" not in st.session_state:
        if DOC_GENERATOR_AVAILABLE:
            st.session_state.doc_generator = DocumentGenerator()
        else:
            st.session_state.doc_generator = None

init_session_state()

# ==================== UTILITY FUNCTIONS ====================
# NOTE: password hashing lives in database.Database._hash_password (salted
# PBKDF2-HMAC-SHA256, 100k iterations). Do not add ad-hoc hashing here.

def format_date(date_str):
    """Format date string for display"""
    try:
        return datetime.fromisoformat(date_str).strftime("%B %d, %Y")
    except:
        return date_str

def days_until_deadline(deadline_date):
    """Calculate days until deadline"""
    try:
        deadline = datetime.fromisoformat(deadline_date) if isinstance(deadline_date, str) else deadline_date
        return (deadline - datetime.now()).days
    except:
        return -1

def get_severity_color(severity):
    """Get color based on severity level"""
    colors = {
        "CRITICAL": "#E63946",
        "HIGH": "#FF9F1C",
        "MEDIUM": "#FFB703",
        "LOW": "#2EC4B6"
    }
    return colors.get(severity, "#94A3B8")

def get_status_icon(status):
    """Get icon based on status"""
    icons = {
        "PENDING": "⏳",
        "IN_PROGRESS": "🔄",
        "COMPLETED": "✅",
        "OPEN": "🔴",
        "CLOSED": "🟢",
        "DETECTED": "⚠️",
        "CONTAINED": "🔒",
        "NOTIFIED_BOARD": "📢",
        "NOTIFIED_PRINCIPALS": "📧",
        "RESOLVED": "✅"
    }
    return icons.get(status, "•")

def get_role_badge(role):
    """Get badge display for user role"""
    badges = {
        "admin": "👑",
        "member": "👤",
        "viewer": "👁️"
    }
    return f"{badges.get(role, '•')} {role.capitalize()}"

# ==================== LOGIN & SIGNUP PAGES ====================
def render_login_page():
    """Render login and signup pages"""
    col1, col2, col3 = st.columns([1, 2, 1])

    with col2:
        st.markdown("""
        <div class="login-hero">
            <div class="login-logo">Svikruti.ai</div>
            <div class="login-tagline">India's AI-powered DPDPA compliance platform</div>
            <div class="login-subtitle">Automate compliance. Reduce risk. Stay compliant.</div>
        </div>
        """, unsafe_allow_html=True)

        tab1, tab2 = st.tabs(["Login", "Sign Up"])

        with tab1:
            st.markdown("### Welcome Back")

            with st.form("login_form", clear_on_submit=True):
                email = st.text_input("Email Address", placeholder="you@example.com")
                password = st.text_input("Password", type="password", placeholder="••••••••")
                submit = st.form_submit_button("Sign In", use_container_width=True, type="primary")

                if submit:
                    if not email or not password:
                        st.error("Please enter both email and password")
                    else:
                        user = st.session_state.db.authenticate_user(email, password)

                        if user:
                            st.session_state.authenticated = True
                            st.session_state.user_id = user['id']
                            st.session_state.org_id = user['org_id']
                            st.session_state.user_info = {
                                "id": user['id'],
                                "email": user['email'],
                                "full_name": user['full_name'],
                                "role": user['role'],
                                "org_id": user['org_id']
                            }
                            st.session_state.page = "Dashboard"
                            st.session_state.db.update_last_login(user['id'])
                            st.success("Welcome back!")
                            st.rerun()
                        else:
                            st.error("Invalid credentials or account temporarily locked. Please try again later.")

        with tab2:
            st.markdown("### Create Account")

            with st.form("signup_form", clear_on_submit=True):
                full_name = st.text_input("Full Name", placeholder="John Doe")
                email = st.text_input("Email Address", placeholder="you@example.com")
                invite_code = st.text_input(
                    "Invite Code (optional)",
                    placeholder="Paste an invite code to join an existing organization"
                )
                st.caption("Leave organization details below empty if you are joining with an invite code.")
                org_name = st.text_input("Organization Name", placeholder="Acme Corp")
                industry = st.selectbox("Industry", config.INDUSTRY_TYPES)

                org_size = st.selectbox("Organization Size", config.ORG_SIZES)
                password = st.text_input("Password", type="password", placeholder="Min 8 characters")
                confirm_password = st.text_input("Confirm Password", type="password", placeholder="Confirm password")

                submit = st.form_submit_button("Create Account", use_container_width=True, type="primary")

                if submit:
                    invite_code = (invite_code or "").strip()
                    if not all([full_name, email, password, confirm_password]):
                        st.error("Please fill in all fields")
                    elif not invite_code and not org_name:
                        st.error("Please enter an organization name (or provide an invite code)")
                    elif len(password) < 8:
                        st.error("Password must be at least 8 characters")
                    elif password != confirm_password:
                        st.error("Passwords do not match")
                    else:
                        conn = st.session_state.db.get_connection()
                        cursor = conn.cursor()
                        cursor.execute("SELECT id FROM users WHERE email = ?", (email,))
                        existing_user = cursor.fetchone()
                        conn.close()

                        if existing_user:
                            st.error("Email already registered. Please login instead.")
                        elif invite_code:
                            # Join an existing organization via invite
                            invite = st.session_state.db.get_invite_by_token(invite_code)
                            if not invite:
                                st.error("Invalid, expired, or already-used invite code.")
                            elif invite["email"].strip().lower() != email.strip().lower():
                                st.error("This invite code was issued for a different email address.")
                            else:
                                try:
                                    user_id = st.session_state.db.create_user(
                                        email=email,
                                        password=password,
                                        full_name=full_name,
                                        role=invite["role"],
                                        org_id=invite["org_id"]
                                    )
                                    st.session_state.db.accept_invite(invite_code, user_id)

                                    st.session_state.authenticated = True
                                    st.session_state.user_id = user_id
                                    st.session_state.org_id = invite["org_id"]
                                    st.session_state.user_info = {
                                        "id": user_id,
                                        "email": email,
                                        "full_name": full_name,
                                        "role": invite["role"],
                                        "org_id": invite["org_id"]
                                    }
                                    st.session_state.page = "Dashboard"
                                    st.success("Account created — you have joined your organization!")
                                    st.rerun()
                                except Exception as e:
                                    st.error(f"Error creating account: {str(e)}")
                        else:
                            try:
                                org_id = st.session_state.db.create_organization(
                                    name=org_name,
                                    created_by=0,
                                    industry=industry,
                                    size=org_size,
                                    sdf_status="Not Determined",
                                    compliance_level="Getting Started"
                                )

                                user_id = st.session_state.db.create_user(
                                    email=email,
                                    password=password,
                                    full_name=full_name,
                                    role="admin",
                                    org_id=org_id
                                )

                                st.session_state.db.update_organization(org_id, created_by=user_id)

                                st.session_state.authenticated = True
                                st.session_state.user_id = user_id
                                st.session_state.org_id = org_id
                                st.session_state.user_info = {
                                    "id": user_id,
                                    "email": email,
                                    "full_name": full_name,
                                    "role": "admin",
                                    "org_id": org_id
                                }
                                st.session_state.page = "Dashboard"
                                st.success("Account created successfully!")
                                st.rerun()
                            except Exception as e:
                                st.error(f"Error creating account: {str(e)}")

# ==================== NAVIGATION & SIDEBAR ====================
def render_sidebar():
    """Render the main navigation sidebar for authenticated users"""
    if not st.session_state.authenticated:
        return

    with st.sidebar:
        st.markdown("""
        <div style="text-align: center; padding: 20px 0; margin-bottom: 24px;">
            <div style="font-size: 24px; font-weight: 700; background: linear-gradient(135deg, #14B8A6, #06B6D4); -webkit-background-clip: text; -webkit-text-fill-color: transparent; margin-bottom: 8px;">
                Svikruti.ai
            </div>
            <div style="color: #94A3B8; font-size: 12px; font-weight: 500;">
                DPDPA Compliance Platform
            </div>
        </div>
        """, unsafe_allow_html=True)

        st.markdown("---")

        user = st.session_state.user_info
        org = st.session_state.db.get_organization(st.session_state.org_id)

        st.markdown(f"""
        <div style="background: rgba(17, 24, 39, 0.8); padding: 16px; border-radius: 12px; border: 1px solid rgba(30, 41, 59, 0.5); margin-bottom: 24px;">
            <div style="color: #14B8A6; font-weight: 600; margin-bottom: 8px; font-size: 14px;">{html.escape(str(user['full_name']))}</div>
            <div style="color: #94A3B8; font-size: 13px; margin-bottom: 8px;">{html.escape(str(org['name']))}</div>
            <div style="color: #64748B; font-size: 12px;">{get_role_badge(user['role'])}</div>
        </div>
        """, unsafe_allow_html=True)

        st.markdown("---")

        nav_sections = {
            "OVERVIEW": [
                ("📊 Dashboard", "Dashboard"),
            ],
            "COMPLIANCE": [
                ("🔍 Gap Assessment", "Gap Assessment"),
                ("📋 RoPA Registry", "RoPA Registry"),
                ("🤝 Consent Manager", "Consent Manager"),
                ("📝 Privacy Notices", "Privacy Notices"),
            ],
            "OPERATIONS": [
                ("👤 Rights Requests", "Rights Requests"),
                ("🏢 Vendor Management", "Vendor Management"),
                ("📄 Document Generator", "Document Generator"),
            ],
            "MONITORING": [
                ("✅ Compliance Tracker", "Compliance Tracker"),
                ("⚠️ Breach Response", "Breach Response"),
            ],
            "REFERENCE": [
                ("📚 Knowledge Base", "Knowledge Base"),
            ],
        }

        if AI_PAGES_AVAILABLE:
            nav_sections["AI TOOLS"] = [
                ("🤖 AI Assistant", "AI Assistant"),
                ("✨ AI Doc Drafter", "AI Doc Drafter"),
                ("🎯 AI Compliance Advisor", "AI Compliance Advisor"),
                ("🚨 AI Breach Analyzer", "AI Breach Analyzer"),
                ("📝 AI Notice Reviewer", "AI Notice Reviewer"),
            ]

        if user['role'] == "admin":
            nav_sections["ADMIN"] = [
                ("⚙️ Settings", "Settings"),
                ("🔧 AI Configuration", "AI Configuration"),
            ]

        for section_name, pages in nav_sections.items():
            if section_name == "AI TOOLS" and not AI_PAGES_AVAILABLE:
                continue
            if section_name == "ADMIN" and user['role'] != "admin":
                continue

            st.markdown(f'<p style="color: #64748B; font-size: 11px; font-weight: 600; margin: 16px 0 8px 0; text-transform: uppercase;">{section_name}</p>', unsafe_allow_html=True)

            for label, page_name in pages:
                btn_type = "primary" if st.session_state.page == page_name else "secondary"
                if st.button(label, key=f"nav_{page_name}", use_container_width=True, type=btn_type):
                    st.session_state.page = page_name

        st.markdown("---")

        if user['role'] == "admin":
            with st.expander("👥 Team Management", expanded=False):
                conn = st.session_state.db.get_connection()
                cursor = conn.cursor()
                cursor.execute("SELECT id, email, full_name, role FROM users WHERE org_id = ? ORDER BY full_name",
                             (st.session_state.org_id,))
                members = cursor.fetchall()
                conn.close()

                st.write(f"**Members ({len(members)})**")
                for member in members:
                    col1, col2 = st.columns([2, 1])
                    with col1:
                        st.write(f"{member['full_name']}")
                    with col2:
                        st.caption(member['role'])

                st.divider()

                st.write("**Invite New User**")
                invite_email = st.text_input("Email to invite", key="invite_email_input")
                invite_role = st.selectbox("Role", ["member", "viewer"], key="invite_role")

                if st.button("Generate Invite Code", use_container_width=True):
                    if not invite_email or "@" not in invite_email:
                        st.error("Enter a valid email address")
                    else:
                        conn = st.session_state.db.get_connection()
                        cursor = conn.cursor()
                        cursor.execute("SELECT id FROM users WHERE email = ?",
                                     (invite_email,))
                        existing = cursor.fetchone()
                        conn.close()

                        if existing:
                            st.error("A user with this email already exists")
                        else:
                            limits = st.session_state.db.check_org_limits(st.session_state.org_id)
                            if limits["users_remaining"] <= 0:
                                st.error("User limit reached for your organization")
                            else:
                                try:
                                    token = st.session_state.db.create_invite(
                                        st.session_state.org_id,
                                        invite_email.strip(),
                                        invite_role
                                    )
                                    st.session_state["last_invite"] = {
                                        "email": invite_email.strip(),
                                        "token": token,
                                    }
                                except Exception as e:
                                    st.error(f"Could not create invite: {str(e)}")

                if st.session_state.get("last_invite"):
                    last = st.session_state["last_invite"]
                    st.success(f"Invite created for {last['email']} (valid 7 days)")
                    st.code(last["token"], language=None)
                    st.caption(
                        "Copy this invite code and share it with the invitee. "
                        "They should paste it into the 'Invite Code' field on the Sign Up form. "
                        "No email is sent — this app is local-first."
                    )

                st.divider()

                st.write("**Pending Invites**")
                pending_invites = st.session_state.db.get_pending_invites(st.session_state.org_id)
                if pending_invites:
                    for inv in pending_invites:
                        col1, col2 = st.columns([2, 1])
                        with col1:
                            st.write(inv["email"])
                            st.caption(f"{inv['role']} | {inv['status']} | expires {str(inv['expires_at'])[:10]}")
                        with col2:
                            if st.button("Revoke", key=f"revoke_invite_{inv['id']}", use_container_width=True):
                                st.session_state.db.revoke_invite(st.session_state.org_id, inv["id"])
                                if st.session_state.get("last_invite", {}).get("token") == inv.get("token"):
                                    st.session_state.pop("last_invite", None)
                                st.rerun()
                else:
                    st.caption("No pending invites")

        st.markdown("---")

        if st.button("🚪 Logout", use_container_width=True, type="secondary"):
            st.session_state.authenticated = False
            st.session_state.user_id = None
            st.session_state.org_id = None
            st.session_state.user_info = None
            st.session_state.page = "Dashboard"
            st.success("Logged out successfully!")
            st.rerun()

# ==================== PAGE: DASHBOARD ====================
def page_dashboard():
    """Dashboard page - overview of compliance status"""
    if not st.session_state.org_id:
        st.warning("Please log in to access the dashboard.")
        return

    st.title(f"Welcome, {st.session_state.user_info['full_name']}")

    org_id = st.session_state.org_id
    stats = st.session_state.db.get_dashboard_stats(org_id)
    org = st.session_state.db.get_organization(org_id) or {}
    latest_assessment = st.session_state.db.get_latest_assessment(org_id)

    # Metric cards
    col1, col2, col3, col4 = st.columns(4)

    with col1:
        if latest_assessment:
            score = round(latest_assessment.get("overall_score", 0), 1)
            st.metric("Compliance Score", f"{score}%", "out of 100")
        else:
            st.metric("Compliance Score", "—", "Not assessed")

    with col2:
        pending_tasks = stats.get("pending_tasks", 0)
        st.metric("Pending Tasks", pending_tasks, "to complete")

    with col3:
        open_breaches = stats.get("open_breaches", 0)
        st.metric("Open Breaches", open_breaches, "incidents")

    with col4:
        docs = stats.get("total_documents", 0)
        st.metric("Documents", docs, "generated")

    st.markdown("---")

    # Compliance visualization
    col1, col2 = st.columns(2)

    with col1:
        st.markdown("### Compliance Score")
        if latest_assessment:
            score = latest_assessment.get("overall_score", 0)
            fig = go.Figure(data=[go.Indicator(
                mode="gauge+number+delta",
                value=score,
                domain={'x': [0, 1], 'y': [0, 1]},
                title={'text': "Overall Score"},
                gauge={
                    'axis': {'range': [0, 100]},
                    'bar': {'color': "#14B8A6"},
                    'steps': [
                        {'range': [0, 50], 'color': "rgba(230, 57, 70, 0.2)"},
                        {'range': [50, 75], 'color': "rgba(255, 159, 28, 0.2)"},
                        {'range': [75, 100], 'color': "rgba(46, 196, 182, 0.2)"}
                    ],
                    'threshold': {
                        'line': {'color': "#06B6D4", 'width': 2},
                        'thickness': 0.75,
                        'value': 75
                    }
                }
            )])
            fig.update_layout(
                paper_bgcolor="rgba(10, 15, 30, 0)",
                font=dict(color="#E2E8F0", family="Inter"),
                height=300
            )
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("Complete a gap assessment to see your compliance score.")

    with col2:
        st.markdown("### Category Breakdown")
        if latest_assessment and latest_assessment.get("category_scores"):
            category_scores = latest_assessment["category_scores"]
            categories = list(category_scores.keys())
            scores = list(category_scores.values())

            fig = go.Figure(data=[go.Scatterpolar(
                r=scores,
                theta=categories,
                fill='toself',
                line=dict(color='#14B8A6'),
                fillcolor='rgba(20, 184, 166, 0.3)',
                name='Score'
            )])
            fig.update_layout(
                polar=dict(
                    bgcolor="rgba(15, 23, 42, 0.5)",
                    radialaxis=dict(
                        visible=True,
                        range=[0, 100],
                        tickfont=dict(color="#94A3B8"),
                        gridcolor="rgba(30, 41, 59, 0.5)"
                    ),
                    angularaxis=dict(
                        tickfont=dict(color="#E2E8F0")
                    )
                ),
                paper_bgcolor="rgba(10, 15, 30, 0)",
                font=dict(color="#E2E8F0", family="Inter"),
                height=300,
                showlegend=False
            )
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("Your category scores will appear here after assessment.")

    st.markdown("---")

    # Deadlines and status
    col1, col2 = st.columns(2)

    with col1:
        st.markdown("### Upcoming Deadlines")
        next_deadline = config.get_next_deadline()

        if next_deadline:
            days = next_deadline["days"]
            deadline_color = "#E63946" if days < 30 else "#FF9F1C" if days < 90 else "#2EC4B6"

            st.markdown(f"""
            <div class="card" style="border-left: 4px solid {deadline_color};">
                <div style="font-weight: 600; color: #14B8A6; margin-bottom: 8px;">{next_deadline['name']}</div>
                <div style="color: #CBD5E1; margin-bottom: 12px;">{next_deadline['date'].strftime('%B %d, %Y')}</div>
                <div style="font-size: 24px; font-weight: 700; color: {deadline_color};">{days} days</div>
            </div>
            """, unsafe_allow_html=True)

            st.write("**All Deadlines**")
            for name, deadline in config.COMPLIANCE_DEADLINES.items():
                days = (deadline["date"] - datetime.now()).days
                status_icon = "🔴" if days < 0 else "🟡" if days < 30 else "🟢"
                st.write(f"{status_icon} **{name}:** {deadline['date'].strftime('%B %d')} ({days} days)")

    with col2:
        st.markdown("### Module Status")
        modules = {
            "Gap Assessment": latest_assessment is not None,
            "Documents": stats.get("total_documents", 0) > 0,
            "Tasks Created": len(st.session_state.db.get_tasks(org_id)) > 0,
            "Breach Plan": True,
            "Activity Log": len(st.session_state.db.get_activity_log(org_id, limit=1)) > 0,
        }

        for module, completed in modules.items():
            status = "✅" if completed else "⏳"
            st.write(f"{status} {module}")

    st.markdown("---")

    # Activity
    col1, col2 = st.columns(2)

    with col1:
        st.markdown("### Recent Activity")
        activities = st.session_state.db.get_activity_log(org_id, limit=8)

        if activities:
            for activity in activities:
                timestamp = datetime.fromisoformat(activity["created_at"])
                time_str = timestamp.strftime("%b %d, %H:%M")
                st.write(f"**{activity['action_type']}** — {time_str}")
                st.caption(activity["description"])
        else:
            st.info("No activity yet")

    with col2:
        st.markdown("### Key Information")
        st.write(f"**Organization:** {org.get('name', '—')}")
        st.write(f"**Industry:** {org.get('industry', '—')}")
        st.write(f"**Size:** {org.get('size', '—')}")
        if latest_assessment and latest_assessment.get('assessment_date'):
            st.write(f"**Last Assessment:** {str(latest_assessment['assessment_date'])[:10]}")
        st.write(f"**SDF Status:** {org.get('sdf_status', '—')}")

# ==================== PAGE: GAP ASSESSMENT ====================
def page_gap_assessment():
    """Gap Assessment page - FULLY DYNAMIC"""
    if not st.session_state.org_id:
        st.warning("Please log in to access this page.")
        return

    st.title("Gap Assessment")

    org_id = st.session_state.org_id

    tabs = st.tabs(["Assessment", "Results", "History"])

    with tabs[0]:
        st.markdown("""
        Evaluate your organization's compliance with DPDPA requirements.
        Answer questions across different compliance categories to identify gaps.
        """)

        category_tabs = st.tabs(list(config.GAP_ASSESSMENT_QUESTIONS.keys()))

        for idx, (category, questions) in enumerate(config.GAP_ASSESSMENT_QUESTIONS.items()):
            with category_tabs[idx]:
                st.markdown(f"_{config.COMPLIANCE_CATEGORIES[category]['description']}_")
                st.markdown("---")

                for question in questions:
                    col1, col2 = st.columns([3, 1])

                    with col1:
                        st.write(f"**{question['question']}**")
                        st.caption(f"💡 {question['hint']}")

                    with col2:
                        response = st.radio(
                            "Response",
                            question["options"],
                            key=f"q_{question['id']}",
                            label_visibility="collapsed",
                            horizontal=False
                        )

                        st.session_state.db.save_assessment_response(
                            org_id,
                            category,
                            question["id"],
                            response
                        )

                    st.markdown("---")

        if st.button("Calculate Score", use_container_width=True, type="primary"):
            scores = st.session_state.db.save_assessment(org_id)
            st.success("Assessment completed!")
            st.balloons()

    with tabs[1]:
        st.subheader("Assessment Results")
        latest = st.session_state.db.get_latest_assessment(org_id)

        if latest:
            overall_score = latest['overall_score']
            st.metric("Overall Score", f"{overall_score:.1f}%")

            interpretation = get_compliance_score_interpretation(overall_score)
            st.info(f"**Interpretation:** {interpretation}")

            st.write("**Category Scores:**")
            cat_scores = latest["category_scores"]

            for cat, score in sorted(cat_scores.items(), key=lambda x: x[1], reverse=True):
                col1, col2 = st.columns([3, 1])
                with col1:
                    st.progress(score / 100)
                with col2:
                    st.write(f"**{score:.1f}%**")
                st.caption(cat)

            st.subheader("Recommendations")
            low_scoring = {cat: score for cat, score in cat_scores.items() if score < 50}

            if low_scoring:
                st.warning("Focus Areas (Below 50%):")
                for cat, score in low_scoring.items():
                    st.write(f"- **{cat}** ({score:.1f}%) - Needs attention")
            else:
                st.success("All areas have good coverage!")

        else:
            st.info("No assessment results yet. Complete the assessment above.")

    with tabs[2]:
        st.subheader("Assessment History")
        conn = st.session_state.db.get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT * FROM assessments WHERE org_id = ?
            ORDER BY assessment_date DESC LIMIT 10
        """, (org_id,))
        assessments = cursor.fetchall()
        conn.close()

        if assessments:
            for assessment in assessments:
                col1, col2, col3 = st.columns(3)
                with col1:
                    st.write(f"**Score:** {assessment['overall_score']:.1f}%")
                with col2:
                    st.write(f"**Date:** {assessment['assessment_date'][:10]}")
                with col3:
                    st.write(f"**ID:** #{assessment['id']}")
                st.divider()
        else:
            st.info("No assessments yet.")

# ==================== PAGE: DOCUMENT GENERATOR ====================
def page_document_generator():
    """Document Generator page"""
    if not st.session_state.org_id:
        st.warning("Please log in to access this page.")
        return

    st.title("Document Generator")

    if not DOC_GENERATOR_AVAILABLE:
        st.error("Document generation requires `python-docx`. Install it with:")
        st.code("pip install python-docx", language="bash")
        return

    org_id = st.session_state.org_id
    org = st.session_state.db.get_organization(org_id)

    st.markdown("""
    Generate DPDPA-compliant documents tailored to your organization.
    All documents are templates that you can customize.
    """)

    col1, col2 = st.columns(2)

    with col1:
        st.subheader("Generate Document")

        doc_type = st.selectbox(
            "Select Document Type",
            options=[
                "Privacy Policy",
                "Consent Notice",
                "Data Processing Agreement",
                "Privacy Impact Assessment",
                "Breach Notification",
                "Record of Processing Activities",
                "Grievance Redressal Policy"
            ]
        )

        with st.expander("Document Details", expanded=True):
            if doc_type == "Privacy Policy":
                data_categories = st.multiselect(
                    "Data Categories",
                    options=[
                        "Name and Contact",
                        "Financial",
                        "Health",
                        "Biometric",
                        "Location",
                        "Online Activity",
                        "Device"
                    ],
                    default=["Name and Contact"]
                )
                purposes = st.multiselect(
                    "Processing Purposes",
                    options=["Service Delivery", "Support", "Marketing", "Compliance", "Risk", "Analytics"],
                    default=["Service Delivery"]
                )
                retention_period = st.text_input("Retention Period", value="3 years")
                contact_email = st.text_input("Contact Email", value=org.get("name", "contact@example.com"))
                dpo_name = st.text_input("DPO Name", value="DPO")

                if st.button("Generate Policy", type="primary", use_container_width=True):
                    try:
                        filepath = st.session_state.doc_generator.generate_privacy_policy(
                            org_name=org["name"],
                            industry=org["industry"],
                            data_categories=data_categories,
                            purposes=purposes,
                            retention_period=retention_period,
                            contact_email=contact_email,
                            dpo_name=dpo_name
                        )

                        with open(filepath, "rb") as f:
                            doc_bytes = f.read()

                        st.session_state.db.create_document(org_id, "privacy_policy", "Privacy Policy", filepath)

                        st.download_button(
                            label="Download Policy",
                            data=doc_bytes,
                            file_name="Privacy_Policy.docx",
                            mime="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                            use_container_width=True
                        )
                        st.success("Generated!")
                        st.session_state.db.log_activity(org_id, "DOCUMENT_GENERATED", "Privacy Policy created")

                    except Exception as e:
                        st.error(f"Error: {str(e)}")

            elif doc_type == "Consent Notice":
                consent_scope = st.text_area("Consent Scope", value="Processing for service delivery")
                data_types = st.multiselect(
                    "Data Types",
                    options=["Personal", "Financial", "Health", "Biometric", "Location"],
                    default=["Personal"]
                )
                retention = st.text_input("Retention", value="2 years")

                if st.button("Generate Notice", type="primary", use_container_width=True):
                    try:
                        filepath = st.session_state.doc_generator.generate_consent_notice(
                            org_name=org["name"],
                            consent_scope=consent_scope,
                            data_types=data_types,
                            retention_period=retention
                        )

                        with open(filepath, "rb") as f:
                            doc_bytes = f.read()

                        st.session_state.db.create_document(org_id, "consent_notice", "Consent Notice", filepath)

                        st.download_button(
                            label="Download Notice",
                            data=doc_bytes,
                            file_name="Consent_Notice.docx",
                            mime="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                            use_container_width=True
                        )
                        st.success("Generated!")
                        st.session_state.db.log_activity(org_id, "DOCUMENT_GENERATED", "Consent Notice created")

                    except Exception as e:
                        st.error(f"Error: {str(e)}")

            elif doc_type == "Data Processing Agreement":
                processor_name = st.text_input("Processor Name")
                processing_activities = st.text_area("Processing Activities", value="Data storage and backup")

                if st.button("Generate DPA", type="primary", use_container_width=True):
                    try:
                        filepath = st.session_state.doc_generator.generate_dpa(
                            data_controller=org["name"],
                            data_processor=processor_name,
                            processing_activities=[processing_activities]
                        )

                        with open(filepath, "rb") as f:
                            doc_bytes = f.read()

                        st.session_state.db.create_document(org_id, "dpa", "Data Processing Agreement", filepath)

                        st.download_button(
                            label="Download DPA",
                            data=doc_bytes,
                            file_name="Data_Processing_Agreement.docx",
                            mime="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                            use_container_width=True
                        )
                        st.success("Generated!")
                        st.session_state.db.log_activity(org_id, "DOCUMENT_GENERATED", "DPA created")

                    except Exception as e:
                        st.error(f"Error: {str(e)}")

            elif doc_type == "Privacy Impact Assessment":
                processing_name = st.text_input("Processing Name")
                processing_desc = st.text_area("Processing Description")
                data_subjects = st.text_input("Data Subjects", value="Customers")

                if st.button("Generate DPIA", type="primary", use_container_width=True):
                    try:
                        filepath = st.session_state.doc_generator.generate_dpia(
                            org_name=org["name"],
                            processing_name=processing_name,
                            processing_description=processing_desc,
                            data_subjects=[data_subjects]
                        )

                        with open(filepath, "rb") as f:
                            doc_bytes = f.read()

                        st.session_state.db.create_document(org_id, "dpia", "Privacy Impact Assessment", filepath)

                        st.download_button(
                            label="Download DPIA",
                            data=doc_bytes,
                            file_name="Privacy_Impact_Assessment.docx",
                            mime="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                            use_container_width=True
                        )
                        st.success("Generated!")
                        st.session_state.db.log_activity(org_id, "DOCUMENT_GENERATED", "DPIA created")

                    except Exception as e:
                        st.error(f"Error: {str(e)}")

            elif doc_type == "Breach Notification":
                breach_desc = st.text_area("Breach Description")
                affected_data = st.text_input("Data Types", value="Personal data")
                individuals = st.number_input("Individuals Affected", value=1, min_value=1)

                if st.button("Generate Notification", type="primary", use_container_width=True):
                    try:
                        filepath = st.session_state.doc_generator.generate_breach_notification(
                            org_name=org["name"],
                            breach_description=breach_desc,
                            data_affected=affected_data,
                            individuals_affected=individuals
                        )

                        with open(filepath, "rb") as f:
                            doc_bytes = f.read()

                        st.session_state.db.create_document(org_id, "breach_notification", "Breach Notification", filepath)

                        st.download_button(
                            label="Download Notification",
                            data=doc_bytes,
                            file_name="Breach_Notification.docx",
                            mime="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                            use_container_width=True
                        )
                        st.success("Generated!")
                        st.session_state.db.log_activity(org_id, "DOCUMENT_GENERATED", "Breach Notification created")

                    except Exception as e:
                        st.error(f"Error: {str(e)}")

            elif doc_type == "Record of Processing Activities":
                processing_name = st.text_input("Processing Name")
                purposes = st.text_area("Purposes")

                if st.button("Generate RoPA", type="primary", use_container_width=True):
                    try:
                        filepath = st.session_state.doc_generator.generate_ropa(
                            org_name=org["name"],
                            processing_activities=[{
                                "name": processing_name,
                                "purpose": purposes,
                                "data_categories": ["Personal Data"],
                                "recipients": ["Internal Team"]
                            }]
                        )

                        with open(filepath, "rb") as f:
                            doc_bytes = f.read()

                        st.session_state.db.create_document(org_id, "ropa", "Record of Processing Activities", filepath)

                        st.download_button(
                            label="Download RoPA",
                            data=doc_bytes,
                            file_name="Record_of_Processing_Activities.docx",
                            mime="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                            use_container_width=True
                        )
                        st.success("Generated!")
                        st.session_state.db.log_activity(org_id, "DOCUMENT_GENERATED", "RoPA created")

                    except Exception as e:
                        st.error(f"Error: {str(e)}")

            else:
                grievance_contact = st.text_input("Contact Email", value="grievance@example.com")
                resolution_time = st.text_input("Resolution Time", value="30 days")

                if st.button("Generate Policy", type="primary", use_container_width=True):
                    try:
                        filepath = st.session_state.doc_generator.generate_grievance_policy(
                            org_name=org["name"],
                            grievance_contact=grievance_contact,
                            resolution_timeframe=resolution_time
                        )

                        with open(filepath, "rb") as f:
                            doc_bytes = f.read()

                        st.session_state.db.create_document(org_id, "grievance_policy", "Grievance Redressal Policy", filepath)

                        st.download_button(
                            label="Download Policy",
                            data=doc_bytes,
                            file_name="Grievance_Redressal_Policy.docx",
                            mime="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                            use_container_width=True
                        )
                        st.success("Generated!")
                        st.session_state.db.log_activity(org_id, "DOCUMENT_GENERATED", "Grievance Policy created")

                    except Exception as e:
                        st.error(f"Error: {str(e)}")

    with col2:
        st.subheader("Generated Documents")

        docs = st.session_state.db.get_documents(org_id)

        if docs:
            for doc in docs:
                if doc['status'] != 'DELETED':
                    st.markdown(f"**{doc['title']}**")
                    st.caption(f"Created: {doc['created_at'][:10]} | {doc['status']}")
                    st.divider()
        else:
            st.info("No documents yet. Generate your first document.")

# ==================== PAGE: COMPLIANCE TRACKER ====================
def page_compliance_tracker():
    """Compliance Tracker page"""
    if not st.session_state.org_id:
        st.warning("Please log in to access this page.")
        return

    st.title("Compliance Tracker")

    org_id = st.session_state.org_id

    col1, col2 = st.columns(2)

    with col1:
        if st.button("Add New Task", use_container_width=True):
            st.session_state.show_new_task = True

    with col2:
        if st.button("Import Default Tasks", use_container_width=True):
            for task in config.DEFAULT_COMPLIANCE_TASKS:
                due_date = datetime.now() + timedelta(days=task["days_to_deadline"])
                st.session_state.db.create_task(
                    org_id=org_id,
                    title=task["title"],
                    category=task["category"],
                    priority=task["priority"],
                    due_date=due_date.strftime("%Y-%m-%d"),
                    description=task["description"]
                )
            st.success("Tasks imported!")
            st.rerun()

    st.markdown("---")

    tabs = st.tabs(["Pending", "In Progress", "Completed", "Create New"])

    with tabs[0]:
        st.subheader("Pending Tasks")
        tasks = st.session_state.db.get_tasks(org_id, "PENDING")

        if tasks:
            for task in tasks:
                col1, col2 = st.columns([3, 1])

                with col1:
                    st.write(f"**{task['title']}**")
                    st.caption(f"{task['category']} | Priority: {task['priority']}")
                    st.caption(f"Due: {task['due_date']}")

                with col2:
                    if st.button("Start", key=f"start_{task['id']}", use_container_width=True):
                        st.session_state.db.update_task(org_id, task["id"], status="IN_PROGRESS")
                        st.session_state.db.log_activity(org_id, "TASK_STARTED", f"'{task['title']}'")
                        st.rerun()
        else:
            st.info("No pending tasks")

    with tabs[1]:
        st.subheader("In Progress")
        tasks = st.session_state.db.get_tasks(org_id, "IN_PROGRESS")

        if tasks:
            for task in tasks:
                col1, col2 = st.columns([3, 1])

                with col1:
                    st.write(f"**{task['title']}**")
                    st.caption(f"{task['category']} | Priority: {task['priority']}")
                    st.caption(f"Due: {task['due_date']}")

                with col2:
                    if st.button("Complete", key=f"complete_{task['id']}", use_container_width=True):
                        st.session_state.db.update_task(org_id, task["id"], status="COMPLETED")
                        st.session_state.db.log_activity(org_id, "TASK_COMPLETED", f"'{task['title']}'")
                        st.rerun()
        else:
            st.info("No in-progress tasks")

    with tabs[2]:
        st.subheader("Completed")
        tasks = st.session_state.db.get_tasks(org_id, "COMPLETED")

        if tasks:
            st.success(f"{len(tasks)} task(s) completed!")
            for task in tasks:
                st.write(f"✅ {task['title']}")
        else:
            st.info("No completed tasks")

    with tabs[3]:
        st.subheader("Create Task")

        task_title = st.text_input("Title")
        task_desc = st.text_area("Description")
        task_cat = st.selectbox("Category", list(config.COMPLIANCE_CATEGORIES.keys()))
        task_priority = st.selectbox("Priority", ["LOW", "MEDIUM", "HIGH", "CRITICAL"])
        task_due = st.date_input("Due Date")

        if st.button("Create", type="primary", use_container_width=True):
            if task_title:
                st.session_state.db.create_task(
                    org_id=org_id,
                    title=task_title,
                    category=task_cat,
                    priority=task_priority,
                    due_date=task_due.strftime("%Y-%m-%d"),
                    description=task_desc
                )
                st.success("Task created!")
                st.rerun()
            else:
                st.error("Enter a title")

    st.markdown("---")
    all_tasks = st.session_state.db.get_tasks(org_id)
    if all_tasks:
        completed = len([t for t in all_tasks if t['status'] == 'COMPLETED'])
        progress = completed / len(all_tasks)
        st.write(f"**Progress:** {completed}/{len(all_tasks)} tasks")
        st.progress(progress)

# ==================== PAGE: BREACH RESPONSE ====================
def page_breach_response():
    """Breach Response page"""
    if not st.session_state.org_id:
        st.warning("Please log in to access this page.")
        return

    st.title("Breach Response")

    org_id = st.session_state.org_id

    tabs = st.tabs(["Report", "Active", "Timeline", "Guide"])

    with tabs[0]:
        st.subheader("Report Breach")

        col1, col2 = st.columns(2)

        with col1:
            incident_date = st.date_input("Date", value=datetime.now())
            severity = st.selectbox("Severity", ["LOW", "MEDIUM", "HIGH", "CRITICAL"])

        with col2:
            data_affected = st.text_input("Data Types", value="Personal data")
            individuals = st.number_input("Individuals Affected", value=1, min_value=1)

        description = st.text_area("Description", height=120)
        notes = st.text_area("Notes", height=80)

        if st.button("Report", type="primary", use_container_width=True):
            if description:
                breach_id = st.session_state.db.create_breach_incident(
                    org_id=org_id,
                    incident_date=incident_date.strftime("%Y-%m-%d"),
                    description=description,
                    severity=severity,
                    data_affected=data_affected,
                    notes=notes
                )
                st.success(f"Breach #{breach_id} reported!")
                st.rerun()
            else:
                st.error("Enter description")

    with tabs[1]:
        st.subheader("Active Breaches")

        breaches = st.session_state.db.get_breach_incidents(org_id)
        open_breaches = [b for b in breaches if b['status'] == 'OPEN']

        if open_breaches:
            for breach in open_breaches:
                col1, col2 = st.columns([3, 1])

                with col1:
                    severity_color = get_severity_color(breach['severity'])
                    st.markdown(f"""
                    <div class="card" style="border-left: 4px solid {severity_color};">
                        <strong>Breach #{breach['id']}</strong><br>
                        <em>{html.escape(str(breach['incident_date']))}</em><br>
                        {html.escape(str(breach['description']))}<br>
                        <span style="color: {severity_color}; font-weight: bold;">Severity: {html.escape(str(breach['severity']))}</span><br>
                        Data: {html.escape(str(breach['data_affected']))} | Individuals: {breach['id']}
                    </div>
                    """, unsafe_allow_html=True)

                with col2:
                    incident_date_obj = datetime.fromisoformat(breach['incident_date'])
                    hours_elapsed = (datetime.now() - incident_date_obj).total_seconds() / 3600
                    hours_remaining = 72 - hours_elapsed

                    if hours_remaining > 0:
                        st.warning(f"{hours_remaining:.1f}h left")
                    else:
                        st.error("Deadline passed!")

                col1, col2, col3 = st.columns(3)

                with col1:
                    new_status = st.selectbox(
                        "Status",
                        ["DETECTED", "CONTAINED", "NOTIFIED_BOARD", "NOTIFIED_PRINCIPALS", "RESOLVED"],
                        key=f"status_{breach['id']}",
                        label_visibility="collapsed"
                    )
                    if new_status != breach['status']:
                        st.session_state.db.update_breach_incident(org_id, breach['id'], status=new_status)
                        st.session_state.db.log_activity(org_id, "BREACH_UPDATED", f"Status: {new_status}")
                        st.rerun()

                with col2:
                    if st.button("Notes", key=f"notes_{breach['id']}", use_container_width=True):
                        st.session_state.show_breach_notes = breach['id']

                with col3:
                    if st.button("Close", key=f"close_{breach['id']}", use_container_width=True):
                        st.session_state.db.update_breach_incident(org_id, breach['id'], status="RESOLVED")
                        st.session_state.db.log_activity(org_id, "BREACH_CLOSED", f"Breach #{breach['id']}")
                        st.rerun()

                st.divider()

        else:
            st.info("No open breaches")

    with tabs[2]:
        st.subheader("Breach Timeline")

        all_breaches = st.session_state.db.get_breach_incidents(org_id)

        if all_breaches:
            for breach in all_breaches:
                st.write(f"**Breach #{breach['id']}** — {breach['incident_date']} ({breach['severity']})")
                st.caption(f"{get_status_icon(breach['status'])} {breach['status']}")
                st.caption(breach['description'][:100])
                st.divider()
        else:
            st.info("No breaches")

    with tabs[3]:
        st.subheader("DPDPA Breach Guidelines")

        st.markdown("""
        ### 72-Hour Rule
        Breaches must be reported to the Data Protection Board within **72 hours**.

        ### Response Steps

        1. **DETECT** (Immediate) — Identify and assess the breach
        2. **CONTAIN** (24h) — Isolate systems and prevent loss
        3. **NOTIFY BOARD** (72h) — Report to Data Protection Board
        4. **NOTIFY INDIVIDUALS** (7 days) — Communicate with affected parties
        5. **INVESTIGATE** — Complete root cause analysis
        6. **DOCUMENT** — Update logs and improve processes
        """)

# ==================== PAGE: KNOWLEDGE BASE ====================
def page_knowledge_base():
    """Knowledge Base page"""
    st.title("Knowledge Base")

    st.markdown("Learn about DPDPA compliance requirements and best practices.")

    search_query = st.text_input("Search Knowledge Base", placeholder="Search...")

    if search_query:
        st.subheader("Results")
        results = search_knowledge(search_query)

        if results:
            for result in results[:10]:
                with st.expander(f"{result['type'].upper()}: {result['title']}", expanded=False):
                    st.write(result['content'][:500])
        else:
            st.info("No results found.")

        st.divider()

    kb_tabs = st.tabs(["Sections", "Definitions", "Checklist", "FAQs", "Penalties", "Guidance", "Timeline"])

    with kb_tabs[0]:
        st.subheader("DPDPA Sections")
        section_num = st.selectbox("Select Section", list(DPDPA_SECTIONS.keys()))
        section = DPDPA_SECTIONS[section_num]

        st.write(f"**{section['number']}. {section['title']}**")
        st.write(section['summary'])

        st.write("**Key Requirements:**")
        for req in section.get('key_requirements', []):
            st.write(f"- {req}")

        st.write(f"**Applies To:** {section.get('applies_to', 'N/A')}")
        st.write(f"**Penalties:** {section.get('penalties', 'N/A')}")

    with kb_tabs[1]:
        st.subheader("Definitions")

        for term, definition in KEY_DEFINITIONS.items():
            with st.expander(f"**{term}**", expanded=False):
                st.write(definition)

    with kb_tabs[2]:
        st.subheader("Compliance Checklist")

        checklist_items = list(COMPLIANCE_CHECKLIST.items())[:15]

        for item, description in checklist_items:
            st.write(f"☐ **{item}:** {description}")

    with kb_tabs[3]:
        st.subheader("FAQs")

        for question, answer in list(FAQ.items())[:10]:
            with st.expander(f"Q: {question}", expanded=False):
                st.write(f"**A:** {answer}")

    with kb_tabs[4]:
        st.subheader("Penalties")

        for violation, penalty_info in list(PENALTY_MATRIX.items())[:10]:
            st.write(f"**{violation}**")
            st.write(f"- ₹{penalty_info.get('amount', 'N/A')}")
            st.write(f"- Section {penalty_info.get('section', 'N/A')}")
            st.divider()

    with kb_tabs[5]:
        st.subheader("Sector Guidance")

        sector = st.selectbox("Industry", list(SECTOR_GUIDANCE.keys()))
        guidance = SECTOR_GUIDANCE[sector]

        st.write(guidance.get('overview', ''))

        st.write("**Requirements:**")
        for req in guidance.get('requirements', []):
            st.write(f"- {req}")

    with kb_tabs[6]:
        st.subheader("Timeline")

        for event, date_info in TIMELINE.items():
            st.write(f"**{event}:** {date_info.get('date', 'N/A')}")
            st.caption(date_info.get('description', ''))

# ==================== PAGE: SETTINGS ====================
def page_settings():
    """Settings page"""
    if st.session_state.user_info['role'] != "admin":
        st.error("Only admins can access settings.")
        return

    st.title("Settings")

    col1, col2 = st.columns(2)

    with col1:
        st.subheader("Organization")

        orgs = st.session_state.db.get_all_organizations()

        if orgs:
            selected_org = st.selectbox(
                "Select Organization",
                [org["name"] for org in orgs],
                key="org_settings"
            )

            org_id = next((org["id"] for org in orgs if org["name"] == selected_org), None)

            if org_id:
                org = st.session_state.db.get_organization(org_id)

                new_name = st.text_input("Name", org["name"])
                new_industry = st.selectbox("Industry", config.INDUSTRY_TYPES, index=config.INDUSTRY_TYPES.index(org["industry"]))
                new_size = st.selectbox("Size", config.ORG_SIZES, index=config.ORG_SIZES.index(org["size"]))
                new_sdf = st.selectbox("SDF Status", config.SDF_STATUSES, index=config.SDF_STATUSES.index(org["sdf_status"]))
                new_compliance = st.selectbox("Compliance Level", config.COMPLIANCE_LEVELS, index=config.COMPLIANCE_LEVELS.index(org["compliance_level"]))

                if st.button("Save", use_container_width=True, type="primary"):
                    st.session_state.db.update_organization(
                        org_id,
                        name=new_name,
                        industry=new_industry,
                        size=new_size,
                        sdf_status=new_sdf,
                        compliance_level=new_compliance
                    )
                    st.success("Updated!")
                    st.rerun()

    with col2:
        st.subheader("New Organization")

        new_org_name = st.text_input("Name", key="new_org_name")
        new_org_industry = st.selectbox("Industry", config.INDUSTRY_TYPES, key="new_org_industry")
        new_org_size = st.selectbox("Size", config.ORG_SIZES, key="new_org_size")
        new_org_sdf = st.selectbox("SDF Status", config.SDF_STATUSES, key="new_org_sdf")
        new_org_compliance = st.selectbox("Compliance Level", config.COMPLIANCE_LEVELS, key="new_org_compliance")

        if st.button("Create", use_container_width=True, type="primary"):
            if new_org_name:
                try:
                    org_id = st.session_state.db.create_organization(
                        name=new_org_name,
                        created_by=st.session_state.user_id,
                        industry=new_org_industry,
                        size=new_org_size,
                        sdf_status=new_org_sdf,
                        compliance_level=new_org_compliance
                    )
                    st.success(f"Created!")
                    st.rerun()
                except ValueError as e:
                    st.error(str(e))
            else:
                st.error("Enter name")

    st.markdown("---")

    st.subheader("Application")

    st.write(f"**Version:** {config.APP_VERSION}")
    st.write(f"**Created by:** {config.CREATED_BY}")
    st.write(f"**Database:** {st.session_state.db.db_path}")

    if st.button("Clear Cache"):
        st.cache_data.clear()
        st.success("Cache cleared!")

# ==================== PAGE ROUTING FUNCTIONS ====================
def render_ropa_page():
    if not st.session_state.org_id:
        st.warning("Please log in.")
        return
    if NEW_PAGES_AVAILABLE:
        page_ropa(st.session_state.db, st.session_state.org_id, st.session_state.user_info)
    else:
        st.info("RoPA Registry not available.")

def render_consent_page():
    if not st.session_state.org_id:
        st.warning("Please log in.")
        return
    if NEW_PAGES_AVAILABLE:
        page_consent_manager(st.session_state.db, st.session_state.org_id, st.session_state.user_info)
    else:
        st.info("Consent Manager not available.")

def render_privacy_notices_page():
    if not st.session_state.org_id:
        st.warning("Please log in.")
        return
    if NEW_PAGES_AVAILABLE:
        page_privacy_notices(st.session_state.db, st.session_state.org_id, st.session_state.user_info)
    else:
        st.info("Privacy Notices not available.")

def render_rights_requests_page():
    if not st.session_state.org_id:
        st.warning("Please log in.")
        return
    if NEW_PAGES_AVAILABLE:
        page_rights_requests(st.session_state.db, st.session_state.org_id, st.session_state.user_info)
    else:
        st.info("Rights Requests not available.")

def render_vendor_management_page():
    if not st.session_state.org_id:
        st.warning("Please log in.")
        return
    if NEW_PAGES_AVAILABLE:
        page_vendor_management(st.session_state.db, st.session_state.org_id, st.session_state.user_info)
    else:
        st.info("Vendor Management not available.")

# ==================== MAIN APP ROUTING ====================
def main():
    """Main application router"""

    if not st.session_state.authenticated:
        render_login_page()
        return

    render_sidebar()

    if st.session_state.page == "Dashboard":
        page_dashboard()
    elif st.session_state.page == "Gap Assessment":
        page_gap_assessment()
    elif st.session_state.page == "RoPA Registry":
        render_ropa_page()
    elif st.session_state.page == "Consent Manager":
        render_consent_page()
    elif st.session_state.page == "Privacy Notices":
        render_privacy_notices_page()
    elif st.session_state.page == "Rights Requests":
        render_rights_requests_page()
    elif st.session_state.page == "Vendor Management":
        render_vendor_management_page()
    elif st.session_state.page == "Document Generator":
        page_document_generator()
    elif st.session_state.page == "Compliance Tracker":
        page_compliance_tracker()
    elif st.session_state.page == "Breach Response":
        page_breach_response()
    elif st.session_state.page == "Knowledge Base":
        page_knowledge_base()
    elif st.session_state.page == "Settings":
        page_settings()
    elif st.session_state.page == "AI Assistant" and AI_PAGES_AVAILABLE:
        page_ai_chatbot(st.session_state.db, st.session_state.org_id, st.session_state.user_info)
    elif st.session_state.page == "AI Doc Drafter" and AI_PAGES_AVAILABLE:
        page_smart_doc_drafter(st.session_state.db, st.session_state.org_id, st.session_state.user_info)
    elif st.session_state.page == "AI Compliance Advisor" and AI_PAGES_AVAILABLE:
        page_gap_assessment_advisor(st.session_state.db, st.session_state.org_id, st.session_state.user_info)
    elif st.session_state.page == "AI Breach Analyzer" and AI_PAGES_AVAILABLE:
        page_breach_classifier(st.session_state.db, st.session_state.org_id, st.session_state.user_info)
    elif st.session_state.page == "AI Notice Reviewer" and AI_PAGES_AVAILABLE:
        page_privacy_notice_reviewer(st.session_state.db, st.session_state.org_id, st.session_state.user_info)
    elif st.session_state.page == "AI Configuration" and AI_PAGES_AVAILABLE:
        page_ai_settings(st.session_state.db, st.session_state.org_id, st.session_state.user_info)
    else:
        page_dashboard()

    st.markdown('<div class="footer">Svikruti.ai v0.2.0 | Multi-tenant DPDPA Compliance | Built by Harsh Kahate</div>', unsafe_allow_html=True)

if __name__ == "__main__":
    main()
