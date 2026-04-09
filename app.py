"""
Anumati.ai - DPDPA Compliance Automation Platform

A comprehensive, offline, rule-based compliance tool for automating
Digital Personal Data Protection Act (DPDPA) compliance in India.

Multi-user, multi-tenant version with authentication and RBAC.
Built with Streamlit and SQLite - no external APIs or dependencies.
Open source and free to use.
"""

import streamlit as st
from datetime import datetime, timedelta
import json
from pathlib import Path
import os
import tempfile
import hashlib

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
    page_title="Anumati.ai - DPDPA Compliance",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ==================== CUSTOM STYLING ====================
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap');

html, body, [class*="css"] {
    font-family: 'Inter', sans-serif;
}

/* Metric cards */
[data-testid="metric-container"] {
    background: #1E293B;
    border: 1px solid #334155;
    border-radius: 12px;
    padding: 16px;
}

/* Sidebar */
[data-testid="stSidebar"] {
    background: #0F172A;
    border-right: 1px solid #1E293B;
}

/* Tabs */
.stTabs [data-baseweb="tab-list"] {
    gap: 8px;
}
.stTabs [data-baseweb="tab"] {
    background: #1E293B;
    border-radius: 8px;
    padding: 8px 16px;
    color: #94A3B8;
}
.stTabs [aria-selected="true"] {
    background: #14B8A6 !important;
    color: #0F172A !important;
}

/* Expander */
.streamlit-expanderHeader {
    background: #1E293B;
    border-radius: 8px;
}

/* Buttons */
.stButton > button[kind="primary"] {
    background: #14B8A6;
    color: #0F172A;
    border: none;
    border-radius: 8px;
    font-weight: 600;
}

/* Cards */
.card {
    background: #1E293B;
    border: 1px solid #334155;
    border-radius: 12px;
    padding: 20px;
    margin-bottom: 12px;
}

.card-header {
    color: #14B8A6;
    font-size: 18px;
    font-weight: 700;
    margin-bottom: 8px;
}

.card-body {
    color: #CBD5E1;
    font-size: 14px;
    line-height: 1.6;
}

/* Footer */
.footer {
    text-align: center;
    padding: 24px 0;
    color: #64748B;
    border-top: 1px solid #1E293B;
    margin-top: 48px;
    font-size: 13px;
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
            pass  # Silently skip if tables already exist or other issue

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

def hash_password(password):
    """Hash a password using SHA-256"""
    return hashlib.sha256(password.encode()).hexdigest()

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
        "admin": "🔴",
        "member": "🟢",
        "viewer": "🔵"
    }
    return f"{badges.get(role, '•')} {role.capitalize()}"

# ==================== LOGIN & SIGNUP PAGES ====================
def render_login_page():
    """Render login and signup pages"""
    col1, col2, col3 = st.columns([1, 2, 1])

    with col2:
        st.markdown("""
        <div style="text-align: center; padding: 2rem 0;">
            <h1 style="color: #14B8A6; margin: 0;">🛡️ Anumati.ai</h1>
            <p style="color: #94A3B8; margin: 0.5rem 0 0 0; font-size: 1.1rem;">
                DPDPA Compliance Automation Platform
            </p>
        </div>
        """, unsafe_allow_html=True)

        st.markdown("---")

        tab1, tab2 = st.tabs(["Login", "Sign Up"])

        with tab1:
            st.subheader("Login to Your Account")

            with st.form("login_form", clear_on_submit=True):
                email = st.text_input("Email Address", placeholder="you@example.com")
                password = st.text_input("Password", type="password", placeholder="Enter your password")
                submit = st.form_submit_button("Login", use_container_width=True, type="primary")

                if submit:
                    if not email or not password:
                        st.error("Please enter both email and password")
                    else:
                        # Check if user exists
                        user = st.session_state.db.authenticate_user(email, password)

                        if user:
                            # Login successful
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
                            st.success("Login successful! Redirecting...")
                            st.rerun()
                        else:
                            st.error("Invalid email or password.")

        with tab2:
            st.subheader("Create a New Account")

            with st.form("signup_form", clear_on_submit=True):
                col1, col2 = st.columns(2)

                with col1:
                    full_name = st.text_input("Full Name", placeholder="John Doe")
                    email = st.text_input("Email Address", placeholder="you@example.com")

                with col2:
                    org_name = st.text_input("Organization Name", placeholder="Acme Corp")
                    industry = st.selectbox("Industry", config.INDUSTRY_TYPES)

                col1, col2 = st.columns(2)

                with col1:
                    org_size = st.selectbox("Organization Size", config.ORG_SIZES)
                    password = st.text_input("Password", type="password", placeholder="Min 8 characters")

                with col2:
                    st.write("")
                    st.write("")
                    confirm_password = st.text_input("Confirm Password", type="password", placeholder="Confirm password")

                st.markdown("---")
                submit = st.form_submit_button("Create Account", use_container_width=True, type="primary")

                if submit:
                    # Validation
                    if not all([full_name, email, org_name, password, confirm_password]):
                        st.error("Please fill in all fields")
                    elif len(password) < 8:
                        st.error("Password must be at least 8 characters")
                    elif password != confirm_password:
                        st.error("Passwords do not match")
                    else:
                        # Check if email already exists
                        conn = st.session_state.db.get_connection()
                        cursor = conn.cursor()
                        cursor.execute("SELECT id FROM users WHERE email = ?", (email,))
                        existing_user = cursor.fetchone()
                        conn.close()

                        if existing_user:
                            st.error("Email already registered. Please login instead.")
                        else:
                            try:
                                # Create organization (created_by=0 initially, updated after user creation)
                                org_id = st.session_state.db.create_organization(
                                    name=org_name,
                                    created_by=0,
                                    industry=industry,
                                    size=org_size,
                                    sdf_status="Not Determined",
                                    compliance_level="Getting Started"
                                )

                                # Create user as admin
                                user_id = st.session_state.db.create_user(
                                    email=email,
                                    password=password,
                                    full_name=full_name,
                                    role="admin",
                                    org_id=org_id
                                )

                                # Update org created_by
                                st.session_state.db.update_organization(org_id, created_by=user_id)

                                # Auto-login
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
                                st.success("Account created successfully! Welcome to Anumati.ai")
                                st.rerun()
                            except Exception as e:
                                st.error(f"Error creating account: {str(e)}")

# ==================== NAVIGATION & SIDEBAR ====================
def render_sidebar():
    """Render the main navigation sidebar for authenticated users"""
    if not st.session_state.authenticated:
        return

    with st.sidebar:
        st.markdown(f"""
            <div style="text-align: center; padding: 1rem 0; border-bottom: 2px solid #14B8A6;">
                <h1 style="color: #14B8A6; margin: 0;">🛡️ Anumati.ai</h1>
                <p style="color: #E2E8F0; margin: 0.5rem 0 0 0; font-size: 0.9rem;">
                    DPDPA Compliance Automation
                </p>
            </div>
        """, unsafe_allow_html=True)

        st.markdown("---")

        # User info
        user = st.session_state.user_info
        org = st.session_state.db.get_organization(st.session_state.org_id)

        st.markdown(f"""
        <div style="background: #1E293B; padding: 1rem; border-radius: 8px; margin-bottom: 1rem;">
            <div style="color: #14B8A6; font-weight: bold; margin-bottom: 0.5rem;">{user['full_name']}</div>
            <div style="color: #94A3B8; font-size: 0.9rem;">{org['name']}</div>
            <div style="color: #64748B; font-size: 0.85rem; margin-top: 0.5rem;">{get_role_badge(user['role'])}</div>
        </div>
        """, unsafe_allow_html=True)

        st.markdown("---")

        # Navigation menu
        st.subheader("Navigation")

        pages = [
            ("📊 Dashboard", "Dashboard"),
            ("🔍 Gap Assessment", "Gap Assessment"),
            ("📋 RoPA Registry", "RoPA Registry"),
            ("🤝 Consent Manager", "Consent Manager"),
            ("📝 Privacy Notices", "Privacy Notices"),
            ("👤 Rights Requests", "Rights Requests"),
            ("🏢 Vendor Management", "Vendor Management"),
            ("📄 Document Generator", "Document Generator"),
            ("✅ Compliance Tracker", "Compliance Tracker"),
            ("⚠️ Breach Response", "Breach Response"),
            ("📚 Knowledge Base", "Knowledge Base"),
            ("⚙️ Settings", "Settings"),
        ]

        # Add AI-powered pages if available
        if AI_PAGES_AVAILABLE:
            pages.insert(-1, ("", ""))  # separator placeholder
            ai_pages_list = [
                ("🤖 AI Assistant", "AI Assistant"),
                ("✨ AI Doc Drafter", "AI Doc Drafter"),
                ("🎯 AI Compliance Advisor", "AI Compliance Advisor"),
                ("🚨 AI Breach Analyzer", "AI Breach Analyzer"),
                ("📝 AI Notice Reviewer", "AI Notice Reviewer"),
                ("🔧 AI Configuration", "AI Configuration"),
            ]
            # Insert AI pages before Settings
            for ap in ai_pages_list:
                pages.insert(-1, ap)

        for label, page_name in pages:
            # Skip empty separator entries
            if not page_name:
                st.markdown("---")
                st.markdown('<p style="color: #14B8A6; font-weight: 600; font-size: 0.8rem; margin: 0;">AI-POWERED</p>', unsafe_allow_html=True)
                continue

            # Skip Settings and AI Configuration if not admin
            if page_name in ("Settings", "AI Configuration") and user['role'] != "admin":
                continue

            btn_type = "primary" if st.session_state.page == page_name else "secondary"
            if st.button(label, key=f"nav_{page_name}", use_container_width=True, type=btn_type):
                st.session_state.page = page_name

        st.markdown("---")

        # Team Management (admin only)
        if user['role'] == "admin":
            st.subheader("👥 Team Management")

            with st.expander("Manage Team", expanded=False):
                # Show org members
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
                        st.write(f"{member['full_name']} ({member['email']})")
                    with col2:
                        st.caption(member['role'])

                st.divider()

                st.write("**Invite New User**")
                invite_email = st.text_input("Email to invite", key="invite_email_input")
                invite_role = st.selectbox("Role", ["member", "viewer"], key="invite_role")

                if st.button("Send Invite", use_container_width=True):
                    if invite_email:
                        # Generate invite (in production, this would send an email)
                        conn = st.session_state.db.get_connection()
                        cursor = conn.cursor()

                        # Check if email already in org
                        cursor.execute("SELECT id FROM users WHERE email = ? AND org_id = ?",
                                     (invite_email, st.session_state.org_id))
                        existing = cursor.fetchone()

                        if existing:
                            st.error("User already in organization")
                        else:
                            # For demo: create user directly with invite role
                            # In production, you'd generate an invite token and send email
                            st.info(f"Invite sent to {invite_email} with {invite_role} role")

                        conn.close()

        st.markdown("---")

        # Help section
        with st.expander("ℹ️ About Anumati.ai"):
            st.markdown(f"""
            **Version:** {config.APP_VERSION}

            Anumati.ai is an open-source DPDPA compliance automation platform
            designed to help organizations implement and maintain compliance
            with India's Digital Personal Data Protection Act.

            **Key Features:**
            - No external dependencies
            - Fully offline and secure
            - Rule-based compliance checks
            - Automated document generation
            - Breach incident tracking
            """)

        st.markdown("---")

        # Logout
        if st.button("🚪 Logout", use_container_width=True):
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

    st.title(f"📊 Welcome back, {st.session_state.user_info['full_name']}")

    org_id = st.session_state.org_id
    stats = st.session_state.db.get_dashboard_stats(org_id)
    org = stats["organization"]

    # Header info
    col1, col2, col3 = st.columns([1, 1, 1])
    with col1:
        st.metric("Organization", org["name"])
    with col2:
        st.metric("Industry", org["industry"])
    with col3:
        st.metric("Compliance Level", org["compliance_level"])

    st.markdown("---")

    # Main metrics
    col1, col2, col3, col4 = st.columns(4)

    with col1:
        latest_score = stats["latest_assessment"]
        if latest_score:
            score = round(latest_score["overall_score"], 1)
            st.metric("Compliance Score", f"{score}%", delta="out of 100")
        else:
            st.metric("Compliance Score", "—", delta="No assessment yet")

    with col2:
        pending_tasks = stats["task_counts"].get("PENDING", 0)
        st.metric("Pending Tasks", pending_tasks)

    with col3:
        open_breaches = stats["open_breaches"]
        st.metric("Open Breaches", open_breaches)

    with col4:
        docs = stats["total_documents"]
        st.metric("Documents Generated", docs)

    st.markdown("---")

    # Compliance score and breakdown
    if stats["latest_assessment"]:
        col1, col2 = st.columns(2)

        with col1:
            st.subheader("Overall Compliance Score")
            score = stats["latest_assessment"]["overall_score"]
            gauge_color = "#E63946" if score < 50 else "#FF9F1C" if score < 75 else "#2EC4B6"
            st.markdown(f"""
                <div style="text-align: center;">
                    <div style="font-size: 3rem; color: {gauge_color}; font-weight: bold;">
                        {score:.1f}%
                    </div>
                    <div style="color: #94A3B8;">Compliance Status</div>
                </div>
            """, unsafe_allow_html=True)

        with col2:
            st.subheader("Category Breakdown")
            category_scores = stats["latest_assessment"]["category_scores"]

            cat_data = []
            for cat, score in sorted(category_scores.items()):
                status = "🟢" if score >= 75 else "🟡" if score >= 50 else "🔴"
                cat_data.append({
                    "Category": cat,
                    "Score": f"{score:.1f}%",
                    "Status": status
                })

            st.dataframe(cat_data, use_container_width=True, hide_index=True)

    st.markdown("---")

    # Upcoming deadlines and modules
    col1, col2 = st.columns(2)

    with col1:
        st.subheader("📅 Upcoming Deadlines")
        next_deadline = config.get_next_deadline()

        if next_deadline:
            days = next_deadline["days"]
            deadline_color = "#E63946" if days < 30 else "#FF9F1C" if days < 90 else "#2EC4B6"

            st.markdown(f"""
                <div style="
                    background-color: #1E293B;
                    padding: 1.5rem;
                    border-radius: 12px;
                    border-left: 4px solid {deadline_color};
                ">
                    <div style="font-weight: bold; color: #14B8A6;">
                        {next_deadline['name']}
                    </div>
                    <div style="color: #CBD5E1; margin-top: 0.5rem;">
                        {next_deadline['date'].strftime('%B %d, %Y')}
                    </div>
                    <div style="color: {deadline_color}; font-size: 1.2rem; font-weight: bold; margin-top: 0.5rem;">
                        {days} days remaining
                    </div>
                </div>
            """, unsafe_allow_html=True)

            st.write("**All Compliance Deadlines:**")
            for name, deadline in config.COMPLIANCE_DEADLINES.items():
                days = (deadline["date"] - datetime.now()).days
                status_icon = "🔴" if days < 0 else "🟡" if days < 30 else "🟢"
                st.write(f"{status_icon} **{name}:** {deadline['date'].strftime('%B %d, %Y')} ({days} days)")

    with col2:
        st.subheader("📋 Module Completion Status")

        modules = {
            "Gap Assessment": stats["latest_assessment"] is not None,
            "Documents Generated": stats["total_documents"] > 0,
            "Tasks Created": sum(stats["task_counts"].values()) > 0,
            "Breach Plan": stats["open_breaches"] >= 0,
            "Activity Log": len(st.session_state.db.get_activity_log(org_id, limit=1)) > 0,
        }

        for module, completed in modules.items():
            status = "✅" if completed else "⏳"
            st.write(f"{status} {module}")

    st.markdown("---")

    # Recent activity
    col1, col2 = st.columns([1, 1])

    with col1:
        st.subheader("📝 Recent Activity")
        activities = st.session_state.db.get_activity_log(org_id, limit=10)

        if activities:
            for activity in activities:
                timestamp = datetime.fromisoformat(activity["created_at"])
                time_str = timestamp.strftime("%b %d, %H:%M")
                st.write(f"**{activity['action_type']}** - {time_str}")
                st.caption(activity["description"])
        else:
            st.info("No recent activity")

    with col2:
        st.subheader("⏰ Key Metrics")
        if stats['latest_assessment']:
            st.write(f"**Assessment Date:** {stats['latest_assessment']['assessment_date'][:10]}")
        else:
            st.write("**Assessment Date:** Never")
        st.write(f"**Total Tasks:** {sum(stats['task_counts'].values())}")
        st.write(f"**Completed Tasks:** {stats['task_counts'].get('COMPLETED', 0)}")
        st.write(f"**Open Breaches:** {stats['open_breaches']}")
        st.write(f"**SDF Status:** {org['sdf_status']}")

# ==================== PAGE: GAP ASSESSMENT ====================
def page_gap_assessment():
    """Gap Assessment page - FULLY DYNAMIC"""
    if not st.session_state.org_id:
        st.warning("Please log in to access this page.")
        return

    st.title("🔍 Gap Assessment")

    org_id = st.session_state.org_id

    tabs = st.tabs(["Assessment", "Results", "History"])

    with tabs[0]:
        st.markdown("""
        This assessment evaluates your organization's compliance with DPDPA requirements.
        Answer questions across different compliance categories to identify gaps.
        """)

        # Create tabs for each category
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

        if st.button("📊 Calculate Assessment Score", use_container_width=True, type="primary"):
            scores = st.session_state.db.save_assessment(org_id)
            st.success("Assessment completed and saved!")
            st.balloons()

    with tabs[1]:
        st.subheader("Assessment Results")
        latest = st.session_state.db.get_latest_assessment(org_id)

        if latest:
            overall_score = latest['overall_score']
            st.metric("Overall Compliance Score", f"{overall_score:.1f}%")

            # Interpretation
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

            # Recommendations
            st.subheader("📌 Recommendations")
            low_scoring = {cat: score for cat, score in cat_scores.items() if score < 50}

            if low_scoring:
                st.warning("Focus Areas (Below 50%):")
                for cat, score in low_scoring.items():
                    st.write(f"- **{cat}** ({score:.1f}%) - Needs immediate attention")
            else:
                st.success("All areas have reasonable coverage!")

            st.write(f"**Assessment Date:** {latest['assessment_date']}")

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
            st.info("No assessments completed yet.")

# ==================== PAGE: DOCUMENT GENERATOR ====================
def page_document_generator():
    """Document Generator page - FULLY FUNCTIONAL"""
    if not st.session_state.org_id:
        st.warning("Please log in to access this page.")
        return

    st.title("📄 Document Generator")

    if not DOC_GENERATOR_AVAILABLE:
        st.error("Document generation requires `python-docx`. Install it with:")
        st.code("pip install python-docx", language="bash")
        st.info("Once installed, restart the app and this page will be fully functional.")
        return

    org_id = st.session_state.org_id
    org = st.session_state.db.get_organization(org_id)

    st.markdown("""
    Generate DPDPA-compliant documents tailored to your organization.
    All documents are templates that you can customize for your needs.
    """)

    col1, col2 = st.columns(2)

    with col1:
        st.subheader("Generate Documents")

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

        with st.expander("📋 Document Details", expanded=True):
            if doc_type == "Privacy Policy":
                data_categories = st.multiselect(
                    "Data Categories Collected",
                    options=[
                        "Name and Contact Information",
                        "Financial Information",
                        "Health Information",
                        "Biometric Data",
                        "Location Data",
                        "Online Activity Data",
                        "Device Information"
                    ],
                    default=["Name and Contact Information"]
                )
                purposes = st.multiselect(
                    "Processing Purposes",
                    options=[
                        "Service Delivery",
                        "Customer Support",
                        "Marketing",
                        "Legal Compliance",
                        "Risk Management",
                        "Analytics"
                    ],
                    default=["Service Delivery"]
                )
                retention_period = st.text_input("Data Retention Period", value="3 years")
                contact_email = st.text_input("Contact Email", value=org.get("name", "contact@example.com"))
                dpo_name = st.text_input("Data Protection Officer Name", value="DPO")

                if st.button("Generate Privacy Policy", type="primary", use_container_width=True):
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

                        st.session_state.db.create_document(
                            org_id,
                            "privacy_policy",
                            "Privacy Policy",
                            filepath
                        )

                        st.download_button(
                            label="📥 Download Privacy Policy (DOCX)",
                            data=doc_bytes,
                            file_name="Privacy_Policy.docx",
                            mime="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                            use_container_width=True
                        )
                        st.success("Privacy Policy generated successfully!")
                        st.session_state.db.log_activity(org_id, "DOCUMENT_GENERATED", "Privacy Policy created")

                    except Exception as e:
                        st.error(f"Error generating document: {str(e)}")

            elif doc_type == "Consent Notice":
                consent_scope = st.text_area("Scope of Consent", value="Processing of personal data for service delivery")
                data_types = st.multiselect(
                    "Data Types Requiring Consent",
                    options=["Personal", "Financial", "Health", "Biometric", "Location"],
                    default=["Personal"]
                )
                retention = st.text_input("Retention Period", value="2 years")

                if st.button("Generate Consent Notice", type="primary", use_container_width=True):
                    try:
                        filepath = st.session_state.doc_generator.generate_consent_notice(
                            org_name=org["name"],
                            consent_scope=consent_scope,
                            data_types=data_types,
                            retention_period=retention
                        )

                        with open(filepath, "rb") as f:
                            doc_bytes = f.read()

                        st.session_state.db.create_document(
                            org_id,
                            "consent_notice",
                            "Consent Notice",
                            filepath
                        )

                        st.download_button(
                            label="📥 Download Consent Notice (DOCX)",
                            data=doc_bytes,
                            file_name="Consent_Notice.docx",
                            mime="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                            use_container_width=True
                        )
                        st.success("Consent Notice generated!")
                        st.session_state.db.log_activity(org_id, "DOCUMENT_GENERATED", "Consent Notice created")

                    except Exception as e:
                        st.error(f"Error generating document: {str(e)}")

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

                        st.session_state.db.create_document(
                            org_id,
                            "dpa",
                            "Data Processing Agreement",
                            filepath
                        )

                        st.download_button(
                            label="📥 Download DPA (DOCX)",
                            data=doc_bytes,
                            file_name="Data_Processing_Agreement.docx",
                            mime="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                            use_container_width=True
                        )
                        st.success("DPA generated!")
                        st.session_state.db.log_activity(org_id, "DOCUMENT_GENERATED", "DPA created")

                    except Exception as e:
                        st.error(f"Error generating document: {str(e)}")

            elif doc_type == "Privacy Impact Assessment":
                processing_name = st.text_input("Processing Activity Name")
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

                        st.session_state.db.create_document(
                            org_id,
                            "dpia",
                            "Privacy Impact Assessment",
                            filepath
                        )

                        st.download_button(
                            label="📥 Download DPIA (DOCX)",
                            data=doc_bytes,
                            file_name="Privacy_Impact_Assessment.docx",
                            mime="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                            use_container_width=True
                        )
                        st.success("DPIA generated!")
                        st.session_state.db.log_activity(org_id, "DOCUMENT_GENERATED", "DPIA created")

                    except Exception as e:
                        st.error(f"Error generating document: {str(e)}")

            elif doc_type == "Breach Notification":
                breach_desc = st.text_area("Breach Description")
                affected_data = st.text_input("Data Types Affected", value="Personal data")
                individuals = st.number_input("Number of Individuals Affected", value=1, min_value=1)

                if st.button("Generate Breach Notification", type="primary", use_container_width=True):
                    try:
                        filepath = st.session_state.doc_generator.generate_breach_notification(
                            org_name=org["name"],
                            breach_description=breach_desc,
                            data_affected=affected_data,
                            individuals_affected=individuals
                        )

                        with open(filepath, "rb") as f:
                            doc_bytes = f.read()

                        st.session_state.db.create_document(
                            org_id,
                            "breach_notification",
                            "Breach Notification",
                            filepath
                        )

                        st.download_button(
                            label="📥 Download Breach Notification (DOCX)",
                            data=doc_bytes,
                            file_name="Breach_Notification.docx",
                            mime="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                            use_container_width=True
                        )
                        st.success("Breach Notification generated!")
                        st.session_state.db.log_activity(org_id, "DOCUMENT_GENERATED", "Breach Notification created")

                    except Exception as e:
                        st.error(f"Error generating document: {str(e)}")

            elif doc_type == "Record of Processing Activities":
                processing_name = st.text_input("Processing Name")
                purposes = st.text_area("Purposes of Processing")

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

                        st.session_state.db.create_document(
                            org_id,
                            "ropa",
                            "Record of Processing Activities",
                            filepath
                        )

                        st.download_button(
                            label="📥 Download RoPA (DOCX)",
                            data=doc_bytes,
                            file_name="Record_of_Processing_Activities.docx",
                            mime="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                            use_container_width=True
                        )
                        st.success("RoPA generated!")
                        st.session_state.db.log_activity(org_id, "DOCUMENT_GENERATED", "RoPA created")

                    except Exception as e:
                        st.error(f"Error generating document: {str(e)}")

            else:  # Grievance Redressal Policy
                grievance_contact = st.text_input("Grievance Contact Email", value="grievance@example.com")
                resolution_time = st.text_input("Resolution Timeframe", value="30 days")

                if st.button("Generate Grievance Policy", type="primary", use_container_width=True):
                    try:
                        filepath = st.session_state.doc_generator.generate_grievance_policy(
                            org_name=org["name"],
                            grievance_contact=grievance_contact,
                            resolution_timeframe=resolution_time
                        )

                        with open(filepath, "rb") as f:
                            doc_bytes = f.read()

                        st.session_state.db.create_document(
                            org_id,
                            "grievance_policy",
                            "Grievance Redressal Policy",
                            filepath
                        )

                        st.download_button(
                            label="📥 Download Grievance Policy (DOCX)",
                            data=doc_bytes,
                            file_name="Grievance_Redressal_Policy.docx",
                            mime="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                            use_container_width=True
                        )
                        st.success("Grievance Policy generated!")
                        st.session_state.db.log_activity(org_id, "DOCUMENT_GENERATED", "Grievance Policy created")

                    except Exception as e:
                        st.error(f"Error generating document: {str(e)}")

    with col2:
        st.subheader("Generated Documents")

        docs = st.session_state.db.get_documents(org_id)

        if docs:
            for doc in docs:
                if doc['status'] != 'DELETED':
                    with st.container():
                        st.markdown(f"**{doc['title']}**")
                        st.caption(f"Created: {doc['created_at'][:10]} | Status: {doc['status']}")
                        st.divider()
        else:
            st.info("No documents generated yet. Start by selecting a document type on the left.")

# ==================== PAGE: COMPLIANCE TRACKER ====================
def page_compliance_tracker():
    """Compliance Tracker page - FULLY DYNAMIC"""
    if not st.session_state.org_id:
        st.warning("Please log in to access this page.")
        return

    st.title("✅ Compliance Tracker")

    org_id = st.session_state.org_id

    col1, col2, col3 = st.columns(3)

    with col1:
        if st.button("➕ Add New Task", use_container_width=True):
            st.session_state.show_new_task = True

    with col2:
        if st.button("📋 Import Default Tasks", use_container_width=True):
            for task in config.DEFAULT_COMPLIANCE_TASKS:
                due_date = datetime.now() + timedelta(days=task["days_to_deadline"])
                st.session_state.db.create_task(
                    org_id,
                    task["title"],
                    task["description"],
                    task["category"],
                    task["priority"],
                    due_date.strftime("%Y-%m-%d")
                )
            st.success("Default tasks imported!")
            st.rerun()

    with col3:
        st.write("")

    st.markdown("---")

    # Show tasks by status
    tabs = st.tabs(["Pending", "In Progress", "Completed", "Add New"])

    with tabs[0]:
        st.subheader("Pending Tasks")
        tasks = st.session_state.db.get_tasks(org_id, "PENDING")

        if tasks:
            for task in tasks:
                col1, col2 = st.columns([3, 1])

                with col1:
                    st.write(f"**{task['title']}**")
                    st.caption(f"Category: {task['category']} | Priority: {task['priority']}")
                    st.caption(f"Due: {task['due_date']}")

                with col2:
                    if st.button("Start", key=f"start_{task['id']}", use_container_width=True):
                        st.session_state.db.update_task(org_id, task["id"], status="IN_PROGRESS")
                        st.session_state.db.log_activity(org_id, "TASK_STARTED", f"Task '{task['title']}' started")
                        st.rerun()
        else:
            st.info("No pending tasks")

    with tabs[1]:
        st.subheader("In Progress Tasks")
        tasks = st.session_state.db.get_tasks(org_id, "IN_PROGRESS")

        if tasks:
            for task in tasks:
                col1, col2 = st.columns([3, 1])

                with col1:
                    st.write(f"**{task['title']}**")
                    st.caption(f"Category: {task['category']} | Priority: {task['priority']}")
                    st.caption(f"Due: {task['due_date']}")

                with col2:
                    if st.button("Complete", key=f"complete_{task['id']}", use_container_width=True):
                        st.session_state.db.update_task(org_id, task["id"], status="COMPLETED")
                        st.session_state.db.log_activity(org_id, "TASK_COMPLETED", f"Task '{task['title']}' completed")
                        st.rerun()
        else:
            st.info("No in-progress tasks")

    with tabs[2]:
        st.subheader("Completed Tasks")
        tasks = st.session_state.db.get_tasks(org_id, "COMPLETED")

        if tasks:
            st.success(f"{len(tasks)} task(s) completed!")
            for task in tasks:
                st.write(f"✅ {task['title']} (Due: {task['due_date']})")
        else:
            st.info("No completed tasks yet")

    with tabs[3]:
        st.subheader("Create New Task")

        task_title = st.text_input("Task Title")
        task_desc = st.text_area("Task Description")
        task_cat = st.selectbox("Category", list(config.COMPLIANCE_CATEGORIES.keys()))
        task_priority = st.selectbox("Priority", ["LOW", "MEDIUM", "HIGH", "CRITICAL"])
        task_due = st.date_input("Due Date")

        if st.button("Create Task", type="primary", use_container_width=True):
            if task_title:
                st.session_state.db.create_task(
                    org_id,
                    task_title,
                    task_desc,
                    task_cat,
                    task_priority,
                    task_due.strftime("%Y-%m-%d")
                )
                st.success("Task created!")
                st.rerun()
            else:
                st.error("Please enter a task title")

    # Progress bar
    st.markdown("---")
    all_tasks = st.session_state.db.get_tasks(org_id)
    if all_tasks:
        completed = len([t for t in all_tasks if t['status'] == 'COMPLETED'])
        progress = completed / len(all_tasks)
        st.write(f"**Overall Progress:** {completed}/{len(all_tasks)} tasks completed")
        st.progress(progress)

# ==================== PAGE: BREACH RESPONSE ====================
def page_breach_response():
    """Breach Response page - INCIDENT MANAGEMENT"""
    if not st.session_state.org_id:
        st.warning("Please log in to access this page.")
        return

    st.title("⚠️ Breach Response Management")

    org_id = st.session_state.org_id

    tabs = st.tabs(["Report Breach", "Active Incidents", "Timeline", "Guidelines"])

    with tabs[0]:
        st.subheader("Report New Breach")

        col1, col2 = st.columns(2)

        with col1:
            incident_date = st.date_input("Incident Date", value=datetime.now())
            severity = st.selectbox("Severity", ["LOW", "MEDIUM", "HIGH", "CRITICAL"])

        with col2:
            data_affected = st.text_input("Data Types Affected", value="Personal data")
            individuals = st.number_input("Individuals Affected", value=1, min_value=1)

        description = st.text_area("Breach Description", height=150)
        notes = st.text_area("Additional Notes", height=100)

        if st.button("Report Breach", type="primary", use_container_width=True):
            if description:
                breach_id = st.session_state.db.create_breach_incident(
                    org_id,
                    incident_date.strftime("%Y-%m-%d"),
                    description,
                    data_affected,
                    severity,
                    notes
                )
                st.success(f"Breach incident #{breach_id} reported!")
                st.rerun()
            else:
                st.error("Please provide a breach description")

    with tabs[1]:
        st.subheader("Active Breach Incidents")

        breaches = st.session_state.db.get_breach_incidents(org_id)
        open_breaches = [b for b in breaches if b['status'] == 'OPEN']

        if open_breaches:
            for breach in open_breaches:
                col1, col2 = st.columns([3, 1])

                with col1:
                    severity_color = get_severity_color(breach['severity'])
                    st.markdown(f"""
                    <div style="background: #1E293B; border-left: 4px solid {severity_color}; padding: 1rem; border-radius: 8px;">
                        <strong>Breach #{breach['id']}</strong><br>
                        <em>{breach['incident_date']}</em><br>
                        {breach['description']}<br>
                        <span style="color: {severity_color}; font-weight: bold;">Severity: {breach['severity']}</span><br>
                        Data: {breach['data_affected']} | Individuals: {breach['id']}
                    </div>
                    """, unsafe_allow_html=True)

                with col2:
                    incident_date_obj = datetime.fromisoformat(breach['incident_date'])
                    hours_elapsed = (datetime.now() - incident_date_obj).total_seconds() / 3600
                    hours_remaining = 72 - hours_elapsed

                    if hours_remaining > 0:
                        st.warning(f"⏱️ {hours_remaining:.1f}h remaining")
                    else:
                        st.error("⏰ 72h deadline passed!")

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
                        st.session_state.db.log_activity(org_id, "BREACH_UPDATED", f"Breach #{breach['id']} status: {new_status}")
                        st.rerun()

                with col2:
                    if st.button("📝 Add Notes", key=f"notes_{breach['id']}", use_container_width=True):
                        st.session_state.show_breach_notes = breach['id']

                with col3:
                    if st.button("Close", key=f"close_{breach['id']}", use_container_width=True):
                        st.session_state.db.update_breach_incident(org_id, breach['id'], status="RESOLVED")
                        st.session_state.db.log_activity(org_id, "BREACH_CLOSED", f"Breach #{breach['id']} closed")
                        st.rerun()

                st.divider()

        else:
            st.info("No open breaches")

    with tabs[2]:
        st.subheader("Breach Timeline")

        all_breaches = st.session_state.db.get_breach_incidents(org_id)

        if all_breaches:
            for breach in all_breaches:
                st.write(f"**Breach #{breach['id']}** - {breach['incident_date']} ({breach['severity']})")
                st.caption(f"Status: {get_status_icon(breach['status'])} {breach['status']}")
                st.caption(breach['description'][:100] + "...")
                st.divider()
        else:
            st.info("No breach incidents recorded")

    with tabs[3]:
        st.subheader("📖 Breach Response Guidelines")

        st.markdown("""
        ### DPDPA 72-Hour Rule
        Data breaches must be reported to the Data Protection Board within **72 hours** of discovery.

        ### Response Steps

        1. **DETECT & ASSESS** (Immediate)
           - Identify the breach
           - Determine scope and severity
           - Log incident details

        2. **CONTAIN** (Within 24 hours)
           - Isolate affected systems
           - Prevent further data loss
           - Preserve evidence

        3. **NOTIFY AUTHORITIES** (Within 72 hours)
           - Report to Data Protection Board
           - Provide detailed incident report
           - Document notification

        4. **NOTIFY INDIVIDUALS** (Within 7 days)
           - Communicate with affected individuals
           - Explain mitigation measures
           - Provide guidance

        5. **INVESTIGATE** (Ongoing)
           - Root cause analysis
           - Document findings
           - Implement preventive measures

        6. **DOCUMENT & IMPROVE** (Post-incident)
           - Update breach log
           - Review and improve processes
           - Train staff

        ### Key Deadlines
        - **Detection to Board:** 72 hours
        - **Board to Individuals:** Reasonable time
        - **Investigation:** Complete within 90 days
        - **Report:** Submit incident report to DPB
        """)

# ==================== PAGE: KNOWLEDGE BASE ====================
def page_knowledge_base():
    """Knowledge Base page - SEARCHABLE & INTERACTIVE"""
    st.title("📚 Knowledge Base")

    st.markdown("Learn about DPDPA compliance requirements and best practices.")

    # Search bar
    search_query = st.text_input("🔍 Search Knowledge Base", placeholder="Search for sections, definitions, FAQs...")

    if search_query:
        st.subheader("Search Results")
        results = search_knowledge(search_query)

        if results:
            for result in results[:10]:
                with st.expander(f"{result['type'].upper()}: {result['title']}", expanded=False):
                    st.write(result['content'][:500])
        else:
            st.info("No results found. Try different keywords.")

        st.divider()

    # Knowledge tabs
    kb_tabs = st.tabs([
        "Sections",
        "Definitions",
        "Checklist",
        "FAQs",
        "Penalties",
        "Sector Guide",
        "Timeline"
    ])

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
        st.subheader("Key Definitions")

        for term, definition in KEY_DEFINITIONS.items():
            with st.expander(f"**{term}**", expanded=False):
                st.write(definition)

    with kb_tabs[2]:
        st.subheader("Compliance Checklist")

        checklist_items = list(COMPLIANCE_CHECKLIST.items())[:15]

        for item, description in checklist_items:
            col1, col2 = st.columns([0.1, 0.9])
            with col1:
                st.write("☐")
            with col2:
                st.write(f"**{item}:** {description}")

    with kb_tabs[3]:
        st.subheader("Frequently Asked Questions")

        for idx, (question, answer) in enumerate(list(FAQ.items())[:10]):
            with st.expander(f"Q: {question}", expanded=False):
                st.write(f"**A:** {answer}")

    with kb_tabs[4]:
        st.subheader("Penalty Matrix")

        for violation, penalty_info in list(PENALTY_MATRIX.items())[:10]:
            st.write(f"**{violation}**")
            st.write(f"- Amount: ₹{penalty_info.get('amount', 'N/A')}")
            st.write(f"- Section: {penalty_info.get('section', 'N/A')}")
            st.write(f"- Description: {penalty_info.get('description', 'N/A')}")
            st.divider()

    with kb_tabs[5]:
        st.subheader("Sector-Specific Guidance")

        sector = st.selectbox("Select Industry", list(SECTOR_GUIDANCE.keys()))
        guidance = SECTOR_GUIDANCE[sector]

        st.write(f"**{sector}**")
        st.write(guidance.get('overview', ''))

        st.write("**Key Requirements:**")
        for req in guidance.get('requirements', []):
            st.write(f"- {req}")

        st.write("**Best Practices:**")
        for practice in guidance.get('best_practices', []):
            st.write(f"- {practice}")

    with kb_tabs[6]:
        st.subheader("DPDPA Timeline")

        for event, date_info in TIMELINE.items():
            st.write(f"**{event}:** {date_info.get('date', 'N/A')}")
            st.caption(date_info.get('description', ''))
            st.divider()

# ==================== PAGE: SETTINGS ====================
def page_settings():
    """Settings page - ORGANIZATION MANAGEMENT (ADMIN ONLY)"""
    if st.session_state.user_info['role'] != "admin":
        st.error("Only administrators can access settings.")
        return

    st.title("⚙️ Settings")

    col1, col2 = st.columns(2)

    with col1:
        st.subheader("Organization Settings")

        orgs = st.session_state.db.get_all_organizations()

        if orgs:
            selected_org = st.selectbox(
                "Select Organization to Edit",
                [org["name"] for org in orgs],
                key="org_settings"
            )

            org_id = next(
                (org["id"] for org in orgs if org["name"] == selected_org),
                None
            )

            if org_id:
                org = st.session_state.db.get_organization(org_id)

                new_name = st.text_input("Organization Name", org["name"])
                new_industry = st.selectbox("Industry", config.INDUSTRY_TYPES, index=config.INDUSTRY_TYPES.index(org["industry"]))
                new_size = st.selectbox("Size", config.ORG_SIZES, index=config.ORG_SIZES.index(org["size"]))
                new_sdf = st.selectbox("SDF Status", config.SDF_STATUSES, index=config.SDF_STATUSES.index(org["sdf_status"]))
                new_compliance = st.selectbox("Compliance Level", config.COMPLIANCE_LEVELS, index=config.COMPLIANCE_LEVELS.index(org["compliance_level"]))

                if st.button("💾 Save Changes", use_container_width=True):
                    st.session_state.db.update_organization(
                        org_id,
                        name=new_name,
                        industry=new_industry,
                        size=new_size,
                        sdf_status=new_sdf,
                        compliance_level=new_compliance
                    )
                    st.success("Organization updated!")
                    st.rerun()

    with col2:
        st.subheader("Add New Organization")

        new_org_name = st.text_input("Organization Name", key="new_org_name")
        new_org_industry = st.selectbox("Industry", config.INDUSTRY_TYPES, key="new_org_industry")
        new_org_size = st.selectbox("Organization Size", config.ORG_SIZES, key="new_org_size")
        new_org_sdf = st.selectbox("SDF Status", config.SDF_STATUSES, key="new_org_sdf")
        new_org_compliance = st.selectbox("Current Compliance Level", config.COMPLIANCE_LEVELS, key="new_org_compliance")

        if st.button("Create Organization", use_container_width=True):
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
                    st.success(f"Organization '{new_org_name}' created!")
                    st.session_state.org_id = org_id
                    st.rerun()
                except ValueError as e:
                    st.error(str(e))
            else:
                st.error("Please enter organization name")

    st.markdown("---")

    st.subheader("Application Settings")

    col1, col2 = st.columns(2)

    with col1:
        st.write(f"**App Version:** {config.APP_VERSION}")
        st.write(f"**Created by:** {config.CREATED_BY}")
        st.write(f"**Database:** {st.session_state.db.db_path}")

    with col2:
        if st.button("🔄 Export Data"):
            st.info("Export feature coming soon")

        if st.button("🗑️ Clear Cache"):
            st.cache_data.clear()
            st.success("Cache cleared!")

# ==================== PAGE ROUTING FUNCTIONS ====================
def render_ropa_page():
    """RoPA page with multi-tenant support"""
    if not st.session_state.org_id:
        st.warning("Please log in to access this page.")
        return

    if NEW_PAGES_AVAILABLE:
        page_ropa(st.session_state.db, st.session_state.org_id, st.session_state.user_info)
    else:
        st.info("RoPA Registry module not yet available.")

def render_consent_page():
    """Consent Manager page with multi-tenant support"""
    if not st.session_state.org_id:
        st.warning("Please log in to access this page.")
        return

    if NEW_PAGES_AVAILABLE:
        page_consent_manager(st.session_state.db, st.session_state.org_id, st.session_state.user_info)
    else:
        st.info("Consent Manager module not yet available.")

def render_privacy_notices_page():
    """Privacy Notices page with multi-tenant support"""
    if not st.session_state.org_id:
        st.warning("Please log in to access this page.")
        return

    if NEW_PAGES_AVAILABLE:
        page_privacy_notices(st.session_state.db, st.session_state.org_id, st.session_state.user_info)
    else:
        st.info("Privacy Notices module not yet available.")

def render_rights_requests_page():
    """Rights Requests page with multi-tenant support"""
    if not st.session_state.org_id:
        st.warning("Please log in to access this page.")
        return

    if NEW_PAGES_AVAILABLE:
        page_rights_requests(st.session_state.db, st.session_state.org_id, st.session_state.user_info)
    else:
        st.info("Rights Requests module not yet available.")

def render_vendor_management_page():
    """Vendor Management page with multi-tenant support"""
    if not st.session_state.org_id:
        st.warning("Please log in to access this page.")
        return

    if NEW_PAGES_AVAILABLE:
        page_vendor_management(st.session_state.db, st.session_state.org_id, st.session_state.user_info)
    else:
        st.info("Vendor Management module not yet available.")

# ==================== MAIN APP ROUTING ====================
def main():
    """Main application router"""

    # Check if user is authenticated
    if not st.session_state.authenticated:
        render_login_page()
        return

    # Render sidebar for authenticated users
    render_sidebar()

    # Page routing for authenticated users
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
    # AI-powered pages
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

    # Footer
    st.markdown('<div class="footer">Anumati.ai v0.2.0 | Multi-tenant DPDPA Compliance Platform | Built by Harsh Kahate</div>', unsafe_allow_html=True)

if __name__ == "__main__":
    main()

# END OF FILE - PRODUCTION MULTI-TENANT VERSION WITH AUTHENTICATION AND RBAC
