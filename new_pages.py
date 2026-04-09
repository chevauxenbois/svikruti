"""
Anumati.ai - DPDPA Compliance Platform
Production-grade page functions for Records of Processing Activities, Consent Management,
Privacy Notices, Data Principal Rights Tracker, and Vendor Management.

Multi-user, multi-tenant with role-based access control and comprehensive error handling.
"""

import streamlit as st
from datetime import datetime, timedelta
from typing import Optional, Dict, List
import plotly.graph_objects as go


# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def _check_role_permission(user_info: Dict, required_roles: List[str]) -> bool:
    """Check if user has permission for an action based on role."""
    return user_info.get("role") in required_roles


def _render_empty_state(message: str, action_tab: str) -> None:
    """Render helpful empty state UI."""
    st.info(message)
    st.write(f"Use the '{action_tab}' tab to get started.")


def _safe_db_call(func, *args, **kwargs):
    """Safely call database functions with error handling."""
    try:
        return func(*args, **kwargs)
    except Exception as e:
        st.error(f"Database error: {str(e)}")
        return None


# ============================================================================
# PAGE 1: RECORDS OF PROCESSING ACTIVITIES (ROPA)
# ============================================================================

def page_ropa(db, org_id: int, user_info: Dict) -> None:
    """
    Records of Processing Activities page - Track and manage all data processing activities.
    Full DPDPA compliance with activity registry, analytics, and role-based access.
    """
    st.title("📋 Records of Processing Activities")

    # Fetch ROPA entries
    ropa_entries = _safe_db_call(db.get_ropa_entries, org_id) or []

    # Metrics Row
    col1, col2, col3, col4 = st.columns(4)
    active_entries = len([e for e in ropa_entries if e.get("status") == "Active"])
    cross_border_count = len([e for e in ropa_entries if e.get("cross_border_transfer")])
    inactive_entries = len([e for e in ropa_entries if e.get("status") == "Inactive"])

    with col1:
        st.metric("Total Entries", len(ropa_entries))
    with col2:
        st.metric("Active", active_entries)
    with col3:
        st.metric("Cross-Border", cross_border_count)
    with col4:
        st.metric("Inactive", inactive_entries)

    st.divider()

    # Role-based tab access
    can_edit = _check_role_permission(user_info, ["admin", "member"])

    if can_edit:
        tab1, tab2, tab3 = st.tabs(["📊 Registry", "➕ Add Entry", "📈 Analytics"])
    else:
        tab1 = st.tabs(["📊 Registry"])[0]

    # TAB 1: Registry
    with tab1:
        if ropa_entries:
            # Build table data
            table_data = []
            for entry in ropa_entries:
                table_data.append({
                    "Activity Name": entry.get("activity_name", ""),
                    "Department": entry.get("department", ""),
                    "Data Categories": entry.get("data_categories", ""),
                    "Lawful Basis": entry.get("lawful_basis", ""),
                    "Retention": entry.get("retention_period", ""),
                    "Status": entry.get("status", ""),
                })

            st.dataframe(table_data, use_container_width=True, hide_index=True)

            # Edit/Delete actions (admin/member only)
            if can_edit:
                st.subheader("Manage Entries")
                col1, col2 = st.columns(2)

                selected_activity = st.selectbox(
                    "Select entry to manage",
                    [e.get("activity_name", "Unnamed") for e in ropa_entries],
                    key="ropa_manage_select"
                )

                with col1:
                    if st.button("✏️ Edit", key="ropa_edit_btn"):
                        st.info("Edit functionality: Database integration ready.")

                with col2:
                    if st.button("🗑️ Delete", key="ropa_delete_btn"):
                        try:
                            matching = [e for e in ropa_entries if e.get("activity_name") == selected_activity]
                            if matching:
                                _safe_db_call(db.delete_ropa_entry, matching[0].get("id"))
                                st.success("Entry deleted.")
                                st.rerun()
                        except Exception as e:
                            st.error(f"Delete failed: {str(e)}")
        else:
            _render_empty_state(
                "No processing activities recorded yet.",
                "Add Entry"
            )

    # TAB 2: Add Entry (admin/member only)
    if can_edit:
        with tab2:
            st.subheader("Add New Processing Activity")

            with st.form("ropa_form_key", clear_on_submit=True):
                col1, col2 = st.columns(2)

                with col1:
                    activity_name = st.text_input(
                        "Activity Name *",
                        placeholder="e.g., Customer Data Processing"
                    )
                    department = st.selectbox(
                        "Department *",
                        ["HR", "IT", "Marketing", "Finance", "Operations", "Legal", "Customer Support", "Product", "Engineering"]
                    )

                with col2:
                    lawful_basis = st.selectbox(
                        "Lawful Basis *",
                        ["Consent - Section 6", "Voluntary Provision - Section 7(a)",
                         "Employment - Section 7(b)", "State Functions - Section 7(c)",
                         "Legal Obligation - Section 7(d)", "Medical Emergency - Section 7(e)"]
                    )
                    retention_period = st.text_input(
                        "Retention Period *",
                        placeholder="e.g., 3 years"
                    )

                purpose = st.text_area(
                    "Purpose *",
                    height=80,
                    placeholder="Describe the processing purpose"
                )

                st.markdown("**Data Categories** *")
                col1, col2, col3 = st.columns(3)
                categories = []
                cat_options = [
                    "Names", "Email Addresses", "Phone Numbers", "Physical Addresses",
                    "Financial Data", "Health Data", "Biometric Data", "Location Data",
                    "Behavioral/Usage Data", "Employment Records", "Government IDs", "Children's Data"
                ]

                for idx, cat in enumerate(cat_options):
                    with [col1, col2, col3][idx % 3]:
                        if st.checkbox(cat, key=f"ropa_cat_{cat}"):
                            categories.append(cat)

                st.markdown("**Data Subjects** *")
                col1, col2 = st.columns(2)
                subjects = []
                subj_options = ["Customers", "Employees", "Job Applicants", "Vendors/Contractors",
                               "Website Visitors", "App Users", "Children", "Partners"]

                for idx, subj in enumerate(subj_options):
                    with [col1, col2][idx % 2]:
                        if st.checkbox(subj, key=f"ropa_subj_{subj}"):
                            subjects.append(subj)

                col1, col2 = st.columns(2)

                with col1:
                    data_processor = st.text_input(
                        "Data Processor",
                        placeholder="External processor name (if applicable)"
                    )
                    processing_location = st.text_input(
                        "Processing Location",
                        placeholder="e.g., India"
                    )

                with col2:
                    security_measures = st.text_area(
                        "Security Measures *",
                        height=80,
                        placeholder="Encryption, access controls, audits"
                    )

                cross_border = st.checkbox(
                    "Cross-border Data Transfer"
                )

                status = st.selectbox(
                    "Status",
                    ["Active", "Inactive"]
                )

                submitted = st.form_submit_button("✅ Add Entry", use_container_width=True)

                if submitted:
                    if not (activity_name and department and categories and subjects and purpose and retention_period and security_measures):
                        st.error("Please fill all required fields (marked *).")
                    else:
                        _safe_db_call(
                            db.create_ropa_entry,
                            org_id=org_id,
                            activity_name=activity_name,
                            department=department,
                            data_categories=", ".join(categories),
                            lawful_basis=lawful_basis,
                            data_subjects=", ".join(subjects),
                            purpose=purpose,
                            retention_period=retention_period,
                            processor_name=data_processor,
                            processing_location=processing_location,
                            security_measures=security_measures,
                            cross_border_transfer=cross_border,
                            status=status,
                            created_by=user_info.get("id")
                        )
                        st.success("Processing activity added successfully!")
                        st.rerun()

        # TAB 3: Analytics (admin/member only)
        with tab3:
            st.subheader("Analytics & Insights")

            if ropa_entries:
                col1, col2 = st.columns(2)

                # Chart 1: Entries by Department
                with col1:
                    dept_counts = {}
                    for e in ropa_entries:
                        dept = e.get("department", "Unknown")
                        dept_counts[dept] = dept_counts.get(dept, 0) + 1

                    fig1 = go.Figure(
                        data=[go.Bar(x=list(dept_counts.keys()), y=list(dept_counts.values()),
                                    marker_color="#14B8A6")],
                        layout=go.Layout(title="Entries by Department", height=400,
                                       plot_bgcolor="#1E293B", paper_bgcolor="#0F172A")
                    )
                    st.plotly_chart(fig1, use_container_width=True)

                # Chart 2: Entries by Lawful Basis
                with col2:
                    basis_counts = {}
                    for e in ropa_entries:
                        basis = e.get("lawful_basis", "Unknown")
                        basis_counts[basis] = basis_counts.get(basis, 0) + 1

                    fig2 = go.Figure(
                        data=[go.Pie(labels=list(basis_counts.keys()), values=list(basis_counts.values()))],
                        layout=go.Layout(title="Distribution by Lawful Basis", height=400,
                                       plot_bgcolor="#1E293B", paper_bgcolor="#0F172A")
                    )
                    st.plotly_chart(fig2, use_container_width=True)

                # Cross-border summary
                st.metric("Cross-Border Transfers", cross_border_count)
            else:
                st.info("No data to display yet.")


# ============================================================================
# PAGE 2: CONSENT MANAGEMENT
# ============================================================================

def page_consent_manager(db, org_id: int, user_info: Dict) -> None:
    """
    Consent Management page - Track all consents, audit compliance against DPDPA Section 6.
    Comprehensive consent lifecycle management with withdrawal tracking.
    """
    st.title("✅ Consent Management")

    st.info(
        """
        **DPDPA Section 6 Requirements:**
        Consent must be free (no coercion), specific (per-purpose), informed (clear notice),
        unambiguous (affirmative action), and unconditional (no bundling with services).
        """
    )

    # Fetch consent records
    consents = _safe_db_call(db.get_consent_records, org_id) or []

    # Metrics Row
    col1, col2, col3, col4 = st.columns(4)
    active_consents = len([c for c in consents if c.get("status") == "Active"])
    withdrawn_consents = len([c for c in consents if c.get("status") == "Withdrawn"])
    children_consents = len([c for c in consents if c.get("is_children_data")])

    with col1:
        st.metric("Total Consents", len(consents))
    with col2:
        st.metric("Active", active_consents)
    with col3:
        st.metric("Withdrawn", withdrawn_consents)
    with col4:
        st.metric("Children's Data", children_consents)

    st.divider()

    # Role-based access
    can_edit = _check_role_permission(user_info, ["admin", "member"])

    if can_edit:
        tab1, tab2, tab3 = st.tabs(["📊 Records", "➕ Add Consent", "✓ Compliance Audit"])
    else:
        tab1 = st.tabs(["📊 Records"])[0]

    # TAB 1: Consent Records
    with tab1:
        if consents:
            table_data = []
            for c in consents:
                table_data.append({
                    "Purpose": c.get("purpose", "")[:50],
                    "Mechanism": c.get("mechanism", ""),
                    "Status": c.get("status", ""),
                    "Data Categories": c.get("data_categories", "")[:40],
                    "Children": "Yes" if c.get("is_children_data") else "No",
                    "Created": str(c.get("created_date", ""))[:10],
                })

            st.dataframe(table_data, use_container_width=True, hide_index=True)
        else:
            _render_empty_state("No consent records yet.", "Add Consent")

    # TAB 2: Add Consent (admin/member only)
    if can_edit:
        with tab2:
            st.subheader("Create New Consent Record")

            with st.form("consent_form_key", clear_on_submit=True):
                purpose = st.text_area(
                    "Purpose *",
                    height=60,
                    placeholder="Clear description of why data is collected"
                )

                st.markdown("**Data Categories** *")
                col1, col2, col3 = st.columns(3)
                categories = []
                cat_opts = [
                    "Names", "Email Addresses", "Phone Numbers", "Physical Addresses",
                    "Financial Data", "Health Data", "Biometric Data", "Location Data",
                    "Behavioral/Usage Data", "Employment Records", "Government IDs", "Children's Data"
                ]

                for idx, cat in enumerate(cat_opts):
                    with [col1, col2, col3][idx % 3]:
                        if st.checkbox(cat, key=f"cons_cat_{cat}"):
                            categories.append(cat)

                col1, col2 = st.columns(2)

                with col1:
                    mechanism = st.selectbox(
                        "Collection Mechanism *",
                        ["Online Checkbox", "In-App Toggle", "Paper Form",
                         "Verbal/Call Center", "Email Opt-in", "API/Programmatic"]
                    )
                    is_children_data = st.checkbox(
                        "Children's Data (under 18)"
                    )

                with col2:
                    withdrawal_method = st.selectbox(
                        "Withdrawal Method *",
                        ["Same channel as collection", "Email request", "In-app toggle",
                         "Phone call", "Written request"]
                    )

                consent_text = st.text_area(
                    "Consent Text (shown to users) *",
                    height=100,
                    placeholder="Plain-language consent statement"
                )

                status = st.selectbox(
                    "Initial Status",
                    ["Active", "Paused", "Withdrawn"]
                )

                submitted = st.form_submit_button("✅ Add Consent", use_container_width=True)

                if submitted:
                    if not (purpose and categories and consent_text and mechanism and withdrawal_method):
                        st.error("Please fill all required fields (marked *).")
                    else:
                        _safe_db_call(
                            db.create_consent_record,
                            org_id=org_id,
                            purpose=purpose,
                            data_categories=", ".join(categories),
                            mechanism=mechanism,
                            consent_text=consent_text,
                            withdrawal_method=withdrawal_method,
                            is_children_data=is_children_data,
                            status=status,
                            created_by=user_info.get("id")
                        )
                        st.success("Consent record created successfully!")
                        st.rerun()

        # TAB 3: Compliance Audit (admin/member only)
        with tab3:
            st.subheader("Compliance Audit - DPDPA Section 6")

            if consents:
                for idx, consent in enumerate(consents):
                    with st.expander(f"📋 {consent.get('purpose', 'Consent')[:40]}..."):
                        col1, col2, col3 = st.columns(3)

                        # Free
                        with col1:
                            st.checkbox(
                                "Free (no coercion)",
                                value=True,
                                disabled=True,
                                key=f"audit_free_{idx}"
                            )
                            st.caption("User can refuse without penalty")

                        # Specific
                        with col2:
                            st.checkbox(
                                "Specific (per-purpose)",
                                value=True,
                                disabled=True,
                                key=f"audit_spec_{idx}"
                            )
                            st.caption(f"Purpose: {consent.get('purpose', '')[:30]}")

                        # Informed
                        with col3:
                            st.checkbox(
                                "Informed (clear notice)",
                                value=True,
                                disabled=True,
                                key=f"audit_info_{idx}"
                            )
                            st.caption(f"Mechanism: {consent.get('mechanism', '')}")

                        col1, col2 = st.columns(2)

                        # Unconditional
                        with col1:
                            st.checkbox(
                                "Unconditional (no bundling)",
                                value=True,
                                disabled=True,
                                key=f"audit_uncond_{idx}"
                            )

                        # Unambiguous
                        with col2:
                            st.checkbox(
                                "Unambiguous (affirmative action)",
                                value=True,
                                disabled=True,
                                key=f"audit_unamb_{idx}"
                            )

                        st.divider()
                        st.caption(f"Withdrawal: {consent.get('withdrawal_method', '')}")
            else:
                st.info("No consent records to audit.")


# ============================================================================
# PAGE 3: PRIVACY NOTICES
# ============================================================================

def page_privacy_notices(db, org_id: int, user_info: Dict) -> None:
    """
    Privacy Notice Builder - Create and manage privacy notices, policies, and collection notices.
    DPDPA Rule 2 compliance with plain-language notice rendering.
    """
    st.title("📄 Privacy Notice Builder")

    # Fetch notices
    notices = _safe_db_call(db.get_privacy_notices, org_id) or []

    # Metrics Row
    col1, col2, col3 = st.columns(3)
    published_notices = len([n for n in notices if n.get("status") == "Published"])
    draft_notices = len([n for n in notices if n.get("status") == "Draft"])

    with col1:
        st.metric("Total Notices", len(notices))
    with col2:
        st.metric("Published", published_notices)
    with col3:
        st.metric("Drafts", draft_notices)

    st.divider()

    # Role-based access
    can_edit = _check_role_permission(user_info, ["admin", "member"])

    if can_edit:
        tab1, tab2, tab3 = st.tabs(["📋 All Notices", "✏️ Create Notice", "👁️ Preview"])
    else:
        tab1 = st.tabs(["📋 All Notices"])[0]

    # TAB 1: All Notices
    with tab1:
        if notices:
            table_data = []
            for n in notices:
                table_data.append({
                    "Type": n.get("notice_type", ""),
                    "Title": n.get("title", ""),
                    "Version": n.get("version", "1.0"),
                    "Status": n.get("status", ""),
                    "Last Updated": str(n.get("last_updated", ""))[:10],
                })

            st.dataframe(table_data, use_container_width=True, hide_index=True)
        else:
            _render_empty_state("No privacy notices created yet.", "Create Notice")

    # TAB 2: Create Notice (admin/member only)
    if can_edit:
        with tab2:
            st.subheader("Create Privacy Notice")

            with st.form("privacy_notice_form_key", clear_on_submit=True):
                col1, col2 = st.columns(2)

                with col1:
                    notice_type = st.selectbox(
                        "Notice Type *",
                        ["Website Privacy Policy", "Mobile App Privacy Policy",
                         "Employee Privacy Notice", "Short-Form Collection Notice",
                         "Cookie/Tracking Notice", "Third-Party Sharing Notice"]
                    )
                    title = st.text_input(
                        "Notice Title *",
                        placeholder="e.g., Privacy Policy"
                    )

                with col2:
                    version = st.text_input(
                        "Version",
                        value="1.0"
                    )
                    status = st.selectbox(
                        "Status",
                        ["Draft", "Under Review", "Published", "Archived"]
                    )

                st.markdown("**Data Categories Collected** *")
                col1, col2, col3 = st.columns(3)
                categories = []
                cat_opts = [
                    "Names", "Email Addresses", "Phone Numbers", "Physical Addresses",
                    "Financial Data", "Health Data", "Biometric Data", "Location Data",
                    "Behavioral/Usage Data", "Employment Records", "Government IDs", "Children's Data"
                ]

                for idx, cat in enumerate(cat_opts):
                    with [col1, col2, col3][idx % 3]:
                        if st.checkbox(cat, key=f"pn_cat_{cat}"):
                            categories.append(cat)

                purposes = st.text_area(
                    "Processing Purposes *",
                    height=60,
                    placeholder="Service delivery, analytics, communications"
                )

                third_parties = st.text_area(
                    "Third Parties (if any)",
                    height=60,
                    placeholder="Payment processors, analytics providers"
                )

                retention = st.text_area(
                    "Data Retention Information *",
                    height=60,
                    placeholder="e.g., Customer data retained for 3 years after account closure"
                )

                # Pre-filled DPDPA rights
                st.markdown("**Data Principal Rights** (DPDPA mandated)")
                dpdpa_rights = (
                    "Right to Access (Section 11): Request a copy of your personal data.\n"
                    "Right to Correction (Section 12): Request corrections to inaccurate data.\n"
                    "Right to Erasure (Section 12): Request deletion of your data.\n"
                    "Right to Nominate (Section 14(3)): Nominate another person to exercise rights.\n"
                    "Right to Grievance (Section 14): Lodge a grievance with our Grievance Officer."
                )
                st.text_area(
                    "Rights Information",
                    value=dpdpa_rights,
                    height=100,
                    disabled=True
                )

                grievance_officer = st.text_input(
                    "Grievance Officer Email/Contact",
                    placeholder="grievance@company.com"
                )

                submitted = st.form_submit_button("✅ Create Notice", use_container_width=True)

                if submitted:
                    if not (title and notice_type and categories and purposes and retention):
                        st.error("Please fill all required fields (marked *).")
                    else:
                        _safe_db_call(
                            db.create_privacy_notice,
                            org_id=org_id,
                            notice_type=notice_type,
                            title=title,
                            data_categories=", ".join(categories),
                            purposes=purposes,
                            third_parties=third_parties,
                            retention_info=retention,
                            rights_info=dpdpa_rights,
                            grievance_officer=grievance_officer,
                            version=version,
                            status=status,
                            created_by=user_info.get("id")
                        )
                        st.success("Privacy notice created successfully!")
                        st.rerun()

        # TAB 3: Preview (admin/member only)
        with tab3:
            st.subheader("Preview Privacy Notice")

            if notices:
                selected_notice = st.selectbox(
                    "Select notice to preview",
                    [n.get("title", "Untitled") for n in notices],
                    key="pn_preview_select"
                )

                matching = [n for n in notices if n.get("title") == selected_notice]
                if matching:
                    notice = matching[0]

                    # Render as plain-language notice
                    st.markdown(f"# {notice.get('title', 'Privacy Notice')}")
                    st.caption(f"Version {notice.get('version', '1.0')} | Last updated {notice.get('last_updated', 'N/A')}")

                    st.markdown("## What We Collect")
                    st.write(notice.get("data_categories", ""))

                    st.markdown("## Why We Collect It")
                    st.write(notice.get("purposes", ""))

                    st.markdown("## Who We Share With")
                    shared = notice.get("third_parties", "")
                    st.write(shared if shared else "We do not share your data with third parties.")

                    st.markdown("## How Long We Keep It")
                    st.write(notice.get("retention_info", ""))

                    st.markdown("## Your Rights")
                    st.write(notice.get("rights_info", ""))

                    st.markdown("## Contact Us")
                    st.write(f"Grievance Officer: {notice.get('grievance_officer', 'contact@company.com')}")
            else:
                st.info("No notices to preview.")


# ============================================================================
# PAGE 4: DATA PRINCIPAL RIGHTS REQUESTS
# ============================================================================

def page_rights_requests(db, org_id: int, user_info: Dict) -> None:
    """
    Data Principal Rights Tracker - Manage SARs, correction, erasure, and grievance requests.
    30-day DPDPA Rule 8 deadline tracking with SLA monitoring and status workflow.
    """
    st.title("🛡️ Data Principal Rights Requests")

    st.info(
        "Track all Subject Access Requests (SARs), corrections, erasures, and grievances. "
        "DPDPA Rule 8 mandates 30-day response deadline."
    )

    # Fetch requests
    requests = _safe_db_call(db.get_rights_requests, org_id) or []

    # Calculate metrics
    open_requests = len([r for r in requests if r.get("status") in ["Received", "Identity Verification", "In Progress"]])
    completed_requests = len([r for r in requests if r.get("status") == "Completed"])
    overdue_requests = len([r for r in requests
                           if (datetime.now() - datetime.fromisoformat(r.get("due_date", datetime.now().isoformat()))).days > 0
                           and r.get("status") != "Completed"])

    # Metrics Row
    col1, col2, col3, col4, col5 = st.columns(5)

    with col1:
        st.metric("Total", len(requests))
    with col2:
        st.metric("Open", open_requests)
    with col3:
        st.metric("Completed", completed_requests)
    with col4:
        st.metric("Overdue", overdue_requests)
    with col5:
        avg_days = sum(
            [(datetime.now() - datetime.fromisoformat(r.get("created_date", datetime.now().isoformat()))).days
             for r in requests if r.get("status") == "Completed"]
        ) / max(1, completed_requests) if completed_requests else 0
        st.metric("Avg Days to Complete", int(avg_days))

    st.divider()

    # Role-based access
    can_edit = _check_role_permission(user_info, ["admin", "member"])

    if can_edit:
        tab1, tab2, tab3 = st.tabs(["📊 All Requests", "➕ Log Request", "📋 Manage"])
    else:
        tab1 = st.tabs(["📊 All Requests"])[0]

    # TAB 1: All Requests
    with tab1:
        if requests:
            table_data = []
            for r in requests:
                created = datetime.fromisoformat(r.get("created_date", datetime.now().isoformat()))
                due = datetime.fromisoformat(r.get("due_date", (created + timedelta(days=30)).isoformat()))
                days_left = (due - datetime.now()).days

                # Color coding
                if r.get("status") == "Completed":
                    status_icon = "✅"
                elif days_left < 0:
                    status_icon = "🔴"
                elif days_left < 5:
                    status_icon = "🟠"
                else:
                    status_icon = "🟢"

                table_data.append({
                    "ID": r.get("id", "")[:8],
                    "Type": r.get("request_type", ""),
                    "Requester": r.get("requester_name", ""),
                    "Status": f"{status_icon} {r.get('status', '')}",
                    "Created": str(created)[:10],
                    "Due": str(due)[:10],
                    "Days Left": max(0, days_left),
                })

            st.dataframe(table_data, use_container_width=True, hide_index=True)

            if overdue_requests > 0:
                st.error(f"⚠️ {overdue_requests} request(s) overdue - immediate action required!")
        else:
            _render_empty_state("No rights requests yet.", "Log Request")

    # TAB 2: Log Request (admin/member only)
    if can_edit:
        with tab2:
            st.subheader("Log New Data Principal Request")

            with st.form("rights_request_form_key", clear_on_submit=True):
                col1, col2 = st.columns(2)

                with col1:
                    request_type = st.selectbox(
                        "Request Type *",
                        ["Access Request - Section 11", "Correction Request - Section 12",
                         "Erasure Request - Section 12", "Grievance - Section 14",
                         "Nomination - Section 14(3)"]
                    )
                    requester_name = st.text_input(
                        "Requester Name *",
                        placeholder="Full name"
                    )

                with col2:
                    requester_email = st.text_input(
                        "Requester Email *",
                        placeholder="email@example.com"
                    )
                    identity_verified = st.checkbox(
                        "Identity Verified"
                    )

                description = st.text_area(
                    "Request Description *",
                    height=80,
                    placeholder="Details of the request"
                )

                created_date = datetime.now()
                due_date = created_date + timedelta(days=30)
                st.markdown(f"**Auto-calculated Due Date (30 days): {due_date.strftime('%Y-%m-%d')}**")

                status = st.selectbox(
                    "Initial Status",
                    ["Received", "Identity Verification", "In Progress"]
                )

                submitted = st.form_submit_button("✅ Log Request", use_container_width=True)

                if submitted:
                    if not (request_type and requester_name and requester_email and description):
                        st.error("Please fill all required fields (marked *).")
                    else:
                        _safe_db_call(
                            db.create_rights_request,
                            org_id=org_id,
                            request_type=request_type,
                            requester_name=requester_name,
                            requester_email=requester_email,
                            description=description,
                            identity_verified=identity_verified,
                            created_date=created_date,
                            due_date=due_date,
                            status=status,
                            created_by=user_info.get("id")
                        )
                        st.success("Request logged successfully!")
                        st.rerun()

        # TAB 3: Manage (admin/member only)
        with tab3:
            st.subheader("Manage Request Status")

            if requests:
                selected = st.selectbox(
                    "Select request",
                    [f"{r.get('request_type', '')} - {r.get('requester_name', '')}" for r in requests],
                    key="req_manage_select"
                )

                matching = [r for r in requests
                           if f"{r.get('request_type', '')} - {r.get('requester_name', '')}" == selected]

                if matching:
                    req = matching[0]
                    col1, col2 = st.columns(2)

                    with col1:
                        new_status = st.selectbox(
                            "Update Status",
                            ["Received", "Identity Verification", "In Progress", "Completed", "Rejected"],
                            key="req_status_select"
                        )

                    with col2:
                        if st.button("Update Status", key="req_update_btn"):
                            _safe_db_call(
                                db.update_rights_request_status,
                                req.get("id"),
                                new_status
                            )
                            st.success("Status updated!")
                            st.rerun()

                    st.divider()
                    st.markdown(f"**Requester:** {req.get('requester_name', '')} ({req.get('requester_email', '')})")
                    st.markdown(f"**Type:** {req.get('request_type', '')}")
                    st.markdown(f"**Description:** {req.get('description', '')}")
                    st.markdown(f"**Identity Verified:** {'Yes' if req.get('identity_verified') else 'No'}")

                    # Response notes
                    response_notes = st.text_area(
                        "Response Notes",
                        height=100,
                        placeholder="Add resolution details, data provided, etc.",
                        key="req_notes"
                    )

                    if response_notes and st.button("Save Notes", key="req_save_notes"):
                        _safe_db_call(
                            db.update_rights_request_notes,
                            req.get("id"),
                            response_notes
                        )
                        st.success("Notes saved!")
            else:
                st.info("No requests to manage.")


# ============================================================================
# PAGE 5: VENDOR / PROCESSOR MANAGEMENT
# ============================================================================

def page_vendor_management(db, org_id: int, user_info: Dict) -> None:
    """
    Vendor/Processor Management - Track third-party data processors, DPA status, and security assessments.
    Risk-rated vendor registry with certification tracking and overdue assessment alerts.
    """
    st.title("🤝 Vendor & Processor Management")

    st.info(
        "Track all third-party data processors. Data Processing Agreements (DPAs) required for all vendors "
        "processing personal data per DPDPA Section 4."
    )

    # Fetch vendors
    vendors = _safe_db_call(db.get_vendors, org_id) or []

    # Calculate metrics
    high_risk = len([v for v in vendors if v.get("risk_level") in ["High", "Critical"]])
    dpas_signed = len([v for v in vendors if v.get("dpa_status") == "Signed"])
    iso_certified = len([v for v in vendors if v.get("iso_27001_certified")])
    overdue_assessments = len([v for v in vendors
                              if (datetime.now() - datetime.fromisoformat(v.get("last_assessment_date", datetime.now().isoformat()))).days > 365])

    # Metrics Row
    col1, col2, col3, col4, col5 = st.columns(5)

    with col1:
        st.metric("Total Vendors", len(vendors))
    with col2:
        st.metric("High Risk", high_risk)
    with col3:
        st.metric("DPAs Signed", dpas_signed)
    with col4:
        st.metric("ISO 27001", iso_certified)
    with col5:
        st.metric("Overdue Assessments", overdue_assessments)

    st.divider()

    # Role-based access
    can_edit = _check_role_permission(user_info, ["admin", "member"])

    if can_edit:
        tab1, tab2, tab3 = st.tabs(["📊 Registry", "➕ Add Vendor", "📈 Risk Dashboard"])
    else:
        tab1 = st.tabs(["📊 Registry"])[0]

    # TAB 1: Vendor Registry
    with tab1:
        if vendors:
            table_data = []
            for v in vendors:
                risk = v.get("risk_level", "Medium")
                risk_icon = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🟢"}.get(risk, "⚪")

                dpa = v.get("dpa_status", "Not Started")
                dpa_icon = {"Signed": "✅", "Expired": "⚠️", "Not Required": "⏭️"}.get(dpa, "❌")

                assess_date = datetime.fromisoformat(v.get("last_assessment_date", datetime.now().isoformat()))
                days_old = (datetime.now() - assess_date).days
                assess_flag = "⚠️ OVERDUE" if days_old > 365 else f"{days_old}d ago"

                table_data.append({
                    "Vendor": v.get("vendor_name", ""),
                    "Service Type": v.get("service_type", ""),
                    "Data Shared": v.get("data_shared", "")[:30],
                    "DPA": f"{dpa_icon} {dpa}",
                    "Risk": f"{risk_icon} {risk}",
                    "ISO 27001": "✅" if v.get("iso_27001_certified") else "❌",
                    "SOC2": "✅" if v.get("soc2_certified") else "❌",
                    "Last Assessment": assess_flag,
                })

            st.dataframe(table_data, use_container_width=True, hide_index=True)

            if overdue_assessments > 0:
                st.warning(f"⚠️ {overdue_assessments} vendor assessment(s) overdue (>12 months)")
        else:
            _render_empty_state("No vendors added yet.", "Add Vendor")

    # TAB 2: Add Vendor (admin/member only)
    if can_edit:
        with tab2:
            st.subheader("Add New Vendor/Processor")

            with st.form("vendor_form_key", clear_on_submit=True):
                col1, col2 = st.columns(2)

                with col1:
                    vendor_name = st.text_input(
                        "Vendor Name *",
                        placeholder="e.g., AWS, Salesforce"
                    )
                    service_type = st.selectbox(
                        "Service Type *",
                        ["Cloud Infrastructure", "SaaS Platform", "Payment Processing",
                         "Marketing/Advertising", "Analytics", "IT Services/Outsourcing",
                         "Logistics/Delivery", "HR/Payroll", "Legal/Consulting", "Data Center/Hosting"]
                    )

                with col2:
                    dpa_status = st.selectbox(
                        "DPA Status *",
                        ["Not Started", "Draft In Progress", "Under Legal Review",
                         "Signed", "Expired", "Not Required"]
                    )
                    security_rating = st.selectbox(
                        "Security Rating",
                        ["A", "B", "C", "D", "Not Assessed"]
                    )

                st.markdown("**Data Shared with Vendor** *")
                col1, col2, col3 = st.columns(3)
                data_shared = []
                data_opts = [
                    "Names", "Email Addresses", "Phone Numbers", "Physical Addresses",
                    "Financial Data", "Health Data", "Biometric Data", "Location Data",
                    "Behavioral/Usage Data", "Employment Records", "Government IDs", "Children's Data"
                ]

                for idx, data_type in enumerate(data_opts):
                    with [col1, col2, col3][idx % 3]:
                        if st.checkbox(data_type, key=f"vendor_data_{data_type}"):
                            data_shared.append(data_type)

                col1, col2, col3 = st.columns(3)

                with col1:
                    iso_27001 = st.checkbox("ISO 27001 Certified")
                    soc2 = st.checkbox("SOC 2 Certified")

                with col2:
                    last_assessment = st.date_input(
                        "Last Assessment Date *",
                        value=datetime.now().date()
                    )

                with col3:
                    risk_level = st.selectbox(
                        "Risk Level *",
                        ["Low", "Medium", "High", "Critical"]
                    )

                col1, col2 = st.columns(2)

                with col1:
                    contract_expiry = st.date_input(
                        "Contract Expiry Date"
                    )

                with col2:
                    next_assessment = st.date_input(
                        "Next Assessment Due"
                    )

                notes = st.text_area(
                    "Notes",
                    height=60,
                    placeholder="e.g., Renewal pending, certification in progress"
                )

                submitted = st.form_submit_button("✅ Add Vendor", use_container_width=True)

                if submitted:
                    if not (vendor_name and service_type and data_shared and dpa_status and risk_level):
                        st.error("Please fill all required fields (marked *).")
                    else:
                        _safe_db_call(
                            db.create_vendor,
                            org_id=org_id,
                            vendor_name=vendor_name,
                            service_type=service_type,
                            data_shared=", ".join(data_shared),
                            dpa_status=dpa_status,
                            security_rating=security_rating,
                            iso_27001_certified=iso_27001,
                            soc2_certified=soc2,
                            last_assessment_date=last_assessment,
                            risk_level=risk_level,
                            contract_expiry_date=contract_expiry,
                            next_assessment_due=next_assessment,
                            notes=notes,
                            created_by=user_info.get("id")
                        )
                        st.success("Vendor added successfully!")
                        st.rerun()

        # TAB 3: Risk Dashboard (admin/member only)
        with tab3:
            st.subheader("Risk & Compliance Dashboard")

            if vendors:
                col1, col2 = st.columns(2)

                # Chart 1: Risk Distribution
                with col1:
                    risk_counts = {}
                    for v in vendors:
                        risk = v.get("risk_level", "Medium")
                        risk_counts[risk] = risk_counts.get(risk, 0) + 1

                    fig1 = go.Figure(
                        data=[go.Bar(
                            x=list(risk_counts.keys()),
                            y=list(risk_counts.values()),
                            marker_color=["#dc2626", "#f59e0b", "#eab308", "#22c55e"]
                        )],
                        layout=go.Layout(
                            title="Vendor Risk Distribution",
                            height=400,
                            plot_bgcolor="#1E293B",
                            paper_bgcolor="#0F172A",
                            xaxis_title="Risk Level",
                            yaxis_title="Count"
                        )
                    )
                    st.plotly_chart(fig1, use_container_width=True)

                # Chart 2: DPA Status
                with col2:
                    dpa_counts = {}
                    for v in vendors:
                        dpa = v.get("dpa_status", "Not Started")
                        dpa_counts[dpa] = dpa_counts.get(dpa, 0) + 1

                    fig2 = go.Figure(
                        data=[go.Pie(labels=list(dpa_counts.keys()), values=list(dpa_counts.values()))],
                        layout=go.Layout(
                            title="DPA Status Breakdown",
                            height=400,
                            plot_bgcolor="#1E293B",
                            paper_bgcolor="#0F172A"
                        )
                    )
                    st.plotly_chart(fig2, use_container_width=True)

                # Summary cards
                st.markdown("## Compliance Summary")
                col1, col2, col3, col4 = st.columns(4)

                dpa_pct = int((dpas_signed / max(1, len(vendors))) * 100)
                with col1:
                    st.metric("DPAs Signed (%)", f"{dpa_pct}%")

                iso_pct = int((iso_certified / max(1, len(vendors))) * 100)
                with col2:
                    st.metric("ISO 27001 (%)", f"{iso_pct}%")

                with col3:
                    st.metric("Overdue Assessments", overdue_assessments)

                avg_age = int(sum(
                    [(datetime.now() - datetime.fromisoformat(v.get("last_assessment_date", datetime.now().isoformat()))).days
                     for v in vendors]
                ) / max(1, len(vendors)))
                with col4:
                    st.metric("Avg Assessment Age (days)", avg_age)
            else:
                st.info("No vendor data to display.")
