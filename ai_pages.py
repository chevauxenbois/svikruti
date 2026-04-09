"""
Svikruti.ai - AI-Powered DPDPA Compliance Pages
Production-grade AI features for document generation, breach analysis, compliance advisement,
and intelligent privacy reviews. Integrates with AIEngine for advanced language model capabilities.

Features:
- AI Chatbot: Conversational DPDPA guidance
- Smart Document Drafter: Auto-generate compliance documents
- Gap Assessment Advisor: AI-powered remediation recommendations
- Breach Classifier: Intelligent breach assessment and response drafting
- Privacy Notice Reviewer: AI-driven privacy policy analysis
- AI Configuration: Settings management for LLM providers

Author: Harsh Kahate
Version: 0.1.0
"""

import streamlit as st
from typing import Optional, Dict, List, Any
from datetime import datetime
import json

try:
    import plotly.graph_objects as go
    PLOTLY_AVAILABLE = True
except ImportError:
    PLOTLY_AVAILABLE = False


# ============================================================================
# UTILITY FUNCTIONS & HELPERS
# ============================================================================

def _check_role_permission(user_info: Dict, required_roles: List[str]) -> bool:
    """Check if user has permission for an action based on role."""
    return user_info.get("role") in required_roles


def _safe_db_call(func, *args, **kwargs):
    """Safely call database functions with error handling."""
    try:
        return func(*args, **kwargs)
    except Exception as e:
        st.error(f"Database error: {str(e)}")
        return None


def _get_ai_engine(db, org_id: int):
    """
    Helper function to initialize AIEngine with org settings.
    Returns None with warning if AI is not configured.

    Args:
        db: Database instance
        org_id: Organization ID

    Returns:
        AIEngine instance or None
    """
    try:
        from ai_engine import AIEngine, get_ai_settings

        settings = get_ai_settings(db, org_id)
        if not settings or not settings.get("api_key"):
            # Styled card for unconfigured AI
            st.markdown("""
            <div style="
                background: linear-gradient(135deg, rgba(20, 184, 166, 0.1), rgba(59, 130, 246, 0.1));
                border: 1px solid rgba(20, 184, 166, 0.3);
                border-radius: 12px;
                padding: 24px;
                margin: 16px 0;
            ">
                <div style="display: flex; align-items: center; gap: 16px;">
                    <div style="font-size: 32px;">⚙️</div>
                    <div>
                        <p style="margin: 0; font-weight: 600; color: #14B8A6;">AI Configuration Required</p>
                        <p style="margin: 8px 0 0 0; color: #9CA3AF; font-size: 14px;">
                            Please configure your AI settings first to use this feature.
                        </p>
                    </div>
                </div>
            </div>
            """, unsafe_allow_html=True)
            return None

        ai = AIEngine(
            db=db,
            org_id=org_id,
            provider=settings.get("provider", "openai"),
            api_key=settings.get("api_key"),
            model=settings.get("model", "gpt-4o-mini")
        )
        return ai
    except ImportError:
        st.error("AIEngine module not available")
        return None
    except Exception as e:
        st.error(f"Failed to initialize AI: {str(e)}")
        return None


def _get_org_context(db, org_id: int) -> Dict[str, Any]:
    """
    Gather organization context for AI personalization.

    Args:
        db: Database instance
        org_id: Organization ID

    Returns:
        Dictionary with org details
    """
    try:
        org = _safe_db_call(db.get_organization, org_id) or {}
        return {
            "org_name": org.get("org_name", ""),
            "industry": org.get("industry", ""),
            "size": org.get("org_size", ""),
            "sdf_status": org.get("sdf_status", ""),
            "compliance_level": org.get("compliance_level", "")
        }
    except Exception:
        return {}


def _render_styled_header(title: str, subtitle: str = "") -> None:
    """Render a clean styled HTML header."""
    st.markdown(f"""
    <div style="margin-bottom: 32px;">
        <h1 style="
            font-size: 32px;
            font-weight: 700;
            margin: 0 0 8px 0;
            color: #F5F5F5;
        ">{title}</h1>
        {f'<p style="margin: 0; color: #9CA3AF; font-size: 16px;">{subtitle}</p>' if subtitle else ''}
    </div>
    """, unsafe_allow_html=True)


def _render_glass_container(content_func, title: str = "") -> None:
    """Render content in a glass-morphism container."""
    st.markdown(f"""
    <div style="
        background: rgba(17, 24, 39, 0.7);
        backdrop-filter: blur(10px);
        border: 1px solid rgba(20, 184, 166, 0.2);
        border-radius: 12px;
        padding: 24px;
        margin: 16px 0;
    ">
    """, unsafe_allow_html=True)

    if title:
        st.markdown(f"#### {title}")

    content_func()

    st.markdown("</div>", unsafe_allow_html=True)


# ============================================================================
# PAGE 1: AI CHATBOT
# ============================================================================

def page_ai_chatbot(db, org_id: int, user_info: Dict) -> None:
    """
    DPDPA AI Assistant - Conversational AI for compliance questions.

    Provides personalized guidance based on organization context.
    Maintains chat history and suggests common questions.

    Args:
        db: Database instance
        org_id: Organization ID
        user_info: Current user information
    """
    _render_styled_header("DPDPA AI Assistant", "Ask me anything about DPDPA compliance, data protection, and best practices")

    # Initialize AI
    ai_engine = _get_ai_engine(db, org_id)
    if not ai_engine:
        return

    # Get org context for personalization
    org_context = _get_org_context(db, org_id)

    # Initialize chat history in session state
    if "ai_chat_history" not in st.session_state:
        st.session_state.ai_chat_history = []

    # Sidebar controls
    with st.sidebar:
        st.subheader("Chat Controls")
        if st.button("🗑️ Clear Chat History", use_container_width=True):
            st.session_state.ai_chat_history = []
            st.rerun()

        st.divider()
        st.subheader("Suggested Questions")

        suggestions = [
            "What is a Significant Data Fiduciary (SDF)?",
            "What are the penalties under DPDPA?",
            "How do I handle a data breach?",
            "What consent requirements apply to me?",
            "What is the DPIA process?",
            "How long can I retain personal data?"
        ]

        for i, suggestion in enumerate(suggestions):
            if st.button(suggestion, key=f"suggest_{i}", use_container_width=True):
                st.session_state.ai_chat_history.append({
                    "role": "user",
                    "content": suggestion
                })
                st.rerun()

    # Display chat history with styled messages
    for message in st.session_state.ai_chat_history:
        if message["role"] == "user":
            # User message - right aligned with blue background
            st.markdown(f"""
            <div style="display: flex; justify-content: flex-end; margin: 12px 0;">
                <div style="
                    background: linear-gradient(135deg, rgba(59, 130, 246, 0.2), rgba(99, 102, 241, 0.2));
                    border: 1px solid rgba(59, 130, 246, 0.3);
                    border-radius: 12px;
                    padding: 12px 16px;
                    max-width: 80%;
                    word-wrap: break-word;
                    color: #F5F5F5;
                ">
                    {message['content']}
                </div>
            </div>
            """, unsafe_allow_html=True)
        else:
            # Assistant message - left aligned with teal accent
            st.markdown(f"""
            <div style="display: flex; justify-content: flex-start; margin: 12px 0;">
                <div style="
                    background: rgba(17, 24, 39, 0.8);
                    border-left: 4px solid #14B8A6;
                    border-radius: 8px;
                    padding: 12px 16px;
                    max-width: 80%;
                    word-wrap: break-word;
                    color: #F5F5F5;
                ">
                    {message['content']}
                </div>
            </div>
            """, unsafe_allow_html=True)

    # Chat input
    user_input = st.chat_input("Ask your DPDPA question...")

    if user_input:
        # Add user message to history
        st.session_state.ai_chat_history.append({
            "role": "user",
            "content": user_input
        })

        # Get AI response
        with st.spinner("Thinking..."):
            try:
                # Prepare context message
                context_msg = f"""
You are a DPDPA compliance expert. The user is from {org_context.get('org_name', 'an organization')}
in the {org_context.get('industry', 'general')} industry with {org_context.get('size', 'unknown')} employees.
SDF Status: {org_context.get('sdf_status', 'Unknown')}.
Provide personalized, accurate, and actionable guidance.
"""

                messages = [
                    {"role": "system", "content": context_msg},
                    *st.session_state.ai_chat_history
                ]

                response = ai_engine.chat_completion(messages)

                if response:
                    st.session_state.ai_chat_history.append({
                        "role": "assistant",
                        "content": response
                    })
                    st.rerun()
                else:
                    st.error("Failed to get response from AI.")
            except Exception as e:
                st.error(f"Error: {str(e)}")


# ============================================================================
# PAGE 2: SMART DOCUMENT DRAFTER
# ============================================================================

def page_smart_doc_drafter(db, org_id: int, user_info: Dict) -> None:
    """
    AI Document Drafter - Auto-generate DPDPA compliance documents.

    Fetches org data and uses AI to draft tailored documents.
    Supports Privacy Policy, DPA, Consent Notice, Breach Notification, etc.

    Args:
        db: Database instance
        org_id: Organization ID
        user_info: Current user information
    """
    # Role check
    if not _check_role_permission(user_info, ["admin", "member"]):
        st.error("This feature is available to admins and members only.")
        return

    _render_styled_header("AI Document Drafter", "Generate compliance documents tailored to your organization using AI")

    # Initialize AI
    ai_engine = _get_ai_engine(db, org_id)
    if not ai_engine:
        return

    # Document type selection
    doc_types = {
        "privacy_policy": "Privacy Policy",
        "dpa": "Data Processing Agreement",
        "consent_notice": "Consent Notice",
        "breach_notification": "Breach Notification Letter",
        "dpia_report": "DPIA Report",
        "ropa_summary": "RoPA Summary",
        "grievance_policy": "Grievance Policy"
    }

    selected_doc_type = st.selectbox(
        "Select Document Type *",
        options=list(doc_types.keys()),
        format_func=lambda x: doc_types[x],
        key="doc_drafter_type"
    )

    st.divider()

    # Generate button
    col1, col2 = st.columns([3, 1])
    with col2:
        generate_btn = st.button("Generate", use_container_width=True)

    if generate_btn:
        with st.spinner("Generating document..."):
            try:
                # Fetch org data for context
                org_data = {
                    "org_info": _safe_db_call(db.get_organization, org_id) or {},
                    "ropa_entries": _safe_db_call(db.get_ropa_entries, org_id) or [],
                    "consent_records": _safe_db_call(db.get_consent_records, org_id) or [],
                    "vendors": _safe_db_call(db.get_vendors, org_id) or [],
                    "privacy_notices": _safe_db_call(db.get_privacy_notices, org_id) or []
                }

                # Generate document using AI
                generated_content = ai_engine.draft_document(
                    doc_type=selected_doc_type,
                    org_data=org_data
                )

                if generated_content:
                    st.success("Document generated successfully!")

                    # Display document
                    st.markdown("---")
                    st.markdown(generated_content)
                    st.markdown("---")

                    # Action buttons
                    col1, col2, col3 = st.columns(3)

                    with col1:
                        if st.button("Copy to Clipboard"):
                            st.write("Copy the text above manually or use Ctrl+A")

                    with col2:
                        if st.button("Download as Text"):
                            st.download_button(
                                label="Download",
                                data=generated_content,
                                file_name=f"{selected_doc_type}_{datetime.now().strftime('%Y%m%d')}.txt",
                                mime="text/plain"
                            )

                    with col3:
                        if st.button("Save to Organization"):
                            try:
                                _safe_db_call(
                                    db.save_document,
                                    org_id=org_id,
                                    doc_type=selected_doc_type,
                                    content=generated_content,
                                    created_by=user_info.get("id"),
                                    generated_by_ai=True
                                )
                                st.success("Document saved!")
                            except Exception as e:
                                st.error(f"Failed to save: {str(e)}")
                else:
                    st.error("Failed to generate document.")
            except Exception as e:
                st.error(f"Error: {str(e)}")


# ============================================================================
# PAGE 3: GAP ASSESSMENT ADVISOR
# ============================================================================

def page_gap_assessment_advisor(db, org_id: int, user_info: Dict) -> None:
    """
    AI Compliance Advisor - AI-powered gap assessment analysis.

    Analyzes completed gap assessments and provides prioritized remediation
    recommendations using AI.

    Args:
        db: Database instance
        org_id: Organization ID
        user_info: Current user information
    """
    _render_styled_header("AI Compliance Advisor", "Get AI-powered recommendations to close compliance gaps")

    # Initialize AI
    ai_engine = _get_ai_engine(db, org_id)
    if not ai_engine:
        return

    # Check if assessment has been completed
    assessment = _safe_db_call(db.get_latest_assessment, org_id)

    if not assessment:
        st.markdown("""
        <div style="
            background: linear-gradient(135deg, rgba(20, 184, 166, 0.1), rgba(59, 130, 246, 0.1));
            border: 1px solid rgba(20, 184, 166, 0.3);
            border-radius: 12px;
            padding: 24px;
            margin: 16px 0;
        ">
            <div style="display: flex; align-items: center; gap: 16px;">
                <div style="font-size: 32px;">📋</div>
                <div>
                    <p style="margin: 0; font-weight: 600; color: #14B8A6;">Complete Assessment First</p>
                    <p style="margin: 8px 0 0 0; color: #9CA3AF; font-size: 14px;">
                        Go to the Gap Assessment page and complete the assessment to get AI-powered recommendations.
                    </p>
                </div>
            </div>
        </div>
        """, unsafe_allow_html=True)
        return

    # Display current scores
    st.subheader("Current Compliance Scores")

    try:
        assessment_responses = _safe_db_call(db.get_assessment_responses, org_id) or {}

        if assessment_responses:
            # Calculate scores by category
            scores = {}
            for category, responses in assessment_responses.items():
                yes_count = sum(1 for r in responses if r.get("answer") == "Yes")
                total = len(responses)
                score = (yes_count / total * 100) if total > 0 else 0
                scores[category] = score

            # Display score metrics
            col1, col2, col3 = st.columns(3)

            overall_score = sum(scores.values()) / len(scores) if scores else 0

            with col1:
                st.metric("Overall Compliance", f"{overall_score:.0f}%")
            with col2:
                st.metric("Categories", len(scores))
            with col3:
                st.metric("Average Gap", f"{100-overall_score:.0f}%")

            # Score breakdown
            st.subheader("Scores by Category")
            score_df = []
            for category, score in sorted(scores.items(), key=lambda x: x[1]):
                score_df.append({
                    "Category": category,
                    "Score": f"{score:.0f}%",
                    "Gap": f"{100-score:.0f}%"
                })

            st.dataframe(score_df, use_container_width=True, hide_index=True)

            st.divider()

            # AI Analysis button
            if st.button("Get AI Analysis & Recommendations", use_container_width=True):
                with st.spinner("Analyzing gaps and generating recommendations..."):
                    try:
                        recommendations = ai_engine.analyze_gap_assessment(
                            scores=scores,
                            responses=assessment_responses
                        )

                        if recommendations:
                            st.session_state.gap_analysis_cache = recommendations
                            st.rerun()
                        else:
                            st.error("Failed to generate recommendations.")
                    except Exception as e:
                        st.error(f"Error: {str(e)}")

            # Display cached analysis if available
            if "gap_analysis_cache" in st.session_state:
                analysis = st.session_state.gap_analysis_cache

                st.subheader("AI Recommendations")

                # Try to parse recommendations if JSON
                try:
                    if isinstance(analysis, str):
                        analysis = json.loads(analysis)
                except json.JSONDecodeError:
                    pass

                # Display as expandable sections
                if isinstance(analysis, dict):
                    for category, details in analysis.items():
                        with st.expander(f"📌 {category}", expanded=False):
                            st.write(details)
                else:
                    st.markdown(analysis)

    except Exception as e:
        st.error(f"Error: {str(e)}")


# ============================================================================
# PAGE 4: BREACH CLASSIFIER
# ============================================================================

def page_breach_classifier(db, org_id: int, user_info: Dict) -> None:
    """
    AI Breach Analyzer - Intelligent data breach assessment and response.

    Classifies breaches by severity and generates notification drafts.
    Handles both new and existing breach incidents.

    Args:
        db: Database instance
        org_id: Organization ID
        user_info: Current user information
    """
    # Role check
    if not _check_role_permission(user_info, ["admin", "member"]):
        st.error("This feature is available to admins and members only.")
        return

    _render_styled_header("AI Breach Analyzer", "Analyze data breaches and generate required notifications")

    # Initialize AI
    ai_engine = _get_ai_engine(db, org_id)
    if not ai_engine:
        return

    # Tabs for new vs existing breach
    tab1, tab2 = st.tabs(["Analyze New Breach", "Analyze Existing Breach"])

    # TAB 1: New Breach Analysis
    with tab1:
        st.subheader("Report New Data Breach")

        with st.form("breach_form_new"):
            # Basic info
            col1, col2 = st.columns(2)

            with col1:
                description = st.text_area(
                    "Breach Description *",
                    height=150,
                    placeholder="Describe what happened, how it was discovered, etc."
                )
                discovery_date = st.date_input("Discovery Date *")

            with col2:
                affected_count = st.number_input(
                    "Estimated Records Affected *",
                    min_value=1,
                    value=100
                )

                data_categories = st.multiselect(
                    "Data Categories Affected *",
                    [
                        "Names", "Email Addresses", "Phone Numbers", "Physical Addresses",
                        "Financial Data", "Health Data", "Biometric Data", "Location Data",
                        "Employment Records", "Government IDs", "Passwords/Authentication"
                    ]
                )

            st.divider()

            # Additional context
            col1, col2 = st.columns(2)
            with col1:
                cause = st.text_input(
                    "Probable Cause (optional)",
                    placeholder="e.g., Unauthorized access, ransomware, etc."
                )

            with col2:
                containment_status = st.selectbox(
                    "Containment Status",
                    ["Ongoing", "Contained", "Fully Resolved"]
                )

            submitted = st.form_submit_button("Classify & Generate Response", use_container_width=True)

        if submitted:
            if not (description and data_categories and affected_count and discovery_date):
                st.error("Please fill all required fields (marked *).")
            else:
                with st.spinner("Analyzing breach..."):
                    try:
                        analysis = ai_engine.classify_breach(
                            description=description,
                            data_categories=", ".join(data_categories),
                            affected_count=affected_count
                        )

                        if analysis:
                            st.session_state.breach_analysis = analysis
                            st.rerun()
                    except Exception as e:
                        st.error(f"Error: {str(e)}")

    # TAB 2: Analyze Existing Breach
    with tab2:
        st.subheader("Select Existing Breach Incident")

        breaches = _safe_db_call(db.get_breach_incidents, org_id) or []

        if breaches:
            breach_options = {b.get("id", i): b.get("description", "Breach")[:50]
                            for i, b in enumerate(breaches)}

            selected_breach_id = st.selectbox(
                "Select Breach",
                options=list(breach_options.keys()),
                format_func=lambda x: breach_options[x]
            )

            if st.button("Analyze Selected Breach"):
                selected = next((b for b in breaches if b.get("id") == selected_breach_id), None)

                if selected:
                    with st.spinner("Analyzing breach..."):
                        try:
                            analysis = ai_engine.classify_breach(
                                description=selected.get("description", ""),
                                data_categories=selected.get("data_categories", ""),
                                affected_count=selected.get("affected_records", 0)
                            )

                            if analysis:
                                st.session_state.breach_analysis = analysis
                                st.rerun()
                        except Exception as e:
                            st.error(f"Error: {str(e)}")
        else:
            st.markdown("""
            <div style="
                background: rgba(17, 24, 39, 0.8);
                border: 1px solid rgba(107, 114, 128, 0.3);
                border-radius: 12px;
                padding: 24px;
                margin: 16px 0;
                text-align: center;
            ">
                <p style="margin: 0; color: #9CA3AF; font-size: 16px;">
                    No breach incidents recorded yet.
                </p>
            </div>
            """, unsafe_allow_html=True)

    # Display analysis results
    if "breach_analysis" in st.session_state:
        analysis = st.session_state.breach_analysis

        st.divider()
        st.subheader("Breach Analysis Results")

        # Parse analysis if needed
        try:
            if isinstance(analysis, str):
                analysis = json.loads(analysis)
        except json.JSONDecodeError:
            pass

        # Display results
        if isinstance(analysis, dict):
            # Severity badge with color-coded card
            severity = analysis.get("severity", "Medium").upper()

            severity_colors = {
                "CRITICAL": ("#EF4444", "#DC2626", "🔴"),
                "HIGH": ("#F97316", "#EA580C", "🟠"),
                "MEDIUM": ("#FBBF24", "#F59E0B", "🟡"),
                "LOW": ("#4ADE80", "#22C55E", "🟢")
            }

            bg_color, border_color, emoji = severity_colors.get(severity, ("#9CA3AF", "#6B7280", "⚪"))

            st.markdown(f"""
            <div style="
                background: linear-gradient(135deg, rgba({int(bg_color[1:3], 16)}, {int(bg_color[3:5], 16)}, {int(bg_color[5:7], 16)}, 0.1), rgba({int(bg_color[1:3], 16)}, {int(bg_color[3:5], 16)}, {int(bg_color[5:7], 16)}, 0.05));
                border: 2px solid {border_color};
                border-radius: 12px;
                padding: 20px;
                margin: 16px 0;
                text-align: center;
            ">
                <div style="font-size: 32px; margin-bottom: 8px;">{emoji}</div>
                <p style="margin: 0; font-size: 24px; font-weight: 700; color: {border_color};">
                    {severity} Severity
                </p>
            </div>
            """, unsafe_allow_html=True)

            st.divider()

            # Risk assessment
            with st.expander("Risk Assessment", expanded=True):
                st.write(analysis.get("risk_assessment", "No risk assessment available"))

            # DPB Notification draft
            with st.expander("DPB Notification Draft"):
                st.markdown(analysis.get("dpb_notification", "No notification draft available"))

            # Data Principal Notification draft
            with st.expander("Data Principal Notification Draft"):
                st.markdown(analysis.get("principal_notification", "No notification draft available"))

            # Recommended actions
            with st.expander("Recommended Actions"):
                actions = analysis.get("actions", "No actions listed")
                if isinstance(actions, list):
                    for i, action in enumerate(actions, 1):
                        st.write(f"{i}. {action}")
                else:
                    st.write(actions)
        else:
            st.markdown(analysis)


# ============================================================================
# PAGE 5: PRIVACY NOTICE REVIEWER
# ============================================================================

def page_privacy_notice_reviewer(db, org_id: int, user_info: Dict) -> None:
    """
    AI Privacy Notice Reviewer - Analyze and improve privacy notices.

    Reviews privacy policies for DPDPA compliance and provides improvement
    suggestions and readability scores.

    Args:
        db: Database instance
        org_id: Organization ID
        user_info: Current user information
    """
    _render_styled_header("AI Privacy Notice Reviewer", "Get AI feedback on your privacy policy or notice")

    # Initialize AI
    ai_engine = _get_ai_engine(db, org_id)
    if not ai_engine:
        return

    # Input method selection
    input_method = st.radio(
        "How would you like to provide the notice?",
        ["Paste Text", "Select Existing Notice"],
        horizontal=True
    )

    notice_text = None

    if input_method == "Paste Text":
        notice_text = st.text_area(
            "Privacy Notice Text *",
            height=300,
            placeholder="Paste your privacy policy or notice here..."
        )
    else:
        notices = _safe_db_call(db.get_privacy_notices, org_id) or []

        if notices:
            notice_options = {n.get("id", i): n.get("title", "Notice")
                            for i, n in enumerate(notices)}

            selected_notice_id = st.selectbox(
                "Select Notice",
                options=list(notice_options.keys()),
                format_func=lambda x: notice_options[x]
            )

            selected = next((n for n in notices if n.get("id") == selected_notice_id), None)
            if selected:
                notice_text = selected.get("content", "")
        else:
            st.markdown("""
            <div style="
                background: rgba(17, 24, 39, 0.8);
                border: 1px solid rgba(107, 114, 128, 0.3);
                border-radius: 12px;
                padding: 24px;
                margin: 16px 0;
                text-align: center;
            ">
                <p style="margin: 0; color: #9CA3AF; font-size: 16px;">
                    No privacy notices found. Create one first or paste text above.
                </p>
            </div>
            """, unsafe_allow_html=True)

    # Review button
    if st.button("Review Notice", use_container_width=True):
        if not notice_text:
            st.error("Please provide a privacy notice to review.")
        else:
            with st.spinner("Reviewing notice..."):
                try:
                    review = ai_engine.review_privacy_notice(notice_text)

                    if review:
                        st.session_state.notice_review = review
                        st.rerun()
                except Exception as e:
                    st.error(f"Error: {str(e)}")

    # Display review results
    if "notice_review" in st.session_state:
        review = st.session_state.notice_review

        st.divider()
        st.subheader("Review Results")

        # Parse review if needed
        try:
            if isinstance(review, str):
                review = json.loads(review)
        except json.JSONDecodeError:
            pass

        if isinstance(review, dict):
            # Overall score with visual gauge indicators
            col1, col2, col3 = st.columns(3)

            overall = review.get("overall_score", 0)
            readability = review.get("readability_score", 0)
            compliance = review.get("compliance_score", 0)

            def render_gauge(label: str, score: int, color: str) -> None:
                """Render a visual gauge indicator."""
                st.markdown(f"""
                <div style="text-align: center; padding: 12px;">
                    <p style="margin: 0 0 12px 0; color: #9CA3AF; font-size: 14px;">{label}</p>
                    <div style="
                        background: rgba(107, 114, 128, 0.2);
                        border-radius: 50%;
                        width: 80px;
                        height: 80px;
                        margin: 0 auto;
                        display: flex;
                        align-items: center;
                        justify-content: center;
                        border: 3px solid {color};
                    ">
                        <span style="font-size: 28px; font-weight: 700; color: {color};">{score}</span>
                    </div>
                    <p style="margin: 8px 0 0 0; color: #F5F5F5; font-size: 12px;">out of 10</p>
                </div>
                """, unsafe_allow_html=True)

            with col1:
                render_gauge("Overall Score", overall, "#14B8A6")
            with col2:
                render_gauge("Readability", readability, "#3B82F6")
            with col3:
                render_gauge("Compliance", compliance, "#F59E0B")

            # Completeness score
            st.divider()
            completeness = review.get("completeness_score", 0)
            st.markdown(f"""
            <div style="
                background: linear-gradient(135deg, rgba(139, 92, 246, 0.1), rgba(59, 130, 246, 0.1));
                border: 1px solid rgba(139, 92, 246, 0.3);
                border-radius: 12px;
                padding: 16px;
                margin: 16px 0;
            ">
                <p style="margin: 0 0 8px 0; color: #9CA3AF; font-size: 14px;">Completeness</p>
                <div style="
                    background: rgba(107, 114, 128, 0.2);
                    height: 8px;
                    border-radius: 4px;
                    overflow: hidden;
                ">
                    <div style="
                        background: linear-gradient(90deg, #8B5CF6, #3B82F6);
                        height: 100%;
                        width: {completeness}%;
                        transition: width 0.3s ease;
                    "></div>
                </div>
                <p style="margin: 8px 0 0 0; color: #F5F5F5; font-weight: 600;">{completeness}/10</p>
            </div>
            """, unsafe_allow_html=True)

            # Issues found
            with st.expander("Issues Found", expanded=True):
                issues = review.get("issues", [])
                if isinstance(issues, list):
                    if issues:
                        for issue in issues:
                            st.markdown(f"""
                            <div style="
                                background: rgba(239, 68, 68, 0.1);
                                border-left: 3px solid #EF4444;
                                border-radius: 4px;
                                padding: 12px;
                                margin: 8px 0;
                            ">
                                <p style="margin: 0; color: #FCA5A5;">• {issue}</p>
                            </div>
                            """, unsafe_allow_html=True)
                    else:
                        st.success("No major issues found!")
                else:
                    st.write(issues)

            # Suggestions
            with st.expander("Suggested Improvements", expanded=True):
                suggestions = review.get("suggestions", "No suggestions available")
                if isinstance(suggestions, list):
                    for i, suggestion in enumerate(suggestions, 1):
                        st.markdown(f"""
                        <div style="
                            background: rgba(59, 130, 246, 0.1);
                            border-left: 3px solid #3B82F6;
                            border-radius: 4px;
                            padding: 12px;
                            margin: 8px 0;
                        ">
                            <p style="margin: 0; color: #93C5FD;"><strong>{i}.</strong> {suggestion}</p>
                        </div>
                        """, unsafe_allow_html=True)
                else:
                    st.write(suggestions)

            # Generate improved version
            if st.button("Generate Improved Version"):
                with st.spinner("Generating improved notice..."):
                    try:
                        # Ask AI to rewrite
                        improved = ai_engine.chat_completion([
                            {
                                "role": "system",
                                "content": "You are a privacy policy expert. Rewrite the following privacy notice to be more compliant with DPDPA, more readable, and more complete. Keep the same general structure but improve clarity and completeness."
                            },
                            {
                                "role": "user",
                                "content": notice_text
                            }
                        ])

                        if improved:
                            st.success("Improved version generated!")
                            st.markdown(improved)

                            st.download_button(
                                label="Download Improved Version",
                                data=improved,
                                file_name=f"privacy_notice_improved_{datetime.now().strftime('%Y%m%d')}.txt",
                                mime="text/plain"
                            )
                    except Exception as e:
                        st.error(f"Error: {str(e)}")
        else:
            st.markdown(review)


# ============================================================================
# PAGE 6: AI SETTINGS & CONFIGURATION
# ============================================================================

def page_ai_settings(db, org_id: int, user_info: Dict) -> None:
    """
    AI Configuration Page - Manage AI provider settings and usage.

    Admin-only page for configuring LLM provider, API key, model selection,
    and monitoring usage statistics.

    Args:
        db: Database instance
        org_id: Organization ID
        user_info: Current user information
    """
    # Admin only
    if not _check_role_permission(user_info, ["admin"]):
        st.error("This page is available to admins only.")
        return

    _render_styled_header("AI Configuration", "Configure your AI provider and monitor usage")

    try:
        from ai_engine import get_ai_settings, save_ai_settings, get_usage_stats

        # Get current settings
        current_settings = get_ai_settings(db, org_id) or {}

        # Configuration section
        st.subheader("Provider Configuration")

        col1, col2 = st.columns(2)

        with col1:
            # Provider selection with visual cards
            provider_options = ["OpenAI", "Anthropic", "Google Gemini"]
            current_provider = current_settings.get("provider", "openai").title().replace("_", " ")
            provider_index = provider_options.index(current_provider) if current_provider in provider_options else 0

            provider = st.radio(
                "AI Provider",
                provider_options,
                index=provider_index,
                horizontal=False
            )
            provider = provider.lower().replace(" ", "_")

        with col2:
            api_key = st.text_input(
                "API Key",
                value=current_settings.get("api_key", ""),
                type="password",
                placeholder="Enter your API key"
            )

        st.divider()

        # Model selection based on provider
        st.subheader("Model Selection")

        model_options = {
            "openai": {
                "gpt-4o-mini": "GPT-4o Mini (Fast, Recommended)",
                "gpt-4o": "GPT-4o (Balanced)",
                "gpt-4-turbo": "GPT-4 Turbo (Powerful)"
            },
            "anthropic": {
                "claude-3-haiku": "Claude 3 Haiku (Fast, Recommended)",
                "claude-3.5-sonnet": "Claude 3.5 Sonnet (Powerful)"
            },
            "google_gemini": {
                "gemini-2.0-flash": "Gemini 2.0 Flash (Fast, Recommended)",
                "gemini-1.5-pro": "Gemini 1.5 Pro (Powerful)"
            }
        }

        available_models = model_options.get(provider, {})
        current_model = current_settings.get("model", list(available_models.keys())[0])

        selected_model = st.selectbox(
            "Model",
            options=list(available_models.keys()),
            format_func=lambda x: available_models[x],
            index=list(available_models.keys()).index(current_model) if current_model in available_models else 0
        )

        st.divider()

        # Usage limits
        st.subheader("Usage Limits")

        col1, col2 = st.columns(2)

        with col1:
            monthly_limit = st.number_input(
                "Monthly Query Limit",
                min_value=1,
                value=current_settings.get("monthly_limit", 100),
                help="Maximum number of AI queries per month"
            )

        with col2:
            if st.button("Test Connection"):
                with st.spinner("Testing connection..."):
                    try:
                        # Attempt to initialize AIEngine to test connection
                        from ai_engine import AIEngine

                        test_ai = AIEngine(
                            db=db,
                            org_id=org_id,
                            provider=provider,
                            api_key=api_key,
                            model=selected_model
                        )

                        # Try a simple call
                        response = test_ai.chat_completion([
                            {"role": "user", "content": "Say 'Connection successful' in 2 words"}
                        ])

                        if response:
                            st.success("Connection successful!")
                        else:
                            st.error("Connection failed")
                    except Exception as e:
                        st.error(f"Connection error: {str(e)}")

        st.divider()

        # Save settings button
        if st.button("Save Settings", use_container_width=True):
            try:
                save_ai_settings(
                    db=db,
                    org_id=org_id,
                    provider=provider,
                    api_key=api_key,
                    model=selected_model,
                    monthly_limit=monthly_limit
                )
                st.success("Settings saved successfully!")
                st.rerun()
            except Exception as e:
                st.error(f"Failed to save settings: {str(e)}")

        st.divider()

        # Usage dashboard
        st.subheader("Usage Dashboard")

        try:
            usage = get_usage_stats(db, org_id) or {}

            col1, col2, col3 = st.columns(3)

            with col1:
                queries_this_month = usage.get("queries_this_month", 0)
                st.metric(
                    "Queries This Month",
                    f"{queries_this_month}/{monthly_limit}",
                    delta=f"{monthly_limit - queries_this_month} remaining"
                )

            with col2:
                est_cost = usage.get("estimated_cost", 0)
                st.metric(
                    "Estimated Cost",
                    f"${est_cost:.2f}",
                    help="Based on current month's queries"
                )

            with col3:
                last_used = usage.get("last_used", "Never")
                st.metric("Last Used", last_used)

            # Usage by feature (if plotly available)
            if PLOTLY_AVAILABLE:
                st.subheader("Usage by Feature")

                feature_usage = usage.get("by_feature", {})
                if feature_usage:
                    fig = go.Figure(
                        data=[go.Bar(
                            x=list(feature_usage.keys()),
                            y=list(feature_usage.values()),
                            marker_color="#14B8A6"
                        )],
                        layout=go.Layout(
                            title="Queries by Feature",
                            height=400,
                            plot_bgcolor="#0A0F1E",
                            paper_bgcolor="#0A0F1E",
                            font=dict(color="#F5F5F5"),
                            xaxis=dict(showgrid=False),
                            yaxis=dict(showgrid=True, gridcolor="rgba(107, 114, 128, 0.1)")
                        )
                    )
                    st.plotly_chart(fig, use_container_width=True)
        except Exception as e:
            st.warning(f"Could not load usage stats: {str(e)}")

    except ImportError:
        st.error("AI module not available. Please check your installation.")
    except Exception as e:
        st.error(f"Error: {str(e)}")
