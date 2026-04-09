# 🛡️ Anumati.ai — DPDPA Compliance Automation Platform

**Open-source, offline, rule-based compliance tool for India's Digital Personal Data Protection Act (DPDPA) 2023**

> *"Anumati" (अनुमति) means "consent" in Sanskrit — the foundation of data privacy.*

[![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)](https://python.org)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.28+-red.svg)](https://streamlit.io)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![DPDPA](https://img.shields.io/badge/DPDPA-2023-teal.svg)](https://www.meity.gov.in)

---

## Why Anumati?

Most DPDPA compliance tools are enterprise-priced (OneTrust at $2,275/month, TrustArc at $8,000+/year) and treat India's law as an afterthought. Anumati is built specifically for DPDPA, by someone who has implemented it.

**Key differentiators:**
- **AI-Powered** — GPT-4o / Claude / Gemini integration for intelligent compliance guidance
- **Rule-based core** — Works offline without AI; AI features are optional add-ons
- **Free & Open Source** — Use it, modify it, contribute to it
- **Built by a practitioner** — Not by someone who just read the Act
- **Multi-tenant** — Multi-user, multi-org with role-based access control

---

## Features

### Core Modules (12 Pages)

| Module | What it does |
|--------|-------------|
| **📊 Dashboard** | Compliance score (0-100%), category breakdown, deadline countdown to May 2027 |
| **🔍 Gap Assessment** | 27 questions across 9 DPDPA categories with weighted scoring |
| **📋 RoPA Registry** | Records of Processing Activities — track all data processing with lawful basis, retention, processors |
| **🤝 Consent Manager** | Consent record management with DPDPA 5-pillar compliance checklist, children's data tracking |
| **📝 Privacy Notices** | Privacy notice builder with plain-language preview, version control, Rule 2 compliance |
| **👤 Rights Requests** | Data Principal rights request tracker with 30-day deadline per Rule 8, status workflow |
| **🏢 Vendor Management** | Vendor registry with DPA tracking, security ratings, ISO/SOC2 certification status |
| **📄 Document Generator** | 7 DPDPA-compliant templates: Privacy Policy, Consent Notice, DPA, DPIA, RoPA, Breach Notification, Grievance Policy |
| **✅ Compliance Tracker** | Task management with priorities, deadlines, and progress tracking |
| **⚠️ Breach Response** | 72-hour notification workflow, incident logging, severity classification |
| **📚 Knowledge Base** | 33 DPDPA sections, 29 definitions, 66 checklist items, 20 FAQs, sector-specific guidance |
| **⚙️ Settings** | Multi-org support, industry classification, SDF status tracking |

### AI-Powered Modules (6 Pages)

| Module | What it does |
|--------|-------------|
| **🤖 AI Assistant** | Conversational DPDPA chatbot — ask anything about compliance, get cited section references |
| **✨ AI Doc Drafter** | Auto-generates privacy policies, DPAs, consent notices using your actual org data |
| **🎯 AI Compliance Advisor** | Analyzes your gap assessment, generates prioritized remediation plan |
| **🚨 AI Breach Analyzer** | Classifies breach severity, drafts DPB + Data Principal notification letters |
| **📝 AI Notice Reviewer** | Scores privacy notices on readability, compliance, completeness (1-10) |
| **🔧 AI Configuration** | API key setup, provider selection (OpenAI/Anthropic/Gemini), usage tracking |

### Knowledge Base Coverage

- **33** DPDPA 2023 sections with requirements and penalties
- **16** DPDP Rules 2025 with deadlines
- **29** key legal definitions
- **66** compliance checklist items
- **20** practical FAQs
- **10** penalty categories (up to ₹250 crore)
- **6** industry-specific guides (FinTech, Healthcare, E-commerce, IT, Education, Government)

---

## Quick Start

```bash
# Clone the repo
git clone https://github.com/chevauxenbois/anumati.git
cd anumati

# Install dependencies
pip install -r requirements.txt

# Run
streamlit run app.py
```

Opens at `http://localhost:8501`

---

## Project Structure

```
anumati/
├── app.py              # Main Streamlit application + routing (1,812 lines)
├── ai_engine.py        # AI/LLM integration engine (1,056 lines)
├── ai_pages.py         # AI-powered UI pages (1,026 lines)
├── new_pages.py        # RoPA, Consent, Privacy Notices, Rights, Vendors (1,168 lines)
├── config.py           # Configuration, categories, questions (492 lines)
├── database.py         # SQLite database layer, 15 tables (1,925 lines)
├── knowledge_base.py   # Complete DPDPA knowledge base (1,918 lines)
├── doc_generator.py    # Document generation engine, 7 templates (1,401 lines)
├── requirements.txt    # Dependencies
├── .streamlit/config.toml  # Dark theme configuration
├── .gitignore
└── README.md
```

**Total: ~10,800 lines of production-quality Python across 8 modules**

---

## Compliance Categories & Weights

| Category | Weight | What it covers |
|----------|--------|----------------|
| Data Collection & Consent | 15% | Valid consent mechanisms, opt-in/opt-out |
| Data Subject Rights | 15% | Access, correction, erasure, nomination |
| Data Protection Policy | 12% | Published privacy policies |
| Breach Notification | 12% | 72-hour reporting to DPB |
| Privacy by Design | 10% | PIAs, data minimization |
| Data Processing Agreements | 10% | Third-party contracts |
| Data Audit & Records | 10% | RoPA, data flow documentation |
| Staff Training | 8% | Employee awareness programs |
| Grievance Redressal | 8% | Complaint handling within 90 days |

---

## Document Templates

All documents are generated as `.docx` files with professional formatting, DPDPA section references, and `[BRACKET]` placeholders for customization.

| Document | Key Sections |
|----------|-------------|
| **Privacy Policy** | 13 sections including Data Principal Rights, Cross-Border Transfers, Children's Data |
| **Consent Notice** | Per Section 5 / Rule 3 — free, specific, informed, unconditional, unambiguous |
| **Data Processing Agreement** | 11 sections including Audit Rights, Sub-processors, Breach Notification |
| **DPIA Report** | Risk matrix (Likelihood × Impact), mitigation measures, sign-off |
| **Breach Notification** | Dual-part: DPB notification (72hrs) + Data Principal notification |
| **RoPA** | 9-column table: Activity, Purpose, Legal Basis, Categories, Recipients, etc. |
| **Grievance Policy** | 48-hour acknowledgment, 90-day resolution, DPB escalation |

---

## Key DPDPA Deadlines

| Date | Milestone |
|------|-----------|
| Nov 13, 2025 | DPDP Rules 2025 in effect |
| Nov 13, 2026 | Consent Manager registration deadline |
| **May 13, 2027** | **Full DPDPA compliance mandatory** |

---

## Tech Stack

- **Python 3.9+** — Core language
- **Streamlit** — Web UI framework
- **SQLite** — Local database (zero config)
- **Plotly** — Dashboard visualizations
- **python-docx** — Document generation
- **OpenAI / Anthropic / Gemini** — AI features (optional, bring your own API key)

---

## Open Source + Premium Model

### Free (Open Source)
- All 12 core modules + 6 AI pages
- Gap assessment with scoring
- All 7 document templates
- Knowledge base with search
- Multi-user, multi-org support
- Breach notification workflow
- AI features (bring your own API key)

### Premium (Coming Soon)
- Managed API keys (no BYOK needed)
- Unlimited AI queries
- Sector-specific compliance packs (BFSI/RBI, Healthcare)
- Advanced reporting and analytics
- Priority support

---

## Contributing

PRs welcome! Areas where help is needed:

- Additional gap assessment questions
- More document templates
- Language translations (Hindi, regional languages)
- UI/UX improvements
- Test coverage
- Docker containerization

---

## License

MIT License — free for personal and commercial use.

---

## Author

**Harsh Kahate**
Information Security & Data Privacy Professional

- LinkedIn: [hkahate](https://linkedin.com/in/hkahate)
- Blog: [substack.com/@harshkahate](https://substack.com/@harshkahate)

---

*Anumati.ai — Making DPDPA compliance accessible for every Indian organization.*
