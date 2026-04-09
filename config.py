"""
Configuration and constants for Svikruti.ai DPDPA Compliance Tool

This module contains all configuration values, enums, and constants
used throughout the application. Centralized configuration makes it
easy to adjust compliance rules and UI themes.
"""

from enum import Enum
from datetime import datetime, timedelta
from typing import Dict, List

# ==================== VERSION INFO ====================
APP_VERSION = "0.1.0"
APP_NAME = "Svikruti.ai"
APP_SUBTITLE = "DPDPA Compliance Automation Platform"
CREATED_BY = "Harsh Kahate"

# ==================== COLOR THEME ====================
# Professional teal and green color scheme
COLOR_PRIMARY = "#028090"      # Deep teal
COLOR_ACCENT = "#02C39A"       # Light teal/green
COLOR_SUCCESS = "#2EC4B6"
COLOR_WARNING = "#FF9F1C"
COLOR_DANGER = "#E63946"
COLOR_DARK = "#1A1A1A"
COLOR_LIGHT = "#F5F5F5"

# ==================== COMPLIANCE CATEGORIES ====================
# DPDPA compliance areas with weights for overall scoring
COMPLIANCE_CATEGORIES = {
    "Data Collection & Consent": {
        "weight": 0.15,
        "description": "Obtaining valid consent for personal data collection"
    },
    "Data Protection Policy": {
        "weight": 0.12,
        "description": "Publishing comprehensive data protection policies"
    },
    "Data Subject Rights": {
        "weight": 0.15,
        "description": "Enabling rights like access, correction, deletion"
    },
    "Breach Notification": {
        "weight": 0.12,
        "description": "Reporting data breaches within required timeframe"
    },
    "Privacy by Design": {
        "weight": 0.10,
        "description": "Implementing privacy in all processes and systems"
    },
    "Data Processing Agreement": {
        "weight": 0.10,
        "description": "Contracts with data processors and third parties"
    },
    "Staff Training": {
        "weight": 0.08,
        "description": "Employee awareness and training programs"
    },
    "Data Audit & Records": {
        "weight": 0.10,
        "description": "Maintaining records of processing activities"
    },
    "Grievance Redressal": {
        "weight": 0.08,
        "description": "Handling user complaints and grievances"
    }
}

# ==================== INDUSTRY TYPES ====================
class IndustryType(Enum):
    """Supported industry types for DPDPA compliance"""
    FINTECH = "FinTech"
    HEALTHCARE = "Healthcare"
    ECOMMERCE = "E-commerce"
    IT_SERVICES = "IT Services"
    MANUFACTURING = "Manufacturing"
    EDUCATION = "Education"
    GOVERNMENT = "Government"
    OTHER = "Other"

INDUSTRY_TYPES = [ind.value for ind in IndustryType]

# ==================== ORGANIZATION SIZE ====================
class OrgSize(Enum):
    """Organization size categories"""
    STARTUP = "Startup (< 50 employees)"
    SMALL = "Small (50-250 employees)"
    MEDIUM = "Medium (250-1000 employees)"
    LARGE = "Large (1000-10000 employees)"
    ENTERPRISE = "Enterprise (> 10000 employees)"

ORG_SIZES = [size.value for size in OrgSize]

# ==================== COMPLIANCE LEVELS ====================
class ComplianceLevel(Enum):
    """Current compliance level stages"""
    NOT_STARTED = "Not Started"
    IN_PROGRESS = "In Progress"
    MAJORITY_COMPLETE = "Majority Complete"
    FULLY_COMPLIANT = "Fully Compliant"

COMPLIANCE_LEVELS = [level.value for level in ComplianceLevel]

# ==================== SDF STATUS ====================
class SDFStatus(Enum):
    """Significant Data Fiduciary status under DPDPA"""
    NOT_SDF = "Not an SDF"
    SDF = "Significant Data Fiduciary"
    UNCERTAIN = "Uncertain"

SDF_STATUSES = [status.value for status in SDFStatus]

# ==================== KEY COMPLIANCE DEADLINES ====================
# As per DPDPA and Rules notifications
COMPLIANCE_DEADLINES = {
    "DPDP Rules Compliance": {
        "date": datetime(2025, 11, 13),
        "description": "Deadline for compliance with DPDP Rules 2024",
        "priority": "HIGH"
    },
    "Consent Manager Implementation": {
        "date": datetime(2026, 11, 13),
        "description": "MEITY Consent Manager framework must be operational",
        "priority": "HIGH"
    },
    "Full Compliance Target": {
        "date": datetime(2027, 5, 13),
        "description": "Full DPDPA compliance across all operations",
        "priority": "CRITICAL"
    }
}

# ==================== PENALTY AMOUNTS ====================
# As per DPDPA sections 25 & 26
PENALTY_AMOUNTS = {
    "violation": 50000000,           # Up to Rs. 5 crore
    "severe_violation": 200000000,   # Up to Rs. 20 crore
    "right_denial": 100000000,       # Up to Rs. 10 crore
}

# ==================== CONSENT MANAGER REQUIREMENTS ====================
CONSENT_MANAGER_RULES = {
    "data_controller_onboarding": "SDFs and other controllers must onboard",
    "user_preference_storage": "Store and manage user preferences",
    "audit_trail": "Maintain comprehensive audit logs",
    "transparency_framework": "Provide clear consent information",
    "cookie_management": "Manage cookies as per guidelines"
}

# ==================== GAP ASSESSMENT QUESTIONS ====================
# Structure: category -> [questions]
GAP_ASSESSMENT_QUESTIONS: Dict[str, List[Dict]] = {
    "Data Collection & Consent": [
        {
            "id": "dcc_1",
            "question": "Do you have a documented consent mechanism for collecting personal data?",
            "options": ["Yes", "No", "Partially"],
            "hint": "Valid consent must be explicit and freely given"
        },
        {
            "id": "dcc_2",
            "question": "Do you inform users about data collection at the point of collection?",
            "options": ["Yes", "No", "Partially"],
            "hint": "Required for lawful processing"
        },
        {
            "id": "dcc_3",
            "question": "Do you have opt-in/opt-out mechanisms for data processing?",
            "options": ["Yes", "No", "Partially"],
            "hint": "Users must have choice in data usage"
        }
    ],
    "Data Protection Policy": [
        {
            "id": "dpp_1",
            "question": "Do you have a published privacy/data protection policy?",
            "options": ["Yes", "No", "Partially"],
            "hint": "Policy must be easily accessible and clear"
        },
        {
            "id": "dpp_2",
            "question": "Does your policy cover data retention periods?",
            "options": ["Yes", "No", "Partially"],
            "hint": "Specify how long you keep personal data"
        },
        {
            "id": "dpp_3",
            "question": "Does your policy describe third-party data sharing?",
            "options": ["Yes", "No", "Partially"],
            "hint": "Be transparent about data transfers"
        }
    ],
    "Data Subject Rights": [
        {
            "id": "dsr_1",
            "question": "Can users request access to their personal data?",
            "options": ["Yes", "No", "Partially"],
            "hint": "Right to access is mandatory"
        },
        {
            "id": "dsr_2",
            "question": "Can users request correction/deletion of their data?",
            "options": ["Yes", "No", "Partially"],
            "hint": "Rights to rectification and erasure are required"
        },
        {
            "id": "dsr_3",
            "question": "Do you respond to data subject requests within 30 days?",
            "options": ["Yes", "No", "Partially"],
            "hint": "Response deadline is 30 days from receipt"
        }
    ],
    "Breach Notification": [
        {
            "id": "bn_1",
            "question": "Do you have a data breach response plan?",
            "options": ["Yes", "No", "Partially"],
            "hint": "Required for quick incident response"
        },
        {
            "id": "bn_2",
            "question": "Do you notify authorities within 72 hours of a breach?",
            "options": ["Yes", "No", "Partially"],
            "hint": "Authority notification deadline is 72 hours"
        },
        {
            "id": "bn_3",
            "question": "Do you maintain a log of all data breaches?",
            "options": ["Yes", "No", "Partially"],
            "hint": "Breach records are crucial for audits"
        }
    ],
    "Privacy by Design": [
        {
            "id": "pbd_1",
            "question": "Is privacy considered in all new system development?",
            "options": ["Yes", "No", "Partially"],
            "hint": "Privacy must be built-in from the start"
        },
        {
            "id": "pbd_2",
            "question": "Do you conduct privacy impact assessments?",
            "options": ["Yes", "No", "Partially"],
            "hint": "PIAs help identify and mitigate risks"
        },
        {
            "id": "pbd_3",
            "question": "Do you use data minimization principles?",
            "options": ["Yes", "No", "Partially"],
            "hint": "Collect only necessary data"
        }
    ],
    "Data Processing Agreement": [
        {
            "id": "dpa_1",
            "question": "Do you have contracts with data processors?",
            "options": ["Yes", "No", "Partially"],
            "hint": "Required for all third-party processing"
        },
        {
            "id": "dpa_2",
            "question": "Do your contracts include DPDPA compliance clauses?",
            "options": ["Yes", "No", "Partially"],
            "hint": "Processors must follow DPDPA rules"
        },
        {
            "id": "dpa_3",
            "question": "Do you monitor processor compliance?",
            "options": ["Yes", "No", "Partially"],
            "hint": "Regular audits and compliance checks"
        }
    ],
    "Staff Training": [
        {
            "id": "st_1",
            "question": "Do you conduct DPDPA awareness training?",
            "options": ["Yes", "No", "Partially"],
            "hint": "Staff must understand DPDPA requirements"
        },
        {
            "id": "st_2",
            "question": "Do new employees receive privacy training?",
            "options": ["Yes", "No", "Partially"],
            "hint": "Onboarding should include privacy basics"
        },
        {
            "id": "st_3",
            "question": "Do you conduct annual refresher trainings?",
            "options": ["Yes", "No", "Partially"],
            "hint": "Regular updates on compliance best practices"
        }
    ],
    "Data Audit & Records": [
        {
            "id": "dar_1",
            "question": "Do you maintain records of data processing activities?",
            "options": ["Yes", "No", "Partially"],
            "hint": "Data inventory/registry is mandatory"
        },
        {
            "id": "dar_2",
            "question": "Do you conduct regular data audits?",
            "options": ["Yes", "No", "Partially"],
            "hint": "Audits help identify and fix issues"
        },
        {
            "id": "dar_3",
            "question": "Do you document data flow across systems?",
            "options": ["Yes", "No", "Partially"],
            "hint": "Know where your data travels"
        }
    ],
    "Grievance Redressal": [
        {
            "id": "gr_1",
            "question": "Do you have a grievance redressal mechanism?",
            "options": ["Yes", "No", "Partially"],
            "hint": "Users should have a way to file complaints"
        },
        {
            "id": "gr_2",
            "question": "Do you respond to grievances within 30 days?",
            "options": ["Yes", "No", "Partially"],
            "hint": "Response deadline is 30 days"
        },
        {
            "id": "gr_3",
            "question": "Do you maintain records of all grievances?",
            "options": ["Yes", "No", "Partially"],
            "hint": "Grievance logs are important for compliance"
        }
    ]
}

# ==================== DOCUMENT TEMPLATES ====================
# Types of documents that can be generated
DOCUMENT_TYPES = {
    "privacy_policy": {
        "name": "Privacy Policy",
        "description": "Comprehensive data protection policy for your organization",
        "sections": [
            "Introduction",
            "Data We Collect",
            "How We Use Your Data",
            "Your Rights",
            "Data Security",
            "Third-Party Sharing",
            "Retention Period",
            "Contact Information"
        ]
    },
    "dpa": {
        "name": "Data Processing Agreement",
        "description": "Agreement for data processors and third parties",
        "sections": [
            "Parties and Scope",
            "Processing Instructions",
            "Sub-processor Authorization",
            "Data Subject Rights",
            "Security Measures",
            "Audit Rights",
            "Liability",
            "Termination"
        ]
    },
    "breach_response": {
        "name": "Data Breach Response Plan",
        "description": "Incident response procedure for data breaches",
        "sections": [
            "Detection and Reporting",
            "Incident Response Team",
            "Containment Procedures",
            "Authority Notification",
            "User Communication",
            "Investigation Process",
            "Documentation",
            "Recovery"
        ]
    },
    "consent_form": {
        "name": "Consent Form",
        "description": "User consent form for personal data collection",
        "sections": [
            "Data Controller Info",
            "Data Collection Purpose",
            "Data Categories",
            "Processing Duration",
            "User Rights",
            "Consent Statement",
            "Signature"
        ]
    },
    "privacy_notice": {
        "name": "Privacy Notice",
        "description": "Short privacy notice for website/app display",
        "sections": [
            "Data Collection Notice",
            "Purpose of Collection",
            "Your Rights",
            "Contact Information",
            "Cookie Notice"
        ]
    }
}

# ==================== COMPLIANCE TASKS ====================
# Standard compliance tasks with assigned deadlines
DEFAULT_COMPLIANCE_TASKS = [
    {
        "title": "Conduct Data Audit",
        "description": "Audit all data collection points and processing activities",
        "category": "Data Audit & Records",
        "priority": "HIGH",
        "days_to_deadline": 30
    },
    {
        "title": "Create Privacy Policy",
        "description": "Draft and publish comprehensive privacy policy",
        "category": "Data Protection Policy",
        "priority": "HIGH",
        "days_to_deadline": 15
    },
    {
        "title": "Set Up Consent Mechanism",
        "description": "Implement consent collection for data processing",
        "category": "Data Collection & Consent",
        "priority": "CRITICAL",
        "days_to_deadline": 20
    },
    {
        "title": "Create Data Processing Agreements",
        "description": "Draft DPAs with all data processors",
        "category": "Data Processing Agreement",
        "priority": "HIGH",
        "days_to_deadline": 45
    },
    {
        "title": "Conduct Privacy Training",
        "description": "Train all staff on DPDPA requirements",
        "category": "Staff Training",
        "priority": "MEDIUM",
        "days_to_deadline": 60
    },
    {
        "title": "Set Up Breach Response Plan",
        "description": "Document and test breach notification procedures",
        "category": "Breach Notification",
        "priority": "HIGH",
        "days_to_deadline": 35
    },
    {
        "title": "Implement Grievance System",
        "description": "Set up mechanism for user complaints",
        "category": "Grievance Redressal",
        "priority": "MEDIUM",
        "days_to_deadline": 40
    }
]

# ==================== UTILITY FUNCTIONS ====================

def get_category_weight(category: str) -> float:
    """Get the weight of a compliance category for scoring"""
    return COMPLIANCE_CATEGORIES.get(category, {}).get("weight", 0)


def get_all_category_weights() -> Dict[str, float]:
    """Get all category weights as a dictionary"""
    return {cat: data["weight"] for cat, data in COMPLIANCE_CATEGORIES.items()}


def days_to_deadline(deadline_name: str) -> int:
    """Calculate days remaining until a compliance deadline"""
    deadline = COMPLIANCE_DEADLINES.get(deadline_name, {}).get("date")
    if not deadline:
        return -1
    return (deadline - datetime.now()).days


def get_next_deadline():
    """Get the upcoming deadline with the least days remaining"""
    deadlines = [
        (name, deadline["date"], deadline["priority"])
        for name, deadline in COMPLIANCE_DEADLINES.items()
    ]
    deadlines.sort(key=lambda x: x[1])
    if deadlines:
        name, date, priority = deadlines[0]
        days = (date - datetime.now()).days
        return {"name": name, "date": date, "days": days, "priority": priority}
    return None
