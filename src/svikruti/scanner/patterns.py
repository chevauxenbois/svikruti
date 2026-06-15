"""Patterns used by the first release scanner.

The rules are intentionally transparent. Teams should be able to inspect why a
finding exists and tune the dictionaries for their own products.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Pattern
import re


@dataclass(frozen=True)
class DataPattern:
    category: str
    terms: List[str]
    severity: str
    dpdpa_area: str


PERSONAL_DATA_PATTERNS: List[DataPattern] = [
    DataPattern("Identity", ["full_name", "first_name", "last_name", "username", "user_name", "customer_name", "display_name"], "MEDIUM", "Notice transparency"),
    DataPattern("Contact", ["email", "phone", "mobile", "telephone", "whatsapp"], "HIGH", "Consent and notice"),
    DataPattern("Government ID", ["aadhaar", "aadhar", "pan_number", "passport", "voter_id", "driving_license"], "CRITICAL", "Data minimization"),
    DataPattern("Financial", ["card_number", "bank_account", "ifsc", "upi", "payment", "razorpay_order"], "HIGH", "Security safeguards"),
    DataPattern("Location", ["latitude", "longitude", "geo", "gps", "location", "address", "pincode"], "HIGH", "Purpose limitation"),
    DataPattern("Children", ["child", "minor", "guardian", "parent_consent", "school", "student_age"], "CRITICAL", "Children's data"),
    DataPattern("Health", ["health", "diagnosis", "prescription", "medical", "blood_group"], "CRITICAL", "Data minimization"),
    DataPattern("Device", ["ip_address", "device_id", "advertising_id", "cookie", "session_id"], "MEDIUM", "Tracking and consent"),
]

THIRD_PARTY_PATTERNS: Dict[str, List[str]] = {
    "Google Analytics": ["google-analytics", "gtag(", "googletagmanager", "analytics.google.com"],
    "Meta Pixel": ["fbq(", "connect.facebook.net", "facebook pixel", "meta pixel"],
    "Razorpay": ["razorpay", "checkout.razorpay.com"],
    "Stripe": ["stripe", "js.stripe.com"],
    "Segment": ["segment.com", "analytics.js", "writekey"],
    "Mixpanel": ["mixpanel"],
    "Hotjar": ["hotjar"],
    "Intercom": ["intercom"],
    "HubSpot": ["hubspot", "hs-scripts"],
    "Firebase": ["firebase", "googleapis.com/firebase"],
    "Sentry": ["sentry.io", "@sentry"],
    "Freshworks": ["freshchat", "freshdesk", "freshworks"],
    "Zoho": ["zoho", "zohocdn"],
    "Cashfree": ["cashfree"],
    "Juspay": ["juspay"],
    "PayU": ["payu", "payu.in"],
    "PhonePe": ["phonepe"],
    "Exotel": ["exotel"],
    "MSG91": ["msg91"],
    "Shiprocket": ["shiprocket"],
    "Delhivery": ["delhivery"],
    "MoEngage": ["moengage"],
    "CleverTap": ["clevertap"],
    "WebEngage": ["webengage"],
}

LITERAL_DATA_REGEXES: Dict[str, Pattern[str]] = {
    "Email literal": re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE),
    "Indian mobile literal": re.compile(r"(?:\+91[-\s]?)?[6-9]\d{9}\b"),
    "PAN literal": re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b"),
    "Aadhaar-like literal": re.compile(r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}\b"),
    "UPI ID literal": re.compile(r"\b[a-zA-Z0-9.\-_]{2,}@(upi|ybl|ibl|okaxis|okhdfcbank|oksbi|okicici|paytm|apl|axl)\b", re.IGNORECASE),
}

INDIA_NOTICE_TERMS: Dict[str, List[str]] = {
    "grievance": ["grievance", "complaint", "grievance officer"],
    "withdrawal": ["withdraw", "withdrawal", "revoke consent"],
    "rights": ["access", "correction", "erasure", "nomination", "data principal"],
    "children": ["child", "children", "minor", "guardian", "parent"],
    "retention": ["retention", "retain", "delete"],
    "third_parties": ["processor", "third party", "vendor", "service provider", "recipient"],
}

COLLECTION_HINTS = [
    "request.form",
    "request.json",
    "req.body",
    "bodyparser",
    "formdata",
    "st.text_input",
    "st.text_area",
    "input",
    "textarea",
    "register",
    "signup",
    "sign_up",
    "profile",
    "checkout",
]

STORAGE_HINTS = [
    "create table",
    "model",
    "schema",
    "insert into",
    "update ",
    "db.",
    "collection(",
    "mongoose.schema",
]

LOGGING_HINTS = [
    "logger.",
    "logging.",
    "console.log",
    "print(",
    "log.info",
    "log.error",
]

PRIVACY_NOTICE_HINTS = [
    "privacy policy",
    "privacy notice",
    "data protection",
    "consent",
    "withdraw",
    "delete my data",
    "data principal",
]

FILE_EXTENSIONS = {
    ".py",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".java",
    ".go",
    ".rb",
    ".php",
    ".cs",
    ".html",
    ".htm",
    ".vue",
    ".svelte",
    ".json",
    ".yml",
    ".yaml",
    ".toml",
    ".env",
}

IGNORED_FILE_PATTERNS = (
    "-report.html",
    "-report.json",
    "-report.sarif",
    "-evidence-pack.html",
    "-evidence-pack.json",
    "-evidence-pack.sarif",
    "-full-report.html",
    "-full-report.json",
    "-full-report.sarif",
    ".sarif",
    "svikruti-report.html",
    "svikruti-report.json",
)

IGNORED_DIRS = {
    ".git",
    "__pycache__",
    ".venv",
    "venv",
    "env",
    "node_modules",
    "dist",
    "build",
    ".next",
    ".turbo",
    ".cache",
    "coverage",
}

FORM_FIELD_RE: Pattern[str] = re.compile(
    r"(?:name|id|formControlName|placeholder)\s*=\s*[\"']([^\"']+)[\"']",
    re.IGNORECASE,
)


def normalize_text(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", value.lower()).strip("_")
