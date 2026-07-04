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
    DataPattern("Identity", ["full_name", "first_name", "last_name", "username", "user_name", "customer_name", "display_name", "date_of_birth", "dob"], "MEDIUM", "Notice transparency"),
    DataPattern("Contact", ["email", "email_address", "phone", "phone_number", "mobile", "mobile_number", "telephone", "whatsapp"], "HIGH", "Consent and notice"),
    # Standalone "pan" removed: it is too ambiguous as a bare token (panel,
    # pandas, PAN-EU, ...). Only compound tokens remain here; literal PAN
    # values are covered by the context-checked "PAN literal" regex below.
    DataPattern("Government ID", ["aadhaar", "aadhar", "pan_number", "pan_card", "passport", "voter_id", "driving_license", "dl_number"], "CRITICAL", "Data minimization"),
    DataPattern("Financial", ["card_number", "card_last4", "bank_account", "account_number", "ifsc", "upi", "upi_id", "payment", "payment_method", "razorpay_order"], "HIGH", "Security safeguards"),
    # "state" and "zip" removed: in code they overwhelmingly mean state
    # machines / React state and compressed archives, not location data.
    DataPattern("Location", ["latitude", "longitude", "geolocation", "gps", "location", "home_address", "address", "address_line", "city", "postal_code", "pincode", "pin_code"], "HIGH", "Purpose limitation"),
    # "student"/"school" (and "patient" in Health) are ambiguous alone; code.py
    # requires a corroborating personal-data token nearby before emitting these
    # at full severity (see AMBIGUOUS_SENSITIVE_TERMS / CORROBORATION_TERMS).
    # Bare "children" removed: in code it is a tree-structure field (DOM
    # props.children, ORM/MPTT category.children) essentially always -
    # benchmark-confirmed on excalidraw and saleor. Real children's-data
    # signals surface through age/guardian/consent compounds instead.
    # "children_data" deliberately absent too: tree-walking code produces
    # "grand_children_data" style identifiers (benchmark: saleor menus).
    DataPattern("Children", ["child_age", "child_dob", "minor", "guardian", "parent_consent", "parental_consent", "school", "student", "student_age"], "CRITICAL", "Children's data"),
    DataPattern("Health", ["health", "diagnosis", "prescription", "medical", "blood_group", "lab_report", "patient"], "CRITICAL", "Data minimization"),
    # Standalone "ip" removed (ubiquitous abbreviation). "session_id",
    # "cookie" and "user_agent" are ordinary web plumbing: code.py downgrades
    # them to LOW unless a collection/storage/logging context co-occurs
    # (see WEB_PLUMBING_TERMS).
    DataPattern("Device", ["ip_address", "device_id", "device_identifier", "advertising_id", "cookie", "session_id", "user_agent"], "MEDIUM", "Tracking and consent"),
]

# Single source of truth for category -> severity. semantic.py and the
# tree-sitter backend import this instead of keeping divergent copies.
CATEGORY_SEVERITY: Dict[str, str] = {pattern.category: pattern.severity for pattern in PERSONAL_DATA_PATTERNS}

# Tokens that corroborate that ambiguous Children/Health terms really refer to
# personal data about people (names, contacts, DOB, addresses, IDs, guardians).
CORROBORATION_TERMS: List[str] = [
    "name", "first_name", "last_name", "full_name", "email", "phone",
    "mobile", "dob", "date_of_birth", "address", "aadhaar", "aadhar",
    "guardian", "parent",
]

# Corroboration set for ambiguous Location tokens: "address" alone usually
# means IP/email/web/memory address in code, and "location"/"city" appear in
# logging, geo-IP plumbing, and UI copy. A postal/person context token nearby
# is what makes them personal-data signals.
# Note: "email"/"phone" are deliberately NOT corroboration here — "email
# address" and "IP address" co-occur constantly without postal meaning.
ADDRESS_CORROBORATION_TERMS: List[str] = [
    "street", "city", "postal_code", "postal", "pincode", "pin_code",
    "zip_code", "billing", "shipping", "home", "residence", "address_line",
    "country", "customer", "user_profile",
]

# Ambiguous tokens -> the corroboration terms that make them credible.
# Benchmarked on real OSS repos (healthchecks, saleor, excalidraw):
# - "children"/"minor" fire on DOM .children and "minor version" without this
# - "address" fires on IP/email/web addresses
# - "location"/"city" fire on window.location, file locations, geo-IP noise
# Children-specific corroboration: deliberately EXCLUDES "name" and bare
# "parent" - React/DOM code pairs ".children" with "parentNode"/"name" props
# constantly (benchmark: 152 false CRITICALs on excalidraw). Only
# consent/guardian/birth-adjacent tokens make a children signal credible.
CHILD_CORROBORATION_TERMS: List[str] = [
    "guardian", "parental", "parent_consent", "consent", "dob",
    "date_of_birth", "birth", "age", "email", "phone", "mobile",
    "aadhaar", "aadhar", "school", "student",
]

AMBIGUOUS_TERM_CORROBORATION: Dict[str, List[str]] = {
    "student": CORROBORATION_TERMS,
    "school": CORROBORATION_TERMS,
    "patient": CORROBORATION_TERMS,
    "children": CHILD_CORROBORATION_TERMS,
    "minor": CHILD_CORROBORATION_TERMS,
    "address": ADDRESS_CORROBORATION_TERMS,
    "location": ADDRESS_CORROBORATION_TERMS + ["latitude", "longitude", "gps", "geolocation"],
    "city": ADDRESS_CORROBORATION_TERMS,
    # "mobile" alone is usually the device/viewport (mobile-toolbar,
    # mobile-web-app-capable); "health" alone is usually a product name or
    # health-check endpoint. Benchmark-confirmed on excalidraw/healthchecks.
    "mobile": ["number", "phone", "contact", "otp", "sms", "tel", "whatsapp", "recipient", "verify", "msisdn", "91"],
    "health": ["patient", "medical", "diagnosis", "prescription", "record", "blood", "clinical", "insurance", "condition", "treatment"],
    # "medical" fires on product/tax category names ("Medical supplies") in
    # ecommerce repos (benchmark: saleor migrations); require clinical context.
    "medical": ["patient", "health", "diagnosis", "prescription", "record", "blood", "clinical", "insurance", "condition", "treatment", "history"],
}

# Mobile-number literal context tokens (same rationale as Aadhaar: a bare
# 10-digit constant starting 6-9 is often an ID/seed, not a phone number).
MOBILE_CONTEXT_TOKENS = ("phone", "mobile", "whatsapp", "tel", "telephone", "contact", "msisdn", "recipient", "sms", "otp", "call")

# Backward-compatible alias: the set of all ambiguous tokens. Ambiguous
# tokens are flagged at full category severity only when a corroborating
# token appears on the same line or within +/-3 lines; otherwise they are
# emitted as a MEDIUM "possible" signal (see code.py).
AMBIGUOUS_SENSITIVE_TERMS = set(AMBIGUOUS_TERM_CORROBORATION)

# Vendored/minified third-party assets: keyword and literal detectors skip
# these entirely (counted in scan-quality limitations). Minified bundles and
# vendored dependencies are not where first-party personal data lives, and
# they produce enormous token noise (e.g. DOM ".children" in *.min.js).
VENDORED_PATH_SEGMENTS = {
    "node_modules", "bower_components", "vendor", "vendors", "third_party",
    "third-party", "site-packages",
}
VENDORED_FILE_SUFFIXES = (".min.js", ".min.css", ".bundle.js", ".map")


def is_vendored_path(rel_path: str) -> bool:
    lowered = rel_path.replace("\\", "/").lower()
    if lowered.endswith(VENDORED_FILE_SUFFIXES):
        return True
    return any(part in VENDORED_PATH_SEGMENTS for part in lowered.split("/"))


# Aadhaar literal context: a Verhoeff-valid 12-digit number is still ~8% of
# random 12-digit values (epoch-milliseconds in API docs pass regularly), so
# CRITICAL requires either 4-4-4 grouping or a nearby context token.
AADHAAR_CONTEXT_TOKENS = ("aadhaar", "aadhar", "uid", "uidai", "kyc", "identity_number")

# Email literals in tests/fixtures/docs or on reserved example domains are
# fixture data, not exposure: reported at LOW severity.
EXAMPLE_EMAIL_DOMAINS = ("example.com", "example.org", "example.net", "example.in", "test.com", "email.com", "localhost", "invalid")
FIXTURE_PATH_SEGMENTS = {"test", "tests", "testing", "fixture", "fixtures", "spec", "specs", "mock", "mocks", "docs", "doc", "samples", "sample_data", "__tests__"}

# Ubiquitous web-plumbing tokens: kept in the Device/Tracking category but
# downgraded to LOW severity by code.py unless they co-occur with a
# collection/storage/logging context.
WEB_PLUMBING_TERMS = {"session_id", "cookie", "user_agent"}

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

# --- Verhoeff checksum (Aadhaar validation) ---------------------------------
# Aadhaar numbers carry a Verhoeff check digit. The algorithm works over the
# dihedral group D5 using the standard tables:
#   _VERHOEFF_D   multiplication table of D5
#   _VERHOEFF_P   position-dependent permutation applied to each digit
#   _VERHOEFF_INV inverses in D5 (only needed to *generate* a check digit)
# Validation folds the digits right-to-left through d[c][p[i % 8][digit]];
# the number is valid iff the accumulator ends at 0.
_VERHOEFF_D = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
    [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
    [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
    [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
]
_VERHOEFF_P = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
    [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
    [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
]
_VERHOEFF_INV = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9]


def verhoeff_checksum_valid(number: str) -> bool:
    """Return True when `number` (digits only, check digit included) passes Verhoeff."""
    if not number or not number.isdigit():
        return False
    checksum = 0
    for index, char in enumerate(reversed(number)):
        checksum = _VERHOEFF_D[checksum][_VERHOEFF_P[index % 8][int(char)]]
    return checksum == 0


def verhoeff_check_digit(number: str) -> str:
    """Generate the Verhoeff check digit for `number` (digits only, no check digit).

    Exposed mainly so tests can construct known-valid Aadhaar-format vectors:
    verhoeff_checksum_valid(number + verhoeff_check_digit(number)) is True.
    """
    checksum = 0
    for index, char in enumerate(reversed(number)):
        checksum = _VERHOEFF_D[checksum][_VERHOEFF_P[(index + 1) % 8][int(char)]]
    return str(_VERHOEFF_INV[checksum])


def is_valid_aadhaar(candidate: str) -> bool:
    """Validate an Aadhaar-format candidate (12 digits, optional space/dash groups).

    A candidate is accepted ONLY if the first digit is 2-9 (Aadhaar numbers
    never start with 0 or 1) AND the Verhoeff checksum passes. Anything else
    is treated as a random 12-digit number and must NOT be flagged.
    """
    digits = re.sub(r"[\s-]", "", candidate)
    if len(digits) != 12 or not digits.isdigit():
        return False
    if digits[0] not in "23456789":
        return False
    return verhoeff_checksum_valid(digits)


# Verified UPI payment-service-provider handles. Requiring the handle to be in
# this allowlist is what keeps ordinary emails (user@gmail.com) from matching:
# common mail domains are simply not present here.
UPI_HANDLES = (
    "okaxis", "okhdfcbank", "okicici", "oksbi", "okbizaxis", "ybl", "ibl",
    "axl", "apl", "yapl", "rapl", "ptyes", "ptaxis", "pthdfc", "ptsbi",
    "upi", "paytm", "gpay", "fbl", "cnrb", "boi", "barodampay", "freecharge",
    "mahb", "kotak", "jupiteraxis", "waaxis", "wahdfcbank", "waicici", "wasbi",
)
# Longest-first alternation so longer handles are never shadowed by shorter ones.
_UPI_HANDLE_ALT = "|".join(sorted(UPI_HANDLES, key=len, reverse=True))

# Context tokens that must appear near a PAN-shaped literal (same line or
# +/-2 lines) before it is flagged; enforced in code.py.
PAN_CONTEXT_TOKENS = ("pan", "tax", "income", "itr", "kyc")

LITERAL_DATA_REGEXES: Dict[str, Pattern[str]] = {
    "Email literal": re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE),
    # (?<![0-9A-Za-z])/(?![0-9A-Za-z]) keep this from matching inside longer
    # digit runs AND letter-attached IDs (benchmark: Apple App Store ID
    # "id6746335356" matched with a digits-only lookbehind). Optional +91
    # prefix and a single space/dash after the first five digits
    # ("+91 98765 43210") are allowed; a plain "9876543210" still matches.
    "Indian mobile literal": re.compile(r"(?<![0-9A-Za-z])(?:\+91[\s-]?)?[6-9]\d{4}[\s-]?\d{5}(?![0-9A-Za-z])"),
    # PAN structure AAAPA1234A with the 4th character restricted to the valid
    # holder-type set {P,C,H,F,A,T,B,L,J,G}. Candidates are additionally
    # context-checked in code.py before being flagged.
    "PAN literal": re.compile(r"\b[A-Z]{3}[PCHFATBLJG][A-Z][0-9]{4}[A-Z]\b"),
    # Candidate only: code.py keeps a match ONLY when is_valid_aadhaar()
    # passes (first digit 2-9 AND Verhoeff checksum valid).
    "Aadhaar-like literal": re.compile(r"(?<!\d)([2-9]\d{3}[\s-]?\d{4}[\s-]?\d{4})(?!\d)"),
    # Word-bounded on both sides; the trailing lookahead rejects email-style
    # continuations such as "user@ybl.com".
    "UPI ID literal": re.compile(
        rf"(?<![A-Za-z0-9._-])[A-Za-z0-9.\-_]{{2,}}@(?:{_UPI_HANDLE_ALT})\b(?!\.[A-Za-z])",
        re.IGNORECASE,
    ),
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
    "params.require",
    "@requestbody",
    "bodyparser",
    "formdata",
    "st.text_input",
    "st.text_area",
    "input",
    "textarea",
    "useState",
    "app.post",
    "router.post",
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
    "@entity",
    "prisma.",
    "insert into",
    "update ",
    "db.",
    "repository.save",
    "objects.create",
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


def compile_hint_patterns(hints: List[str]) -> List[Pattern[str]]:
    """Compile substring hints into boundary-aware regexes.

    Raw substring checks caused false positives: "input" matched
    "inputStream", "register" matched "registerServiceWorker", "model"
    matched "ModelSerializer". Each hint is escaped and anchored with
    word-character lookarounds, but only on the sides of the hint that
    start/end with a word character, so punctuation-anchored hints such as
    "print(", "db." or "@requestbody" keep working. Hints are matched
    against lowercased text, so camelCase identifiers become single lowered
    words and short hints no longer match inside them.
    """
    compiled: List[Pattern[str]] = []
    for hint in hints:
        escaped = re.escape(hint.lower())
        prefix = r"(?<![a-z0-9_])" if (hint[0].isalnum() or hint[0] == "_") else ""
        suffix = r"(?![a-z0-9_])" if (hint[-1].isalnum() or hint[-1] == "_") else ""
        compiled.append(re.compile(prefix + escaped + suffix))
    return compiled


COLLECTION_HINT_PATTERNS: List[Pattern[str]] = compile_hint_patterns(COLLECTION_HINTS)
STORAGE_HINT_PATTERNS: List[Pattern[str]] = compile_hint_patterns(STORAGE_HINTS)
LOGGING_HINT_PATTERNS: List[Pattern[str]] = compile_hint_patterns(LOGGING_HINTS)

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
    ".sql",
    ".tf",
    ".tfvars",
    ".hcl",
    ".conf",
    ".ini",
    ".properties",
    ".gradle",
    ".lock",
    ".prisma",
    ".graphql",
    ".gql",
    # Prose files: scanned for LITERAL identifier patterns (Aadhaar/PAN/
    # mobile/UPI/email) only; code.py classifies them as "reference" context
    # so keyword-category findings are excluded (documentation noise).
    ".md",
    ".txt",
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
    camel_split = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", value)
    return re.sub(r"[^a-z0-9]+", "_", camel_split.lower()).strip("_")
