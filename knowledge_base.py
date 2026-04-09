"""
DPDPA Knowledge Base for Anumati.ai
Complete reference data for DPDPA 2023 and DPDP Rules 2025

This module stores all DPDPA 2023 and DPDP Rules 2025 knowledge in structured data
for the Anumati.ai compliance tool. Pure data structure - NO AI/LLM dependency.

Covers:
- DPDPA Sections (Act sections 1-33)
- DPDP Rules (Rules 1-16)
- Key Definitions (25+ terms)
- Compliance Checklist (50+ items)
- FAQ (20+ questions)
- Penalty Matrix (violation types and penalties)
- Timeline (key dates)
- Sector-specific guidance (6 industries)
"""

# 1. DPDPA_SECTIONS - Comprehensive section reference
DPDPA_SECTIONS = {
    1: {
        "number": 1,
        "title": "Short Title and Commencement",
        "summary": "This Act may be called the Digital Personal Data Protection Act, 2023. Section 1 came into force on August 4, 2023, with specific sections coming into force on prescribed dates per Government notification.",
        "key_requirements": [
            "The Act applies to processing of digital personal data",
            "Staggered commencement dates for different provisions"
        ],
        "applies_to": "All data fiduciaries and data principals",
        "penalties": "N/A - procedural provision"
    },
    2: {
        "number": 2,
        "title": "Definitions",
        "summary": "Defines 25 key terms used throughout the Act including Personal Data, Data Fiduciary, Data Principal, Processing, Consent, Data Protection Board, and others. Establishes foundational concepts for the entire data protection framework.",
        "key_requirements": [
            "Personal Data: any data about an individual identifiable by or in relation to such data",
            "Data Fiduciary: person who alone or in conjunction with others determines purpose and means of processing",
            "Data Principal: individual to whom personal data relates",
            "Processing: automated or partly automated operations on digital personal data",
            "Consent: voluntary, specific, informed, and clear affirmative action",
            "Significant Data Fiduciary (SDF): high-risk fiduciaries based on criteria in Section 5"
        ],
        "applies_to": "All data fiduciaries, data principals, and consent managers",
        "penalties": "N/A - definitional provision"
    },
    3: {
        "number": 3,
        "title": "Application of Act",
        "summary": "The Act applies to processing of personal data in digital form by data fiduciaries in the territory of India. It does not apply to personal data of government employees in official capacity or non-automated processing.",
        "key_requirements": [
            "Applies to digital personal data processing in India",
            "Excludes government employee data in official capacity",
            "Excludes non-digital/manual processing",
            "Applies regardless of where fiduciary or principal is located"
        ],
        "applies_to": "All data fiduciaries processing digital personal data in India",
        "penalties": "N/A - scope provision"
    },
    4: {
        "number": 4,
        "title": "Grounds for Processing",
        "summary": "Personal data may be processed only with consent of data principal or for specified legitimate uses including voluntary provision, state functions, legal obligations, and other Government-prescribed uses.",
        "key_requirements": [
            "Consent must be obtained (with specific, informed, and affirmative action)",
            "Legitimate uses available without consent: voluntary provision, state functions, legal obligations",
            "No processing for behavioral manipulation or deceptive practices",
            "Processing purpose must be disclosed before collection"
        ],
        "applies_to": "All data fiduciaries",
        "penalties": "Up to INR 50 crore for unauthorized processing"
    },
    5: {
        "number": 5,
        "title": "Legitimate Uses",
        "summary": "Specifies when personal data can be processed without explicit consent: (1) voluntary provision by individual, (2) state functions (subsidies, benefits, services, licenses, certificates), (3) legal compliance with judgments/court orders, (4) employment-related processing, (5) other Government-prescribed purposes.",
        "key_requirements": [
            "Voluntary provision for stated purpose",
            "Delivery of government services and subsidies",
            "Compliance with court orders and legal obligations",
            "Processing must be necessary for stated legitimate purpose",
            "No secondary use beyond stated purpose"
        ],
        "applies_to": "Data fiduciaries - applies when fiduciary is government entity or acting on behalf",
        "penalties": "Up to INR 50 crore for violating legitimate use boundaries"
    },
    6: {
        "number": 6,
        "title": "Notice to Data Protection Board and Data Principal",
        "summary": "Data Fiduciary must notify the Data Protection Board without delay upon becoming aware of a data breach. Within 72 hours, detailed report must be submitted. Data Principals must be notified without delay with breach details.",
        "key_requirements": [
            "Notify DPBI immediately upon breach awareness",
            "Provide detailed 72-hour report with remedial actions",
            "Notify affected data principals without delay",
            "Include nature, extent, timing, and location of breach",
            "Describe mitigation and preventive measures taken",
            "Extensions only with written request to Board"
        ],
        "applies_to": "All data fiduciaries experiencing data breaches",
        "penalties": "Up to INR 200 crore for breach notification failure"
    },
    7: {
        "number": 7,
        "title": "Data Protection Impact Assessment",
        "summary": "DPIA required by Significant Data Fiduciaries. Assessment must examine likelihood of harm to data principals' rights, adequacy of safeguards, and risks. Results must be documented and reviewed periodically.",
        "key_requirements": [
            "Mandatory for Significant Data Fiduciaries",
            "Assess processing likely to pose risk to data principal rights",
            "Document safeguards and risk mitigation",
            "Review annually or when processing changes significantly",
            "Appoint independent auditor for SDF compliance",
            "Consider automated decision-making impacts"
        ],
        "applies_to": "Significant Data Fiduciaries",
        "penalties": "Up to INR 250 crore for failure to conduct DPIA"
    },
    8: {
        "number": 8,
        "title": "Data Protection Officer",
        "summary": "Significant Data Fiduciaries must appoint a Data Protection Officer. DPO must be Indian resident, point of contact for grievances, responsible to governing body, and act as compliance focal point.",
        "key_requirements": [
            "Mandatory for Significant Data Fiduciaries only",
            "Must be Indian resident",
            "Reports to Board of Directors or Chief Executive Officer",
            "Acts as point of contact for grievance redressal",
            "Ensures compliance with DPDPA provisions",
            "Maintains independence and organizational autonomy"
        ],
        "applies_to": "Significant Data Fiduciaries",
        "penalties": "Up to INR 250 crore for non-appointment or non-functional DPO"
    },
    9: {
        "number": 9,
        "title": "Obligations of Data Fiduciary",
        "summary": "Core obligations include ensuring accuracy, protecting data from unauthorized access, maintaining retention limits, preventing secondary use, and implementing reasonable security measures. Fiduciaries must handle data only for stated purposes.",
        "key_requirements": [
            "Ensure accuracy and completeness of personal data",
            "Protect data from unauthorized access and processing",
            "Implement reasonable security safeguards",
            "Provide unhindered access to data principals",
            "Store personal data only while necessary for purpose",
            "Delete data when no longer required",
            "Process data only for stated purposes",
            "Not process data if likely to cause detriment to principal"
        ],
        "applies_to": "All data fiduciaries",
        "penalties": "Up to INR 250 crore for security safeguards failure"
    },
    10: {
        "number": 10,
        "title": "Obligations of Significant Data Fiduciary",
        "summary": "Additional stringent obligations for SDFs: appoint DPO, conduct annual DPIA, perform independent audits, maintain reasonable security, track algorithmic decisions. SDFs face heightened accountability and oversight.",
        "key_requirements": [
            "Appoint Data Protection Officer",
            "Conduct annual Data Protection Impact Assessment",
            "Undertake independent compliance audit annually",
            "Maintain enhanced security measures",
            "Monitor algorithmic software for bias/risk",
            "Track automated decision-making systems",
            "Report to Data Protection Board periodically",
            "Implement additional safeguards beyond standard requirements"
        ],
        "applies_to": "Significant Data Fiduciaries",
        "penalties": "Up to INR 250 crore for non-compliance with SDF obligations"
    },
    11: {
        "number": 11,
        "title": "Consent of Data Principal",
        "summary": "Consent must be voluntary, specific, informed, clear, and affirmative action. Cannot be bundled with other terms. Fiduciary must demonstrate consent was obtained. Consent can be withdrawn anytime.",
        "key_requirements": [
            "Consent must be voluntary and free from coercion",
            "Specific consent for each purpose (no blanket consent)",
            "Informed - data principal understands what they consent to",
            "Clear and unambiguous affirmative action (opt-in, not opt-out)",
            "Cannot be bundled with service terms/conditions",
            "Data fiduciary must maintain proof of consent",
            "Consent record must be stored for verification",
            "Data principal can withdraw consent anytime"
        ],
        "applies_to": "All data fiduciaries obtaining consent",
        "penalties": "Up to INR 50 crore for invalid or coerced consent"
    },
    12: {
        "number": 12,
        "title": "Rights of Data Principal - Correction and Erasure",
        "summary": "Data principals can request correction of inaccurate/misleading data, completion of incomplete data, or erasure of data. Fiduciary must comply within reasonable timeframe. Limited exceptions for legal retention or retention with disproportionate effort.",
        "key_requirements": [
            "Right to correct inaccurate or misleading data",
            "Right to complete incomplete data",
            "Right to request data update when circumstances change",
            "Right to erasure when data no longer needed",
            "Data principal must provide evidence of inaccuracy",
            "Fiduciary must comply within reasonable time",
            "Exceptions: legal retention requirements, court orders, disproportionate effort"
        ],
        "applies_to": "All data fiduciaries receiving data principal requests",
        "penalties": "Up to INR 50 crore for denying valid correction/erasure requests"
    },
    13: {
        "number": 13,
        "title": "Right of Data Principal to Information",
        "summary": "Data principals have right to inquire about processing their personal data, categories of data processed, purposes, recipients, and retention period. Fiduciary must provide clear, accessible information.",
        "key_requirements": [
            "Right to inquire about data processing",
            "Right to know categories of personal data held",
            "Right to know processing purposes",
            "Right to know data recipients and processors",
            "Right to know data retention period",
            "Information must be provided clearly and accessibly",
            "Response required within reasonable timeframe"
        ],
        "applies_to": "All data fiduciaries receiving information requests",
        "penalties": "Up to INR 50 crore for denying information access"
    },
    14: {
        "number": 14,
        "title": "Rights of Data Principal - Grievance Redressal",
        "summary": "Data principals have right to file grievances with Data Protection Board. Board may initiate inquiries into violations. Fiduciaries must maintain internal grievance redressal mechanism.",
        "key_requirements": [
            "Right to file grievance with Data Protection Board",
            "Board has authority to initiate inquiries",
            "Data fiduciary must maintain internal complaint mechanism",
            "Grievances must be addressed in reasonable time",
            "Data fiduciary must maintain grievance records",
            "No retaliation against data principals filing complaints"
        ],
        "applies_to": "Data Protection Board and all data fiduciaries",
        "penalties": "Up to INR 50 crore for denying grievance rights"
    },
    15: {
        "number": 15,
        "title": "Processing by Data Processor",
        "summary": "Data Processor is agent acting on fiduciary's instructions. Processing contract must clearly define roles. Processor has limited obligations. Fiduciary remains responsible for processor's acts.",
        "key_requirements": [
            "Processing must be on written instructions only",
            "Contract must clearly define processor obligations",
            "Processor cannot process data for own purposes",
            "Fiduciary remains responsible for processor compliance",
            "Processor must implement security safeguards",
            "Sub-processor authorization requires fiduciary consent",
            "Processor must maintain processing logs"
        ],
        "applies_to": "Data fiduciaries and their processors",
        "penalties": "Up to INR 50 crore for improper processor arrangement"
    },
    16: {
        "number": 16,
        "title": "Consent Managers",
        "summary": "Consent Managers are intermediaries managing consent on behalf of data principals. Must be registered with Data Protection Board. Have specific obligations regarding consent recording and data principal notification.",
        "key_requirements": [
            "Must be incorporated in India",
            "Must meet eligibility criteria and financial thresholds",
            "Must register with Data Protection Board",
            "Must maintain separate consent records",
            "Must facilitate consent withdrawal",
            "Must not process personal data itself",
            "Must implement security safeguards",
            "Registration effective November 13, 2026"
        ],
        "applies_to": "Consent Manager entities",
        "penalties": "Up to INR 50 crore for operating without registration or violating obligations"
    },
    17: {
        "number": 17,
        "title": "Data Transfer Outside India",
        "summary": "Personal data may be transferred outside India if reasonable safeguards exist and fiduciary ensures recipient country has adequate data protection. Transfer requires explicit consent unless for legitimate use.",
        "key_requirements": [
            "Transfer requires explicit consent (no bundled consent)",
            "Exception for legitimate uses with notice",
            "Recipient country/entity must have reasonable safeguards",
            "Assessment of recipient's data protection adequacy",
            "Fiduciary responsible for recipient's processing",
            "Cannot transfer if would circumvent DPDPA",
            "Documentation of transfer and safeguards required"
        ],
        "applies_to": "Data fiduciaries transferring data internationally",
        "penalties": "Up to INR 250 crore for unauthorized international transfer"
    },
    18: {
        "number": 18,
        "title": "Children's Data Protection",
        "summary": "Special protections for individuals under 18. Verifiable parental/guardian consent required. Behavioral monitoring and targeted advertising strictly prohibited. Enhanced safeguards for children's data.",
        "key_requirements": [
            "Parental/guardian verifiable consent required for processing",
            "Cannot track or monitor children's behavior",
            "Cannot target advertising to children",
            "Cannot process if likely to cause detriment to child",
            "Enhanced privacy notices for parent/guardian",
            "Age verification mechanisms required",
            "No profiling of children without guardian consent"
        ],
        "applies_to": "All data fiduciaries processing children's data",
        "penalties": "Up to INR 250 crore for children's data violations"
    },
    19: {
        "number": 19,
        "title": "Data Protection Board - Constitution",
        "summary": "Establishes Data Protection Board of India as fully digital regulator. Board comprises Chairperson, Member-Secretary, and Members. Headquartered in New Delhi with regional offices.",
        "key_requirements": [
            "Board is apex regulatory authority",
            "Reports to Ministry of Electronics and IT",
            "Chairperson appointed by Central Government",
            "Members selected through transparent process",
            "Board operates fully digital infrastructure",
            "Provides online grievance filing and tracking",
            "Regional offices established across India"
        ],
        "applies_to": "Central Government and Board operations",
        "penalties": "N/A - institutional provision"
    },
    20: {
        "number": 20,
        "title": "Data Protection Board - Powers and Functions",
        "summary": "Board has extensive powers: receive and process grievances, investigate violations, conduct inquiries, issue orders, impose penalties, make rules, coordinate internationally, and maintain transparency.",
        "key_requirements": [
            "Receive and process data principal grievances",
            "Investigate alleged violations",
            "Conduct own-motion inquiries",
            "Issue directions and remedial orders",
            "Impose monetary penalties",
            "Maintain transparency through public registry",
            "Coordinate with international authorities",
            "Make rules within Board's scope"
        ],
        "applies_to": "Data Protection Board",
        "penalties": "N/A - authority provision"
    },
    21: {
        "number": 21,
        "title": "Data Protection Board - Procedure",
        "summary": "Board follows natural justice principles with opportunity to be heard. Inquiries conducted in camera unless otherwise directed. Digital proceedings for transparency. Orders published publicly.",
        "key_requirements": [
            "Natural justice principles apply",
            "Opportunity to be heard for accused",
            "In camera inquiries (unless directed otherwise)",
            "Digital proceedings and records",
            "Written orders with reasoned findings",
            "Orders published on public website",
            "Appeal mechanisms available",
            "Confidentiality of personal data maintained"
        ],
        "applies_to": "Data Protection Board proceedings",
        "penalties": "N/A - procedural provision"
    },
    22: {
        "number": 22,
        "title": "Appeals",
        "summary": "Data fiduciaries can appeal Board's orders to appellate authority (designated by Government). Appeal must be filed within 30 days of order. Appellate authority can confirm, modify, or reverse order.",
        "key_requirements": [
            "Appeal to designated appellate authority within 30 days",
            "Appellate authority reviews Board's findings",
            "Can confirm, modify, or reverse order",
            "Stay of Board's order can be requested",
            "Natural justice applies to appeals",
            "Appellate decision final"
        ],
        "applies_to": "Data fiduciaries appealing Board orders",
        "penalties": "N/A - procedural provision"
    },
    23: {
        "number": 23,
        "title": "Rule-making",
        "summary": "Government empowered to make rules to implement the Act. Rules prescribe procedures, forms, eligibility criteria, and operational details. DPDP Rules 2025 notified on November 14, 2025.",
        "key_requirements": [
            "Government makes implementing rules",
            "Rules prescribe details for Act's provisions",
            "DPDP Rules 2025 effective from November 14, 2025",
            "Staggered implementation of various rules",
            "Rules subject to parliamentary procedure",
            "Board also can make procedural rules"
        ],
        "applies_to": "Government and Data Protection Board",
        "penalties": "N/A - rule-making authority"
    },
    24: {
        "number": 24,
        "title": "Jurisdiction",
        "summary": "Board has jurisdiction over violations within India's territory. Can receive grievances from any data principal regarding data fiduciaries processing in India.",
        "key_requirements": [
            "Board jurisdiction over India territory",
            "Applies to all fiduciaries processing in India",
            "Data principal location irrelevant",
            "Fiduciary location irrelevant if processing in India"
        ],
        "applies_to": "Data Protection Board",
        "penalties": "N/A - jurisdictional provision"
    },
    25: {
        "number": 25,
        "title": "Representation of Fiduciaries and Data Principals",
        "summary": "Parties can be represented before Board through authorized representatives, advocates, or others with Board's permission. Representation subject to natural justice.",
        "key_requirements": [
            "Right to be represented before Board",
            "Advocates, authorized representatives allowed",
            "Board can permit other representatives",
            "Representation at parties' own cost",
            "Proceedings open unless confidentiality ordered"
        ],
        "applies_to": "Board proceedings and parties",
        "penalties": "N/A - procedural provision"
    },
    26: {
        "number": 26,
        "title": "Protection of Members",
        "summary": "Board members and officers have protection for actions taken in good faith during duties. Prevents frivolous litigation against Board officials.",
        "key_requirements": [
            "Members/officers protected for good faith acts",
            "Protection extends to Board staff",
            "Only applies to official duty actions"
        ],
        "applies_to": "Board members and officers",
        "penalties": "N/A - protection provision"
    },
    27: {
        "number": 27,
        "title": "Power to Remove Obstacles",
        "summary": "Government can issue directions to remove obstacles to implementation. Can require Board cooperation with central/state bodies.",
        "key_requirements": [
            "Government can issue implementation directions",
            "Board must cooperate with Government bodies",
            "Coordination between state and central authorities"
        ],
        "applies_to": "Government and Board",
        "penalties": "N/A - administrative provision"
    },
    28: {
        "number": 28,
        "title": "Confidentiality",
        "summary": "Board members, staff must maintain confidentiality of information received during proceedings. Protects data principals' and fiduciaries' sensitive business information.",
        "key_requirements": [
            "Maintain confidentiality of proceeding information",
            "Protects data principal personal data",
            "Protects fiduciary business confidential information",
            "Applies to Board members and staff",
            "Extends after service termination"
        ],
        "applies_to": "Board members, staff, and proceedings",
        "penalties": "N/A - confidentiality provision"
    },
    29: {
        "number": 29,
        "title": "Immunity from Liability",
        "summary": "Board and members have immunity for acts done in official capacity. Protects against frivolous claims while maintaining accountability through appellate mechanism.",
        "key_requirements": [
            "Immunity for good faith official acts",
            "No liability for Board decisions in official capacity",
            "Appeal mechanism provides accountability",
            "Protects Board independence"
        ],
        "applies_to": "Board and members",
        "penalties": "N/A - immunity provision"
    },
    30: {
        "number": 30,
        "title": "Penalty for Unauthorized Processing",
        "summary": "Data fiduciaries must not process personal data without valid legal basis (consent or legitimate use). Unauthorized processing attracts up to INR 50 crore penalty.",
        "key_requirements": [
            "Processing must have valid legal basis",
            "Unauthorized processing prohibited",
            "Processing for undisclosed purposes prohibited",
            "No secondary use for different purposes",
            "Must document consent or legitimate use basis"
        ],
        "applies_to": "All data fiduciaries",
        "penalties": "Up to INR 50 crore"
    },
    31: {
        "number": 31,
        "title": "Penalty for Failure to Discharge Obligations",
        "summary": "Failure to discharge fiduciary obligations (accuracy, security, deletion, etc.) attracts penalties. Tiered structure based on violation severity.",
        "key_requirements": [
            "Maintain data accuracy",
            "Protect from unauthorized access",
            "Implement security safeguards",
            "Delete data timely",
            "Provide access to principals",
            "Maintain retention limits"
        ],
        "applies_to": "All data fiduciaries",
        "penalties": "Up to INR 250 crore depending on violation type"
    },
    32: {
        "number": 32,
        "title": "Penalty for Failure to Comply with Orders",
        "summary": "Failure to comply with Board orders, directions, or corrective measures attracts penalties. Board can impose progressive penalties for continued non-compliance.",
        "key_requirements": [
            "Comply with Board orders",
            "Comply with Board directions",
            "Implement remedial measures",
            "Provide information to Board when required",
            "Meet Board deadlines"
        ],
        "applies_to": "All data fiduciaries and consent managers",
        "penalties": "Up to INR 50 crore"
    },
    33: {
        "number": 33,
        "title": "Penalty Imposition",
        "summary": "Board considers breach nature, gravity, duration, data type, and affected individuals when determining penalties. Schedule appended to Act specifies maximum penalties for each violation category.",
        "key_requirements": [
            "Board imposes penalties based on Schedule",
            "Consider breach nature and gravity",
            "Consider duration of breach",
            "Consider personal data types affected",
            "Consider number of data principals affected",
            "Consider harm potential and actual harm",
            "Monetary penalties in absolute amounts (not revenue percentage)",
            "Board can require remedial actions alongside penalties"
        ],
        "applies_to": "Data Protection Board enforcement",
        "penalties": "INR 50 crore to INR 250 crore based on violation type"
    }
}


# 2. DPDP_RULES - Comprehensive rules reference
DPDP_RULES = {
    1: {
        "number": 1,
        "title": "Definitions and Interpretation",
        "summary": "Defines terms used in rules including Consent Manager, Data Protection Officer, processing logs, sensitive personal data indicators, and other operational terms.",
        "requirements": [
            "Clarifies terms specific to Rules implementation",
            "Provides examples for key concepts",
            "Establishes standards for operational definitions"
        ],
        "deadline": "Effective November 14, 2025",
        "applies_to": "All implementing authorities"
    },
    2: {
        "number": 2,
        "title": "Notice to Data Principal",
        "summary": "Data Fiduciaries must provide clear, standalone notices to data principals. Notice must include personal data categories, processing purposes, recipients, retention period, and principal's rights.",
        "requirements": [
            "Standalone notice (not buried in T&Cs)",
            "Clear language and accessible format",
            "Itemized list of personal data collected",
            "Specific purposes of processing",
            "Retention period or deletion policy",
            "Links to withdraw consent and exercise rights",
            "Information about grievance redressal mechanism"
        ],
        "deadline": "Must be provided before or at data collection",
        "applies_to": "All data fiduciaries"
    },
    3: {
        "number": 3,
        "title": "Consent",
        "summary": "Prescribes detailed consent requirements and procedures. Consent must be documented, specific, informed, and voluntary. Fiduciary must maintain proof of consent.",
        "requirements": [
            "Clear affirmative action (checkbox, button click, etc.)",
            "Specific consent for each purpose",
            "Cannot be bundled with service terms",
            "Fiduciary maintains consent records",
            "Easy withdrawal mechanism",
            "Consent scope clearly defined",
            "Cannot be condition for unrelated service"
        ],
        "deadline": "Effective May 13, 2027",
        "applies_to": "All data fiduciaries obtaining consent"
    },
    4: {
        "number": 4,
        "title": "Registration and Obligations of Consent Manager",
        "summary": "Consent Managers must be registered with Board. Specifies eligibility criteria, registration process, obligations, and compliance requirements.",
        "requirements": [
            "Incorporated in India (company, society, or trust)",
            "Minimum net worth of INR 2 crore",
            "Sound financial condition and management",
            "Technical, operational, and financial capacity",
            "Maintain separate consent records",
            "Implement robust security safeguards",
            "Facilitate consent withdrawal easily",
            "Not process personal data itself",
            "Submit annual compliance reports to Board"
        ],
        "deadline": "Registration effective November 13, 2026",
        "applies_to": "Entities operating as Consent Managers"
    },
    5: {
        "number": 5,
        "title": "Data Retention and Deletion",
        "summary": "Data Fiduciaries must retain personal data only while necessary. Must establish retention schedules and timely delete data when no longer required.",
        "requirements": [
            "Establish data retention policy",
            "Delete data when purpose fulfilled",
            "Maintain retention schedule",
            "Document deletion procedures",
            "Cannot indefinitely retain data",
            "Log retention and deletion activities",
            "Exception: legal retention requirements"
        ],
        "deadline": "Effective May 13, 2027",
        "applies_to": "All data fiduciaries"
    },
    6: {
        "number": 6,
        "title": "Security Safeguards",
        "summary": "Prescribes security measures to protect personal data from unauthorized access, disclosure, modification, or deletion. Includes technical and organizational safeguards.",
        "requirements": [
            "Implement reasonable security safeguards",
            "Encryption for personal data at rest and in transit",
            "Access controls and authentication",
            "Regular security testing and penetration testing",
            "Incident response procedures",
            "Employee training and awareness",
            "Vulnerability assessment and patch management",
            "Audit trails and logging",
            "Data minimization principles"
        ],
        "deadline": "Effective May 13, 2027",
        "applies_to": "All data fiduciaries"
    },
    7: {
        "number": 7,
        "title": "Data Breach Notification",
        "summary": "Specifies procedures for data breach notification to Board and affected principals. Requires 72-hour reporting with detailed information.",
        "requirements": [
            "Notify Board immediately upon breach discovery",
            "Provide detailed 72-hour report",
            "Notify affected principals without delay",
            "Describe breach nature, extent, and impact",
            "Include mitigation and remedial measures",
            "Maintain breach documentation",
            "Extensions only with Board approval",
            "No materiality threshold - all breaches reportable"
        ],
        "deadline": "72 hours for detailed report (effective May 13, 2027)",
        "applies_to": "All data fiduciaries experiencing breaches"
    },
    8: {
        "number": 8,
        "title": "Data Principal Rights - Access, Correction, Deletion",
        "summary": "Establishes mechanisms for data principals to exercise rights: access information about their data, correct inaccuracies, and request deletion.",
        "requirements": [
            "Respond to access requests within 30 days",
            "Provide information in clear, accessible format",
            "Respond to correction requests promptly",
            "Respond to deletion requests if no legal hold",
            "Maintain records of requests and responses",
            "Cannot charge unreasonable fees",
            "Support data principal understanding"
        ],
        "deadline": "Effective May 13, 2027",
        "applies_to": "All data fiduciaries"
    },
    9: {
        "number": 9,
        "title": "Grievance Redressal",
        "summary": "Data Fiduciaries must establish grievance mechanisms. Board provides centralized grievance portal for data principals.",
        "requirements": [
            "Maintain internal grievance mechanism",
            "Respond to grievances within 30 days",
            "Escalate to DPO if SDF",
            "No retaliation against complainants",
            "Maintain grievance records",
            "Board provides online portal for filing",
            "Track and report grievance resolution"
        ],
        "deadline": "Effective May 13, 2027",
        "applies_to": "All data fiduciaries"
    },
    10: {
        "number": 10,
        "title": "Processing of Personal Data of Children",
        "summary": "Establishes special protections for children (under 18). Requires verifiable parental/guardian consent, prohibits behavioral tracking and targeted advertising.",
        "requirements": [
            "Obtain verifiable parental/guardian consent",
            "Age verification mechanisms",
            "Prohibit behavioral tracking/monitoring",
            "Prohibit targeted advertising to children",
            "Enhanced privacy notices",
            "Cannot profile children",
            "Consider best interests of child",
            "No processing if likely to cause detriment"
        ],
        "deadline": "Effective May 13, 2027",
        "applies_to": "Data fiduciaries processing children's data"
    },
    11: {
        "number": 11,
        "title": "Processing of Personal Data of Persons with Disability",
        "summary": "Establishes safeguards for processing data of persons with disabilities. Requires accessibility in all processes and special consideration of their needs.",
        "requirements": [
            "Accessible notice mechanisms",
            "Support for exercising data rights",
            "Accessible grievance mechanisms",
            "Consider dignity and autonomy",
            "Reasonable accommodations provided",
            "Informed consent with support if needed"
        ],
        "deadline": "Effective May 13, 2027",
        "applies_to": "Data fiduciaries processing data of persons with disabilities"
    },
    12: {
        "number": 12,
        "title": "Data Processors",
        "summary": "Establishes obligations for data processors acting on fiduciary's instructions. Processor must implement safeguards and assist fiduciary in compliance.",
        "requirements": [
            "Written processing contract required",
            "Processor acts on fiduciary instructions only",
            "Cannot process for own purposes",
            "Implement security safeguards",
            "Maintain processing logs",
            "Assist in data principal rights exercise",
            "Assist in breach notification",
            "Sub-processor authorization required"
        ],
        "deadline": "Effective May 13, 2027",
        "applies_to": "Data fiduciaries and their processors"
    },
    13: {
        "number": 13,
        "title": "Additional Obligations of Significant Data Fiduciary",
        "summary": "Establishes heightened obligations for SDFs: appoint DPO, conduct annual DPIA, perform independent audits, monitor algorithmic decisions.",
        "requirements": [
            "Appoint Indian resident Data Protection Officer",
            "Conduct annual Data Protection Impact Assessment",
            "Undertake independent compliance audit annually",
            "Maintain enhanced security measures",
            "Monitor algorithmic software for risk/bias",
            "Track automated decision-making systems",
            "Document all compliance activities",
            "Report to Board as required",
            "Implement additional safeguards"
        ],
        "deadline": "Effective May 13, 2027 (SDF obligations)",
        "applies_to": "Significant Data Fiduciaries"
    },
    14: {
        "number": 14,
        "title": "International Data Transfer",
        "summary": "Prescribes requirements for transferring personal data outside India. Requires explicit consent and adequate safeguards in recipient jurisdiction.",
        "requirements": [
            "Explicit consent for international transfer",
            "Exception for legitimate uses (with notice)",
            "Assess recipient jurisdiction protections",
            "Ensure adequate data protection framework",
            "Document transfer and safeguards",
            "Fiduciary remains responsible for recipient",
            "Cannot transfer to circumvent DPDPA",
            "Board can restrict transfers to certain countries"
        ],
        "deadline": "Effective May 13, 2027",
        "applies_to": "Data fiduciaries transferring data internationally"
    },
    15: {
        "number": 15,
        "title": "Significant Data Fiduciary - Criteria and Determination",
        "summary": "Specifies criteria for determining SDF status. Includes volume of data, use for impactful decisions, sensitive data, critical infrastructure, and data combination factors.",
        "requirements": [
            "Government notifies SDF classifications",
            "Consider volume of personal data (50+ lakh Indian residents)",
            "Consider impactful automated decisions",
            "Consider sensitive data processing",
            "Consider critical information infrastructure",
            "Consider cross-sectoral data use",
            "Consider emerging technology use",
            "Consider national security/democracy impact"
        ],
        "deadline": "Criteria notified under Rule 15",
        "applies_to": "Government and data fiduciaries"
    },
    16: {
        "number": 16,
        "title": "Legitimate Uses",
        "summary": "Provides detailed guidance on processing without consent for legitimate uses: voluntary provision, state functions, legal obligations, and Government-prescribed purposes.",
        "requirements": [
            "Voluntary provision with informed choice",
            "State subsidies and benefits delivery",
            "Court orders and legal obligations",
            "Employment relationship processing",
            "Government-prescribed uses",
            "Processing limited to stated purpose",
            "Transparency in legitimate use processing",
            "Data principal notification required"
        ],
        "deadline": "Effective May 13, 2027",
        "applies_to": "All data fiduciaries relying on legitimate uses"
    }
}


# 3. KEY_DEFINITIONS - Comprehensive term definitions
KEY_DEFINITIONS = {
    "Personal Data": "Any data about an individual who is identifiable by or in relation to such data. Includes name, email, phone, IP address, ID number, or any information linking to an individual.",

    "Data Principal": "The individual to whom the personal data relates. The rights holder who can exercise control over their data.",

    "Data Fiduciary": "Any person who alone or in conjunction with other persons determines the purpose and means of processing of personal data. Decision-maker about how and why data is processed.",

    "Data Processor": "A person who processes personal data on behalf of a data fiduciary. Acts only on fiduciary's instructions and cannot process for own purposes.",

    "Processing": "Wholly or partly automated operation or set of operations performed on digital personal data, including collection, recording, organization, storage, retrieval, use, disclosure, or deletion.",

    "Consent": "Voluntary, specific, informed, and clear affirmative action by data principal agreeing to processing. Must be freely given without coercion or being bundled with other terms.",

    "Withdrawal of Consent": "Data principal's right to withdraw consent at any time. Fiduciary must provide easy mechanism for withdrawal.",

    "Data Protection Board": "Apex regulatory authority for DPDPA enforcement. Receives grievances, conducts inquiries, imposes penalties, and makes rules within scope.",

    "Data Protection Officer": "Individual appointed by Significant Data Fiduciaries to ensure DPDPA compliance. Must be Indian resident, point of contact for grievances.",

    "Significant Data Fiduciary": "Data fiduciary meeting criteria: large volume data (50+ lakh Indian residents), impactful automated decisions, sensitive data, critical infrastructure, or data combination factors.",

    "Data Breach": "Unauthorized access, disclosure, modification, deletion, or loss of personal data. Must be reported to Board within 72 hours.",

    "Breach Notification": "Notice to Data Protection Board and affected data principals describing breach nature, extent, impact, and mitigation measures.",

    "Security Safeguards": "Technical and organizational measures protecting personal data from unauthorized access, modification, or deletion. Include encryption, access controls, auditing.",

    "Data Retention": "Period for which personal data is kept. Fiduciary must delete data when no longer necessary for purpose.",

    "Data Deletion": "Permanent removal of personal data from systems. Fiduciary must delete upon request or when retention period expires.",

    "Legitimate Use": "Processing without explicit consent for purposes: voluntary provision, state functions, legal obligations, employment, or Government-prescribed uses.",

    "Cross-border Data Transfer": "Transfer of personal data outside India. Requires explicit consent or legitimate use justification. Recipient must have adequate protections.",

    "Consent Manager": "Registered intermediary managing consents on behalf of data principals. Must meet eligibility criteria and register with Board.",

    "Data Protection Impact Assessment": "Mandatory assessment for SDFs examining likelihood of harm to principals' rights, adequacy of safeguards, and mitigation measures. Conducted annually.",

    "Automated Decision-making": "Decisions made wholly by technical systems without human involvement. Fiduciary must assess impact and maintain human oversight.",

    "Behavioral Tracking": "Monitoring of individual's online activities, preferences, or behavior. Prohibited for children; requires consent for adults.",

    "Targeted Advertising": "Advertisements directed at individuals based on profiling. Prohibited for children under DPDPA.",

    "Grievance": "Formal complaint to Data Protection Board alleging violation of DPDPA provisions by data fiduciary.",

    "Child": "Individual under 18 years of age. Subject to enhanced data protection and parental consent requirements.",

    "Sensitive Personal Data": "Under DPDPA, all personal data is treated similarly. However, certain categories like children's, disability, and behavioral data require higher protections.",

    "Data Minimization": "Collecting only personal data necessary for stated purpose. Fiduciary must not collect excessive data.",

    "Purpose Limitation": "Personal data collected for specific purpose cannot be used for different purposes without fresh consent.",

    "Transparency": "Data principals must be clearly informed about data collection, processing, purposes, and their rights.",

    "Accountability": "Data fiduciary responsible for compliance and must demonstrate it through documentation and records."
}


# 4. COMPLIANCE_CHECKLIST - Comprehensive compliance items
COMPLIANCE_CHECKLIST = {
    "Governance": [
        {
            "item": "Assess SDF Status",
            "description": "Determine if organization qualifies as Significant Data Fiduciary based on data volume, processing impact, or data sensitivity",
            "priority": "CRITICAL",
            "section_reference": "Section 5, Rule 15",
            "is_sdf_only": False
        },
        {
            "item": "Appoint Data Protection Officer",
            "description": "SDFs must appoint Indian resident DPO responsible to Board/CEO, acting as compliance focal point",
            "priority": "CRITICAL",
            "section_reference": "Section 8",
            "is_sdf_only": True
        },
        {
            "item": "Establish Grievance Mechanism",
            "description": "Create internal grievance redressal process with 30-day response target. Escalate to DPO if SDF",
            "priority": "CRITICAL",
            "section_reference": "Section 14, Rule 9",
            "is_sdf_only": False
        },
        {
            "item": "Maintain Data Fiduciary Records",
            "description": "Document all processing activities, legal bases, consent records, breach reports, and compliance evidence",
            "priority": "HIGH",
            "section_reference": "Section 9",
            "is_sdf_only": False
        },
        {
            "item": "Create Data Retention Policy",
            "description": "Establish written policy specifying retention period for each data category and deletion procedures",
            "priority": "HIGH",
            "section_reference": "Section 9, Rule 5",
            "is_sdf_only": False
        }
    ],
    "Consent Management": [
        {
            "item": "Obtain Written Consent",
            "description": "Collect voluntary, specific, informed, clear affirmative consent. Maintain proof and records",
            "priority": "CRITICAL",
            "section_reference": "Section 11, Rule 3",
            "is_sdf_only": False
        },
        {
            "item": "Use Consent Manager for Consent Collection",
            "description": "Consider using registered Consent Manager to collect and manage consents on behalf of fiduciary",
            "priority": "MEDIUM",
            "section_reference": "Section 16, Rule 4",
            "is_sdf_only": False
        },
        {
            "item": "Implement Consent Withdrawal Mechanism",
            "description": "Provide easy mechanism for data principals to withdraw consent at any time",
            "priority": "HIGH",
            "section_reference": "Section 11",
            "is_sdf_only": False
        },
        {
            "item": "Avoid Bundled Consent",
            "description": "Do not bundle data consent with service terms. Consent must be separate, specific, and optional",
            "priority": "CRITICAL",
            "section_reference": "Section 11, Rule 3",
            "is_sdf_only": False
        },
        {
            "item": "Obtain Parental Consent for Children",
            "description": "For children (under 18), obtain verifiable consent from parent or guardian before processing",
            "priority": "CRITICAL",
            "section_reference": "Section 9(1)(d), Rule 10",
            "is_sdf_only": False
        }
    ],
    "Data Privacy Notices": [
        {
            "item": "Create Standalone Privacy Notice",
            "description": "Provide clear, standalone notice (not buried in T&Cs) disclosing all data collection and processing details",
            "priority": "CRITICAL",
            "section_reference": "Rule 2",
            "is_sdf_only": False
        },
        {
            "item": "Itemize Personal Data Categories",
            "description": "Clearly list each category of personal data collected with examples",
            "priority": "HIGH",
            "section_reference": "Rule 2",
            "is_sdf_only": False
        },
        {
            "item": "Disclose Processing Purposes",
            "description": "Specify every purpose for which personal data will be processed",
            "priority": "CRITICAL",
            "section_reference": "Rule 2",
            "is_sdf_only": False
        },
        {
            "item": "Include Data Retention Period",
            "description": "Clearly state how long personal data will be retained and deletion policy",
            "priority": "HIGH",
            "section_reference": "Rule 2, Rule 5",
            "is_sdf_only": False
        },
        {
            "item": "Disclose Data Recipients",
            "description": "Identify parties who will receive personal data (processors, partners, government agencies)",
            "priority": "HIGH",
            "section_reference": "Rule 2",
            "is_sdf_only": False
        },
        {
            "item": "Include Data Principal Rights Information",
            "description": "Inform about rights: access, correction, deletion, grievance filing with links/instructions",
            "priority": "HIGH",
            "section_reference": "Rule 2, Rule 8",
            "is_sdf_only": False
        },
        {
            "item": "Update Privacy Notices",
            "description": "Review and update notices when processing changes or new purposes added",
            "priority": "MEDIUM",
            "section_reference": "Rule 2",
            "is_sdf_only": False
        }
    ],
    "Security and Data Protection": [
        {
            "item": "Implement Security Safeguards",
            "description": "Deploy technical and organizational measures: encryption, access controls, authentication, auditing",
            "priority": "CRITICAL",
            "section_reference": "Section 9, Rule 6",
            "is_sdf_only": False
        },
        {
            "item": "Encrypt Data at Rest",
            "description": "Use strong encryption for stored personal data in databases, backups, archives",
            "priority": "CRITICAL",
            "section_reference": "Rule 6",
            "is_sdf_only": False
        },
        {
            "item": "Encrypt Data in Transit",
            "description": "Use TLS/SSL encryption for data transmission over networks and internet",
            "priority": "CRITICAL",
            "section_reference": "Rule 6",
            "is_sdf_only": False
        },
        {
            "item": "Implement Access Controls",
            "description": "Restrict access to personal data to authorized personnel only. Use role-based access control",
            "priority": "CRITICAL",
            "section_reference": "Rule 6",
            "is_sdf_only": False
        },
        {
            "item": "Maintain Processing Logs",
            "description": "Document all processing activities including access, modification, deletion with timestamps and user info",
            "priority": "HIGH",
            "section_reference": "Rule 6",
            "is_sdf_only": False
        },
        {
            "item": "Conduct Security Audits",
            "description": "Regularly audit security safeguards through internal reviews and third-party assessments",
            "priority": "MEDIUM",
            "section_reference": "Rule 6",
            "is_sdf_only": False
        },
        {
            "item": "Perform Penetration Testing",
            "description": "Test systems against vulnerabilities and simulated attacks. Remediate findings promptly",
            "priority": "MEDIUM",
            "section_reference": "Rule 6",
            "is_sdf_only": False
        },
        {
            "item": "Manage Vendor/Processor Security",
            "description": "Ensure data processors implement equivalent security measures through contracts and audits",
            "priority": "HIGH",
            "section_reference": "Section 15, Rule 12",
            "is_sdf_only": False
        }
    ],
    "Data Breach Management": [
        {
            "item": "Establish Breach Detection Mechanism",
            "description": "Implement tools and processes to detect unauthorized access, disclosure, or modification of personal data",
            "priority": "CRITICAL",
            "section_reference": "Section 6",
            "is_sdf_only": False
        },
        {
            "item": "Notify Board Within 72 Hours",
            "description": "Report data breach to Data Protection Board with detailed information within 72 hours of discovery",
            "priority": "CRITICAL",
            "section_reference": "Section 6, Rule 7",
            "is_sdf_only": False
        },
        {
            "item": "Notify Data Principals Without Delay",
            "description": "Inform affected data principals of breach, its nature, extent, and mitigation measures",
            "priority": "CRITICAL",
            "section_reference": "Section 6, Rule 7",
            "is_sdf_only": False
        },
        {
            "item": "Maintain Breach Records",
            "description": "Document all breaches with discovery date, notification evidence, impact assessment, and remediation",
            "priority": "HIGH",
            "section_reference": "Section 6",
            "is_sdf_only": False
        },
        {
            "item": "Create Incident Response Plan",
            "description": "Develop procedures for breach discovery, containment, notification, remediation, and communication",
            "priority": "HIGH",
            "section_reference": "Rule 7",
            "is_sdf_only": False
        },
        {
            "item": "Train Employees on Breach Response",
            "description": "Ensure staff know breach discovery procedures, reporting, and notification requirements",
            "priority": "MEDIUM",
            "section_reference": "Rule 7",
            "is_sdf_only": False
        }
    ],
    "Data Principal Rights": [
        {
            "item": "Enable Access Requests",
            "description": "Provide mechanism for data principals to access their personal data. Respond within 30 days",
            "priority": "HIGH",
            "section_reference": "Section 13, Rule 8",
            "is_sdf_only": False
        },
        {
            "item": "Enable Correction Requests",
            "description": "Allow data principals to correct inaccurate/misleading data. Process promptly",
            "priority": "HIGH",
            "section_reference": "Section 12, Rule 8",
            "is_sdf_only": False
        },
        {
            "item": "Enable Deletion Requests",
            "description": "Allow data principals to request erasure of personal data. Delete unless legal retention required",
            "priority": "HIGH",
            "section_reference": "Section 12, Rule 8",
            "is_sdf_only": False
        },
        {
            "item": "Provide Information in Accessible Format",
            "description": "Respond to principal requests with clear information in commonly understood format",
            "priority": "MEDIUM",
            "section_reference": "Rule 8",
            "is_sdf_only": False
        },
        {
            "item": "Do Not Charge Excessive Fees",
            "description": "If charging for access requests, fees must be reasonable and not excessive",
            "priority": "MEDIUM",
            "section_reference": "Rule 8",
            "is_sdf_only": False
        }
    ],
    "Children and Vulnerable Groups": [
        {
            "item": "Identify Children's Data Processing",
            "description": "Map all processing of children's personal data and implement enhanced protections",
            "priority": "CRITICAL",
            "section_reference": "Section 9(1)(d), Rule 10",
            "is_sdf_only": False
        },
        {
            "item": "Implement Age Verification",
            "description": "Implement mechanisms to verify age of users. Treat under-18 as child requiring parental consent",
            "priority": "HIGH",
            "section_reference": "Rule 10",
            "is_sdf_only": False
        },
        {
            "item": "Prohibit Behavioral Tracking of Children",
            "description": "Do not track, monitor, or profile children's online behavior, activities, or preferences",
            "priority": "CRITICAL",
            "section_reference": "Section 9(1)(d)",
            "is_sdf_only": False
        },
        {
            "item": "Prohibit Targeted Advertising to Children",
            "description": "Do not direct advertisements to children based on profiling or behavior",
            "priority": "CRITICAL",
            "section_reference": "Section 9(1)(d)",
            "is_sdf_only": False
        },
        {
            "item": "Provide Accessible Mechanisms for Disability",
            "description": "Ensure all DPDPA-related mechanisms (notices, grievance, rights exercise) are accessible to persons with disabilities",
            "priority": "HIGH",
            "section_reference": "Rule 11",
            "is_sdf_only": False
        }
    ],
    "Data Processors and Vendors": [
        {
            "item": "Identify All Data Processors",
            "description": "Document all third parties processing personal data on your behalf (hosting, analytics, CRM, etc.)",
            "priority": "HIGH",
            "section_reference": "Section 15, Rule 12",
            "is_sdf_only": False
        },
        {
            "item": "Execute Data Processing Contracts",
            "description": "Have written agreement with each processor clearly defining roles, obligations, and security requirements",
            "priority": "CRITICAL",
            "section_reference": "Section 15, Rule 12",
            "is_sdf_only": False
        },
        {
            "item": "Restrict Processor to Instructions",
            "description": "Ensure processor agreement explicitly prohibits processing beyond fiduciary's instructions",
            "priority": "CRITICAL",
            "section_reference": "Section 15, Rule 12",
            "is_sdf_only": False
        },
        {
            "item": "Audit Processor Security",
            "description": "Conduct or require audits of processor's security and compliance measures annually",
            "priority": "HIGH",
            "section_reference": "Rule 12",
            "is_sdf_only": False
        },
        {
            "item": "Control Sub-processor Use",
            "description": "Require processor to get your approval before engaging sub-processors. Maintain sub-processor list",
            "priority": "HIGH",
            "section_reference": "Rule 12",
            "is_sdf_only": False
        },
        {
            "item": "Include Data Principal Rights Assistance",
            "description": "Require processors to assist in responding to access, correction, deletion, and breach notification requests",
            "priority": "HIGH",
            "section_reference": "Rule 12",
            "is_sdf_only": False
        }
    ],
    "International Data Transfer": [
        {
            "item": "Identify International Data Transfers",
            "description": "Map all transfer of personal data outside India to other countries",
            "priority": "MEDIUM",
            "section_reference": "Section 17, Rule 14",
            "is_sdf_only": False
        },
        {
            "item": "Obtain Explicit Consent for Transfers",
            "description": "Get specific, informed consent for transferring data outside India. Exception only for legitimate uses with notice",
            "priority": "CRITICAL",
            "section_reference": "Section 17, Rule 14",
            "is_sdf_only": False
        },
        {
            "item": "Assess Recipient Country Protection",
            "description": "Evaluate data protection laws and practices in recipient country. Ensure adequate safeguards exist",
            "priority": "HIGH",
            "section_reference": "Section 17, Rule 14",
            "is_sdf_only": False
        },
        {
            "item": "Document Transfer Safeguards",
            "description": "Maintain evidence of safeguards ensuring transferred data protection equivalent to India standards",
            "priority": "HIGH",
            "section_reference": "Section 17, Rule 14",
            "is_sdf_only": False
        },
        {
            "item": "Remain Accountable for Recipient",
            "description": "Ensure fiduciary remains responsible for recipient's processing and protection of transferred data",
            "priority": "CRITICAL",
            "section_reference": "Section 17",
            "is_sdf_only": False
        }
    ],
    "SDF-Specific Obligations": [
        {
            "item": "Conduct Annual Data Protection Impact Assessment",
            "description": "SDFs must assess high-risk processing, document safeguards, and risk mitigation measures annually",
            "priority": "CRITICAL",
            "section_reference": "Section 7, Section 10, Rule 13",
            "is_sdf_only": True
        },
        {
            "item": "Perform Independent Annual Audit",
            "description": "SDFs must commission independent auditor to assess DPDPA compliance once per year",
            "priority": "CRITICAL",
            "section_reference": "Section 10, Rule 13",
            "is_sdf_only": True
        },
        {
            "item": "Monitor Algorithmic Processing",
            "description": "SDFs must assess automated decision-making systems for bias, fairness, and data principal impact",
            "priority": "HIGH",
            "section_reference": "Section 10, Rule 13",
            "is_sdf_only": True
        },
        {
            "item": "Maintain DPO Independence",
            "description": "Ensure DPO has sufficient organizational independence to raise compliance concerns without retaliation",
            "priority": "CRITICAL",
            "section_reference": "Section 8",
            "is_sdf_only": True
        },
        {
            "item": "Document SDF Compliance Activities",
            "description": "Maintain records of DPIA, audits, DPO activities, algorithmic assessments, and Board interactions",
            "priority": "HIGH",
            "section_reference": "Section 10, Rule 13",
            "is_sdf_only": True
        },
        {
            "item": "Report to Data Protection Board",
            "description": "Provide Board with audit reports, DPIA summaries, and compliance documentation as requested",
            "priority": "HIGH",
            "section_reference": "Section 10, Rule 13",
            "is_sdf_only": True
        }
    ],
    "Training and Awareness": [
        {
            "item": "Develop Data Protection Policy",
            "description": "Create comprehensive policy covering data handling, security, breach response, principal rights",
            "priority": "HIGH",
            "section_reference": "General",
            "is_sdf_only": False
        },
        {
            "item": "Train Employees on DPDPA",
            "description": "Conduct awareness training for all staff on DPDPA obligations, data handling, breach notification",
            "priority": "MEDIUM",
            "section_reference": "Rule 6",
            "is_sdf_only": False
        },
        {
            "item": "Establish Access Control Training",
            "description": "Train authorized personnel on accessing personal data, maintaining confidentiality, audit logs",
            "priority": "MEDIUM",
            "section_reference": "Rule 6",
            "is_sdf_only": False
        },
        {
            "item": "Create Incident Response Training",
            "description": "Train relevant teams on breach discovery, containment, notification, and communication procedures",
            "priority": "MEDIUM",
            "section_reference": "Rule 7",
            "is_sdf_only": False
        }
    ],
    "Compliance Assessment": [
        {
            "item": "Conduct Compliance Audit",
            "description": "Perform internal audit to identify DPDPA compliance gaps. Document findings and remediation plan",
            "priority": "HIGH",
            "section_reference": "General",
            "is_sdf_only": False
        },
        {
            "item": "Maintain Compliance Documentation",
            "description": "Keep records: consent, privacy notices, breach reports, audit results, grievances, remediation actions",
            "priority": "HIGH",
            "section_reference": "General",
            "is_sdf_only": False
        },
        {
            "item": "Review Compliance Regularly",
            "description": "Quarterly or annual reviews of compliance status, changes in processing, policy updates, new risks",
            "priority": "MEDIUM",
            "section_reference": "General",
            "is_sdf_only": False
        },
        {
            "item": "Monitor Legal Developments",
            "description": "Track Board guidance, regulations, enforcement actions, and legal precedents affecting DPDPA compliance",
            "priority": "MEDIUM",
            "section_reference": "General",
            "is_sdf_only": False
        }
    ]
}


# 5. FAQ - Frequently Asked Questions
FAQ = [
    {
        "question": "Who does DPDPA apply to?",
        "answer": "DPDPA applies to any person (individual, company, organization, government entity) who determines the purpose and means of processing personal data in digital form in India. Excludes: government employee data in official capacity, non-digital processing."
    },
    {
        "question": "What is personal data under DPDPA?",
        "answer": "Personal data is any data about an individual who is identifiable by or in relation to such data. Examples: name, email, phone, IP address, ID number, biometric data, cookies, device identifiers, or any information that identifies an individual."
    },
    {
        "question": "What is a Significant Data Fiduciary?",
        "answer": "SDF is a data fiduciary meeting specific criteria: processes 50+ lakh personal data of Indian residents, makes impactful automated decisions, processes sensitive data, operates critical information infrastructure, or processes data in combination with other data. SDFs face stricter obligations."
    },
    {
        "question": "Can I collect personal data without consent?",
        "answer": "Yes, in two cases: (1) Legitimate uses - voluntary provision, state benefits, legal obligations, employment, or Government-prescribed purposes; (2) Automatic processing without consent is NOT allowed. All non-legitimate processing requires explicit consent."
    },
    {
        "question": "How do I obtain valid consent under DPDPA?",
        "answer": "Consent must be: (1) Voluntary - free from coercion; (2) Specific - for each purpose separately; (3) Informed - data principal understands what they consent to; (4) Clear affirmative action - opt-in, not opt-out, such as checkbox click or signature; (5) Kept separate from service terms. Maintain proof of consent."
    },
    {
        "question": "Can I use blanket consent for all purposes?",
        "answer": "No. Consent must be specific for each purpose. Blanket/general consent accepting all future purposes is invalid. You must obtain separate consent for each distinct processing purpose."
    },
    {
        "question": "How long can I keep personal data?",
        "answer": "Only as long as necessary for the stated purpose. You must establish retention schedules and delete data when: (1) Purpose is fulfilled, (2) Individual withdraws consent, (3) Retention period expires, or (4) Data no longer needed. Exceptions: legal retention requirements or court orders."
    },
    {
        "question": "What must I do if personal data is breached?",
        "answer": "Upon discovering a breach: (1) Immediately notify Data Protection Board; (2) Provide detailed 72-hour report with breach details, impact, and remediation; (3) Notify affected individuals without delay with breach information; (4) Maintain breach documentation; (5) Implement preventive measures. No materiality threshold - all breaches reportable."
    },
    {
        "question": "What are my data principal rights?",
        "answer": "Data principals can: (1) Access their personal data; (2) Know what data is processed and why; (3) Correct inaccurate or incomplete data; (4) Request data deletion; (5) Withdraw consent anytime; (6) File grievance with Board; (7) Receive information in accessible format. Fiduciary must respond within reasonable timeframe."
    },
    {
        "question": "Do I need a Data Protection Officer?",
        "answer": "Only Significant Data Fiduciaries must appoint a DPO. The DPO must be an Indian resident, report to governing body, act as compliance focal point, and handle grievance redressal. Regular data fiduciaries do not require DPO appointment."
    },
    {
        "question": "What is a Data Protection Impact Assessment?",
        "answer": "DPIA is an assessment required annually by SDFs examining: (1) Likelihood of harm to data principals' rights, (2) Adequacy of safeguards, (3) Processing risks, (4) Risk mitigation measures. Results must be documented and reviewed. Helps identify high-risk processing."
    },
    {
        "question": "How do I handle children's data?",
        "answer": "For individuals under 18: (1) Obtain verifiable consent from parent/guardian before processing; (2) Implement age verification; (3) Prohibit behavioral tracking and monitoring; (4) Prohibit targeted advertising; (5) Use accessible privacy notices for parents; (6) Do not process if likely to cause detriment to child."
    },
    {
        "question": "Can I use a Consent Manager?",
        "answer": "Yes. Consent Managers are registered intermediaries who manage consents on your behalf. They must: be incorporated in India, have minimum net worth of INR 2 crore, meet Board eligibility, be registered with Board. Registration begins November 13, 2026. Benefits: simplified consent management, compliance proof."
    },
    {
        "question": "What happens if I transfer data outside India?",
        "answer": "International transfer requires: (1) Explicit consent from data principal (exception: legitimate uses with notice); (2) Assessment that recipient country has adequate data protection; (3) Documentation of safeguards; (4) Fiduciary remains responsible for recipient's processing. Cannot transfer to circumvent DPDPA."
    },
    {
        "question": "What are DPDPA penalties?",
        "answer": "Penalties range from INR 50 crore to INR 250 crore depending on violation: (1) INR 50 crore - unauthorized processing, consent violations, data principal rights denial; (2) INR 200 crore - breach notification failure; (3) INR 250 crore - security safeguards failure, SDF obligations failure. Penalties are absolute amounts, not revenue percentage."
    },
    {
        "question": "How do I file a grievance with Data Protection Board?",
        "answer": "Data principals can file grievances: (1) Online through Board's digital portal (effective May 13, 2027); (2) Against data fiduciaries violating DPDPA; (3) Board initiates own inquiries; (4) Natural justice principles apply; (5) Board can impose remedial orders and penalties. Board contact info available on official website."
    },
    {
        "question": "What is the implementation timeline?",
        "answer": "DPDPA has staggered implementation: (1) August 4, 2023 - Act commencement (definitions, Board); (2) November 13, 2026 - Consent Managers registration begins; (3) May 13, 2027 - Full compliance mandatory (consent, fiduciary obligations, Board powers effective). Prepare from now for May 2027 deadline."
    },
    {
        "question": "How do I ensure my data processor complies?",
        "answer": "For data processors: (1) Execute written processing contract clearly defining roles; (2) Restrict processor to your instructions only; (3) Require processor to implement equivalent security measures; (4) Audit processor's compliance regularly; (5) Require processor approval of sub-processors; (6) Include data principal rights assistance obligations. Fiduciary remains responsible."
    },
    {
        "question": "What security measures must I implement?",
        "answer": "Reasonable security safeguards include: (1) Encryption at rest and in transit; (2) Access controls and authentication; (3) Processing logs and audit trails; (4) Regular security testing and penetration testing; (5) Employee training; (6) Vulnerability management; (7) Incident response procedures; (8) Backup and recovery systems. Measures must be proportionate to risk."
    },
    {
        "question": "Can data be used for behavioral targeting/profiling?",
        "answer": "Behavioral targeting/profiling requires explicit consent. Prohibited for children under 18. For adults: consent must be specific for profiling purposes, clear disclosure of profiling practices, right to understand decisions made by profiling, right to contest. SDFs must monitor algorithmic systems for bias."
    }
]


# 6. PENALTY_MATRIX - Detailed penalty information
PENALTY_MATRIX = {
    "Unauthorized Processing": {
        "description": "Processing personal data without valid legal basis (consent or legitimate use)",
        "max_penalty": "50 crore INR",
        "section": "Section 4, 30",
        "examples": [
            "Processing without obtaining consent",
            "Using data for purpose not disclosed",
            "Secondary use for different purpose",
            "Processing after consent withdrawal"
        ]
    },
    "Consent Violations": {
        "description": "Invalid, coerced, bundled consent or failure to maintain consent proof",
        "max_penalty": "50 crore INR",
        "section": "Section 11",
        "examples": [
            "Bundled consent with service terms",
            "Opt-out instead of opt-in consent",
            "Coerced or conditional consent",
            "No proof of consent maintained",
            "Consent not specific for each purpose"
        ]
    },
    "Data Principal Rights Denial": {
        "description": "Denying access, correction, deletion, or grievance rights",
        "max_penalty": "50 crore INR",
        "section": "Section 12, 13, 14",
        "examples": [
            "Refusing access request without justification",
            "Denying correction of inaccurate data",
            "Refusing deletion request",
            "Not responding to grievance within timeframe",
            "Charging excessive fees for rights exercise"
        ]
    },
    "Breach Notification Failure": {
        "description": "Failure to notify Board within 72 hours or notify affected principals",
        "max_penalty": "200 crore INR",
        "section": "Section 6, Rule 7",
        "examples": [
            "No notification to Board within 72 hours",
            "No notification to affected principals",
            "Inadequate breach details provided",
            "Delayed notification beyond 72 hours"
        ]
    },
    "Security Safeguards Failure": {
        "description": "Inadequate security measures leading to unauthorized access/disclosure",
        "max_penalty": "250 crore INR",
        "section": "Section 9, Rule 6",
        "examples": [
            "No encryption of stored personal data",
            "Weak access controls and authentication",
            "No security testing/vulnerability management",
            "Inadequate incident response",
            "Unencrypted data transmission"
        ]
    },
    "SDF Obligations Failure": {
        "description": "SDFs failing to appoint DPO, conduct DPIA, or perform audits",
        "max_penalty": "250 crore INR",
        "section": "Section 10, Rule 13",
        "examples": [
            "No Data Protection Officer appointed",
            "Missing annual DPIA",
            "No independent audit performed",
            "Inadequate algorithmic monitoring",
            "No processing logs maintained"
        ]
    },
    "Children's Data Violations": {
        "description": "Processing children's data without parental consent or violating protections",
        "max_penalty": "250 crore INR",
        "section": "Section 9(1)(d), Rule 10",
        "examples": [
            "Processing without parental/guardian consent",
            "Behavioral tracking of children",
            "Targeted advertising to children",
            "Processing likely to cause detriment to child",
            "No age verification mechanism"
        ]
    },
    "Processor/Vendor Non-compliance": {
        "description": "Using processor without contract or failing to ensure compliance",
        "max_penalty": "50 crore INR",
        "section": "Section 15, Rule 12",
        "examples": [
            "No processing contract with vendor",
            "Processor processes beyond fiduciary instructions",
            "No processor security audit",
            "Unapproved sub-processor use",
            "Fiduciary fails to supervise processor"
        ]
    },
    "Consent Manager Violations": {
        "description": "Operating as consent manager without registration or violating obligations",
        "max_penalty": "50 crore INR",
        "section": "Section 16, Rule 4",
        "examples": [
            "Operating without Board registration",
            "Processing personal data itself",
            "Inadequate security for consent records",
            "Failing to facilitate consent withdrawal",
            "Not maintaining separate consent records"
        ]
    },
    "Board Order Non-compliance": {
        "description": "Failure to comply with Board directions, orders, or corrective measures",
        "max_penalty": "50 crore INR",
        "section": "Section 32",
        "examples": [
            "Not implementing Board-ordered remedies",
            "Missing Board-imposed deadlines",
            "Not providing information to Board when required",
            "Continuing violation despite Board notice",
            "Not cooperating with Board inquiry"
        ]
    }
}


# 7. TIMELINE - Key implementation dates
TIMELINE = [
    {
        "date": "August 4, 2023",
        "event": "DPDPA 2023 Commencement",
        "description": "Digital Personal Data Protection Act 2023 came into force. Definitions, Data Protection Board establishment, rule-making authority became effective.",
        "who_affected": "All organizations"
    },
    {
        "date": "November 14, 2025",
        "event": "DPDP Rules 2025 Notification",
        "description": "Digital Personal Data Protection Rules 2025 officially notified by MeitY. Provides operational framework and detailed compliance procedures.",
        "who_affected": "All data fiduciaries and consent managers"
    },
    {
        "date": "November 13, 2026",
        "event": "Consent Manager Registration Opens",
        "description": "Consent Manager registration with Data Protection Board becomes operational. Registration effective one year from rules notification.",
        "who_affected": "Consent Manager entities"
    },
    {
        "date": "May 13, 2027",
        "event": "Full DPDPA Compliance Mandatory",
        "description": "Core provisions of DPDPA become fully effective after 18-month transition period. All compliance obligations mandatory: consent requirement, fiduciary obligations, Board enforcement powers. No grace period - full penalties applicable from Day 1.",
        "who_affected": "All data fiduciaries and data principals"
    },
    {
        "date": "Ongoing",
        "event": "Data Protection Board Operations",
        "description": "Board fully operational from November 14, 2025 with digital grievance portal. Data principals can file complaints. Board conducts inquiries and imposes penalties.",
        "who_affected": "All data principals and fiduciaries"
    }
]


# 8. SECTOR_GUIDANCE - Industry-specific compliance notes
SECTOR_GUIDANCE = {
    "FinTech and Banking": {
        "special_considerations": [
            "Processing financial data (account numbers, transaction history) - highly sensitive",
            "Likely classified as Significant Data Fiduciary due to volume and criticality",
            "Regulatory compliance (KYC, AML) may qualify as legitimate use",
            "Investment/trading algorithms must be monitored for bias and fairness",
            "Cross-border money transfer involves international data transfer - explicit consent required",
            "Fraudulent transaction detection uses behavioral analysis - consent/legitimate basis required",
            "Loan approval algorithms: Automated decision-making impact assessment required"
        ],
        "additional_regulations": [
            "Reserve Bank of India (RBI) guidelines on data security",
            "Payments Systems Act 2007 and regulations",
            "Prevention of Money Laundering Act (PMLA) 2002",
            "KYC (Know Your Customer) requirements",
            "Complaint Redressal Mechanism",
            "Data localization requirements"
        ],
        "examples": [
            "Bank collecting KYC data as legitimate use (legal obligation)",
            "Fintech requiring explicit consent for behavioral tracking in lending algorithm",
            "Investment platform needing DPO and DPIA due to SDF status",
            "Payment processor with vendor agreements ensuring processor compliance"
        ]
    },
    "Healthcare": {
        "special_considerations": [
            "Processing medical/health data - highly sensitive requiring enhanced protections",
            "Likely Significant Data Fiduciary due to health data sensitivity",
            "Telemedicine platforms collecting patient data including location",
            "Medical records transmission to specialists - disclosure without fresh consent problematic",
            "Prescription data, medication history, diagnoses - sensitive and require specific consent",
            "Patient consent management critical - medical history cannot be disclosed broadly",
            "Health algorithms (diagnosis support, treatment recommendation) require DPIA",
            "Data of minors requiring guardian consent for all processing"
        ],
        "additional_regulations": [
            "Bharatiya Nyaya Sanhita 2023 privacy implications",
            "Medical Council regulations on patient data",
            "Pharmacy regulations",
            "Hospital accreditation standards",
            "Mental Health Care Act 2017",
            "Disability Rights Act 2016"
        ],
        "examples": [
            "Hospital obtaining parental consent for child patient data processing",
            "Telemedicine app implementing location data transparency notice",
            "Healthcare provider appointing DPO due to SDF classification",
            "Medical records transfer to specialists requiring specific new consent",
            "AI diagnosis tool requiring DPIA examining accuracy and bias"
        ]
    },
    "E-commerce": {
        "special_considerations": [
            "Extensive customer data collection (name, address, payment, browsing, preferences)",
            "Likely Significant Data Fiduciary due to large customer base and volume",
            "Behavioral tracking for personalized recommendations - consent required",
            "Targeted advertising to customers - specific consent needed",
            "Payment processors as vendors - processor agreements essential",
            "Customer reviews/ratings potentially containing sensitive information",
            "Inventory management related to customer purchase data - purpose limitation critical",
            "Children shopping - age verification and parental consent if under 18"
        ],
        "additional_regulations": [
            "Consumer Protection Act 2019",
            "E-commerce Rules 2020",
            "Food Safety Standards (if applicable)",
            "Various product-specific regulations"
        ],
        "examples": [
            "E-commerce platform obtaining specific consent for recommendation algorithm",
            "Marketplace restricting personalized email marketing to opted-in users",
            "Shopping app appointing DPO due to volume and algorithmic profiling",
            "Vendor management ensuring third-party sellers comply with DPDPA",
            "Payment processor agreement ensuring PCI compliance and data security"
        ]
    },
    "IT Services and Software": {
        "special_considerations": [
            "SaaS platforms processing customer data - often Significant Data Fiduciary",
            "Cloud infrastructure providers as data processors - vendor agreements critical",
            "Logging and monitoring systems collecting personal data - purpose limitation needed",
            "Bug fixes and product improvement using customer data - require consent",
            "Analytics tools tracking user behavior - explicit consent required",
            "Subcontractors and third-party tools used - all processor contracts required",
            "Open-source software implications - verify compliance of libraries/dependencies",
            "Developer access to production personal data - strict access controls needed"
        ],
        "additional_regulations": [
            "Information Technology Act 2000",
            "Data Protection Standards for government contracts",
            "Cloud provider compliance certifications"
        ],
        "examples": [
            "SaaS vendor implementing consent management for analytics",
            "API service requiring API keys with scope limitations",
            "Development team restricting personal data access to authorized developers only",
            "Cloud infrastructure provider publishing security certifications",
            "Software company conducting DPIA for new machine learning feature"
        ]
    },
    "Education": {
        "special_considerations": [
            "Processing student data including academic records, attendance, test scores",
            "Children's data - parental/guardian consent essential for all processing",
            "Learning management systems (LMS) collecting behavioral data - consent required",
            "Online exam proctoring with continuous monitoring - privacy concerns and consent",
            "Alumni data retention after graduation - clear retention limits needed",
            "Faculty/staff data separate from student data - different consent levels",
            "Automated grading systems - transparency and appeal mechanisms needed",
            "Educational institution likely SDF due to student data volume and sensitivity"
        ],
        "additional_regulations": [
            "National Education Policy 2020",
            "UGC Regulations",
            "Board exam regulations",
            "Student data protection guidelines"
        ],
        "examples": [
            "School obtaining parental consent before using educational app collecting behavior data",
            "Online exam platform disclosing proctoring methods and data collection",
            "Educational institution appointing DPO due to large student database",
            "University retaining alumni contact data with clear retention period and deletion policy",
            "School implementing age-appropriate privacy notices for student data"
        ]
    },
    "Government and Public Sector": {
        "special_considerations": [
            "Government employee data processing - exempt from DPDPA if in official capacity",
            "Citizen data (taxes, licenses, subsidies, services) - legitimate use basis (state functions)",
            "Public records with personal data - balance transparency with privacy",
            "Biometric data collection for identification (Aadhaar interface) - consent and transparency critical",
            "Intelligence and law enforcement data - separate legal frameworks may apply",
            "Digital India initiatives collecting citizen data - clear consent mechanisms needed",
            "Government databases consolidation - purpose limitation and data minimization critical",
            "Citizen grievance systems handling sensitive information - confidentiality essential"
        ],
        "additional_regulations": [
            "Government Data Governance Policy",
            "Right to Information Act 2005",
            "Constitution of India privacy rights",
            "Specific acts (Aadhaar, Election, Tax, etc.)"
        ],
        "examples": [
            "Tax authority processing income data as legitimate use (legal obligation)",
            "Government agency appointing nodal officer as data protection contact",
            "Public portal collecting citizen feedback with clear notice about data use",
            "Social welfare program collecting beneficiary data with transparent use notice",
            "Government conducting DPIA for new citizen identification scheme"
        ]
    }
}


# 9. Search function - searches across all knowledge base data
def search_knowledge(query: str) -> dict:
    """
    Simple keyword-based search across knowledge base.

    Args:
        query: Search keyword or phrase

    Returns:
        Dictionary with matches organized by category
    """
    query_lower = query.lower()
    results = {
        "sections": [],
        "rules": [],
        "definitions": [],
        "checklist_items": [],
        "faqs": [],
        "penalties": [],
        "timeline": [],
        "sector_guidance": []
    }

    # Search sections
    for section_num, section_data in DPDPA_SECTIONS.items():
        if (query_lower in section_data["title"].lower() or
            query_lower in section_data["summary"].lower() or
            any(query_lower in req.lower() for req in section_data.get("key_requirements", []))):
            results["sections"].append({
                "number": section_num,
                "title": section_data["title"],
                "summary": section_data["summary"]
            })

    # Search rules
    for rule_num, rule_data in DPDP_RULES.items():
        if (query_lower in rule_data["title"].lower() or
            query_lower in rule_data["summary"].lower() or
            any(query_lower in req.lower() for req in rule_data.get("requirements", []))):
            results["rules"].append({
                "number": rule_num,
                "title": rule_data["title"],
                "summary": rule_data["summary"]
            })

    # Search definitions
    for term, definition in KEY_DEFINITIONS.items():
        if query_lower in term.lower() or query_lower in definition.lower():
            results["definitions"].append({
                "term": term,
                "definition": definition
            })

    # Search checklist items
    for category, items in COMPLIANCE_CHECKLIST.items():
        for item in items:
            if (query_lower in item["item"].lower() or
                query_lower in item["description"].lower()):
                results["checklist_items"].append({
                    "category": category,
                    "item": item["item"],
                    "description": item["description"],
                    "priority": item["priority"]
                })

    # Search FAQs
    for faq in FAQ:
        if query_lower in faq["question"].lower() or query_lower in faq["answer"].lower():
            results["faqs"].append(faq)

    # Search penalties
    for violation, penalty_data in PENALTY_MATRIX.items():
        if (query_lower in violation.lower() or
            query_lower in penalty_data["description"].lower() or
            any(query_lower in ex.lower() for ex in penalty_data.get("examples", []))):
            results["penalties"].append({
                "violation": violation,
                "description": penalty_data["description"],
                "max_penalty": penalty_data["max_penalty"]
            })

    # Search timeline
    for event in TIMELINE:
        if (query_lower in event["event"].lower() or
            query_lower in event["description"].lower()):
            results["timeline"].append(event)

    # Search sector guidance
    for sector, guidance in SECTOR_GUIDANCE.items():
        combined_text = " ".join([
            sector,
            " ".join(guidance.get("special_considerations", [])),
            " ".join(guidance.get("additional_regulations", [])),
            " ".join(guidance.get("examples", []))
        ])
        if query_lower in combined_text.lower():
            results["sector_guidance"].append({
                "sector": sector,
                "special_considerations": guidance["special_considerations"]
            })

    return results


# 10. Compliance score interpretation
def get_compliance_score_interpretation(score: float) -> dict:
    """
    Returns text interpretation of a compliance score.

    Args:
        score: Compliance score from 0 to 100

    Returns:
        Dictionary with interpretation and recommendations
    """
    if score >= 90:
        level = "EXCELLENT"
        status = "Your organization demonstrates strong DPDPA compliance"
        color = "green"
        recommendations = [
            "Maintain current compliance practices",
            "Conduct periodic refresher training",
            "Monitor Board guidance for updates",
            "Consider benchmarking against industry standards"
        ]
    elif score >= 75:
        level = "GOOD"
        status = "Your organization has satisfactory DPDPA compliance"
        color = "yellow"
        recommendations = [
            "Address gaps identified in compliance assessment",
            "Strengthen security safeguards",
            "Enhance data principal rights mechanisms",
            "Document all compliance activities"
        ]
    elif score >= 60:
        level = "MODERATE"
        status = "Your organization has some DPDPA compliance gaps"
        color = "orange"
        recommendations = [
            "Prioritize critical gaps (consent, security, breach notification)",
            "Develop remediation timeline with deadlines",
            "Allocate resources for compliance improvements",
            "Consider external compliance audit",
            "Engage legal counsel for guidance"
        ]
    else:
        level = "POOR"
        status = "Your organization has significant DPDPA compliance risks"
        color = "red"
        recommendations = [
            "Conduct comprehensive compliance audit immediately",
            "Develop urgent remediation plan with executive sponsorship",
            "Prioritize critical violations (security, breach notification, consent)",
            "Engage external compliance and legal experts",
            "Implement interim risk mitigation measures",
            "Target May 13, 2027 compliance deadline with milestones"
        ]

    return {
        "score": score,
        "level": level,
        "status": status,
        "color": color,
        "recommendations": recommendations,
        "deadline": "May 13, 2027 (Full DPDPA Compliance Mandatory)"
    }


# Metadata about knowledge base
KNOWLEDGE_BASE_INFO = {
    "version": "1.0",
    "last_updated": "March 4, 2026",
    "coverage": "DPDPA 2023 and DPDP Rules 2025",
    "total_sections": len(DPDPA_SECTIONS),
    "total_rules": len(DPDP_RULES),
    "total_definitions": len(KEY_DEFINITIONS),
    "total_checklist_items": sum(len(items) for items in COMPLIANCE_CHECKLIST.values()),
    "total_faqs": len(FAQ),
    "total_penalty_types": len(PENALTY_MATRIX),
    "timeline_events": len(TIMELINE),
    "sectors_covered": len(SECTOR_GUIDANCE)
}
