"""
DPDPA Knowledge Base for Svikruti.ai
Complete reference data for DPDPA 2023 and DPDP Rules 2025

This module stores all DPDPA 2023 and DPDP Rules 2025 knowledge in structured data
for the Svikruti.ai compliance tool. Pure data structure - NO AI/LLM dependency.

Covers:
- DPDPA Sections (Act sections 1-44 across 9 chapters, plus the Schedule of penalties)
- DPDP Rules, 2025 (topic-wise guidance; verify rule numbers against the gazetted Rules)
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
        "summary": "This Act may be called the Digital Personal Data Protection Act, 2023. It comes into force on such date(s) as the Central Government may appoint by notification, and different dates may be appointed for different provisions (staged commencement).",
        "key_requirements": [
            "The Act applies to processing of digital personal data",
            "Provisions are brought into force in stages by Central Government notification"
        ],
        "applies_to": "All Data Fiduciaries and Data Principals",
        "penalties": "N/A - procedural provision"
    },
    2: {
        "number": 2,
        "title": "Definitions",
        "summary": "Defines the key terms used throughout the Act, including Data Principal, Data Fiduciary, Data Processor, Consent Manager, personal data, processing, and child (an individual who has not completed eighteen years of age).",
        "key_requirements": [
            "Personal data: any data about an individual who is identifiable by or in relation to such data",
            "Data Fiduciary: any person who alone or in conjunction with other persons determines the purpose and means of processing of personal data",
            "Data Principal: the individual to whom the personal data relates",
            "Data Processor: any person who processes personal data on behalf of a Data Fiduciary",
            "Consent Manager: a person registered with the Data Protection Board of India who enables a Data Principal to give, manage, review and withdraw consent (see Section 6(7)-(9))",
            "Processing: a wholly or partly automated operation or set of operations performed on digital personal data",
            "Child: an individual who has not completed eighteen years of age"
        ],
        "applies_to": "All Data Fiduciaries, Data Principals, Data Processors and Consent Managers",
        "penalties": "N/A - definitional provision"
    },
    3: {
        "number": 3,
        "title": "Application of the Act",
        "summary": "The Act applies to the processing of digital personal data within India, and to processing outside India if it is in connection with offering goods or services to Data Principals in India. It does not apply to personal data processed by an individual for personal or domestic purposes, or to personal data made publicly available by the Data Principal or by any other person under a legal obligation.",
        "key_requirements": [
            "Applies to digital personal data processed within India",
            "Extraterritorial application: processing outside India in connection with offering goods or services to Data Principals in India",
            "Excludes processing by an individual for personal or domestic purposes",
            "Excludes personal data made publicly available by the Data Principal, or by another person under a legal obligation to do so"
        ],
        "applies_to": "All Data Fiduciaries processing digital personal data within the Act's scope",
        "penalties": "N/A - scope provision"
    },
    4: {
        "number": 4,
        "title": "Grounds for Processing Personal Data",
        "summary": "Personal data may be processed only in accordance with the provisions of the Act, for a lawful purpose, and only (a) with the consent of the Data Principal (Section 6), or (b) for certain legitimate uses specified in Section 7.",
        "key_requirements": [
            "Processing only for a lawful purpose",
            "Legal basis must be either consent (Section 6) or a certain legitimate use (Section 7)",
            "A request for consent must be accompanied or preceded by a notice under Section 5"
        ],
        "applies_to": "All Data Fiduciaries",
        "penalties": "Schedule (residual): up to INR 50 crore for breaches of the Act or Rules not otherwise specified"
    },
    5: {
        "number": 5,
        "title": "Notice",
        "summary": "Every request for consent must be accompanied or preceded by a notice informing the Data Principal of: the personal data sought and the purpose of processing; the manner in which rights may be exercised (including withdrawal of consent under Section 6(4) and grievance redressal under Section 13); and the manner in which a complaint may be made to the Data Protection Board of India. Where consent was obtained before commencement of the Act, notice must be given as soon as reasonably practicable.",
        "key_requirements": [
            "Notice must accompany or precede every request for consent",
            "Describe the personal data sought and the purpose of processing",
            "Explain how to exercise rights, including withdrawal of consent (Section 6(4)) and grievance redressal (Section 13)",
            "Explain how to make a complaint to the Data Protection Board of India",
            "For consent obtained before commencement of the Act, give notice as soon as reasonably practicable",
            "Give the Data Principal the option to access the notice in English or any of the 22 languages in the Eighth Schedule of the Constitution"
        ],
        "applies_to": "All Data Fiduciaries relying on consent",
        "penalties": "Schedule (residual): up to INR 50 crore"
    },
    6: {
        "number": 6,
        "title": "Consent",
        "summary": "Consent must be free, specific, informed, unconditional and unambiguous, given by a clear affirmative action. It signifies agreement to processing for the specified purpose only, and is limited to the personal data necessary for that purpose. Consent may be withdrawn at any time, with ease comparable to that with which it was given (Section 6(4)-(6)). Consent may be given, managed, reviewed or withdrawn through a Consent Manager registered with the Data Protection Board of India (Section 6(7)-(9)).",
        "key_requirements": [
            "Consent must be free, specific, informed, unconditional and unambiguous",
            "Given by a clear affirmative action (opt-in, not opt-out)",
            "Limited to the specified purpose and to the personal data necessary for that purpose",
            "Withdrawal must be as easy as giving consent (Section 6(4))",
            "Withdrawal does not affect the lawfulness of processing done before withdrawal (Section 6(5))",
            "On withdrawal, cease processing within a reasonable time unless processing is otherwise required by law (Section 6(6))",
            "Consent Managers must be registered with the Board, be accountable to the Data Principal, and act through an interoperable platform (Section 6(7)-(9))"
        ],
        "applies_to": "All Data Fiduciaries relying on consent, and Consent Managers",
        "penalties": "Schedule (residual): up to INR 50 crore"
    },
    7: {
        "number": 7,
        "title": "Certain Legitimate Uses",
        "summary": "Personal data may be processed without consent for certain legitimate uses: (a) voluntary provision of data by the Data Principal for a specified purpose, without any indication of non-consent; (b) provision by the State of subsidies, benefits, services, certificates, licences or permits; (c) performance of State functions or in the interests of sovereignty, integrity or security of the State; (d) fulfilling a legal obligation or disclosure to the State; (e) compliance with a judgment, decree or order; (f) responding to a medical emergency involving a threat to life or health; (g) measures during an epidemic or other threat to public health; (h) measures during a disaster or breakdown of public order; and (i) employment purposes or safeguarding the employer (e.g., protection from corporate espionage, trade secrets, provision of employee benefits).",
        "key_requirements": [
            "Voluntary provision for a specified purpose, with no indication of non-consent (Section 7(a))",
            "State provision of subsidies, benefits, services, certificates, licences and permits (Section 7(b))",
            "State functions and sovereignty, integrity or security of the State (Section 7(c))",
            "Compliance with legal obligations and disclosures to the State (Section 7(d))",
            "Compliance with judgments, decrees or orders (Section 7(e))",
            "Medical emergencies involving a threat to life or health (Section 7(f))",
            "Epidemics and public health measures (Section 7(g))",
            "Disasters and breakdown of public order (Section 7(h))",
            "Employment purposes and safeguarding the employer, e.g., prevention of corporate espionage, protection of trade secrets, provision of employee benefits (Section 7(i))",
            "Processing must remain limited to the relevant legitimate use"
        ],
        "applies_to": "Data Fiduciaries relying on legitimate uses, including the State",
        "penalties": "Schedule (residual): up to INR 50 crore"
    },
    8: {
        "number": 8,
        "title": "General Obligations of Data Fiduciary",
        "summary": "The Data Fiduciary is responsible for compliance with the Act, including for processing undertaken on its behalf by Data Processors (Section 8(1)-(2)). Where personal data is used to make a decision affecting the Data Principal or is disclosed to another Data Fiduciary, it must be complete, accurate and consistent (Section 8(3)). Fiduciaries must implement appropriate technical and organisational measures (Section 8(4)) and reasonable security safeguards to prevent personal data breach (Section 8(5)). In the event of a breach, the Board and each affected Data Principal must be intimated in the prescribed form and manner (Section 8(6)). Personal data must be erased when consent is withdrawn or the purpose is no longer served, unless retention is required by law (Section 8(7)). Fiduciaries must publish contact details of a Data Protection Officer or a person able to answer questions (Section 8(9)) and maintain an effective grievance redressal mechanism (Section 8(10)).",
        "key_requirements": [
            "Responsible for compliance with the Act, including for processing by Data Processors (Section 8(1)-(2))",
            "Engage Data Processors only under a valid contract (Section 8(2))",
            "Ensure completeness, accuracy and consistency where data is used for decisions affecting the Data Principal or is disclosed to another Data Fiduciary (Section 8(3))",
            "Implement appropriate technical and organisational measures (Section 8(4))",
            "Implement reasonable security safeguards to prevent personal data breach (Section 8(5))",
            "On breach, intimate the Board and each affected Data Principal in the prescribed form and manner (Section 8(6))",
            "Erase personal data when consent is withdrawn or the purpose is no longer served, and cause Data Processors to erase it, unless retention is required by law (Section 8(7))",
            "Publish contact information of the Data Protection Officer or a person able to answer questions about processing (Section 8(9))",
            "Establish an effective grievance redressal mechanism (Section 8(10))"
        ],
        "applies_to": "All Data Fiduciaries",
        "penalties": "Schedule: up to INR 250 crore for failure of reasonable security safeguards (Section 8(5)); up to INR 200 crore for failure to notify the Board/Data Principals of a breach (Section 8(6)); up to INR 50 crore (residual) for other breaches"
    },
    9: {
        "number": 9,
        "title": "Processing of Personal Data of Children",
        "summary": "Before processing the personal data of a child (an individual under 18) or of a person with disability who has a lawful guardian, the Data Fiduciary must obtain the verifiable consent of the parent or lawful guardian. Processing likely to cause any detrimental effect on the well-being of a child is prohibited, as are tracking, behavioural monitoring of children, and targeted advertising directed at children (Section 9(3)). The Central Government may exempt classes of Data Fiduciaries or purposes, or lower the applicable age, for fiduciaries verified as processing children's data in a safe manner.",
        "key_requirements": [
            "Obtain verifiable consent of the parent or lawful guardian before processing a child's data",
            "Verifiable guardian consent also required for a person with disability who has a lawful guardian",
            "No processing likely to cause a detrimental effect on the well-being of a child",
            "No tracking or behavioural monitoring of children (Section 9(3))",
            "No targeted advertising directed at children (Section 9(3))",
            "Central Government may exempt classes/purposes or lower the age threshold for fiduciaries verified as safe"
        ],
        "applies_to": "All Data Fiduciaries processing children's data or data of persons with disability who have lawful guardians",
        "penalties": "Schedule: up to INR 200 crore for breach of obligations in relation to children (Section 9)"
    },
    10: {
        "number": 10,
        "title": "Significant Data Fiduciary",
        "summary": "The Central Government may, by notification, designate any Data Fiduciary or class of Data Fiduciaries as a Significant Data Fiduciary (SDF), based on an assessment of factors including the volume and sensitivity of personal data processed, risk to the rights of Data Principals, potential impact on the sovereignty and integrity of India, electoral democracy, security of the State, and public order. The Act contains no numeric or resident-count threshold. SDFs must appoint a Data Protection Officer based in India who is responsible to the board of directors (or similar governing body) and acts as the point of contact for grievance redressal, appoint an independent data auditor, and undertake periodic Data Protection Impact Assessments and periodic audits.",
        "key_requirements": [
            "SDF status arises only by Central Government notification (no numeric threshold in the Act)",
            "Notification factors: volume and sensitivity of data, risk to Data Principal rights, potential impact on sovereignty and integrity of India, electoral democracy, security of the State, and public order",
            "Appoint a Data Protection Officer based in India, responsible to the board of directors and acting as point of contact for grievance redressal",
            "Appoint an independent data auditor to evaluate compliance",
            "Undertake periodic Data Protection Impact Assessment (DPIA)",
            "Undertake periodic audit",
            "Undertake such other measures as may be prescribed"
        ],
        "applies_to": "Data Fiduciaries notified as Significant Data Fiduciaries",
        "penalties": "Schedule: up to INR 150 crore for breach of additional SDF obligations (Section 10)"
    },
    11: {
        "number": 11,
        "title": "Right to Access Information About Personal Data",
        "summary": "The Data Principal has the right to obtain from the Data Fiduciary: a summary of the personal data being processed and the processing activities undertaken; the identities of all other Data Fiduciaries and Data Processors with whom the personal data has been shared, along with a description of the data shared; and any other information as may be prescribed.",
        "key_requirements": [
            "Provide a summary of the personal data processed and the processing activities undertaken",
            "Identify all other Data Fiduciaries and Data Processors with whom the data has been shared, with a description of the data shared",
            "Provide any other information as may be prescribed",
            "Respond within the time period published by the Data Fiduciary / as prescribed under the DPDP Rules, 2025 (verify against the gazetted Rules)"
        ],
        "applies_to": "All Data Fiduciaries receiving access requests",
        "penalties": "Schedule (residual): up to INR 50 crore"
    },
    12: {
        "number": 12,
        "title": "Right to Correction, Completion, Updating and Erasure",
        "summary": "The Data Principal has the right to correction of inaccurate or misleading personal data, completion of incomplete personal data, updating of personal data, and erasure of personal data. The Data Fiduciary must erase the data upon request unless retention is necessary for the specified purpose or for compliance with any law.",
        "key_requirements": [
            "Correct inaccurate or misleading personal data",
            "Complete incomplete personal data",
            "Update personal data",
            "Erase personal data on request, unless retention is necessary for the specified purpose or required for legal compliance"
        ],
        "applies_to": "All Data Fiduciaries receiving Data Principal requests",
        "penalties": "Schedule (residual): up to INR 50 crore"
    },
    13: {
        "number": 13,
        "title": "Right of Grievance Redressal",
        "summary": "The Data Principal has the right to readily available means of grievance redressal provided by the Data Fiduciary or Consent Manager. The Data Fiduciary or Consent Manager must respond within the prescribed period. The Data Principal must exhaust this grievance redressal opportunity before approaching the Data Protection Board of India.",
        "key_requirements": [
            "Provide readily available means of grievance redressal",
            "Respond to grievances within the time period published by the Data Fiduciary / as prescribed under the DPDP Rules, 2025 (verify against the gazetted Rules)",
            "Data Principal must exhaust the fiduciary's grievance redressal mechanism before complaining to the Board"
        ],
        "applies_to": "All Data Fiduciaries and Consent Managers",
        "penalties": "Schedule (residual): up to INR 50 crore"
    },
    14: {
        "number": 14,
        "title": "Right to Nominate",
        "summary": "The Data Principal has the right to nominate one or more individuals who may exercise the Data Principal's rights under the Act in the event of the Data Principal's death or incapacity.",
        "key_requirements": [
            "Enable Data Principals to nominate individual(s) to exercise their rights",
            "Nomination operates in the event of the death or incapacity of the Data Principal"
        ],
        "applies_to": "All Data Fiduciaries",
        "penalties": "Schedule (residual): up to INR 50 crore"
    },
    15: {
        "number": 15,
        "title": "Duties of Data Principals",
        "summary": "Data Principals must: comply with applicable laws while exercising rights under the Act; not impersonate another person; not suppress material information when providing personal data for documents, identity proof or address proof issued by the State; not register false or frivolous grievances or complaints; and furnish only verifiably authentic information when exercising the rights to correction or erasure.",
        "key_requirements": [
            "Comply with all applicable laws when exercising rights under the Act",
            "Do not impersonate another person while providing personal data",
            "Do not suppress material information when providing personal data to the State",
            "Do not register false or frivolous grievances or complaints",
            "Furnish verifiably authentic information when seeking correction or erasure"
        ],
        "applies_to": "All Data Principals",
        "penalties": "Schedule: up to INR 10,000 for breach of duties by a Data Principal (Section 15)"
    },
    16: {
        "number": 16,
        "title": "Processing of Personal Data Outside India (Cross-Border Transfer)",
        "summary": "The Act follows a negative-list model: personal data may be transferred to any country or territory outside India EXCEPT those restricted by the Central Government by notification. There is no adequacy requirement, no explicit-consent requirement, and no standard contractual clauses (SCC) mechanism under the Act. Stricter sectoral restrictions (e.g., RBI payment data localisation) continue to apply (Section 16(2)).",
        "key_requirements": [
            "Transfers permitted to any country except those restricted by Central Government notification (negative list)",
            "No adequacy assessment, explicit-consent requirement or SCC mechanism under the Act",
            "Monitor Central Government notifications restricting transfers to specific countries or territories",
            "Continue to comply with stricter sectoral laws, e.g., RBI payment data localisation (Section 16(2))"
        ],
        "applies_to": "Data Fiduciaries transferring personal data outside India",
        "penalties": "Schedule (residual): up to INR 50 crore"
    },
    17: {
        "number": 17,
        "title": "Exemptions",
        "summary": "Certain provisions of the Act do not apply to specified processing, including: enforcement of legal rights or claims; processing by courts and tribunals; prevention, detection, investigation or prosecution of offences; processing in India of non-resident data under a foreign contract; schemes of merger or amalgamation approved by a tribunal; and assessment of financial position of loan defaulters. The Central Government may also, by notification, exempt State instrumentalities, processing for research or statistical purposes, and notified classes of Data Fiduciaries such as startups.",
        "key_requirements": [
            "Enforcement of legal rights and claims",
            "Processing by courts, tribunals and other adjudicatory bodies",
            "Prevention, detection, investigation and prosecution of offences",
            "Processing in India of personal data of persons outside India under a contract with a person outside India",
            "Tribunal-approved schemes of merger, amalgamation or restructuring",
            "Ascertaining the financial position of loan defaulters",
            "Central Government may exempt State instrumentalities, research/statistical purposes and notified classes (e.g., startups)"
        ],
        "applies_to": "Specified processing activities and notified classes of Data Fiduciaries",
        "penalties": "N/A - exemption provision"
    },
    18: {
        "number": 18,
        "title": "Establishment of the Data Protection Board of India",
        "summary": "Provides for the establishment of the Data Protection Board of India by the Central Government, the adjudicatory body under the Act.",
        "key_requirements": [
            "Board established by the Central Government by notification"
        ],
        "applies_to": "Central Government",
        "penalties": "N/A - institutional provision"
    },
    19: {
        "number": 19,
        "title": "Composition and Qualifications of the Board",
        "summary": "Provides for the composition of the Data Protection Board of India (Chairperson and Members) and the qualifications for their appointment.",
        "key_requirements": [
            "Chairperson and Members appointed in accordance with the Act and the Rules"
        ],
        "applies_to": "Data Protection Board of India",
        "penalties": "N/A - institutional provision"
    },
    20: {
        "number": 20,
        "title": "Salary, Allowances and Terms of Service",
        "summary": "Provides for the salary, allowances and other terms and conditions of service of the Chairperson and Members of the Board.",
        "key_requirements": [
            "Terms of service of the Chairperson and Members as prescribed"
        ],
        "applies_to": "Data Protection Board of India",
        "penalties": "N/A - institutional provision"
    },
    21: {
        "number": 21,
        "title": "Disqualification of Chairperson and Members",
        "summary": "Provides the grounds of disqualification for appointment and continuation in office of the Chairperson and Members of the Board.",
        "key_requirements": [
            "Disqualification grounds apply to appointment and continuation in office"
        ],
        "applies_to": "Data Protection Board of India",
        "penalties": "N/A - institutional provision"
    },
    22: {
        "number": 22,
        "title": "Removal and Vacancy",
        "summary": "Provides for resignation and removal from office of the Chairperson and Members of the Board, and for the filling of vacancies.",
        "key_requirements": [
            "Removal and resignation of Chairperson and Members governed by the Act"
        ],
        "applies_to": "Data Protection Board of India",
        "penalties": "N/A - institutional provision"
    },
    23: {
        "number": 23,
        "title": "Proceedings of the Board",
        "summary": "Provides for the conduct and validity of the proceedings of the Board and the authentication of its orders. The Board is designed to function as a digital office (see also Section 28).",
        "key_requirements": [
            "Proceedings conducted and orders authenticated as provided under the Act",
            "Board designed to function by digital means"
        ],
        "applies_to": "Data Protection Board of India",
        "penalties": "N/A - procedural provision"
    },
    24: {
        "number": 24,
        "title": "Officers and Employees of the Board",
        "summary": "The Board may appoint such officers and employees as it considers necessary for the efficient discharge of its functions.",
        "key_requirements": [
            "Officers and employees appointed by the Board as needed"
        ],
        "applies_to": "Data Protection Board of India",
        "penalties": "N/A - institutional provision"
    },
    25: {
        "number": 25,
        "title": "Members and Officers Deemed Public Servants",
        "summary": "The Chairperson, Members, officers and employees of the Board are deemed to be public servants while acting under the Act.",
        "key_requirements": [
            "Public-servant status for Board personnel acting under the Act"
        ],
        "applies_to": "Data Protection Board of India",
        "penalties": "N/A - institutional provision"
    },
    26: {
        "number": 26,
        "title": "Powers of the Chairperson",
        "summary": "Provides for the general superintendence and administrative powers of the Chairperson of the Board.",
        "key_requirements": [
            "Chairperson exercises general superintendence over Board administration"
        ],
        "applies_to": "Data Protection Board of India",
        "penalties": "N/A - institutional provision"
    },
    27: {
        "number": 27,
        "title": "Powers and Functions of the Board",
        "summary": "On receiving an intimation of a personal data breach, the Board may direct urgent remedial or mitigation measures. It inquires into breaches of the Act on a complaint by an affected Data Principal or on a reference by the Central or a State Government, and may impose monetary penalties in accordance with Section 33 and the Schedule.",
        "key_requirements": [
            "Direct urgent remedial or mitigation measures upon breach intimation",
            "Inquire into breaches on complaint by a Data Principal or on government reference",
            "Impose monetary penalties in accordance with Section 33 and the Schedule"
        ],
        "applies_to": "Data Protection Board of India",
        "penalties": "N/A - authority provision"
    },
    28: {
        "number": 28,
        "title": "Procedure to be Followed by the Board",
        "summary": "The Board functions as a digital office: receipt of complaints, hearings and pronouncement of decisions adopt digital, techno-legal means. For the purposes of an inquiry, the Board has the powers of a civil court in respect of summoning and enforcing attendance, receiving evidence, and inspecting documents.",
        "key_requirements": [
            "Board functions as a digital office",
            "Powers of a civil court for summoning, enforcing attendance, receiving evidence and inspecting documents",
            "Principles of natural justice observed in inquiries"
        ],
        "applies_to": "Data Protection Board of India proceedings",
        "penalties": "N/A - procedural provision"
    },
    29: {
        "number": 29,
        "title": "Appeal to the Appellate Tribunal (TDSAT)",
        "summary": "Any person aggrieved by an order or direction of the Board may appeal to the Telecom Disputes Settlement and Appellate Tribunal (TDSAT) within 60 days of receipt of the order. The Appellate Tribunal may entertain an appeal after 60 days if satisfied there was sufficient cause. A further appeal lies to the Supreme Court.",
        "key_requirements": [
            "Appeals lie to the TDSAT (not a separately constituted appellate authority)",
            "File the appeal within 60 days of the Board's order or direction",
            "Late appeals may be admitted for sufficient cause",
            "Further appeal lies to the Supreme Court"
        ],
        "applies_to": "Persons aggrieved by orders or directions of the Data Protection Board of India",
        "penalties": "N/A - procedural provision"
    },
    30: {
        "number": 30,
        "title": "Orders Enforceable as Civil Court Decree",
        "summary": "Orders passed under the Act are enforceable in the same manner as a decree of a civil court.",
        "key_requirements": [
            "Orders executable as a civil court decree"
        ],
        "applies_to": "Parties subject to orders under the Act",
        "penalties": "N/A - enforcement provision"
    },
    31: {
        "number": 31,
        "title": "Voluntary Undertaking",
        "summary": "The Board may accept a voluntary undertaking from a person at any stage of proceedings in respect of any matter relating to observance of the Act. Acceptance of a voluntary undertaking bars proceedings in respect of the matters it covers.",
        "key_requirements": [
            "Board may accept a voluntary undertaking at any stage",
            "Acceptance bars proceedings on the matters covered by the undertaking"
        ],
        "applies_to": "Persons in proceedings before the Data Protection Board of India",
        "penalties": "See Section 32 for breach of an accepted undertaking"
    },
    32: {
        "number": 32,
        "title": "Breach of Voluntary Undertaking",
        "summary": "Breach of an accepted voluntary undertaking is treated as a breach for the purposes of penalties under the Schedule; the penalty may extend up to the penalty applicable to the underlying breach.",
        "key_requirements": [
            "Comply with the terms of any accepted voluntary undertaking",
            "Breach exposes the person to the penalty applicable to the underlying breach (Schedule)"
        ],
        "applies_to": "Persons whose voluntary undertakings have been accepted by the Board",
        "penalties": "Schedule: up to the penalty applicable to the underlying breach"
    },
    33: {
        "number": 33,
        "title": "Penalties",
        "summary": "If the Board determines on inquiry that a significant breach has occurred, it may impose a monetary penalty as specified in the Schedule, after considering the nature, gravity and duration of the breach, the type and nature of the personal data affected, whether the breach is repetitive, whether any gain was realised or loss avoided, and mitigation actions taken.",
        "key_requirements": [
            "Penalties determined by the Board in accordance with the Schedule",
            "Factors: nature, gravity and duration of the breach; type of personal data affected; repetitive nature of the breach; gain realised or loss avoided; mitigation actions",
            "Schedule maximums: INR 250 crore (security safeguards, Section 8(5)); INR 200 crore (breach notification, Section 8(6)); INR 200 crore (children, Section 9); INR 150 crore (SDF obligations, Section 10); INR 10,000 (Data Principal duties, Section 15); breach of voluntary undertaking - up to the penalty applicable to the underlying breach; INR 50 crore (residual, any other breach of the Act or Rules)",
            "Monetary penalties are absolute amounts (not a percentage of turnover)"
        ],
        "applies_to": "Data Protection Board of India enforcement",
        "penalties": "Per the Schedule: from up to INR 10,000 (Data Principal duties) up to INR 250 crore (security safeguards)"
    },
    34: {
        "number": 34,
        "title": "Penalties Credited to Consolidated Fund of India",
        "summary": "All sums realised by way of penalties imposed by the Board under the Act are credited to the Consolidated Fund of India.",
        "key_requirements": [
            "Penalty amounts credited to the Consolidated Fund of India"
        ],
        "applies_to": "Data Protection Board of India / Central Government",
        "penalties": "N/A - fiscal provision"
    },
    35: {
        "number": 35,
        "title": "Protection of Action Taken in Good Faith",
        "summary": "No suit, prosecution or other legal proceeding lies against the Central Government, the Board, its Chairperson, Members, officers or employees for anything done or intended to be done in good faith under the Act or the Rules.",
        "key_requirements": [
            "Good-faith protection for the Central Government and Board personnel"
        ],
        "applies_to": "Central Government and the Data Protection Board of India",
        "penalties": "N/A - protection provision"
    },
    36: {
        "number": 36,
        "title": "Power to Call for Information",
        "summary": "The Central Government may require the Board and any Data Fiduciary or intermediary to furnish such information as it may call for.",
        "key_requirements": [
            "Furnish information called for by the Central Government"
        ],
        "applies_to": "The Board, Data Fiduciaries and intermediaries",
        "penalties": "N/A - administrative provision"
    },
    37: {
        "number": 37,
        "title": "Power to Issue Directions (Including Blocking)",
        "summary": "Empowers the Central Government to issue directions in the circumstances specified in the Act, including directions for blocking public access to information, on reference from the Board and in the interests of the general public.",
        "key_requirements": [
            "Comply with directions issued by the Central Government",
            "Blocking directions may be issued in the specified circumstances"
        ],
        "applies_to": "Data Fiduciaries and intermediaries",
        "penalties": "N/A - administrative provision"
    },
    38: {
        "number": 38,
        "title": "Consistency with Other Laws",
        "summary": "Addresses the relationship between the Act and other laws in force: the Act is in addition to, and not in derogation of, other laws, and prevails to the extent of any conflict.",
        "key_requirements": [
            "Comply with the Act alongside other applicable laws; the Act prevails to the extent of conflict"
        ],
        "applies_to": "All persons subject to the Act",
        "penalties": "N/A - interpretive provision"
    },
    39: {
        "number": 39,
        "title": "Bar of Jurisdiction of Civil Courts",
        "summary": "No civil court has jurisdiction to entertain any suit or proceeding in respect of any matter which the Board is empowered to determine under the Act, and no injunction may be granted in respect of action taken under the Act.",
        "key_requirements": [
            "Disputes within the Board's competence cannot be taken to civil courts"
        ],
        "applies_to": "All persons subject to the Act",
        "penalties": "N/A - jurisdictional provision"
    },
    40: {
        "number": 40,
        "title": "Power to Make Rules",
        "summary": "The Central Government may, by notification, make rules to carry out the purposes of the Act. The Digital Personal Data Protection Rules, 2025 were notified on November 13, 2025 (G.S.R. 846(E)). Per Rule 1: Rules 1, 2 and 17-21 took effect on publication; Rule 4 (Consent Manager registration) takes effect November 13, 2026; Rules 3, 5-16, 22 and 23 (notice, security safeguards, breach intimation, erasure, children, SDF, rights, cross-border) take effect May 13, 2027.",
        "key_requirements": [
            "Central Government makes implementing rules by notification",
            "DPDP Rules, 2025 notified on November 13, 2025 with staged effectiveness"
        ],
        "applies_to": "Central Government",
        "penalties": "N/A - rule-making authority"
    },
    41: {
        "number": 41,
        "title": "Power to Amend Schedule",
        "summary": "Enables the Central Government to amend the Schedule (of penalties) by notification.",
        "key_requirements": [
            "Schedule may be amended by Central Government notification"
        ],
        "applies_to": "Central Government",
        "penalties": "N/A - amendment provision"
    },
    42: {
        "number": 42,
        "title": "Laying Before Parliament",
        "summary": "Rules made and specified notifications issued under the Act are to be laid before each House of Parliament.",
        "key_requirements": [
            "Rules and specified notifications laid before Parliament"
        ],
        "applies_to": "Central Government",
        "penalties": "N/A - procedural provision"
    },
    43: {
        "number": 43,
        "title": "Power to Remove Difficulties",
        "summary": "Enables the Central Government to make provisions, by order, for removing difficulties in giving effect to the provisions of the Act.",
        "key_requirements": [
            "Difficulty-removal orders may be made by the Central Government"
        ],
        "applies_to": "Central Government",
        "penalties": "N/A - transitional provision"
    },
    44: {
        "number": 44,
        "title": "Amendments to Other Laws",
        "summary": "Amends certain other enactments, including Section 8(1)(j) of the Right to Information Act, 2005 (the exemption relating to personal information).",
        "key_requirements": [
            "Consequential amendments to other laws, including the RTI Act, 2005 (Section 8(1)(j))"
        ],
        "applies_to": "Other enactments amended by the Act",
        "penalties": "N/A - consequential amendment provision"
    }
}


# 2. DPDP_RULES - Comprehensive rules reference
DPDP_RULES = {
    "notice": {
        "number": "DPDP Rules, 2025",
        "title": "Notice to Data Principal",
        "summary": "Data Fiduciaries must provide clear, standalone notices to Data Principals (Section 5 of the Act read with the DPDP Rules, 2025). The notice must describe the personal data sought and the purpose of processing, explain how to exercise rights (including consent withdrawal and grievance redressal) and how to complain to the Data Protection Board of India, and be available in English or any of the 22 languages in the Eighth Schedule of the Constitution.",
        "requirements": [
            "Standalone notice (not buried in T&Cs), understandable independently",
            "Clear language and accessible format",
            "Itemized description of the personal data sought",
            "Specific purposes of processing",
            "How to withdraw consent (Section 6(4)) and exercise other rights",
            "Information about the grievance redressal mechanism (Section 13)",
            "How to complain to the Data Protection Board of India",
            "Option to access the notice in English or any of the 22 Eighth Schedule languages"
        ],
        "deadline": "Substantive obligations effective May 13, 2027; must accompany or precede every request for consent",
        "applies_to": "All Data Fiduciaries"
    },
    "consent": {
        "number": "DPDP Rules, 2025",
        "title": "Consent Standards",
        "summary": "Operationalises Section 6 of the Act: consent must be free, specific, informed, unconditional and unambiguous, given by a clear affirmative action, limited to the specified purpose and to the data necessary for that purpose. Withdrawal must be as easy as giving consent.",
        "requirements": [
            "Clear affirmative action (checkbox, button click, etc.)",
            "Specific consent limited to the specified purpose",
            "Cannot be bundled with unrelated service terms (must be unconditional)",
            "Data limited to what is necessary for the specified purpose",
            "Easy withdrawal mechanism, as easy as giving consent (Section 6(4))",
            "Maintain records evidencing notice and consent",
            "Cease processing within a reasonable time after withdrawal unless required by law"
        ],
        "deadline": "Substantive obligations effective May 13, 2027",
        "applies_to": "All Data Fiduciaries relying on consent"
    },
    "consent_managers": {
        "number": "DPDP Rules, 2025",
        "title": "Registration and Obligations of Consent Managers",
        "summary": "Consent Managers must be registered with the Data Protection Board of India (Section 6(7)-(9) of the Act read with the DPDP Rules, 2025). The Rules specify eligibility criteria, registration and obligations. Consent Managers are accountable to the Data Principal and act through an interoperable platform.",
        "requirements": [
            "Incorporated in India",
            "Minimum net worth of INR 2 crore",
            "Sound financial condition and management",
            "Technical, operational, and financial capacity",
            "Registered with the Data Protection Board of India",
            "Accountable to the Data Principal (Section 6(8))",
            "Interoperable platform enabling giving, managing, reviewing and withdrawing consent",
            "Maintain records and implement robust security safeguards",
            "Must not use personal data for its own purposes"
        ],
        "deadline": "Registration with the Board opens November 13, 2026",
        "applies_to": "Entities operating as Consent Managers"
    },
    "retention_and_erasure": {
        "number": "DPDP Rules, 2025",
        "title": "Data Retention and Erasure",
        "summary": "Personal data must be erased when the Data Principal withdraws consent or when the specified purpose is no longer being served, unless retention is required by law (Section 8(7) of the Act read with the DPDP Rules, 2025).",
        "requirements": [
            "Establish a data retention policy tied to the specified purpose",
            "Erase data when consent is withdrawn or the purpose is no longer served",
            "Cause Data Processors to erase data likewise",
            "Document erasure procedures and retention schedules",
            "Cannot retain data indefinitely",
            "Exception: retention required for compliance with law"
        ],
        "deadline": "Substantive obligations effective May 13, 2027",
        "applies_to": "All Data Fiduciaries"
    },
    "security_safeguards": {
        "number": "DPDP Rules, 2025",
        "title": "Reasonable Security Safeguards",
        "summary": "Prescribes minimum reasonable security safeguards to prevent personal data breach (Section 8(5) of the Act read with the DPDP Rules, 2025), including technical and organisational measures.",
        "requirements": [
            "Implement reasonable security safeguards to prevent personal data breach",
            "Encryption, obfuscation or masking of personal data as appropriate",
            "Access controls and authentication",
            "Logs and monitoring to detect unauthorised access",
            "Data backups to ensure continuity",
            "Incident response procedures",
            "Contractual security obligations on Data Processors",
            "Appropriate technical and organisational measures (Section 8(4))"
        ],
        "deadline": "Substantive obligations effective May 13, 2027",
        "applies_to": "All Data Fiduciaries"
    },
    "breach_intimation": {
        "number": "Rule 7, DPDP Rules, 2025",
        "title": "Intimation of Personal Data Breach",
        "summary": "Operationalises Section 8(6) of the Act: on becoming aware of a personal data breach, the Data Fiduciary must intimate the Data Protection Board of India immediately (without delay) and submit a detailed report to the Board within 72 hours, and must intimate each affected Data Principal without delay.",
        "requirements": [
            "Intimate the Board immediately upon becoming aware of a breach",
            "Submit a detailed report to the Board within 72 hours (extendable only with Board approval)",
            "Intimate each affected Data Principal without delay, in the prescribed form and manner",
            "Describe the nature, extent and impact of the breach",
            "Include mitigation and remedial measures taken",
            "Maintain breach documentation",
            "No materiality threshold - all personal data breaches are reportable"
        ],
        "deadline": "72 hours for the detailed report to the Board (Rule 7)",
        "applies_to": "All Data Fiduciaries experiencing personal data breaches"
    },
    "data_principal_rights": {
        "number": "DPDP Rules, 2025",
        "title": "Exercise of Data Principal Rights",
        "summary": "Establishes mechanisms for Data Principals to exercise their rights: access information about personal data (Section 11), correction, completion, updating and erasure (Section 12), grievance redressal (Section 13) and nomination (Section 14).",
        "requirements": [
            "Publish the means by which Data Principals can make rights requests",
            "Respond to access requests within the time period published by the Data Fiduciary / as prescribed under the DPDP Rules, 2025 (verify against the gazetted Rules)",
            "Provide information in a clear, accessible format",
            "Act on correction, completion, updating and erasure requests",
            "Enable nomination of individual(s) to exercise rights on death or incapacity (Section 14)",
            "Maintain records of requests and responses"
        ],
        "deadline": "Substantive obligations effective May 13, 2027",
        "applies_to": "All Data Fiduciaries"
    },
    "grievance_redressal": {
        "number": "DPDP Rules, 2025",
        "title": "Grievance Redressal",
        "summary": "Data Fiduciaries and Consent Managers must provide readily available means of grievance redressal (Section 13 of the Act read with the DPDP Rules, 2025). The Data Principal must exhaust this mechanism before approaching the Data Protection Board of India.",
        "requirements": [
            "Maintain a readily available grievance redressal mechanism",
            "Respond to grievances within the time period published by the Data Fiduciary / as prescribed under the DPDP Rules, 2025 (verify against the gazetted Rules)",
            "Publish contact details of the DPO or a person able to answer questions (Section 8(9))",
            "Maintain grievance records",
            "Data Principals must exhaust this mechanism before complaining to the Board"
        ],
        "deadline": "Substantive obligations effective May 13, 2027",
        "applies_to": "All Data Fiduciaries and Consent Managers"
    },
    "children": {
        "number": "DPDP Rules, 2025",
        "title": "Processing of Personal Data of Children",
        "summary": "Operationalises Section 9 of the Act: verifiable consent of the parent or lawful guardian is required before processing a child's (under 18) personal data. Tracking, behavioural monitoring of children and targeted advertising directed at children are prohibited (Section 9(3)).",
        "requirements": [
            "Obtain verifiable consent of the parent or lawful guardian",
            "Exercise due diligence to verify that the person giving consent is an adult identifiable as the parent/guardian",
            "No tracking or behavioural monitoring of children (Section 9(3))",
            "No targeted advertising directed at children (Section 9(3))",
            "No processing likely to cause a detrimental effect on the well-being of a child",
            "Exemptions or a lower age threshold may be notified by the Central Government for fiduciaries verified as safe"
        ],
        "deadline": "Substantive obligations effective May 13, 2027",
        "applies_to": "Data Fiduciaries processing children's data"
    },
    "persons_with_disability": {
        "number": "DPDP Rules, 2025",
        "title": "Processing of Personal Data of Persons with Disability",
        "summary": "Where a person with disability has a lawful guardian, the Data Fiduciary must obtain the verifiable consent of the lawful guardian before processing (Section 9 of the Act read with the DPDP Rules, 2025). Accessibility of notices and rights mechanisms supports valid, informed consent.",
        "requirements": [
            "Obtain verifiable consent of the lawful guardian where one exists",
            "Accessible notice mechanisms",
            "Support for exercising Data Principal rights",
            "Accessible grievance mechanisms",
            "Consider dignity and autonomy"
        ],
        "deadline": "Substantive obligations effective May 13, 2027",
        "applies_to": "Data Fiduciaries processing data of persons with disability who have lawful guardians"
    },
    "data_processors": {
        "number": "DPDP Rules, 2025",
        "title": "Data Processors",
        "summary": "The Data Fiduciary may engage a Data Processor only under a valid contract, and remains responsible for compliance with the Act in respect of processing undertaken on its behalf (Section 8(1)-(2) of the Act).",
        "requirements": [
            "Engage Data Processors only under a valid contract (Section 8(2))",
            "Data Fiduciary remains responsible for the processor's compliance (Section 8(1))",
            "Processor must not process data for its own purposes",
            "Impose security safeguard obligations on processors",
            "Cause processors to erase data when required (Section 8(7))",
            "Require processor assistance with breach intimation and rights requests"
        ],
        "deadline": "Substantive obligations effective May 13, 2027",
        "applies_to": "Data Fiduciaries and their Data Processors"
    },
    "significant_data_fiduciaries": {
        "number": "DPDP Rules, 2025",
        "title": "Additional Obligations of Significant Data Fiduciaries",
        "summary": "Operationalises Section 10 of the Act. SDF status arises only by Central Government notification, based on factors including the volume and sensitivity of data, risk to Data Principal rights, and potential impact on sovereignty and integrity of India, electoral democracy, security of the State and public order. There is no numeric or resident-count threshold in the Act.",
        "requirements": [
            "Appoint a Data Protection Officer based in India, responsible to the board of directors",
            "Conduct periodic Data Protection Impact Assessments (annual under the DPDP Rules, 2025 - verify against the gazetted Rules)",
            "Undertake periodic audit through an independent data auditor",
            "Verify that algorithmic software deployed does not pose a risk to the rights of Data Principals",
            "Undertake other measures as prescribed",
            "Monitor Central Government notifications for SDF designation"
        ],
        "deadline": "Substantive obligations effective May 13, 2027 (for notified SDFs)",
        "applies_to": "Data Fiduciaries notified as Significant Data Fiduciaries"
    },
    "cross_border_transfers": {
        "number": "DPDP Rules, 2025",
        "title": "Cross-Border Data Transfers",
        "summary": "Under Section 16 of the Act, personal data may be transferred to any country or territory outside India except those restricted by Central Government notification (negative-list model). There is no adequacy requirement, no explicit-consent requirement, and no SCC mechanism. Stricter sectoral restrictions (e.g., RBI payment data localisation) continue to apply (Section 16(2)).",
        "requirements": [
            "Transfers permitted unless the destination is on the notified negative list",
            "Monitor Central Government notifications restricting transfers",
            "Comply with any conditions prescribed for transfers under the DPDP Rules, 2025",
            "Continue complying with stricter sectoral laws (e.g., RBI payment data localisation) per Section 16(2)"
        ],
        "deadline": "Substantive obligations effective May 13, 2027",
        "applies_to": "Data Fiduciaries transferring personal data outside India"
    }
}


# 3. KEY_DEFINITIONS - Comprehensive term definitions
KEY_DEFINITIONS = {
    "Personal Data": "Any data about an individual who is identifiable by or in relation to such data. Includes name, email, phone, IP address, ID number, or any information linking to an individual.",

    "Data Principal": "The individual to whom the personal data relates. The rights holder who can exercise control over their data.",

    "Data Fiduciary": "Any person who alone or in conjunction with other persons determines the purpose and means of processing of personal data. Decision-maker about how and why data is processed.",

    "Data Processor": "A person who processes personal data on behalf of a data fiduciary. Acts only on fiduciary's instructions and cannot process for own purposes.",

    "Processing": "Wholly or partly automated operation or set of operations performed on digital personal data, including collection, recording, organization, storage, retrieval, use, disclosure, or deletion.",

    "Consent": "Free, specific, informed, unconditional and unambiguous indication by the Data Principal, given by a clear affirmative action, signifying agreement to processing for the specified purpose and limited to the personal data necessary for that purpose (Section 6).",

    "Withdrawal of Consent": "Data principal's right to withdraw consent at any time. Fiduciary must provide easy mechanism for withdrawal.",

    "Data Protection Board of India": "The adjudicatory body established under Section 18 of the Act. Functions as a digital office (Section 28); directs urgent remedial measures on breach intimation, inquires into breaches on complaint or government reference, and imposes penalties per Section 33 and the Schedule (Section 27). Appeals against its orders lie to the TDSAT (Section 29).",

    "Data Protection Officer": "Individual appointed by a Significant Data Fiduciary under Section 10. Must be based in India, be responsible to the board of directors (or similar governing body), and act as the point of contact for grievance redressal.",

    "Significant Data Fiduciary": "A Data Fiduciary or class of Data Fiduciaries notified by the Central Government under Section 10, based on factors such as the volume and sensitivity of personal data processed, risk to Data Principal rights, and potential impact on sovereignty and integrity of India, electoral democracy, security of the State and public order. The Act contains no numeric or resident-count threshold.",

    "Data Breach": "Unauthorized processing, or accidental disclosure, acquisition, sharing, use, alteration, destruction or loss of access to personal data, that compromises its confidentiality, integrity or availability. The Data Fiduciary must intimate the Board and each affected Data Principal (Section 8(6)); under the DPDP Rules, 2025, the Board must be intimated immediately with a detailed report within 72 hours (Rule 7).",

    "Breach Notification": "Intimation to the Data Protection Board of India and each affected Data Principal in the prescribed form and manner (Section 8(6)). Under Rule 7 of the DPDP Rules, 2025: immediate intimation to the Board, followed by a detailed 72-hour report; affected Data Principals must be intimated without delay.",

    "Security Safeguards": "Technical and organizational measures protecting personal data from unauthorized access, modification, or deletion. Include encryption, access controls, auditing.",

    "Data Retention": "Period for which personal data is kept. Fiduciary must delete data when no longer necessary for purpose.",

    "Data Deletion": "Permanent removal of personal data from systems. Fiduciary must delete upon request or when retention period expires.",

    "Certain Legitimate Uses": "Grounds under Section 7 for processing without consent: (a) voluntary provision for a specified purpose without indication of non-consent; (b) State subsidies, benefits, services, certificates, licences and permits; (c) State functions/sovereignty/security; (d) legal obligations and disclosures to the State; (e) compliance with judgments, decrees or orders; (f) medical emergencies (threat to life or health); (g) epidemics/public health; (h) disasters/breakdown of public order; (i) employment purposes and safeguarding the employer.",

    "Cross-border Data Transfer": "Transfer of personal data outside India. Under Section 16, permitted to any country except those restricted by Central Government notification (negative-list model). No adequacy requirement or explicit-consent requirement under the Act; stricter sectoral laws (e.g., RBI payment data localisation) continue to apply (Section 16(2)).",

    "Consent Manager": "A person registered with the Data Protection Board of India who enables Data Principals to give, manage, review and withdraw consent through an accessible, transparent and interoperable platform, and who is accountable to the Data Principal (Section 6(7)-(9)).",

    "Data Protection Impact Assessment": "A process assessing risks to the rights of Data Principals and related safeguards. Significant Data Fiduciaries must undertake periodic DPIAs (Section 10); the DPDP Rules, 2025 prescribe the periodicity (verify against the gazetted Rules).",

    "Automated Decision-making": "Decision-making performed by automated means. 'Processing' under the Act covers wholly or partly automated operations (Section 2); under the DPDP Rules, 2025, Significant Data Fiduciaries must verify that algorithmic software they deploy does not pose a risk to the rights of Data Principals.",

    "Behavioral Tracking": "Monitoring of an individual's online activities, preferences, or behavior. Tracking and behavioural monitoring of children are prohibited (Section 9(3)).",

    "Targeted Advertising": "Advertisements directed at individuals based on profiling. Targeted advertising directed at children is prohibited (Section 9(3)).",

    "Grievance": "Complaint by a Data Principal regarding an act or omission of a Data Fiduciary or Consent Manager. Must first be raised through the fiduciary's or consent manager's grievance redressal mechanism (Section 13); only after exhausting that remedy may the Data Principal complain to the Data Protection Board of India.",

    "Child": "An individual who has not completed eighteen years of age (Section 2). Processing requires verifiable consent of the parent or lawful guardian, and tracking, behavioural monitoring and targeted advertising directed at children are prohibited (Section 9).",

    "Sensitive Personal Data": "The DPDPA does not create a separate 'sensitive personal data' category - all digital personal data is protected uniformly. Children's data attracts additional protections (Section 9), and data sensitivity is a factor the Central Government considers when notifying Significant Data Fiduciaries (Section 10).",

    "Nomination": "The Data Principal's right under Section 14 to nominate one or more individuals to exercise the Data Principal's rights under the Act in the event of death or incapacity.",

    "Duties of Data Principals": "Obligations under Section 15: comply with applicable laws, do not impersonate, do not suppress material information, do not register false or frivolous complaints, and furnish verifiably authentic information for correction or erasure. Breach attracts a penalty of up to INR 10,000 (Schedule).",

    "Appellate Tribunal (TDSAT)": "The Telecom Disputes Settlement and Appellate Tribunal, which hears appeals against orders and directions of the Data Protection Board of India. Appeals must be filed within 60 days (extendable for sufficient cause); further appeal lies to the Supreme Court (Section 29).",

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
            "description": "SDF status arises only by Central Government notification (Section 10 factors: volume and sensitivity of data, risk to Data Principal rights, impact on sovereignty, electoral democracy, security of the State, public order). Monitor notifications to determine whether your organization is designated",
            "priority": "CRITICAL",
            "section_reference": "Section 10",
            "is_sdf_only": False
        },
        {
            "item": "Appoint Data Protection Officer",
            "description": "SDFs must appoint a DPO based in India, responsible to the board of directors (or similar governing body) and acting as point of contact for grievance redressal",
            "priority": "CRITICAL",
            "section_reference": "Section 10",
            "is_sdf_only": True
        },
        {
            "item": "Establish Grievance Mechanism",
            "description": "Create a readily available grievance redressal process; respond within the time period published by the Data Fiduciary / as prescribed under the DPDP Rules, 2025 (verify against the gazetted Rules). Escalate to DPO if SDF",
            "priority": "CRITICAL",
            "section_reference": "Section 13, Section 8(10)",
            "is_sdf_only": False
        },
        {
            "item": "Maintain Data Fiduciary Records",
            "description": "Document all processing activities, legal bases, consent records, breach reports, and compliance evidence",
            "priority": "HIGH",
            "section_reference": "Section 8",
            "is_sdf_only": False
        },
        {
            "item": "Create Data Retention Policy",
            "description": "Establish written policy specifying retention period for each data category and erasure procedures (erase when consent is withdrawn or purpose no longer served)",
            "priority": "HIGH",
            "section_reference": "Section 8(7)",
            "is_sdf_only": False
        }
    ],
    "Consent Management": [
        {
            "item": "Obtain Written Consent",
            "description": "Collect voluntary, specific, informed, clear affirmative consent. Maintain proof and records",
            "priority": "CRITICAL",
            "section_reference": "Section 6, DPDP Rules 2025",
            "is_sdf_only": False
        },
        {
            "item": "Use Consent Manager for Consent Collection",
            "description": "Consider using registered Consent Manager to collect and manage consents on behalf of fiduciary",
            "priority": "MEDIUM",
            "section_reference": "Section 6(7)-(9), DPDP Rules 2025",
            "is_sdf_only": False
        },
        {
            "item": "Implement Consent Withdrawal Mechanism",
            "description": "Provide easy mechanism for Data Principals to withdraw consent at any time; withdrawal must be as easy as giving consent",
            "priority": "HIGH",
            "section_reference": "Section 6(4)",
            "is_sdf_only": False
        },
        {
            "item": "Avoid Bundled Consent",
            "description": "Do not bundle data consent with service terms. Consent must be separate, specific, and optional",
            "priority": "CRITICAL",
            "section_reference": "Section 6, DPDP Rules 2025",
            "is_sdf_only": False
        },
        {
            "item": "Obtain Parental Consent for Children",
            "description": "For children (under 18), obtain verifiable consent from parent or guardian before processing",
            "priority": "CRITICAL",
            "section_reference": "Section 9, DPDP Rules 2025",
            "is_sdf_only": False
        }
    ],
    "Data Privacy Notices": [
        {
            "item": "Create Standalone Privacy Notice",
            "description": "Provide clear, standalone notice (not buried in T&Cs) disclosing all data collection and processing details",
            "priority": "CRITICAL",
            "section_reference": "Section 5, DPDP Rules 2025",
            "is_sdf_only": False
        },
        {
            "item": "Itemize Personal Data Categories",
            "description": "Clearly list each category of personal data collected with examples",
            "priority": "HIGH",
            "section_reference": "Section 5, DPDP Rules 2025",
            "is_sdf_only": False
        },
        {
            "item": "Disclose Processing Purposes",
            "description": "Specify every purpose for which personal data will be processed",
            "priority": "CRITICAL",
            "section_reference": "Section 5, DPDP Rules 2025",
            "is_sdf_only": False
        },
        {
            "item": "Include Data Retention Period",
            "description": "Clearly state how long personal data will be retained and deletion policy",
            "priority": "HIGH",
            "section_reference": "Section 5, Section 8(7)",
            "is_sdf_only": False
        },
        {
            "item": "Disclose Data Recipients",
            "description": "Identify parties who will receive personal data (processors, partners, government agencies)",
            "priority": "HIGH",
            "section_reference": "Section 5, DPDP Rules 2025",
            "is_sdf_only": False
        },
        {
            "item": "Include Data Principal Rights Information",
            "description": "Inform about rights: access, correction, deletion, grievance filing with links/instructions",
            "priority": "HIGH",
            "section_reference": "Section 5, Sections 11-14",
            "is_sdf_only": False
        },
        {
            "item": "Update Privacy Notices",
            "description": "Review and update notices when processing changes or new purposes added",
            "priority": "MEDIUM",
            "section_reference": "Section 5, DPDP Rules 2025",
            "is_sdf_only": False
        }
    ],
    "Security and Data Protection": [
        {
            "item": "Implement Security Safeguards",
            "description": "Deploy technical and organizational measures: encryption, access controls, authentication, auditing",
            "priority": "CRITICAL",
            "section_reference": "Section 8(4)-(5)",
            "is_sdf_only": False
        },
        {
            "item": "Encrypt Data at Rest",
            "description": "Use strong encryption for stored personal data in databases, backups, archives",
            "priority": "CRITICAL",
            "section_reference": "Section 8(5), DPDP Rules 2025",
            "is_sdf_only": False
        },
        {
            "item": "Encrypt Data in Transit",
            "description": "Use TLS/SSL encryption for data transmission over networks and internet",
            "priority": "CRITICAL",
            "section_reference": "Section 8(5), DPDP Rules 2025",
            "is_sdf_only": False
        },
        {
            "item": "Implement Access Controls",
            "description": "Restrict access to personal data to authorized personnel only. Use role-based access control",
            "priority": "CRITICAL",
            "section_reference": "Section 8(5), DPDP Rules 2025",
            "is_sdf_only": False
        },
        {
            "item": "Maintain Processing Logs",
            "description": "Document all processing activities including access, modification, deletion with timestamps and user info",
            "priority": "HIGH",
            "section_reference": "Section 8(5), DPDP Rules 2025",
            "is_sdf_only": False
        },
        {
            "item": "Conduct Security Audits",
            "description": "Regularly audit security safeguards through internal reviews and third-party assessments",
            "priority": "MEDIUM",
            "section_reference": "Section 8(5), DPDP Rules 2025",
            "is_sdf_only": False
        },
        {
            "item": "Perform Penetration Testing",
            "description": "Test systems against vulnerabilities and simulated attacks. Remediate findings promptly",
            "priority": "MEDIUM",
            "section_reference": "Section 8(5), DPDP Rules 2025",
            "is_sdf_only": False
        },
        {
            "item": "Manage Vendor/Processor Security",
            "description": "Ensure data processors implement equivalent security measures through contracts and audits",
            "priority": "HIGH",
            "section_reference": "Section 8(2)",
            "is_sdf_only": False
        }
    ],
    "Data Breach Management": [
        {
            "item": "Establish Breach Detection Mechanism",
            "description": "Implement tools and processes to detect unauthorized access, disclosure, or modification of personal data",
            "priority": "CRITICAL",
            "section_reference": "Section 8(6)",
            "is_sdf_only": False
        },
        {
            "item": "Notify Board Within 72 Hours",
            "description": "Intimate the Data Protection Board of India immediately, with a detailed report within 72 hours of becoming aware of the breach",
            "priority": "CRITICAL",
            "section_reference": "Section 8(6), Rule 7",
            "is_sdf_only": False
        },
        {
            "item": "Notify Data Principals Without Delay",
            "description": "Inform affected data principals of breach, its nature, extent, and mitigation measures",
            "priority": "CRITICAL",
            "section_reference": "Section 8(6), Rule 7",
            "is_sdf_only": False
        },
        {
            "item": "Maintain Breach Records",
            "description": "Document all breaches with discovery date, notification evidence, impact assessment, and remediation",
            "priority": "HIGH",
            "section_reference": "Section 8(6)",
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
            "description": "Provide mechanism for Data Principals to obtain a summary of their personal data, processing activities, and the identities of fiduciaries/processors with whom it was shared. Respond within the time period published by the Data Fiduciary / as prescribed under the DPDP Rules, 2025 (verify against the gazetted Rules)",
            "priority": "HIGH",
            "section_reference": "Section 11, DPDP Rules 2025",
            "is_sdf_only": False
        },
        {
            "item": "Enable Correction Requests",
            "description": "Allow data principals to correct inaccurate/misleading data. Process promptly",
            "priority": "HIGH",
            "section_reference": "Section 12, DPDP Rules 2025",
            "is_sdf_only": False
        },
        {
            "item": "Enable Deletion Requests",
            "description": "Allow data principals to request erasure of personal data. Delete unless legal retention required",
            "priority": "HIGH",
            "section_reference": "Section 12, DPDP Rules 2025",
            "is_sdf_only": False
        },
        {
            "item": "Provide Information in Accessible Format",
            "description": "Respond to Data Principal requests with clear information in commonly understood format",
            "priority": "MEDIUM",
            "section_reference": "Section 11, DPDP Rules 2025",
            "is_sdf_only": False
        },
        {
            "item": "Enable Nomination Facility",
            "description": "Allow Data Principals to nominate one or more individuals who may exercise their rights in the event of death or incapacity",
            "priority": "MEDIUM",
            "section_reference": "Section 14",
            "is_sdf_only": False
        }
    ],
    "Children and Vulnerable Groups": [
        {
            "item": "Identify Children's Data Processing",
            "description": "Map all processing of children's personal data and implement enhanced protections",
            "priority": "CRITICAL",
            "section_reference": "Section 9, DPDP Rules 2025",
            "is_sdf_only": False
        },
        {
            "item": "Implement Age Verification",
            "description": "Implement mechanisms to verify age of users. Treat under-18 as child requiring verifiable parental/guardian consent",
            "priority": "HIGH",
            "section_reference": "Section 9, DPDP Rules 2025",
            "is_sdf_only": False
        },
        {
            "item": "Prohibit Behavioral Tracking of Children",
            "description": "Do not track, monitor, or profile children's online behavior, activities, or preferences",
            "priority": "CRITICAL",
            "section_reference": "Section 9(3)",
            "is_sdf_only": False
        },
        {
            "item": "Prohibit Targeted Advertising to Children",
            "description": "Do not direct advertisements to children based on profiling or behavior",
            "priority": "CRITICAL",
            "section_reference": "Section 9(3)",
            "is_sdf_only": False
        },
        {
            "item": "Provide Accessible Mechanisms for Disability",
            "description": "Ensure all DPDPA-related mechanisms (notices, grievance, rights exercise) are accessible to persons with disabilities; obtain verifiable consent of the lawful guardian where one exists",
            "priority": "HIGH",
            "section_reference": "Section 9, DPDP Rules 2025",
            "is_sdf_only": False
        }
    ],
    "Data Processors and Vendors": [
        {
            "item": "Identify All Data Processors",
            "description": "Document all third parties processing personal data on your behalf (hosting, analytics, CRM, etc.)",
            "priority": "HIGH",
            "section_reference": "Section 8(2)",
            "is_sdf_only": False
        },
        {
            "item": "Execute Data Processing Contracts",
            "description": "Have written agreement with each processor clearly defining roles, obligations, and security requirements",
            "priority": "CRITICAL",
            "section_reference": "Section 8(2)",
            "is_sdf_only": False
        },
        {
            "item": "Restrict Processor to Instructions",
            "description": "Ensure processor agreement explicitly prohibits processing beyond fiduciary's instructions",
            "priority": "CRITICAL",
            "section_reference": "Section 8(2)",
            "is_sdf_only": False
        },
        {
            "item": "Audit Processor Security",
            "description": "Conduct or require audits of processor's security and compliance measures annually",
            "priority": "HIGH",
            "section_reference": "Section 8(1)-(2)",
            "is_sdf_only": False
        },
        {
            "item": "Control Sub-processor Use",
            "description": "Require processor to get your approval before engaging sub-processors. Maintain sub-processor list",
            "priority": "HIGH",
            "section_reference": "Section 8(1)-(2)",
            "is_sdf_only": False
        },
        {
            "item": "Include Data Principal Rights Assistance",
            "description": "Require processors to assist in responding to access, correction, deletion, and breach notification requests",
            "priority": "HIGH",
            "section_reference": "Section 8(1)-(2)",
            "is_sdf_only": False
        }
    ],
    "International Data Transfer": [
        {
            "item": "Identify International Data Transfers",
            "description": "Map all transfers of personal data outside India to other countries",
            "priority": "MEDIUM",
            "section_reference": "Section 16",
            "is_sdf_only": False
        },
        {
            "item": "Check the Negative List Before Transferring",
            "description": "Transfers are permitted to any country except those restricted by Central Government notification (negative-list model). Monitor notifications; no adequacy assessment or explicit-consent requirement applies under the Act",
            "priority": "CRITICAL",
            "section_reference": "Section 16",
            "is_sdf_only": False
        },
        {
            "item": "Comply with Sectoral Localisation Requirements",
            "description": "Stricter sectoral restrictions (e.g., RBI payment data localisation) continue to apply in addition to the Act",
            "priority": "HIGH",
            "section_reference": "Section 16(2)",
            "is_sdf_only": False
        },
        {
            "item": "Document Transfer Locations and Recipients",
            "description": "Maintain records of destinations and recipients of transferred personal data, so restricted-country notifications can be acted on quickly",
            "priority": "HIGH",
            "section_reference": "Section 16",
            "is_sdf_only": False
        },
        {
            "item": "Remain Accountable for Recipient",
            "description": "The Data Fiduciary remains responsible for compliance in respect of processing undertaken on its behalf, including by overseas processors, under a valid contract",
            "priority": "CRITICAL",
            "section_reference": "Section 8(1)-(2), Section 16",
            "is_sdf_only": False
        }
    ],
    "SDF-Specific Obligations": [
        {
            "item": "Conduct Periodic Data Protection Impact Assessment",
            "description": "SDFs must undertake periodic DPIAs assessing risks to Data Principal rights, documenting safeguards and mitigation (annual under the DPDP Rules, 2025 - verify against the gazetted Rules)",
            "priority": "CRITICAL",
            "section_reference": "Section 10, DPDP Rules 2025",
            "is_sdf_only": True
        },
        {
            "item": "Perform Periodic Independent Audit",
            "description": "SDFs must appoint an independent data auditor and undertake periodic audits of DPDPA compliance (annual under the DPDP Rules, 2025 - verify against the gazetted Rules)",
            "priority": "CRITICAL",
            "section_reference": "Section 10, DPDP Rules 2025",
            "is_sdf_only": True
        },
        {
            "item": "Monitor Algorithmic Processing",
            "description": "SDFs must assess automated decision-making systems for bias, fairness, and data principal impact",
            "priority": "HIGH",
            "section_reference": "Section 10, DPDP Rules 2025",
            "is_sdf_only": True
        },
        {
            "item": "Maintain DPO Independence",
            "description": "Ensure DPO has sufficient organizational independence to raise compliance concerns without retaliation; DPO is responsible to the board of directors",
            "priority": "CRITICAL",
            "section_reference": "Section 10",
            "is_sdf_only": True
        },
        {
            "item": "Document SDF Compliance Activities",
            "description": "Maintain records of DPIA, audits, DPO activities, algorithmic assessments, and Board interactions",
            "priority": "HIGH",
            "section_reference": "Section 10, DPDP Rules 2025",
            "is_sdf_only": True
        },
        {
            "item": "Report to Data Protection Board of India",
            "description": "Provide Board with audit reports, DPIA summaries, and compliance documentation as requested",
            "priority": "HIGH",
            "section_reference": "Section 10, DPDP Rules 2025",
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
            "section_reference": "Section 8(5), DPDP Rules 2025",
            "is_sdf_only": False
        },
        {
            "item": "Establish Access Control Training",
            "description": "Train authorized personnel on accessing personal data, maintaining confidentiality, audit logs",
            "priority": "MEDIUM",
            "section_reference": "Section 8(5), DPDP Rules 2025",
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
        "answer": "DPDPA applies to any person (individual, company, organization, government entity) processing digital personal data within India, and to processing outside India in connection with offering goods or services to Data Principals in India (Section 3). It does not apply to: personal data processed by an individual for personal or domestic purposes, or personal data made publicly available by the Data Principal or by another person under a legal obligation."
    },
    {
        "question": "What is personal data under DPDPA?",
        "answer": "Personal data is any data about an individual who is identifiable by or in relation to such data. Examples: name, email, phone, IP address, ID number, biometric data, cookies, device identifiers, or any information that identifies an individual."
    },
    {
        "question": "What is a Significant Data Fiduciary?",
        "answer": "An SDF is a Data Fiduciary (or class of fiduciaries) notified as such by the Central Government under Section 10 - there is no numeric or resident-count threshold in the Act. The notification is based on factors including the volume and sensitivity of personal data processed, risk to Data Principal rights, and potential impact on the sovereignty and integrity of India, electoral democracy, security of the State, and public order. SDFs face additional obligations: a DPO based in India responsible to the board of directors, an independent data auditor, and periodic DPIAs and audits."
    },
    {
        "question": "Can I collect personal data without consent?",
        "answer": "Yes, only for the 'certain legitimate uses' in Section 7: (a) voluntary provision for a specified purpose without indication of non-consent; (b) State subsidies, benefits, services, certificates, licences and permits; (c) State functions and sovereignty/security; (d) legal obligations and disclosures to the State; (e) compliance with judgments or orders; (f) medical emergencies; (g) epidemics/public health; (h) disasters/breakdown of public order; (i) employment purposes and safeguarding the employer. All other processing requires consent under Section 6."
    },
    {
        "question": "How do I obtain valid consent under DPDPA?",
        "answer": "Under Section 6, consent must be: (1) Free - without coercion; (2) Specific - limited to the specified purpose; (3) Informed - preceded or accompanied by a Section 5 notice; (4) Unconditional - not bundled with unrelated terms; (5) Unambiguous, with a clear affirmative action (opt-in, not opt-out); and (6) Limited to the personal data necessary for the purpose. Withdrawal must be as easy as giving consent. Maintain records evidencing notice and consent."
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
        "answer": "Under Section 8(6) read with Rule 7 of the DPDP Rules, 2025: (1) Immediately intimate the Data Protection Board of India; (2) Submit a detailed report to the Board within 72 hours covering breach details, impact, and remediation; (3) Intimate each affected Data Principal without delay; (4) Maintain breach documentation; (5) Implement preventive measures. No materiality threshold - all breaches reportable. Maximum penalty for failure to notify: INR 200 crore (Schedule)."
    },
    {
        "question": "What are my Data Principal rights?",
        "answer": "Data Principals can: (1) Access a summary of their personal data, processing activities, and the fiduciaries/processors it was shared with (Section 11); (2) Seek correction, completion, updating and erasure (Section 12); (3) Use readily available grievance redressal (Section 13); (4) Nominate individual(s) to exercise rights on death or incapacity (Section 14); (5) Withdraw consent at any time, as easily as it was given (Section 6(4)). The fiduciary must respond within the time period published by the Data Fiduciary / as prescribed under the DPDP Rules, 2025 (verify against the gazetted Rules)."
    },
    {
        "question": "Do I need a Data Protection Officer?",
        "answer": "Only Significant Data Fiduciaries (notified under Section 10) must appoint a DPO. The DPO must be based in India, be responsible to the board of directors (or similar governing body), and act as the point of contact for grievance redressal. Other Data Fiduciaries need not appoint a DPO, but must publish contact details of a person able to answer Data Principals' questions about processing (Section 8(9))."
    },
    {
        "question": "What is a Data Protection Impact Assessment?",
        "answer": "A DPIA is a process assessing risks to the rights of Data Principals and the safeguards and mitigation measures in place. Significant Data Fiduciaries must undertake DPIAs periodically (Section 10); the DPDP Rules, 2025 prescribe the periodicity (verify against the gazetted Rules). Results must be documented; SDFs must also undergo periodic audit by an independent data auditor."
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
        "answer": "Section 16 follows a negative-list model: transfer is allowed to any country EXCEPT those restricted by Central Government notification. There is no adequacy requirement, no explicit-consent requirement, and no SCC mechanism under the Act. You must: (1) Monitor restricted-country notifications; (2) Continue meeting all your Data Fiduciary obligations for the transferred data, including for overseas processors (Section 8(1)-(2)); (3) Comply with stricter sectoral rules that continue to apply, e.g., RBI payment data localisation (Section 16(2))."
    },
    {
        "question": "What are DPDPA penalties?",
        "answer": "Penalties are set out in the Schedule to the Act and imposed by the Board under Section 33: (1) up to INR 250 crore - failure of reasonable security safeguards (Section 8(5)); (2) up to INR 200 crore - failure to notify a breach to the Board/Data Principals (Section 8(6)); (3) up to INR 200 crore - breach of children's data obligations (Section 9); (4) up to INR 150 crore - breach of SDF obligations (Section 10); (5) up to INR 10,000 - breach of Data Principal duties (Section 15); (6) breach of a voluntary undertaking - up to the penalty for the underlying breach; (7) up to INR 50 crore - any other breach of the Act or Rules (residual). Penalties are absolute amounts, not a revenue percentage, and are credited to the Consolidated Fund of India (Section 34)."
    },
    {
        "question": "How do I complain to the Data Protection Board of India?",
        "answer": "First exhaust the Data Fiduciary's or Consent Manager's own grievance redressal mechanism (Section 13) - this is mandatory before approaching the Board. Then: (1) Complain to the Board, which functions as a digital office (Section 28); (2) The Board may inquire, direct remedial measures and impose penalties per the Schedule (Section 27); (3) Appeals against Board orders lie to the Telecom Disputes Settlement and Appellate Tribunal (TDSAT) within 60 days, extendable for sufficient cause, with further appeal to the Supreme Court (Section 29)."
    },
    {
        "question": "What is the implementation timeline?",
        "answer": "DPDPA has staggered implementation: (1) August 11, 2023 - Act enacted (received Presidential assent); provisions commence in stages by notification; (2) November 13, 2025 - DPDP Rules, 2025 notified; (3) November 13, 2026 - Consent Manager registration with the Board begins; (4) May 13, 2027 - substantive obligations mandatory (notice, consent, fiduciary obligations, rights). Prepare from now for the May 2027 deadline."
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
        "answer": "For children (under 18), tracking, behavioural monitoring and targeted advertising are prohibited outright (Section 9(3)). For adults, such processing needs a valid legal basis - in practice, consent under Section 6 that is specific to the profiling purpose and covered in the Section 5 notice. Under the DPDP Rules, 2025, Significant Data Fiduciaries must also verify that algorithmic software they deploy does not pose a risk to the rights of Data Principals."
    }
]


# 6. PENALTY_MATRIX - Detailed penalty information
PENALTY_MATRIX = {
    "Unauthorized Processing": {
        "description": "Processing personal data without valid legal basis (consent or certain legitimate use)",
        "max_penalty": "50 crore INR",
        "section": "Sections 4-7; Schedule (residual)",
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
        "section": "Section 6; Schedule (residual)",
        "examples": [
            "Bundled consent with service terms",
            "Opt-out instead of opt-in consent",
            "Coerced or conditional consent",
            "No proof of consent maintained",
            "Consent not specific for each purpose"
        ]
    },
    "Data Principal Rights Denial": {
        "description": "Denying access, correction/erasure, grievance redressal, or nomination rights",
        "max_penalty": "50 crore INR",
        "section": "Sections 11-14; Schedule (residual)",
        "examples": [
            "Refusing access request without justification (Section 11)",
            "Denying correction of inaccurate data (Section 12)",
            "Refusing erasure request without a legal basis to retain (Section 12)",
            "Not responding to grievance within the prescribed/published period (Section 13)",
            "Not providing a nomination facility (Section 14)"
        ]
    },
    "Breach Notification Failure": {
        "description": "Failure to intimate the Board (immediately, with a detailed 72-hour report) or affected Data Principals of a personal data breach",
        "max_penalty": "200 crore INR",
        "section": "Section 8(6); Rule 7, DPDP Rules 2025",
        "examples": [
            "No notification to Board within 72 hours",
            "No notification to affected principals",
            "Inadequate breach details provided",
            "Delayed notification beyond 72 hours"
        ]
    },
    "Security Safeguards Failure": {
        "description": "Failure to take reasonable security safeguards to prevent personal data breach",
        "max_penalty": "250 crore INR",
        "section": "Section 8(5); Schedule",
        "examples": [
            "No encryption of stored personal data",
            "Weak access controls and authentication",
            "No security testing/vulnerability management",
            "Inadequate incident response",
            "Unencrypted data transmission"
        ]
    },
    "SDF Obligations Failure": {
        "description": "SDFs failing to appoint a DPO based in India, appoint an independent data auditor, or undertake periodic DPIAs and audits",
        "max_penalty": "150 crore INR",
        "section": "Section 10; Schedule",
        "examples": [
            "No Data Protection Officer appointed",
            "Missing periodic DPIA",
            "No independent data auditor appointed / no periodic audit",
            "Failure to verify algorithmic software does not pose risk to Data Principal rights",
            "Other prescribed SDF measures not undertaken"
        ]
    },
    "Children's Data Violations": {
        "description": "Processing children's data without verifiable parental/guardian consent or violating Section 9 protections",
        "max_penalty": "200 crore INR",
        "section": "Section 9; Schedule",
        "examples": [
            "Processing without parental/guardian consent",
            "Behavioral tracking of children",
            "Targeted advertising to children",
            "Processing likely to cause detriment to child",
            "No age verification mechanism"
        ]
    },
    "Processor/Vendor Non-compliance": {
        "description": "Engaging a Data Processor without a valid contract or failing to ensure compliance",
        "max_penalty": "50 crore INR",
        "section": "Section 8(2); Schedule (residual)",
        "examples": [
            "No processing contract with vendor",
            "Processor processes beyond fiduciary instructions",
            "No processor security audit",
            "Unapproved sub-processor use",
            "Fiduciary fails to supervise processor"
        ]
    },
    "Consent Manager Violations": {
        "description": "Operating as Consent Manager without Board registration or violating obligations",
        "max_penalty": "50 crore INR",
        "section": "Section 6(7)-(9); Schedule (residual)",
        "examples": [
            "Operating without Board registration",
            "Processing personal data itself",
            "Inadequate security for consent records",
            "Failing to facilitate consent withdrawal",
            "Not maintaining separate consent records"
        ]
    },
    "Board Order Non-compliance": {
        "description": "Failure to comply with directions, orders, or remedial measures of the Data Protection Board of India",
        "max_penalty": "50 crore INR",
        "section": "Section 27; Schedule (residual)",
        "examples": [
            "Not implementing Board-directed remedial or mitigation measures",
            "Missing Board-imposed deadlines",
            "Not providing information to the Board when required",
            "Continuing breach despite Board direction",
            "Not cooperating with a Board inquiry"
        ]
    },
    "Data Principal Duties Breach": {
        "description": "Breach by a Data Principal of the duties under Section 15 (e.g., impersonation, suppression of material information, false or frivolous complaints)",
        "max_penalty": "10,000 INR",
        "section": "Section 15; Schedule",
        "examples": [
            "Impersonating another person while providing personal data",
            "Suppressing material information when providing data to the State",
            "Registering a false or frivolous grievance or complaint",
            "Furnishing unverifiable information for correction or erasure"
        ]
    },
    "Breach of Voluntary Undertaking": {
        "description": "Breach of a voluntary undertaking accepted by the Board under Section 31",
        "max_penalty": "Up to the penalty applicable to the underlying breach",
        "section": "Sections 31-32; Schedule",
        "examples": [
            "Failing to perform actions committed to in an accepted voluntary undertaking",
            "Resuming the conduct the undertaking was meant to remedy"
        ]
    }
}


# 7. TIMELINE - Key implementation dates
TIMELINE = [
    {
        "date": "August 11, 2023",
        "event": "DPDPA 2023 Enacted",
        "description": "Digital Personal Data Protection Act 2023 received Presidential assent. Its provisions come into force in stages, on dates notified by the Central Government (Section 1).",
        "who_affected": "All organizations"
    },
    {
        "date": "November 13, 2025",
        "event": "DPDP Rules 2025 Notification",
        "description": "Digital Personal Data Protection Rules 2025 officially notified by MeitY. Provides operational framework and detailed compliance procedures.",
        "who_affected": "All Data Fiduciaries and Consent Managers"
    },
    {
        "date": "November 13, 2026",
        "event": "Consent Manager Registration Opens",
        "description": "Consent Manager registration with the Data Protection Board of India becomes operational. Registration effective one year from rules notification.",
        "who_affected": "Consent Manager entities"
    },
    {
        "date": "May 13, 2027",
        "event": "Full DPDPA Compliance Mandatory",
        "description": "Core provisions of DPDPA become fully effective after 18-month transition period. All compliance obligations mandatory: consent requirement, fiduciary obligations, Board enforcement powers. No grace period - full penalties applicable from Day 1.",
        "who_affected": "All Data Fiduciaries and Data Principals"
    },
    {
        "date": "Ongoing",
        "event": "Data Protection Board of India Operations",
        "description": "The Data Protection Board of India operates as a digital office. Data Principals can complain to the Board after exhausting the fiduciary's grievance redressal (Section 13). The Board conducts inquiries and imposes penalties; appeals lie to the TDSAT within 60 days (Section 29).",
        "who_affected": "All Data Principals and Data Fiduciaries"
    }
]


# 8. SECTOR_GUIDANCE - Industry-specific compliance notes
SECTOR_GUIDANCE = {
    "FinTech and Banking": {
        "special_considerations": [
            "Processing financial data (account numbers, transaction history) - highly sensitive",
            "May be notified as a Significant Data Fiduciary by the Central Government (Section 10 factors include volume and sensitivity of data)",
            "Regulatory compliance (KYC, AML) may qualify as a legitimate use (Section 7(d) - legal obligation)",
            "If notified as an SDF, verify that algorithmic software does not pose a risk to Data Principal rights (DPDP Rules, 2025)",
            "Cross-border money transfer: permitted unless the destination country is restricted by Central Government notification (Section 16); RBI payment data localisation continues to apply (Section 16(2))",
            "Fraudulent transaction detection uses behavioral analysis - consent or a legitimate use basis required",
            "Loan default assessment benefits from a Section 17 exemption; other credit processing needs a valid legal basis"
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
            "Fintech obtaining specific consent for behavioral tracking in lending algorithm",
            "Investment platform needing DPO and DPIA if notified as an SDF (Section 10)",
            "Payment processor with vendor agreements ensuring processor compliance"
        ]
    },
    "Healthcare": {
        "special_considerations": [
            "Processing medical/health data - sensitivity of data is a factor for SDF notification (Section 10)",
            "May be notified as a Significant Data Fiduciary given the sensitivity of health data (Section 10)",
            "Medical emergencies (threat to life or health) are a legitimate use permitting processing without consent (Section 7(f)); epidemic/public health measures under Section 7(g)",
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
            "Healthcare provider appointing DPO after being notified as an SDF (Section 10)",
            "Medical records transfer to specialists requiring specific new consent",
            "AI diagnosis tool requiring DPIA examining accuracy and bias"
        ]
    },
    "E-commerce": {
        "special_considerations": [
            "Extensive customer data collection (name, address, payment, browsing, preferences)",
            "May be notified as a Significant Data Fiduciary given data volume (a Section 10 factor)",
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
            "Shopping app appointing DPO after being notified as an SDF (Section 10)",
            "Vendor management ensuring third-party sellers comply with DPDPA",
            "Payment processor agreement ensuring PCI compliance and data security"
        ]
    },
    "IT Services and Software": {
        "special_considerations": [
            "SaaS platforms processing customer data - may be notified as a Significant Data Fiduciary (Section 10)",
            "Cloud infrastructure providers as data processors - vendor agreements critical",
            "Logging and monitoring systems collecting personal data - purpose limitation needed",
            "Bug fixes and product improvement using customer data - require consent",
            "Analytics tools tracking user behavior - specific consent required (Section 6)",
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
            "Educational institution may be notified as an SDF given student data volume and sensitivity (Section 10 factors)"
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
            "Educational institution appointing DPO after being notified as an SDF (Section 10)",
            "University retaining alumni contact data with clear retention period and deletion policy",
            "School implementing age-appropriate privacy notices for student data"
        ]
    },
    "Government and Public Sector": {
        "special_considerations": [
            "State instrumentalities may be exempted from certain provisions only by Central Government notification (Section 17)",
            "Citizen data (taxes, licenses, subsidies, services, certificates, permits) - legitimate use basis under Section 7(b)-(c)",
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
    "version": "1.1",
    "last_updated": "July 3, 2026",
    "coverage": "DPDPA 2023 (Sections 1-44 and the Schedule) and DPDP Rules 2025",
    "total_sections": len(DPDPA_SECTIONS),
    "total_rules": len(DPDP_RULES),
    "total_definitions": len(KEY_DEFINITIONS),
    "total_checklist_items": sum(len(items) for items in COMPLIANCE_CHECKLIST.values()),
    "total_faqs": len(FAQ),
    "total_penalty_types": len(PENALTY_MATRIX),
    "timeline_events": len(TIMELINE),
    "sectors_covered": len(SECTOR_GUIDANCE)
}
