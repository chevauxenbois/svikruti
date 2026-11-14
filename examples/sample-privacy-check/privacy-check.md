# Svikruti privacy check

❌ **Blocked**: 3 finding(s) at HIGH or above.

Manifest `privacy.yaml` reconciled against 7 file(s) with personal-data evidence: 3 activit(ies), 2 processor(s), **3 open finding(s)** (0 under exception).

## Frameworks

| Framework | Verified | Attested | Failing | Not verified | N/A | Verified share |
|---|---|---|---|---|---|---|
| DPDPA | 14 | 4 | 5 | 0 | 1 | 61% of 23 |
| GDPR | 14 | 4 | 5 | 0 | 1 | 61% of 23 |
| ISO 27701 | 14 | 4 | 5 | 0 | 1 | 61% of 23 |

## Drift and policy findings

| Severity | Rule | What drifted | Where | Fix |
|---|---|---|---|---|
| HIGH | D002 | Activity 'repayments' processes Location data in code, but the record does not declare it. | `services/payments/refund.js:7`, `services/payments/refund.js:10` | Declare the category on the activity (and update the notice and legal basis), or remove the data from the code. |
| HIGH | D003 | Activity 'repayments' sends data to Mixpanel, which is not a declared processor. | `services/payments/refund.js` | Add the processor with country and contract reference, link it to the activity, or remove the integration. |
| HIGH | P001 | Contact data is written to logs in activity 'repayments' (1 location(s)). | `services/payments/refund.js:8` | Remove or mask the field before logging, or record a time-boxed exception with a reason. |

## Processing record, reconciled with code

| Activity | Declared data | Detected in code | Processors | Lawful basis | Retention | In sync |
|---|---|---|---|---|---|---|
| Loan applicant onboarding and KYC | Identity, Contact, Government ID | Contact, Government ID, Identity |  | dpdpa: consent, gdpr: legal_obligation | 8 years after loan closure (PML Rules), then erased | yes |
| EMI repayment collection | Contact, Financial | Contact, Financial, Location | Razorpay | dpdpa: legitimate_use, gdpr: contract | 8 years after loan closure (tax and PML records) | **no** |
| Repayment reminders | Contact | Contact | MSG91 | dpdpa: consent, gdpr: legitimate_interests | Message logs kept 90 days | yes |

## Obligation crosswalk

| | Obligation | DPDPA | GDPR | ISO 27701 | Result |
|---|---|---|---|---|---|
| ❌ | **OBL-01** The processing record matches the code | Sec. 8(1), Sec. 10(2)(c) | Art. 30(1), Art. 5(2) | A.1.2.9 | Failing: 2 open finding(s): Undeclared personal data category; Undeclared processor / third party |
| ✅ | **OBL-02** Every activity has a specified purpose | Sec. 4(1), Sec. 5(1)(i) | Art. 5(1)(b), Art. 30(1)(b) | A.1.2.2 | Verified: Every activity states its purposes. |
| ✅ | **OBL-03** Every activity has a lawful basis | Sec. 4(1), Sec. 6, Sec. 7 | Art. 6(1), Art. 9(2) | A.1.2.3 | Verified: Every activity records a lawful basis valid under the selected frameworks. |
| ✅ | **OBL-04** Retention is defined | Sec. 8(7), Rule 8 | Art. 5(1)(e), Art. 30(1)(f) | A.1.4.8, A.1.4.6 | Verified: Every activity defines retention. |
| ❌ | **OBL-05** Only declared data is collected | Sec. 6(1) | Art. 5(1)(c), Art. 25(2) | A.1.4.2, A.1.4.5 | Failing: 1 open finding(s): Undeclared personal data category |
| ❌ | **OBL-06** No personal data in logs | Sec. 8(5), Rule 6 | Art. 5(1)(c), Art. 5(1)(f), Art. 32(1) | A.1.4.3, A.1.4.5, A.3.25 | Failing: 1 open finding(s): Personal data written to logs |
| ❌ | **OBL-07** The privacy notice matches actual processing | Sec. 5, Rule 3 | Art. 13, Art. 14, Art. 5(1)(a) | A.1.3.3, A.1.3.4 | Failing: The notice omits 1 item(s) the code processes. |
| ❌ | **OBL-08** Processors are identified and under contract | Sec. 8(2), Rule 6 | Art. 28(1), Art. 28(3), Art. 30(1)(d) | A.1.2.7, A.1.5.5, A.3.10 | Failing: 1 open finding(s): Undeclared processor / third party |
| ✅ | **OBL-09** Cross-border transfers are documented | Sec. 16, Rule 15 | Art. 44, Art. 46, Art. 30(1)(e) | A.1.5.2, A.1.5.3, A.1.5.4 | Verified: Every processor has a recorded country and, where required, a transfer mechanism. |
| ✅ | **OBL-10** High-risk processing has an impact assessment | Sec. 10(2)(c)(i), Rule 13 | Art. 35(1), Art. 35(3)(b) | A.1.2.6 | Verified: Every activity handling high-risk data references an impact assessment. |
| ➖ | **OBL-11** Children's data has verifiable safeguards | Sec. 9, Rule 10 | Art. 8 | A.1.2.4, A.1.2.6 | Not applicable: No children's data is declared or detected. |
| ✅ | **OBL-12** Encryption in transit | Sec. 8(5), Rule 6 | Art. 32(1)(a), Art. 5(1)(f) | A.1.4.10, A.3.26 | Verified: 2 piece(s) of repository evidence. |
| ✅ | **OBL-13** Encryption at rest and key management | Sec. 8(5), Rule 6 | Art. 32(1)(a) | A.3.26 | Verified: 5 piece(s) of repository evidence. |
| ✅ | **OBL-14** Secrets and credential hygiene | Sec. 8(5), Rule 6 | Art. 32(1)(b) | A.3.23, A.3.27 | Verified: 1 piece(s) of repository evidence. |
| ✅ | **OBL-15** Vulnerability management | Sec. 8(4), Sec. 8(5) | Art. 32(1)(d) | A.3.27, A.3.28 | Verified: 3 piece(s) of repository evidence. |
| ✅ | **OBL-16** Security monitoring and logging | Sec. 8(5), Rule 6 | Art. 32(1)(b), Art. 33(1) | A.3.25, A.3.11 | Verified: 2 piece(s) of repository evidence. |
| ✅ | **OBL-17** Breach response readiness | Sec. 8(6), Rule 7 | Art. 33, Art. 34 | A.3.11, A.3.12 | Verified: 1 piece(s) of repository evidence. |
| ✅ | **OBL-18** Backup and recovery | Rule 6 | Art. 32(1)(c) | A.3.24 | Verified: 1 piece(s) of repository evidence. |
| ✅ | **OBL-19** Infrastructure guardrails | Sec. 8(4), Sec. 8(5) | Art. 25(1), Art. 32(1)(b) | A.3.29 | Verified: 1 piece(s) of repository evidence. |
| 📝 | **OBL-20** Tracking waits for consent | Sec. 6(1), Sec. 9(3) | Art. 6(1)(a), Art. 7, Directive 2002/58/EC Art. 5(3) | A.1.2.4, A.1.2.5 | Attested: Attested by web-platform on 2026-10-20: The marketing site loads no non-essential trackers; verified with a browser consent scan each release. |
| 📝 | **OBL-21** Individuals' rights requests are handled | Secs. 11-14, Rule 14 | Art. 12(3), Arts. 15-22 | A.1.3.2, A.1.3.7, A.1.3.10 | Attested: Attested by privacy-office on 2026-10-01: Access, correction and erasure requests are handled by the support desk within 30 days. |
| 📝 | **OBL-22** Consent is recorded and withdrawable | Sec. 6(4), Sec. 6(10) | Art. 7(1), Art. 7(3) | A.1.2.5, A.1.3.5 | Attested: Attested by lending-platform on 2026-10-01: Consent is stored as an append-only ledger with timestamp and notice version; withdrawal is one tap in the app. |
| ✅ | **OBL-23** A privacy contact is published | Sec. 8(9), Sec. 8(10), Rule 9 | Art. 13(1)(a)-(b), Arts. 37-39 | A.1.3.4, A.3.4 | Verified: Privacy contact recorded: privacy@lendflow.example. |
| 📝 | **OBL-24** Breach notification procedure exists | Sec. 8(6), Rule 7 | Art. 33(1), Art. 33(5) | A.3.12 | Attested: Attested by security on 2026-09-15: Breach notification procedure tested in the September tabletop exercise. |

---

_Engineering evidence, not legal advice or a certification. A passing check supports a clause; it does not establish compliance with it._
_Static analysis sees the repository, not production. Attested and manual items need review by a privacy professional._
