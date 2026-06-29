# Svikruti Fix Pack

Copy these into GitHub/Jira/Linear. Generated from scanner evidence; review before assigning.

## 1. [P0] Update privacy notice for Children

**Severity:** CRITICAL
**Control Area:** Notice transparency
**Owner:** Legal / Privacy
**Status:** Open
**Due:** Before launch / next release
**Artifact:** Privacy notice change

### Why
Svikruti detected Children data in engineering evidence, but not in the notice text.

### Evidence
rails_students.rb; react_signup.tsx

### Acceptance Criteria
- [ ] Privacy notice explicitly covers Children data or documents why it is out of scope.
- [ ] Purpose, retention, rights path, and withdrawal/complaint path are reviewed.
- [ ] Svikruti scan is rerun and attached to the ticket.

## 2. [P0] Reduce Children logging exposure

**Severity:** CRITICAL
**Control Area:** Security safeguards
**Owner:** Engineering / Security
**Status:** Open
**Due:** Before launch / next release
**Artifact:** Logging redaction control

### Why
Personal data appears near logging statements.

### Evidence
rails_students.rb

### Acceptance Criteria
- [ ] Personal data is masked, hashed, removed, or justified in logs.
- [ ] Log retention is documented.
- [ ] Regression test or code review evidence is attached.

## 3. [P1] Reduce Contact logging exposure

**Severity:** HIGH
**Control Area:** Security safeguards
**Owner:** Engineering / Security
**Status:** Open
**Due:** Before launch / next release
**Artifact:** Logging redaction control

### Why
Personal data appears near logging statements.

### Evidence
express_checkout.js; rails_students.rb

### Acceptance Criteria
- [ ] Personal data is masked, hashed, removed, or justified in logs.
- [ ] Log retention is documented.
- [ ] Regression test or code review evidence is attached.

## 4. [P1] Update privacy notice for Device

**Severity:** HIGH
**Control Area:** Notice transparency
**Owner:** Legal / Privacy
**Status:** Open
**Due:** Before launch / next release
**Artifact:** Privacy notice change

### Why
Svikruti detected Device data in engineering evidence, but not in the notice text.

### Evidence
customer_schema.sql; react_signup.tsx

### Acceptance Criteria
- [ ] Privacy notice explicitly covers Device data or documents why it is out of scope.
- [ ] Purpose, retention, rights path, and withdrawal/complaint path are reviewed.
- [ ] Svikruti scan is rerun and attached to the ticket.

## 5. [P1] Update privacy notice for Financial

**Severity:** HIGH
**Control Area:** Notice transparency
**Owner:** Legal / Privacy
**Status:** Open
**Due:** Before launch / next release
**Artifact:** Privacy notice change

### Why
Svikruti detected Financial data in engineering evidence, but not in the notice text.

### Evidence
express_checkout.js; laravel_checkout.php; schema.prisma

### Acceptance Criteria
- [ ] Privacy notice explicitly covers Financial data or documents why it is out of scope.
- [ ] Purpose, retention, rights path, and withdrawal/complaint path are reviewed.
- [ ] Svikruti scan is rerun and attached to the ticket.

## 6. [P1] Reduce Financial logging exposure

**Severity:** HIGH
**Control Area:** Security safeguards
**Owner:** Engineering / Security
**Status:** Open
**Due:** Before launch / next release
**Artifact:** Logging redaction control

### Why
Personal data appears near logging statements.

### Evidence
laravel_checkout.php

### Acceptance Criteria
- [ ] Personal data is masked, hashed, removed, or justified in logs.
- [ ] Log retention is documented.
- [ ] Regression test or code review evidence is attached.

## 7. [P0] Update privacy notice for Government ID

**Severity:** CRITICAL
**Control Area:** Notice transparency
**Owner:** Legal / Privacy
**Status:** Open
**Due:** Before launch / next release
**Artifact:** Privacy notice change

### Why
Svikruti detected Government ID data in engineering evidence, but not in the notice text.

### Evidence
SpringCustomerController.java; customer_schema.sql; express_checkout.js; openapi.json; schema.prisma

### Acceptance Criteria
- [ ] Privacy notice explicitly covers Government ID data or documents why it is out of scope.
- [ ] Purpose, retention, rights path, and withdrawal/complaint path are reviewed.
- [ ] Svikruti scan is rerun and attached to the ticket.

## 8. [P0] Reduce Government ID logging exposure

**Severity:** CRITICAL
**Control Area:** Security safeguards
**Owner:** Engineering / Security
**Status:** Open
**Due:** Before launch / next release
**Artifact:** Logging redaction control

### Why
Personal data appears near logging statements.

### Evidence
SpringCustomerController.java; express_checkout.js

### Acceptance Criteria
- [ ] Personal data is masked, hashed, removed, or justified in logs.
- [ ] Log retention is documented.
- [ ] Regression test or code review evidence is attached.

## 9. [P0] Update privacy notice for Health

**Severity:** CRITICAL
**Control Area:** Notice transparency
**Owner:** Legal / Privacy
**Status:** Open
**Due:** Before launch / next release
**Artifact:** Privacy notice change

### Why
Svikruti detected Health data in engineering evidence, but not in the notice text.

### Evidence
django_patient.py; go_patient.go

### Acceptance Criteria
- [ ] Privacy notice explicitly covers Health data or documents why it is out of scope.
- [ ] Purpose, retention, rights path, and withdrawal/complaint path are reviewed.
- [ ] Svikruti scan is rerun and attached to the ticket.

## 10. [P0] Reduce Health logging exposure

**Severity:** CRITICAL
**Control Area:** Security safeguards
**Owner:** Engineering / Security
**Status:** Open
**Due:** Before launch / next release
**Artifact:** Logging redaction control

### Why
Personal data appears near logging statements.

### Evidence
go_patient.go

### Acceptance Criteria
- [ ] Personal data is masked, hashed, removed, or justified in logs.
- [ ] Log retention is documented.
- [ ] Regression test or code review evidence is attached.

## 11. [P1] Update privacy notice for Location

**Severity:** HIGH
**Control Area:** Notice transparency
**Owner:** Legal / Privacy
**Status:** Open
**Due:** Before launch / next release
**Artifact:** Privacy notice change

### Why
Svikruti detected Location data in engineering evidence, but not in the notice text.

### Evidence
SpringCustomerController.java; customer_schema.sql; express_checkout.js; go_patient.go; laravel_checkout.php; react_signup.tsx

### Acceptance Criteria
- [ ] Privacy notice explicitly covers Location data or documents why it is out of scope.
- [ ] Purpose, retention, rights path, and withdrawal/complaint path are reviewed.
- [ ] Svikruti scan is rerun and attached to the ticket.

## 12. [P1] Reduce Location logging exposure

**Severity:** HIGH
**Control Area:** Security safeguards
**Owner:** Engineering / Security
**Status:** Open
**Due:** Before launch / next release
**Artifact:** Logging redaction control

### Why
Personal data appears near logging statements.

### Evidence
express_checkout.js

### Acceptance Criteria
- [ ] Personal data is masked, hashed, removed, or justified in logs.
- [ ] Log retention is documented.
- [ ] Regression test or code review evidence is attached.

## 13. [P1] Add withdrawal language to privacy notice

**Severity:** HIGH
**Control Area:** Notice transparency
**Owner:** Legal / Privacy
**Status:** Open
**Due:** Before launch / next release
**Artifact:** Privacy notice change

### Why
The notice does not clearly include DPDPA-relevant withdrawal terms.

### Evidence
privacy notice text

### Acceptance Criteria
- [ ] Notice includes reviewed withdrawal language.
- [ ] Language is understandable and reachable from product/privacy paths.

## 14. [P1] Add rights language to privacy notice

**Severity:** HIGH
**Control Area:** Notice transparency
**Owner:** Legal / Privacy
**Status:** Open
**Due:** Before launch / next release
**Artifact:** Privacy notice change

### Why
The notice does not clearly include DPDPA-relevant rights terms.

### Evidence
privacy notice text

### Acceptance Criteria
- [ ] Notice includes reviewed rights language.
- [ ] Language is understandable and reachable from product/privacy paths.

## 15. [P1] Add children language to privacy notice

**Severity:** HIGH
**Control Area:** Notice transparency
**Owner:** Legal / Privacy
**Status:** Open
**Due:** Before launch / next release
**Artifact:** Privacy notice change

### Why
The notice does not clearly include DPDPA-relevant children terms.

### Evidence
privacy notice text

### Acceptance Criteria
- [ ] Notice includes reviewed children language.
- [ ] Language is understandable and reachable from product/privacy paths.

## 16. [P1] Add retention language to privacy notice

**Severity:** HIGH
**Control Area:** Notice transparency
**Owner:** Legal / Privacy
**Status:** Open
**Due:** Before launch / next release
**Artifact:** Privacy notice change

### Why
The notice does not clearly include DPDPA-relevant retention terms.

### Evidence
privacy notice text

### Acceptance Criteria
- [ ] Notice includes reviewed retention language.
- [ ] Language is understandable and reachable from product/privacy paths.

## 17. [P1] Add third parties language to privacy notice

**Severity:** HIGH
**Control Area:** Notice transparency
**Owner:** Legal / Privacy
**Status:** Open
**Due:** Before launch / next release
**Artifact:** Privacy notice change

### Why
The notice does not clearly include DPDPA-relevant third parties terms.

### Evidence
privacy notice text

### Acceptance Criteria
- [ ] Notice includes reviewed third parties language.
- [ ] Language is understandable and reachable from product/privacy paths.

## 18. [P1] Disclose processor/vendor categories

**Severity:** HIGH
**Control Area:** Vendor governance
**Owner:** Legal / Procurement
**Status:** Open
**Due:** Before launch / next release
**Artifact:** Vendor register + notice update

### Why
Third-party services were detected but processor/vendor disclosure language is missing or weak.

### Evidence
Razorpay

### Acceptance Criteria
- [ ] Vendor register includes detected processors/tools.
- [ ] DPA/contract status and transfer location are confirmed.
- [ ] Privacy notice discloses recipient/vendor categories where applicable.
