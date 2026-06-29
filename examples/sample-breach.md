# Svikruti Breach Readiness Pack

Generated from repository, privacy, and imported security evidence. Review before treating this as production assurance.

Posture: not_ready
Score: 52/100

## Domains

| Domain | Status | Score | Evidence |
| --- | --- | ---: | --- |
| Vulnerability Management | needs_action | 25 | security_pipeline.yml:technical.security_tooling.code_ql; security_pipeline.yml:technical.security_tooling.gitleaks; security_pipeline.yml:technical.security_tooling.semgrep; security_pipeline.yml:technical.security_tooling.trivy; semgrep.sarif:sarif:0:0; trivy.json:trivy:CVE-2026-0001 |
| Security Monitoring | evidence_present | 80 | platform_controls.tf:technical.security_monitoring.cloud_watch; security_pipeline.yml:technical.security_monitoring.pager_duty |
| Endpoint Or Workload Detection | evidence_present | 80 | platform_controls.tf:technical.endpoint_security.guard_duty |
| Incident Response | evidence_present | 80 | platform_controls.tf:technical.incident_readiness.runbook_escalation; security_pipeline.yml:technical.incident_readiness.runbook_escalation |
| Secrets And Crypto | needs_action | 25 | gitleaks.json:gitleaks:0; insecure_controls.js:3:technical.weak_crypto.md5_hashing; insecure_controls.js:5:technical.secret_exposure.hard_coded_token; platform_controls.tf:technical.encryption_evidence.kms_managed_keys; platform_controls.tf:technical.encryption_evidence.storage_encryption; risky_cloud.tf:technical.encryption_evidence.storage_encryption |
| Backup And Recovery | evidence_present | 80 | platform_controls.tf:technical.resilience_evidence.backup_restore_retention |
| Cloud And Iac Guardrails | needs_action | 25 | risky_cloud.tf:3:technical.cloud_misconfiguration.public_database_exposure; risky_cloud.tf:4:technical.cloud_misconfiguration.storage_encryption_disabled; risky_cloud.tf:9:technical.cloud_misconfiguration.public_storage_acl |
| Personal Data Mapping | needs_action | 25 | SpringCustomerController.java:15:semantic.java.request_source.government_id; SpringCustomerController.java:16:code.logging_risk.government_id; SpringCustomerController.java:16:semantic.java.log_sink.government_id; SpringCustomerController.java:16:semantic.treesitter.java.log_sink.government_id; SpringCustomerController.java:5:code.personal_data_reference.identity; SpringCustomerController.java:5:semantic.java.field.identity; SpringCustomerController.java:5:semantic.treesitter.java.storage_field.identity; SpringCustomerController.java:6:code.personal_data_reference.contact; SpringCustomerController.java:6:code.personal_data_reference.location; SpringCustomerController.java:6:semantic.java.field.location; SpringCustomerController.java:6:semantic.treesitter.java.storage_field.location; SpringCustomerController.java:7:code.personal_data_reference.government_id; SpringCustomerController.java:7:semantic.java.field.government_id; SpringCustomerController.java:7:semantic.treesitter.java.storage_field.government_id; customer_schema.sql:10:code.personal_data_reference.device; customer_schema.sql:10:semantic.sql.schema_field.device; customer_schema.sql:3:code.personal_data_reference.identity; customer_schema.sql:3:semantic.sql.schema_field.identity; customer_schema.sql:4:code.personal_data_reference.contact; customer_schema.sql:4:code.personal_data_reference.location |

## Priority Actions

- [ ] Fix failed security controls before relying on this breach-readiness pack.
- [ ] Fix cloud/IaC guardrail failures before relying on this breach-readiness pack.

## Control Exceptions

Failed controls: DPDPA-TECH-001; DPDPA-TECH-002; DPDPA-TECH-003; DPDPA-TECH-004; DPDPA-TECH-008
Missing controls: None
