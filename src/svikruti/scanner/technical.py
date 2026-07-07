"""Technical-control evidence for privacy engineering readiness."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set

from svikruti.models import Evidence
from svikruti.scanner.code import _file_context, _language_for, iter_source_files
from svikruti.scanner.patterns import normalize_text


SECURITY_TOOL_PATTERNS = {
    "CodeQL": ["codeql-action", "github/codeql", "codeql-analysis"],
    "Dependabot": ["dependabot.yml", "dependabot.yaml", "dependabot"],
    "Renovate": ["renovate.json", "renovatebot", "renovate/"],
    "Semgrep": ["semgrep", ".semgrep"],
    "Trivy": ["trivy", "aquasecurity/trivy"],
    "Gitleaks": ["gitleaks"],
    "OSV Scanner": ["osv-scanner", "osv.dev"],
    "pip-audit": ["pip-audit"],
    "npm audit": ["npm audit"],
    "Snyk": ["snyk"],
    "OWASP Dependency-Check": ["dependency-check", "owasp/dependency-check"],
}

MONITORING_PATTERNS = {
    "OpenTelemetry": ["opentelemetry", "otelcol", "otel_"],
    "CloudWatch": ["cloudwatch", "awslogs"],
    "Datadog": ["datadog", "dd_api_key", "dd_service"],
    "Sentry": ["sentry.io", "sentry_sdk", "@sentry/"],
    "Splunk": ["splunk"],
    "Elastic": ["elastic apm", "elasticapm", "filebeat", "metricbeat"],
    "Prometheus": ["prometheus", "prometheus.io/scrape"],
    "Grafana": ["grafana"],
    "PagerDuty": ["pagerduty"],
    "Opsgenie": ["opsgenie"],
    "Slack alerting": ["slack_webhook", "slack.com/api/chat.postmessage", "hooks.slack.com"],
}

ENDPOINT_SECURITY_PATTERNS = {
    "Microsoft Defender": ["microsoft defender", "defender for endpoint", "mdatp"],
    "CrowdStrike": ["crowdstrike", "falcon sensor"],
    "SentinelOne": ["sentinelone"],
    "Jamf": ["jamf"],
    "osquery": ["osquery"],
    "Wazuh": ["wazuh"],
    "Falco": ["falco"],
    "GuardDuty": ["guardduty"],
    "Security Hub": ["securityhub", "security hub"],
}

STRONG_CRYPTO_PATTERNS = {
    "TLS enforced": ["https://", "sslmode=require", "tls_min_version", "minimum_tls_version"],
    "KMS / managed keys": ["aws_kms_key", "kms_key_id", "google_kms_crypto_key", "azurerm_key_vault_key", "secretsmanager"],
    "Secret manager": ["aws_secretsmanager", "secretmanager", "key vault", "vault kv", "hashicorp vault"],
    "Password hashing": ["bcrypt", "argon2", "scrypt", "pbkdf2"],
    "Modern encryption": ["aesgcm", "aes-gcm", "fernet", "nacl.secretbox"],
    "Storage encryption": ["encrypted = true", "storage_encrypted", "server_side_encryption", "sse_algorithm", "bucket_key_enabled"],
}

WEAK_CRYPTO_REGEXES = {
    "MD5 hashing": re.compile(r"\b(md5|createHash\([\"']md5[\"']|hashlib\.md5)\b", re.IGNORECASE),
    # SHA1 only in an actual crypto/hash call context (sha1(, getInstance("SHA-1"),
    # hashlib.sha1, createHash('sha1')), never as a bare word (git SHAs, docs).
    "SHA1 hashing": re.compile(
        r"(?i)(hashlib\.sha1|createHash\(\s*[\"']sha-?1[\"']|getInstance\(\s*[\"']sha-?1[\"']|\bsha-?1\s*\()"
    ),
    "DES / RC4": re.compile(r"(?i)\b(3des|des|rc4)\b"),
    "ECB mode": re.compile(r"(?i)(MODE_ECB|AES/ECB|/ECB[/\"'\s)]|\becb\b)"),
    # Fixed dead regex: the old trailing \b after ')' could never match.
    # Now both the JS (Math.random() and Python (random.random()) branches fire.
    "Non-crypto randomness": re.compile(r"(?i)(Math\.random\s*\(|(?<![\w.])random\.random\s*\()"),
}

# Math.random()/random.random() is only a security problem when the value
# feeds tokens/secrets/session IDs - most uses (jitter, sampling, UI) are
# fine. It is therefore reported at MEDIUM ("verify usage"), not HIGH.
WEAK_CRYPTO_SEVERITY_OVERRIDES = {"Non-crypto randomness": "MEDIUM"}

# Ambiguous weak-crypto tokens (des, rc4, ecb) also occur as ordinary
# identifiers/prose, so those subtypes additionally require a crypto-context
# term on the SAME line before they count as evidence.
WEAK_CRYPTO_CONTEXT_REGEXES = {
    "DES / RC4": re.compile(r"(?i)(cipher|crypt|encrypt|decrypt|algorithm|getinstance|commoncrypto|openssl)"),
    "ECB mode": re.compile(r"(?i)(cipher|crypt|aes|\bdes\b|\bmode\b|mode_ecb|getinstance|openssl)"),
}

SECRET_REGEXES = {
    "AWS access key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "Private key material": re.compile(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "Hard-coded token": re.compile(
        r"(?i)\b(api[_-]?key|secret|token|password|client_secret)\b\s*[:=]\s*[\"'][^\"'\n]{12,}[\"']"
    ),
}

# Template/environment references are NOT hard-coded secrets:
# ${{ secrets.X }} (GitHub Actions), ${VAR}/$VAR interpolation, {{ var }}
# (Jinja/Helm), process.env / os.environ lookups. Benchmark: frappe/hrms
# labeller.yml `repo-token: "${{ secrets.GITHUB_TOKEN }}"` flagged CRITICAL.
SECRET_TEMPLATE_REFERENCE_RE = re.compile(
    r"(\$\{\{|\$\{|\{\{|\bprocess\.env\b|\bos\.environ\b|\bENV\[|\bgetenv\b|\bsecrets\.)"
)

INSECURE_HTTP_RE = re.compile(r"http://([^\s\"'<>()\[\]]+)", re.IGNORECASE)

# Non-risk http:// destinations: local/loopback, documentation placeholders,
# XML namespaces and schema/license URLs. Matched against the URL remainder.
HTTP_URL_ALLOWLIST = (
    "localhost",
    "127.0.0.1",
    "0.0.0.0",
    "example.com",
    "example.org",
    "schemas.",
    "www.w3.org",
    "w3.org/",
    "apache.org/licenses",
    "opensource.org",
    # License/attribution URLs common in font and asset headers.
    "scripts.sil.org",
    "creativecommons.org",
    "gnu.org/licenses",
)

# Lines that are clearly comments should not raise insecure-transport findings.
COMMENT_LINE_PREFIXES = ("//", "#", "*", "<!--", "/*")

# Keep HIGH severity only when the http:// URL appears in a fetch/request/
# endpoint/config-value context; other mentions are downgraded to MEDIUM.
HTTP_RISK_CONTEXT_RE = re.compile(
    r"(?i)(fetch|axios|request|urlopen|urllib|httpx|http\.get|curl|wget|endpoint|base_?url|api[_-]?url|"
    r"url\s*[:=]|uri\s*[:=]|host\s*[:=]|server\s*[:=]|proxy|webhook)"
)


def _skip_insecure_http(line: str, url_rest: str) -> bool:
    stripped = line.lstrip()
    if stripped.startswith(COMMENT_LINE_PREFIXES):
        return True
    if "xmlns" in line.lower():
        return True
    lowered_url = url_rest.lower()
    return any(token in lowered_url for token in HTTP_URL_ALLOWLIST)


CLOUD_MISCONFIG_REGEXES = {
    "Public storage ACL": re.compile(r"\bacl\s*=\s*[\"']public-(read|write|read-write)[\"']", re.IGNORECASE),
    "Public database exposure": re.compile(r"\bpublicly_accessible\s*=\s*true\b", re.IGNORECASE),
    "Storage encryption disabled": re.compile(r"\b(storage_encrypted|encrypted)\s*=\s*false\b", re.IGNORECASE),
    "Wildcard CORS origin": re.compile(r"(\ballowed_origins\b|\borigins\b|\bAccess-Control-Allow-Origin\b).{0,80}(\*|[\"']\*[\"'])", re.IGNORECASE),
    "Permissive IAM action": re.compile(r"[\"']Action[\"']\s*:\s*[\"']\*[\"']", re.IGNORECASE),
    "Permissive IAM resource": re.compile(r"[\"']Resource[\"']\s*:\s*[\"']\*[\"']", re.IGNORECASE),
}

CLOUD_SAFEGUARD_PATTERNS = {
    "S3 public access block": ["aws_s3_bucket_public_access_block", "block_public_acls", "block_public_policy"],
    "Cloud audit logging": ["cloudtrail", "audit_log_config", "diagnostic_setting", "logging_config"],
    "WAF / edge protection": ["aws_wafv2_web_acl", "cloudarmor", "azurerm_web_application_firewall"],
    "Database deletion protection": ["deletion_protection = true", "prevent_destroy"],
    "Private networking": ["private_subnet", "vpc_config", "private_endpoint", "authorized_networks"],
}

RUNBOOK_TERMS = [
    "incident response",
    "breach",
    "security incident",
    "postmortem",
    "on-call",
    "oncall",
    "pagerduty",
    "opsgenie",
    "sev1",
    "severity 1",
]

BACKUP_TERMS = [
    "backup",
    "restore",
    "point_in_time_recovery",
    "deletion_protection",
    "versioning",
    "retention_in_days",
    "lifecycle_rule",
]

CONTROL_CATALOG = [
    {
        "id": "DPDPA-TECH-001",
        "title": "Encryption in transit",
        "area": "Security safeguards",
        "owner": "Engineering / Security",
        "positive_kinds": {"encryption_evidence"},
        "positive_subtypes": {"TLS enforced"},
        "negative_kinds": {"insecure_transport"},
        "fail_action": "Replace insecure personal-data transport with HTTPS/TLS and document any internal exceptions.",
        "missing_action": "Attach TLS enforcement evidence from code, gateway, infrastructure, or deployment config.",
    },
    {
        "id": "DPDPA-TECH-002",
        "title": "Encryption at rest and key management",
        "area": "Security safeguards",
        "owner": "Cloud / Platform / Security",
        "positive_kinds": {"encryption_evidence"},
        "positive_subtypes": {"KMS / managed keys", "Secret manager", "Storage encryption", "Modern encryption"},
        "negative_kinds": {"weak_crypto", "secret_exposure"},
        "fail_action": "Remove weak crypto/secrets and prove storage encryption or managed-key usage for personal-data stores.",
        "missing_action": "Add KMS, storage encryption, or secret-manager evidence for systems processing personal data.",
    },
    {
        "id": "DPDPA-TECH-003",
        "title": "Secrets and credential hygiene",
        "area": "Security safeguards",
        "owner": "Engineering / Security",
        "positive_kinds": {"encryption_evidence"},
        "positive_subtypes": {"Secret manager"},
        "negative_kinds": {"secret_exposure"},
        "fail_action": "Remove hard-coded secrets, rotate credentials, and move secrets to managed storage.",
        "missing_action": "Attach evidence of secret-manager usage and rotation ownership.",
    },
    {
        "id": "DPDPA-TECH-004",
        "title": "Vulnerability management",
        "area": "Breach readiness",
        "owner": "Security / Engineering",
        "positive_kinds": {"security_tooling", "imported_security_finding"},
        "positive_subtypes": set(SECURITY_TOOL_PATTERNS),
        "negative_kinds": set(),
        "fail_action": "Triage imported critical/high vulnerabilities and block release until accepted or fixed.",
        "missing_action": "Enable dependency, container, secret, and static-analysis scans in CI.",
    },
    {
        "id": "DPDPA-TECH-005",
        "title": "Security monitoring and alerting",
        "area": "Breach readiness",
        "owner": "Security / Platform",
        "positive_kinds": {"security_monitoring", "endpoint_security"},
        "positive_subtypes": set(MONITORING_PATTERNS) | set(ENDPOINT_SECURITY_PATTERNS),
        "negative_kinds": set(),
        "fail_action": "Connect monitoring/alerting evidence to incident response ownership.",
        "missing_action": "Attach SIEM/APM/logging/EDR evidence or a documented monitoring exception.",
    },
    {
        "id": "DPDPA-TECH-006",
        "title": "Incident and breach response readiness",
        "area": "Breach readiness",
        "owner": "Security / Legal / Privacy",
        "positive_kinds": {"incident_readiness"},
        "positive_subtypes": set(),
        "negative_kinds": set(),
        "fail_action": "Create breach-response workflow with owners, timeline, evidence capture, and notification drafts.",
        "missing_action": "Add incident/breach runbook evidence and connect it to personal-data categories.",
    },
    {
        "id": "DPDPA-TECH-007",
        "title": "Backup, retention, and recovery evidence",
        "area": "Resilience",
        "owner": "Platform / Engineering",
        "positive_kinds": {"resilience_evidence"},
        "positive_subtypes": set(),
        "negative_kinds": set(),
        "fail_action": "Document backup, restore, retention, and recovery ownership for personal-data systems.",
        "missing_action": "Attach backup/restore/retention evidence or documented exception.",
    },
    {
        "id": "DPDPA-TECH-008",
        "title": "Cloud and infrastructure guardrails",
        "area": "Security safeguards",
        "owner": "Cloud / Platform / Security",
        "positive_kinds": {"cloud_security_evidence"},
        "positive_subtypes": set(CLOUD_SAFEGUARD_PATTERNS),
        "negative_kinds": {"cloud_misconfiguration"},
        "fail_action": "Fix cloud/IaC exposure such as public storage, public databases, disabled encryption, permissive IAM, or wildcard CORS.",
        "missing_action": "Attach Terraform/Kubernetes/cloud evidence for public-access blocking, audit logs, WAF, private networking, and production guardrails.",
    },
]


def scan_technical_evidence(repo_path: str) -> List[Evidence]:
    root = Path(repo_path).resolve()
    if not root.exists() or not root.is_dir():
        raise ValueError(f"Repository path does not exist or is not a directory: {repo_path}")

    evidence: List[Evidence] = []
    seen: Set[str] = set()

    for path in iter_source_files(root):
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        rel = str(path.relative_to(root))
        file_context = _file_context(rel, text)
        if file_context == "reference":
            continue
        # Test/fixture code: weak-crypto, insecure-HTTP, and cloud-misconfig
        # patterns there are fixtures/assertions, not production posture
        # (benchmark: 19 of 21 wildcard-CORS findings on a real Django app
        # were test assertions). Secret detection still runs on tests -
        # committed real credentials in test configs are a classic leak.
        is_test_context = file_context == "test"
        lowered = text.lower()
        lines = text.splitlines()

        for index, line in enumerate(lines, start=1):
            if not is_test_context:
                _append_regex_evidence(
                    evidence,
                    seen,
                    rel,
                    path,
                    file_context,
                    index,
                    line,
                    WEAK_CRYPTO_REGEXES,
                    kind="weak_crypto",
                    severity="HIGH",
                    category="Security safeguards",
                    detail_prefix="Weak or legacy cryptography pattern detected",
                    recommendation="Use modern, reviewed cryptography and document the control protecting personal data.",
                    context_regexes=WEAK_CRYPTO_CONTEXT_REGEXES,
                    severity_overrides=WEAK_CRYPTO_SEVERITY_OVERRIDES,
                )
            # Secrets are scanned in test files too (committed real
            # credentials in test configs are a classic leak), but at MEDIUM:
            # benchmark showed all 31 secret hits on a real ecommerce repo
            # were intentional fake keys in payment-gateway tests.
            # Template/env references (${{ secrets.X }}, ${VAR}, {{ var }},
            # process.env, os.environ) are correct practice, not exposure.
            if not SECRET_TEMPLATE_REFERENCE_RE.search(line):
                _append_regex_evidence(
                    evidence,
                    seen,
                    rel,
                    path,
                    file_context,
                    index,
                    line,
                    SECRET_REGEXES,
                    kind="secret_exposure",
                    severity="MEDIUM" if is_test_context else "CRITICAL",
                    category="Security safeguards",
                    detail_prefix=(
                        "Potential hard-coded credential in TEST code (verify it is not a real key)"
                        if is_test_context
                        else "Potential hard-coded secret or credential detected"
                    ),
                    recommendation="Remove the secret, rotate it, and use a managed secret store.",
                )
            http_match = None if is_test_context else INSECURE_HTTP_RE.search(line)
            if http_match and not _skip_insecure_http(line, http_match.group(1)):
                key = f"insecure_transport:{rel}:{index}"
                if key not in seen:
                    seen.add(key)
                    http_severity = "HIGH" if HTTP_RISK_CONTEXT_RE.search(line) else "MEDIUM"
                    evidence.append(
                        _evidence(
                            kind="insecure_transport",
                            label="Insecure HTTP endpoint detected",
                            severity=http_severity,
                            rel=rel,
                            path=path,
                            line=index,
                            category="Security safeguards",
                            detail="Code or config references a non-local HTTP endpoint. If personal data flows here, transport protection is weak.",
                            recommendation="Use HTTPS/TLS for personal-data transport or document a tightly scoped internal exception.",
                            file_context=file_context,
                            extra={"control_id": "DPDPA-TECH-001", "subtype": "HTTP endpoint"},
                        )
                    )
            if not is_test_context:
                _append_regex_evidence(
                    evidence,
                    seen,
                    rel,
                    path,
                    file_context,
                    index,
                    line,
                    CLOUD_MISCONFIG_REGEXES,
                    kind="cloud_misconfiguration",
                    severity="HIGH",
                    category="Security safeguards",
                    detail_prefix="Cloud or infrastructure misconfiguration pattern detected",
                    recommendation="Review production exposure, restrict access, enable encryption, and attach cloud control evidence.",
                )

        for subtype, needles in STRONG_CRYPTO_PATTERNS.items():
            if any(needle.lower() in lowered for needle in needles):
                _append_positive(
                    evidence,
                    seen,
                    rel,
                    path,
                    file_context,
                    kind="encryption_evidence",
                    label=f"{subtype} evidence",
                    subtype=subtype,
                    detail=f"Repository contains {subtype.lower()} evidence.",
                    recommendation="Confirm this protects personal-data systems in production and link it to the technical control register.",
                )

        for subtype, needles in CLOUD_SAFEGUARD_PATTERNS.items():
            if any(needle.lower() in lowered for needle in needles):
                _append_positive(
                    evidence,
                    seen,
                    rel,
                    path,
                    file_context,
                    kind="cloud_security_evidence",
                    label=f"{subtype} evidence",
                    subtype=subtype,
                    detail=f"Repository contains {subtype.lower()} evidence.",
                    recommendation="Confirm this safeguard is enabled in production for systems processing personal data.",
                )

        for name, needles in SECURITY_TOOL_PATTERNS.items():
            blob = f"{rel.lower()}\n{lowered}"
            if any(needle.lower() in blob for needle in needles):
                _append_positive(
                    evidence,
                    seen,
                    rel,
                    path,
                    file_context,
                    kind="security_tooling",
                    label=f"{name} evidence",
                    subtype=name,
                    detail=f"Repository references {name}, indicating vulnerability/security scanning evidence may exist.",
                    recommendation="Attach scan output or CI run evidence to the DPDPA breach-readiness pack.",
                )

        for name, needles in MONITORING_PATTERNS.items():
            if any(needle.lower() in lowered for needle in needles):
                _append_positive(
                    evidence,
                    seen,
                    rel,
                    path,
                    file_context,
                    kind="security_monitoring",
                    label=f"{name} monitoring evidence",
                    subtype=name,
                    detail=f"Repository references {name}, indicating logging, monitoring, or alerting coverage.",
                    recommendation="Confirm alert routing, retention, owner, and incident escalation path.",
                )

        for name, needles in ENDPOINT_SECURITY_PATTERNS.items():
            if any(needle.lower() in lowered for needle in needles):
                _append_positive(
                    evidence,
                    seen,
                    rel,
                    path,
                    file_context,
                    kind="endpoint_security",
                    label=f"{name} endpoint/security evidence",
                    subtype=name,
                    detail=f"Repository references {name}, indicating endpoint, workload, or cloud security monitoring evidence.",
                    recommendation="Confirm coverage for production assets that process personal data.",
                )

        if any(term in lowered for term in RUNBOOK_TERMS):
            _append_positive(
                evidence,
                seen,
                rel,
                path,
                file_context,
                kind="incident_readiness",
                label="Incident or breach response evidence",
                subtype="Runbook / escalation",
                detail="Repository contains incident, breach, on-call, or escalation language.",
                recommendation="Confirm owners, notification workflow, impact assessment, and evidence retention.",
            )

        if any(term in lowered for term in BACKUP_TERMS):
            _append_positive(
                evidence,
                seen,
                rel,
                path,
                file_context,
                kind="resilience_evidence",
                label="Backup or recovery evidence",
                subtype="Backup / restore / retention",
                detail="Repository contains backup, recovery, retention, or deletion-protection evidence.",
                recommendation="Confirm backup scope, restore testing, retention, and deletion alignment for personal data.",
            )

    return evidence


def ingest_security_findings(paths: Sequence[str] | None) -> List[Evidence]:
    evidence: List[Evidence] = []
    for raw_path in paths or []:
        path = Path(raw_path)
        if not path.exists() or not path.is_file():
            evidence.append(
                Evidence(
                    kind="import_error",
                    label="Security scan import missing",
                    severity="HIGH",
                    source="security-import",
                    detail=f"Security evidence file not found: {raw_path}",
                    recommendation="Check the scanner output path and rerun the import.",
                    category="Breach readiness",
                    metadata={"detector_id": "security_import.missing_file", "evidence_ref": raw_path, "confidence": "high"},
                )
            )
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
        except json.JSONDecodeError as exc:
            evidence.append(
                Evidence(
                    kind="import_error",
                    label="Security scan import parse error",
                    severity="MEDIUM",
                    source="security-import",
                    file=str(path),
                    detail=f"Could not parse security scanner JSON: {exc}",
                    recommendation="Export SARIF, Trivy, Gitleaks, OSV, or compatible JSON and retry.",
                    category="Breach readiness",
                    metadata={"detector_id": "security_import.parse_error", "evidence_ref": str(path), "confidence": "medium"},
                )
            )
            continue
        evidence.extend(_parse_security_payload(path, data))
    return evidence


def build_technical_controls(evidence: Iterable[Evidence]) -> List[Dict[str, Any]]:
    items = list(evidence)
    controls: List[Dict[str, Any]] = []
    for spec in CONTROL_CATALOG:
        positive = _matching_evidence(items, spec["positive_kinds"], spec["positive_subtypes"])
        # A control flips to "failing" (and thus breach posture "not_ready")
        # only on CRITICAL/HIGH findings; MEDIUM/LOW findings do not fail it.
        negative = [
            item
            for item in items
            if item.kind in spec["negative_kinds"] and item.severity in {"HIGH", "CRITICAL"}
        ]
        imported_high = [
            item
            for item in positive
            if item.kind == "imported_security_finding" and item.severity in {"HIGH", "CRITICAL"}
        ]

        if negative or imported_high:
            status = "fail"
            severity = "CRITICAL" if any(item.severity == "CRITICAL" for item in negative + imported_high) else "HIGH"
            score = 15
            next_action = str(spec["fail_action"])
        elif positive:
            status = "pass"
            severity = "LOW"
            score = 90
            next_action = "Confirm production scope, owner, and retention of this evidence."
        else:
            status = "missing"
            severity = "MEDIUM"
            score = 35
            next_action = str(spec["missing_action"])

        refs = [_evidence_ref(item) for item in [*negative, *imported_high, *positive]][:20]
        controls.append(
            {
                "id": spec["id"],
                "title": spec["title"],
                "area": spec["area"],
                "owner": spec["owner"],
                "status": status,
                "severity": severity,
                "score": score,
                "evidence_count": len(set(refs)),
                "evidence_refs": sorted(set(refs)),
                "gaps": _control_gaps(status, negative, imported_high, spec),
                "next_action": next_action,
                "ai_prompt": _control_ai_prompt(spec, status, refs, next_action),
            }
        )
    return controls


def build_breach_readiness(evidence: Iterable[Evidence], technical_controls: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    items = list(evidence)
    categories = {
        "vulnerability_management": _by_kinds(items, {"security_tooling", "imported_security_finding"}),
        "security_monitoring": _by_kinds(items, {"security_monitoring"}),
        "endpoint_or_workload_detection": _by_kinds(items, {"endpoint_security"}),
        "incident_response": _by_kinds(items, {"incident_readiness"}),
        "secrets_and_crypto": _by_kinds(items, {"secret_exposure", "weak_crypto", "encryption_evidence"}),
        "backup_and_recovery": _by_kinds(items, {"resilience_evidence"}),
        "cloud_and_iac_guardrails": _by_kinds(items, {"cloud_security_evidence", "cloud_misconfiguration"}),
        "personal_data_mapping": [item for item in items if item.metadata.get("data_category")],
    }
    domain_scores: Dict[str, Dict[str, Any]] = {}
    for name, matched in categories.items():
        bad = [item for item in matched if item.severity in {"HIGH", "CRITICAL"} and item.kind not in {"encryption_evidence", "security_tooling", "security_monitoring", "endpoint_security", "incident_readiness", "resilience_evidence"}]
        if bad:
            status = "needs_action"
            score = 25
        elif matched:
            status = "evidence_present"
            score = 80
        else:
            status = "missing_evidence"
            score = 35
        domain_scores[name] = {
            "status": status,
            "score": score,
            "evidence_refs": sorted({_evidence_ref(item) for item in matched})[:20],
            "count": len(matched),
        }

    failed_controls = [control for control in technical_controls if control.get("status") == "fail"]
    missing_controls = [control for control in technical_controls if control.get("status") == "missing"]
    average = int(sum(item["score"] for item in domain_scores.values()) / max(1, len(domain_scores)))
    if failed_controls:
        posture = "not_ready"
    elif average >= 70 and not missing_controls:
        posture = "ready_with_review"
    elif average >= 55:
        posture = "partial"
    else:
        posture = "missing_core_evidence"

    actions = []
    if failed_controls:
        actions.append("Fix failed security controls before relying on this breach-readiness pack.")
    if domain_scores["incident_response"]["status"] == "missing_evidence":
        actions.append("Add incident/breach response runbook evidence with owner, severity, timeline, and notification workflow.")
    if domain_scores["vulnerability_management"]["status"] == "missing_evidence":
        actions.append("Attach dependency/container/static/secret scan outputs or enable CI scanner ingestion.")
    if domain_scores["security_monitoring"]["status"] == "missing_evidence":
        actions.append("Attach monitoring, alerting, SIEM, APM, or log-retention evidence.")
    if domain_scores["endpoint_or_workload_detection"]["status"] == "missing_evidence":
        actions.append("Attach endpoint/workload/cloud detection evidence or document why it is out of scope.")
    if domain_scores["cloud_and_iac_guardrails"]["status"] == "missing_evidence":
        actions.append("Attach cloud/IaC guardrail evidence for encryption, audit logging, public access blocking, WAF, and private networking.")
    if domain_scores["cloud_and_iac_guardrails"]["status"] == "needs_action":
        actions.append("Fix cloud/IaC guardrail failures before relying on this breach-readiness pack.")
    if domain_scores["personal_data_mapping"]["status"] == "missing_evidence":
        actions.append("Run repository/website privacy evidence scanning so incident impact can map to data categories.")

    return {
        "schema_version": "svikruti-breach-readiness-v1",
        "posture": posture,
        "score": average,
        "domains": domain_scores,
        "failed_controls": [control["id"] for control in failed_controls],
        "missing_controls": [control["id"] for control in missing_controls],
        "priority_actions": actions[:8],
    }


def _append_regex_evidence(
    evidence: List[Evidence],
    seen: Set[str],
    rel: str,
    path: Path,
    file_context: str,
    line_number: int,
    line: str,
    regexes: Dict[str, re.Pattern[str]],
    *,
    kind: str,
    severity: str,
    category: str,
    detail_prefix: str,
    recommendation: str,
    context_regexes: Optional[Dict[str, re.Pattern[str]]] = None,
    severity_overrides: Optional[Dict[str, str]] = None,
) -> None:
    for subtype, regex in regexes.items():
        if not regex.search(line):
            continue
        context_regex = (context_regexes or {}).get(subtype)
        if context_regex is not None and not context_regex.search(line):
            continue
        key = f"{kind}:{subtype}:{rel}:{line_number}"
        if key in seen:
            continue
        seen.add(key)
        evidence.append(
            _evidence(
                kind=kind,
                label=subtype,
                severity=(severity_overrides or {}).get(subtype, severity),
                rel=rel,
                path=path,
                line=line_number,
                category=category,
                detail=f"{detail_prefix}: {subtype}.",
                recommendation=recommendation,
                file_context=file_context,
                extra={"subtype": subtype, "control_id": "DPDPA-TECH-002" if kind == "weak_crypto" else "DPDPA-TECH-003"},
            )
        )


def _append_positive(
    evidence: List[Evidence],
    seen: Set[str],
    rel: str,
    path: Path,
    file_context: str,
    *,
    kind: str,
    label: str,
    subtype: str,
    detail: str,
    recommendation: str,
) -> None:
    key = f"{kind}:{subtype}:{rel}"
    if key in seen:
        return
    seen.add(key)
    evidence.append(
        _evidence(
            kind=kind,
            label=label,
            severity="LOW",
            rel=rel,
            path=path,
            line=None,
            category="Security safeguards" if kind in {"encryption_evidence", "security_monitoring", "endpoint_security"} else "Breach readiness",
            detail=detail,
            recommendation=recommendation,
            file_context=file_context,
            extra={"subtype": subtype, "positive_evidence": True},
        )
    )


def _evidence(
    *,
    kind: str,
    label: str,
    severity: str,
    rel: str,
    path: Path,
    line: Optional[int],
    category: str,
    detail: str,
    recommendation: str,
    file_context: str,
    extra: Dict[str, Any],
) -> Evidence:
    detector_id = f"technical.{kind}.{normalize_text(str(extra.get('subtype') or label))}"
    evidence_ref = f"{rel}:{line}:{detector_id}" if line else f"{rel}:{detector_id}"
    return Evidence(
        kind=kind,
        label=label,
        severity=severity,
        source="technical-control",
        file=rel,
        line=line,
        detail=detail,
        recommendation=recommendation,
        category=category,
        metadata={
            "detector_id": detector_id,
            "confidence": "high" if severity in {"HIGH", "CRITICAL"} else "medium",
            "evidence_ref": evidence_ref,
            "file_context": file_context,
            "language": _language_for(path),
            **extra,
        },
    )


def _parse_security_payload(path: Path, data: Any) -> List[Evidence]:
    if isinstance(data, dict) and "runs" in data:
        return _parse_sarif(path, data)
    if isinstance(data, dict) and "Results" in data:
        return _parse_trivy(path, data)
    if isinstance(data, dict) and "vulns" in data:
        # OSV API response shape: {"vulns": [...]}.
        return _parse_osv(path, data)
    if isinstance(data, dict) and _looks_like_osv_scanner(data):
        # `osv-scanner --json` shape: {"results": [{"source": ..., "packages":
        # [{"package": ..., "vulnerabilities": [...]}]}]}.
        return _parse_osv_scanner(path, data)
    if isinstance(data, dict) and ("leaks" in data or "Leaks" in data):
        return _parse_gitleaks(path, data.get("leaks") or data.get("Leaks") or [])
    if isinstance(data, list):
        # A bare JSON list is only Gitleaks when items actually look like
        # Gitleaks findings; otherwise emit an unrecognized-format note.
        if _looks_like_gitleaks(data):
            return _parse_gitleaks(path, data)
        return [_unknown_format_evidence(path, "Bare JSON list did not look like Gitleaks findings (no RuleID/Description/File keys).")]
    return [_unknown_format_evidence(path, "Security JSON did not match SARIF, Trivy, Gitleaks, osv-scanner, or OSV-API shapes.")]


def _looks_like_osv_scanner(data: Dict[str, Any]) -> bool:
    results = data.get("results")
    if not isinstance(results, list):
        return False
    return any(isinstance(result, dict) and isinstance(result.get("packages"), list) for result in results)


def _looks_like_gitleaks(items: Sequence[Any]) -> bool:
    dict_items = [item for item in items if isinstance(item, dict)]
    if not items:
        # An empty list is a valid empty Gitleaks report.
        return True
    if not dict_items:
        return False
    return all(
        any(key in item for key in ("RuleID", "Description", "File", "rule"))
        for item in dict_items[:20]
    )


def _unknown_format_evidence(path: Path, reason: str) -> Evidence:
    return Evidence(
        kind="import_error",
        label="Unknown security scan format",
        severity="LOW",
        source="security-import",
        file=str(path),
        detail=reason,
        recommendation="Use --security-evidence with supported scanner outputs.",
        category="Breach readiness",
        metadata={"detector_id": "security_import.unknown_format", "evidence_ref": str(path), "confidence": "low"},
    )


def _parse_sarif(path: Path, data: Dict[str, Any]) -> List[Evidence]:
    evidence: List[Evidence] = []
    for run_index, run in enumerate(data.get("runs", []) or []):
        rules = {
            rule.get("id"): rule
            for rule in ((run.get("tool") or {}).get("driver") or {}).get("rules", []) or []
            if isinstance(rule, dict)
        }
        for result_index, result in enumerate(run.get("results", []) or []):
            rule_id = str(result.get("ruleId") or "sarif-result")
            rule = rules.get(rule_id, {})
            severity = _sarif_severity(result, rule)
            location = _sarif_location(result)
            evidence.append(
                Evidence(
                    kind="imported_security_finding",
                    label=f"SARIF finding: {rule_id}",
                    severity=severity,
                    source="security-import",
                    file=location.get("file") or str(path),
                    line=location.get("line"),
                    detail=_sanitize_import_text(
                        (result.get("message") or {}).get("text")
                        or rule.get("shortDescription", {}).get("text")
                        or "Imported SARIF security finding."
                    ),
                    recommendation="Triage this scanner result and attach remediation/acceptance evidence to breach readiness.",
                    category="Breach readiness",
                    metadata={
                        "detector_id": f"security_import.sarif.{normalize_text(rule_id)}",
                        "confidence": "high",
                        "evidence_ref": f"{path.name}:sarif:{run_index}:{result_index}",
                        "scanner": "SARIF",
                        "rule_id": rule_id,
                    },
                )
            )
    return evidence


def _parse_trivy(path: Path, data: Dict[str, Any]) -> List[Evidence]:
    evidence: List[Evidence] = []
    for result in data.get("Results", []) or []:
        target = str(result.get("Target") or path)
        for vuln in result.get("Vulnerabilities", []) or []:
            severity = _normalize_import_severity(vuln.get("Severity"))
            vuln_id = str(vuln.get("VulnerabilityID") or "trivy-vulnerability")
            evidence.append(
                Evidence(
                    kind="imported_security_finding",
                    label=f"Trivy vulnerability: {vuln_id}",
                    severity=severity,
                    source="security-import",
                    file=target,
                    detail=_sanitize_import_text(vuln.get("Title") or vuln.get("Description") or "Imported Trivy vulnerability."),
                    recommendation="Patch, upgrade, suppress with justification, or document risk acceptance before launch.",
                    category="Breach readiness",
                    metadata={
                        "detector_id": f"security_import.trivy.{normalize_text(vuln_id)}",
                        "confidence": "high",
                        "evidence_ref": f"{path.name}:trivy:{vuln_id}",
                        "scanner": "Trivy",
                        "package": vuln.get("PkgName"),
                        "installed_version": vuln.get("InstalledVersion"),
                        "fixed_version": vuln.get("FixedVersion"),
                    },
                )
            )
    return evidence


def _parse_osv(path: Path, data: Dict[str, Any]) -> List[Evidence]:
    evidence: List[Evidence] = []
    for vuln in data.get("vulns", []) or []:
        vuln_id = str(vuln.get("id") or "osv-vulnerability")
        evidence.append(
            Evidence(
                kind="imported_security_finding",
                label=f"OSV vulnerability: {vuln_id}",
                severity="HIGH",
                source="security-import",
                file=str(path),
                detail=_sanitize_import_text(vuln.get("summary") or "Imported OSV vulnerability."),
                recommendation="Patch, upgrade, suppress with justification, or document risk acceptance before launch.",
                category="Breach readiness",
                metadata={
                    "detector_id": f"security_import.osv.{normalize_text(vuln_id)}",
                    "confidence": "high",
                    "evidence_ref": f"{path.name}:osv:{vuln_id}",
                    "scanner": "OSV",
                },
            )
        )
    return evidence


def _parse_osv_scanner(path: Path, data: Dict[str, Any]) -> List[Evidence]:
    """Parse real `osv-scanner --json` output: results[].packages[].vulnerabilities[]."""
    evidence: List[Evidence] = []
    for result in data.get("results", []) or []:
        if not isinstance(result, dict):
            continue
        source = (result.get("source") or {})
        source_path = str(source.get("path") or path)
        for package in result.get("packages", []) or []:
            if not isinstance(package, dict):
                continue
            package_info = package.get("package") or {}
            package_name = package_info.get("name")
            package_version = package_info.get("version")
            for vuln in package.get("vulnerabilities", []) or []:
                if not isinstance(vuln, dict):
                    continue
                vuln_id = str(vuln.get("id") or "osv-vulnerability")
                database_specific = vuln.get("database_specific") or {}
                raw_severity = database_specific.get("severity")
                severity = _normalize_import_severity(raw_severity) if raw_severity else "HIGH"
                evidence.append(
                    Evidence(
                        kind="imported_security_finding",
                        label=f"OSV vulnerability: {vuln_id}",
                        severity=severity,
                        source="security-import",
                        file=source_path,
                        detail=_sanitize_import_text(vuln.get("summary") or "Imported osv-scanner vulnerability."),
                        recommendation="Patch, upgrade, suppress with justification, or document risk acceptance before launch.",
                        category="Breach readiness",
                        metadata={
                            "detector_id": f"security_import.osv.{normalize_text(vuln_id)}",
                            "confidence": "high",
                            "evidence_ref": f"{path.name}:osv-scanner:{vuln_id}",
                            "scanner": "osv-scanner",
                            "package": package_name,
                            "installed_version": package_version,
                        },
                    )
                )
    return evidence


def _parse_gitleaks(path: Path, leaks: Sequence[Any]) -> List[Evidence]:
    evidence: List[Evidence] = []
    for index, leak in enumerate(leaks):
        if not isinstance(leak, dict):
            continue
        rule_id = str(leak.get("RuleID") or leak.get("rule") or "gitleaks-secret")
        evidence.append(
            Evidence(
                kind="secret_exposure",
                label=f"Gitleaks secret: {rule_id}",
                severity="CRITICAL",
                source="security-import",
                file=str(leak.get("File") or path),
                line=_safe_int(leak.get("StartLine")),
                detail=_sanitize_import_text(leak.get("Description") or "Imported Gitleaks secret finding."),
                recommendation="Remove the secret, rotate it, and prove the secret is now managed outside source control.",
                category="Security safeguards",
                metadata={
                    "detector_id": f"security_import.gitleaks.{normalize_text(rule_id)}",
                    "confidence": "high",
                    "evidence_ref": f"{path.name}:gitleaks:{index}",
                    "scanner": "Gitleaks",
                    "rule_id": rule_id,
                    "control_id": "DPDPA-TECH-003",
                },
            )
        )
    return evidence


def _sarif_severity(result: Dict[str, Any], rule: Dict[str, Any]) -> str:
    """Map a SARIF result to severity.

    Honors properties."security-severity" (CVSS-style score) when present:
    >=9 CRITICAL, >=7 HIGH, >=4 MEDIUM, else LOW. Otherwise maps SARIF level:
    error -> HIGH, warning -> MEDIUM, note/none -> LOW, absent -> MEDIUM.
    """
    merged_properties: Dict[str, Any] = {}
    for source in (rule.get("properties"), result.get("properties")):
        if isinstance(source, dict):
            merged_properties.update(source)
    raw_score = merged_properties.get("security-severity")
    if raw_score is not None:
        try:
            cvss = float(raw_score)
        except (TypeError, ValueError):
            cvss = None
        if cvss is not None:
            if cvss >= 9.0:
                return "CRITICAL"
            if cvss >= 7.0:
                return "HIGH"
            if cvss >= 4.0:
                return "MEDIUM"
            return "LOW"
    level = result.get("level")
    if level is None:
        return "MEDIUM"
    level_text = str(level).lower()
    if level_text == "error":
        return "HIGH"
    if level_text == "warning":
        return "MEDIUM"
    return "LOW"


# Cap and redact imported scanner text before it enters evidence details so
# scanner messages cannot leak secrets into reports or AI packets.
IMPORT_DETAIL_MAX_CHARS = 300
_SECRET_RUN_RE = re.compile(r"[A-Za-z0-9+/=_-]{21,}")


def _redact_secret_runs(text: str) -> str:
    return _SECRET_RUN_RE.sub(lambda match: f"{match.group(0)[:6]}…REDACTED…{match.group(0)[-4:]}", text)


def _sanitize_import_text(value: Any, limit: int = IMPORT_DETAIL_MAX_CHARS) -> str:
    text = " ".join(str(value or "").split())
    text = _redact_secret_runs(text)
    if len(text) > limit:
        text = text[: limit - 1] + "…"
    return text


def _sarif_location(result: Dict[str, Any]) -> Dict[str, Any]:
    try:
        location = result["locations"][0]["physicalLocation"]
        artifact = location.get("artifactLocation") or {}
        region = location.get("region") or {}
        return {"file": artifact.get("uri"), "line": _safe_int(region.get("startLine"))}
    except (KeyError, IndexError, TypeError):
        return {}


def _normalize_import_severity(value: Any) -> str:
    text = str(value or "").upper()
    if text in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}:
        return text
    return "MEDIUM"


def _matching_evidence(items: Sequence[Evidence], kinds: Iterable[str], subtypes: Iterable[str]) -> List[Evidence]:
    kind_set = set(kinds)
    subtype_set = {str(item) for item in subtypes}
    matched: List[Evidence] = []
    for item in items:
        if item.kind not in kind_set:
            continue
        if item.kind == "imported_security_finding":
            matched.append(item)
            continue
        subtype = str(item.metadata.get("subtype") or item.metadata.get("scanner") or item.label)
        if subtype_set and subtype not in subtype_set and item.label not in subtype_set:
            continue
        matched.append(item)
    return matched


def _by_kinds(items: Sequence[Evidence], kinds: Set[str]) -> List[Evidence]:
    return [item for item in items if item.kind in kinds]


def _control_gaps(status: str, negative: Sequence[Evidence], imported_high: Sequence[Evidence], spec: Dict[str, Any]) -> List[str]:
    if status == "pass":
        return []
    if negative or imported_high:
        return sorted({item.label for item in [*negative, *imported_high]})[:10]
    return [str(spec["missing_action"])]


def _control_ai_prompt(spec: Dict[str, Any], status: str, refs: Sequence[str], next_action: str) -> str:
    return (
        f"Assess {spec['id']} ({spec['title']}) for DPDPA technical-control readiness. "
        f"Status: {status}. Evidence refs: {', '.join(refs[:8]) or 'none'}. "
        f"Recommend owner-specific next steps: {next_action}"
    )


def _evidence_ref(item: Evidence) -> str:
    ref = item.metadata.get("evidence_ref")
    if ref:
        return str(ref)
    location = item.file or item.source
    if item.line:
        return f"{location}:{item.line}:{item.kind}"
    return f"{location}:{item.kind}"


def _safe_int(value: Any) -> Optional[int]:
    try:
        if value is None:
            return None
        return int(value)
    except (TypeError, ValueError):
        return None
