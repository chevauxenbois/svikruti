"""
AI Engine Module for Svikruti.ai DPDPA Compliance Platform

This module handles all LLM interactions for the platform, supporting multiple
providers (OpenAI, Anthropic Claude, Google Gemini) with cost controls, usage
tracking, and caching.

Author: Svikruti.ai
License: Proprietary
"""

import base64
import hashlib
import json
import logging
import os
import re
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Configure logging
logger = logging.getLogger(__name__)

# Supported provider keys (canonical form used everywhere)
VALID_PROVIDERS = ("openai", "anthropic", "gemini")


def normalize_provider(provider: Optional[str]) -> str:
    """
    Normalize a provider identifier to its canonical key.

    Accepts legacy values such as "google_gemini" (stored by older versions)
    and maps them to "gemini". Unknown values fall back to "openai".
    """
    p = (provider or "openai").strip().lower()
    if p in ("google_gemini", "google gemini", "google-gemini", "google"):
        p = "gemini"
    return p if p in VALID_PROVIDERS else "openai"


# ==================== API KEY ENCRYPTION (Fernet) ====================
# API keys are encrypted at rest with a per-install Fernet key stored in a
# file with 0600 permissions. Legacy base64-only values are transparently
# migrated to encrypted form on first read.

def _secret_key_path(db=None) -> Path:
    """Resolve the path of the per-install secret key file (alongside the DB when possible)."""
    base = None
    if db is not None:
        db_path = getattr(db, "db_path", None)
        if db_path:
            base = Path(db_path).resolve().parent
    if base is None:
        base = Path.home() / ".svikruti"
    try:
        base.mkdir(mode=0o700, parents=True, exist_ok=True)
    except OSError:
        pass
    return base / ".svikruti_secret.key"


def _load_or_create_secret_key(db=None) -> bytes:
    """Load the per-install Fernet key, generating it (0600 perms) on first use."""
    from cryptography.fernet import Fernet

    path = _secret_key_path(db)
    if path.exists():
        return path.read_bytes().strip()

    key = Fernet.generate_key()
    try:
        fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(key)
    except FileExistsError:
        # Another process created it first — use theirs
        return path.read_bytes().strip()
    return key


def encrypt_api_key(api_key: str, db=None) -> str:
    """Encrypt an API key for storage. Raises if cryptography is unavailable."""
    if not api_key:
        return ""
    from cryptography.fernet import Fernet

    f = Fernet(_load_or_create_secret_key(db))
    return f.encrypt(api_key.encode("utf-8")).decode("ascii")


def decrypt_api_key(stored: str, db=None) -> Tuple[str, bool]:
    """
    Decrypt a stored API key.

    Returns:
        (api_key, was_legacy). was_legacy is True when the stored value was a
        legacy base64-encoded key (should be re-encrypted by the caller).
    """
    if not stored:
        return "", False
    try:
        from cryptography.fernet import Fernet, InvalidToken

        try:
            f = Fernet(_load_or_create_secret_key(db))
            return f.decrypt(stored.encode("ascii")).decode("utf-8"), False
        except (InvalidToken, ValueError):
            pass  # Not a Fernet token — try legacy base64 below
    except ImportError:
        logger.warning("cryptography package not installed; attempting legacy base64 decode")
    try:
        return base64.b64decode(stored.encode("ascii")).decode("utf-8"), True
    except Exception:
        return "", False


def _migrate_legacy_key(conn: sqlite3.Connection, org_id: int, api_key: str, db=None) -> None:
    """Re-encrypt a legacy base64 API key in place (best effort)."""
    try:
        new_value = encrypt_api_key(api_key, db)
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE ai_settings SET api_key_encrypted = ?, updated_at = CURRENT_TIMESTAMP WHERE org_id = ?",
            (new_value, org_id),
        )
        conn.commit()
        logger.info(f"Migrated legacy API key to encrypted storage for org {org_id}")
    except Exception as e:
        logger.warning(f"Could not migrate legacy API key for org {org_id}: {e}")


class AIEngine:
    """
    Core AI module for DPDPA compliance chatbot, document drafting, and analysis.

    Supports multiple LLM providers with cost tracking, usage limits, and response caching.
    """

    # Cost estimates per 1M tokens (pricing as of April 2026)
    COST_PER_MILLION = {
        "openai": {
            "gpt-4o-mini": {"input": 0.15, "output": 0.60},
            "gpt-4": {"input": 3.00, "output": 6.00},
        },
        "anthropic": {
            "claude-haiku-4-5": {"input": 1.00, "output": 5.00},
            "claude-sonnet-4-5": {"input": 3.00, "output": 15.00},
        },
        "gemini": {
            "gemini-2.5-flash": {"input": 0.30, "output": 2.50},
            "gemini-2.0-flash": {"input": 0.075, "output": 0.30},
        },
    }

    def __init__(
        self,
        db: sqlite3.Connection,
        org_id: int,
        provider: str = "openai",
        api_key: Optional[str] = None,
        model: Optional[str] = None,
    ):
        """
        Initialize the AI Engine for an organization.

        Args:
            db: SQLite database connection
            org_id: Organization ID
            provider: LLM provider ('openai', 'anthropic', 'gemini')
            api_key: API key for the provider (loaded from DB if not provided)
            model: Model name (uses default if not specified)
        """
        # Handle both Database instances and raw sqlite3 connections
        if hasattr(db, 'get_connection'):
            self._db_factory = db.get_connection  # callable that returns new connections
        else:
            self._db_factory = None
            self.db = db  # raw connection
        self._db_ref = db  # kept for locating the encryption key file
        self.org_id = org_id
        self.provider = normalize_provider(provider)
        self.model = model
        self.api_key = api_key

        # Response cache: {prompt_hash: (response, timestamp)}
        self._cache: Dict[str, Tuple[str, datetime]] = {}
        self.cache_ttl_minutes = 60

        # Load settings from DB if not provided
        if not self.api_key or not self.model:
            self._load_from_db()

        # Initialize LLM client
        self._init_client()

    def _get_conn(self) -> sqlite3.Connection:
        """Get a database connection."""
        if self._db_factory:
            return self._db_factory()
        return self.db

    def _load_from_db(self) -> None:
        """Load API key and model preferences from database."""
        try:
            conn = self._get_conn()
            cursor = conn.cursor()
            cursor.execute(
                "SELECT provider, api_key_encrypted, model FROM ai_settings WHERE org_id = ?",
                (self.org_id,),
            )
            row = cursor.fetchone()
            if row:
                self.provider = normalize_provider(row[0] or self.provider)
                encrypted_key = row[1]
                self.model = row[2] or self._get_default_model()
                if encrypted_key:
                    self.api_key, was_legacy = decrypt_api_key(encrypted_key, self._db_ref)
                    if was_legacy and self.api_key:
                        _migrate_legacy_key(conn, self.org_id, self.api_key, self._db_ref)
        except sqlite3.OperationalError:
            logger.warning("ai_settings table not found; using defaults")
            self.model = self._get_default_model()

    def _init_client(self) -> None:
        """Initialize the appropriate LLM client based on provider. Client is lazily validated on first API call."""
        self.client = None

        if not self.api_key:
            logger.warning(f"No API key for {self.provider} — client not initialized")
            return

        try:
            if self.provider == "openai":
                from openai import OpenAI
                self.client = OpenAI(api_key=self.api_key)
            elif self.provider == "anthropic":
                from anthropic import Anthropic
                self.client = Anthropic(api_key=self.api_key)
            elif self.provider == "gemini":
                from openai import OpenAI
                self.client = OpenAI(
                    api_key=self.api_key,
                    base_url="https://generativelanguage.googleapis.com/v1beta/openai/",
                )
            else:
                raise ValueError(f"Unsupported provider: {self.provider}")
        except ImportError as e:
            logger.error(f"Required package for {self.provider} not installed: {e}")
            self.client = None
        except Exception as e:
            logger.error(f"Failed to initialize {self.provider} client: {e}")
            self.client = None

    def _get_default_model(self) -> str:
        """Get default model for provider."""
        defaults = {
            "openai": "gpt-4o-mini",
            "anthropic": "claude-sonnet-4-5",
            "gemini": "gemini-2.5-flash",
        }
        return defaults.get(self.provider, "gpt-4o-mini")

    def _estimate_tokens(self, text: str) -> int:
        """
        Rough token estimation using word count.
        Approximation: 1 token ≈ 1.3 words
        """
        word_count = len(text.split())
        return max(1, int(word_count / 1.3))

    def _get_cache_key(self, prompt: str, feature: str) -> str:
        """Generate cache key from prompt hash."""
        cache_input = f"{feature}:{prompt}"
        return hashlib.md5(cache_input.encode()).hexdigest()

    def _get_from_cache(self, key: str) -> Optional[str]:
        """Retrieve from cache if not expired."""
        if key in self._cache:
            response, timestamp = self._cache[key]
            if datetime.now() - timestamp < timedelta(minutes=self.cache_ttl_minutes):
                logger.info(f"Cache hit for {key}")
                return response
            else:
                del self._cache[key]
        return None

    def _store_in_cache(self, key: str, response: str) -> None:
        """Store response in cache."""
        self._cache[key] = (response, datetime.now())

    def _call_llm(
        self,
        messages: List[Dict[str, str]],
        system_prompt: str,
        temperature: float = 0.7,
        max_tokens: int = 2000,
    ) -> Tuple[str, int, int]:
        """
        Make LLM API call with error handling.

        Returns:
            (response_text, input_tokens, output_tokens)
        """
        if not self.client:
            return "AI is not configured. Please set up your API key in AI Configuration.", 0, 0

        # Enforce the organization's monthly usage limit BEFORE calling the provider
        if self._monthly_limit_reached():
            raise RuntimeError(
                "Monthly AI usage limit reached for your organization. "
                "Increase the limit in AI Configuration or try again next month."
            )

        full_messages = [{"role": "system", "content": system_prompt}] + messages

        try:
            if self.provider == "anthropic":
                # Anthropic takes the system prompt separately; strip any
                # system-role entries from the message list.
                anthropic_messages = [
                    m for m in messages if m.get("role") in ("user", "assistant")
                ]
                response = self.client.messages.create(
                    model=self.model,
                    max_tokens=max_tokens,
                    system=system_prompt,
                    messages=anthropic_messages,
                    temperature=temperature,
                )
                response_text = response.content[0].text
                input_tokens = response.usage.input_tokens
                output_tokens = response.usage.output_tokens
            else:  # openai and gemini
                response = self.client.chat.completions.create(
                    model=self.model,
                    messages=full_messages,
                    temperature=temperature,
                    max_tokens=max_tokens,
                )
                response_text = response.choices[0].message.content
                input_tokens = response.usage.prompt_tokens
                output_tokens = response.usage.completion_tokens

            return response_text, input_tokens, output_tokens

        except Exception as e:
            if "rate_limit" in str(e).lower():
                raise RuntimeError(
                    "API rate limit exceeded. Please retry in a few moments."
                )
            elif "unauthorized" in str(e).lower() or "invalid" in str(e).lower():
                raise RuntimeError("Invalid API key. Please verify your credentials.")
            else:
                raise RuntimeError(f"LLM API error: {str(e)}")

    def _monthly_limit_reached(self) -> bool:
        """Check whether the org has used up its monthly AI query allowance."""
        try:
            conn = self._get_conn()
            cursor = conn.cursor()
            cursor.execute(
                "SELECT monthly_limit FROM ai_settings WHERE org_id = ?",
                (self.org_id,),
            )
            row = cursor.fetchone()
            limit = row[0] if row and row[0] is not None else None
            if not limit or limit <= 0:
                return False

            current_month = datetime.utcnow().strftime("%Y-%m")
            cursor.execute(
                "SELECT COUNT(*) FROM ai_usage WHERE org_id = ? AND strftime('%Y-%m', created_at) = ?",
                (self.org_id, current_month),
            )
            used = cursor.fetchone()[0] or 0
            return used >= limit
        except sqlite3.OperationalError:
            return False

    def _track_usage(
        self,
        feature: str,
        input_tokens: int,
        output_tokens: int,
        user_id: Optional[int] = None,
    ) -> None:
        """Record API usage in database."""
        try:
            # Calculate cost estimate
            costs = self.COST_PER_MILLION.get(self.provider, {}).get(self.model, {})
            cost_estimate = (
                (input_tokens / 1_000_000 * costs.get("input", 0))
                + (output_tokens / 1_000_000 * costs.get("output", 0))
            )

            conn = self._get_conn()
            cursor = conn.cursor()
            cursor.execute(
                """INSERT INTO ai_usage
                   (org_id, user_id, feature, provider, model, input_tokens, output_tokens, cost_estimate)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    self.org_id,
                    user_id,
                    feature,
                    self.provider,
                    self.model,
                    input_tokens,
                    output_tokens,
                    cost_estimate,
                ),
            )
            conn.commit()
        except sqlite3.OperationalError:
            logger.warning("Unable to log usage: ai_usage table not found")

    def chat_completion(
        self,
        messages: List[Dict[str, str]],
        org_context: Optional[Dict[str, Any]] = None,
        user_id: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        DPDPA Compliance Chatbot.

        Provides expert guidance on India's DPDPA 2023 and DPDP Rules 2025.

        Args:
            messages: Conversation history [{"role": "user"|"assistant", "content": "..."}]
            org_context: Optional org data for context
            user_id: Optional user ID for tracking

        Returns:
            {"response": str, "tokens_used": int, "cached": bool}
        """
        # Check cache (only for single-turn questions)
        if len(messages) == 1 and messages[0]["role"] == "user":
            cache_key = self._get_cache_key(messages[0]["content"], "chat_completion")
            cached = self._get_from_cache(cache_key)
            if cached:
                return {"response": cached, "tokens_used": 0, "cached": True}
        else:
            cache_key = None

        system_prompt = """You are Svikruti AI, an expert on India's DPDPA 2023 and DPDP Rules 2025.

You help compliance officers understand requirements, provide accurate section references,
and give practical implementation advice.

Core Responsibilities:
- Cite specific DPDPA sections or Rules when relevant
- Explain obligations for Data Processors, Data Controllers, and Fiduciaries
- Discuss consent, storage, processing, and breach notification
- Provide practical compliance guidance
- Be concise and actionable

If unsure, acknowledge the gap and suggest consulting legal counsel."""

        try:
            response_text, input_tokens, output_tokens = self._call_llm(
                messages, system_prompt, temperature=0.7, max_tokens=1500
            )

            self._track_usage("chat_completion", input_tokens, output_tokens, user_id)

            if cache_key:
                self._store_in_cache(cache_key, response_text)

            return {
                "response": response_text,
                "tokens_used": input_tokens + output_tokens,
                "cached": False,
            }
        except RuntimeError as e:
            return {"error": str(e), "response": None}

    def draft_document(
        self,
        doc_type: str,
        org_data: Dict[str, Any],
        user_id: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Smart Legal Document Drafter.

        Generates privacy policy, DPA, consent notices, breach notifications, etc.

        Args:
            doc_type: Type of document ("privacy_policy", "dpa", "consent_notice", "dpa_notice", "breach_letter")
            org_data: Organization data (RoPA, consent records, vendor list, name, address, etc.)
            user_id: Optional user ID for tracking

        Returns:
            {"document": str, "tokens_used": int, "doc_type": str}
        """
        system_prompt = """You are a legal document specialist for Indian data protection law (DPDPA 2023).

Generate professional, legally-informed documents that are:
- Compliant with DPDPA 2023 and DPDP Rules 2025
- Clear and accessible to data principals
- Specific to the organization's data practices
- Formatted in clean markdown

Use the organization data provided to fill in specifics."""

        # Build context prompt with org data
        context_lines = ["# Organization Context"]
        if "org_name" in org_data:
            context_lines.append(f"**Organization**: {org_data['org_name']}")
        if "org_address" in org_data:
            context_lines.append(f"**Address**: {org_data['org_address']}")
        if "ropa_entries" in org_data:
            context_lines.append("\n**Data Processing (RoPA)**:")
            for entry in org_data["ropa_entries"]:
                context_lines.append(f"  - {entry}")
        if "consent_records" in org_data:
            context_lines.append(f"\n**Consent Records**: Available for {len(org_data['consent_records'])} data principals")
        if "vendors" in org_data:
            context_lines.append(f"\n**Third-party Processors**: {', '.join(org_data['vendors'])}")

        context = "\n".join(context_lines)

        doc_prompts = {
            "privacy_policy": f"""Draft a comprehensive Privacy Notice compliant with DPDPA Section 5 and 6.

{context}

Requirements:
- Use plain language per Section 5(1)
- Cover all data collection, processing, and sharing
- Include rights of data principals
- Specify retention periods
- Include grievance officer contact

Output in markdown format.""",
            "dpa": f"""Draft a Data Processing Agreement (DPA) for this organization.

{context}

Include:
- Data controller and processor definitions
- Nature and duration of processing
- Instructions and obligations
- Sub-processor policy
- Data principal rights
- Breach notification procedures

Use DPDPA-compliant language.""",
            "consent_notice": f"""Draft a granular consent notice for data collection.

{context}

Include separate consents for:
- Contact information collection
- Marketing communications
- Third-party sharing
- Cookie/tracking technologies
- Specific processing activities

Use simple, non-coercive language per DPDPA guidance.""",
            "dpa_notice": f"""Draft a Data Protection Impact Assessment (DPIA) summary notice.

{context}

Document:
- Lawful basis for processing
- Legitimate interests assessment
- Risk assessment
- Mitigation measures
- Data principal rights

Per DPDP Rule 4.""",
            "breach_letter": f"""Draft a data breach notification letter to the Data Protection Board.

{context}

Include:
- Breach description and date
- Data categories affected
- Estimated number of data principals
- Breach notification letter (separately)
- Remediation steps

Per DPDP Rule 7.""",
        }

        prompt = doc_prompts.get(
            doc_type,
            f"Draft a DPDPA-compliant document of type: {doc_type}\n\n{context}",
        )

        try:
            response_text, input_tokens, output_tokens = self._call_llm(
                [{"role": "user", "content": prompt}],
                system_prompt,
                temperature=0.5,
                max_tokens=3000,
            )

            self._track_usage("draft_document", input_tokens, output_tokens, user_id)

            return {
                "document": response_text,
                "tokens_used": input_tokens + output_tokens,
                "doc_type": doc_type,
            }
        except RuntimeError as e:
            return {"error": str(e), "document": None}

    def analyze_gap_assessment(
        self,
        scores: Dict[str, float],
        responses: Dict[str, str],
        user_id: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Gap Assessment Analysis & Remediation Planner.

        Analyzes assessment results and generates prioritized remediation plan.

        Args:
            scores: Category scores {category: score_0_to_100}
            responses: Individual question responses {question: answer}
            user_id: Optional user ID for tracking

        Returns:
            {"plan": str, "tokens_used": int, "priority_areas": list}
        """
        system_prompt = """You are a DPDPA compliance consultant.

Analyze the gap assessment results and provide a prioritized, actionable remediation plan.

Your output should:
- Identify critical gaps (score < 50)
- Map gaps to specific DPDPA sections at risk
- Provide realistic timelines (Quick/Medium/Long-term)
- Estimate implementation effort (Low/Medium/High)
- Recommend specific actions per area"""

        # Format scores for analysis
        scores_str = "\n".join(
            [f"  - {cat}: {score}%" for cat, score in sorted(scores.items())]
        )

        responses_str = "\n".join(
            [f"  - {q}: {a}" for q, a in list(responses.items())[:10]]
        )
        if len(responses) > 10:
            responses_str += f"\n  ... and {len(responses) - 10} more responses"

        prompt = f"""# Gap Assessment Results

## Category Scores
{scores_str}

## Key Responses (sample)
{responses_str}

## Task
Generate a prioritized remediation plan addressing the critical gaps.
Focus on quick wins first, then medium and long-term initiatives."""

        try:
            response_text, input_tokens, output_tokens = self._call_llm(
                [{"role": "user", "content": prompt}],
                system_prompt,
                temperature=0.6,
                max_tokens=2500,
            )

            self._track_usage("analyze_gap_assessment", input_tokens, output_tokens, user_id)

            # Extract priority areas (categories with score < 50)
            priority_areas = [
                cat for cat, score in scores.items() if score < 50
            ]

            return {
                "plan": response_text,
                "tokens_used": input_tokens + output_tokens,
                "priority_areas": priority_areas,
                "critical_count": len(priority_areas),
            }
        except RuntimeError as e:
            return {"error": str(e), "plan": None}

    def classify_breach(
        self,
        description: str,
        data_categories: List[str],
        affected_count: int,
        user_id: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Data Breach Classifier & Notification Generator.

        Classifies breach severity and drafts notification letters.

        Args:
            description: Breach description
            data_categories: List of affected data categories
            affected_count: Number of affected data principals
            user_id: Optional user ID for tracking

        Returns:
            {
                "severity": "Low|Medium|High|Critical",
                "dpa_notification": str,
                "principal_notification": str,
                "tokens_used": int
            }
        """
        system_prompt = """You are a data breach response specialist under DPDPA.

Your tasks:
1. Classify breach severity (Low/Medium/High/Critical)
2. Assess notification requirements per DPDPA Section 8
3. Draft Data Protection Board notification letter (per DPDP Rule 7)
4. Draft Data Principal notification letter

The FIRST line of your response MUST be exactly in this format:
Severity: <Low|Medium|High|Critical>

Be concise, legally accurate, and actionable."""

        categories_str = (
            data_categories if isinstance(data_categories, str) else ", ".join(data_categories)
        )

        prompt = f"""# Data Breach Incident

**Description**: {description}

**Affected Data Categories**: {categories_str}

**Number of Affected Data Principals**: {affected_count}

## Task
1. Classify this breach as Low, Medium, High, or Critical. Start your response with a line exactly in the format "Severity: <level>".
2. Assess whether Board notification is required per DPDPA Section 8(2)
3. Draft concise Board notification letter (if required)
4. Draft Data Principal notification letter

Provide clear reasoning for severity classification."""

        try:
            response_text, input_tokens, output_tokens = self._call_llm(
                [{"role": "user", "content": prompt}],
                system_prompt,
                temperature=0.6,
                max_tokens=2000,
            )

            self._track_usage("classify_breach", input_tokens, output_tokens, user_id)

            # Parse the explicit "Severity: X" line the model was instructed
            # to output. Fall back to "Unclassified" rather than guessing
            # from an incidental mention.
            severity = "Unclassified"
            match = re.search(
                r"^\s*\**\s*severity\s*\**\s*[:\-]\s*\**\s*(critical|high|medium|low)",
                response_text,
                re.IGNORECASE | re.MULTILINE,
            )
            if match:
                severity = match.group(1).capitalize()

            return {
                "severity": severity,
                "analysis": response_text,
                "tokens_used": input_tokens + output_tokens,
            }
        except RuntimeError as e:
            return {"error": str(e), "severity": None}

    def review_privacy_notice(
        self,
        notice_text: str,
        user_id: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Privacy Notice Compliance Reviewer.

        Audits notice for DPDPA compliance, readability, and completeness.

        Args:
            notice_text: The privacy notice text to review
            user_id: Optional user ID for tracking

        Returns:
            {
                "compliance_score": int (1-10),
                "readability_score": int (1-10),
                "completeness_score": int (1-10),
                "feedback": str,
                "tokens_used": int,
                "issues": list
            }
        """
        system_prompt = """You are a privacy notice auditor for DPDPA compliance.

Evaluate the notice on three dimensions:
1. DPDPA Compliance (Sections 5, 6): Does it cover all requirements?
2. Readability (Section 5(1) plain language requirement): Is it clear to average data principal?
3. Completeness: Does it address all processing, retention, and rights?

Score each 1-10 and provide specific improvement suggestions."""

        prompt = f"""# Privacy Notice Review

**Notice Text:**
{notice_text}

## Task
1. Score DPDPA Compliance (1-10)
2. Score Readability (1-10)
3. Score Completeness (1-10)
4. List specific issues (max 5)
5. Provide top 3 improvement recommendations

Begin your response with exactly these three lines (replace X with the score):
Compliance Score: X/10
Readability Score: X/10
Completeness Score: X/10

Then format the rest of your response with clear sections."""

        try:
            response_text, input_tokens, output_tokens = self._call_llm(
                [{"role": "user", "content": prompt}],
                system_prompt,
                temperature=0.6,
                max_tokens=1500,
            )

            self._track_usage("review_privacy_notice", input_tokens, output_tokens, user_id)

            # Parse scores from the response. If parsing fails, the score is
            # None and the UI must show an "unscored" state — never a
            # fabricated number.
            def _parse_score(label: str) -> Optional[int]:
                match = re.search(
                    rf"{label}[^0-9]{{0,20}}(10|[0-9])",
                    response_text,
                    re.IGNORECASE,
                )
                return int(match.group(1)) if match else None

            scores = {
                "compliance": _parse_score("compliance"),
                "readability": _parse_score("readability"),
                "completeness": _parse_score("completeness"),
            }
            scores_available = any(v is not None for v in scores.values())

            return {
                "scores": scores,
                "scores_available": scores_available,
                "feedback": response_text,
                "tokens_used": input_tokens + output_tokens,
            }
        except RuntimeError as e:
            return {"error": str(e), "feedback": None}

    def get_usage_stats(self) -> Dict[str, Any]:
        """
        Get monthly usage statistics for the organization.

        Returns:
            {
                "total_queries": int,
                "total_tokens": int,
                "total_cost": float,
                "by_feature": {feature: count},
                "month": str
            }
        """
        try:
            conn = self._get_conn()
            cursor = conn.cursor()
            current_month = datetime.now().strftime("%Y-%m")

            # Total usage this month
            cursor.execute(
                """SELECT COUNT(*), SUM(input_tokens + output_tokens), SUM(cost_estimate)
                   FROM ai_usage
                   WHERE org_id = ? AND strftime('%Y-%m', created_at) = ?""",
                (self.org_id, current_month),
            )
            row = cursor.fetchone()
            total_queries = row[0] or 0
            total_tokens = row[1] or 0
            total_cost = row[2] or 0.0

            # Usage by feature
            cursor.execute(
                """SELECT feature, COUNT(*) FROM ai_usage
                   WHERE org_id = ? AND strftime('%Y-%m', created_at) = ?
                   GROUP BY feature""",
                (self.org_id, current_month),
            )
            by_feature = {row[0]: row[1] for row in cursor.fetchall()}

            return {
                "total_queries": total_queries,
                "total_tokens": total_tokens,
                "total_cost": round(total_cost, 2),
                "by_feature": by_feature,
                "month": current_month,
            }
        except sqlite3.OperationalError:
            return {
                "error": "ai_usage table not found",
                "total_queries": 0,
            }

    def get_ai_settings(self) -> Dict[str, Any]:
        """Get current AI settings for organization."""
        try:
            conn = self._get_conn()
            cursor = conn.cursor()
            cursor.execute(
                """SELECT provider, model, monthly_limit, is_enabled
                   FROM ai_settings WHERE org_id = ?""",
                (self.org_id,),
            )
            row = cursor.fetchone()
            if row:
                return {
                    "provider": normalize_provider(row[0]),
                    "model": row[1],
                    "monthly_limit": row[2],
                    "enabled": bool(row[3]),
                }
            return {
                "provider": "openai",
                "model": "gpt-4o-mini",
                "monthly_limit": 100,
                "enabled": False,
            }
        except sqlite3.OperationalError:
            return {"error": "ai_settings table not found"}

    def save_ai_settings(
        self,
        provider: str,
        api_key: str,
        model: str,
        monthly_limit: int,
    ) -> Dict[str, Any]:
        """
        Save AI settings for organization.

        Args:
            provider: Provider name ('openai', 'anthropic', 'gemini')
            api_key: API key (encrypted at rest with Fernet)
            model: Model name
            monthly_limit: Monthly token usage limit

        Returns:
            {"success": bool, "message": str}
        """
        try:
            provider = normalize_provider(provider)
            encrypted_key = encrypt_api_key(api_key, self._db_ref)
            conn = self._get_conn()
            cursor = conn.cursor()

            cursor.execute(
                """INSERT OR REPLACE INTO ai_settings
                   (org_id, provider, api_key_encrypted, model, monthly_limit, is_enabled, updated_at)
                   VALUES (?, ?, ?, ?, ?, 1, CURRENT_TIMESTAMP)""",
                (self.org_id, provider, encrypted_key, model, monthly_limit),
            )
            conn.commit()

            # Reload client with new settings
            self.provider = provider
            self.api_key = api_key
            self.model = model
            self._init_client()

            return {"success": True, "message": "AI settings saved successfully"}
        except Exception as e:
            return {"success": False, "message": str(e)}


def init_ai_tables(db: sqlite3.Connection) -> None:
    """
    Initialize AI-related tables in the database.

    Creates:
    - ai_usage: Track API usage per org per feature
    - ai_settings: Store org AI provider settings and credentials
    """
    cursor = db.cursor()

    # AI Usage tracking table
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS ai_usage (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            org_id INTEGER NOT NULL,
            user_id INTEGER,
            feature TEXT NOT NULL,
            provider TEXT NOT NULL,
            model TEXT NOT NULL,
            input_tokens INTEGER DEFAULT 0,
            output_tokens INTEGER DEFAULT 0,
            cost_estimate REAL DEFAULT 0.0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(org_id) REFERENCES organizations(id)
        )
        """
    )

    # AI Settings table
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS ai_settings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            org_id INTEGER NOT NULL UNIQUE,
            provider TEXT DEFAULT 'openai',
            api_key_encrypted TEXT,
            model TEXT DEFAULT 'gpt-4o-mini',
            monthly_limit INTEGER DEFAULT 100,
            is_enabled INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(org_id) REFERENCES organizations(id)
        )
        """
    )

    db.commit()
    logger.info("AI tables initialized successfully")


# ==================== STANDALONE HELPER FUNCTIONS ====================
# These are used by ai_pages.py for settings management without needing
# a full AIEngine instance (which requires a valid API key).


def get_ai_settings(db, org_id: int) -> Optional[Dict[str, Any]]:
    """
    Get AI settings for an organization without instantiating AIEngine.

    Args:
        db: Database instance (with get_connection method) or sqlite3.Connection
        org_id: Organization ID

    Returns:
        Dictionary with settings or None
    """
    try:
        if hasattr(db, "get_connection"):
            conn = db.get_connection()
        else:
            conn = db
        cursor = conn.cursor()
        cursor.execute(
            "SELECT provider, api_key_encrypted, model, monthly_limit, is_enabled "
            "FROM ai_settings WHERE org_id = ?",
            (org_id,),
        )
        row = cursor.fetchone()

        result = None
        if row:
            api_key = ""
            if row[1]:
                api_key, was_legacy = decrypt_api_key(row[1], db)
                if was_legacy and api_key:
                    _migrate_legacy_key(conn, org_id, api_key, db)
            result = {
                "provider": normalize_provider(row[0]),
                "api_key": api_key,
                "model": row[2] or "gpt-4o-mini",
                "monthly_limit": row[3] or 100,
                "is_enabled": bool(row[4]) if row[4] is not None else False,
            }

        if hasattr(db, "get_connection"):
            conn.close()
        return result
    except Exception as e:
        logger.warning(f"Failed to load AI settings: {e}")
        return None


def save_ai_settings(
    db,
    org_id: int,
    provider: str = "openai",
    api_key: str = "",
    model: str = "gpt-4o-mini",
    monthly_limit: int = 100,
    is_enabled: bool = True,
) -> bool:
    """
    Save AI settings for an organization.

    Args:
        db: Database instance or sqlite3.Connection
        org_id: Organization ID
        provider: LLM provider name
        api_key: Raw API key (encrypted at rest with Fernet)
        model: Model identifier
        monthly_limit: Max queries per month
        is_enabled: Whether AI features are active

    Returns:
        True if saved successfully
    """
    try:
        if hasattr(db, "get_connection"):
            conn = db.get_connection()
        else:
            conn = db
        cursor = conn.cursor()

        provider = normalize_provider(provider)
        encrypted_key = encrypt_api_key(api_key, db) if api_key else ""

        cursor.execute(
            """
            INSERT INTO ai_settings (org_id, provider, api_key_encrypted, model, monthly_limit, is_enabled, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(org_id) DO UPDATE SET
                provider = excluded.provider,
                api_key_encrypted = excluded.api_key_encrypted,
                model = excluded.model,
                monthly_limit = excluded.monthly_limit,
                is_enabled = excluded.is_enabled,
                updated_at = CURRENT_TIMESTAMP
            """,
            (org_id, provider, encrypted_key, model, monthly_limit, int(is_enabled)),
        )
        conn.commit()
        if hasattr(db, "get_connection"):
            conn.close()
        return True
    except Exception as e:
        logger.error(f"Failed to save AI settings: {e}")
        return False


def get_usage_stats(db, org_id: int) -> Dict[str, Any]:
    """
    Get monthly AI usage statistics for an organization.

    Args:
        db: Database instance or sqlite3.Connection
        org_id: Organization ID

    Returns:
        Dictionary with usage stats
    """
    try:
        if hasattr(db, "get_connection"):
            conn = db.get_connection()
        else:
            conn = db
        cursor = conn.cursor()

        # Current month usage
        month_start = datetime.now().replace(day=1, hour=0, minute=0, second=0, microsecond=0)

        cursor.execute(
            """
            SELECT
                COUNT(*) as query_count,
                COALESCE(SUM(input_tokens), 0) as total_input_tokens,
                COALESCE(SUM(output_tokens), 0) as total_output_tokens,
                COALESCE(SUM(cost_estimate), 0) as total_cost
            FROM ai_usage
            WHERE org_id = ? AND created_at >= ?
            """,
            (org_id, month_start.isoformat()),
        )
        row = cursor.fetchone()

        # Usage by feature
        cursor.execute(
            """
            SELECT feature, COUNT(*) as count, COALESCE(SUM(cost_estimate), 0) as cost
            FROM ai_usage
            WHERE org_id = ? AND created_at >= ?
            GROUP BY feature
            """,
            (org_id, month_start.isoformat()),
        )
        feature_rows = cursor.fetchall()

        if hasattr(db, "get_connection"):
            conn.close()

        feature_usage = {}
        for fr in feature_rows:
            feature_usage[fr[0]] = {"count": fr[1], "cost": fr[2]}

        return {
            "query_count": row[0] if row else 0,
            "total_input_tokens": row[1] if row else 0,
            "total_output_tokens": row[2] if row else 0,
            "total_cost": row[3] if row else 0.0,
            "feature_usage": feature_usage,
        }
    except Exception as e:
        logger.warning(f"Failed to get usage stats: {e}")
        return {
            "query_count": 0,
            "total_input_tokens": 0,
            "total_output_tokens": 0,
            "total_cost": 0.0,
            "feature_usage": {},
        }
