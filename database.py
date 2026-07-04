"""
Production-quality database layer for Svikruti.ai

Multi-tenant DPDPA compliance platform with:
- User authentication and role-based access control
- Organization and subscription management
- Multi-tenant data isolation
- Complete DPDPA compliance tracking (RoPA, DPIA, DPA, consent, privacy notices)
- DSR (Data Subject Request) management
- Vendor and third-party management
- Comprehensive audit trail
- Invite and team management

No external dependencies beyond Python stdlib + sqlite3.
All operations are design for offline use and security.
"""

import sqlite3
import hashlib
import os
import secrets
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any

try:
    import config
except ImportError:
    config = None


class Database:
    """Production-grade SQLite database handler for multi-tenant Svikruti.ai platform"""

    def __init__(self, db_path: Optional[str] = None):
        """
        Initialize database connection and create tables if needed.

        Args:
            db_path: Path to SQLite database file. If None, uses temp directory.
        """
        if db_path is None:
            # Use persistent volume on Railway/Docker, fallback to a
            # user-private app directory (never a world-shared temp dir).
            data_dir = os.environ.get("DATA_DIR", "/data")
            if os.path.isdir(data_dir) and os.access(data_dir, os.W_OK):
                self.db_path = str(Path(data_dir) / "svikruti_data.db")
            else:
                app_dir = Path.home() / ".svikruti"
                app_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
                try:
                    os.chmod(app_dir, 0o700)
                except OSError:
                    pass
                self.db_path = str(app_dir / "svikruti_data.db")
        else:
            self.db_path = db_path

        self.init_database()

    def get_connection(self) -> sqlite3.Connection:
        """
        Get a database connection with row factory.

        Returns:
            sqlite3.Connection: Connection with Row factory enabled.
        """
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def init_database(self) -> None:
        """Initialize database tables if they don't exist."""
        conn = self.get_connection()
        cursor = conn.cursor()

        # ==================== USERS TABLE ====================
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                password_salt TEXT NOT NULL,
                full_name TEXT NOT NULL,
                role TEXT NOT NULL CHECK(role IN ('admin', 'member', 'viewer')),
                org_id INTEGER NOT NULL,
                is_active INTEGER DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP,
                failed_login_count INTEGER DEFAULT 0,
                last_failed_login TIMESTAMP,
                FOREIGN KEY(org_id) REFERENCES organizations(id)
            )
        """)

        # Migration for databases created before login rate-limiting columns existed
        for migration_stmt in (
            "ALTER TABLE users ADD COLUMN failed_login_count INTEGER DEFAULT 0",
            "ALTER TABLE users ADD COLUMN last_failed_login TIMESTAMP",
        ):
            try:
                cursor.execute(migration_stmt)
            except sqlite3.OperationalError:
                pass  # Column already exists

        # ==================== ORGANIZATIONS TABLE ====================
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS organizations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                industry TEXT,
                size TEXT,
                sdf_status TEXT,
                compliance_level TEXT,
                created_by INTEGER,
                subscription_tier TEXT DEFAULT 'free' CHECK(subscription_tier IN ('free', 'premium')),
                max_users INTEGER DEFAULT 5,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(created_by) REFERENCES users(id)
            )
        """)

        # ==================== INVITES TABLE ====================
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS invites (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                org_id INTEGER NOT NULL,
                email TEXT NOT NULL,
                role TEXT NOT NULL CHECK(role IN ('admin', 'member', 'viewer')),
                status TEXT DEFAULT 'pending' CHECK(status IN ('pending', 'accepted', 'expired')),
                token TEXT UNIQUE NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP NOT NULL,
                FOREIGN KEY(org_id) REFERENCES organizations(id)
            )
        """)

        # ==================== ASSESSMENT RESPONSES TABLE ====================
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS assessment_responses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                org_id INTEGER NOT NULL,
                category TEXT NOT NULL,
                question_id TEXT NOT NULL,
                response TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(org_id) REFERENCES organizations(id),
                UNIQUE(org_id, question_id)
            )
        """)

        # ==================== ASSESSMENTS TABLE ====================
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS assessments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                org_id INTEGER NOT NULL,
                overall_score REAL NOT NULL,
                category_scores TEXT NOT NULL,
                assessment_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(org_id) REFERENCES organizations(id)
            )
        """)

        # ==================== DOCUMENTS TABLE ====================
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS documents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                org_id INTEGER NOT NULL,
                doc_type TEXT NOT NULL,
                title TEXT NOT NULL,
                content TEXT NOT NULL,
                status TEXT DEFAULT 'DRAFT',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(org_id) REFERENCES organizations(id)
            )
        """)

        # ==================== COMPLIANCE TASKS TABLE ====================
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS compliance_tasks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                org_id INTEGER NOT NULL,
                title TEXT NOT NULL,
                description TEXT,
                category TEXT NOT NULL,
                priority TEXT NOT NULL,
                status TEXT DEFAULT 'PENDING',
                due_date DATE NOT NULL,
                assigned_to TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(org_id) REFERENCES organizations(id)
            )
        """)

        # ==================== BREACH INCIDENTS TABLE ====================
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS breach_incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                org_id INTEGER NOT NULL,
                incident_date TIMESTAMP NOT NULL,
                description TEXT NOT NULL,
                data_affected TEXT,
                severity TEXT NOT NULL,
                authority_notified INTEGER DEFAULT 0,
                authority_date TIMESTAMP,
                status TEXT DEFAULT 'OPEN',
                notes TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(org_id) REFERENCES organizations(id)
            )
        """)

        # ==================== ROPA ENTRIES TABLE ====================
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS ropa_entries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                org_id INTEGER NOT NULL,
                activity_name TEXT NOT NULL,
                department TEXT,
                data_categories TEXT NOT NULL,
                data_subjects TEXT NOT NULL,
                purpose TEXT NOT NULL,
                lawful_basis TEXT NOT NULL,
                retention_period TEXT,
                data_processor TEXT,
                processing_location TEXT,
                security_measures TEXT,
                cross_border INTEGER DEFAULT 0,
                status TEXT DEFAULT 'ACTIVE',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(org_id) REFERENCES organizations(id)
            )
        """)

        # ==================== CONSENT RECORDS TABLE ====================
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS consent_records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                org_id INTEGER NOT NULL,
                purpose TEXT NOT NULL,
                data_categories TEXT NOT NULL,
                mechanism TEXT NOT NULL,
                consent_text TEXT,
                withdrawal_method TEXT,
                is_children INTEGER DEFAULT 0,
                status TEXT DEFAULT 'ACTIVE',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(org_id) REFERENCES organizations(id)
            )
        """)

        # ==================== PRIVACY NOTICES TABLE ====================
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS privacy_notices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                org_id INTEGER NOT NULL,
                notice_type TEXT NOT NULL,
                title TEXT NOT NULL,
                data_categories TEXT NOT NULL,
                purposes TEXT NOT NULL,
                third_parties TEXT,
                retention_info TEXT,
                rights_info TEXT,
                grievance_info TEXT,
                version TEXT DEFAULT '1.0',
                status TEXT DEFAULT 'DRAFT',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(org_id) REFERENCES organizations(id)
            )
        """)

        # ==================== RIGHTS REQUESTS TABLE ====================
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS rights_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                org_id INTEGER NOT NULL,
                request_type TEXT NOT NULL,
                requester_name TEXT NOT NULL,
                requester_email TEXT,
                description TEXT,
                identity_verified INTEGER DEFAULT 0,
                status TEXT DEFAULT 'RECEIVED',
                due_date DATE,
                response_notes TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(org_id) REFERENCES organizations(id)
            )
        """)

        # ==================== VENDORS TABLE ====================
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS vendors (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                org_id INTEGER NOT NULL,
                vendor_name TEXT NOT NULL,
                service_type TEXT NOT NULL,
                data_shared TEXT NOT NULL,
                dpa_status TEXT DEFAULT 'NOT_STARTED',
                security_rating TEXT,
                iso_certified INTEGER DEFAULT 0,
                soc2_certified INTEGER DEFAULT 0,
                last_assessment_date DATE,
                risk_level TEXT DEFAULT 'MEDIUM',
                notes TEXT,
                status TEXT DEFAULT 'ACTIVE',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(org_id) REFERENCES organizations(id)
            )
        """)

        # ==================== DPIA RECORDS TABLE ====================
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS dpia_records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                org_id INTEGER NOT NULL,
                project_name TEXT NOT NULL,
                processing_description TEXT NOT NULL,
                necessity_assessment TEXT,
                risk_assessment TEXT,
                mitigation_measures TEXT,
                risk_level TEXT DEFAULT 'MEDIUM',
                approved_by TEXT,
                status TEXT DEFAULT 'DRAFT',
                review_date DATE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(org_id) REFERENCES organizations(id)
            )
        """)

        # ==================== ACTIVITY LOG TABLE ====================
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS activity_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                org_id INTEGER NOT NULL,
                user_id INTEGER,
                action_type TEXT NOT NULL,
                description TEXT NOT NULL,
                entity_type TEXT,
                entity_id INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(org_id) REFERENCES organizations(id),
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
        """)

        conn.commit()
        conn.close()

    # ==================== USER AUTHENTICATION ====================

    @staticmethod
    def _hash_password(password: str, salt: Optional[bytes] = None) -> Tuple[str, str]:
        """
        Hash password with salt using SHA256.

        Args:
            password: Plain text password to hash
            salt: Optional existing salt. If None, generates new salt.

        Returns:
            Tuple of (password_hash, salt) as hex strings.
        """
        if salt is None:
            salt = os.urandom(32)
        else:
            salt = bytes.fromhex(salt)

        hash_obj = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
        return hash_obj.hex(), salt.hex()

    def create_user(
        self,
        email: str,
        password: str,
        full_name: str,
        role: str,
        org_id: int
    ) -> int:
        """
        Create a new user with secure password hashing.

        Args:
            email: User email (must be unique within org)
            password: Plain text password
            full_name: User's full name
            role: User role (admin, member, or viewer)
            org_id: Organization ID

        Returns:
            User ID of created user

        Raises:
            ValueError: If email already exists or invalid role
            sqlite3.IntegrityError: If foreign key constraint fails
        """
        if role not in ('admin', 'member', 'viewer'):
            raise ValueError(f"Invalid role: {role}")

        password_hash, salt = self._hash_password(password)
        conn = self.get_connection()
        cursor = conn.cursor()

        try:
            cursor.execute("""
                INSERT INTO users
                (email, password_hash, password_salt, full_name, role, org_id, is_active)
                VALUES (?, ?, ?, ?, ?, ?, 1)
            """, (email, password_hash, salt, full_name, role, org_id))
            conn.commit()
            user_id = cursor.lastrowid
            self.log_activity(org_id, "USER_CREATED", f"User '{email}' created with role {role}")
            return user_id
        except sqlite3.IntegrityError as e:
            raise ValueError(f"Email already exists: {email}")
        finally:
            conn.close()

    # Brute-force protection: lock the account for LOCKOUT_MINUTES after
    # LOCKOUT_THRESHOLD consecutive failed login attempts.
    LOCKOUT_THRESHOLD = 5
    LOCKOUT_MINUTES = 15

    def authenticate_user(self, email: str, password: str) -> Optional[Dict]:
        """
        Authenticate user by email and password, with brute-force lockout.

        After 5 consecutive failed attempts the account is locked for
        15 minutes. The failure counter resets on successful login.

        Args:
            email: User email
            password: Plain text password

        Returns:
            User dict if authentication successful, None otherwise
        """
        conn = self.get_connection()
        cursor = conn.cursor()
        try:
            cursor.execute(
                "SELECT * FROM users WHERE email = ? AND is_active = 1",
                (email,)
            )
            row = cursor.fetchone()

            if not row:
                return None

            user_dict = dict(row)

            # Check lockout window
            failed_count = user_dict.get('failed_login_count') or 0
            last_failed = user_dict.get('last_failed_login')
            if failed_count >= self.LOCKOUT_THRESHOLD and last_failed:
                try:
                    last_failed_dt = datetime.fromisoformat(str(last_failed))
                except ValueError:
                    last_failed_dt = None
                if last_failed_dt and (
                    datetime.utcnow() - last_failed_dt
                    < timedelta(minutes=self.LOCKOUT_MINUTES)
                ):
                    # Account temporarily locked — do not even verify password
                    return None

            stored_hash = user_dict['password_hash']
            salt = user_dict['password_salt']
            computed_hash, _ = self._hash_password(password, salt)

            if computed_hash == stored_hash:
                # Reset failure counter and update last login
                cursor.execute(
                    "UPDATE users SET failed_login_count = 0, last_failed_login = NULL WHERE id = ?",
                    (user_dict['id'],)
                )
                conn.commit()
                self.update_last_login(user_dict['id'])
                return user_dict

            # Record the failed attempt
            cursor.execute(
                "UPDATE users SET failed_login_count = COALESCE(failed_login_count, 0) + 1, "
                "last_failed_login = ? WHERE id = ?",
                (datetime.utcnow().isoformat(), user_dict['id'])
            )
            conn.commit()
            return None
        finally:
            conn.close()

    def get_user(self, user_id: int) -> Optional[Dict]:
        """
        Get user by ID.

        Args:
            user_id: User ID

        Returns:
            User dict or None if not found
        """
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        row = cursor.fetchone()
        conn.close()
        return dict(row) if row else None

    def get_users_by_org(self, org_id: int) -> List[Dict]:
        """
        Get all active users in an organization.

        Args:
            org_id: Organization ID

        Returns:
            List of user dicts
        """
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, email, full_name, role, is_active, created_at, last_login "
            "FROM users WHERE org_id = ? AND is_active = 1 ORDER BY created_at DESC",
            (org_id,)
        )
        rows = cursor.fetchall()
        conn.close()
        return [dict(row) for row in rows]

    def update_user(self, user_id: int, **kwargs) -> bool:
        """
        Update user details.

        Args:
            user_id: User ID
            **kwargs: Fields to update (full_name, role, is_active)

        Returns:
            True if update successful
        """
        allowed_fields = {'full_name', 'role', 'is_active'}
        fields = {k: v for k, v in kwargs.items() if k in allowed_fields}

        if not fields:
            return False

        conn = self.get_connection()
        cursor = conn.cursor()
        set_clause = ", ".join([f"{field} = ?" for field in fields.keys()])
        values = list(fields.values()) + [user_id]

        cursor.execute(f"UPDATE users SET {set_clause} WHERE id = ?", values)
        conn.commit()
        success = cursor.rowcount > 0
        conn.close()
        return success

    def update_last_login(self, user_id: int) -> None:
        """
        Update user's last login timestamp.

        Args:
            user_id: User ID
        """
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?",
            (user_id,)
        )
        conn.commit()
        conn.close()

    # ==================== ORGANIZATION OPERATIONS ====================

    def create_organization(
        self,
        name: str,
        created_by: int,
        industry: Optional[str] = None,
        size: Optional[str] = None,
        sdf_status: Optional[str] = None,
        compliance_level: Optional[str] = None,
        subscription_tier: str = 'free',
        max_users: int = 5
    ) -> int:
        """
        Create a new organization.

        Args:
            name: Organization name (must be unique)
            created_by: User ID of creator
            industry: Industry type
            size: Organization size
            sdf_status: SDF status
            compliance_level: Current compliance level
            subscription_tier: 'free' or 'premium'
            max_users: Maximum users allowed

        Returns:
            Organization ID

        Raises:
            ValueError: If name already exists
        """
        conn = self.get_connection()
        cursor = conn.cursor()

        try:
            cursor.execute("""
                INSERT INTO organizations
                (name, created_by, industry, size, sdf_status, compliance_level,
                 subscription_tier, max_users)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (name, created_by, industry, size, sdf_status, compliance_level,
                  subscription_tier, max_users))
            conn.commit()
            org_id = cursor.lastrowid
            self.log_activity(org_id, "ORG_CREATED", f"Organization '{name}' created")
            return org_id
        except sqlite3.IntegrityError:
            raise ValueError(f"Organization '{name}' already exists")
        finally:
            conn.close()

    def get_organization(self, org_id: int) -> Optional[Dict]:
        """
        Get organization by ID.

        Args:
            org_id: Organization ID

        Returns:
            Organization dict or None
        """
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM organizations WHERE id = ?", (org_id,))
        row = cursor.fetchone()
        conn.close()
        return dict(row) if row else None

    def get_all_organizations(self) -> List[Dict]:
        """
        Get all organizations.

        Returns:
            List of organization dicts
        """
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM organizations ORDER BY created_at DESC")
        rows = cursor.fetchall()
        conn.close()
        return [dict(row) for row in rows]

    def update_organization(self, org_id: int, **kwargs) -> bool:
        """
        Update organization details.

        Args:
            org_id: Organization ID
            **kwargs: Fields to update

        Returns:
            True if update successful
        """
        allowed_fields = {
            'name', 'industry', 'size', 'sdf_status', 'compliance_level',
            'subscription_tier', 'max_users', 'created_by'
        }
        fields = {k: v for k, v in kwargs.items() if k in allowed_fields}

        if not fields:
            return False

        conn = self.get_connection()
        cursor = conn.cursor()
        set_clause = ", ".join([f"{field} = ?" for field in fields.keys()])
        values = list(fields.values()) + [org_id]

        try:
            cursor.execute(f"UPDATE organizations SET {set_clause}, updated_at = CURRENT_TIMESTAMP WHERE id = ?", values)
            conn.commit()
            success = cursor.rowcount > 0
        except sqlite3.IntegrityError:
            success = False
        finally:
            conn.close()

        return success

    def check_org_limits(self, org_id: int) -> Dict[str, int]:
        """
        Check organization subscription limits.

        Args:
            org_id: Organization ID

        Returns:
            Dict with current_users, max_users, users_remaining
        """
        org = self.get_organization(org_id)
        if not org:
            return {'current_users': 0, 'max_users': 0, 'users_remaining': 0}

        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) as count FROM users WHERE org_id = ? AND is_active = 1", (org_id,))
        row = cursor.fetchone()
        conn.close()

        current_users = row['count'] if row else 0
        max_users = org['max_users']
        users_remaining = max(0, max_users - current_users)

        return {
            'current_users': current_users,
            'max_users': max_users,
            'users_remaining': users_remaining
        }

    # ==================== INVITE OPERATIONS ====================

    def create_invite(self, org_id: int, email: str, role: str) -> str:
        """
        Create an invite token for a new user.

        Args:
            org_id: Organization ID
            email: Email to invite
            role: Role to assign (admin, member, viewer)

        Returns:
            Invite token

        Raises:
            ValueError: If invalid role
        """
        if role not in ('admin', 'member', 'viewer'):
            raise ValueError(f"Invalid role: {role}")

        token = secrets.token_urlsafe(16)
        expires_at = (datetime.utcnow() + timedelta(days=7)).strftime("%Y-%m-%d %H:%M:%S")

        conn = self.get_connection()
        cursor = conn.cursor()

        try:
            cursor.execute("""
                INSERT INTO invites (org_id, email, role, token, expires_at)
                VALUES (?, ?, ?, ?, ?)
            """, (org_id, email, role, token, expires_at))
            conn.commit()
            self.log_activity(org_id, "INVITE_CREATED", f"Invite created for {email}")
            return token
        finally:
            conn.close()

    def get_invite_by_token(self, token: str) -> Optional[Dict]:
        """
        Look up a pending, unexpired invite by its token.

        Args:
            token: Invite token (the invite code)

        Returns:
            Invite dict if valid (pending and unexpired), None otherwise
        """
        if not token:
            return None
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT * FROM invites
            WHERE token = ? AND status = 'pending' AND expires_at > CURRENT_TIMESTAMP
        """, (token,))
        row = cursor.fetchone()
        conn.close()
        return dict(row) if row else None

    def revoke_invite(self, org_id: int, invite_id: int) -> bool:
        """
        Revoke a pending invite (marks it expired so it can no longer be used).

        Args:
            org_id: Organization ID (for isolation)
            invite_id: Invite ID

        Returns:
            True if the invite was revoked
        """
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE invites SET status = 'expired' WHERE id = ? AND org_id = ? AND status = 'pending'",
            (invite_id, org_id)
        )
        conn.commit()
        success = cursor.rowcount > 0
        conn.close()
        if success:
            self.log_activity(org_id, "INVITE_REVOKED", f"Invite #{invite_id} revoked")
        return success

    def get_pending_invites(self, org_id: int) -> List[Dict]:
        """
        Get pending invites for an organization.

        Args:
            org_id: Organization ID

        Returns:
            List of invite dicts
        """
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT * FROM invites
            WHERE org_id = ? AND status = 'pending' AND expires_at > CURRENT_TIMESTAMP
            ORDER BY created_at DESC
        """, (org_id,))
        rows = cursor.fetchall()
        conn.close()
        return [dict(row) for row in rows]

    def accept_invite(self, token: str, user_id: int) -> bool:
        """
        Accept an invite and update status.

        Args:
            token: Invite token
            user_id: User ID accepting the invite

        Returns:
            True if successful
        """
        conn = self.get_connection()
        cursor = conn.cursor()

        try:
            cursor.execute(
                "SELECT * FROM invites WHERE token = ? AND status = 'pending'",
                (token,)
            )
            row = cursor.fetchone()

            if not row:
                return False

            invite = dict(row)
            cursor.execute(
                "UPDATE invites SET status = 'accepted' WHERE token = ?",
                (token,)
            )
            conn.commit()
            self.log_activity(invite["org_id"], "INVITE_ACCEPTED",
                            f"Invite accepted by user {user_id}")
            return True
        finally:
            conn.close()

    # ==================== ASSESSMENT OPERATIONS ====================

    def save_assessment_response(
        self,
        org_id: int,
        category: str,
        question_id: str,
        response: str
    ) -> bool:
        """
        Save or update an assessment response.

        Args:
            org_id: Organization ID
            category: Question category
            question_id: Question ID
            response: Response text

        Returns:
            True if successful
        """
        conn = self.get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            INSERT INTO assessment_responses
            (org_id, category, question_id, response)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(org_id, question_id) DO UPDATE SET
            response = excluded.response,
            updated_at = CURRENT_TIMESTAMP
        """, (org_id, category, question_id, response))

        conn.commit()
        conn.close()
        return True

    def get_assessment_responses(self, org_id: int) -> Dict[str, List[Dict]]:
        """
        Get all assessment responses for an organization.

        Args:
            org_id: Organization ID

        Returns:
            Dict mapping categories to lists of responses
        """
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT * FROM assessment_responses
            WHERE org_id = ?
            ORDER BY category, question_id
        """, (org_id,))
        rows = cursor.fetchall()
        conn.close()

        result = {}
        for row in rows:
            cat = row['category']
            if cat not in result:
                result[cat] = []
            result[cat].append(dict(row))

        return result

    def save_assessment_scores(
        self,
        org_id: int,
        overall_score: float,
        category_scores: Dict[str, float]
    ) -> int:
        """
        Save assessment scores.

        Args:
            org_id: Organization ID
            overall_score: Overall compliance score
            category_scores: Dict of category scores

        Returns:
            Assessment ID
        """
        conn = self.get_connection()
        cursor = conn.cursor()
        import json
        scores_json = json.dumps(category_scores)

        cursor.execute("""
            INSERT INTO assessments (org_id, overall_score, category_scores)
            VALUES (?, ?, ?)
        """, (org_id, overall_score, scores_json))

        conn.commit()
        assessment_id = cursor.lastrowid
        conn.close()
        return assessment_id

    def get_latest_assessment(self, org_id: int) -> Optional[Dict]:
        """
        Get the latest assessment for an organization.

        Args:
            org_id: Organization ID

        Returns:
            Assessment dict or None
        """
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT * FROM assessments
            WHERE org_id = ?
            ORDER BY assessment_date DESC
            LIMIT 1
        """, (org_id,))
        row = cursor.fetchone()
        conn.close()

        if not row:
            return None

        result = dict(row)
        import json
        result['category_scores'] = json.loads(result['category_scores'])
        return result

    # ==================== DOCUMENT OPERATIONS ====================

    def create_document(
        self,
        org_id: int,
        doc_type: str,
        title: str,
        content: str,
        status: str = 'DRAFT'
    ) -> int:
        """
        Create a new document.

        Args:
            org_id: Organization ID
            doc_type: Type of document
            title: Document title
            content: Document content
            status: Document status (DRAFT, PUBLISHED, etc.)

        Returns:
            Document ID
        """
        conn = self.get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            INSERT INTO documents (org_id, doc_type, title, content, status)
            VALUES (?, ?, ?, ?, ?)
        """, (org_id, doc_type, title, content, status))

        conn.commit()
        doc_id = cursor.lastrowid
        self.log_activity(org_id, "DOCUMENT_CREATED", f"Document '{title}' created")
        conn.close()
        return doc_id

    def get_documents(self, org_id: int, doc_type: Optional[str] = None) -> List[Dict]:
        """
        Get documents for an organization.

        Args:
            org_id: Organization ID
            doc_type: Optional filter by document type

        Returns:
            List of document dicts
        """
        conn = self.get_connection()
        cursor = conn.cursor()

        if doc_type:
            cursor.execute("""
                SELECT * FROM documents
                WHERE org_id = ? AND doc_type = ?
                ORDER BY created_at DESC
            """, (org_id, doc_type))
        else:
            cursor.execute("""
                SELECT * FROM documents
                WHERE org_id = ?
                ORDER BY created_at DESC
            """, (org_id,))

        rows = cursor.fetchall()
        conn.close()
        return [dict(row) for row in rows]

    def update_document(self, org_id: int, doc_id: int, **kwargs) -> bool:
        """
        Update a document.

        Args:
            org_id: Organization ID (for isolation check)
            doc_id: Document ID
            **kwargs: Fields to update (title, content, status)

        Returns:
            True if successful
        """
        allowed_fields = {'title', 'content', 'status'}
        fields = {k: v for k, v in kwargs.items() if k in allowed_fields}

        if not fields:
            return False

        conn = self.get_connection()
        cursor = conn.cursor()
        set_clause = ", ".join([f"{field} = ?" for field in fields.keys()])
        values = list(fields.values()) + [org_id, doc_id]

        cursor.execute(f"""
            UPDATE documents
            SET {set_clause}, updated_at = CURRENT_TIMESTAMP
            WHERE id = ? AND org_id = ?
        """, values)

        conn.commit()
        success = cursor.rowcount > 0
        conn.close()
        return success

    # ==================== COMPLIANCE TASKS ====================

    def create_task(
        self,
        org_id: int,
        title: str,
        category: str,
        priority: str,
        due_date: str,
        description: Optional[str] = None,
        assigned_to: Optional[str] = None
    ) -> int:
        """
        Create a compliance task.

        Args:
            org_id: Organization ID
            title: Task title
            category: Task category
            priority: Priority level
            due_date: Due date (YYYY-MM-DD)
            description: Optional description
            assigned_to: Optional assignment

        Returns:
            Task ID
        """
        conn = self.get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            INSERT INTO compliance_tasks
            (org_id, title, category, priority, due_date, description, assigned_to)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (org_id, title, category, priority, due_date, description, assigned_to))

        conn.commit()
        task_id = cursor.lastrowid
        self.log_activity(org_id, "TASK_CREATED", f"Task '{title}' created")
        conn.close()
        return task_id

    def get_tasks(self, org_id: int, status: Optional[str] = None) -> List[Dict]:
        """
        Get compliance tasks for an organization.

        Args:
            org_id: Organization ID
            status: Optional filter by status

        Returns:
            List of task dicts
        """
        conn = self.get_connection()
        cursor = conn.cursor()

        if status:
            cursor.execute("""
                SELECT * FROM compliance_tasks
                WHERE org_id = ? AND status = ?
                ORDER BY due_date ASC
            """, (org_id, status))
        else:
            cursor.execute("""
                SELECT * FROM compliance_tasks
                WHERE org_id = ?
                ORDER BY due_date ASC
            """, (org_id,))

        rows = cursor.fetchall()
        conn.close()
        return [dict(row) for row in rows]

    def update_task(self, org_id: int, task_id: int, **kwargs) -> bool:
        """
        Update a compliance task.

        Args:
            org_id: Organization ID (for isolation)
            task_id: Task ID
            **kwargs: Fields to update

        Returns:
            True if successful
        """
        allowed_fields = {'title', 'description', 'category', 'priority', 'status', 'due_date', 'assigned_to'}
        fields = {k: v for k, v in kwargs.items() if k in allowed_fields}

        if not fields:
            return False

        conn = self.get_connection()
        cursor = conn.cursor()
        set_clause = ", ".join([f"{field} = ?" for field in fields.keys()])
        values = list(fields.values()) + [org_id, task_id]

        cursor.execute(f"""
            UPDATE compliance_tasks
            SET {set_clause}, updated_at = CURRENT_TIMESTAMP
            WHERE id = ? AND org_id = ?
        """, values)

        conn.commit()
        success = cursor.rowcount > 0
        conn.close()
        return success

    # ==================== BREACH INCIDENTS ====================

    def create_breach_incident(
        self,
        org_id: int,
        incident_date: str,
        description: str,
        severity: str,
        data_affected: Optional[str] = None,
        notes: Optional[str] = None
    ) -> int:
        """
        Create a breach incident record.

        Args:
            org_id: Organization ID
            incident_date: Date of incident (ISO format)
            description: Incident description
            severity: Severity level
            data_affected: Data categories affected
            notes: Additional notes

        Returns:
            Incident ID
        """
        conn = self.get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            INSERT INTO breach_incidents
            (org_id, incident_date, description, severity, data_affected, notes)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (org_id, incident_date, description, severity, data_affected, notes))

        conn.commit()
        incident_id = cursor.lastrowid
        self.log_activity(org_id, "BREACH_REPORTED", f"Breach incident #{incident_id} reported")
        conn.close()
        return incident_id

    def get_breach_incidents(self, org_id: int) -> List[Dict]:
        """
        Get all breach incidents for an organization.

        Args:
            org_id: Organization ID

        Returns:
            List of incident dicts
        """
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT * FROM breach_incidents
            WHERE org_id = ?
            ORDER BY incident_date DESC
        """, (org_id,))
        rows = cursor.fetchall()
        conn.close()
        return [dict(row) for row in rows]

    def update_breach_incident(self, org_id: int, incident_id: int, **kwargs) -> bool:
        """
        Update a breach incident.

        Args:
            org_id: Organization ID (for isolation)
            incident_id: Incident ID
            **kwargs: Fields to update

        Returns:
            True if successful
        """
        allowed_fields = {'status', 'authority_notified', 'authority_date', 'notes'}
        fields = {k: v for k, v in kwargs.items() if k in allowed_fields}

        if not fields:
            return False

        conn = self.get_connection()
        cursor = conn.cursor()
        set_clause = ", ".join([f"{field} = ?" for field in fields.keys()])
        values = list(fields.values()) + [org_id, incident_id]

        cursor.execute(f"""
            UPDATE breach_incidents
            SET {set_clause}, updated_at = CURRENT_TIMESTAMP
            WHERE id = ? AND org_id = ?
        """, values)

        conn.commit()
        success = cursor.rowcount > 0
        conn.close()
        return success

    # ==================== ROPA ENTRIES ====================

    def create_ropa_entry(
        self,
        org_id: int,
        activity_name: str,
        data_categories: str,
        data_subjects: str,
        purpose: str,
        lawful_basis: str,
        **kwargs
    ) -> int:
        """
        Create a Records of Processing Activities entry.

        Args:
            org_id: Organization ID
            activity_name: Name of processing activity
            data_categories: Categories of personal data
            data_subjects: Categories of data subjects
            purpose: Purpose of processing
            lawful_basis: Legal basis for processing
            **kwargs: Optional fields (department, retention_period, etc.)

        Returns:
            RoPA entry ID
        """
        conn = self.get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            INSERT INTO ropa_entries
            (org_id, activity_name, data_categories, data_subjects, purpose, lawful_basis,
             department, retention_period, data_processor, processing_location, security_measures, cross_border)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (org_id, activity_name, data_categories, data_subjects, purpose, lawful_basis,
              kwargs.get('department'), kwargs.get('retention_period'), kwargs.get('data_processor'),
              kwargs.get('processing_location'), kwargs.get('security_measures'), kwargs.get('cross_border', 0)))

        conn.commit()
        entry_id = cursor.lastrowid
        self.log_activity(org_id, "ROPA_CREATED", f"RoPA entry '{activity_name}' created")
        conn.close()
        return entry_id

    def get_ropa_entries(self, org_id: int) -> List[Dict]:
        """
        Get all RoPA entries for an organization.

        Args:
            org_id: Organization ID

        Returns:
            List of RoPA entry dicts
        """
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT * FROM ropa_entries
            WHERE org_id = ? AND status = 'ACTIVE'
            ORDER BY created_at DESC
        """, (org_id,))
        rows = cursor.fetchall()
        conn.close()
        return [dict(row) for row in rows]

    # ==================== CONSENT RECORDS ====================

    def create_consent_record(
        self,
        org_id: int,
        purpose: str,
        data_categories: str,
        mechanism: str,
        **kwargs
    ) -> int:
        """
        Create a consent record.

        Args:
            org_id: Organization ID
            purpose: Purpose of data processing
            data_categories: Categories of data
            mechanism: Consent mechanism (e.g., checkbox, verbal)
            **kwargs: Optional fields

        Returns:
            Consent record ID
        """
        conn = self.get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            INSERT INTO consent_records
            (org_id, purpose, data_categories, mechanism, consent_text, withdrawal_method, is_children)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (org_id, purpose, data_categories, mechanism, kwargs.get('consent_text'),
              kwargs.get('withdrawal_method'), kwargs.get('is_children', 0)))

        conn.commit()
        consent_id = cursor.lastrowid
        self.log_activity(org_id, "CONSENT_CREATED", f"Consent record created for '{purpose}'")
        conn.close()
        return consent_id

    def get_consent_records(self, org_id: int) -> List[Dict]:
        """
        Get all consent records for an organization.

        Args:
            org_id: Organization ID

        Returns:
            List of consent record dicts
        """
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT * FROM consent_records
            WHERE org_id = ? AND status = 'ACTIVE'
            ORDER BY created_at DESC
        """, (org_id,))
        rows = cursor.fetchall()
        conn.close()
        return [dict(row) for row in rows]

    # ==================== PRIVACY NOTICES ====================

    def create_privacy_notice(
        self,
        org_id: int,
        notice_type: str,
        title: str,
        data_categories: str,
        purposes: str,
        **kwargs
    ) -> int:
        """
        Create a privacy notice.

        Args:
            org_id: Organization ID
            notice_type: Type of notice
            title: Notice title
            data_categories: Data categories covered
            purposes: Processing purposes
            **kwargs: Optional fields

        Returns:
            Privacy notice ID
        """
        conn = self.get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            INSERT INTO privacy_notices
            (org_id, notice_type, title, data_categories, purposes, third_parties,
             retention_info, rights_info, grievance_info)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (org_id, notice_type, title, data_categories, purposes, kwargs.get('third_parties'),
              kwargs.get('retention_info'), kwargs.get('rights_info'), kwargs.get('grievance_info')))

        conn.commit()
        notice_id = cursor.lastrowid
        self.log_activity(org_id, "NOTICE_CREATED", f"Privacy notice '{title}' created")
        conn.close()
        return notice_id

    def get_privacy_notices(self, org_id: int) -> List[Dict]:
        """
        Get all privacy notices for an organization.

        Args:
            org_id: Organization ID

        Returns:
            List of privacy notice dicts
        """
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT * FROM privacy_notices
            WHERE org_id = ?
            ORDER BY created_at DESC
        """, (org_id,))
        rows = cursor.fetchall()
        conn.close()
        return [dict(row) for row in rows]

    # ==================== DATA SUBJECT RIGHTS REQUESTS ====================

    def create_rights_request(
        self,
        org_id: int,
        request_type: str,
        requester_name: str,
        **kwargs
    ) -> int:
        """
        Create a data subject rights request (DSR).

        Args:
            org_id: Organization ID
            request_type: Type of request (access, deletion, portability, etc.)
            requester_name: Name of requester
            **kwargs: Optional fields (email, description, etc.)

        Returns:
            Request ID
        """
        conn = self.get_connection()
        cursor = conn.cursor()

        # Due date is 30 days from now (DPDPA requirement)
        due_date = (datetime.utcnow() + timedelta(days=30)).date()

        cursor.execute("""
            INSERT INTO rights_requests
            (org_id, request_type, requester_name, requester_email, description, due_date)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (org_id, request_type, requester_name, kwargs.get('requester_email'),
              kwargs.get('description'), due_date))

        conn.commit()
        request_id = cursor.lastrowid
        self.log_activity(org_id, "DSR_RECEIVED", f"Data subject {request_type} request received")
        conn.close()
        return request_id

    def get_rights_requests(self, org_id: int, status: Optional[str] = None) -> List[Dict]:
        """
        Get data subject rights requests for an organization.

        Args:
            org_id: Organization ID
            status: Optional filter by status

        Returns:
            List of request dicts
        """
        conn = self.get_connection()
        cursor = conn.cursor()

        if status:
            cursor.execute("""
                SELECT * FROM rights_requests
                WHERE org_id = ? AND status = ?
                ORDER BY due_date ASC
            """, (org_id, status))
        else:
            cursor.execute("""
                SELECT * FROM rights_requests
                WHERE org_id = ?
                ORDER BY due_date ASC
            """, (org_id,))

        rows = cursor.fetchall()
        conn.close()
        return [dict(row) for row in rows]

    def update_rights_request(self, org_id: int, request_id: int, **kwargs) -> bool:
        """
        Update a data subject rights request.

        Args:
            org_id: Organization ID (for isolation)
            request_id: Request ID
            **kwargs: Fields to update (status, identity_verified, response_notes)

        Returns:
            True if successful
        """
        allowed_fields = {'status', 'identity_verified', 'response_notes'}
        fields = {k: v for k, v in kwargs.items() if k in allowed_fields}

        if not fields:
            return False

        conn = self.get_connection()
        cursor = conn.cursor()
        set_clause = ", ".join([f"{field} = ?" for field in fields.keys()])
        values = list(fields.values()) + [org_id, request_id]

        cursor.execute(f"""
            UPDATE rights_requests
            SET {set_clause}, updated_at = CURRENT_TIMESTAMP
            WHERE id = ? AND org_id = ?
        """, values)

        conn.commit()
        success = cursor.rowcount > 0
        conn.close()
        return success

    # ==================== VENDOR MANAGEMENT ====================

    def create_vendor(
        self,
        org_id: int,
        vendor_name: str,
        service_type: str,
        data_shared: str,
        **kwargs
    ) -> int:
        """
        Create a vendor record.

        Args:
            org_id: Organization ID
            vendor_name: Vendor name
            service_type: Type of service provided
            data_shared: Data shared with vendor
            **kwargs: Optional fields

        Returns:
            Vendor ID
        """
        conn = self.get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            INSERT INTO vendors
            (org_id, vendor_name, service_type, data_shared, dpa_status, risk_level, notes)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (org_id, vendor_name, service_type, data_shared, kwargs.get('dpa_status', 'NOT_STARTED'),
              kwargs.get('risk_level', 'MEDIUM'), kwargs.get('notes')))

        conn.commit()
        vendor_id = cursor.lastrowid
        self.log_activity(org_id, "VENDOR_CREATED", f"Vendor '{vendor_name}' added")
        conn.close()
        return vendor_id

    def get_vendors(self, org_id: int) -> List[Dict]:
        """
        Get all vendors for an organization.

        Args:
            org_id: Organization ID

        Returns:
            List of vendor dicts
        """
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT * FROM vendors
            WHERE org_id = ? AND status = 'ACTIVE'
            ORDER BY vendor_name ASC
        """, (org_id,))
        rows = cursor.fetchall()
        conn.close()
        return [dict(row) for row in rows]

    def update_vendor(self, org_id: int, vendor_id: int, **kwargs) -> bool:
        """
        Update a vendor record.

        Args:
            org_id: Organization ID (for isolation)
            vendor_id: Vendor ID
            **kwargs: Fields to update

        Returns:
            True if successful
        """
        allowed_fields = {
            'vendor_name', 'service_type', 'data_shared', 'dpa_status', 'security_rating',
            'iso_certified', 'soc2_certified', 'last_assessment_date', 'risk_level', 'notes'
        }
        fields = {k: v for k, v in kwargs.items() if k in allowed_fields}

        if not fields:
            return False

        conn = self.get_connection()
        cursor = conn.cursor()
        set_clause = ", ".join([f"{field} = ?" for field in fields.keys()])
        values = list(fields.values()) + [org_id, vendor_id]

        cursor.execute(f"""
            UPDATE vendors
            SET {set_clause}, updated_at = CURRENT_TIMESTAMP
            WHERE id = ? AND org_id = ?
        """, values)

        conn.commit()
        success = cursor.rowcount > 0
        conn.close()
        return success

    # ==================== DPIA RECORDS ====================

    def create_dpia_record(
        self,
        org_id: int,
        project_name: str,
        processing_description: str,
        **kwargs
    ) -> int:
        """
        Create a Data Protection Impact Assessment record.

        Args:
            org_id: Organization ID
            project_name: Name of project being assessed
            processing_description: Description of processing activity
            **kwargs: Optional fields

        Returns:
            DPIA record ID
        """
        conn = self.get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            INSERT INTO dpia_records
            (org_id, project_name, processing_description, necessity_assessment,
             risk_assessment, mitigation_measures, risk_level, approved_by)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (org_id, project_name, processing_description, kwargs.get('necessity_assessment'),
              kwargs.get('risk_assessment'), kwargs.get('mitigation_measures'),
              kwargs.get('risk_level', 'MEDIUM'), kwargs.get('approved_by')))

        conn.commit()
        dpia_id = cursor.lastrowid
        self.log_activity(org_id, "DPIA_CREATED", f"DPIA for '{project_name}' created")
        conn.close()
        return dpia_id

    def get_dpia_records(self, org_id: int) -> List[Dict]:
        """
        Get all DPIA records for an organization.

        Args:
            org_id: Organization ID

        Returns:
            List of DPIA record dicts
        """
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT * FROM dpia_records
            WHERE org_id = ?
            ORDER BY created_at DESC
        """, (org_id,))
        rows = cursor.fetchall()
        conn.close()
        return [dict(row) for row in rows]

    def update_dpia_record(self, org_id: int, dpia_id: int, **kwargs) -> bool:
        """
        Update a DPIA record.

        Args:
            org_id: Organization ID (for isolation)
            dpia_id: DPIA record ID
            **kwargs: Fields to update

        Returns:
            True if successful
        """
        allowed_fields = {
            'project_name', 'processing_description', 'necessity_assessment',
            'risk_assessment', 'mitigation_measures', 'risk_level', 'status', 'approved_by', 'review_date'
        }
        fields = {k: v for k, v in kwargs.items() if k in allowed_fields}

        if not fields:
            return False

        conn = self.get_connection()
        cursor = conn.cursor()
        set_clause = ", ".join([f"{field} = ?" for field in fields.keys()])
        values = list(fields.values()) + [org_id, dpia_id]

        cursor.execute(f"""
            UPDATE dpia_records
            SET {set_clause}, updated_at = CURRENT_TIMESTAMP
            WHERE id = ? AND org_id = ?
        """, values)

        conn.commit()
        success = cursor.rowcount > 0
        conn.close()
        return success

    # ==================== ACTIVITY LOGGING ====================

    def log_activity(
        self,
        org_id: int,
        action_type: str,
        description: str,
        user_id: Optional[int] = None,
        entity_type: Optional[str] = None,
        entity_id: Optional[int] = None
    ) -> int:
        """
        Log an activity to the audit trail.

        Args:
            org_id: Organization ID
            user_id: User ID performing the action (optional)
            action_type: Type of action
            description: Description of action
            entity_type: Type of entity affected
            entity_id: ID of entity affected

        Returns:
            Activity log ID
        """
        conn = self.get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            INSERT INTO activity_log
            (org_id, user_id, action_type, description, entity_type, entity_id)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (org_id, user_id, action_type, description, entity_type, entity_id))

        conn.commit()
        activity_id = cursor.lastrowid
        conn.close()
        return activity_id

    def get_activity_log(self, org_id: int, limit: int = 100) -> List[Dict]:
        """
        Get activity log for an organization.

        Args:
            org_id: Organization ID
            limit: Maximum number of entries to return

        Returns:
            List of activity log entries
        """
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT * FROM activity_log
            WHERE org_id = ?
            ORDER BY created_at DESC
            LIMIT ?
        """, (org_id, limit))
        rows = cursor.fetchall()
        conn.close()
        return [dict(row) for row in rows]

    # ==================== DASHBOARD STATISTICS ====================

    def get_dashboard_stats(self, org_id: int) -> Dict[str, Any]:
        """
        Get comprehensive dashboard statistics for an organization.
        Enforces multi-tenant isolation by only returning data for the specified org_id.

        Args:
            org_id: Organization ID

        Returns:
            Dict with counts for all tracked entities and compliance status
        """
        conn = self.get_connection()
        cursor = conn.cursor()

        stats = {'org_id': org_id}

        # Count users
        cursor.execute("SELECT COUNT(*) as count FROM users WHERE org_id = ? AND is_active = 1", (org_id,))
        stats['total_users'] = cursor.fetchone()['count']

        # Count assessments
        cursor.execute("SELECT COUNT(*) as count FROM assessments WHERE org_id = ?", (org_id,))
        stats['total_assessments'] = cursor.fetchone()['count']

        # Count documents
        cursor.execute("SELECT COUNT(*) as count FROM documents WHERE org_id = ?", (org_id,))
        stats['total_documents'] = cursor.fetchone()['count']

        # Count compliance tasks
        cursor.execute("SELECT COUNT(*) as count FROM compliance_tasks WHERE org_id = ? AND status != 'COMPLETED'", (org_id,))
        stats['pending_tasks'] = cursor.fetchone()['count']

        # Count breach incidents
        cursor.execute("SELECT COUNT(*) as count FROM breach_incidents WHERE org_id = ? AND status = 'OPEN'", (org_id,))
        stats['open_breaches'] = cursor.fetchone()['count']

        # Count RoPA entries
        cursor.execute("SELECT COUNT(*) as count FROM ropa_entries WHERE org_id = ? AND status = 'ACTIVE'", (org_id,))
        stats['ropa_entries'] = cursor.fetchone()['count']

        # Count consent records
        cursor.execute("SELECT COUNT(*) as count FROM consent_records WHERE org_id = ? AND status = 'ACTIVE'", (org_id,))
        stats['consent_records'] = cursor.fetchone()['count']

        # Count privacy notices
        cursor.execute("SELECT COUNT(*) as count FROM privacy_notices WHERE org_id = ?", (org_id,))
        stats['privacy_notices'] = cursor.fetchone()['count']

        # Count pending DSRs (data subject rights)
        cursor.execute("SELECT COUNT(*) as count FROM rights_requests WHERE org_id = ? AND status IN ('RECEIVED', 'IN_PROGRESS')", (org_id,))
        stats['pending_dsrs'] = cursor.fetchone()['count']

        # Count vendors
        cursor.execute("SELECT COUNT(*) as count FROM vendors WHERE org_id = ? AND status = 'ACTIVE'", (org_id,))
        stats['vendors'] = cursor.fetchone()['count']

        # Count DPIAs
        cursor.execute("SELECT COUNT(*) as count FROM dpia_records WHERE org_id = ?", (org_id,))
        stats['dpia_records'] = cursor.fetchone()['count']

        # Get latest assessment score
        cursor.execute("""
            SELECT overall_score FROM assessments
            WHERE org_id = ?
            ORDER BY assessment_date DESC
            LIMIT 1
        """, (org_id,))
        row = cursor.fetchone()
        stats['latest_compliance_score'] = row['overall_score'] if row else None

        # Count overdue tasks
        cursor.execute("""
            SELECT COUNT(*) as count FROM compliance_tasks
            WHERE org_id = ? AND status != 'COMPLETED' AND due_date < DATE('now')
        """, (org_id,))
        stats['overdue_tasks'] = cursor.fetchone()['count']

        # Count overdue DSRs
        cursor.execute("""
            SELECT COUNT(*) as count FROM rights_requests
            WHERE org_id = ? AND status IN ('RECEIVED', 'IN_PROGRESS') AND due_date < DATE('now')
        """, (org_id,))
        stats['overdue_dsrs'] = cursor.fetchone()['count']

        conn.close()
        return stats

    # ==================== MISSING CRUD METHODS ====================

    def delete_ropa_entry(self, entry_id: int) -> bool:
        """Delete a RoPA entry"""
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM ropa_entries WHERE id = ?", (entry_id,))
        conn.commit()
        success = cursor.rowcount > 0
        conn.close()
        return success

    def update_ropa_entry(self, entry_id: int, **kwargs) -> bool:
        """Update a RoPA entry"""
        return self._generic_update('ropa_entries', entry_id, **kwargs)

    def delete_consent_record(self, record_id: int) -> bool:
        """Delete a consent record"""
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM consent_records WHERE id = ?", (record_id,))
        conn.commit()
        success = cursor.rowcount > 0
        conn.close()
        return success

    def update_consent_record(self, record_id: int, **kwargs) -> bool:
        """Update a consent record"""
        return self._generic_update('consent_records', record_id, **kwargs)

    def update_privacy_notice(self, notice_id: int, **kwargs) -> bool:
        """Update a privacy notice"""
        return self._generic_update('privacy_notices', notice_id, **kwargs)

    def delete_vendor(self, vendor_id: int) -> bool:
        """Delete a vendor"""
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM vendors WHERE id = ?", (vendor_id,))
        conn.commit()
        success = cursor.rowcount > 0
        conn.close()
        return success

    def update_rights_request_status(self, request_id: int, status: str) -> bool:
        """Update rights request status"""
        return self._generic_update('rights_requests', request_id, status=status)

    def update_rights_request_notes(self, request_id: int, response_notes: str) -> bool:
        """Update rights request response notes"""
        return self._generic_update('rights_requests', request_id, response_notes=response_notes)

    # Compatibility aliases for old method names
    def save_assessment(self, org_id: int) -> Dict:
        """Calculate assessment scores from responses and save them"""
        responses = self.get_assessment_responses(org_id)
        response_scores = {"Yes": 1.0, "Partially": 0.5, "No": 0.0}
        category_scores = {}

        for category, questions in config.GAP_ASSESSMENT_QUESTIONS.items():
            if category not in responses:
                category_scores[category] = 0.0
                continue
            response_dict = {r["question_id"]: r["response"] for r in responses[category]}
            scores = [response_scores.get(response_dict.get(q["id"], "No"), 0.0) for q in questions]
            category_scores[category] = (sum(scores) / len(scores)) * 100 if scores else 0.0

        weights = config.get_all_category_weights()
        overall_score = sum(category_scores.get(cat, 0) * weight for cat, weight in weights.items()) / 100

        self.save_assessment_scores(org_id, overall_score, category_scores)
        return {"overall_score": overall_score, "category_scores": category_scores}

    def calculate_assessment_score(self, org_id: int):
        """Alias for save_assessment"""
        return self.save_assessment(org_id)

    # Allowlist of tables (and their updatable columns) usable via _generic_update.
    # Prevents SQL injection through table/column name interpolation.
    _GENERIC_UPDATE_ALLOWLIST = {
        'ropa_entries': {
            'activity_name', 'department', 'data_categories', 'data_subjects',
            'purpose', 'lawful_basis', 'retention_period', 'data_processor',
            'processing_location', 'security_measures', 'cross_border', 'status'
        },
        'consent_records': {
            'purpose', 'data_categories', 'mechanism', 'consent_text',
            'withdrawal_method', 'is_children', 'status'
        },
        'privacy_notices': {
            'notice_type', 'title', 'data_categories', 'purposes', 'third_parties',
            'retention_info', 'rights_info', 'grievance_info', 'version', 'status'
        },
        'rights_requests': {
            'request_type', 'requester_name', 'requester_email', 'description',
            'identity_verified', 'status', 'due_date', 'response_notes'
        },
    }

    def _generic_update(self, table: str, record_id: int, **kwargs) -> bool:
        """Generic update method restricted to allowlisted tables and columns."""
        allowed_columns = self._GENERIC_UPDATE_ALLOWLIST.get(table)
        if allowed_columns is None:
            raise ValueError(f"Table not allowed for generic update: {table}")

        fields = {k: v for k, v in kwargs.items() if k in allowed_columns}
        if not fields:
            return False

        conn = self.get_connection()
        cursor = conn.cursor()
        set_clause = ", ".join([f"{k} = ?" for k in fields.keys()])
        values = list(fields.values()) + [record_id]
        cursor.execute(f"UPDATE {table} SET {set_clause}, updated_at = CURRENT_TIMESTAMP WHERE id = ?", values)
        conn.commit()
        success = cursor.rowcount > 0
        conn.close()
        return success
