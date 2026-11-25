import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

DB_PATH = Path("vaultguard.db")


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def init_db() -> None:
    """Creates core PAM & IGA tables if they do not exist."""
    with get_connection() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS identities (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                email TEXT,
                identity_type TEXT NOT NULL CHECK(identity_type IN ('HUMAN', 'NHI')),
                department TEXT NOT NULL,
                role TEXT NOT NULL,
                status TEXT NOT NULL CHECK(status IN ('ACTIVE', 'TERMINATED', 'DORMANT')),
                standing_privileges TEXT NOT NULL DEFAULT '[]',
                last_login_days INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS secrets (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL UNIQUE,
                owner_id TEXT NOT NULL,
                secret_type TEXT NOT NULL,
                encrypted_value TEXT NOT NULL,
                version INTEGER NOT NULL DEFAULT 1,
                rotation_interval_days INTEGER NOT NULL DEFAULT 30,
                last_rotated_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                FOREIGN KEY (owner_id) REFERENCES identities(id)
            );

            CREATE TABLE IF NOT EXISTS jit_grants (
                id TEXT PRIMARY KEY,
                identity_id TEXT NOT NULL,
                target_resource TEXT NOT NULL,
                elevated_role TEXT NOT NULL,
                reason TEXT NOT NULL,
                status TEXT NOT NULL CHECK(status IN ('ACTIVE', 'EXPIRED', 'REVOKED')),
                granted_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                FOREIGN KEY (identity_id) REFERENCES identities(id)
            );

            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                actor_id TEXT NOT NULL,
                action TEXT NOT NULL,
                target TEXT NOT NULL,
                status TEXT NOT NULL,
                details TEXT
            );
            """
        )


def log_audit_event(
    actor_id: str,
    action: str,
    target: str,
    status: str = "SUCCESS",
    details: Optional[str] = None,
) -> None:
    """Appends an immutable event record to the privileged audit trail."""
    with get_connection() as conn:
        conn.execute(
            """
            INSERT INTO audit_logs (timestamp, actor_id, action, target, status, details)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (utc_now_iso(), actor_id, action, target, status, details or ""),
        )


if __name__ == "__main__":
    init_db()
    log_audit_event("SYSTEM", "DB_INIT", "vaultguard.db", "SUCCESS", "Initialized PAM/IGA schema")
    print(f"[OK] SQLite schema initialized at {DB_PATH.resolve()}")