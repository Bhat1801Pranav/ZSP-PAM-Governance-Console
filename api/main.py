import json
import uuid
from datetime import datetime, timedelta, timezone
from typing import List, Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from core.crypto_vault import CryptoVault
from core.database import get_connection, init_db, log_audit_event
from core.governance import run_governance_audit, seed_org_data

app = FastAPI(
    title="ZSP-PAM-Governance-Console API",
    description="Zero Standing Privilege (ZSP), Privileged Access Management (PAM), and AI/NHI Access Governance backend.",
    version="0.1.0",
)

vault = CryptoVault()


@app.on_event("startup")
def on_startup() -> None:
    init_db()
    seed_org_data()


# --- Request Models ---
class SecretCreateRequest(BaseModel):
    name: str = Field(..., min_length=2, max_length=100)
    owner_id: str
    secret_type: str = Field(default="API_KEY")
    plaintext_value: Optional[str] = None
    rotation_interval_days: int = Field(default=30, ge=1, le=365)


class JitElevationRequest(BaseModel):
    identity_id: str
    target_resource: str
    elevated_role: str
    reason: str = Field(..., min_length=5, max_length=300)
    duration_minutes: int = Field(default=15, ge=1, le=480)


class RemediationRequest(BaseModel):
    action: str = Field(default="REVOKE_HIGH_RISK")  # REVOKE_HIGH_RISK | DEPROVISION | CLEAR_ALL_PRIVS


# --- Helper ---
def _parse_iso(ts: str) -> datetime:
    dt = datetime.fromisoformat(ts)
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


# --- Routes ---
@app.get("/health")
def health_check() -> dict:
    return {"status": "ok", "service": "ZSP-PAM-Governance-Console"}


@app.get("/identities")
def list_identities(identity_type: Optional[str] = None) -> List[dict]:
    query = "SELECT * FROM identities"
    params: list = []
    if identity_type in {"HUMAN", "NHI"}:
        query += " WHERE identity_type = ?"
        params.append(identity_type)
    query += " ORDER BY id"

    with get_connection() as conn:
        rows = conn.execute(query, params).fetchall()

    return [
        {
            "id": r["id"],
            "name": r["name"],
            "email": r["email"],
            "identity_type": r["identity_type"],
            "department": r["department"],
            "role": r["role"],
            "status": r["status"],
            "standing_privileges": json.loads(r["standing_privileges"]),
            "last_login_days": r["last_login_days"],
        }
        for r in rows
    ]


@app.get("/audit")
def get_governance_audit() -> dict:
    report = run_governance_audit()
    log_audit_event(
        "API_CLIENT",
        "GOVERNANCE_AUDIT",
        "identities",
        "SUCCESS",
        f"Score={report['posture_score']}%, Findings={report['total_findings']}",
    )
    return report


@app.post("/remediate/{identity_id}")
def remediate_identity(identity_id: str, req: RemediationRequest) -> dict:
    with get_connection() as conn:
        row = conn.execute("SELECT * FROM identities WHERE id = ?", (identity_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail=f"Identity '{identity_id}' not found.")

        privs = json.loads(row["standing_privileges"])
        new_status = row["status"]

        if req.action == "DEPROVISION":
            new_status = "TERMINATED"
            new_privs = []
        elif req.action == "CLEAR_ALL_PRIVS":
            new_privs = []
        else:
            # Default: strip high-risk standing privileges to enforce ZSP
            high_risk = {
                "aws_root_console",
                "domain_admin",
                "prod_db_admin",
                "k8s_cluster_admin",
                "s3_full_access",
                "audit_log_delete",
            }
            new_privs = [p for p in privs if p not in high_risk]

        conn.execute(
            "UPDATE identities SET status = ?, standing_privileges = ? WHERE id = ?",
            (new_status, json.dumps(new_privs), identity_id),
        )

    log_audit_event(
        "IAM_ADMIN",
        f"REMEDIATE_{req.action}",
        identity_id,
        "SUCCESS",
        f"Privileges {privs} -> {new_privs}, Status -> {new_status}",
    )
    return {
        "identity_id": identity_id,
        "action": req.action,
        "status": new_status,
        "standing_privileges": new_privs,
    }


@app.get("/secrets")
def list_secrets() -> List[dict]:
    now = datetime.now(timezone.utc)
    with get_connection() as conn:
        rows = conn.execute(
            """
            SELECT id, name, owner_id, secret_type, version, rotation_interval_days, last_rotated_at, expires_at
            FROM secrets ORDER BY id
            """
        ).fetchall()

    results = []
    for r in rows:
        exp_dt = _parse_iso(r["expires_at"])
        days_left = max(0, int((exp_dt - now).total_seconds() // 86400))
        results.append(
            {
                "id": r["id"],
                "name": r["name"],
                "owner_id": r["owner_id"],
                "secret_type": r["secret_type"],
                "version": r["version"],
                "rotation_interval_days": r["rotation_interval_days"],
                "last_rotated_at": r["last_rotated_at"],
                "expires_at": r["expires_at"],
                "days_until_expiry": days_left,
            }
        )
    return results


@app.post("/secrets")
def create_secret(req: SecretCreateRequest) -> dict:
    with get_connection() as conn:
        owner = conn.execute("SELECT id FROM identities WHERE id = ?", (req.owner_id,)).fetchone()
        if not owner:
            raise HTTPException(status_code=404, detail=f"Owner '{req.owner_id}' not found.")

        existing = conn.execute("SELECT id FROM secrets WHERE name = ?", (req.name,)).fetchone()
        if existing:
            raise HTTPException(status_code=409, detail=f"Secret '{req.name}' already exists.")

        plaintext = req.plaintext_value or vault.generate_secret("zg")
        encrypted = vault.encrypt(plaintext)
        now = datetime.now(timezone.utc)
        expires_at = (now + timedelta(days=req.rotation_interval_days)).isoformat()
        sec_id = f"SEC-{uuid.uuid4().hex[:6].upper()}"

        conn.execute(
            """
            INSERT INTO secrets
            (id, name, owner_id, secret_type, encrypted_value, version, rotation_interval_days, last_rotated_at, expires_at)
            VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?)
            """,
            (
                sec_id,
                req.name,
                req.owner_id,
                req.secret_type,
                encrypted,
                req.rotation_interval_days,
                now.isoformat(),
                expires_at,
            ),
        )

    log_audit_event("IAM_ADMIN", "SECRET_CREATE", req.name, "SUCCESS", f"Owner={req.owner_id}, Type={req.secret_type}")
    return {"id": sec_id, "name": req.name, "owner_id": req.owner_id, "version": 1, "expires_at": expires_at}


@app.post("/secrets/{secret_name}/checkout")
def checkout_secret(secret_name: str, requester_id: str = "USR-001") -> dict:
    with get_connection() as conn:
        row = conn.execute("SELECT * FROM secrets WHERE name = ?", (secret_name,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail=f"Secret '{secret_name}' not found.")

    try:
        secret_value = vault.decrypt(row["encrypted_value"])
    except ValueError as exc:
        log_audit_event(requester_id, "SECRET_CHECKOUT", secret_name, "FAILED", str(exc))
        raise HTTPException(status_code=500, detail=str(exc)) from exc

    log_audit_event(
        requester_id,
        "SECRET_CHECKOUT",
        secret_name,
        "SUCCESS",
        f"Checked out v{row['version']} ({row['secret_type']})",
    )
    return {
        "name": row["name"],
        "secret_type": row["secret_type"],
        "version": row["version"],
        "secret_value": secret_value,
        "checked_out_by": requester_id,
    }


@app.post("/secrets/{secret_name}/rotate")
def rotate_secret(secret_name: str, actor_id: str = "PAM_ROTATOR") -> dict:
    with get_connection() as conn:
        row = conn.execute("SELECT * FROM secrets WHERE name = ?", (secret_name,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail=f"Secret '{secret_name}' not found.")

        new_plain = vault.generate_secret("zg_rot")
        new_enc = vault.encrypt(new_plain)
        new_version = int(row["version"]) + 1
        now = datetime.now(timezone.utc)
        new_expires = (now + timedelta(days=int(row["rotation_interval_days"]))).isoformat()

        conn.execute(
            """
            UPDATE secrets
            SET encrypted_value = ?, version = ?, last_rotated_at = ?, expires_at = ?
            WHERE name = ?
            """,
            (new_enc, new_version, now.isoformat(), new_expires, secret_name),
        )

    log_audit_event(
        actor_id,
        "SECRET_ROTATE",
        secret_name,
        "SUCCESS",
        f"Rotated to v{new_version}; next expiry {new_expires}",
    )
    return {
        "name": secret_name,
        "version": new_version,
        "last_rotated_at": now.isoformat(),
        "expires_at": new_expires,
        "new_secret_preview": f"{new_plain[:12]}...",
    }


@app.post("/jit/request")
def request_jit_elevation(req: JitElevationRequest) -> dict:
    with get_connection() as conn:
        ident = conn.execute("SELECT id, status FROM identities WHERE id = ?", (req.identity_id,)).fetchone()
        if not ident:
            raise HTTPException(status_code=404, detail=f"Identity '{req.identity_id}' not found.")
        if ident["status"] != "ACTIVE":
            log_audit_event(req.identity_id, "JIT_REQUEST", req.target_resource, "DENIED", f"Identity status={ident['status']}")
            raise HTTPException(status_code=403, detail=f"Cannot grant JIT access to {ident['status']} identity.")

        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(minutes=req.duration_minutes)
        grant_id = f"JIT-{uuid.uuid4().hex[:6].upper()}"

        conn.execute(
            """
            INSERT INTO jit_grants
            (id, identity_id, target_resource, elevated_role, reason, status, granted_at, expires_at)
            VALUES (?, ?, ?, ?, ?, 'ACTIVE', ?, ?)
            """,
            (
                grant_id,
                req.identity_id,
                req.target_resource,
                req.elevated_role,
                req.reason,
                now.isoformat(),
                expires_at.isoformat(),
            ),
        )

    log_audit_event(
        req.identity_id,
        "JIT_GRANTED",
        req.target_resource,
        "SUCCESS",
        f"Grant={grant_id}, Role={req.elevated_role}, TTL={req.duration_minutes}m, Reason={req.reason}",
    )
    return {
        "grant_id": grant_id,
        "identity_id": req.identity_id,
        "target_resource": req.target_resource,
        "elevated_role": req.elevated_role,
        "status": "ACTIVE",
        "granted_at": now.isoformat(),
        "expires_at": expires_at.isoformat(),
    }


@app.get("/jit/active")
def list_jit_grants() -> List[dict]:
    now = datetime.now(timezone.utc)
    with get_connection() as conn:
        rows = conn.execute("SELECT * FROM jit_grants ORDER BY granted_at DESC").fetchall()
        grants = []
        for r in rows:
            status = r["status"]
            exp_dt = _parse_iso(r["expires_at"])
            if status == "ACTIVE" and now >= exp_dt:
                status = "EXPIRED"
                conn.execute("UPDATE jit_grants SET status = 'EXPIRED' WHERE id = ?", (r["id"],))
                log_audit_event("SYSTEM_JIT", "JIT_EXPIRED", r["target_resource"], "SUCCESS", f"Grant={r['id']} TTL elapsed")

            remaining_sec = max(0, int((exp_dt - now).total_seconds())) if status == "ACTIVE" else 0
            grants.append(
                {
                    "grant_id": r["id"],
                    "identity_id": r["identity_id"],
                    "target_resource": r["target_resource"],
                    "elevated_role": r["elevated_role"],
                    "reason": r["reason"],
                    "status": status,
                    "granted_at": r["granted_at"],
                    "expires_at": r["expires_at"],
                    "remaining_seconds": remaining_sec,
                }
            )
    return grants


@app.post("/jit/{grant_id}/revoke")
def revoke_jit_grant(grant_id: str, actor_id: str = "IAM_ADMIN") -> dict:
    with get_connection() as conn:
        row = conn.execute("SELECT * FROM jit_grants WHERE id = ?", (grant_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail=f"JIT grant '{grant_id}' not found.")

        conn.execute("UPDATE jit_grants SET status = 'REVOKED' WHERE id = ?", (grant_id,))

    log_audit_event(actor_id, "JIT_REVOKED", row["target_resource"], "SUCCESS", f"Revoked grant={grant_id}")
    return {"grant_id": grant_id, "status": "REVOKED"}


@app.get("/audit-logs")
def get_audit_logs(limit: int = 100) -> List[dict]:
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT id, timestamp, actor_id, action, target, status, details FROM audit_logs ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [dict(r) for r in rows]