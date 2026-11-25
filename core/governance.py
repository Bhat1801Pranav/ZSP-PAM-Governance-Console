import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List

from core.crypto_vault import CryptoVault
from core.database import get_connection, init_db, log_audit_event, utc_now_iso

SAMPLE_DATA_PATH = Path("data/sample_org.json")

# High-risk standing privileges that violate Zero Standing Privilege (ZSP)
HIGH_RISK_PRIVILEGES = {
    "aws_root_console",
    "domain_admin",
    "prod_db_admin",
    "k8s_cluster_admin",
    "s3_full_access",
}

# Separation of Duties (SoD) toxic combinations
SOD_RULES = [
    {
        "rule_id": "SOD-001",
        "name": "Procurement Fraud Risk",
        "required_pair": {"create_vendor", "approve_payment"},
        "severity": "HIGH",
        "remediation": "Split vendor creation and payment approval across separate roles.",
    },
    {
        "rule_id": "SOD-002",
        "name": "Unreviewed Production Deployment",
        "required_pair": {"code_commit", "prod_deploy_approve"},
        "severity": "HIGH",
        "remediation": "Remove standing prod_deploy_approve; enforce peer review + JIT elevation.",
    },
    {
        "rule_id": "SOD-003",
        "name": "Audit Trail Tampering Risk",
        "required_pair": {"iam_user_create", "audit_log_delete"},
        "severity": "CRITICAL",
        "remediation": "Revoke audit_log_delete immediately; audit logs must be immutable.",
    },
]

# Privileges restricted to specific departments (for Access Creep detection)
RESTRICTED_DEPT_PRIVILEGES = {
    "prod_db_read": {"Engineering", "IT Security"},
    "ledger_export": {"Finance", "Legal"},
    "billing_export": {"Finance"},
}


def seed_org_data() -> Dict[str, int]:
    """Seeds identities and initial encrypted vault secrets from data/sample_org.json."""
    init_db()
    payload = json.loads(SAMPLE_DATA_PATH.read_text(encoding="utf-8"))
    vault = CryptoVault()

    identities_added = 0
    secrets_added = 0

    with get_connection() as conn:
        for item in payload["identities"]:
            cur = conn.execute(
                """
                INSERT OR IGNORE INTO identities
                (id, name, email, identity_type, department, role, status, standing_privileges, last_login_days)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    item["id"],
                    item["name"],
                    item.get("email", ""),
                    item["identity_type"],
                    item["department"],
                    item["role"],
                    item["status"],
                    json.dumps(item["standing_privileges"]),
                    item["last_login_days"],
                ),
            )
            identities_added += cur.rowcount

        now = datetime.now(timezone.utc)
        for sec in payload.get("initial_secrets", []):
            raw_secret = vault.generate_secret("zg")
            encrypted = vault.encrypt(raw_secret)
            expires_at = (now + timedelta(days=sec["rotation_interval_days"])).isoformat()
            cur = conn.execute(
                """
                INSERT OR IGNORE INTO secrets
                (id, name, owner_id, secret_type, encrypted_value, version, rotation_interval_days, last_rotated_at, expires_at)
                VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?)
                """,
                (
                    sec["id"],
                    sec["name"],
                    sec["owner_id"],
                    sec["secret_type"],
                    encrypted,
                    sec["rotation_interval_days"],
                    now.isoformat(),
                    expires_at,
                ),
            )
            secrets_added += cur.rowcount

    if identities_added or secrets_added:
        log_audit_event(
            "SYSTEM",
            "ORG_SEED",
            "vaultguard.db",
            "SUCCESS",
            f"Seeded {identities_added} identities and {secrets_added} encrypted secrets",
        )

    return {"identities_added": identities_added, "secrets_added": secrets_added}


def run_governance_audit() -> Dict[str, Any]:
    """Scans all identities for Orphaned Leavers, SoD, ZSP violations, Dormancy, and Access Creep."""
    with get_connection() as conn:
        rows = conn.execute("SELECT * FROM identities ORDER BY id").fetchall()

    findings: List[Dict[str, Any]] = []
    severity_weights = {"CRITICAL": 40, "HIGH": 25, "MEDIUM": 15}
    risky_identity_ids = set()

    for row in rows:
        privs = set(json.loads(row["standing_privileges"]))
        identity_findings = []

        # 1. Orphaned Leaver Account
        if row["status"] == "TERMINATED" and privs:
            identity_findings.append(
                {
                    "category": "ORPHANED_LEAVER",
                    "severity": "CRITICAL",
                    "detail": f"Terminated {row['identity_type']} still holds {sorted(privs)}.",
                    "remediation": "Deprovision immediately and revoke all active sessions/keys.",
                }
            )

        # 2. Separation of Duties (SoD)
        for rule in SOD_RULES:
            if rule["required_pair"].issubset(privs):
                identity_findings.append(
                    {
                        "category": f"SOD_VIOLATION ({rule['rule_id']})",
                        "severity": rule["severity"],
                        "detail": f"{rule['name']}: holds conflicting pair {sorted(rule['required_pair'])}.",
                        "remediation": rule["remediation"],
                    }
                )

        # 3. Zero Standing Privilege (ZSP) Violation
        zsp_hits = privs.intersection(HIGH_RISK_PRIVILEGES)
        if zsp_hits and row["status"] != "TERMINATED":
            identity_findings.append(
                {
                    "category": "ZSP_VIOLATION",
                    "severity": "HIGH",
                    "detail": f"Permanent standing high-risk access: {sorted(zsp_hits)}.",
                    "remediation": "Strip standing admin role and require time-bound JIT elevation.",
                }
            )

        # 4. Dormant Privileged Account
        if (row["status"] == "DORMANT" or row["last_login_days"] >= 90) and privs:
            identity_findings.append(
                {
                    "category": "DORMANT_PRIVILEGED",
                    "severity": "MEDIUM",
                    "detail": f"Inactive for {row['last_login_days']} days while holding {sorted(privs)}.",
                    "remediation": "Disable account and require manager recertification.",
                }
            )

        # 5. Cross-Department Access Creep
        for priv, allowed_depts in RESTRICTED_DEPT_PRIVILEGES.items():
            if priv in privs and row["department"] not in allowed_depts:
                identity_findings.append(
                    {
                        "category": "ACCESS_CREEP",
                        "severity": "MEDIUM",
                        "detail": f"{row['department']} identity holds restricted privilege '{priv}'.",
                        "remediation": f"Revoke '{priv}' (restricted to {sorted(allowed_depts)}).",
                    }
                )

        if identity_findings:
            risky_identity_ids.add(row["id"])
            risk_score = min(100, sum(severity_weights[f["severity"]] for f in identity_findings))
            for f in identity_findings:
                findings.append(
                    {
                        "identity_id": row["id"],
                        "name": row["name"],
                        "identity_type": row["identity_type"],
                        "department": row["department"],
                        "status": row["status"],
                        "risk_score": risk_score,
                        **f,
                    }
                )

    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}
    findings.sort(key=lambda x: (severity_order[x["severity"]], -x["risk_score"]))

    total_identities = len(rows)
    compliant_count = total_identities - len(risky_identity_ids)
    posture_score = round((compliant_count / total_identities) * 100, 1) if total_identities else 100.0

    return {
        "audited_at": utc_now_iso(),
        "total_identities": total_identities,
        "risky_identities": len(risky_identity_ids),
        "posture_score": posture_score,
        "total_findings": len(findings),
        "findings": findings,
    }


if __name__ == "__main__":
    seed_result = seed_org_data()
    print(f"[OK] Seed result: {seed_result}")
    report = run_governance_audit()
    print(
        f"[OK] Audit complete | Posture Score: {report['posture_score']}% "
        f"| Risky Identities: {report['risky_identities']}/{report['total_identities']} "
        f"| Findings: {report['total_findings']}"
    )
    for finding in report["findings"][:5]:
        print(f"  - [{finding['severity']}] {finding['identity_id']} ({finding['name']}): {finding['category']} -> {finding['detail']}")