import pandas as pd
import requests
import streamlit as st

API_BASE = "http://127.0.0.1:8000"

st.set_page_config(
    page_title="ZSP-PAM-Governance-Console",
    page_icon="🛡️",
    layout="wide",
)


def api_get(path: str, params: dict | None = None):
    resp = requests.get(f"{API_BASE}{path}", params=params, timeout=10)
    resp.raise_for_status()
    return resp.json()


def api_post(path: str, payload: dict | None = None, params: dict | None = None):
    resp = requests.post(f"{API_BASE}{path}", json=payload, params=params, timeout=10)
    resp.raise_for_status()
    return resp.json()


st.title("🛡️ ZSP-PAM-Governance-Console")
st.caption("Zero Standing Privilege (ZSP) • Privileged Access Management (PAM) • Human & AI/NHI Governance")

# Verify FastAPI backend connectivity
try:
    health = api_get("/health")
except Exception as exc:
    st.error(
        f"Cannot connect to FastAPI backend at `{API_BASE}`. "
        f"Start it in a terminal first with: `uvicorn api.main:app --reload --port 8000`\n\nError: {exc}"
    )
    st.stop()

# Fetch live state for top summary metrics
try:
    identities = api_get("/identities")
    audit = api_get("/audit")
    secrets_list = api_get("/secrets")
    jit_grants = api_get("/jit/active")
except Exception as exc:
    st.error(f"Failed to load telemetry from backend: {exc}")
    st.stop()

active_jit = [g for g in jit_grants if g["status"] == "ACTIVE"]

m1, m2, m3, m4 = st.columns(4)
m1.metric("Org Security Posture", f"{audit['posture_score']}%")
m2.metric("Governance Findings", audit["total_findings"], delta=f"-{audit['risky_identities']} risky identities", delta_color="inverse")
m3.metric("Vault Secrets & NHI Keys", len(secrets_list))
m4.metric("Active JIT Elevations", len(active_jit))

st.divider()

tab1, tab2, tab3, tab4 = st.tabs(
    [
        "📊 Governance & Access Creep",
        "🔐 Credential & NHI Vault",
        "⚡ Just-in-Time (JIT) Elevation",
        "📜 Privileged Audit Log",
    ]
)

# ==============================================================================
# TAB 1: Governance & Access Creep Audit + One-Click Remediation
# ==============================================================================
with tab1:
    st.subheader("Identity Governance & Administration (IGA) Audit")
    st.write(
        "Detects **Orphaned Leavers**, **Separation of Duties (SoD)** conflicts, "
        "**Zero Standing Privilege (ZSP)** violations, **Dormant Admins**, and **Cross-Department Access Creep** "
        "across human employees and Non-Human Identities (AI agents, service accounts, CI/CD tokens)."
    )

    c_filter1, c_filter2 = st.columns(2)
    sev_filter = c_filter1.multiselect(
        "Filter by Severity",
        options=["CRITICAL", "HIGH", "MEDIUM"],
        default=["CRITICAL", "HIGH", "MEDIUM"],
    )
    type_filter = c_filter2.multiselect(
        "Filter by Identity Type",
        options=["HUMAN", "NHI"],
        default=["HUMAN", "NHI"],
    )

    filtered_findings = [
        f
        for f in audit["findings"]
        if f["severity"] in sev_filter and f["identity_type"] in type_filter
    ]

    if filtered_findings:
        df_findings = pd.DataFrame(filtered_findings)[
            [
                "severity",
                "risk_score",
                "identity_id",
                "name",
                "identity_type",
                "department",
                "category",
                "detail",
                "remediation",
            ]
        ]
        st.dataframe(df_findings, use_container_width=True, hide_index=True)
    else:
        st.success("No findings match the current filter criteria.")

    st.markdown("### One-Click Remediation")
    identity_options = {
        f"{i['id']} — {i['name']} [{i['identity_type']} | {i['status']}]": i["id"]
        for i in identities
    }
    r_col1, r_col2, r_col3 = st.columns([2, 2, 1])
    selected_label = r_col1.selectbox("Select Identity to Remediate", options=list(identity_options.keys()))
    rem_action = r_col2.selectbox(
        "Remediation Action",
        options=["REVOKE_HIGH_RISK", "CLEAR_ALL_PRIVS", "DEPROVISION"],
    )
    if r_col3.button("Apply Remediation", type="primary", use_container_width=True):
        target_id = identity_options[selected_label]
        try:
            res = api_post(f"/remediate/{target_id}", payload={"action": rem_action})
            st.success(
                f"Updated **{res['identity_id']}** → Status: `{res['status']}`, "
                f"Standing Privileges: `{res['standing_privileges']}`"
            )
            st.rerun()
        except Exception as exc:
            st.error(f"Remediation failed: {exc}")

    with st.expander("View All Organization Identities (25 Human + 10 NHI)"):
        df_ids = pd.DataFrame(identities)
        st.dataframe(df_ids, use_container_width=True, hide_index=True)

# ==============================================================================
# TAB 2: Encrypted Credential & NHI Vault
# ==============================================================================
with tab2:
    st.subheader("Fernet-Encrypted Vault & Secret Rotation")
    st.write("Secrets are encrypted at rest using AES-128-CBC + HMAC-SHA256 (`cryptography.fernet`) with version tracking and rotation timers.")

    if secrets_list:
        df_sec = pd.DataFrame(secrets_list)[
            [
                "id",
                "name",
                "owner_id",
                "secret_type",
                "version",
                "rotation_interval_days",
                "days_until_expiry",
                "last_rotated_at",
            ]
        ]
        st.dataframe(df_sec, use_container_width=True, hide_index=True)

    v_col1, v_col2 = st.columns(2)

    with v_col1:
        st.markdown("### Checkout or Rotate Existing Secret")
        secret_names = [s["name"] for s in secrets_list]
        if secret_names:
            chosen_secret = st.selectbox("Select Secret", options=secret_names)
            requester = st.text_input("Requester / Actor ID", value="USR-001")
            b1, b2 = st.columns(2)
            if b1.button("🔓 Checkout (Decrypt)", use_container_width=True):
                try:
                    out = api_post(f"/secrets/{chosen_secret}/checkout", params={"requester_id": requester})
                    st.info(f"**{out['name']}** (v{out['version']}): `{out['secret_value']}`")
                    st.rerun()
                except Exception as exc:
                    st.error(f"Checkout failed: {exc}")

            if b2.button("🔄 Rotate Secret Now", type="primary", use_container_width=True):
                try:
                    rot = api_post(f"/secrets/{chosen_secret}/rotate", params={"actor_id": requester})
                    st.success(
                        f"Rotated **{rot['name']}** to **v{rot['version']}** "
                        f"(Preview: `{rot['new_secret_preview']}`)"
                    )
                    st.rerun()
                except Exception as exc:
                    st.error(f"Rotation failed: {exc}")

    with v_col2:
        st.markdown("### Store New Secret / NHI Key")
        owner_ids = [i["id"] for i in identities]
        with st.form("create_secret_form"):
            new_sec_name = st.text_input("Secret Name", placeholder="AI_AGENT_VECTOR_DB_KEY")
            new_owner = st.selectbox("Owner Identity", options=owner_ids, index=owner_ids.index("NHI-006") if "NHI-006" in owner_ids else 0)
            new_type = st.selectbox("Secret Type", options=["NHI_API_KEY", "DATABASE_CREDENTIAL", "CICD_TOKEN", "SERVICE_PASSWORD"])
            new_plain = st.text_input("Plaintext Value (leave blank to auto-generate)", type="password")
            new_rot_days = st.number_input("Rotation Interval (days)", min_value=1, max_value=365, value=30)
            submitted = st.form_submit_button("Encrypt & Store Secret")

        if submitted:
            if not new_sec_name.strip():
                st.warning("Please enter a secret name.")
            else:
                try:
                    created = api_post(
                        "/secrets",
                        payload={
                            "name": new_sec_name.strip(),
                            "owner_id": new_owner,
                            "secret_type": new_type,
                            "plaintext_value": new_plain.strip() or None,
                            "rotation_interval_days": int(new_rot_days),
                        },
                    )
                    st.success(f"Stored encrypted secret **{created['name']}** (ID: `{created['id']}`).")
                    st.rerun()
                except Exception as exc:
                    st.error(f"Could not create secret: {exc}")

# ==============================================================================
# TAB 3: Just-in-Time (JIT) Privilege Elevation
# ==============================================================================
with tab3:
    st.subheader("Just-in-Time (JIT) Temporary Privilege Elevation")
    st.write("Eliminates standing admin rights by issuing time-bound access grants that expire automatically or can be revoked immediately.")

    j_left, j_right = st.columns([1, 1.4])

    with j_left:
        st.markdown("### Request Temporary Elevation")
        active_ids = [f"{i['id']} ({i['name']})" for i in identities if i["status"] == "ACTIVE"]
        id_map = {f"{i['id']} ({i['name']})": i["id"] for i in identities if i["status"] == "ACTIVE"}

        with st.form("jit_request_form"):
            jit_user_label = st.selectbox("Identity", options=active_ids)
            jit_target = st.text_input("Target Resource", value="prod-postgres-cluster-01")
            jit_role = st.selectbox(
                "Elevated Role",
                options=["prod_db_admin", "k8s_cluster_admin", "iam_privileged_operator", "ai_agent_write_override"],
            )
            jit_duration = st.slider("Duration (minutes)", min_value=1, max_value=120, value=15)
            jit_reason = st.text_area("Justification / Ticket Ref", placeholder="INC-4092: Investigating replication lag on primary node")
            jit_submit = st.form_submit_button("Grant Time-Bound Access", type="primary")

        if jit_submit:
            if len(jit_reason.strip()) < 5:
                st.warning("Provide a clear justification (at least 5 characters).")
            else:
                try:
                    grant = api_post(
                        "/jit/request",
                        payload={
                            "identity_id": id_map[jit_user_label],
                            "target_resource": jit_target.strip(),
                            "elevated_role": jit_role,
                            "reason": jit_reason.strip(),
                            "duration_minutes": int(jit_duration),
                        },
                    )
                    st.success(f"Granted **{grant['grant_id']}** for `{grant['identity_id']}` until `{grant['expires_at']}`.")
                    st.rerun()
                except Exception as exc:
                    st.error(f"JIT request failed: {exc}")

    with j_right:
        st.markdown("### JIT Elevation Grants & Revocation")
        if st.button("🔄 Refresh / Check Expirations"):
            st.rerun()

        if jit_grants:
            df_jit = pd.DataFrame(jit_grants)[
                [
                    "grant_id",
                    "identity_id",
                    "target_resource",
                    "elevated_role",
                    "status",
                    "remaining_seconds",
                    "reason",
                ]
            ]
            st.dataframe(df_jit, use_container_width=True, hide_index=True)

            active_grant_ids = [g["grant_id"] for g in jit_grants if g["status"] == "ACTIVE"]
            if active_grant_ids:
                revoke_choice = st.selectbox("Select Active Grant to Revoke", options=active_grant_ids)
                if st.button("🛑 Revoke Grant Immediately", type="primary"):
                    try:
                        rev = api_post(f"/jit/{revoke_choice}/revoke")
                        st.warning(f"Revoked grant **{rev['grant_id']}**.")
                        st.rerun()
                    except Exception as exc:
                        st.error(f"Revoke failed: {exc}")
        else:
            st.info("No JIT elevation grants recorded yet. Request one on the left to test time-bound access.")

# ==============================================================================
# TAB 4: Privileged Audit Log
# ==============================================================================
with tab4:
    st.subheader("Immutable Privileged Activity & Governance Log")
    st.write("Every vault checkout, secret rotation, JIT grant/revocation/expiry, audit scan, and remediation action is recorded here.")

    try:
        logs = api_get("/audit-logs", params={"limit": 150})
        if logs:
            df_logs = pd.DataFrame(logs)[["id", "timestamp", "actor_id", "action", "target", "status", "details"]]
            st.dataframe(df_logs, use_container_width=True, hide_index=True)
        else:
            st.info("No audit log entries found.")
    except Exception as exc:
        st.error(f"Failed to load audit logs: {exc}")