# ZSP-PAM-Governance-Console

A Python-based **Zero Standing Privilege (ZSP)**, **Privileged Access Management (PAM)**, and **Identity Governance & Administration (IGA)** console for both **Human Identities** and **Non-Human Identities (NHIs)** (AI agents, service accounts, and CI/CD credentials).

## Architecture

```mermaid
flowchart LR
    UI["Streamlit Console<br/>(ui/dashboard.py)"] <--> API["FastAPI Backend<br/>(api/main.py)"]
    API --> GOV["Governance & Audit Engine<br/>(core/governance.py)"]
    API --> VAULT["Fernet CryptoVault<br/>(core/crypto_vault.py)"]
    GOV --> SEED["Sample Org Dataset<br/>(data/sample_org.json)"]
    GOV --> DB[("SQLite Store<br/>(vaultguard.db)")]
    VAULT --> DB
    API --> DB