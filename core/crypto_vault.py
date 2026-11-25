import os
import secrets
from pathlib import Path
from cryptography.fernet import Fernet, InvalidToken
from dotenv import load_dotenv

ENV_FILE = Path(".env")


def _load_or_create_master_key() -> bytes:
    """Loads VAULT_MASTER_KEY from .env, or generates one on first local run."""
    load_dotenv(dotenv_path=ENV_FILE)
    key = os.getenv("VAULT_MASTER_KEY")

    if not key or key == "your-fernet-base64-key-here":
        key = Fernet.generate_key().decode("utf-8")
        with open(ENV_FILE, "a", encoding="utf-8") as f:
            f.write(f"\nVAULT_MASTER_KEY={key}\n")
        os.environ["VAULT_MASTER_KEY"] = key

    return key.encode("utf-8")


class CryptoVault:
    def __init__(self) -> None:
        self._fernet = Fernet(_load_or_create_master_key())

    def encrypt(self, plaintext: str) -> str:
        """Encrypts a plaintext secret into a URL-safe base64 ciphertext."""
        return self._fernet.encrypt(plaintext.encode("utf-8")).decode("utf-8")

    def decrypt(self, ciphertext: str) -> str:
        """Decrypts a ciphertext secret back to plaintext."""
        try:
            return self._fernet.decrypt(ciphertext.encode("utf-8")).decode("utf-8")
        except InvalidToken as exc:
            raise ValueError("Decryption failed: invalid token or mismatched master key.") from exc

    @staticmethod
    def generate_secret(prefix: str = "zg_live") -> str:
        """Generates a high-entropy credential for secret rotation."""
        return f"{prefix}_{secrets.token_urlsafe(24)}"


if __name__ == "__main__":
    vault = CryptoVault()
    sample = vault.generate_secret("api")
    enc = vault.encrypt(sample)
    dec = vault.decrypt(enc)
    assert sample == dec, "Encryption round-trip failed!"
    print(f"[OK] CryptoVault verified | Ciphertext preview: {enc[:36]}...")