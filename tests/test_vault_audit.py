"""Unit tests — AES-256-GCM vault and hash-chained audit logger."""

import os

import pytest

from biocrypt.audit.logger import AuditLogger, AuditRecord, GENESIS
from biocrypt.crypto import vault


# ---------------------------------------------------------------------------
# Vault
# ---------------------------------------------------------------------------
@pytest.fixture()
def vault_dir(tmp_path):
    d = tmp_path / "vault"
    d.mkdir()
    (d / "secret.txt").write_text("top secret payload", encoding="utf-8")
    sub = d / "nested"
    sub.mkdir()
    (sub / "image.bin").write_bytes(bytes(range(256)))
    return d


class TestVault:
    def test_seal_replaces_files_and_writes_manifest(self, vault_dir):
        result = vault.seal_folder(str(vault_dir), "pass-123")
        assert len(result.sealed_paths) == 2
        assert vault.is_sealed(str(vault_dir))
        assert (vault_dir / "secret.txt").exists() is False
        assert (vault_dir / "secret.txt.bcl").exists()
        assert (vault_dir / "manifest.bcl").exists()

    def test_manifest_metadata(self, vault_dir):
        import json
        vault.seal_folder(str(vault_dir), "pass-123")
        manifest = json.loads((vault_dir / "manifest.bcl").read_text())
        assert manifest["cipher"] == "AES-256-GCM"
        assert manifest["kdf"] == "PBKDF2-HMAC-SHA256"
        assert manifest["iterations"] == 600_000
        assert {f["path"] for f in manifest["files"]} == {
            "secret.txt", "nested/image.bin"}

    def test_roundtrip_restores_originals(self, vault_dir):
        original = (vault_dir / "secret.txt").read_bytes()
        nested = (vault_dir / "nested" / "image.bin").read_bytes()
        vault.seal_folder(str(vault_dir), "pass-123")
        result = vault.unseal_folder(str(vault_dir), "pass-123")
        assert len(result.restored_paths) == 2
        assert (vault_dir / "secret.txt").read_bytes() == original
        assert (vault_dir / "nested" / "image.bin").read_bytes() == nested
        assert not vault.is_sealed(str(vault_dir))
        assert not (vault_dir / "secret.txt.bcl").exists()

    def test_wrong_passphrase_rejected(self, vault_dir):
        vault.seal_folder(str(vault_dir), "correct")
        with pytest.raises(vault.VaultError):
            vault.unseal_folder(str(vault_dir), "wrong")

    def test_tampered_ciphertext_rejected(self, vault_dir):
        vault.seal_folder(str(vault_dir), "pass-123")
        target = vault_dir / "secret.txt.bcl"
        blob = bytearray(target.read_bytes())
        blob[-1] ^= 0x01                     # flip one bit
        target.write_bytes(bytes(blob))
        with pytest.raises(vault.VaultError):
            vault.unseal_folder(str(vault_dir), "pass-123")

    def test_ciphertext_swap_rejected(self, vault_dir):
        """AAD binding: ciphertexts cannot be swapped between files."""
        vault.seal_folder(str(vault_dir), "pass-123")
        a = vault_dir / "secret.txt.bcl"
        b = vault_dir / "nested" / "image.bin.bcl"
        a.write_bytes(b.read_bytes())
        with pytest.raises(vault.VaultError):
            vault.unseal_folder(str(vault_dir), "pass-123")

    def test_seal_requires_folder(self, tmp_path):
        with pytest.raises(vault.VaultError):
            vault.seal_folder(str(tmp_path / "nope"), "x")


# ---------------------------------------------------------------------------
# Audit logger
# ---------------------------------------------------------------------------
class TestAuditLogger:
    @pytest.fixture()
    def audit(self, tmp_path):
        logger = AuditLogger(str(tmp_path / "audit.db"))
        yield logger
        logger.close()

    def _record(self, **kw) -> AuditRecord:
        defaults = dict(fp_score=95.0, rssi_dbm=-42.0, failed_attempts=0,
                        risk_score=2.5, tier="Low Risk (0-30)",
                        status="Unlocked — single factor")
        defaults.update(kw)
        return AuditRecord(**defaults)

    def test_row_written_and_chained(self, audit):
        audit.log(self._record())
        audit.log(self._record(fp_score=40.0))
        rows = audit.fetch_all()
        assert len(rows) == 2
        assert rows[0]["prev_hash"] == GENESIS
        assert rows[1]["prev_hash"] == rows[0]["row_hash"]
        assert rows[0]["row_hash"] != rows[1]["row_hash"]

    def test_chain_verification_passes(self, audit):
        for i in range(5):
            audit.log(self._record(risk_score=float(i)))
        ok, msg = audit.verify_chain()
        assert ok

    def test_tampering_detected(self, audit):
        audit.log(self._record())
        audit.log(self._record(fp_score=10.0))
        assert audit.verify_chain()[0]
        # forge a row directly in SQLite (simulated attacker)
        audit._conn.execute(
            "UPDATE audit_log SET risk_score = 0.0 WHERE id = 1")
        audit._conn.commit()
        ok, msg = audit.verify_chain()
        assert not ok
        assert "altered" in msg or "mismatch" in msg

    def test_replay_fields_persist(self, audit):
        audit.log(self._record(otp_issued=True, otp_digits=6,
                               otp_entered="123456", otp_valid=False,
                               otp_reason="replay", token_replay=True,
                               status="Access denied — replay"))
        row = audit.fetch_all()[0]
        assert row["token_replay"] == 1
        assert row["otp_reason"] == "replay"
        assert row["otp_digits"] == 6

    def test_csv_export(self, audit, tmp_path):
        audit.log(self._record())
        audit.log(self._record(fp_score=1.0))
        out = tmp_path / "export.csv"
        n = audit.export_csv(str(out))
        assert n == 2
        text = out.read_text(encoding="utf-8")
        header = text.splitlines()[0]
        assert header.startswith("id,session_id")
        assert "risk_score" in header and "row_hash" in header
