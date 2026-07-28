"""Credential encryption.

What this defends against: someone obtaining a copy of the database, from a
backup, a stolen volume, or a misconfigured share. What it does not: someone who
can read the running container. They have the key, which is why the threat model
treats Docker access as root-equivalent rather than pretending otherwise.
"""

from __future__ import annotations

import base64
import os
from pathlib import Path

import pytest

from app.core.config import get_settings
from app.core.crypto import DecryptionError, decrypt, encrypt, fingerprint, reset_cipher


@pytest.fixture(autouse=True)
def _fresh_cipher(env: Path):
    """The cipher is cached, so it must be dropped when the key changes."""
    reset_cipher()
    yield
    reset_cipher()


class TestRoundTrip:
    def test_a_secret_survives_encryption_and_decryption(self) -> None:
        secret = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNza\n-----END-----"
        assert decrypt(encrypt(secret)) == secret

    def test_ciphertext_does_not_contain_the_plaintext(self) -> None:
        secret = "hunter2-correct-horse"
        assert secret.encode() not in encrypt(secret)

    def test_encrypting_twice_gives_different_ciphertext(self) -> None:
        """Fernet includes a random IV. Identical ciphertext for identical input
        would leak which credentials share a value."""
        secret = "the-same-secret"
        assert encrypt(secret) != encrypt(secret)
        assert decrypt(encrypt(secret)) == secret

    def test_unicode_survives(self) -> None:
        secret = "pässwörd-🔐-日本語"
        assert decrypt(encrypt(secret)) == secret

    def test_a_long_secret_survives(self) -> None:
        secret = "x" * 100_000
        assert decrypt(encrypt(secret)) == secret

    def test_an_empty_secret_is_refused(self) -> None:
        """Storing an empty credential would look like a working one."""
        with pytest.raises(ValueError, match="empty"):
            encrypt("")


class TestFailureModes:
    def test_the_wrong_key_fails_loudly(self, env: Path) -> None:
        """The failure that matters. Silently returning nothing would be
        indistinguishable from an empty password."""
        ciphertext = encrypt("original-secret")

        (env / "secrets" / "crypto_key").write_text(
            base64.urlsafe_b64encode(os.urandom(32)).decode()
        )
        get_settings.cache_clear()
        reset_cipher()

        with pytest.raises(DecryptionError):
            decrypt(ciphertext)

    def test_altered_ciphertext_is_rejected(self) -> None:
        """Fernet authenticates. Without that, a modified value would decrypt to
        garbage and be used as a key."""
        ciphertext = bytearray(encrypt("original-secret"))
        ciphertext[-5] ^= 0xFF

        with pytest.raises(DecryptionError):
            decrypt(bytes(ciphertext))

    def test_truncated_ciphertext_is_rejected(self) -> None:
        with pytest.raises(DecryptionError):
            decrypt(encrypt("original-secret")[:20])

    @pytest.mark.parametrize("junk", [b"", b"not-ciphertext", b"\x00\x01\x02"])
    def test_junk_is_rejected(self, junk: bytes) -> None:
        with pytest.raises(DecryptionError):
            decrypt(junk)

    def test_the_error_does_not_echo_the_ciphertext(self) -> None:
        ciphertext = encrypt("original-secret")
        with pytest.raises(DecryptionError) as caught:
            decrypt(ciphertext[:-4] + b"XXXX")
        assert ciphertext[:16].decode("latin-1") not in str(caught.value)

    def test_the_error_explains_what_to_do(self) -> None:
        """An operator seeing this needs to know it is a key problem, not a bug."""
        with pytest.raises(DecryptionError) as caught:
            decrypt(b"junk")
        message = str(caught.value)
        assert "key" in message.lower()
        assert "backup" in message.lower() or "re-enter" in message.lower()


class TestFingerprint:
    def test_it_is_stable(self) -> None:
        material = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5"
        assert fingerprint(material) == fingerprint(material)

    def test_different_material_differs(self) -> None:
        assert fingerprint("ssh-ed25519 AAAA") != fingerprint("ssh-ed25519 BBBB")

    def test_it_looks_like_an_ssh_fingerprint(self) -> None:
        value = fingerprint("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5")
        assert value.startswith("SHA256:")
        assert not value.endswith("=")
