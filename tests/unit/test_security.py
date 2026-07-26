from __future__ import annotations

import re

from app.core.security import generate_password, hash_password, verify_password


def test_hash_is_argon2id_and_salted() -> None:
    a = hash_password("correct horse battery staple")
    b = hash_password("correct horse battery staple")
    assert a.startswith("$argon2id$")
    assert a != b, "identical passwords must not produce identical hashes"


def test_verify_round_trip() -> None:
    assert verify_password("s3cret", hash_password("s3cret")) is True
    assert verify_password("wrong", hash_password("s3cret")) is False


def test_verify_against_unknown_user_returns_false() -> None:
    """Passing None must still run a real verify, not short-circuit.

    Short-circuiting on a missing user turns login into a username oracle: the
    response comes back measurably faster for accounts that do not exist.
    """
    assert verify_password("anything", None) is False


def test_verify_rejects_a_malformed_hash_without_raising() -> None:
    assert verify_password("anything", "not-a-hash") is False


def test_generated_password_length_and_alphabet() -> None:
    password = generate_password()
    assert len(password) == 24
    # No characters that are ambiguous when read off a terminal and retyped.
    assert not set(password) & set("lIO01")
    assert re.fullmatch(r"[A-Za-z2-9\-_]+", password)


def test_generated_passwords_are_unique() -> None:
    assert len({generate_password() for _ in range(50)}) == 50
