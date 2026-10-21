"""The client address must be usable as a throttle and audit key, not a log payload."""

from __future__ import annotations

import pytest
from starlette.requests import Request

from app.core.requests import client_ip


@pytest.mark.parametrize(
    ("supplied", "expected"),
    [
        ("10.0.0.1", "10.0.0.1"),
        ("2001:db8::1", "2001:db8::1"),
        ("10.0.0.1\nFORGED EVENT", "unknown"),
        ("not-an-address", "unknown"),
    ],
)
def test_client_ip_accepts_only_real_ip_addresses(supplied: str, expected: str) -> None:
    request = Request({"type": "http", "method": "GET", "path": "/", "client": (supplied, 1234)})
    assert client_ip(request) == expected
