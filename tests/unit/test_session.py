from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from app.core.session import (
    ABSOLUTE_LIFETIME,
    IDLE_LIFETIME,
    SESSION_CREATED_AT,
    SESSION_LAST_SEEN,
    SESSION_SID,
    current_user_id,
    end_session,
    get_csrf_token,
    start_session,
    touch,
    verify_csrf,
)
from app.core.templating import safe_external_url


class FakeRequest:
    """Minimal stand-in — the session helpers only ever touch request.session."""

    def __init__(self) -> None:
        self.session: dict[str, Any] = {}


class TestSessionLifecycle:
    def test_start_session_populates_identity_and_timestamps(self) -> None:
        request = FakeRequest()
        start_session(request, 7)  # type: ignore[arg-type]

        assert current_user_id(request) == 7  # type: ignore[arg-type]
        assert request.session[SESSION_SID]
        assert request.session[SESSION_CREATED_AT]

    def test_start_session_discards_any_prior_session(self) -> None:
        """Session fixation: an attacker-planted session must be destroyed at
        login, not adopted."""
        request = FakeRequest()
        request.session["planted"] = "value"
        start_session(request, 1)  # type: ignore[arg-type]
        first_sid = request.session[SESSION_SID]

        start_session(request, 1)  # type: ignore[arg-type]

        assert "planted" not in request.session
        assert request.session[SESSION_SID] != first_sid

    def test_end_session_clears_everything(self) -> None:
        request = FakeRequest()
        start_session(request, 1)  # type: ignore[arg-type]
        end_session(request)  # type: ignore[arg-type]

        assert request.session == {}
        assert current_user_id(request) is None  # type: ignore[arg-type]

    def test_no_session_means_no_user(self) -> None:
        assert current_user_id(FakeRequest()) is None  # type: ignore[arg-type]


class TestExpiry:
    def _aged(self, *, created: timedelta, last_seen: timedelta) -> FakeRequest:
        request = FakeRequest()
        start_session(request, 1)  # type: ignore[arg-type]
        now = datetime.now(UTC)
        request.session[SESSION_CREATED_AT] = (now - created).isoformat()
        request.session[SESSION_LAST_SEEN] = (now - last_seen).isoformat()
        return request

    def test_absolute_lifetime_ends_the_session(self) -> None:
        """Enforced server-side, not by cookie max-age — a cookie lifetime is a
        client-side hint and this is not."""
        request = self._aged(
            created=ABSOLUTE_LIFETIME + timedelta(minutes=1), last_seen=timedelta(seconds=1)
        )
        assert current_user_id(request) is None  # type: ignore[arg-type]
        assert request.session == {}

    def test_idle_lifetime_ends_the_session(self) -> None:
        request = self._aged(
            created=timedelta(minutes=1), last_seen=IDLE_LIFETIME + timedelta(minutes=1)
        )
        assert current_user_id(request) is None  # type: ignore[arg-type]

    def test_an_active_session_survives(self) -> None:
        request = self._aged(created=timedelta(hours=1), last_seen=timedelta(minutes=1))
        assert current_user_id(request) == 1  # type: ignore[arg-type]

    def test_touch_slides_the_idle_window(self) -> None:
        request = self._aged(
            created=timedelta(minutes=1), last_seen=IDLE_LIFETIME - timedelta(minutes=1)
        )
        touch(request)  # type: ignore[arg-type]
        assert current_user_id(request) == 1  # type: ignore[arg-type]

    @pytest.mark.parametrize("corrupt", ["", "not-a-date", None, 12345])
    def test_an_unreadable_timestamp_fails_closed(self, corrupt: object) -> None:
        request = FakeRequest()
        start_session(request, 1)  # type: ignore[arg-type]
        request.session[SESSION_LAST_SEEN] = corrupt
        assert current_user_id(request) is None  # type: ignore[arg-type]


class TestCsrfToken:
    def test_a_token_is_minted_for_anonymous_visitors(self) -> None:
        """The login form is itself a POST, so a token is needed before login."""
        request = FakeRequest()
        assert len(get_csrf_token(request)) > 20  # type: ignore[arg-type]

    def test_the_token_is_stable_within_a_session(self) -> None:
        request = FakeRequest()
        assert get_csrf_token(request) == get_csrf_token(request)  # type: ignore[arg-type]

    def test_verification_accepts_the_matching_token(self) -> None:
        request = FakeRequest()
        token = get_csrf_token(request)  # type: ignore[arg-type]
        assert verify_csrf(request, token) is True  # type: ignore[arg-type]

    @pytest.mark.parametrize("submitted", ["", None, "wrong-token", " "])
    def test_verification_rejects_anything_else(self, submitted: str | None) -> None:
        request = FakeRequest()
        get_csrf_token(request)  # type: ignore[arg-type]
        assert verify_csrf(request, submitted) is False  # type: ignore[arg-type]

    def test_verification_fails_when_the_session_has_no_token(self) -> None:
        assert verify_csrf(FakeRequest(), "anything") is False  # type: ignore[arg-type]

    def test_login_rotates_the_token(self) -> None:
        request = FakeRequest()
        before = get_csrf_token(request)  # type: ignore[arg-type]
        start_session(request, 1)  # type: ignore[arg-type]
        assert get_csrf_token(request) != before  # type: ignore[arg-type]


class TestSafeExternalUrl:
    @pytest.mark.parametrize(
        "value", ["http://10.0.0.1", "https://nas.lan:5000/", "HTTPS://Device.lan"]
    )
    def test_allows_http_and_https(self, value: str) -> None:
        assert safe_external_url(value) == value

    @pytest.mark.parametrize(
        "value",
        [
            "javascript:alert(1)",
            "JaVaScRiPt:alert(1)",
            "data:text/html,<script>alert(1)</script>",
            "vbscript:msgbox(1)",
            "file:///etc/passwd",
            "//evil.example.com",
            "http://ok\njavascript:alert(1)",
            "",
            None,
        ],
    )
    def test_rejects_everything_else(self, value: str | None) -> None:
        """Device hostnames come from the network and land in href attributes.
        Autoescaping does not help when the payload is the attribute value."""
        assert safe_external_url(value) is None
