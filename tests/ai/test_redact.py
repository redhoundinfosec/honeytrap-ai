"""Unit tests for ``honeytrap.ai.redact``."""

from __future__ import annotations

from honeytrap.ai.redact import redact_prompt


def test_redact_password_assignment() -> None:
    assert "<redacted>" in redact_prompt("password=hunter2")


def test_redact_password_colon_form() -> None:
    out = redact_prompt("PASSWORD: secret123")
    assert "<redacted>" in out


def test_redact_api_key() -> None:
    assert "<redacted>" in redact_prompt("api_key=ABCDEFG12345")


def test_redact_authorization_bearer() -> None:
    out = redact_prompt("Authorization: Bearer eyJhbGc.payload.sig")
    assert "<redacted>" in out


def test_redact_aws_secret_access_key() -> None:
    out = redact_prompt("aws_secret_access_key=ABCDEF0123456789/+=")
    assert "<redacted>" in out


def test_redact_private_key_block() -> None:
    pem = "-----BEGIN RSA PRIVATE KEY-----\nABCDEF\n-----END RSA PRIVATE KEY-----"
    assert redact_prompt(pem) == "<redacted-private-key>"


def test_redact_long_alphanumeric_token() -> None:
    token = "a" * 40
    assert "<redacted-token>" in redact_prompt(token)


def test_redact_short_token_preserved() -> None:
    out = redact_prompt("hello deadbeef world")
    assert "deadbeef" in out


def test_redact_preserves_structure() -> None:
    out = redact_prompt("user=admin&password=hunter2&action=login")
    assert "user=admin" in out and "action=login" in out


def test_redact_idempotent() -> None:
    text = "password=foobar123"
    assert redact_prompt(redact_prompt(text)) == redact_prompt(text)
