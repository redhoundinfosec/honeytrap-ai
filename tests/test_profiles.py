"""Tests for the device profile loader."""

from __future__ import annotations

import pytest

from honeytrap.core.profile import list_bundled_profiles, load_profile
from honeytrap.exceptions import ProfileError


def test_bundled_profiles_present() -> None:
    bundled = list_bundled_profiles()
    names = {p.stem for p in bundled}
    assert {"web_server", "file_share", "iot_camera"}.issubset(names)


def test_load_web_server_profile() -> None:
    profile = load_profile("web_server")
    assert profile.category == "web_server"
    http = profile.service("http")
    ssh = profile.service("ssh")
    assert http is not None and http.port == 80
    assert ssh is not None and ssh.port == 22


def test_load_file_share_profile() -> None:
    profile = load_profile("file_share")
    assert profile.service("ftp") is not None
    assert profile.service("smb") is not None


def test_missing_profile() -> None:
    with pytest.raises(ProfileError):
        load_profile("does_not_exist_xyz")
