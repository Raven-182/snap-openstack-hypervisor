# SPDX-FileCopyrightText: 2026 - Canonical Ltd
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for encrypted storage mount management."""

import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from openstack_hypervisor.encrypted_storage import (
    BLKID_TIMEOUT_SECONDS,
    FSTAB_MANAGED_MARKER,
    FSTAB_MOUNT_OPTIONS,
    MOUNT_TIMEOUT_SECONDS,
    fstab_entry_exists,
    mount_instances_path,
    validate_xfs_filesystem,
    write_fstab_entry,
)

_MAPPER_PATH = Path("/dev/mapper/crypt-a1b2c3d4")
_INSTANCES_PATH = Path("/var/snap/openstack-hypervisor/common/lib/nova/instances")


@pytest.fixture
def fstab(tmp_path):
    return tmp_path / "fstab"


@pytest.fixture
def instances_dir(tmp_path):
    directory = tmp_path / "instances"
    directory.mkdir()
    return directory


class TestValidateXfsFilesystem:
    """Tests for validate_xfs_filesystem()."""

    def test_returns_true_for_xfs(self):
        result = MagicMock(returncode=0, stdout="xfs\n", stderr="")
        with patch(
            "openstack_hypervisor.encrypted_storage.subprocess.run", return_value=result
        ) as run:
            assert validate_xfs_filesystem(_MAPPER_PATH) is True
        run.assert_called_once_with(
            ["blkid", "-o", "value", "-s", "TYPE", str(_MAPPER_PATH)],
            capture_output=True,
            check=False,
            text=True,
            timeout=BLKID_TIMEOUT_SECONDS,
        )

    def test_returns_false_for_other_filesystem(self):
        result = MagicMock(returncode=0, stdout="ext4\n", stderr="")
        with patch("openstack_hypervisor.encrypted_storage.subprocess.run", return_value=result):
            assert validate_xfs_filesystem(_MAPPER_PATH) is False

    def test_returns_false_when_blkid_fails(self):
        result = MagicMock(returncode=2, stdout="", stderr="not found")
        with patch("openstack_hypervisor.encrypted_storage.subprocess.run", return_value=result):
            assert validate_xfs_filesystem(_MAPPER_PATH) is False

    def test_returns_false_on_oserror(self):
        with patch(
            "openstack_hypervisor.encrypted_storage.subprocess.run",
            side_effect=OSError("no blkid"),
        ):
            assert validate_xfs_filesystem(_MAPPER_PATH) is False

    def test_returns_false_on_timeout(self):
        with patch(
            "openstack_hypervisor.encrypted_storage.subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd="blkid", timeout=1),
        ):
            assert validate_xfs_filesystem(_MAPPER_PATH) is False


class TestFstabEntryExists:
    """Tests for fstab_entry_exists()."""

    def test_returns_true_for_matching_entry(self, fstab):
        fstab.write_text(f"/dev/sdb1 {_INSTANCES_PATH} xfs defaults 0 2\n")
        assert fstab_entry_exists(_INSTANCES_PATH, fstab) is True

    def test_returns_false_without_matching_entry(self, fstab):
        fstab.write_text("/dev/sda1 / ext4 defaults 0 1\n")
        assert fstab_entry_exists(_INSTANCES_PATH, fstab) is False

    def test_returns_false_when_unreadable(self, tmp_path):
        assert fstab_entry_exists(_INSTANCES_PATH, tmp_path / "missing") is False

    def test_ignores_comments_and_blanks(self, fstab):
        fstab.write_text("\n# comment line\n")
        assert fstab_entry_exists(_INSTANCES_PATH, fstab) is False


class TestWriteFstabEntry:
    """Tests for write_fstab_entry()."""

    def test_adds_entry_when_absent(self, fstab):
        fstab.write_text("/dev/sda1 / ext4 defaults 0 1\n")

        assert write_fstab_entry(_MAPPER_PATH, _INSTANCES_PATH, fstab) is True

        content = fstab.read_text()
        assert f"{_MAPPER_PATH} {_INSTANCES_PATH} xfs {FSTAB_MOUNT_OPTIONS} 0 2" in content
        assert FSTAB_MANAGED_MARKER in content

    def test_is_idempotent(self, fstab):
        fstab.write_text("/dev/sda1 / ext4 defaults 0 1\n")
        write_fstab_entry(_MAPPER_PATH, _INSTANCES_PATH, fstab)

        assert write_fstab_entry(_MAPPER_PATH, _INSTANCES_PATH, fstab) is False
        assert fstab.read_text().count(str(_INSTANCES_PATH)) == 1

    def test_respects_existing_unmanaged_entry(self, fstab):
        fstab.write_text(f"/dev/sdb1 {_INSTANCES_PATH} xfs defaults 0 2\n")

        assert write_fstab_entry(_MAPPER_PATH, _INSTANCES_PATH, fstab) is False
        assert str(_MAPPER_PATH) not in fstab.read_text()

    def test_creates_fstab_when_missing(self, tmp_path):
        new_fstab = tmp_path / "sub" / "fstab"
        new_fstab.parent.mkdir()

        assert write_fstab_entry(_MAPPER_PATH, _INSTANCES_PATH, new_fstab) is True
        assert _INSTANCES_PATH.as_posix() in new_fstab.read_text()


class TestMountInstancesPath:
    """Tests for mount_instances_path()."""

    def test_already_mounted_and_usable(self, instances_dir):
        with patch("openstack_hypervisor.encrypted_storage.is_mounted", return_value=True), patch(
            "openstack_hypervisor.encrypted_storage.is_usable", return_value=True
        ), patch("openstack_hypervisor.encrypted_storage.subprocess.run") as run:
            assert mount_instances_path(instances_dir) is True
        run.assert_not_called()

    def test_mounted_but_not_usable(self, instances_dir):
        with patch("openstack_hypervisor.encrypted_storage.is_mounted", return_value=True), patch(
            "openstack_hypervisor.encrypted_storage.is_usable", return_value=False
        ):
            assert mount_instances_path(instances_dir) is False

    def test_mounts_and_verifies(self, instances_dir):
        result = MagicMock(returncode=0, stderr="")
        with patch(
            "openstack_hypervisor.encrypted_storage.is_mounted",
            side_effect=[False, True],
        ), patch("openstack_hypervisor.encrypted_storage.is_usable", return_value=True), patch(
            "openstack_hypervisor.encrypted_storage.subprocess.run", return_value=result
        ) as run:
            assert mount_instances_path(instances_dir) is True
        run.assert_called_once_with(
            ["mount", str(instances_dir)],
            capture_output=True,
            check=False,
            text=True,
            timeout=MOUNT_TIMEOUT_SECONDS,
        )

    def test_mount_failure(self, instances_dir):
        result = MagicMock(returncode=32, stderr="mount failed")
        with patch("openstack_hypervisor.encrypted_storage.is_mounted", return_value=False), patch(
            "openstack_hypervisor.encrypted_storage.subprocess.run", return_value=result
        ):
            assert mount_instances_path(instances_dir) is False

    def test_mount_oserror(self, instances_dir):
        with patch("openstack_hypervisor.encrypted_storage.is_mounted", return_value=False), patch(
            "openstack_hypervisor.encrypted_storage.subprocess.run",
            side_effect=OSError("no mount"),
        ):
            assert mount_instances_path(instances_dir) is False

    def test_mount_timeout(self, instances_dir):
        with patch("openstack_hypervisor.encrypted_storage.is_mounted", return_value=False), patch(
            "openstack_hypervisor.encrypted_storage.subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd="mount", timeout=1),
        ):
            assert mount_instances_path(instances_dir) is False
