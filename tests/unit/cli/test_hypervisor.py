# SPDX-FileCopyrightText: 2024 - Canonical Ltd
# SPDX-License-Identifier: Apache-2.0

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from openstack_hypervisor.cli.hypervisor import get_client_from_env, hypervisor


@pytest.fixture
def mock_snap():
    """Create a mock Snap instance."""
    snap = MagicMock()
    snap.paths.common = "/var/snap/test/common"
    snap.paths.data = "/var/snap/test/data"
    snap.paths.snap = "/snap/test/current"
    snap.name = "test-snap"
    return snap


@pytest.fixture
def mock_ovs_cli():
    """Create a mock OVSCli instance."""
    return MagicMock()


class TestDPDKReadyCommand:
    """Tests for the dpdk-ready CLI command."""

    @patch("openstack_hypervisor.cli.hypervisor.Snap")
    @patch("openstack_hypervisor.cli.hypervisor.OVSCli")
    @patch("openstack_hypervisor.cli.hypervisor.ovs_switch_socket")
    @patch("openstack_hypervisor.cli.hypervisor._get_configure_context")
    @patch("openstack_hypervisor.cli.hypervisor._dpdk_config_is_ready")
    def test_dpdk_ready_success(
        self,
        mock_dpdk_ready,
        mock_get_context,
        mock_socket,
        mock_ovs_cli_class,
        mock_snap_class,
    ):
        """Test dpdk-ready command returns 0 when ready."""
        mock_dpdk_ready.return_value = True
        mock_get_context.return_value = {"network": {}}
        mock_socket.return_value = "unix:/some/path"

        runner = CliRunner()
        result = runner.invoke(hypervisor, ["dpdk-ready"])

        assert result.exit_code == 0
        assert "DPDK configuration is ready" in result.output

    @patch("openstack_hypervisor.cli.hypervisor.Snap")
    @patch("openstack_hypervisor.cli.hypervisor.OVSCli")
    @patch("openstack_hypervisor.cli.hypervisor.ovs_switch_socket")
    @patch("openstack_hypervisor.cli.hypervisor._get_configure_context")
    @patch("openstack_hypervisor.cli.hypervisor._dpdk_config_is_ready")
    def test_dpdk_ready_not_ready(
        self,
        mock_dpdk_ready,
        mock_get_context,
        mock_socket,
        mock_ovs_cli_class,
        mock_snap_class,
    ):
        """Test dpdk-ready command returns 1 when not ready."""
        mock_dpdk_ready.return_value = False
        mock_get_context.return_value = {"network": {}}
        mock_socket.return_value = "unix:/some/path"

        runner = CliRunner()
        result = runner.invoke(hypervisor, ["dpdk-ready"])

        assert result.exit_code == 1
        assert "NOT ready" in result.output

    @patch("openstack_hypervisor.cli.hypervisor.Snap")
    @patch("openstack_hypervisor.cli.hypervisor.OVSCli")
    @patch("openstack_hypervisor.cli.hypervisor.ovs_switch_socket")
    @patch("openstack_hypervisor.cli.hypervisor.ovs_switchd_ctl_socket")
    @patch("openstack_hypervisor.cli.hypervisor._get_configure_context")
    @patch("openstack_hypervisor.cli.hypervisor._dpdk_config_is_ready")
    def test_dpdk_ready_uses_correct_socket(
        self,
        mock_dpdk_ready,
        mock_get_context,
        mock_switchd_ctl_socket,
        mock_socket,
        mock_ovs_cli_class,
        mock_snap_class,
    ):
        """Test dpdk-ready command uses ovs_switch_socket."""
        mock_dpdk_ready.return_value = True
        mock_get_context.return_value = {"network": {}}
        mock_socket.return_value = "unix:/custom/socket/path"
        mock_switchd_ctl_socket.return_value = "unix:/custom/ctl/socket/path"

        runner = CliRunner()
        runner.invoke(hypervisor, ["dpdk-ready"])

        # Verify OVSCli was created with the socket from ovs_switch_socket
        mock_ovs_cli_class.assert_called_once_with(
            "unix:/custom/socket/path", "unix:/custom/ctl/socket/path"
        )


class TestGetClientFromEnv:
    """Tests for get_client_from_env cacert handling."""

    @patch("openstack_hypervisor.cli.hypervisor.client")
    @patch("openstack_hypervisor.cli.hypervisor.Snap")
    def test_cacert_is_file_path_not_pem_bytes(self, mock_snap_class, mock_client, tmp_path):
        """Cacert passed to novaclient must be a file path string, not PEM bytes."""
        import base64

        pem = b"-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----"
        certs_dir = tmp_path / "etc/ssl/certs"
        certs_dir.mkdir(parents=True)
        cacert_file = certs_dir / "receive-ca-bundle.pem"
        cacert_file.write_bytes(pem)

        snap = MagicMock()
        snap.paths.common = tmp_path
        snap.config.get_options.return_value = {
            "identity.auth-url": "https://keystone/v3",
            "identity.username": "user",
            "identity.password": "pass",
            "identity.project-id": "proj",
            "identity.user-domain-id": "udid",
            "identity.project-domain-id": "pdid",
        }
        snap.config.get.side_effect = lambda key: {
            "ca.bundle": base64.b64encode(pem).decode(),
        }.get(key, "")
        mock_snap_class.return_value = snap

        get_client_from_env(snap)

        _, kwargs = mock_client.Client.call_args
        assert kwargs["cacert"] is not None
        # must be a str path, not bytes/PEM content
        assert isinstance(kwargs["cacert"], str)
        assert "BEGIN CERTIFICATE" not in kwargs["cacert"]
        assert kwargs["cacert"] == str(cacert_file)


class TestConfigureEncryptedStorageCommand:
    """Tests for the configure-encrypted-storage CLI command."""

    @patch("openstack_hypervisor.cli.hypervisor.Snap")
    @patch("openstack_hypervisor.cli.hypervisor.validate_xfs_filesystem")
    @patch("openstack_hypervisor.cli.hypervisor.write_fstab_entry")
    @patch("openstack_hypervisor.cli.hypervisor.mount_instances_path")
    def test_success(self, mock_mount, mock_write, mock_validate, mock_snap_class):
        """A valid XFS mapper is recorded and mounted."""
        snap = MagicMock()
        snap.paths.common = Path("/var/snap/test/common")
        mock_snap_class.return_value = snap
        mock_validate.return_value = True
        mock_mount.return_value = True

        result = CliRunner().invoke(
            hypervisor,
            [
                "configure-encrypted-storage",
                "--mapper-path",
                "/dev/mapper/crypt-a1b2c3d4",
                "--luks-uuid",
                "a1b2c3d4",
            ],
        )

        instances_path = Path("/var/snap/test/common/lib/nova/instances")
        assert result.exit_code == 0
        mock_validate.assert_called_once_with(Path("/dev/mapper/crypt-a1b2c3d4"))
        mock_write.assert_called_once_with(Path("/dev/mapper/crypt-a1b2c3d4"), instances_path)
        mock_mount.assert_called_once_with(instances_path)
        assert json.loads(result.output)["luks_uuid"] == "a1b2c3d4"

    @patch("openstack_hypervisor.cli.hypervisor.Snap")
    @patch("openstack_hypervisor.cli.hypervisor.validate_xfs_filesystem")
    @patch("openstack_hypervisor.cli.hypervisor.write_fstab_entry")
    @patch("openstack_hypervisor.cli.hypervisor.mount_instances_path")
    def test_rejects_non_xfs(self, mock_mount, mock_write, mock_validate, mock_snap_class):
        """A non-XFS device is rejected before any fstab change."""
        mock_validate.return_value = False

        result = CliRunner().invoke(
            hypervisor,
            [
                "configure-encrypted-storage",
                "--mapper-path",
                "/dev/mapper/crypt-a1b2c3d4",
                "--luks-uuid",
                "a1b2c3d4",
            ],
        )

        assert result.exit_code == 1
        mock_write.assert_not_called()
        mock_mount.assert_not_called()

    @patch("openstack_hypervisor.cli.hypervisor.Snap")
    @patch("openstack_hypervisor.cli.hypervisor.validate_xfs_filesystem")
    @patch("openstack_hypervisor.cli.hypervisor.write_fstab_entry")
    @patch("openstack_hypervisor.cli.hypervisor.mount_instances_path")
    def test_rejects_mount_failure(self, mock_mount, mock_write, mock_validate, mock_snap_class):
        """A mount failure exits non-zero."""
        snap = MagicMock()
        snap.paths.common = Path("/var/snap/test/common")
        mock_snap_class.return_value = snap
        mock_validate.return_value = True
        mock_mount.return_value = False

        result = CliRunner().invoke(
            hypervisor,
            [
                "configure-encrypted-storage",
                "--mapper-path",
                "/dev/mapper/crypt-a1b2c3d4",
                "--luks-uuid",
                "a1b2c3d4",
            ],
        )

        assert result.exit_code == 1
        mock_write.assert_called_once()
