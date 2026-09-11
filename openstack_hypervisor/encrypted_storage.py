# SPDX-FileCopyrightText: 2026 - Canonical Ltd
# SPDX-License-Identifier: Apache-2.0

"""Manage the mount for encrypted Nova instance storage.

The operator prepares the LUKS container and XFS filesystem. Vaultlocker
opens the mapper device and this module validates the filesystem, records
a managed ``/etc/fstab`` entry, and mounts the Nova instances path.
"""

import logging
import subprocess
from pathlib import Path

from openstack_hypervisor.mount_validation import is_mounted, is_usable

LOG = logging.getLogger(__name__)

#: Marker appended to ``/etc/fstab`` entries managed by the hypervisor.
FSTAB_MANAGED_MARKER = "# managed-by-openstack-hypervisor"

#: Mount options for the managed entry. ``nofail`` keeps the host booting
#: when the encrypted device is unavailable; nova-compute stays stopped.
FSTAB_MOUNT_OPTIONS = "defaults,nofail"

#: Maximum seconds to wait for ``blkid`` and ``mount`` before giving up.
BLKID_TIMEOUT_SECONDS = 30
MOUNT_TIMEOUT_SECONDS = 60


def validate_xfs_filesystem(mapper_path: Path) -> bool:
    """Return True when the mapper device contains an XFS filesystem."""
    try:
        result = subprocess.run(
            ["blkid", "-o", "value", "-s", "TYPE", str(mapper_path)],
            capture_output=True,
            check=False,
            text=True,
            timeout=BLKID_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        LOG.warning("Unable to inspect filesystem on %s (%s).", mapper_path, exc)
        return False

    if result.returncode != 0 or result.stdout.strip() != "xfs":
        LOG.error(
            "Device %s does not contain an XFS filesystem (blkid: %s).",
            mapper_path,
            result.stdout.strip() or result.stderr.strip(),
        )
        return False

    return True


def fstab_entry_exists(
    instances_path: Path,
    fstab_path: Path = Path("/etc/fstab"),
) -> bool:
    """Return True when an fstab entry already targets the instances path."""
    try:
        text = fstab_path.read_text()
    except OSError as exc:
        LOG.warning("Unable to read %s: %s", fstab_path, exc)
        return False

    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        fields = stripped.split()
        if len(fields) >= 2 and Path(fields[1]) == instances_path:
            return True
    return False


def write_fstab_entry(
    mapper_path: Path,
    instances_path: Path,
    fstab_path: Path = Path("/etc/fstab"),
) -> bool:
    """Idempotently add a managed fstab entry for the encrypted storage.

    Returns True when the file was changed. An entry that already exists
    for the instances path is left untouched, whether or not it carries
    the managed marker.
    """
    if fstab_entry_exists(instances_path, fstab_path):
        LOG.info("An fstab entry for %s already exists, leaving it unchanged.", instances_path)
        return False

    entry = "{} {} xfs {} 0 2 {}\n".format(
        mapper_path,
        instances_path,
        FSTAB_MOUNT_OPTIONS,
        FSTAB_MANAGED_MARKER,
    )
    with fstab_path.open("a", encoding="utf-8") as fstab:
        fstab.write(entry)
    LOG.info("Added managed fstab entry for %s.", instances_path)
    return True


def mount_instances_path(instances_path: Path) -> bool:
    """Mount the instances path from fstab and verify it is usable.

    Idempotent: an already-mounted path is only re-verified.
    """
    if is_mounted(instances_path):
        return is_usable(instances_path)

    try:
        instances_path.mkdir(parents=True, exist_ok=True)
        result = subprocess.run(
            ["mount", str(instances_path)],
            capture_output=True,
            check=False,
            text=True,
            timeout=MOUNT_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        LOG.error("Unable to mount %s (%s).", instances_path, exc)
        return False

    if result.returncode != 0:
        LOG.error("Failed to mount %s: %s", instances_path, result.stderr.strip())
        return False

    return is_mounted(instances_path) and is_usable(instances_path)
