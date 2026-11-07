"""
fileutil.py — file helpers shared by the CLI and the web dashboard.
"""

import contextlib
import json
import os
import tempfile


def give_to_invoking_user(path):
    """If running under sudo, hand a file we created back to the real user.

    Raw-packet scanning needs root, so the scanner is started with sudo and
    every file it writes is owned by root. The next normal (non-sudo) run then
    fails with PermissionError. sudo records who the real user is in SUDO_UID
    and SUDO_GID, so we give ownership back to them.

    Does nothing when not root, or when there is no sudo user (a real root
    shell or a container), which is the correct behaviour in both cases.
    """
    if not hasattr(os, "geteuid") or os.geteuid() != 0:
        return
    uid = os.environ.get("SUDO_UID")
    gid = os.environ.get("SUDO_GID")
    if uid is None or gid is None:
        return
    with contextlib.suppress(OSError, ValueError):
        os.chown(path, int(uid), int(gid))


def ensure_dir(path):
    """Create a directory (if needed) owned by the real user, and return it."""
    os.makedirs(path, exist_ok=True)
    give_to_invoking_user(path)
    return path


def write_json_atomic(path, data, indent=2):
    """Write JSON so the file is never left half-written.

    The data goes to a temporary file in the same directory, which then
    replaces the target in one step (os.replace is atomic). If the process
    dies mid-write, the old file is still intact instead of truncated, and a
    corrupt history file can't silently wipe the scan history on next save.
    """
    directory = os.path.dirname(os.path.abspath(path))
    fd, tmp_path = tempfile.mkstemp(dir=directory, prefix=".tmp-", suffix=".json")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=indent)
        os.replace(tmp_path, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.remove(tmp_path)
        raise
    give_to_invoking_user(path)
