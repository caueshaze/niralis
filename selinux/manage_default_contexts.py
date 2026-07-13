#!/usr/bin/env python3
"""Install or remove Niralis' exact pam_selinux default-context mapping.

This tool intentionally manages one fixed file and one fixed line. It does not
accept a caller-supplied target path, and refuses a conflicting niralis_t row.
"""

import argparse
import errno
import os
import re
import stat
import tempfile

TARGET = "/etc/selinux/targeted/contexts/default_contexts"
MANAGED_LINE = (
    "system_r:niralis_t:s0 user_r:user_t:s0 staff_r:staff_t:s0 "
    "sysadm_r:sysadm_t:s0 unconfined_r:unconfined_t:s0"
)
NIRALIS_ROW = re.compile(r"^system_r:niralis_t:s0(?:\s|$)")


def read_target():
    metadata = os.stat(TARGET, follow_symlinks=False)
    if not stat.S_ISREG(metadata.st_mode):
        raise RuntimeError(f"{TARGET} is not a regular file")
    if metadata.st_uid != 0:
        raise RuntimeError(f"{TARGET} is not root-owned")
    with open(TARGET, "r", encoding="utf-8", newline="") as source:
        return metadata, source.read()


def validate_existing(content):
    for line in content.splitlines():
        if NIRALIS_ROW.match(line) and line != MANAGED_LINE:
            raise RuntimeError("refusing conflicting manually managed niralis_t default_contexts row")


def atomically_replace(metadata, content):
    directory = os.path.dirname(TARGET)
    label = None
    try:
        label = os.getxattr(TARGET, "security.selinux", follow_symlinks=False)
    except OSError as error:
        if error.errno not in (errno.ENODATA, errno.EOPNOTSUPP, errno.ENOTSUP):
            raise
    fd, temporary = tempfile.mkstemp(prefix=".niralis-default-contexts-", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as destination:
            destination.write(content)
            destination.flush()
            os.fsync(destination.fileno())
        os.chown(temporary, metadata.st_uid, metadata.st_gid, follow_symlinks=False)
        os.chmod(temporary, stat.S_IMODE(metadata.st_mode), follow_symlinks=False)
        if label is not None:
            os.setxattr(temporary, "security.selinux", label, follow_symlinks=False)
        os.replace(temporary, TARGET)
        directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def install():
    metadata, content = read_target()
    validate_existing(content)
    if MANAGED_LINE in content.splitlines():
        return
    if content and not content.endswith("\n"):
        content += "\n"
    atomically_replace(metadata, content + MANAGED_LINE + "\n")


def uninstall():
    metadata, content = read_target()
    validate_existing(content)
    lines = content.splitlines(keepends=True)
    retained = [line for line in lines if line.rstrip("\r\n") != MANAGED_LINE]
    if len(retained) != len(lines):
        atomically_replace(metadata, "".join(retained))


parser = argparse.ArgumentParser()
parser.add_argument("action", choices=("install", "uninstall"))
args = parser.parse_args()
{"install": install, "uninstall": uninstall}[args.action]()
