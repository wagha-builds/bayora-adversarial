#!/usr/bin/env python3
"""
Bayora Negative Security Tests (Phase 2.3 Verification Pass)
Explicitly validates that denied actions under Seccomp, AppArmor,
Read-Only Rootfs, and Capability-Drop (cap_drop: ALL) fail visibly with
their expected denial error codes (EPERM, EACCES, EROFS).
"""

import ctypes
import os
import socket
import sys

def test_ptrace_denied() -> tuple[bool, str]:
    """Test that ptrace syscall is blocked by Seccomp (EPERM = 1)."""
    print("[*] Testing ptrace syscall (expected denial: Seccomp SCMP_ACT_ERRNO -> EPERM)...")
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        # PTRACE_TRACEME = 0
        res = libc.ptrace(0, 0, 0, 0)
        err = ctypes.get_errno()
        if res == -1 and err == 1:  # EPERM (Operation not permitted)
            print(f"  [+] SUCCESS (BLOCKED): ptrace returned -1 with expected EPERM (errno=1: {os.strerror(err)})")
            return True, "EPERM (errno=1)"
        elif res == -1:
            print(f"  [-] ERROR: ptrace failed with unexpected errno={err} ({os.strerror(err)}), expected EPERM (1)")
            return False, f"Unexpected errno={err}"
        else:
            print(f"  [-] FAILED: ptrace succeeded unexpectedly (res={res})")
            return False, f"Unexpected success (res={res})"
    except Exception as e:
        print(f"  [-] ERROR: Unexpected exception during ptrace test: {type(e).__name__}: {e}")
        return False, str(e)

def test_raw_socket_denied() -> tuple[bool, str]:
    """Test that SOCK_RAW is blocked by AppArmor ('deny network raw') and cap_drop ALL."""
    print("[*] Testing raw socket creation (expected denial: AppArmor / cap_drop ALL -> EACCES / EPERM)...")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        s.close()
        print("  [-] FAILED: raw socket creation succeeded unexpectedly!")
        return False, "Unexpected success"
    except PermissionError as e:
        # PermissionError corresponds to Errno 13 (EACCES) or Errno 1 (EPERM)
        errno_val = getattr(e, "errno", 13)
        if errno_val in (1, 13):
            print(f"  [+] SUCCESS (BLOCKED): raw socket creation raised expected PermissionError: [Errno {errno_val}] {e.strerror or e}")
            return True, f"PermissionError: [Errno {errno_val}]"
        else:
            print(f"  [-] ERROR: PermissionError with unexpected errno={errno_val}")
            return False, f"Unexpected errno={errno_val}"
    except OSError as e:
        if e.errno in (1, 13):
            print(f"  [+] SUCCESS (BLOCKED): raw socket creation failed with expected [Errno {e.errno}] {e.strerror}")
            return True, f"OSError: [Errno {e.errno}]"
        else:
            print(f"  [-] ERROR: raw socket failed with unexpected errno={e.errno}")
            return False, f"Unexpected errno={e.errno}"
    except Exception as e:
        print(f"  [-] ERROR: Unexpected exception during socket test: {type(e).__name__}: {e}")
        return False, str(e)

def test_mount_denied() -> tuple[bool, str]:
    """Test that mount syscall is blocked by Seccomp/AppArmor/cap_drop."""
    print("[*] Testing mount syscall (expected denial: Seccomp/AppArmor/cap_drop -> EPERM=1 or EACCES=13)...")
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        # mount(source, target, filesystemtype, mountflags, data)
        res = libc.mount(b"none", b"/tmp", b"tmpfs", 0, None)
        err = ctypes.get_errno()
        if res == -1 and err in (1, 13):  # EPERM or EACCES
            print(f"  [+] SUCCESS (BLOCKED): mount returned -1 with expected errno={err} ({os.strerror(err)})")
            return True, f"errno={err} ({os.strerror(err)})"
        elif res == -1:
            print(f"  [-] ERROR: mount failed with unexpected errno={err} ({os.strerror(err)})")
            return False, f"Unexpected errno={err}"
        else:
            print(f"  [-] FAILED: mount succeeded unexpectedly (res={res})")
            return False, f"Unexpected success (res={res})"
    except Exception as e:
        print(f"  [-] ERROR: Unexpected exception during mount test: {type(e).__name__}: {e}")
        return False, str(e)

def test_readonly_filesystem() -> tuple[bool, str]:
    """Test that writing to rootfs is blocked by read_only rootfs (EROFS = 30)."""
    print("[*] Testing file write to rootfs (expected denial: read_only rootfs -> EROFS=30)...")
    test_path = "/app/test_write_denied.txt"
    try:
        with open(test_path, "w") as f:
            f.write("forbidden")
        print(f"  [-] FAILED: writing to {test_path} succeeded unexpectedly!")
        return False, "Unexpected success"
    except OSError as e:
        if e.errno in (30, 13):  # EROFS (Read-only file system) or EACCES
            print(f"  [+] SUCCESS (BLOCKED): write to {test_path} raised expected OSError: [Errno {e.errno}] {e.strerror}")
            return True, f"[Errno {e.errno}] {e.strerror}"
        else:
            print(f"  [-] ERROR: write failed with unexpected errno={e.errno} ({e.strerror})")
            return False, f"Unexpected errno={e.errno}"
    except Exception as e:
        print(f"  [-] ERROR: Unexpected exception during write test: {type(e).__name__}: {e}")
        return False, str(e)

def main():
    print("=" * 65)
    print(f" Bayora Negative Security Test Suite — Container: {socket.gethostname()}")
    print("=" * 65)

    all_passed = True
    tests = [
        ("ptrace_seccomp", test_ptrace_denied),
        ("raw_socket_apparmor", test_raw_socket_denied),
        ("mount_apparmor", test_mount_denied),
        ("readonly_rootfs", test_readonly_filesystem),
    ]

    for name, fn in tests:
        passed, detail = fn()
        if not passed:
            all_passed = False

    print("=" * 65)
    if all_passed:
        print("[+] ALL NEGATIVE SECURITY TESTS CONFIRMED EXPECTED DENIALS.")
        sys.exit(0)
    else:
        print("[-] ONE OR MORE NEGATIVE SECURITY TESTS FAILED OR HAD UNEXPECTED OUTCOMES.")
        sys.exit(1)

if __name__ == "__main__":
    main()
