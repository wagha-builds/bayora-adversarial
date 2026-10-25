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


def test_readonly_filesystem() -> tuple[str, str]:
    """Test that writing to rootfs is blocked strictly by read_only rootfs (EROFS = 30)."""
    print("[*] Testing file write to rootfs (expected denial: read_only rootfs -> EROFS=30)...")
    test_path = "/app/test_write_denied.txt"
    try:
        with open(test_path, "w") as f:
            f.write("forbidden")
        print(f"  [-] FAILED: writing to {test_path} succeeded unexpectedly!")
        return "FAIL", "Unexpected success"
    except OSError as e:
        if e.errno == 30:  # EROFS (Read-only file system)
            print(f"  [+] SUCCESS (BLOCKED): write to {test_path} raised expected [Errno 30] {e.strerror} (enforced by read_only rootfs)")
            return "PASS", f"[Errno 30] {e.strerror} (read_only rootfs)"
        elif e.errno == 13:  # EACCES (Permission denied) - not proof of EROFS
            print(f"  [-] INCONCLUSIVE: write failed with EACCES (13) rather than expected EROFS (30). DAC permission denied before read-only rootfs check.")
            return "INCONCLUSIVE", f"Unexpected errno=13 (EACCES), expected 30 (EROFS)"
        else:
            print(f"  [-] ERROR: write failed with unexpected errno={e.errno} ({e.strerror})")
            return "ERROR", f"Unexpected errno={e.errno}"
    except Exception as e:
        print(f"  [-] ERROR: Unexpected exception during write test: {type(e).__name__}: {e}")
        return "ERROR", str(e)

def test_ptrace_denied() -> tuple[str, str]:
    """Test that ptrace syscall is blocked (consistent with Seccomp SCMP_ACT_ERRNO -> EPERM=1)."""
    print("[*] Testing ptrace syscall (expected denial: consistent with Seccomp SCMP_ACT_ERRNO -> EPERM=1)...")
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        # PTRACE_TRACEME = 0
        res = libc.ptrace(0, 0, 0, 0)
        err = ctypes.get_errno()
        if res == -1 and err == 1:  # EPERM (Operation not permitted)
            print(f"  [+] SUCCESS (BLOCKED): ptrace returned -1 with expected EPERM (errno=1: {os.strerror(err)}) [consistent with Seccomp]")
            return "PASS", "EPERM (errno=1) [consistent with Seccomp]"
        elif res == -1:
            print(f"  [-] ERROR: ptrace failed with unexpected errno={err} ({os.strerror(err)}), expected EPERM (1)")
            return "ERROR", f"Unexpected errno={err}"
        else:
            print(f"  [-] FAILED: ptrace succeeded unexpectedly (res={res})")
            return "FAIL", f"Unexpected success (res={res})"
    except Exception as e:
        print(f"  [-] ERROR: Unexpected exception during ptrace test: {type(e).__name__}: {e}")
        return "ERROR", str(e)

def test_raw_socket_denied() -> tuple[str, str]:
    """Test that SOCK_RAW is blocked (expected: PermissionError due to cap_drop: ALL; AppArmor attribution not independently verified)."""
    print("[*] Testing raw socket creation (expected denial: cap_drop: ALL / AppArmor -> EACCES=13 or EPERM=1)...")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        s.close()
        print("  [-] FAILED: raw socket creation succeeded unexpectedly!")
        return "FAIL", "Unexpected success"
    except PermissionError as e:
        errno_val = getattr(e, "errno", 13)
        if errno_val in (1, 13):
            print(f"  [+] SUCCESS (BLOCKED): raw socket creation raised expected PermissionError: [Errno {errno_val}] (enforced by cap_drop: ALL; AppArmor attribution not independently verified)")
            return "PASS", f"PermissionError: [Errno {errno_val}] (cap_drop: ALL; AppArmor unverified)"
        else:
            print(f"  [-] ERROR: PermissionError with unexpected errno={errno_val}")
            return "ERROR", f"Unexpected errno={errno_val}"
    except OSError as e:
        if e.errno in (1, 13):
            print(f"  [+] SUCCESS (BLOCKED): raw socket creation failed with expected [Errno {e.errno}] {e.strerror} (enforced by cap_drop: ALL; AppArmor attribution not independently verified)")
            return "PASS", f"OSError: [Errno {e.errno}] (cap_drop: ALL; AppArmor unverified)"
        else:
            print(f"  [-] ERROR: raw socket failed with unexpected errno={e.errno}")
            return "ERROR", f"Unexpected errno={e.errno}"
    except Exception as e:
        print(f"  [-] ERROR: Unexpected exception during socket test: {type(e).__name__}: {e}")
        return "ERROR", str(e)

def test_mount_denied() -> tuple[str, str]:
    """Test that mount syscall is blocked (expected denial: consistent with Seccomp / cap_drop: ALL -> EPERM=1; AppArmor attribution not independently verified)."""
    print("[*] Testing mount syscall (expected denial: consistent with Seccomp / cap_drop: ALL -> EPERM=1)...")
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        # mount(source, target, filesystemtype, mountflags, data)
        res = libc.mount(b"none", b"/tmp", b"tmpfs", 0, None)
        err = ctypes.get_errno()
        if res == -1 and err == 1:  # EPERM
            print(f"  [+] SUCCESS (BLOCKED): mount returned -1 with expected errno=1 ({os.strerror(err)}) [consistent with Seccomp/cap_drop; AppArmor attribution not independently verified]")
            return "PASS", "errno=1 (EPERM) [consistent with Seccomp/cap_drop; AppArmor unverified]"
        elif res == -1 and err == 13: # EACCES
            print(f"  [+] SUCCESS (BLOCKED): mount returned -1 with errno=13 ({os.strerror(err)}) [consistent with cap_drop/LSM; AppArmor attribution not independently verified]")
            return "PASS", "errno=13 (EACCES) [consistent with cap_drop; AppArmor unverified]"
        elif res == -1:
            print(f"  [-] ERROR: mount failed with unexpected errno={err} ({os.strerror(err)})")
            return "ERROR", f"Unexpected errno={err}"
        else:
            print(f"  [-] FAILED: mount succeeded unexpectedly (res={res})")
            return "FAIL", f"Unexpected success (res={res})"
    except Exception as e:
        print(f"  [-] ERROR: Unexpected exception during mount test: {type(e).__name__}: {e}")
        return "ERROR", str(e)

def main():
    print("=" * 70)
    print(f" Bayora Negative Security Test Suite — Container: {socket.gethostname()}")
    print("=" * 70)

    all_passed = True
    tests = [
        ("ptrace_seccomp", test_ptrace_denied),
        ("raw_socket_capdrop", test_raw_socket_denied),
        ("mount_seccomp_capdrop", test_mount_denied),
        ("readonly_rootfs", test_readonly_filesystem),
    ]

    results = []
    for name, fn in tests:
        status, detail = fn()
        results.append((name, status, detail))
        if status != "PASS":
            all_passed = False

    print("\n" + "=" * 70)
    print(" NEGATIVE SECURITY TEST SUMMARY")
    print("=" * 70)
    print(f"{'TEST NAME':<25} | {'STATUS':<12} | {'DETAIL'}")
    print("-" * 70)
    for name, status, detail in results:
        print(f"{name:<25} | {status:<12} | {detail}")
    print("-" * 70)

    if all_passed:
        print("[+] ALL NEGATIVE SECURITY TESTS CONFIRMED EXPECTED DENIALS (100% PASS).")
        sys.exit(0)
    else:
        print("[-] ONE OR MORE NEGATIVE SECURITY TESTS FAILED, ERRORED, OR WERE INCONCLUSIVE.")
        sys.exit(1)

if __name__ == "__main__":
    main()
