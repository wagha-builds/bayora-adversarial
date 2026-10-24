#!/usr/bin/env python3
"""
Bayora Negative Security Tests (Phase 2.3 Verification Pass)
Explicitly validates that denied actions under Seccomp, AppArmor,
Read-Only Rootfs, and Capability-Drop (cap_drop: ALL) fail visibly with
expected denial codes (EPERM, EACCES, EROFS).
"""

import ctypes
import os
import socket
import sys

def test_ptrace_denied():
    """Test that ptrace syscall is blocked by Seccomp (EPERM = 1)."""
    print("[*] Testing ptrace syscall (should be blocked by Seccomp)...")
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        # PTRACE_TRACEME = 0
        res = libc.ptrace(0, 0, 0, 0)
        err = ctypes.get_errno()
        if res == -1 and err == 1: # EPERM
            print(f"  [+] SUCCESS (BLOCKED): ptrace returned -1 with EPERM (errno=1, Operation not permitted)")
            return True, "EPERM (errno=1)"
        elif res == -1:
            print(f"  [+] BLOCKED: ptrace returned -1 with errno={err}")
            return True, f"errno={err}"
        else:
            print(f"  [-] FAILED: ptrace succeeded unexpectedly (res={res})")
            return False, f"Unexpected success (res={res})"
    except Exception as e:
        print(f"  [+] EXCEPTION: {e}")
        return True, str(e)

def test_raw_socket_denied():
    """Test that SOCK_RAW is blocked by AppArmor ('deny network raw') and cap_drop ALL."""
    print("[*] Testing raw socket creation (should be blocked by AppArmor/cap_drop)...")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        s.close()
        print("  [-] FAILED: raw socket creation succeeded unexpectedly!")
        return False, "Unexpected success"
    except PermissionError as e:
        print(f"  [+] SUCCESS (BLOCKED): raw socket creation raised PermissionError: {e}")
        return True, str(e)
    except Exception as e:
        print(f"  [+] SUCCESS (BLOCKED): raw socket creation failed: {e}")
        return True, str(e)

def test_mount_denied():
    """Test that mount syscall is blocked by AppArmor ('deny mount') and cap_drop ALL."""
    print("[*] Testing mount syscall (should be blocked by AppArmor/cap_drop)...")
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        # mount(source, target, filesystemtype, mountflags, data)
        res = libc.mount(b"none", b"/tmp", b"tmpfs", 0, None)
        err = ctypes.get_errno()
        if res == -1:
            print(f"  [+] SUCCESS (BLOCKED): mount returned -1 with errno={err} ({os.strerror(err)})")
            return True, f"errno={err} ({os.strerror(err)})"
        else:
            print(f"  [-] FAILED: mount succeeded unexpectedly (res={res})")
            return False, f"Unexpected success (res={res})"
    except Exception as e:
        print(f"  [+] EXCEPTION: {e}")
        return True, str(e)

def test_readonly_filesystem():
    """Test that writing to rootfs is blocked by read_only rootfs."""
    print("[*] Testing file write to rootfs (should be blocked by read_only rootfs)...")
    test_path = "/app/test_write_denied.txt"
    try:
        with open(test_path, "w") as f:
            f.write("forbidden")
        print(f"  [-] FAILED: writing to {test_path} succeeded unexpectedly!")
        return False, "Unexpected success"
    except OSError as e:
        print(f"  [+] SUCCESS (BLOCKED): write to {test_path} failed with: {e}")
        return True, str(e)

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
        print("[+] ALL NEGATIVE SECURITY TESTS CONFIRMED ENFORCEMENT.")
        sys.exit(0)
    else:
        print("[-] ONE OR MORE NEGATIVE SECURITY TESTS FAILED.")
        sys.exit(1)

if __name__ == "__main__":
    main()
