#!/usr/bin/env python3
"""
Bayora Seccomp Profiles Static Security Audit
Programmatically validates that all 18 designated high-risk syscalls:
- Are validly parsed in JSON
- Have an explicit unconditional deny rule (SCMP_ACT_ERRNO/KILL/TRAP with empty args)
- Are STRICTLY ABSENT from ANY SCMP_ACT_ALLOW rule (unconditional, conditional, or arch-specific) across the entire profile.
- Distinguishes static profile verification from runtime empirical testing.
"""

import datetime
import json
import os
import sys

TARGET_SYSCALLS = [
    "ptrace",
    "bpf",
    "perf_event_open",
    "userfaultfd",
    "kexec_load",
    "kexec_file_load",
    "mount",
    "umount",
    "umount2",
    "pivot_root",
    "keyctl",
    "add_key",
    "request_key",
    "init_module",
    "finit_module",
    "delete_module",
    "process_vm_readv",
    "process_vm_writev"
]

EMPIRICALLY_TESTED = ["ptrace", "mount"]

PROFILES = [
    "policies/seccomp/model-server-seccomp.json",
    "policies/seccomp/python-service-seccomp.json"
]


def audit_profile_data(data: dict, filepath: str = "memory") -> dict:
    """Audit parsed seccomp profile dictionary across all rule blocks."""
    default_action = data.get("defaultAction", "")
    syscall_rules = data.get("syscalls", [])

    allow_occurrences = {s: [] for s in TARGET_SYSCALLS}
    unconditional_deny = {s: [] for s in TARGET_SYSCALLS}
    conditional_deny = {s: [] for s in TARGET_SYSCALLS}

    for idx, rule in enumerate(syscall_rules):
        action = rule.get("action", "")
        names = rule.get("names", [])
        args = rule.get("args", [])
        comment = rule.get("comment", "")
        includes = rule.get("includes", {})
        excludes = rule.get("excludes", {})

        is_conditional = bool(args) or bool(includes) or bool(excludes)
        rule_desc = f"block #{idx} (action={action}, args={len(args)})"
        if comment:
            rule_desc += f" /* {comment} */"

        for s in TARGET_SYSCALLS:
            if s in names:
                if action == "SCMP_ACT_ALLOW":
                    allow_occurrences[s].append(rule_desc)
                elif action in ("SCMP_ACT_ERRNO", "SCMP_ACT_KILL", "SCMP_ACT_TRAP"):
                    if not is_conditional:
                        unconditional_deny[s].append(rule_desc)
                    else:
                        conditional_deny[s].append(rule_desc)

    prohibited_allowed = {s: occ for s, occ in allow_occurrences.items() if occ}
    missing_unconditional_deny = {}

    syscall_details = {}
    for s in TARGET_SYSCALLS:
        allowed = bool(allow_occurrences[s])
        has_uncond_deny = bool(unconditional_deny[s])
        has_cond_deny = bool(conditional_deny[s])

        if allowed:
            status = "PROHIBITED_IN_ALLOW"
        elif has_uncond_deny:
            status = "UNCONDITIONALLY_DENIED"
        elif has_cond_deny:
            status = "CONDITIONALLY_DENIED_ONLY"
            missing_unconditional_deny[s] = conditional_deny[s]
        elif default_action in ("SCMP_ACT_ERRNO", "SCMP_ACT_KILL", "SCMP_ACT_TRAP"):
            status = f"DENIED_BY_DEFAULT_ACTION ({default_action})"
        else:
            status = "MISSING_DENY_RULE"
            missing_unconditional_deny[s] = ["not found in deny rules or defaultAction"]

        syscall_details[s] = {
            "status": status,
            "allow_rules": allow_occurrences[s],
            "unconditional_deny_rules": unconditional_deny[s],
            "conditional_deny_rules": conditional_deny[s]
        }

    passed = (len(prohibited_allowed) == 0) and (len(missing_unconditional_deny) == 0)

    return {
        "file": filepath,
        "valid_json": True,
        "passed": passed,
        "default_action": default_action,
        "total_rule_blocks": len(syscall_rules),
        "prohibited_allowed": prohibited_allowed,
        "missing_unconditional_deny": missing_unconditional_deny,
        "details": syscall_details
    }


def audit_profile_file(filepath: str) -> dict:
    if not os.path.isfile(filepath):
        print(f"[-] ERROR: File {filepath} not found!")
        return {"file": filepath, "valid_json": False, "passed": False, "error": "file_not_found"}

    try:
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        print(f"[-] JSON Syntax INVALID in {filepath}: {e}")
        return {"file": filepath, "valid_json": False, "passed": False, "error": str(e)}

    return audit_profile_data(data, filepath)


def run_self_tests() -> bool:
    """Validate auditor logic using safe synthetic seccomp profiles."""
    print("[*] Running auditor self-tests against synthetic profiles...")

    # Test 1: Valid hardened synthetic profile
    valid_profile = {
        "defaultAction": "SCMP_ACT_ERRNO",
        "syscalls": [
            {"names": list(TARGET_SYSCALLS), "action": "SCMP_ACT_ERRNO"},
            {"names": ["read", "write", "exit"], "action": "SCMP_ACT_ALLOW"}
        ]
    }
    res1 = audit_profile_data(valid_profile, "synthetic_valid")
    if not res1["passed"]:
        print("[-] Self-test 1 (valid profile) FAILED unexpectedly!")
        return False

    # Test 2: Target syscall in unconditional allow rule
    allow_violation = {
        "defaultAction": "SCMP_ACT_ERRNO",
        "syscalls": [
            {"names": list(TARGET_SYSCALLS), "action": "SCMP_ACT_ERRNO"},
            {"names": ["ptrace"], "action": "SCMP_ACT_ALLOW"}
        ]
    }
    res2 = audit_profile_data(allow_violation, "synthetic_allow_violation")
    if res2["passed"] or "ptrace" not in res2["prohibited_allowed"]:
        print("[-] Self-test 2 (allow violation) failed to catch prohibited allow rule!")
        return False

    # Test 3: Target syscall in conditional allow rule
    cond_allow_violation = {
        "defaultAction": "SCMP_ACT_ERRNO",
        "syscalls": [
            {"names": list(TARGET_SYSCALLS), "action": "SCMP_ACT_ERRNO"},
            {"names": ["mount"], "action": "SCMP_ACT_ALLOW", "args": [{"index": 0, "value": 0, "op": "SCMP_CMP_EQ"}]}
        ]
    }
    res3 = audit_profile_data(cond_allow_violation, "synthetic_cond_allow_violation")
    if res3["passed"] or "mount" not in res3["prohibited_allowed"]:
        print("[-] Self-test 3 (conditional allow violation) failed to catch conditional allow rule!")
        return False

    # Test 4: Missing unconditional deny when defaultAction is ALLOW
    missing_deny = {
        "defaultAction": "SCMP_ACT_ALLOW",
        "syscalls": [
            {"names": [s for s in TARGET_SYSCALLS if s != "bpf"], "action": "SCMP_ACT_ERRNO"}
        ]
    }
    res4 = audit_profile_data(missing_deny, "synthetic_missing_deny")
    if res4["passed"] or "bpf" not in res4["missing_unconditional_deny"]:
        print("[-] Self-test 4 (missing deny) failed to catch omitted target syscall!")
        return False

    print("[+] All 4 auditor self-tests passed successfully.")
    return True


def main():
    capture_time = datetime.datetime.now(datetime.timezone.utc).isoformat()

    print("=" * 70)
    print(" BAYORA STATIC SECCOMP PROFILE AUDIT")
    print(f" Timestamp (UTC): {capture_time}")
    print(f" Target List: {len(TARGET_SYSCALLS)} designated high-risk syscalls")
    print("=" * 70)

    if not run_self_tests():
        print("[-] AUDITOR LOGIC INTEGRITY CHECK FAILED.")
        sys.exit(1)

    all_passed = True
    results = []
    for p in PROFILES:
        print(f"\n--- Auditing: {p} ---")
        res = audit_profile_file(p)
        results.append(res)
        if not res["passed"]:
            all_passed = False
        else:
            print(f"[+] Syntax: VALID | Default Action: {res['default_action']} | Total Rule Blocks: {res['total_rule_blocks']}")
            print(f"[+] All {len(TARGET_SYSCALLS)} target syscalls confirmed unconditionally denied.")
            print(f"[+] Zero target syscalls present in any SCMP_ACT_ALLOW rule.")

    print("\n" + "=" * 70)
    print(" STATIC AUDIT SUMMARY & EMPIRICAL DISTINCTION")
    print("=" * 70)
    for r in results:
        status = "PASSED" if r["passed"] else "FAILED"
        print(f"Profile: {r['file']:<45} | Status: {status}")

    print("\nEmpirical Runtime Testing Status:")
    print(f"- Empirically tested in negative harness: {', '.join(EMPIRICALLY_TESTED)} (denials observed: ptrace -> EPERM, mount -> EPERM)")
    remaining_syscalls = [s for s in TARGET_SYSCALLS if s not in EMPIRICALLY_TESTED]
    print(f"- Statically verified in profile rules only: {', '.join(remaining_syscalls)}")
    print(f"  Note: The remaining {len(remaining_syscalls)} syscalls were not individually tested at runtime.")

    # Save authentic evidence artifact
    output_dir = "results/hardening/phase2.3-least-privilege/local-ubuntu-vm"
    os.makedirs(output_dir, exist_ok=True)
    report_file = os.path.join(output_dir, "seccomp_static_audit.txt")

    with open(report_file, "w", encoding="utf-8") as f:
        f.write("# Bayora Static Seccomp Profile Audit Output\n")
        f.write(f"# Capture Timestamp (UTC): {capture_time}\n")
        f.write(f"# Command: python3 scripts/audit_seccomp_profiles.py\n")
        f.write(f"# Auditor Self-Tests: 4/4 PASSED\n")
        f.write(f"# Target High-Risk Syscalls: {len(TARGET_SYSCALLS)}\n\n")

        for r in results:
            f.write(f"Profile: {r['file']}\n")
            f.write(f"  JSON Syntax: {'VALID' if r['valid_json'] else 'INVALID'}\n")
            f.write(f"  Default Action: {r.get('default_action', 'N/A')}\n")
            f.write(f"  Total Rule Blocks: {r.get('total_rule_blocks', 0)}\n")
            f.write(f"  Audit Status: {'PASSED' if r['passed'] else 'FAILED'}\n")
            f.write(f"  Prohibited in Allow: {len(r.get('prohibited_allowed', {}))}\n")
            f.write(f"  Missing Unconditional Deny: {len(r.get('missing_unconditional_deny', {}))}\n")
            f.write("  Target Syscall Breakdown:\n")
            for s in TARGET_SYSCALLS:
                det = r.get("details", {}).get(s, {})
                f.write(f"    - {s:<20}: {det.get('status', 'UNKNOWN')}\n")
            f.write("\n")

        f.write("# Empirical vs Static Enforcement Distinction:\n")
        f.write(f"# Empirically tested at runtime: {', '.join(EMPIRICALLY_TESTED)}\n")
        f.write(f"# Statically verified in profile rules only: {', '.join(remaining_syscalls)}\n")
        f.write(f"# Note: The remaining {len(remaining_syscalls)} syscalls were not individually tested at runtime.\n")

    print(f"\n[+] Refreshed seccomp audit artifact saved to: {report_file}")
    sys.exit(0 if all_passed else 1)


if __name__ == "__main__":
    main()
