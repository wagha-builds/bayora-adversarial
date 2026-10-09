# Bayora Phase 2.0 Roadmap & Planning

This document tracks the decisions and Definition of Done for Phase 2.0, since the primary tracker (`task.md`) is untracked for competition reasons.

## Key Decisions
- **VM Strategy:** Oracle ARM64 instance (Ubuntu 24.04, 4 cores, 24 GB) is the primary target. If capacity is unavailable after one day, fallback to a local full Ubuntu 24.04 VM (Hyper-V/VirtualBox/VMware).
- **Same-Host Re-Baselining:** A definitive native hardware baseline must be captured on the *same machine* before hardening is applied.
- **Tagging:** The verified Phase 1 baseline is tagged as `phase1-baseline-v2`.

## Phase 2.0 Definition of Done
1. **VM Provisioning & Lockdown:** VM is running Ubuntu 24.04 with key-only SSH and only port 22 open. No Docker ports are publicly published (bind to localhost or internal network).
2. **Environment Checks:** Docker is installed, `cgroup v2` is confirmed, `docker run --runtime=runsc hello-world` works (gVisor), and `aa-status` confirms AppArmor is active.
3. **Phase 1 Stack Execution:** The Phase 1 stack runs unchanged on the VM.
4. **Native Baseline Testing:** All five leak tests, the latency benchmark, the cache-timing test, and the contention test run successfully. Host details are recorded.
5. **Tagging:** The repository is tagged as `phase2.0-vm-baseline`.
