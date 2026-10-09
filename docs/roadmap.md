# Bayora Phase 2.0 Roadmap & Planning

This document tracks architectural decisions, environment specifications, and the Definition of Done for Phase 2.0.

## Key Decisions & VM Strategy
- **Immediate Target (Local VM):** Full Ubuntu 24.04 LTS VM running on VMware Workstation Pro 17+ (or VirtualBox 7.0+). Windows Home does not support Hyper-V Manager.
- **Host Specs & VM Sizing:**
  - Host: 13th Gen Intel Core i5-13450HX (10 cores / 16 threads, 16 GB RAM).
  - VM Configuration: **6 vCPUs, 8 GB RAM** (avoids Windows 11 host paging/swapping), **60 GB dynamic disk**.
  - Networking: NAT with forwarded SSH port (e.g., host `127.0.0.1:2222` -> VM `22`) or Host-Only. Do not bridge onto LAN.
- **Oracle ARM64 Strategy:** Treat Oracle OCI as a future migration target rather than a blocker. If/when Oracle capacity is provisioned, migrate only at a phase boundary.
- **Host-Separated Evidence Storage:**
  - Local VM baseline results: `results/baseline/local-ubuntu-vm/`
  - Oracle ARM64 baseline results (when migrated): `results/baseline/oracle-arm64/`
  - All test results record host CPU, core count, RAM, kernel version, and architecture.
- **Same-Host Comparison Invariant:** Hardened vs. unhardened benchmarks must strictly be measured on the *same machine*. If switching to Oracle later, re-baseline the stack on the new host first.
- **Automated Provisioning:** Use `scripts/provision-host.sh` for architecture-aware setup (Docker, gVisor `runsc`, AppArmor, cgroup v2 verification).

## Phase 2.0 Definition of Done
1. **VM Provisioning & Lockdown:** VM is running Ubuntu 24.04 with key-only SSH. Docker ports are bound strictly to localhost.
2. **Environment Checks:** `scripts/provision-host.sh` executes cleanly: Docker running, `cgroup v2` confirmed (`cgroup2fs`), `docker run --runtime=runsc hello-world` passes, and AppArmor is active.
3. **Phase 1 Stack Execution:** The Phase 1 stack runs unchanged on the VM.
4. **Native Baseline Testing:** All five leak tests, latency benchmark, cache-timing test, and contention test run successfully. Host fingerprint is saved with results.
5. **Tagging:** The repository is tagged as `phase2.0-vm-baseline`.

