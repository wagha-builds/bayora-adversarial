# Bayora Hardening Roadmap & Planning (Phases 2.0–2.3)


This document tracks architectural decisions, environment specifications, and the Definition of Done for Phase 2.0.

## Key Decisions & VM Strategy
- **Immediate Target (Local VM):** Full Ubuntu 24.04 LTS VM running on VMware Workstation Pro 17+ (or VirtualBox 7.0+). Windows Home does not support Hyper-V Manager.
- **Host Specs & VM Sizing:**
  - Host: 13th Gen Intel Core i5-13450HX (10 cores / 16 threads, 16 GB RAM).
  - VM Configuration: **6 vCPUs, 8 GB RAM** (avoids Windows 11 host paging/swapping), **60 GB dynamic disk**.
  - **Limitation Note:** Windows dynamically schedules VM threads across P-cores (with hyperthreading) and E-cores. vCPUs are not pinned to physical P-cores, meaning timing results (especially contention) will have noise/variance and are considered provisional.
  - Networking: NAT with forwarded SSH port (e.g., host `127.0.0.1:2222` -> VM `22`) or Host-Only. Do not bridge onto LAN.
- **Oracle ARM64 Strategy:** Treat Oracle OCI as a future migration target rather than a blocker. If/when Oracle capacity is provisioned, migrate only at a phase boundary.
- **Host-Separated Evidence Storage:**
  - Local VM baseline results: `results/baseline/local-ubuntu-vm/`
  - Oracle ARM64 baseline results (when migrated): `results/baseline/oracle-arm64/`
  - All test results record host CPU, core count, RAM, kernel version, and architecture.
- **Same-Host Comparison Invariant:** Hardened vs. unhardened benchmarks must strictly be measured on the *same machine*. If switching to Oracle later, re-baseline the stack on the new host first.
- **Automated Provisioning:** Use `scripts/provision-host.sh` for architecture-aware setup (Docker, gVisor `runsc`, AppArmor, cgroup v2 verification).

## Phase 2.0 Definition of Done (COMPLETED WITH WAIVER ✅)
1. **VM Provisioning & Lockdown:** VM is running Ubuntu 24.04 with key-only SSH. Docker ports are bound strictly to localhost.
2. **Environment Checks:** `scripts/provision-host.sh` executes cleanly: Docker running, `cgroup v2` confirmed (`cgroup2fs`), `docker run --runtime=runsc hello-world` passes, and AppArmor is active.
3. **Phase 1 Stack Execution:** The Phase 1 stack runs unchanged on the VM.
4. **Native Baseline Testing:** All five leak tests, latency benchmark, cache-timing test, and contention test run successfully. Host fingerprint is saved with results (contention benchmark waived; deferred to Phase 7).
5. **Tagging:** The repository is tagged as `phase2.0-vm-baseline`.

## Phase 2.1 Definition of Done (COMPLETED & TAGGED ✅ — `phase2.1-gvisor-hardening`)
1. **gVisor Availability:** Installed gVisor runtime (`runsc release-20261012.0`) is registered and active in Docker daemon.
2. **Red Sandboxing:** `bayora-red-runner` runs under verified `runsc` runtime with Sentry syscall isolation (`dmesg` confirms `Starting gVisor...`).
3. **Model Evaluation & Evidence Decision:** `bayora-model-server` was evaluated under `runsc`; empirical evidence recorded an 826.2% latency regression ($0.99\text{ tok/s}$). Runtime decision to retain `runc` for Model is documented and supported by evidence (`benchmark_gvisor_trial.json`).
4. **Baseline Services Functionality:** All 4 baseline services remain operational, healthy, and interconnected.
5. **Bounded Post-Change Performance:** Measured and recorded bounded before-and-after inference latency ($p50 = 4,859.72\text{ ms}$, $14.98\text{ tok/s}$).
6. **Leak Test Master Suite:** Master leak suite executed within Red gVisor sandbox; all 5 tests classified (`leak_test_results.json`) as `still_reproducible` (demonstrating expected leak reproduction under syscall-only isolation).
7. **Separate Evidence Storage:** 10 new evidence artifacts stored under `results/hardening/phase2.1-gvisor/local-ubuntu-vm/`, leaving Phase 2.0 baseline untouched.
8. **No Scope Creep:** No Phase 2.2 (`seccomp`, AppArmor) or Phase 2.3 (capabilities, volume removal) changes introduced.
9. **Rollback Path:** Documented clear rollback procedure via Compose runtime attribute.
10. **Documented Limitations:** Accepted dynamic IPAM order-dependency in `extra_hosts` and pre-existing guest port exposure (`0.0.0.0`) deferred to Phase 3.

## Phase 2.2 Definition of Done (COMPLETED & TAGGED ✅ — `phase2.2-seccomp-apparmor`)
1. **Custom Seccomp Profiles:** Implemented tailored seccomp profiles for `model-server` (`model-server-seccomp.json`) and Python microservices (`python-service-seccomp.json`), unconditionally denying 18 high-risk syscalls (`ptrace`, `bpf`, `perf_event_open`, `mount`, etc.) while allowing required runtime execution.
2. **Custom AppArmor Policies:** Implemented tailored AppArmor profiles (`bayora-model-server` and `bayora-python-service`) loaded into the host kernel in enforce mode, denying `network raw`, `mount`, and high-risk capabilities, while enforcing read-only model weight directory protection.
3. **Red Runner Runtime Parity:** Maintained `red-runner` under gVisor Sentry userspace virtualization; documented non-applicability of host AppArmor.
4. **Baseline Services Functionality:** All 4 services healthy and running; end-to-end inference passes through the gateway.
5. **Bounded Post-Change Performance:** Measured bounded 10-request inference performance ($p50 = 7,451.25\text{ ms}$, $9.39\text{ tok/s}$), showing no measurable overhead beyond host noise (about ±40%).
6. **Leak Test Master Suite:** Master leak suite executed within Red gVisor sandbox; all 5 tests classified as `still_reproducible` (demonstrating expected leak reproduction under host MAC and syscall isolation).
7. **Separate Evidence Storage:** 10 new evidence artifacts stored under `results/hardening/phase2.2-seccomp-apparmor/local-ubuntu-vm/`, leaving prior phase artifacts untouched.
8. **Rollback Path:** Documented clear rollback procedure via Compose security attributes.

## Phase 2.3 Definition of Done (COMPLETED & TAGGED ✅ — `phase2.3-least-privilege`)
1. **Shared Volume Removal & Mount Lockdown:** Removed `shared_data` named volume mounts; restricted Red to payloads-only read-only mount (`payloads.json:ro`) and an in-memory `tmpfs` results volume (`/app/results`, no host filesystem access).
2. **Baked-In Blue Rules:** Reconfigured `blue-filter` via `BLUE_RULES_PATH=/app/blue_rules.json`; verified rules load correctly from container image.
3. **Capability Dropping & Non-Root Execution:** Applied `cap_drop: ["ALL"]` and `no-new-privileges: true` across all services. Blue filter and Gateway run as non-root (`65534:65534`) with `read_only: true` rootfs.
4. **Localhost Port Binding:** Published host ports strictly bound to `127.0.0.1` (`127.0.0.1:8000:8000`, `127.0.0.1:8001:8001`, `127.0.0.1:8080:8080`).
5. **SEC-001 Verification:** Verified that `test_fs_blue_rules.py` fails inside `red-runner` (file not found), eliminating filesystem-based rule extraction. Direct network access to `/rules` remains open until Phase 3 network segmentation.
6. **Negative Security Testing:** Explicit negative tests verified visible failure of denied actions: `ptrace` returned EPERM (errno=1) [consistent with Seccomp], raw socket creation raised `PermissionError` (errno=13) [enforced by `cap_drop: ALL`; AppArmor attribution not independently verified via audit logs], mount returned permission denied [consistent with `cap_drop: ALL`/Seccomp; AppArmor unverified], and write to rootfs returned Read-only file system (`EROFS`, errno=30).
7. **Cold Reboot Persistence:** AppArmor profiles permanently installed in `/etc/apparmor.d/`; full cold VM reboot verified stack recovery, profile persistence in enforce mode, and `extra_hosts` IP parity.
8. **Leak Test Suite Parity:** Remaining 4 leak tests accurately classified as `still_reproducible` pending later phases (network, cache, logging).
9. **Smoke Test Verification:** Verified single-request gateway inference smoke test recorded in saved artifact `inference_smoke_test.txt` ($p50 = 8,001.58\text{ ms}$, $9.55\text{ tok/s}$, 0 timeouts, 0 errors).
10. **Separate Evidence Storage:** Evidence artifacts stored under `results/hardening/phase2.3-least-privilege/local-ubuntu-vm/`.

## Phase 2 Final Audit & Hardening Consolidation (COMPLETED & TAGGED ✅ — `phase2-complete`)
1. **Consolidated Tagging:** Created and pushed annotated tag `phase2-complete` at the final verified corrective audit commit.
2. **Git Hygiene & Tag Integrity:** Audited historical tags (`phase2.0-vm-baseline`, `phase2.1-gvisor-hardening`, `phase2.2-seccomp-apparmor`), documented `phase2.3-least-privilege` movement history, and confirmed historical commit `5b7f231` remains fully intact.
3. **Seccomp Static Audit:** Programmatically verified that all 18 target high-risk syscalls are absent from allow rules across both profiles.
4. **Full-Filesystem Scan:** Verified Red runner container has no access to `blue_rules.json` or `BLUE_DEFENSE_PROPRIETARY` across the entire accessible filesystem.
5. **Rigorous Negative Security Testing:** Updated negative security test harness with strict errno assertions and exit code verification.
