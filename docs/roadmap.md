# Bayora Phase 2.0 Roadmap & Planning

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

## Phase 2.1 Definition of Done (PRE-COMMIT AUDIT VERIFIED — PENDING APPROVAL)
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

## Phase 2.2 Definition of Done (IMPLEMENTED & VERIFIED ✅)
1. **Custom Seccomp Profiles:** Implemented tailored seccomp profiles for `model-server` (`model-server-seccomp.json`) and Python microservices (`python-service-seccomp.json`), unconditionally denying 18 high-risk syscalls (`ptrace`, `bpf`, `perf_event_open`, `mount`, etc.) while allowing required runtime execution.
2. **Custom AppArmor Policies:** Implemented tailored AppArmor profiles (`bayora-model-server` and `bayora-python-service`) loaded into the host kernel in enforce mode, denying `network raw`, `mount`, and high-risk capabilities, while enforcing read-only model weight directory protection.
3. **Red Runner Runtime Parity:** Maintained `red-runner` under gVisor Sentry userspace virtualization; documented non-applicability of host AppArmor.
4. **Baseline Services Functionality:** All 4 services healthy and running; end-to-end inference passes through the gateway.
5. **Bounded Post-Change Performance:** Measured bounded 10-request inference performance ($p50 = 7,451.25\text{ ms}$, $9.39\text{ tok/s}$), confirming negligible (~4%) overhead over baseline.
6. **Leak Test Master Suite:** Master leak suite executed within Red gVisor sandbox; all 5 tests classified as `still_reproducible` (demonstrating expected leak reproduction under host MAC and syscall isolation).
7. **Separate Evidence Storage:** 10 new evidence artifacts stored under `results/hardening/phase2.2-seccomp-apparmor/local-ubuntu-vm/`, leaving prior phase artifacts untouched.
8. **Rollback Path:** Documented clear rollback procedure via Compose security attributes.

