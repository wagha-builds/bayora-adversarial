# Bayora Lifecycle Makefile
#
# IMPORTANT: Current Phase is Phase 0 (Alignment + Threat Model).
# Phase 0 produces documentation only. Application and container execution
# targets are defined as stubs to formalize the lifecycle interface.

.PHONY: help verify-docs up down baseline hardened clean

help:
	@echo Bayora Adversarial AI Evaluation Platform
	@echo Current Phase: Phase 0 (Alignment + Threat Model)

verify-docs:
	@python -c "import os, sys; files = ['docs/architecture/dfd.md', 'docs/architecture/zones.md', 'docs/threat-model/stride.md', 'docs/api/gateway-contract.md', 'docs/risk/risk-register.md', 'task.md', 'README.md', '.gitignore']; missing = [f for f in files if not os.path.exists(f)]; sys.exit(f'Missing: {missing}') if missing else print('All Phase 0 deliverables verified successfully.')"

baseline:
	@echo [PHASE 1 NOTICE] The insecure baseline is not built in Phase 0. Do not start Phase 1 until explicit authorization.

hardened:
	@echo [PHASE 2+ NOTICE] The hardened environment is not built in Phase 0. Follow roadmap sequentially.

up:
	@echo [PHASE 10 NOTICE] Production bring-up target is disabled in Phase 0.

down:
	@echo [PHASE 10 NOTICE] Teardown target is disabled in Phase 0.

clean:
	@echo Cleaning up local workspace caches...
