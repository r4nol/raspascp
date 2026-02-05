SHELL := /bin/bash

IMAGE_NAME ?= ascp-app
IMAGE_TAG ?= dev
IMAGE_REF := $(IMAGE_NAME):$(IMAGE_TAG)

LOCAL_REGISTRY ?= localhost:5000
REGISTRY_REF := $(LOCAL_REGISTRY)/$(IMAGE_NAME):$(IMAGE_TAG)

COSIGN_DIR ?= .cosign
COSIGN_KEY_PREFIX ?= $(COSIGN_DIR)/ascp-dev
COSIGN_KEY := $(COSIGN_KEY_PREFIX).key
COSIGN_PUB := $(COSIGN_KEY_PREFIX).pub

ARTIFACTS_DIR ?= artifacts
TRIVY_REPORT ?= $(ARTIFACTS_DIR)/trivy.txt

GITLEAKS_IMAGE ?= ghcr.io/gitleaks/gitleaks:latest
TRIVY_IMAGE ?= aquasec/trivy:latest

.PHONY: help build secrets scan sign verify check up demo _ensure_registry _ensure_cosign

help:
	@printf "ASCP DevSecOps targets:\n"
	@printf "  build   Build local image (%s)\n" "$(IMAGE_REF)"
	@printf "  secrets Run gitleaks secret scan\n"
	@printf "  scan    Run trivy image scan (HIGH/CRITICAL)\n"
	@printf "  sign    Sign image with cosign (local registry)\n"
	@printf "  verify  Verify image signature with cosign\n"
	@printf "  check   Run secrets + scan\n"
	@printf "  up      docker compose up --build\n"
	@printf "  demo    Run scripts/demo.sh\n"

build:
	@printf "🐳 Building image %s\n" "$(IMAGE_REF)"
	docker build -t $(IMAGE_REF) .

secrets:
	@printf "🔎 Running gitleaks scan (repo-wide)\n"
	docker run --rm \
		-v "$(PWD):/repo" \
		-w /repo \
		$(GITLEAKS_IMAGE) detect \
		--source=/repo \
		--config=/repo/.gitleaks.toml \
		--no-banner \
		--exit-code=1

scan: build
	@printf "🛡️  Running trivy scan for %s (HIGH/CRITICAL)\n" "$(IMAGE_REF)"
	@mkdir -p $(ARTIFACTS_DIR)/trivy-cache
	@set -euo pipefail; \
	docker run --rm \
		-v /var/run/docker.sock:/var/run/docker.sock \
		-v "$(PWD)/$(ARTIFACTS_DIR)/trivy-cache:/root/.cache/" \
		$(TRIVY_IMAGE) image \
		--severity HIGH,CRITICAL \
		--exit-code 1 \
		$(IMAGE_REF) | tee $(TRIVY_REPORT)
	@printf "✅ Trivy report saved to %s\n" "$(TRIVY_REPORT)"

sign: build _ensure_registry _ensure_cosign
	@printf "🔐 Signing %s (local registry)\n" "$(REGISTRY_REF)"
	docker tag $(IMAGE_REF) $(REGISTRY_REF)
	docker push $(REGISTRY_REF)
	@set -euo pipefail; \
	IMAGE_DIGEST=$$(docker inspect --format='{{index .RepoDigests 0}}' $(REGISTRY_REF) 2>/dev/null || true); \
	if [ -z "$$IMAGE_DIGEST" ]; then \
		printf "   Digest not found locally. Pulling from registry...\n"; \
		docker pull $(REGISTRY_REF) >/dev/null; \
		IMAGE_DIGEST=$$(docker inspect --format='{{index .RepoDigests 0}}' $(REGISTRY_REF)); \
	fi; \
	if [ -z "$$IMAGE_DIGEST" ]; then \
		printf "   Failed to resolve image digest for %s\n" "$(REGISTRY_REF)"; \
		exit 1; \
	fi; \
	cosign sign --yes --key $(COSIGN_KEY) --tlog-upload=false --allow-http-registry "$$IMAGE_DIGEST"
	@printf "✅ Signed %s\n" "$(REGISTRY_REF)"

verify: _ensure_registry _ensure_cosign
	@printf "🔎 Verifying signature for %s\n" "$(REGISTRY_REF)"
	@set -euo pipefail; \
	IMAGE_DIGEST=$$(docker inspect --format='{{index .RepoDigests 0}}' $(REGISTRY_REF) 2>/dev/null || true); \
	if [ -z "$$IMAGE_DIGEST" ]; then \
		printf "   Digest not found locally. Pulling from registry...\n"; \
		docker pull $(REGISTRY_REF) >/dev/null; \
		IMAGE_DIGEST=$$(docker inspect --format='{{index .RepoDigests 0}}' $(REGISTRY_REF)); \
	fi; \
	if [ -z "$$IMAGE_DIGEST" ]; then \
		printf "   Failed to resolve image digest for %s\n" "$(REGISTRY_REF)"; \
		exit 1; \
	fi; \
	cosign verify --key $(COSIGN_PUB) --insecure-ignore-tlog=true --allow-http-registry "$$IMAGE_DIGEST"
	@printf "✅ Verified %s\n" "$(REGISTRY_REF)"

check: secrets scan
	@printf "✅ Security gates passed (gitleaks + trivy)\n"

up:
	@printf "🚀 Starting stack with docker compose\n"
	docker compose up --build

demo:
	@printf "🎬 Running demo script\n"
	./scripts/demo.sh

_ensure_registry:
	@printf "📦 Ensuring local registry is running (%s)\n" "$(LOCAL_REGISTRY)"
	@if docker ps --format '{{.Names}}' | grep -q '^ascp-local-registry$$'; then \
		printf "   Registry already running.\n"; \
	elif docker ps -a --format '{{.Names}}' | grep -q '^ascp-local-registry$$'; then \
		docker start ascp-local-registry >/dev/null; \
		printf "   Registry started.\n"; \
	else \
		docker run -d --restart unless-stopped -p 5000:5000 --name ascp-local-registry registry:2 >/dev/null; \
		printf "   Registry created and started.\n"; \
	fi

_ensure_cosign:
	@if ! command -v cosign >/dev/null 2>&1; then \
		printf "Cosign is required. Install via: https://docs.sigstore.dev/cosign/installation/\n"; \
		exit 1; \
	fi
	@mkdir -p $(COSIGN_DIR)
	@if [ ! -f $(COSIGN_KEY) ]; then \
		printf "🔑 Generating dev cosign key pair at %s (you may be prompted for a password)\n" "$(COSIGN_KEY_PREFIX)"; \
		cosign generate-key-pair --output-key-prefix $(COSIGN_KEY_PREFIX); \
	fi
