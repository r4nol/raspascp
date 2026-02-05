# Adaptive Security Control Plane (ASCP) - DevSecOps MVP

This repository provides the **Secure Supply Chain** baseline for ASCP. The goal is a predictable, human-readable pipeline with three security gates and matching local commands.

**Security gates in CI**
- **Gitleaks**: scans the entire repo and fails on findings (including custom IBAN/SWIFT patterns).
- **Trivy**: scans the built Docker image and fails on **HIGH/CRITICAL**.
- **Cosign**: signs and verifies images on `main` or tag pushes.

**One command to run**
- `docker compose up --build` or `make up`

## Local usage

Prereqs:
- Docker + Docker Compose
- `cosign` (only needed for `make sign` / `make verify`)

Commands:
- `make build` - build local image (`ascp-app:dev`).
- `make secrets` - gitleaks scan (fails on findings).
- `make scan` - trivy image scan (fails on HIGH/CRITICAL), saves report to `artifacts/trivy.txt`.
- `make sign` - signs image using a local registry and dev key in `.cosign/`.
- `make verify` - verifies the local signature.
- `make check` - runs `secrets` + `scan`.
- `make up` - `docker compose up --build`.
- `make demo` - placeholder demo script for the next phase.

### Local: secrets scan (failure demo)
Add a **fake** secret-like value in a non-allowlisted file, then run `make secrets`:

```
FAKE_IBAN=DE89 3704 0044 0532 0130 00
```

This triggers the custom IBAN rule and makes the pipeline fail.

### Local: signing and verification
`make sign` uses a local registry (`localhost:5000`) so signatures can be stored without an external registry. It will start a local registry container if one is not running.

Example:
```
export COSIGN_PASSWORD="dev-password"
make sign
make verify
```

Notes:
- Dev keys are generated in `.cosign/` and ignored by git.
- You can override image settings: `IMAGE_NAME`, `IMAGE_TAG`.

## CI signing (cosign)
Signing happens **only** on pushes to `main` or on tags.

Add these GitHub Secrets:
- `COSIGN_PRIVATE_KEY`
- `COSIGN_PUBLIC_KEY`
- `COSIGN_PASSWORD`

Generate a key pair locally:
```
cosign generate-key-pair
```

Then store the generated `cosign.key` and `cosign.pub` values as secrets (keep the password in `COSIGN_PASSWORD`).

## Notes
- The Dockerfile is multi-stage, runs as a non-root user, and avoids embedding secrets.
- If your real app has a different entrypoint, set `APP_CMD` in `docker-compose.yml` or update the Dockerfile accordingly.
