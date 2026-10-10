# SLSA Level 3 Compliance Matrix

## Supply-chain Levels for Software Artifacts (SLSA v1.0)

This matrix maps enterprise Zero-Trust pipeline controls against official SLSA requirements.

| SLSA Requirement | Level Required | Implementation in Pipeline | Verification Method |
|---|---|---|---|
| **Build Service** | Level 1, 2, 3 | GitHub Actions hosted virtual environments with isolated ephemeral VMs per build | Verified via GitHub OIDC Token issuer `https://token.actions.githubusercontent.com` |
| **Build as Code** | Level 1, 2, 3 | Build instructions defined strictly in version-controlled workflow (`.github/workflows/security-pipeline.yml`) | Audited via GitHub commit history |
| **Generated Provenance** | Level 1, 2, 3 | Generated via `slsa-framework/slsa-github-generator` emitting in-toto statement format | Kyverno Policy `require-slsa-l3-provenance` checks predicate |
| **Non-Falsifiable Provenance** | Level 3 | Provenance signed with cryptographic certificate tied to GitHub Actions OIDC identity | Rekor transparency log public entry validation |
| **Isolated Build Environment** | Level 3 | Worker VM isolated from prior build states; memory and disk wiped immediately post-run | Standard GitHub Actions isolated runner architecture |
| **Hermetic & Parameterless** | Level 3 | Reusable workflow invoked without arbitrary external command override injection | Parameters strictly typed in workflow inputs |
| **Cryptographic Signatures** | Level 2, 3 | Cosign keyless container signing with Fulcio CA and Rekor transparency log | Verified at cluster admission via Kyverno & Gatekeeper |
| **SBOM Completeness** | Level 2, 3 | Syft generates CycloneDX & SPDX SBOM including transitive package hashes and licenses | `src/sbom_analyzer.py` license audit & Kyverno attestation |
