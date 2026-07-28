It is designed to let maintainers safely label or comment on PRs from forks.

# Security Scan Types — Guide for Your DevSecOps Pipeline

Here's a breakdown of the common scan types, when each applies, and how to wire them into your `secure-pipeline-workshop` project.

## 1. SAST (Static Application Security Testing)
It analyzes source code without running it to find bugs like SQL injection, XSS, hardcoded secrets patterns, insecure APIs.
- **Use for:** Your own application code (Java, Python, JS, Go, etc.).
- **Tools:** CodeQL (GitHub-native), Semgrep, SonarQube, Checkmarx.
- **Integrate:** Add a GitHub Actions workflow (`.github/workflows/codeql.yml`) on push/PR. Results show up in the **Security → Code scanning** tab.

## 2. SCA (Software Composition Analysis) / Dependency Scanning
- **What:** Scans third-party libraries (npm, pip, Maven, NuGet) for known CVEs.
- **Use for:** `package.json`, `requirements.txt`, `pom.xml`, `go.mod`, etc.
- **Tools:** Dependabot (free, GitHub-native), Snyk, OWASP Dependency-Check, Trivy.
- **Integrate:** Enable Dependabot in repo settings → alerts appear in **Security → Dependabot**.

## 3. Secret Scanning
- **What:** Detects committed API keys, tokens, passwords.
- **Tools:** GitHub Secret Scanning (free for public repos), Gitleaks, TruffleHog.
- **Integrate:** Enable in repo settings, or add Gitleaks as a pre-commit hook + CI job.

## 4. IaC Scanning (Infrastructure as Code)
- **What:** Scans Terraform, CloudFormation, Kubernetes manifests, Dockerfiles for misconfigurations (open S3 buckets, privileged containers).
- **Use for:** Your `infra/` folder.
- **Tools:** Checkov, tfsec, Terrascan, KICS.
- **Integrate:** GitHub Action on PRs touching `infra/**`.

## 5. Container Image Scanning
- **What:** Scans Docker images for OS package CVEs and misconfigurations.
- **Tools:** Trivy, Grype, Docker Scout, Clair.
- **Integrate:** Run after `docker build` in CI; fail build on HIGH/CRITICAL.

## 6. DAST (Dynamic Application Security Testing)
- **What:** Tests a *running* app from outside (black-box) — finds runtime issues SAST misses.
- **Tools:** OWASP ZAP, Burp Suite, Nuclei.
- **Integrate:** Run in a staging environment, not on every PR (slow).

## 7. License Compliance
- **What:** Flags GPL/AGPL or other restrictive licenses in dependencies.
- **Tools:** FOSSA, ScanCode, Syft.

---

## Quick Mapping for Your Repo
| Folder | Recommended Scans |
|---|---|
| `code/` | SAST + SCA + Secret |
| `infra/` | IaC + Secret |
| Docker images | Container + SCA |
| Deployed app | DAST |

## Tracking Alerts Effectively
1. **Centralize in GitHub Security tab** — CodeQL, Dependabot, Secret Scanning all feed it natively. Third-party tools (Trivy, Checkov) can upload SARIF via `github/codeql-action/upload-sarif`.
2. **Severity policy** — fail CI on `CRITICAL`/`HIGH`, warn on `MEDIUM`, ignore `LOW` initially to avoid alert fatigue.
3. **Auto-triage** — Dependabot auto-PRs for patch upgrades; assign owners via `CODEOWNERS`.
4. **SLAs** — Critical: 7 days, High: 30 days, Medium: 90 days. Track via GitHub Issues or a project board.
5. **Suppress false positives explicitly** — use `.semgrepignore`, CodeQL query filters, or inline comments — never disable the scanner.
6. **Metrics** — track MTTR (mean time to remediate), open vs. closed alerts, and trend over time.

---

Want me to:
- **(a)** scaffold a `.github/workflows/security.yml` combining CodeQL + Trivy + Checkov + Gitleaks with SARIF upload, or
- **(b)** review what's already in your `code/` and `infra/` folders and tailor the workflows accordingly?