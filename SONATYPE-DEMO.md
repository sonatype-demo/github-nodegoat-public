# Sonatype Demo - GitHub Actions

## TL;DR

This is a demo showing how to integrate Sonatype Lifecycle with GitHub Actions:

- Scan the project (incl. reachability analysis). When manually triggered, select the stage for the evaluation. By default, the stage is "build".
- Build and test NodeGoat, create a Docker image, and evaluate that image at the fixed Lifecycle **Stage Release** stage.
- Fetch the SBOM
- Manually generate a Dependency-Track-compatible CycloneDX npm SBOM, run a matching Lifecycle evaluation, and compare both SBOMs.
- Run OWASP Dependency-Check with authenticated Sonatype Guide vulnerability discovery and convert its JSON inventory and findings into a Guide-labelled CycloneDX 1.6 SBOM while retaining the original report.

To speed up the CI/CD pipeline, the other workflows have been disabled.

## Public mirror

The current file tree of the `sonatype` branch is mirrored to the public repository [`sonatype-demo/github-nodegoat-public`](https://github.com/sonatype-demo/github-nodegoat-public). `.github/workflows/sync-public-mirror.yml` publishes a new content snapshot after each source push, on a daily repair schedule, or by manual dispatch. The private source history, tags, and other branches are intentionally not published.

The source repository secret `PUBLIC_MIRROR_TOKEN` provides write access to the public target; its value is never stored in Git. GitHub Actions are disabled in the public target so mirrored workflows cannot execute there.

## Sonatype's GitHub Integration

- [Sonatype GitHub Actions](https://help.sonatype.com/en/sonatype-github-actions.html#sonatype-github-actions-326935)
- [GitHub Configuration](https://help.sonatype.com/en/github-configuration.html)
- [Reachability Analysis with Sonatype for GitHub Actions](https://help.sonatype.com/en/reachability-analysis-with-sonatype-for-github-actions.html#reachability-analysis-with-sonatype-for-github-actions)
- [Automated remediation](https://help.sonatype.com/en/automated-pull-requests.html)

Configure secrets and variables per `ENV.md`.

For developer workstations, see [Configure local npm access through Nexus Repository](NPM-NEXUS-SETUP.md) for authenticated npm group setup, credential handling, verification, and troubleshooting.

## Files / folders changed

- `SONATYPE-DEMO.md` (simplified)
- `NPM-NEXUS-SETUP.md` (local authenticated npm setup)
- `.env.example` (secret-free local configuration template)
- `ENV.md` (local-only detailed `op` + `gh` instructions)
- `.github/workflows/sonatype.yml`
- `.github/workflows/sonatype-container.yml`
- `.github/workflows/compare-sboms.yml`
- `.github/workflows/dependency-check-sbom.yml`
- `.github/workflows/sync-public-mirror.yml`
- `.github/sbom-tools/package.json` and `package-lock.json` (integrity-pinned generator toolchain)
- `scripts/compare_cyclonedx_sboms.py`
- `scripts/dependency_check_to_cyclonedx.py`
- `Dockerfile` and `.dockerignore` (credential-safe BuildKit secret and build-context hygiene)

## Prerequisites

The source workflow targets the organization runner labels `[self-hosted, sonatype-demo, pve, docker]`. The container workflow additionally requires `memory-8gb`. An allowlisted runner in the `sonatype-demo-pve` group must be online. Node.js 24 is supplied per job by `actions/setup-node@v6`.

Nexus npm credentials are written with mode `0600` under `RUNNER_TEMP` and removed unconditionally at the end of the job; they are not persisted in the shared runner user's home directory.

The container workflow passes that temporary npm configuration to `docker build` as a BuildKit secret, so the registry credential is not stored in an image layer. The locally built image is scanned by `sonatype/actions/evaluate@v1` with `stage: stage-release` and removed from the shared runner afterward.

## Compare Lifecycle and Dependency-Track SBOM inputs

Run the **Compare Lifecycle and Dependency-Track SBOMs** workflow manually and select the Lifecycle stage. The workflow installs one dependency tree and then:

1. Installs the lockfile-pinned official `@cyclonedx/cyclonedx-npm` generator with package scripts disabled, removes the temporary Nexus credential, and generates a CycloneDX 1.6 JSON SBOM. This is the SBOM that can be uploaded to Dependency-Track; Dependency-Track consumes SBOMs rather than generating the npm inventory itself.
2. Evaluates the same `package.json`, `package-lock.json`, and `node_modules` tree with Lifecycle and exports its CycloneDX 1.6 JSON SBOM.
3. Compares coordinate-level and strict Package URLs, metadata coverage, and per-component metadata values, then publishes a Markdown summary plus a downloadable artifact containing both SBOMs and the complete JSON comparison.

Lifecycle policy violations are reported in the run but do not suppress the SBOM comparison. Connectivity, authentication, scanning, or export failures still fail the workflow.

## Generate a Guide-labelled SBOM from OWASP Dependency-Check results

Run the **Generate Sonatype Guide SBOM** workflow manually. It installs the lockfile-pinned project tree with package scripts and npm audit disabled, then runs the official OWASP Dependency-Check `13.0.0` container, pinned by image digest, against `package.json`, `package-lock.json`, and the installed `node_modules`. Dependency-Check authenticates to `https://api.guide.sonatype.com` with the `SONATYPE_GUIDE_TOKEN` repository secret. For this Guide-specific profile, the npm Audit and NVD analyzers are disabled so vulnerability discovery comes from Sonatype Guide. Dependency-Check 13 still requires an initialized local CPE database, so the workflow restores its existing weekly database cache and can refresh it from the official mirrored NVD feed; that database is not used as a finding source because the NVD analyzer remains disabled. The PAT is written only to a mode-`0600` temporary properties file, mounted read-only into the scanner container, and deleted before the step exits. Temporary npm credentials and installed dependencies are also removed under `always()` cleanup.

The workflow retains the native `dependency-check-report.json`, converts Dependency-Check's identified package URLs, hashes, licenses, evidence, and Guide findings into `guide.cdx.json`, restores npm dependency relationships and development scope from the same `package-lock.json`, validates its internal references, and uploads the files as the `sonatype-guide-sbom` artifact. The conversion fails unless the vulnerable demo produces at least one finding and every native finding has Dependency-Check source `OSSINDEX`, preventing a non-Guide report from being labelled `Guide`. The CycloneDX metadata includes the label `Guide` and the configured vulnerability provider `Sonatype Guide`.

Dependency-Check does **not** natively emit CycloneDX. `guide.cdx.json` remains an explicit conversion of the native Dependency-Check JSON report; the `Guide` label identifies the vulnerability-discovery profile, not a native Dependency-Check output format.

## Variables / secrets needed

See `ENV.md` for full list, retrieval via `op`, and `gh secret`/`gh variable` setup commands.

**IQ application ID**: `github-nodegoat__cleygraf`

**Secrets** (sensitive):
- NPM_AUTH_TOKEN
- LIFECYCLE_USERNAME
- LIFECYCLE_PASSWORD
- SONATYPE_GUIDE_TOKEN

**Variables** (non-sensitive):
- NPM_REGISTRY_HOST
- NPM_REGISTRY_URL
- IQ_SERVER_URL

*Updated 2026-09-29*
