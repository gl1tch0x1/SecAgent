# GitHub Releases — Configuration & Troubleshooting Guide

## Why Releases Don't Show Up

The release.yml workflow has several common issues that prevent releases from appearing:

### ❌ Common Issues

1. **Artifacts Path Mismatch** — Built artifacts don't exist in the expected directory
2. **Tag Format Issue** — Tags don't match the `v*` pattern
3. **Missing Permissions** — `contents: write` permission not set
4. **Build Failure** — PyInstaller/Docker build fails silently
5. **Artifact Download Failure** — Actions don't find artifacts from previous jobs
6. **Missing GITHUB_TOKEN** — No token provided to softprops/action-gh-release

---

## ✅ Fixed Issues in Updated release.yml

### 1. **Validation Step**
```yaml
validate-release:
  - Extracts version from tag or workflow input
  - Validates semver format (X.Y.Z)
  - Exits early on invalid version
  - Outputs version and tag for downstream jobs
```

### 2. **Tests Before Release**
```yaml
test:
  - Runs full test suite
  - Ensures code quality
  - Prevents broken releases
```

### 3. **Proper Artifact Handling**
```yaml
- Download with explicit paths
- Verify binaries exist
- Copy to release-assets directory
- Generate SHA256 checksums
```

### 4. **Release Notes Generation**
```yaml
- Embedded release notes (no external action dependency)
- Links to downloads
- Installation instructions
- Version information
```

### 5. **Docker Image Publishing**
```yaml
- Builds and pushes API, Rust Core, Recon images
- Uses semantic versioning tags
- Supports both manual and push events
```

### 6. **PyPI Package Publishing**
```yaml
- Builds distribution packages
- Publishes to PyPI
- Skips if token not configured
```

---

## How to Create a Release

### Method 1: Git Tag (Automatic)

```bash
# Create and push a tag matching v*
git tag -a v0.2.0 -m "Release v0.2.0 — bug fixes and improvements"
git push origin v0.2.0

# GitHub will automatically trigger the release workflow
```

### Method 2: Workflow Dispatch (Manual)

1. Go to **Actions** tab on GitHub
2. Click **Release** workflow
3. Click **Run workflow**
4. Enter version (e.g., `v0.2.0`)
5. Click **Run workflow**

---

## Debugging Release Failures

### Check Workflow Logs

1. Go to **Actions** → **Release** workflow
2. Click the failed run
3. Check each job's logs:
   - ✅ validate-release — Check version format
   - ✅ test — Check for test failures
   - ✅ build-binaries — Check PyInstaller output
   - ✅ build-docker — Check Docker build errors
   - ✅ create-release — Check artifact downloads

### Common Errors & Fixes

**Error: "No files matched the pattern"**
```
Fix: Check if __main__.py exists in python-agents/secagents/
```

**Error: "HTTP 422: Validation Failed"**
```
Fix: Tag already exists. Use different version or delete tag and recreate.
git tag -d v0.2.0
git push origin :refs/tags/v0.2.0
```

**Error: "No artifacts to download"**
```
Fix: Build job failed. Check build logs for errors.
```

**Error: "PyInstaller: Module not found"**
```
Fix: Ensure all dependencies are listed in pyproject.toml
```

---

## Testing Releases Locally

```bash
# Simulate the build process
cd python-agents
pip install -e .
pip install pyinstaller

# Build single-file executable
pyinstaller --onefile --name secagent-linux secagents/__main__.py

# Verify
./dist/secagent-linux --help
```

---

## Version Management

All versions are centralized in:
- **python-agents/secagents/_version.py** — Canonical version source
- **python-agents/pyproject.toml** — Python package version
- **api/pyproject.toml** — API package version
- **Cargo.toml** — Rust version
- **frontend/apex/package.json** — Frontend version

To release new version:

```bash
# 1. Update _version.py
sed -i 's/__version__ = "0.2.0"/__version__ = "0.3.0"/g' python-agents/secagents/_version.py

# 2. Update pyproject.toml files
sed -i 's/version = "0.2.0"/version = "0.3.0"/g' python-agents/pyproject.toml api/pyproject.toml

# 3. Commit and tag
git add -A
git commit -m "chore: bump version to 0.3.0"
git tag -a v0.3.0 -m "Release v0.3.0"
git push origin main v0.3.0
```

---

## Signed Releases & Verification

Release artifacts are signed with a GPG key when the repository secret `RELEASE_GPG_PRIVATE_KEY` is configured. The workflow automatically imports the key, signs every binary and checksum file, and uploads the `.asc` signatures alongside the release assets.

### Verify a signed artifact

```bash
# Download the binary and signature
curl -L -O https://github.com/your-org/secagents/releases/download/v1.0.0/secagent-linux-x64
curl -L -O https://github.com/your-org/secagents/releases/download/v1.0.0/secagent-linux-x64.asc

# Verify the signature
gpg --verify secagent-linux-x64.asc secagent-linux-x64

# Verify the SHA256 manifest
curl -L -O https://github.com/your-org/secagents/releases/download/v1.0.0/SHA256SUMS.txt
sha256sum -c SHA256SUMS.txt
```

If the signature or checksum fails, do not ship or trust the artifact and treat the release as suspect until the issue is resolved.

---

## Monitoring Releases

### GitHub UI
- **Releases page** → Shows all published releases
- **Release assets** → Click to download binaries
- **SHA256SUMS.txt** → Verify binary integrity
- ***.asc** → Detached GPG signatures for artifact authenticity

### Verify Release Integrity

```bash
# Download and verify binary
curl -L https://github.com/.../releases/download/v0.2.0/secagent-linux-x64 -o secagent

# Check SHA256
curl -L https://github.com/.../releases/download/v0.2.0/SHA256SUMS.txt -o SHA256SUMS.txt
sha256sum -c SHA256SUMS.txt

# Should output: secagent-linux-x64: OK
```

---

## Rollback Procedure

If a release has critical issues:

```bash
# 1. Delete the release on GitHub
# 2. Delete the tag
git push origin :refs/tags/v1.0.0

# 3. Fix the issue and create a patch version
git checkout main
git pull --ff-only
git tag -a v1.0.1 -m "Hotfix: rollback and recovery for v1.0.0"
git push origin v1.0.1
```

Recommended recovery path:
1. Freeze rollout and notify operators.
2. Revert or disable the broken release in your package manager or deployment pipeline.
3. Redeploy the last known-good version from the prior release tag.
4. Publish a clear patch release with the fix and changelog note.

---

## Environment Variables & Secrets

For full CI/CD, configure these secrets in GitHub:

| Secret | Value | Purpose |
|--------|-------|---------|
| `PYPI_TOKEN` | PyPI API key | Publish to PyPI |
| `SLACK_WEBHOOK_URL` | Slack webhook | Notifications |
| `GITHUB_TOKEN` | Auto-generated | Built-in, always available |

---

## CI/CD Integration

### Full CI Pipeline

1. **Push to main/develop** → Runs linting, tests, security scans
2. **Create release tag** → Triggers full release workflow
3. **Release published** → Docker images pushed, PyPI package published
4. **Manual deploy** → Deploy to staging/production

See `.github/workflows/ci.yml` for full test pipeline.

---

## Best Practices

✅ **DO:**
- Always run tests before creating release
- Use semantic versioning (X.Y.Z)
- Include detailed release notes
- Sign commits/tags when possible
- Document breaking changes

❌ **DON'T:**
- Release without testing
- Force-push to main
- Use vague version numbers
- Forget to update documentation
- Publish duplicate versions

