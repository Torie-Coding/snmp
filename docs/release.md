# Release Guide

## One-Time Prerequisites

Before the first release, complete these steps:

### 1. Galaxy Namespace

- Log in to [galaxy.ansible.com](https://galaxy.ansible.com) with your GitHub account.
- Navigate to **My Namespaces**.
- If `torie_coding` does not exist, create it. Galaxy namespaces use underscores matching the GitHub org/user.

### 2. Galaxy API Token

- On galaxy.ansible.com → **Preferences** → **API Token** → **Generate**.
- Copy the token securely.

### 3. GitHub Repository Secret

- In the GitHub repo → **Settings** → **Secrets and variables** → **Actions** → **New repository secret**.
- Name: `GALAXY_API_KEY`
- Value: the Galaxy API token from step 2.

### 4. Recommended Branch Protection

| Setting | Value | Reason |
|---|---|---|
| Require PR reviews on `main` | ≥ 1 reviewer | Prevent broken code from reaching main |
| Require status checks | lint, sanity, unit, molecule, build | All CI must pass before merge |
| Restrict tag creation | Admins/maintainers only | Prevent unauthorized releases |
| GitHub Environment `release` | Optional: add required reviewers | Manual approval gate before Galaxy publish |
| `GITHUB_TOKEN` permissions | `contents: write` in release workflow | Required for creating GitHub Releases |

## Release Workflow

The changelog is generated and **committed to `main` before tagging**. The tag-triggered workflow consumes the already-prepared release state — it does not generate changelogs.

### Step-by-Step

> **Important:** At least one changelog fragment must exist in `changelogs/fragments/`
> before running `antsibull-changelog release`. Without fragments, the generated
> `CHANGELOG.rst` will be empty and the release workflow will fail validation.

```bash
# 1. Ensure changelog fragments exist in changelogs/fragments/
ls changelogs/fragments/

# 2. Update version in galaxy.yml
# Edit galaxy.yml and set version to the new release version (e.g., 1.0.0)
vim galaxy.yml

# 3. Generate the changelog
# This consumes fragment files, updates changelogs/changelog.yaml,
# and generates/updates CHANGELOG.rst
antsibull-changelog release

# 4. Commit the release
git add galaxy.yml changelogs/ CHANGELOG.rst
git commit -m "Release v1.0.0"

# 5. Tag the release commit
git tag v1.0.0

# 6. Push commit and tag
git push origin main --tags
```

### What the Tag-Triggered Workflow Does

When a `v*` tag is pushed, `.github/workflows/release.yml` runs:

1. **Validates** that `galaxy.yml` version matches the tag (fails if mismatch)
2. **Validates** that `CHANGELOG.rst` exists and is non-empty
3. **Builds** the collection tarball (`ansible-galaxy collection build`)
4. **Creates** a GitHub Release with the tarball as an asset
5. **Publishes** to Ansible Galaxy (`ansible-galaxy collection publish`)

### If Something Goes Wrong

- If the tag workflow fails validation, fix the issue on `main`, amend or delete the tag, and re-tag:

```bash
git tag -d v1.0.0
git push origin :refs/tags/v1.0.0
# Fix the issue, commit, then re-tag
git tag v1.0.0
git push origin main --tags
```
