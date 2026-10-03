# Releasing hardly

> Purpose: How maintainers publish hardly (PyPI, GitHub Release, container image, MCP Registry), verify a release, and roll back.

## One-time owner checklist

Do these once, before the first tag. Nothing here uses stored API tokens.

- [ ] **PyPI name.** Check that `hardly` is available on https://pypi.org/project/hardly/ and on TestPyPI. A pending publisher does not reserve the name until the first upload, so publish the first release soon after registering.
- [ ] **PyPI pending publisher** (https://pypi.org/manage/account/publishing/): project `hardly`, owner `b1tninja`, repository `hardly`, workflow filename `release.yml`, environment `pypi`.
- [ ] **TestPyPI pending publisher** (https://test.pypi.org/manage/account/publishing/): same fields, environment `testpypi`.
- [ ] **GitHub environments** (Settings > Environments): create `pypi` (add required reviewers, restrict to tags `v*`) and `testpypi`.
- [ ] **Attestations.** Repository must allow Actions to write attestations (public repos: available by default; private repos need a plan that supports artifact attestations).
- [ ] **GHCR.** After the first image push, open the package `hardly` under the owner's Packages, link it to the repository, and set visibility to public if desired.
- [ ] **MCP Registry namespace.** `io.github.b1tninja/*` is authenticated by GitHub OIDC from this repository; nothing to register, but the first `publish-mcp` run must succeed once. `README.md` carries the required `mcp-name: io.github.b1tninja/hardly` line, which PyPI shows in the project description.
- [x] **License:** MPL-2.0 (`LICENSE`, `NOTICE.md` for generated output); set in `pyproject.toml`. Revisit before the first release if you prefer another license.
- [ ] **Default branch.** Workflows assume `master`. Change the `branches:` filters if the default branch is renamed.
- [ ] Optional: pin actions to commit SHAs (`pinact run`, or accept Dependabot's weekly grouped updates). Workflows currently use major tags.

## Distribution matrix

| Channel | What | Trust |
|---------|------|-------|
| PyPI `hardly` | wheel + sdist; docs and Agent Skill ship inside the wheel under `hardly/_data` | Trusted Publishing (OIDC), PEP 740 attestations, GitHub provenance |
| GitHub Release | wheel, sdist, `SHA256SUMS`, `sbom.cdx.json` (CycloneDX), notes from CHANGELOG | build provenance + SBOM attestations |
| GHCR `ghcr.io/b1tninja/hardly` | multi-arch (amd64, arm64) archive/headless MCP server image | buildx provenance + SBOM, build provenance attestation on the digest |
| MCP Registry `io.github.b1tninja/hardly` | `server.json` pointing at the PyPI package (`uvx hardly serve`) | GitHub OIDC |
| Agent Skill | `hardly skill install` (from the wheel) | same as PyPI |

Install paths: `uvx hardly serve`, `uvx --from 'hardly[capture]' hardly capture --help`, `pipx install 'hardly[capture]'`, `docker run ghcr.io/b1tninja/hardly`. Browser capture needs a local install; the container is for analysis.

Extras: `[capture]` adds Playwright; `[dev]` adds pytest, ruff, build and twine. Entry point: `hardly` -> `hardly.cli:main` (`hardly serve` or `python -m hardly` starts the MCP server).

## Pre-release checklist

- [ ] `PYTHONPATH=src python -m pytest -q -m "not browser and not live"` and `ruff check .` pass.
- [ ] `python scripts/gen_tool_docs.py` leaves no diff.
- [ ] Latest nightly browser run is green.
- [ ] Version bumped in all three places: `pyproject.toml`, `src/hardly/__init__.py`, `server.json` (two fields). `tests/test_packaging.py` and the release workflow both enforce this.
- [ ] `CHANGELOG.md`: rename `[Unreleased]` content into `## [X.Y.Z] - YYYY-MM-DD` (the release notes are taken from that section) and start a fresh `[Unreleased]`.
- [ ] Optional dry run: Actions > Release > Run workflow (publishes to TestPyPI only). Locally: `python -m build && python -m twine check --strict dist/* && python scripts/check_dist.py dist`.
- [ ] `tests/test_neutrality.py` passes (no site-specific content).

## Release steps

1. Land the version bump and changelog on `master` through a pull request.
2. Tag and push: `git tag vX.Y.Z && git push origin vX.Y.Z`.
3. The `Release` workflow runs: `build` (version/tag consistency, build, `twine check --strict`, contents check, clean-venv smoke test, SBOM, checksums) then, after `pypi` environment approval, `publish-pypi` (attest, then upload), then in parallel `github-release`, `publish-image` and `publish-mcp`.
4. Pre-release versions (`aN`, `bN`, `rcN`, `devN`) are published to TestPyPI only and stop there.

## Verifying a release

```bash
# GitHub build provenance (wheel, sdist) and SBOM attestation
gh attestation verify hardly-X.Y.Z-py3-none-any.whl --repo b1tninja/hardly
gh attestation verify hardly-X.Y.Z.tar.gz --repo b1tninja/hardly

# What PyPI served is what was released
pip download hardly==X.Y.Z --no-deps -d dl
sha256sum dl/*.whl            # compare with SHA256SUMS on the GitHub Release
sha256sum -c SHA256SUMS --ignore-missing

# Container image
gh attestation verify oci://ghcr.io/b1tninja/hardly:X.Y.Z --repo b1tninja/hardly
```

PyPI attestations (PEP 740) appear on the file's page under "Provenance" ("Publisher: GitHub Actions, b1tninja/hardly, release.yml") and in the Simple/JSON API.

## Yanking and rollback

- Bad release: on PyPI, Manage > Releases > Options > **Yank** (installs of the exact pin still work; resolvers skip it). Never delete and re-upload: versions cannot be reused.
- Fix forward with `X.Y.(Z+1)`. Mark the GitHub Release as pre-release or edit its notes; retag the image `latest` by re-running a good tag's `publish-image`.
- MCP Registry: publish the fixed version; the registry keeps history.
- Leaked or wrong workflow config: disable the `pypi` environment, or remove the trusted publisher on PyPI.

## Hardening notes

Top-level `permissions: contents: read`; `id-token`, `attestations`, `packages` and `contents: write` are granted only on the job that needs them. Checkout uses `persist-credentials: false`; superseded CI runs are cancelled; releases never are. `actionlint` and `zizmor` run (non-blocking) in CI, `pip-audit` too: make them blocking once they run clean.
