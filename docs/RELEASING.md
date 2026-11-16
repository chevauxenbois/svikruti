# Releasing

Releases are built, tested, attested and published by
`.github/workflows/release.yml` when a version tag is pushed.

One-time setup:

1. Create the `svikruti` project on PyPI (or reserve the name with a first
   manual upload).
2. In the PyPI project settings, add a Trusted Publisher: owner
   `chevauxenbois`, repository `svikruti`, workflow `release.yml`,
   environment `pypi`. No API token is stored in GitHub.
3. In the GitHub repository settings, create an environment named `pypi`.
   Add yourself as a required reviewer if you want a manual approval before
   each publish.

Each release:

1. Update `__version__` in `src/svikruti/__init__.py`, `version` in
   `pyproject.toml`, and `CHANGELOG.md`.
2. Merge to `main` with the Tests workflow green.
3. `git tag v0.9.0 && git push origin v0.9.0`

The workflow refuses to publish if the tag does not match the package
version, runs the test suite against the built wheel, attaches build
provenance, publishes to PyPI and creates the GitHub release.

A version number can be published to PyPI only once. If a release fails after
the upload step, fix forward with the next patch version.
