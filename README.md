# StellarOS.ReleaseIntegrity

Public, independently hosted integrity anchors and monitoring for StellarOS releases.

The scheduled GitHub Actions workflow runs every 12 hours. It verifies the pinned
baseline itself, fully hashes site files and release files up to 50 MiB, and checks
three pinned byte ranges plus the expected size for larger artifacts. A failed check
opens or updates a GitHub issue and marks the workflow run as failed.

The monitor uses only public hashes and URLs. Private release-signing keys must never
be stored in this repository or on the release host.

Run the same verification locally with:

```sh
python3 verify_release_integrity.py
```
