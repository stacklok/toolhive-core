# Embedded TUF snapshots

This directory embeds point-in-time snapshots of Sigstore trust material,
keyed by TUF repository host.

## Contents

- `<host>/root.json` — the TUF *bootstrap* root used to start a live TUF
  refresh (consumed by `New` / the online verifier).
- `tuf-repo-cdn.sigstore.dev/trusted_root.json` — the `trusted_root.json`
  *target* from the Sigstore public-good TUF repository, used by
  `OfflineTrustedMaterial` for network-free bundle verification. sigstore-go
  embeds only the bootstrap root, not this target, so vendoring it is the
  canonical offline pattern (see sigstore-go's own verification example).

## Provenance of `trusted_root.json`

Fetched 2026-07-24 from the `tuf-repo-cdn.sigstore.dev` TUF repository via
`sigstore-go`'s TUF client (`tuf.New(tuf.DefaultOptions())` +
`client.GetTarget("trusted_root.json")`), which verifies the target against
the TUF metadata chain before returning it. Do not edit by hand; refresh
with the same client and commit the new snapshot.

## Staleness trade-off

The snapshot cannot see key rotations that happen after the fetch date, in
either direction:

- signatures made with newly rotated-in keys fail offline verification
  until the snapshot is refreshed and consumers pick up the release;
- a key rotated out **because of compromise** keeps being trusted by
  offline verification until the same release + bump cycle completes.

Consumers that need timely revocation must use the online verifier (`New`),
which refreshes over TUF on construction. Refresh this snapshot on a
regular cadence and whenever Sigstore announces a rotation.
