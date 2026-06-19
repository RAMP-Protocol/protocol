# RAMP-authored CoMP V1 conformance fixtures — NOT verbatim spec examples

These JSON files are **RAMP-authored**, not vendored from the IAB Tech Lab
specification. They exist solely to give `TestCompV1SyntheticCoverageRoundTrip`
(`../../compexamples_test.go`) coverage of proto fields the published worked
examples (in `../comp_v1_examples/`) leave unpopulated.

Keep them strictly separate from `../comp_v1_examples/`: that directory is a
clean, blob-pinned 1:1 mirror of the spec's 8 worked examples and must stay
verbatim. Mixing synthetic payloads into it would break its provenance pin.

## Why these exist

Canonical CoMP V1 folds all commercial/licensing terms onto `Scope`
(`ause`, `pricetype`, `pricetier`, `unitprice`, `cur`, `country`, `licensedur`)
and adds per-asset `language` / `update`. None of the 16 verbatim spec examples
populate those fields, so the round-trip gate would stay green even if one of
them were renamed, retyped, or renumbered in `comp.proto`. These fixtures
exercise that surface so such drift fails the gate.

The test holds each fixture to the **same adversarial round-trip** as the
verbatim set (unknown-field rejection on; value-exact containment) **and** an
anti-vacuity floor: `requiredSyntheticCoverage` in the test names the JSON paths
each fixture must populate, so the coverage cannot silently regress.

## Fixtures

- `commercial_terms.package.json` → `comp.v1.Package`. Exercises the full Scope
  commercial block, `Package.packager`, `Package.reporturl`, and per-asset
  `Text.update` / `Text.language`.

## Note on field values

Values are illustrative and chosen only to round-trip losslessly through the
proto wire types — they do not assert membership in any external registry. In
particular `language` is typed `repeated int32` in `comp.proto` (a faithful
mirror of CoMP V1's integer-coded Lists), so the integers here demonstrate the
field carries and preserves values, not a specific ISO-639 mapping.
