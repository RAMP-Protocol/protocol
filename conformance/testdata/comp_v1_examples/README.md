# CoMP V1 worked examples — vendored testdata

These JSON files are the worked examples from the IAB Tech Lab **Content
Monetization Protocols (CoMP) V1** specification, vendored verbatim for the
`TestCompV1ExamplesRoundTrip` conformance gate (`../../compexamples_test.go`).

## Source of truth (immutable pin)

- Repository: `https://github.com/IABTechLab/CoMP`
- File: `CoMP-1.0.md`
- Branch: `main`
- Spec-file content (git blob SHA): `aa8c796be7a9bcfa1189a1cf6c1ec50aa67a0f5f`
- `main` commit at vendoring time: `880238e0100b3d0d67d5afd7357a18fc21a97be5`
- Raw URL (commit-pinned, reproducible):
  `https://raw.githubusercontent.com/IABTechLab/CoMP/880238e0100b3d0d67d5afd7357a18fc21a97be5/CoMP-1.0.md`

The pin is the **blob SHA** of the spec file, which is content-addressed and
therefore immutable regardless of future branch movement. To re-derive these
examples, fetch the URL above and confirm `git hash-object` of the result equals
`aa8c796be7a9bcfa1189a1cf6c1ec50aa67a0f5f`.

## Provenance discrepancy — release tag does NOT carry the spec

The CoMP repository carries a release tag `1.0-202604`
(commit `819a242bdad6e1644cfbdc0a8a49dfcfa201375c`). That tag was proposed as the
immutable provenance pin, but **it does not contain the CoMP V1 specification**:
the tree at `819a242` holds only a boilerplate `README.md`. `main` is 6 commits
*ahead* of the tag, and the entire specification — every object table, the
consolidated `Lists` section, and all 8 worked examples — was added to `main` in
those 6 commits, AFTER the tag was cut. The final content commit on `main`
("CoMP 1.0 Public Comment Changes") is what introduced `package.reporturl`, the
asset `cattax` / `cat` / `language` fields, and the integer-coded Lists — exactly
the surface the re-baselined `comp.proto` mirrors.

Conclusion: the proto was (correctly) baselined against `main`, not against the
`1.0-202604` tag. The examples here are therefore pinned to the `main` blob SHA
above. If IAB later re-tags so that the release tag actually contains
`CoMP-1.0.md`, this pin should be revisited and the tag's content diffed against
blob `aa8c796be7a9bcfa1189a1cf6c1ec50aa67a0f5f`.

## File layout

The spec wraps each example payload in a single envelope key — `"aisystem"` for
requests, `"package"` for responses. The vendored files contain the **inner
object only**, because that inner object is the actual CoMP root type modeled by
the proto (`comp.v1.AISystem` / `comp.v1.Package`). The envelope is encoded in
the filename suffix so the test can select the correct generated root type:

- `*.aisystem.json` → `comp.v1.AISystem` (the AI System request side)
- `*.package.json`  → `comp.v1.Package` (the Content Owner / Marketplace response side)

8 examples × {request, response} = 16 payloads.
