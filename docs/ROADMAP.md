# Roadmap

ExplainBin is intentionally scoped: a careful, explainable, local static analyzer. The roadmap favors depth and correctness over breadth.

## 1.0 — current

- [x] Bounds-checked PE32/PE32+ parser
- [x] Imports, delay imports, exports, resources, debug/CodeView, TLS, certificates, overlay, Rich header
- [x] SHA-256 / SHA-1 / optional MD5 via CNG
- [x] Authenticode verification with offline revocation policy
- [x] Embedded and local Windows catalog signature verification
- [x] Entropy and structural findings
- [x] Import capability rules with benign explanations
- [x] JSON, HTML and text reports
- [x] Qt 6 desktop application with eight sections
- [x] Headless CLI
- [x] GoogleTest suite with synthetic fixtures
- [x] GitHub Actions CI

## 1.1 — deeper metadata

- [ ] Version resource parsing (company, product, description, original filename)
- [ ] Manifest inspection (requested execution level, DPI, compatibility)
- [ ] Rich header decoding (toolchain build IDs)
- [ ] Load configuration directory (CFG, safe SEH, GS, guard flags)
- [ ] Exception directory summary (x64 unwind info)
- [ ] Section hash table and per-section byte signatures

## 1.2 — stronger explainability

- [ ] Rule documentation generated from code annotations
- [ ] Finding relationships ("part of the same injection pattern")
- [ ] Import graph visualization and keyboard navigation
- [ ] Search and filter across all views
- [ ] Copyable evidence blocks and deep links from findings to views
- [ ] Localization-ready string tables (English first)

## 1.3 — reporting and automation

- [ ] SARIF export for code-scanning pipelines
- [ ] CSV export for inventory workflows
- [ ] Batch analysis of a directory (CLI)
- [ ] Baseline/diff mode between two builds
- [ ] Optional password-protected report export
- [ ] Signed release artifacts and SBOM

## 2.0 — analysis depth (still static)

- [ ] Safe disassembly of the entry point and TLS callbacks
- [ ] String extraction with encoding detection and categorization
- [ ] Resource payload inspection (icons, manifests, embedded PE detection)
- [ ] Import hash (imphash) computation
- [ ] Authenticode timestamp and countersignature details
- [ ] .NET metadata summary (assembly name, references, strong name)
- [ ] Plugin API for organization-specific rules

## Explicit non-goals

- Executing, unpacking or emulating samples in-process
- Uploading files, hashes or telemetry
- A malware/clean verdict or a "threat score"
- Replacing a sandbox, EDR or human analyst
- Cross-platform binary formats (ELF, Mach-O) in the 1.x line

## How to influence the roadmap

Open a discussion or issue describing the analyst workflow you want to support. Proposals that improve explainability, safety or evidence quality are prioritized. Changes that add opaque scoring or execution of samples will not be accepted.
