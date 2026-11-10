# Changelog

All notable changes to ExplainBin are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [1.0.0] - 2026-11-10

### Added

- Bounds-checked PE32/PE32+ parser with diagnostics for malformed, truncated
  and inconsistent images.
- SHA-256, SHA-1 and optional MD5 hashing through Windows CNG.
- Embedded Authenticode verification and local Windows catalog verification
  through WinTrust/Crypt32, with an explicit offline revocation policy.
- Import, delay-import and export analysis with capability rules, evidence,
  benign explanations and investigation steps.
- Shannon entropy, packer-name, section-permission, overlap and entry-point
  findings.
- JSON, self-contained HTML and plain-text reports.
- Qt 6 desktop application with eight sections and background analysis.
- Headless `explainbin-cli` with JSON/HTML/text output and stable exit codes.
- GoogleTest suite with synthetic PE fixtures and no binary samples.
- GitHub Actions CI for core tests and the Qt build.
- Build, architecture, rule and roadmap documentation.

### Accuracy

- Capability findings are separated from observed behavior and never produce a
  malware score.
- Process-injection findings require explicit cross-process APIs and are
  suppressed for modules that export the same APIs.
- Common Microsoft section names, managed .NET entry points, padding sections
  and resource/relocation entropy are excluded from structural findings.
- A 4,209-file `C:\Windows\System32` corpus scan produced no High or Critical
  findings; the only Medium results were five `EB-IMP-001` capability
  observations on legitimate Microsoft debugging, fault-reporting and
  application-virtualization binaries.
