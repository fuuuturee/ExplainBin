# Security Policy

## Supported versions

| Version | Supported |
| --- | --- |
| `main` / latest release | Yes |
| Older releases | No |

## Reporting a vulnerability

Please **do not** open a public issue for security vulnerabilities.

Report privately through GitHub's **Security** tab → **Report a vulnerability** for this repository. Include:

- A description of the issue and its impact
- Affected version or commit
- Reproduction steps, ideally with a minimal synthetic file (never a live malware sample)
- Relevant logs, crash dumps or sanitizer output
- Whether the issue requires a malicious file, a malicious report path, or local access

You can expect an acknowledgement within 5 business days and a status update within 10 business days.

## Scope

ExplainBin parses untrusted binaries. The following are in scope:

- Crashes, hangs, out-of-bounds reads/writes or memory exhaustion caused by malformed PE files
- Path traversal or arbitrary file write through report export
- HTML or JSON injection through untrusted PE strings
- Signature verification results that incorrectly claim validity
- Denial of service through unbounded loops, allocations or recursion
- Supply-chain issues in dependencies fetched by CMake

## Out of scope

- The fact that a sample is detected or not detected
- Findings that are intentionally heuristic or that have documented benign explanations
- Missing malware detection (ExplainBin is not an antivirus)
- Vulnerabilities in the analyzed file itself
- Issues that require the analyzed file to be executed, loaded or unpacked

## Handling samples

Do not attach live malware to issues or pull requests. Use synthetic fixtures, hashes, structural descriptions or minimal reproducer files. The test suite builds its PE fixtures in memory so the repository stays free of binaries.

## Hardening expectations

When reporting a parser issue, describe the malformed structure (offset, field, size) so a regression test can be added to `tests/`. Fixes for parsing vulnerabilities should include a test that exercises the malformed input through the public analyzer API.
