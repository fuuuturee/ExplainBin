# JSON report schema

ExplainBin writes a single UTF-8 JSON object. The current schema version is
`1.0` and is also embedded as `schemaVersion` in every report.

```json
{
  "schemaVersion": "1.0",
  "tool": { "name": "ExplainBin", "version": "1.0.0", "analysisMode": "static-local", "disclaimer": "..." },
  "generatedAtUtc": "2026-11-10T12:00:00Z",
  "analysis": { "success": true, "parseSuccess": true, "error": "", "durationMs": 42,
                "signatureRequested": true, "fileEntropy": 6.12,
                "fileEntropyComputed": true, "analyzedAtUtc": "..." },
  "file": { "path": "...", "fileName": "sample.exe", "extension": ".exe", "sizeBytes": 123456,
            "lastWriteTimeUtc": "...", "creationTimeUtc": "...",
            "hashes": { "md5": "", "sha1": "...", "sha256": "..." } },
  "severityCounts": { "informational": 2, "low": 0, "medium": 0, "high": 0, "critical": 0, "total": 2 },
  "pe": { "...": "parsed headers, sections, directories, imports, exports, resources, debug, TLS, overlay" },
  "signature": { "...": "verification state and signer details" },
  "findings": [ { "...": "explainable finding objects" } ],
  "diagnostics": [ { "code": "EB-PE-...", "message": "...", "fatal": false } ]
}
```

## Top-level fields

| Field | Type | Meaning |
| --- | --- | --- |
| `schemaVersion` | string | Report schema version (`1.0`) |
| `tool` | object | Tool identity, analysis mode and disclaimer |
| `generatedAtUtc` | string | ISO-8601 UTC report generation time |
| `analysis` | object | Success flags, error text, duration and whole-file entropy |
| `file` | object | Path, names, size, timestamps and hashes of the analyzed bytes |
| `severityCounts` | object | Finding totals per severity plus `total` |
| `pe` | object | Parsed PE metadata; present even for partial parses |
| `signature` | object | Signature verification state and signer details |
| `findings` | array | Ordered findings, highest severity first |
| `diagnostics` | array | Parser diagnostics, including non-fatal inconsistencies |

## Finding object

| Field | Type | Meaning |
| --- | --- | --- |
| `id` | string | Stable rule ID, for example `EB-IMP-001` |
| `category` | string | Group such as `Imports`, `Sections` or `Digital signature` |
| `title` | string | Short neutral observation |
| `severity` | string | `Informational`, `Low`, `Medium`, `High` or `Critical` |
| `confidence` | string | `Low`, `Medium` or `High` |
| `description` | string | What was observed |
| `whyItMatters` | string | Plain-language impact |
| `evidence` | array of strings | File-derived facts such as RVAs, API names and sizes |
| `possibleLegitimateExplanations` | array of strings | Benign scenarios that produce the same pattern |
| `recommendedInvestigation` | array of strings | Safe next steps |

`severity` is not a probability of malice. ExplainBin does not emit an
aggregate score or a clean/malware verdict.

## Signature object

| Field | Type | Meaning |
| --- | --- | --- |
| `checked` | boolean | Verification was requested and attempted |
| `present` | boolean | An embedded certificate table exists |
| `catalogSigned` | boolean | A matching local Windows catalog verified successfully |
| `status` | string | `Not checked`, `Unsigned`, `Valid`, `Invalid` or `Unknown` |
| `statusText` | string | Human-readable state |
| `subject`, `issuer` | string | Signer identity when available |
| `serialNumber` | string | Certificate serial number |
| `notBeforeUtc`, `notAfterUtc` | string | Certificate validity window |
| `expired`, `notYetValid` | boolean | Validity-window flags |
| `digestAlgorithm`, `signatureAlgorithm` | string | Algorithm identifiers |
| `trustMessage` | string | WinVerifyTrust detail |
| `trustStatus` | number | Raw WinVerifyTrust status code |
| `revocationChecked` | boolean | Always `false`; revocation is not checked online |
| `chain` | array of strings | Certificate chain summary |

## PE object

The `pe` object exposes headers (`format`, `is64Bit`, `machine`, `subsystem`,
`entryPointRva`, `imageBase`, `sizeOfImage`, alignments, checksum state,
timestamp, characteristics), `sections`, `dataDirectories`, `imports`,
`exports`, `resources`, `debugEntries`, `tls`, `overlay` and
`certificateTable`.

File-derived strings are sanitized to printable ASCII before they are written.
Consumers should still treat every value as untrusted data.

## Compatibility policy

- Additive fields may appear within schema `1.x`; consumers should ignore
  unknown fields.
- Removing or renaming a field, or changing its type or meaning, requires a
  new major schema version.
- Rule IDs are stable. Titles, explanations and severities may be refined when
  accuracy improves; use the ID, not the title, for automation.
- Finding order is deterministic (severity first) but should not be used as a
  priority score.
