# Finding rules

Every finding has a stable ID, a category, a severity, a confidence, the observation, its impact, technical evidence, possible legitimate explanations and recommended investigation.

Severity describes **how strongly the observation can matter**, not a probability of malice. Confidence describes **how well the parsed evidence supports the observation**.

| Level | Meaning |
| --- | --- |
| Informational | Context or metadata; expected in many legitimate files |
| Low | Capability or anomaly worth noting; common in benign software |
| Medium | Combination or anomaly that deserves review, with realistic benign explanations |
| High | Strong indicator or structural abnormality that should be resolved before execution |
| Critical | The file cannot be interpreted or a signature actively fails in a way indicating tampering |

There is no aggregate malware score.

## PE structure

| ID | Title | Severity | Trigger |
| --- | --- | --- | --- |
| `EB-PE-001` | The file could not be parsed as a valid PE image | Critical | Fatal DOS/NT/optional header error |
| `EB-PE-002` | PE structure contains inconsistencies | Medium | Parser set `partial` with diagnostics |
| `EB-PE-008` | SizeOfImage is smaller than the section layout requires | High | Highest section end exceeds `SizeOfImage` |
| `EB-PE-009` | File or section alignment is inconsistent | Low | Invalid/non-power-of-two alignment or `SectionAlignment < FileAlignment` |
| `EB-PE-011` | Data is appended after the last PE section | Informational | Overlay ≥ 4 KiB |
| `EB-PE-012` | PE checksum does not match the file | Low | Nonzero stored checksum differs from computed checksum |
| `EB-PE-013` | Compile timestamp is zero or in the future | Informational/Low | `TimeDateStamp == 0` or > now + 1 day |
| `EB-PE-014` | Image contains a .NET runtime directory | Informational | CLR runtime data directory present |
| `EB-PE-015` | Executable does not advertise ASLR or NX | Informational | Neither `DYNAMIC_BASE` nor `NX_COMPAT` set |
| `EB-PE-017` | Declared section count exceeds the loader limit | Medium | `NumberOfSections > 96` |

Overlay, checksum, timestamp and mitigation findings are deliberately informational/low: they appear in many legitimate binaries. They are context, not accusations. A legitimate self-extracting installer, for example, carries an overlay by design.

## Sections and layout

| ID | Title | Severity | Trigger |
| --- | --- | --- | --- |
| `EB-SEC-001` | A section is both writable and executable | High | Any section with `IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE` |
| `EB-SEC-002` | Executable sections use unusual names | Low | Executable section name is not a common compiler/system name (case-insensitive, common prefixes accepted) and not a known packer name |
| `EB-SEC-003` | Section names match known packers/protectors | Medium | Name matches UPX, ASPack, Themida, VMProtect, Enigma and similar |
| `EB-SEC-004` | An executable or writable section has high entropy | Low | Executable/writable section with raw size ≥ 4 KiB, entropy ≥ 7.2 bits/byte, excluding `.rsrc`/`.reloc` |
| `EB-SEC-005` | Missing entry point / entry point outside executable sections | Medium/High | `AddressOfEntryPoint == 0` for a native EXE (managed .NET assemblies excluded), or no executable section contains it |
| `EB-SEC-006` | Sections overlap in memory | High | Two virtual ranges intersect |
| `EB-SEC-007` | Executable section has no file-backed data | Medium | Executable with `rawSize == 0` and `virtualSize > 0`, excluding padding sections named `Pad`, `Pad1`, ... |

Writable executable memory is used by JIT compilers, runtimes, protectors and unpackers, but also by self-modifying or injected code. Entropy is a statistical property: compressed resources, media, archives and databases legitimately approach 8 bits/byte.

## Imports

| ID | Title | Severity | Trigger |
| --- | --- | --- | --- |
| `EB-IMP-001` | Imports include a classic process-injection sequence | Medium | Explicit remote allocation + remote write + remote thread/APC APIs, excluding modules that export those APIs |
| `EB-IMP-002` | Keyboard hook and key-state APIs are present | Low | Hook installation + key state APIs; hook type/scope is not visible statically |
| `EB-IMP-003` | Imports support downloading and starting another program | Low | Network + process execution APIs |
| `EB-IMP-004` | Imports can create and start a Windows service | Low | Service creation + service control APIs |
| `EB-IMP-005` | The file can modify the Windows registry | Informational | `RegSetValueEx`/`RegCreateKeyEx` |
| `EB-IMP-006` | APIs associated with debugger detection are present | Informational | Anti-debug APIs |
| `EB-IMP-007` | The file can access stored credentials or protected data | Low | Credential APIs / `CryptUnprotectData` |
| `EB-IMP-008` | Encryption and file enumeration capabilities are both present | Low | Crypto + file enumeration APIs |
| `EB-IMP-009` | APIs are resolved dynamically at runtime | Informational | `LoadLibrary` + `GetProcAddress` |
| `EB-IMP-010` | Networking APIs are present | Informational | Network APIs without execution APIs |
| `EB-IMP-011` | No imported functions were observed | Low/Informational | Empty/absent import table; Informational for managed assemblies or images that export an API surface |
| `EB-IMP-012` | GDI pixel-copying APIs are present | Informational | `BitBlt`/`StretchBlt` + DC API + `CreateCompatibleBitmap` |

Import rules describe **capability combinations**, not observed behavior. A debugger and a game overlay can match `EB-IMP-001`; an updater can match `EB-IMP-003`; a backup tool can match `EB-IMP-008`. Each finding lists these benign explanations.

## Signature

| ID | Title | Severity | Trigger |
| --- | --- | --- | --- |
| `EB-SIG-000` | The digital signature could not be checked | Informational | Verification requested but not completed |
| `EB-SIG-001` | No trusted digital signature was found | Informational | No embedded signature and no matching trusted local catalog |
| `EB-SIG-002` | Signature verified (embedded or catalog) | Informational | WinVerifyTrust returns success for the embedded signature or a matching catalog |
| `EB-SIG-003` | Signature did not verify | High | Certificate table/signer present but verification fails |
| `EB-SIG-004` | Signature status is indeterminate | Low | Uncommon trust-provider result |

Unsigned is **not** malicious. Many open-source and internal tools are unsigned. A valid signature proves provenance and integrity of the signed bytes, not safety. Revocation is not checked online by design; reports state this explicitly.

## TLS and debug

| ID | Title | Severity | Trigger |
| --- | --- | --- | --- |
| `EB-TLS-001` | TLS callbacks are registered before the entry point | Low | TLS directory with a non-empty callback array |
| `EB-DBG-001` | Embedded PDB path | Informational | CodeView record contains a path |

TLS callbacks are a normal runtime feature used by C++ runtimes, security products and frameworks, and also by packers to run code before the entry point. An embedded PDB path reveals build metadata, not intent.

## Writing new rules

A rule should answer:

1. **What exactly was observed?** Include field names, RVAs, offsets, API names and sizes.
2. **Why could it matter?** Describe the capability or risk in plain language.
3. **What benign scenarios produce the same pattern?** Provide at least two realistic cases.
4. **What should an analyst do next?** Prefer safe, static or sandboxed steps.

Rules must not claim malware, compute a combined score or treat the absence of findings as proof of safety.
