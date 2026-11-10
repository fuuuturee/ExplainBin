# Contributing to ExplainBin

Thanks for your interest. ExplainBin is a defensive, local-only static analysis tool. Contributions that improve correctness, safety, clarity and explainability are especially welcome.

## Ground rules

- **Never execute or load analyzed files** in tests, CI or development tooling.
- **No live malware** in issues, pull requests or fixtures. Build synthetic PE files in memory or generate them with `tests/TestPeBuilder.hpp`.
- **No network calls at analysis time.** Signature revocation remains cache-only.
- **No opaque scores.** Every finding must include evidence, a plain-language explanation, legitimate explanations and next steps.
- **Validate every offset and size** before reading untrusted data.
- Keep the core library free of Qt; UI code belongs under `src/ui` and `include/explainbin/ui`.

## Development setup

1. Install CMake 3.24+, Ninja and a C++20 compiler (VS 2022 or MinGW-w64).
2. Install Qt 6.5+ with Widgets, Svg and Concurrent for GUI work.
3. Configure and build:

```powershell
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Debug
cmake --build build
ctest --test-dir build --output-on-failure
```

Core-only builds are faster when working on the parser:

```powershell
cmake -S . -B build -G Ninja -DEXPLAINBIN_BUILD_UI=OFF
```

## Code style

- C++20, four-space indentation, 100-column soft limit.
- `namespace explainbin` for core and reports; `explainbin::ui` for UI.
- Prefer `std::filesystem::path`, `std::span`, `std::string_view` and `[[nodiscard]]`.
- No exceptions across the public analyzer boundary: the pipeline converts expected failures into `errorMessage` or `Diagnostic` entries.
- Keep functions small and name evidence precisely (RVA, offset, field, size).
- Do not add third-party dependencies without discussion. The current set is Qt 6, nlohmann/json and GoogleTest.

## Adding a finding rule

1. Choose a stable ID from the correct prefix (`EB-PE-`, `EB-SEC-`, `EB-IMP-`, `EB-SIG-`, `EB-TLS-`, `EB-DBG-`).
2. Implement detection in `src/core/FindingsEngine.cpp` or `src/core/ImportAnalyzer.cpp`.
3. Populate **all** fields:
   - `description`: what was observed, with exact evidence
   - `whyItMatters`: impact without alarmism
   - `evidence`: RVA, offsets, API names, sizes, counts
   - `legitimateExplanations`: at least two realistic benign cases
   - `nextSteps`: safe, concrete investigation steps
4. Pick severity and confidence deliberately. A capability alone is usually Informational or Low. A combination of capabilities can be Medium or High. Reserve Critical for cases where the file cannot be interpreted at all or a signature is actively invalid in a way that indicates tampering.
5. Add a unit test in `tests/FindingsTests.cpp`.
6. Update `docs/RULES.md`.

Rules must never claim malware, produce a score or claim that a file is safe.

## Parser changes

- Every read must go through the bounds-checked `Reader` or equivalent validation.
- Cap counts (sections, imports, thunks, resources, debug entries, TLS callbacks).
- Track partial parses with a diagnostic instead of aborting the entire analysis.
- Add regression tests for truncation, invalid RVAs, zero sizes, integer overflow and cyclic structures.
- Keep `AnalysisResult::pe` internally consistent even when parsing is partial.

## UI changes

- Use code-based widgets (no `.ui` files) and the established `Theme` palette.
- Never block the GUI thread; analysis runs through QtConcurrent.
- Treat all file-derived strings as untrusted. Never interpret them as HTML or rich text.
- Keep accessibility in mind: keyboard navigation, readable contrast, scalable layouts.

## Pull requests

- Keep changes focused and describe the motivation.
- Include tests for behavior changes.
- Run a full build and `ctest` before opening the PR.
- Update README/docs when behavior or options change.
- Note any remaining limitations explicitly.

## Commit messages

Use a short imperative summary, optionally with a scope:

```
parser: bound the resource directory walk
findings: add EB-SEC-007 for zero-raw executable sections
ui: keep analysis result when the window is resized
```

## License

By contributing, you agree that your contributions are licensed under the MIT License.
