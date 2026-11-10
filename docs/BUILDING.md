# Building ExplainBin

## Prerequisites

| Requirement | Minimum | Notes |
| --- | --- | --- |
| Windows | 10 1809 | Windows 11 recommended |
| CMake | 3.24 | 3.28+ recommended |
| Compiler | MSVC 19.3x or GCC 13 | C++20 required |
| Qt | 6.5 | Widgets, Svg, Concurrent; GUI only |
| Ninja | 1.11 | Optional with MSVC |
| Git | any | Only for FetchContent and cloning |

The core and CLI need the Windows SDK (headers and link libraries) but no third-party runtime. `nlohmann/json` and GoogleTest are fetched automatically when not installed.

## CMake presets

`CMakePresets.json` provides equivalent shortcuts:

```powershell
# Core, CLI and tests (Ninja, Release)
cmake --preset core
cmake --build --preset core
ctest --preset core

# Full GUI build; point QT_ROOT at the matching Qt kit
$env:QT_ROOT = "C:\Qt\6.8.0\msvc2022_64"
cmake --preset gui-msvc
cmake --build --preset gui-msvc
ctest --preset gui-msvc
```

Use `gui-mingw` instead of `gui-msvc` for a MinGW kit. The core preset enables
warnings-as-errors; the GUI presets keep warnings visible without failing the
build on third-party or platform-specific diagnostics.

## Visual Studio 2022

Install **Desktop development with C++** including the Windows 10/11 SDK and CMake tools. Then, from a Developer PowerShell:

```powershell
cmake -S . -B build -G Ninja `
  -DCMAKE_BUILD_TYPE=Release `
  -DCMAKE_PREFIX_PATH="C:\Qt\6.8.0\msvc2022_64"
cmake --build build
.\build\ExplainBin.exe
```

If `cl.exe` is not found, use the Visual Studio generator instead of Ninja:

```powershell
cmake -S . -B build -G "Visual Studio 17 2022" -A x64 `
  -DCMAKE_PREFIX_PATH="C:\Qt\6.8.0\msvc2022_64"
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
```

## MinGW-w64

Use a UCRT or MSVCRT build with POSIX threads and SEH. Verify:

```powershell
g++ --version
cmake --version
ninja --version
```

Configure with an explicit compiler so CMake does not pick up MSVC:

```powershell
cmake -S . -B build -G Ninja `
  -DCMAKE_BUILD_TYPE=Release `
  -DCMAKE_CXX_COMPILER=g++ `
  -DCMAKE_PREFIX_PATH="C:\Qt\6.8.0\mingw_64"
cmake --build build
```

Qt must match the compiler ABI. A MinGW compiler cannot link an MSVC Qt build (and vice versa).

## Core-only build

Useful for parser work, CI and embedding the core:

```powershell
cmake -S . -B build-core -G Ninja `
  -DCMAKE_BUILD_TYPE=Release `
  -DEXPLAINBIN_BUILD_UI=OFF
cmake --build build-core
```

## Tests

```powershell
cmake -S . -B build -G Ninja -DEXPLAINBIN_BUILD_UI=OFF -DEXPLAINBIN_BUILD_TESTS=ON
cmake --build build
ctest --test-dir build --output-on-failure
```

Run a single test:

```powershell
.\build\explainbin_tests.exe --gtest_filter=Analyzer.*
```

The tests generate synthetic PE files in memory and in the system temporary directory. They do not ship or execute binaries.

## CLI smoke test

```powershell
.\build\explainbin-cli.exe C:\Windows\System32\notepad.exe --json notepad.json --html notepad.html
```

Inspect the JSON schema and verify that the SHA-256 matches `Get-FileHash`:

```powershell
(Get-FileHash C:\Windows\System32\notepad.exe -Algorithm SHA256).Hash.ToLower()
(Get-Content notepad.json | ConvertFrom-Json).file.hashes.sha256
```

## Installation

```powershell
cmake --install build --prefix dist
```

With a multi-config generator add `--config Release`.

## Packaging notes

- Ship `Qt6Core.dll`, `Qt6Gui.dll`, `Qt6Widgets.dll`, `Qt6Svg.dll`, `Qt6Concurrent.dll` and the `platforms/qwindows.dll` plugin, or use `windeployqt`.
- The MinGW build may also require `libgcc_s_seh-1.dll`, `libstdc++-6.dll` and `libwinpthread-1.dll`, or link the runtime statically.
- The application does not require administrator rights.

### Single-file installer

`installer/ExplainBin.iss` packages a self-contained build into one
`ExplainBin-<version>-Setup.exe`. It installs per-user under
`%LOCALAPPDATA%\Programs\ExplainBin`, so no administrator rights are needed.
Pushing a `v*` tag runs `.github/workflows/release.yml`, which builds with MSVC,
runs the tests, deploys the Qt runtime, compiles the installer and publishes it
as the only download asset of the GitHub release.

To build the installer locally with [Inno Setup 6](https://jrsoftware.org/isinfo.php):

```powershell
# 1. Stage a Release build and bundle the Qt runtime
New-Item -ItemType Directory -Force dist\stage | Out-Null
Copy-Item build\Release\ExplainBin.exe                    dist\stage
Copy-Item build\Release\explainbin-cli.exe                dist\stage
Copy-Item LICENSE                                         dist\stage
windeployqt --release --no-translations --compiler-runtime dist\stage\ExplainBin.exe

# 2. Compile the installer (adjust the version if needed)
& "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe" `
  /DAppVersion=1.0.0 installer\ExplainBin.iss
```

The result is `dist\ExplainBin-<version>-Setup.exe`. Validate it silently with
`/VERYSILENT /NORESTART` before publishing.

## Troubleshooting

### `Could not find a package configuration file provided by "Qt6"`

Set `CMAKE_PREFIX_PATH` to the Qt kit directory, for example `C:\Qt\6.8.0\msvc2022_64`, and delete `CMakeCache.txt` before reconfiguring.

### `undefined reference to WinMain`

The GUI target uses `WIN32` and `main`; the CLI uses `wmain` and links `-municode` with MinGW. Do not link `-municode` into the GUI target.

### GoogleTest or nlohmann/json download fails

Pre-install them with vcpkg or a system package, or configure with `-DFETCHCONTENT_FULLY_DISCONNECTED=OFF` and a working proxy. CMake caches downloads under `build/_deps`.

### `bcrypt`, `crypt32` or `wintrust` unresolved

These libraries are linked by `explainbin_core`. On non-Windows or with a stripped Windows SDK they will not exist; ExplainBin currently targets Windows only.

### Antivirus flags the build output

The tool parses PE files and links WinTrust. Some heuristic scanners react to the strings and APIs. Build from source and add an exclusion for your build directory if you trust the toolchain.

### Signature verification returns unknown

WinVerifyTrust may fail in restricted environments, offline scenarios or when the file is catalog-signed by a catalog that is not installed locally. ExplainBin checks locally installed catalogs before reporting unsigned. A failed catalog lookup is reported as unsigned/unknown, never as valid. Do not treat it as a safety verdict.
