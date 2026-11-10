#include "explainbin/core/FindingsEngine.hpp"

#include "explainbin/core/PEFormat.hpp"
#include "explainbin/core/Util.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <string>
#include <vector>

namespace explainbin {
namespace {

Finding makeFinding(std::string id, std::string category, std::string title,
                    Severity severity, Confidence confidence,
                    std::string description, std::string whyItMatters,
                    std::vector<std::string> evidence,
                    std::vector<std::string> legitimateExplanations,
                    std::vector<std::string> nextSteps) {
    Finding finding;
    finding.id = std::move(id);
    finding.category = std::move(category);
    finding.title = std::move(title);
    finding.severity = severity;
    finding.confidence = confidence;
    finding.description = std::move(description);
    finding.whyItMatters = std::move(whyItMatters);
    finding.evidence = std::move(evidence);
    finding.legitimateExplanations = std::move(legitimateExplanations);
    finding.nextSteps = std::move(nextSteps);
    return finding;
}

std::string entropyText(double value) {
    std::array<char, 32> buffer{};
    std::snprintf(buffer.data(), buffer.size(), "%.3f bits/byte", value);
    return buffer.data();
}

std::string percentText(double value) {
    std::array<char, 32> buffer{};
    std::snprintf(buffer.data(), buffer.size(), "%.1f%%", value);
    return buffer.data();
}

std::string sectionFlags(const SectionInfo& section) {
    std::string flags;
    const auto append = [&flags](const char* flag) {
        if (!flags.empty()) {
            flags += ", ";
        }
        flags += flag;
    };
    if (section.readable) {
        append("read");
    }
    if (section.writable) {
        append("write");
    }
    if (section.executable) {
        append("execute");
    }
    if (section.code) {
        append("code");
    }
    if (section.initializedData) {
        append("initialized data");
    }
    if (section.uninitializedData) {
        append("uninitialized data");
    }
    return flags.empty() ? "none" : flags;
}

// The loader maps VirtualSize bytes for a section; SizeOfRawData is only the
// file-aligned backing size and can be larger than the mapped region. Using the
// larger value can invent overlaps or an image that extends past SizeOfImage.
std::uint64_t sectionVirtualSpan(const SectionInfo& section) {
    const auto virtualSize = static_cast<std::uint64_t>(section.virtualSize);
    return virtualSize != 0 ? virtualSize : static_cast<std::uint64_t>(section.rawSize);
}

bool sectionContainsRva(const SectionInfo& section, std::uint32_t rva) {
    const auto start = static_cast<std::uint64_t>(section.virtualAddress);
    const auto span = sectionVirtualSpan(section);
    return span != 0 && rva >= start && rva < start + span;
}

bool isPowerOfTwo(std::uint32_t value) {
    return value != 0 && (value & (value - 1U)) == 0;
}

} // namespace

std::vector<Finding> FindingsEngine::evaluate(const AnalysisResult& result) const {
    std::vector<Finding> findings;
    const auto& pe = result.pe;

    if (!pe.parsed) {
        std::vector<std::string> evidence;
        for (const auto& diagnostic : result.diagnostics) {
            if (diagnostic.fatal) {
                evidence.push_back(diagnostic.code + ": " + diagnostic.message);
            }
        }
        if (evidence.empty()) {
            evidence.push_back("The PE parser did not produce a valid image.");
        }
        findings.push_back(makeFinding(
            "EB-PE-001", "PE structure", "The file could not be parsed as a valid PE image",
            Severity::Critical, Confidence::High,
            "The file does not contain a structurally valid DOS/NT header chain, so ExplainBin "
            "could not analyze sections, imports, signatures or resources.",
            "A damaged or deliberately malformed header prevents reliable static assessment. "
            "This could be corruption, a non-PE file, a truncated download, or an attempt to "
            "evade parsers. It does not by itself prove malicious intent.",
            std::move(evidence),
            {"The file may be a different format with a misleading extension.",
             "The file may have been truncated during download or transfer.",
             "The file may be intentionally packed or protected."},
            {"Verify the file hash and obtain a fresh copy from the original source.",
             "Inspect the first bytes with a hex editor.",
             "Do not execute the file; analyze a known-good sample of the same product."}));
        return findings;
    }

    if (pe.partial) {
        std::vector<std::string> evidence;
        for (const auto& diagnostic : result.diagnostics) {
            if (!diagnostic.fatal) {
                evidence.push_back(diagnostic.code + ": " + diagnostic.message);
            }
            if (evidence.size() >= 12) {
                break;
            }
        }
        findings.push_back(makeFinding(
            "EB-PE-002", "PE structure",
            "The PE structure contains inconsistencies or unsupported values", Severity::Medium,
            Confidence::High,
            "Some header, section or directory values are internally inconsistent. ExplainBin "
            "parsed what was safe to parse and skipped the rest.",
            "Malformed structures can indicate corruption or deliberate evasion, but unusual "
            "toolchains and protectors can also produce nonstandard images. Partial analysis "
            "may miss imports or other metadata.",
            std::move(evidence),
            {"The file may use an unusual packer, protector or linker.",
             "The file may be damaged or partially downloaded.",
             "Some legitimate binaries contain nonstandard padding or directory sizes."},
            {"Compare the hash with the publisher's official artifact.",
             "Inspect the reported fields in a second PE tool.",
             "Treat missing metadata as unknown, not as evidence of safety."}));
    }

    std::vector<std::string> wxEvidence;
    for (const auto& section : pe.sections) {
        if (section.executable && section.writable) {
            std::string evidence = "Section '" + section.name + "' at RVA " +
                                   util::toHex(section.virtualAddress) +
                                   " has characteristics " + util::toHex(section.characteristics) +
                                   " (" + sectionFlags(section) + ")";
            if (section.entropy >= 0.0) {
                evidence += "; entropy " + entropyText(section.entropy);
            }
            wxEvidence.push_back(std::move(evidence));
        }
    }
    if (!wxEvidence.empty()) {
        findings.push_back(makeFinding(
            "EB-SEC-001", "Sections", "A section is both writable and executable",
            Severity::High, Confidence::High,
            "One or more sections have both the writable and executable memory permissions. "
            "Normal compiler output separates code from writable data.",
            "Writable executable memory makes it easier to modify code at runtime. This is used "
            "by just-in-time compilers, protectors and unpackers, but also by self-modifying or "
            "injected code. The permission flags alone do not show what the section contains.",
            std::move(wxEvidence),
            {"Just-in-time compilers and scripting runtimes allocate executable memory.",
             "Packers unpack code into a writable executable section at startup.",
             "Some copy-protection and anti-tamper products use this layout.",
             "Hand-written assembly or unusual build systems may merge code and data."},
            {"Inspect the section's entropy and raw contents.",
             "Determine whether the entry point or TLS callbacks lie in this section.",
             "Run the sample in an isolated sandbox and monitor memory protection changes."}));
    }

    std::vector<std::string> unusualNames;
    std::vector<std::string> packerNames;
    for (const auto& section : pe.sections) {
        if (section.name.empty()) {
            // Only an executable section with no name supports the claim made by
            // EB-SEC-002. Data-only sections may legitimately have no name.
            if (section.executable) {
                unusualNames.push_back("An executable section has an empty name.");
            }
            continue;
        }
        if (pe::isPackerSectionName(section.name)) {
            packerNames.push_back("Section name '" + section.name + "' matches a known packer or protector.");
        }
        if (section.executable && !pe::isCommonSectionName(section.name) &&
            !pe::isPackerSectionName(section.name)) {
            unusualNames.push_back("Executable section '" + section.name + "' is not a common compiler section name.");
        }
    }
    if (!unusualNames.empty()) {
        findings.push_back(makeFinding(
            "EB-SEC-002", "Sections", "Executable sections use unusual names", Severity::Low,
            Confidence::Medium,
            "The section table contains executable sections whose names are not typical for "
            "the Microsoft, GCC or Clang toolchains.",
            "Section names are chosen by the linker and carry no enforcement. Malware and "
            "protectors sometimes rename sections, but custom names also appear in legitimate "
            "software with custom build pipelines.",
            std::move(unusualNames),
            {"The project uses a custom linker script or embedded toolchain.",
             "A protector or packer renamed sections.",
             "The file was built with a nonstandard compiler or post-processing tool."},
            {"Review section contents and permissions rather than relying on names.",
             "Compare against a known build of the same software.",
             "Check the signature and file origin."}));
    }
    if (!packerNames.empty()) {
        findings.push_back(makeFinding(
            "EB-SEC-003", "Sections", "Section names match known packers or protectors",
            Severity::Medium, Confidence::Medium,
            "At least one section name is associated with a known executable packer, protector "
            "or crypter.",
            "Packed executables hide their original code and imports until runtime. Packing is "
            "used by legitimate commercial software for compression and protection, and by "
            "malware to hinder analysis.",
            std::move(packerNames),
            {"Commercial applications often ship packed to reduce size or deter reverse engineering.",
             "Game and anti-cheat vendors use protectors.",
             "Installer builders may use compression stubs."},
            {"Identify the packer and attempt safe unpacking in an isolated environment.",
             "Check the digital signature; valid signatures are stronger evidence than section names.",
             "Treat the import table as potentially incomplete until unpacked."}));
    }

    std::vector<std::string> highEntropySections;
    for (const auto& section : pe.sections) {
        if (!section.rawRangeValid || section.rawSize < 4096 || section.entropy < 7.2) {
            continue;
        }
        // Resource, relocation and read-only data sections routinely contain compressed
        // payloads. Only executable or writable sections support a packing observation.
        if (!section.executable && !section.writable) {
            continue;
        }
        const auto lowerName = util::toLowerAscii(section.name);
        if (lowerName == ".rsrc" || lowerName == ".reloc") {
            continue;
        }
        highEntropySections.push_back(
            "Section '" + section.name + "' has entropy " + entropyText(section.entropy) +
            " across " + util::humanBytes(section.rawSize) + " of file data.");
    }
    if (!highEntropySections.empty()) {
        findings.push_back(makeFinding(
            "EB-SEC-004", "Entropy",
            "An executable or writable section has high entropy", Severity::Low,
            Confidence::Medium,
            "One or more executable or writable sections contain data with entropy close to the "
            "theoretical maximum of 8 bits per byte. Compressed, encrypted or packed data "
            "typically has this property.",
            "High entropy can indicate packing or encryption that hides code and strings. It can "
            "also be normal for embedded media, databases or compressed data. Entropy is a "
            "statistical observation, not a malware signature.",
            std::move(highEntropySections),
            {"The section contains compressed resources or embedded media.",
             "The application is packed with a commercial protector.",
             "The section holds a database, archive or cryptographic material."},
            {"Inspect the section bytes for known compression or encryption headers.",
             "Determine whether imports and strings are unusually sparse.",
             "Unpack or emulate in an isolated environment before making a judgment."}));
    }

    if (pe.entryPointRva == 0) {
        // Managed .NET assemblies normally have AddressOfEntryPoint = 0; the CLR invokes
        // the managed entry method through metadata instead.
        if (!pe.isDll && !pe.hasClrDirectory) {
            findings.push_back(makeFinding(
                "EB-SEC-005", "PE structure", "The executable has no entry point",
                Severity::Medium, Confidence::High,
                "AddressOfEntryPoint is zero. A normal executable needs an entry point to begin "
                "execution; DLLs may legitimately omit DllMain.",
                "An executable without an entry point may be malformed, or it may rely on a "
                "loader, service host or reflective-loading mechanism.",
                {"AddressOfEntryPoint = 0x0", "Image type = executable"},
                {"The file may be a resource or data container with an .exe extension.",
                 "A packer may populate the entry point later.",
                 "The file may be damaged."},
                {"Confirm the file type and how it is launched.",
                 "Inspect the section table for executable content.",
                 "Do not double-click the file; analyze it statically or in a sandbox."}));
        }
    } else {
        const bool entryInsideExecutable = std::any_of(
            pe.sections.begin(), pe.sections.end(), [&pe](const SectionInfo& section) {
                return section.executable && sectionContainsRva(section, pe.entryPointRva);
            });
        if (!entryInsideExecutable) {
            findings.push_back(makeFinding(
                "EB-SEC-005", "PE structure",
                "The entry point lies outside every executable section", Severity::High,
                Confidence::High,
                "AddressOfEntryPoint does not fall inside a section marked executable.",
                "The Windows loader transfers control to this address. If it is not backed by "
                "executable section data, the image is structurally abnormal or depends on "
                "runtime modification.",
                {"AddressOfEntryPoint = " + util::toHex(pe.entryPointRva),
                 "No executable section contains this RVA."},
                {"A protector may map code into place before transferring control.",
                 "The file may be deliberately malformed.",
                 "The header may have been damaged or edited."},
                {"Inspect the entry point mapping in a disassembler without running the file.",
                 "Check for packing and TLS callbacks.",
                 "Analyze the file in an isolated sandbox if execution is necessary."}));
        }
    }

    std::vector<std::string> overlaps;
    for (std::size_t first = 0; first < pe.sections.size(); ++first) {
        for (std::size_t second = first + 1; second < pe.sections.size(); ++second) {
            const auto& a = pe.sections[first];
            const auto& b = pe.sections[second];
            const auto aSpan = sectionVirtualSpan(a);
            const auto bSpan = sectionVirtualSpan(b);
            if (aSpan == 0 || bSpan == 0) {
                continue;
            }
            const auto aStart = static_cast<std::uint64_t>(a.virtualAddress);
            const auto bStart = static_cast<std::uint64_t>(b.virtualAddress);
            if (aStart < bStart + bSpan && bStart < aStart + aSpan) {
                overlaps.push_back("Sections '" + a.name + "' and '" + b.name +
                                   "' overlap in the virtual address range.");
            }
        }
    }
    if (!overlaps.empty()) {
        findings.push_back(makeFinding(
            "EB-SEC-006", "Sections", "Sections overlap in memory", Severity::High,
            Confidence::High,
            "Two or more sections claim overlapping virtual address ranges. The Windows loader "
            "expects section mappings to be distinct.",
            "Overlapping sections can cause one section's data to overwrite another's and are "
            "sometimes used to confuse analysis tools or construct unusual mappings.",
            std::move(overlaps),
            {"A custom linker script or protector may produce unusual mappings.",
             "The header may have been edited or corrupted.",
             "A legitimately obfuscated application may overlap unused ranges."},
            {"Map each section independently and compare with the loader's view.",
             "Check whether the entry point or imports fall in an overlapping region.",
             "Treat the file as untrusted and use an isolated analysis environment."}));
    }

    std::vector<std::string> zeroRawExecutable;
    for (const auto& section : pe.sections) {
        if (section.executable && section.rawSize == 0 && section.virtualSize > 0 &&
            !pe::isPaddingSectionName(section.name)) {
            zeroRawExecutable.push_back(
                "Section '" + section.name + "' is executable but has no file-backed data (virtual size " +
                util::humanBytes(section.virtualSize) + ").");
        }
    }
    if (!zeroRawExecutable.empty()) {
        findings.push_back(makeFinding(
            "EB-SEC-007", "Sections", "An executable section has no file-backed data",
            Severity::Medium, Confidence::Medium,
            "A section marked executable has a nonzero virtual size but zero raw size, so there "
            "are no bytes for it in the file.",
            "Code cannot normally execute from a section that has no file data. This can be a "
            "packer that fills the section at runtime, or a malformed header.",
            std::move(zeroRawExecutable),
            {"A packer or virtualizer may prepare the section at runtime.",
             "The linker may emit a zero-filled executable section in unusual configurations.",
             "The header may be corrupt."},
            {"Inspect runtime memory writes and protection changes in a sandbox.",
             "Check whether imports, TLS callbacks or the entry point depend on this section.",
             "Compare with a known build of the same product."}));
    }

    if (pe.sizeOfImage != 0 && !pe.sections.empty() && pe.sectionAlignment != 0) {
        std::uint64_t required = 0;
        for (const auto& section : pe.sections) {
            const auto end = static_cast<std::uint64_t>(section.virtualAddress) +
                             sectionVirtualSpan(section);
            required = std::max(required, end);
        }
        if (required > pe.sizeOfImage) {
            findings.push_back(makeFinding(
                "EB-PE-008", "PE structure",
                "SizeOfImage is smaller than the section layout requires", Severity::High,
                Confidence::High,
                "The optional header's SizeOfImage is smaller than the end of one or more "
                "sections. The loader uses SizeOfImage to reserve the image address space.",
                "An undersized image can cause sections to extend beyond the reserved mapping. "
                "This is structurally inconsistent and may indicate header tampering or a "
                "nonstandard loader.",
                {"SizeOfImage = " + util::toHex(pe.sizeOfImage),
                 "Highest section end = " + util::toHex(required),
                 "SectionAlignment = " + util::toHex(pe.sectionAlignment)},
                {"A packer may expand the image at runtime.",
                 "A tool may have edited section sizes without updating the header.",
                 "The file may be intentionally malformed."},
                {"Validate the image with an independent PE parser.",
                 "Inspect section mapping and runtime memory reservations in a sandbox.",
                 "Treat the file's metadata as unreliable."}));
        }
    }

    if (pe.fileAlignment == 0 || !isPowerOfTwo(pe.fileAlignment) ||
        pe.fileAlignment > 0x10000 ||
        (pe.sectionAlignment != 0 && pe.sectionAlignment < pe.fileAlignment)) {
        findings.push_back(makeFinding(
            "EB-PE-009", "PE structure", "The file or section alignment is inconsistent",
            Severity::Low, Confidence::High,
            "FileAlignment and SectionAlignment do not follow the usual Windows PE rules "
            "(nonzero powers of two, with SectionAlignment at least as large as FileAlignment).",
            "Invalid alignment can break section mapping or indicate hand-edited headers. Some "
            "legitimate low-alignment images use SectionAlignment below the page size, but "
            "FileAlignment must still be valid.",
            {"FileAlignment = " + util::toHex(pe.fileAlignment),
             "SectionAlignment = " + util::toHex(pe.sectionAlignment)},
            {"A custom linker configuration or embedded toolchain may use unusual alignment.",
             "The file may be a low-alignment image.",
             "The header may be corrupt."},
            {"Compare with the documented PE alignment requirements.",
             "Inspect the section table and mapping in an independent tool.",
             "Do not execute the file if the structure is otherwise inconsistent."}));
    }

    if (pe.numberOfSections > pe::kMaxSections) {
        findings.push_back(makeFinding(
            "EB-PE-017", "PE structure", "The declared section count exceeds the loader limit",
            Severity::Medium, Confidence::High,
            "The COFF header declares more than 96 sections, the documented maximum supported by "
            "the Windows loader.",
            "The extra sections cannot be loaded normally and may be an attempt to confuse "
            "analysis tools or a sign of a malformed file.",
            {"NumberOfSections = " + std::to_string(pe.numberOfSections),
             "Windows loader limit = 96"},
            {"The header may be corrupt.",
             "A non-Windows PE producer may use a different limit.",
             "A tool may have merged or appended sections incorrectly."},
            {"Verify the section table with an independent parser.",
             "Identify which sections the loader would map.",
             "Treat the file as untrusted until its structure is explained."}));
    }

    if (pe.overlaySize >= 4096) {
        const double percentage = result.file.size == 0 ? 0.0
            : (static_cast<double>(pe.overlaySize) * 100.0 /
               static_cast<double>(result.file.size));
        findings.push_back(makeFinding(
            "EB-PE-011", "Overlay", "Data is appended after the last PE section",
            Severity::Informational, Confidence::High,
            "The file contains " + util::humanBytes(pe.overlaySize) + " of data after the last "
            "section (or after the certificate table).",
            "Installers, self-extracting archives and signed files legitimately carry appended "
            "data. Overlay data can also contain a hidden payload that is not mapped as part of "
            "the image. The overlay is reported as metadata and is not executed.",
            {"Overlay offset = " + util::toHex(pe.overlayOffset),
             "Overlay size = " + std::to_string(pe.overlaySize) + " bytes (" +
                 percentText(percentage) + " of the file)"},
            {"The executable is a self-extracting archive or installer.",
             "The vendor appended a signature, update package or configuration blob.",
             "The build process embeds resources after the section table."},
            {"Extract and identify the overlay as data only; do not execute it.",
             "Inspect the overlay for archive or executable headers.",
             "Verify the file hash and signature against the vendor's official release."}));
    }

    if (pe.checksumPresent && !pe.checksumValid) {
        findings.push_back(makeFinding(
            "EB-PE-012", "PE structure", "The PE checksum does not match the file",
            Severity::Low, Confidence::High,
            "The optional header contains a nonzero PE checksum, but the checksum computed over "
            "the file does not match it.",
            "The PE checksum is used by some drivers and loader paths. A mismatch can indicate "
            "that the file changed after linking, but many signing and patching workflows do not "
            "update it. A zero checksum is common and is not flagged.",
            {"Stored checksum = " + util::toHex(pe.checksum),
             "Computed checksum = " + util::toHex(pe.computedChecksum)},
            {"The file was signed or patched after linking and the checksum was not updated.",
             "The file may have been truncated or modified.",
             "Some build pipelines intentionally leave stale checksums."},
            {"Verify the Authenticode signature and file hash.",
             "Compare against the publisher's original artifact.",
             "Do not treat a checksum mismatch as proof of tampering."}));
    }

    const auto now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    if (pe.timestamp == 0) {
        findings.push_back(makeFinding(
            "EB-PE-013", "PE structure", "The compile timestamp is zero", Severity::Informational,
            Confidence::High,
            "The COFF TimeDateStamp field is zero rather than a plausible compiler timestamp.",
            "Reproducible builds and some modern linkers deliberately zero this field. An older "
            "binary with a zero timestamp may also have been edited.",
            {"TimeDateStamp = 0"},
            {"The build uses reproducible-build settings.",
             "The linker intentionally omits a timestamp.",
             "The header was edited or generated by a nonstandard tool."},
            {"Do not rely on the compile timestamp for trust decisions.",
             "Verify the signature and file hash.",
             "Check other build metadata such as the debug directory."}));
    } else if (static_cast<std::int64_t>(pe.timestamp) >
               static_cast<std::int64_t>(now) + 86400) {
        findings.push_back(makeFinding(
            "EB-PE-013", "PE structure", "The compile timestamp is in the future",
            Severity::Low, Confidence::Medium,
            "The COFF TimeDateStamp is later than the current time by more than one day.",
            "A future timestamp can result from clock skew during the build, but it can also "
            "indicate a hand-edited header or a fabricated timestamp.",
            {"TimeDateStamp = " + pe.timestampUtc,
             "Current UTC time = " + util::currentUtcTimestamp()},
            {"The build machine clock was incorrect.",
             "The file was built in a different time zone with incorrect settings.",
             "The header was modified after linking."},
            {"Verify the signature and file origin.",
             "Compare with other files from the same release.",
             "Do not use the timestamp as a standalone indicator."}));
    }

    if (!pe.tls.callbacks.empty()) {
        std::vector<std::string> evidence{"TLS directory is present."};
        evidence.push_back("TLS callback count = " + std::to_string(pe.tls.callbacks.size()));
        for (std::size_t index = 0; index < pe.tls.callbacks.size() && index < 8; ++index) {
            evidence.push_back("TLS callback[" + std::to_string(index) + "] = " +
                               util::toHex(pe.tls.callbacks[index]));
        }
        findings.push_back(makeFinding(
            "EB-TLS-001", "TLS", "TLS callbacks are registered before the entry point",
            Severity::Low, Confidence::Medium,
            "The image registers one or more Thread Local Storage callbacks. Windows calls them "
            "before the executable's entry point and for each new thread.",
            "TLS callbacks are a legitimate runtime feature used by some frameworks and security "
            "software, but they are also used by packers and malware to run code earlier than "
            "typical entry-point analysis expects.",
            std::move(evidence),
            {"Some runtimes and frameworks use callbacks for early per-thread setup.",
             "Security products and application frameworks may use callbacks for early setup.",
             "A packer may unpack or decrypt code in a TLS callback."},
            {"Inspect the callback code in a disassembler.",
             "Set breakpoints on TLS callbacks in an isolated debugger.",
             "Combine this finding with section entropy and import evidence."}));
    }

    for (const auto& debugEntry : pe.debugEntries) {
        if (debugEntry.pdbPath.empty()) {
            continue;
        }
        findings.push_back(makeFinding(
            "EB-DBG-001", "Debug", "A PDB path is embedded in the debug directory",
            Severity::Informational, Confidence::High,
            "The CodeView debug record contains a program database path. It can reveal build "
            "paths, usernames or project names.",
            "Debug paths help developers symbolize crashes. They are not malicious, but they can "
            "leak information about the build environment and can help correlate builds.",
            {"PDB path = " + debugEntry.pdbPath,
             debugEntry.guid.empty() ? "Debug type = CodeView" : "PDB GUID = " + debugEntry.guid},
            {"The vendor shipped a normal debug build or retained symbol metadata.",
             "The build system did not strip debug information.",
             "The file is a development or pre-release build."},
            {"Use the PDB GUID to locate matching public symbols if available.",
             "Do not infer trust from the presence or absence of a PDB path.",
             "Review other metadata and the digital signature."}));
    }

    if (pe.hasClrDirectory) {
        findings.push_back(makeFinding(
            "EB-PE-014", "PE structure", "The image contains a .NET runtime directory",
            Severity::Informational, Confidence::High,
            "A CLR runtime header is present, so this is likely a managed .NET assembly.",
            "Managed assemblies often have small native import tables and different section "
            "layouts. The usual native PE heuristics need additional context when interpreting "
            "them.",
            {"CLR Runtime data directory is present."},
            {"The application is written in C#, F#, VB.NET or another managed language.",
             "A native host embeds a managed runtime component.",
             "The file is a mixed-mode assembly."},
            {"Analyze IL metadata with a managed-code tool in addition to this report.",
             "Do not treat a small native import table as suspicious for a managed assembly.",
             "Check the assembly's strong name and Authenticode signature."}));
    }

    const std::uint16_t aslr = 0x0040;
    const std::uint16_t nxCompat = 0x0100;
    if (!pe.isDll && (pe.dllCharacteristics & (aslr | nxCompat)) == 0) {
        findings.push_back(makeFinding(
            "EB-PE-015", "PE structure",
            "The executable does not advertise ASLR or NX compatibility", Severity::Informational,
            Confidence::High,
            "Neither DYNAMIC_BASE (ASLR) nor NX_COMPAT (DEP) is set in DllCharacteristics.",
            "These flags are hardening preferences, not trust indicators. Older software and some "
            "custom toolchains legitimately omit them, but their absence can make exploitation "
            "easier if the program has other vulnerabilities.",
            {"DllCharacteristics = " + util::toHex(pe.dllCharacteristics),
             "DYNAMIC_BASE = not set",
             "NX_COMPAT = not set"},
            {"The binary was built for an older Windows version.",
             "The toolchain does not set these flags by default.",
             "The program is intentionally compatible with legacy systems."},
            {"Do not use missing mitigations as evidence of malware.",
             "Record it as a hardening observation.",
             "Review the program's update and vulnerability history."}));
    }

    if (result.signatureRequested) {
        const auto& signature = result.signature;
        if (!signature.checked) {
            findings.push_back(makeFinding(
                "EB-SIG-000", "Signature", "The digital signature could not be checked",
                Severity::Informational, Confidence::High,
                "Signature verification was requested but could not be completed. The result "
                "does not establish that the file is unsigned or signed.",
                "A failed verification step leaves the signature status unknown. It should not "
                "be interpreted as a clean or malicious verdict.",
                {"Verification status = " + std::string(toString(signature.status))},
                {"The verification service or API returned an unexpected error.",
                 "The file changed or was removed during analysis.",
                 "The environment restricts cryptographic trust operations."},
                {"Re-run the analysis on a stable local copy.",
                 "Verify the signature with an independent tool.",
                 "Do not treat unknown status as either safe or malicious."}));
        } else if (signature.status == SignatureStatus::Unsigned) {
            findings.push_back(makeFinding(
                "EB-SIG-001", "Signature", "No trusted digital signature was found",
                Severity::Informational, Confidence::High,
                "Windows did not find a valid Authenticode signature embedded in the file, and "
                "no matching trusted catalog signature was verified on this system. This is an "
                "observation about signing, not a malware verdict.",
                "Signing helps establish publisher identity and detects some post-signing "
                "modifications. Many legitimate open-source and internal tools are unsigned. "
                "Unsigned files require more context, such as a verified hash and trusted source.",
                {"Signature status = unsigned",
                 signature.present
                     ? "A certificate table exists but no usable signer was found."
                     : "No embedded certificate table was found; no matching catalog signature "
                       "was verified."},
                {"The software is open source and distributed without signing.",
                 "The build is internal or pre-release.",
                 "The publisher uses a catalog that is not installed on this system."},
                {"Verify the SHA-256 hash against the publisher's official release.",
                 "Download only from the official source over HTTPS.",
                 "Submit the file to a reputable multi-engine service if provenance is unknown."}));
        } else if (signature.status == SignatureStatus::Valid) {
            const bool catalog = signature.catalogSigned;
            std::vector<std::string> evidence;
            evidence.push_back(catalog ? "Signature type = Windows catalog"
                                       : "Signature type = embedded Authenticode");
            evidence.push_back("WinVerifyTrust status = valid");
            if (!signature.subject.empty()) {
                evidence.push_back("Subject = " + signature.subject);
            }
            if (!signature.issuer.empty()) {
                evidence.push_back("Issuer = " + signature.issuer);
            }
            if (!signature.notAfterUtc.empty()) {
                evidence.push_back("Certificate validity ends = " + signature.notAfterUtc);
            }
            findings.push_back(makeFinding(
                "EB-SIG-002", "Signature",
                catalog ? "The file's signature verified through a Windows catalog"
                        : "The embedded signature verified successfully",
                Severity::Informational, Confidence::High,
                catalog
                    ? "A trusted local Windows catalog contains this file's hash, and Windows "
                      "verified the catalog's signature and certificate chain."
                    : "Windows verified the embedded Authenticode signature against its trust "
                      "chain at the time of analysis.",
                "A valid signature is useful provenance evidence and indicates the signed bytes "
                "were not modified after signing. It does not guarantee that the software is "
                "free of vulnerabilities or that the publisher is trustworthy.",
                std::move(evidence),
                {catalog ? "The publisher distributes catalog-signed system or vendor files."
                         : "The file was signed by its publisher and has not been modified since signing.",
                 "The certificate chain is trusted on this system.",
                 "A timestamp may extend validity beyond the certificate's expiration."},
                {"Confirm that the signer identity matches the expected publisher.",
                 "Check the certificate's expiration and revocation status with the CA.",
                 "Remember that validly signed software can still be malicious or vulnerable."}));
        } else if (signature.status == SignatureStatus::Invalid) {
            std::vector<std::string> evidence{"WinVerifyTrust status = invalid",
                                               "Trust detail = " + signature.trustMessage};
            if (!signature.subject.empty()) {
                evidence.push_back("Subject = " + signature.subject);
            }
            if (!signature.issuer.empty()) {
                evidence.push_back("Issuer = " + signature.issuer);
            }
            if (signature.expired) {
                evidence.push_back("The signing certificate is expired.");
            }
            if (signature.notYetValid) {
                evidence.push_back("The signing certificate is not yet valid.");
            }
            findings.push_back(makeFinding(
                "EB-SIG-003", "Signature",
                "The file contains a signature that did not verify", Severity::High,
                Confidence::High,
                "A certificate table or signer was found, but Windows could not validate the "
                "signature or its trust chain.",
                "An invalid signature can mean the file was modified after signing, the "
                "certificate is untrusted or expired, or the signature structure is damaged. "
                "Self-signed and internal certificates also fail public trust validation.",
                std::move(evidence),
                {"The publisher uses a private or self-signed certificate.",
                 "The certificate expired without a trusted timestamp.",
                 "The local trust store is missing the issuing root.",
                 "The file was altered after signing."},
                {"Verify the file hash against the publisher's official source.",
                 "Inspect the signer certificate and chain with an independent tool.",
                 "Do not execute the file until the signature discrepancy is explained.",
                 "Check revocation with the issuing certificate authority."}));
        } else if (signature.status == SignatureStatus::Unknown) {
            findings.push_back(makeFinding(
                "EB-SIG-004", "Signature", "The signature status is indeterminate",
                Severity::Low, Confidence::Medium,
                "A signature-related result was returned, but ExplainBin could not classify it "
                "as valid, invalid or unsigned.",
                "Indeterminate results should be resolved before relying on publisher identity.",
                {"Status = " + std::string(toString(signature.status)),
                 "Detail = " + signature.trustMessage},
                {"A trust provider returned an uncommon error.",
                 "The certificate chain uses an unsupported or unavailable algorithm.",
                 "The file uses catalog signing rather than an embedded signature."},
                {"Verify with an independent Authenticode tool.",
                 "Check whether the file is expected to be catalog-signed.",
                 "Use the file hash and source as additional provenance evidence."}));
        }
    }

    FindingsEngine::sortBySeverity(findings);
    return findings;
}

void FindingsEngine::sortBySeverity(std::vector<Finding>& findings) {
    std::stable_sort(findings.begin(), findings.end(),
                     [](const Finding& left, const Finding& right) {
                         if (left.severity != right.severity) {
                             return severityRank(left.severity) > severityRank(right.severity);
                         }
                         return left.id < right.id;
                     });
}

} // namespace explainbin
