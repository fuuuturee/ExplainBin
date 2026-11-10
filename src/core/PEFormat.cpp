#include "explainbin/core/PEFormat.hpp"

#include "explainbin/core/Util.hpp"

#include <algorithm>
#include <array>
#include <cstdio>

namespace explainbin::pe {

std::string_view directoryName(int index) {
    static constexpr std::array<std::string_view, 16> kNames{
        "Export", "Import", "Resource", "Exception", "Certificate",
        "Base Relocation", "Debug", "Architecture", "Global Pointer", "TLS",
        "Load Config", "Bound Import", "Import Address Table", "Delay Import",
        "CLR Runtime", "Reserved"};
    if (index < 0 || index >= static_cast<int>(kNames.size())) {
        return "Unknown";
    }
    return kNames[static_cast<std::size_t>(index)];
}

std::string_view machineName(std::uint16_t machine) {
    switch (machine) {
    case 0x014C: return "x86";
    case 0x8664: return "x64";
    case 0x01C0: return "ARM";
    case 0x01C4: return "ARMv7";
    case 0xAA64: return "ARM64";
    case 0x0200: return "Itanium";
    case 0x5032: return "RISC-V 32";
    case 0x5064: return "RISC-V 64";
    case 0x5128: return "RISC-V 128";
    default: return "Unknown";
    }
}

std::string_view subsystemName(std::uint16_t subsystem) {
    switch (subsystem) {
    case 0: return "Unknown";
    case 1: return "Native";
    case 2: return "Windows GUI";
    case 3: return "Windows Console";
    case 5: return "OS/2 Console";
    case 7: return "POSIX Console";
    case 9: return "Windows CE";
    case 10: return "EFI Application";
    case 11: return "EFI Boot Service Driver";
    case 12: return "EFI Runtime Driver";
    case 13: return "EFI ROM";
    case 14: return "Xbox";
    case 16: return "Windows Boot Application";
    default: return "Other";
    }
}

std::string_view debugTypeName(std::uint32_t type) {
    switch (type) {
    case 0: return "Unknown";
    case 1: return "COFF";
    case 2: return "CodeView";
    case 3: return "FPO";
    case 4: return "Misc";
    case 5: return "Exception";
    case 6: return "Fixup";
    case 9: return "Borland";
    case 10: return "Reserved";
    case 11: return "VC Feature";
    case 12: return "POGO";
    case 13: return "ILTCG";
    case 14: return "MPX";
    case 16: return "Repro";
    case 17: return "Embedded Portable PDB";
    case 19: return "PDB Checksum";
    default: return "Other";
    }
}

std::string_view resourceTypeName(std::uint32_t type) {
    switch (type) {
    case 1: return "Cursor";
    case 2: return "Bitmap";
    case 3: return "Icon";
    case 4: return "Menu";
    case 5: return "Dialog";
    case 6: return "String Table";
    case 7: return "Font Directory";
    case 8: return "Font";
    case 9: return "Accelerator";
    case 10: return "RC Data";
    case 11: return "Message Table";
    case 12: return "Group Cursor";
    case 14: return "Group Icon";
    case 16: return "Version Info";
    case 17: return "DLG Include";
    case 19: return "Plug and Play";
    case 20: return "VXD";
    case 21: return "Animated Cursor";
    case 22: return "Animated Icon";
    case 23: return "HTML";
    case 24: return "Manifest";
    default: return {};
    }
}

bool isPackerSectionName(std::string_view name) {
    static constexpr std::array<std::string_view, 26> kNames{
        "upx0", "upx1", "upx2", "upx!", ".aspack", ".adata", ".nsp0", ".nsp1",
        ".nsp2", ".petite", ".packed", ".mpress1", ".mpress2", ".themida",
        ".vmp0", ".vmp1", ".enigma1", ".enigma2", ".boom", ".ccg", ".perplex",
        ".rlpack", ".svkp", ".y0da", ".pklstb", ".maskpe"};
    const auto lower = util::toLowerAscii(std::string(name));
    for (const auto candidate : kNames) {
        if (lower == candidate) {
            return true;
        }
    }
    return false;
}

bool isPaddingSectionName(std::string_view name) {
    const auto lower = util::toLowerAscii(std::string(name));
    if (lower == "pad") {
        return true;
    }
    if (lower.size() <= 3 || lower.compare(0, 3, "pad") != 0) {
        return false;
    }
    return std::all_of(lower.begin() + 3, lower.end(),
                       [](char c) { return c >= '0' && c <= '9'; });
}

bool isCommonSectionName(std::string_view name) {
    static constexpr std::array<std::string_view, 25> kNames{
        ".text", ".data", ".rdata", ".bss", ".idata", ".edata", ".pdata",
        ".xdata", ".tls", ".rsrc", ".reloc", ".debug", ".didata", ".didat",
        ".sdata", ".gfids", ".giats", ".00cfg", ".crt", ".vtordisp", ".rodata",
        ".detourc", ".detourd", ".mrdata", ".textbss"};
    // Known section names used by Microsoft system binaries: "fothk" (function-override
    // hooking support), "PAGE" and "RT" (ntdll), and "SCPCFG*" (control-flow guard
    // configuration). They are legitimate system components, not anomalies.
    static constexpr std::array<std::string_view, 3> kAdditionalNames{"fothk", "page", "rt"};
    // Section names are case-sensitive by ABI, but toolchains emit .TEXT/.DATA and
    // per-object suffixes such as .text$mn. Treat those as ordinary, not unusual.
    const auto lower = util::toLowerAscii(std::string(name));
    if (isPaddingSectionName(name)) {
        return true;
    }
    for (const auto candidate : kNames) {
        if (lower == candidate) {
            return true;
        }
    }
    for (const auto candidate : kAdditionalNames) {
        if (lower == candidate) {
            return true;
        }
    }
    static constexpr std::array<std::string_view, 9> kPrefixes{
        ".text", ".data", ".rdata", ".pdata", ".rsrc", ".reloc", ".debug", ".sdata",
        "scpcfg"};
    for (const auto prefix : kPrefixes) {
        if (lower.size() > prefix.size() && lower.compare(0, prefix.size(), prefix) == 0) {
            return true;
        }
    }
    return false;
}

std::string formatGuid(const std::array<std::uint8_t, 16>& guid) {
    std::array<char, 40> buffer{};
    std::snprintf(buffer.data(), buffer.size(),
                  "%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X",
                  static_cast<unsigned>(guid[0] | (guid[1] << 8) | (guid[2] << 16) |
                                        (static_cast<unsigned>(guid[3]) << 24)),
                  static_cast<unsigned>(guid[4] | (guid[5] << 8)),
                  static_cast<unsigned>(guid[6] | (guid[7] << 8)),
                  guid[8], guid[9], guid[10], guid[11], guid[12], guid[13],
                  guid[14], guid[15]);
    return buffer.data();
}

} // namespace explainbin::pe
