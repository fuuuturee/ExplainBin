#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <string_view>

namespace explainbin::pe {

constexpr std::uint16_t kDosMagic = 0x5A4D;   // "MZ"
constexpr std::uint32_t kNtSignature = 0x00004550; // "PE\0\0"
constexpr std::uint16_t kOptionalHeader32 = 0x010B;
constexpr std::uint16_t kOptionalHeader64 = 0x020B;

enum class DirectoryIndex : int {
    Export = 0,
    Import = 1,
    Resource = 2,
    Exception = 3,
    Certificate = 4,
    BaseRelocation = 5,
    Debug = 6,
    Architecture = 7,
    GlobalPointer = 8,
    Tls = 9,
    LoadConfig = 10,
    BoundImport = 11,
    ImportAddressTable = 12,
    DelayImport = 13,
    ClrRuntime = 14,
    Reserved = 15
};

constexpr int kMaxSections = 96;
constexpr int kMaxImportDescriptors = 1024;
constexpr int kMaxThunksPerLibrary = 8192;
constexpr int kMaxExports = 16384;
constexpr int kMaxResources = 4096;
constexpr int kMaxDebugEntries = 64;
constexpr int kMaxTlsCallbacks = 128;

std::string_view directoryName(int index);
std::string_view machineName(std::uint16_t machine);
std::string_view subsystemName(std::uint16_t subsystem);
std::string_view debugTypeName(std::uint32_t type);
std::string_view resourceTypeName(std::uint32_t type);

bool isPackerSectionName(std::string_view name);
bool isCommonSectionName(std::string_view name);
// Padding sections named Pad, Pad1, Pad2, ... appear in Hyper-V and firmware images.
bool isPaddingSectionName(std::string_view name);

std::string formatGuid(const std::array<std::uint8_t, 16>& guid);

} // namespace explainbin::pe
