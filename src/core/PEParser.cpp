#include "explainbin/core/PEParser.hpp"

#include "explainbin/core/PEFormat.hpp"
#include "explainbin/core/Util.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <functional>
#include <limits>
#include <optional>
#include <set>
#include <string>
#include <vector>

namespace explainbin {
namespace {

class Reader {
public:
    explicit Reader(std::span<const std::uint8_t> data) : data_(data) {}

    [[nodiscard]] std::uint64_t size() const noexcept { return data_.size(); }

    [[nodiscard]] bool range(std::uint64_t offset, std::uint64_t length) const noexcept {
        return offset <= data_.size() && length <= data_.size() - offset;
    }

    bool u8(std::uint64_t offset, std::uint8_t& value) const {
        if (!range(offset, 1)) {
            return false;
        }
        value = data_[static_cast<std::size_t>(offset)];
        return true;
    }

    bool u16(std::uint64_t offset, std::uint16_t& value) const {
        if (!range(offset, 2)) {
            return false;
        }
        value = static_cast<std::uint16_t>(data_[offset] | (data_[offset + 1] << 8));
        return true;
    }

    bool u32(std::uint64_t offset, std::uint32_t& value) const {
        if (!range(offset, 4)) {
            return false;
        }
        value = static_cast<std::uint32_t>(data_[offset]) |
                (static_cast<std::uint32_t>(data_[offset + 1]) << 8) |
                (static_cast<std::uint32_t>(data_[offset + 2]) << 16) |
                (static_cast<std::uint32_t>(data_[offset + 3]) << 24);
        return true;
    }

    bool u64(std::uint64_t offset, std::uint64_t& value) const {
        std::uint32_t low = 0;
        std::uint32_t high = 0;
        if (!u32(offset, low) || !u32(offset + 4, high)) {
            return false;
        }
        value = static_cast<std::uint64_t>(low) | (static_cast<std::uint64_t>(high) << 32);
        return true;
    }

    bool bytes(std::uint64_t offset, std::size_t length,
               std::span<const std::uint8_t>& output) const {
        if (!range(offset, length)) {
            return false;
        }
        output = data_.subspan(static_cast<std::size_t>(offset), length);
        return true;
    }

    bool cString(std::uint64_t offset, std::size_t maxLength, std::string& output) const {
        output.clear();
        if (offset >= data_.size()) {
            return false;
        }
        const std::uint64_t end = std::min<std::uint64_t>(data_.size(), offset + maxLength);
        for (std::uint64_t index = offset; index < end; ++index) {
            const auto value = data_[static_cast<std::size_t>(index)];
            if (value == 0) {
                return true;
            }
            output.push_back(static_cast<char>(value));
        }
        return true;
    }

private:
    std::span<const std::uint8_t> data_;
};

std::string versionString(std::uint8_t major, std::uint8_t minor) {
    return std::to_string(static_cast<unsigned>(major)) + "." +
           std::to_string(static_cast<unsigned>(minor));
}

std::string resolveResourceType(const std::string& name) {
    if (name.size() < 2 || name.front() != '#') {
        return name;
    }
    try {
        const auto id = static_cast<std::uint32_t>(std::stoul(name.substr(1)));
        const auto mapped = pe::resourceTypeName(id);
        if (!mapped.empty()) {
            return std::string(mapped) + " (" + name + ")";
        }
    } catch (const std::exception&) {
        // Keep the original untrusted resource name.
    }
    return name;
}

std::string utf16ToUtf8(std::span<const std::uint8_t> bytes) {
    std::string output;
    output.reserve(bytes.size());
    for (std::size_t index = 0; index + 1 < bytes.size(); index += 2) {
        std::uint32_t codeUnit = static_cast<std::uint32_t>(bytes[index]) |
                                 (static_cast<std::uint32_t>(bytes[index + 1]) << 8);
        std::uint32_t codePoint = codeUnit;

        if (codeUnit >= 0xD800 && codeUnit <= 0xDBFF && index + 3 < bytes.size()) {
            const std::uint32_t low = static_cast<std::uint32_t>(bytes[index + 2]) |
                                      (static_cast<std::uint32_t>(bytes[index + 3]) << 8);
            if (low >= 0xDC00 && low <= 0xDFFF) {
                codePoint = 0x10000 + ((codeUnit - 0xD800) << 10) + (low - 0xDC00);
                index += 2;
            }
        }

        if (codePoint == 0) {
            break;
        }
        if (codePoint < 0x20 || codePoint == 0x7F) {
            output.push_back('?');
        } else if (codePoint < 0x80) {
            output.push_back(static_cast<char>(codePoint));
        } else if (codePoint < 0x800) {
            output.push_back(static_cast<char>(0xC0 | (codePoint >> 6)));
            output.push_back(static_cast<char>(0x80 | (codePoint & 0x3F)));
        } else if (codePoint < 0x10000) {
            output.push_back(static_cast<char>(0xE0 | (codePoint >> 12)));
            output.push_back(static_cast<char>(0x80 | ((codePoint >> 6) & 0x3F)));
            output.push_back(static_cast<char>(0x80 | (codePoint & 0x3F)));
        } else {
            output.push_back(static_cast<char>(0xF0 | (codePoint >> 18)));
            output.push_back(static_cast<char>(0x80 | ((codePoint >> 12) & 0x3F)));
            output.push_back(static_cast<char>(0x80 | ((codePoint >> 6) & 0x3F)));
            output.push_back(static_cast<char>(0x80 | (codePoint & 0x3F)));
        }
        if (output.size() > 256) {
            output += "...";
            break;
        }
    }
    return output;
}

std::uint32_t computePeChecksum(std::span<const std::uint8_t> data,
                                std::uint64_t checksumOffset) {
    std::uint64_t sum = 0;
    std::uint64_t index = 0;
    while (index + 1 < data.size()) {
        if (index == checksumOffset || index == checksumOffset + 2) {
            index += 2;
            continue;
        }
        const auto word = static_cast<std::uint16_t>(
            data[index] | (static_cast<std::uint16_t>(data[index + 1]) << 8));
        sum += word;
        sum = (sum & 0xFFFFULL) + (sum >> 16);
        index += 2;
    }
    if ((data.size() & 1ULL) != 0) {
        sum += data[data.size() - 1];
        sum = (sum & 0xFFFFULL) + (sum >> 16);
    }
    sum = (sum & 0xFFFFULL) + (sum >> 16);
    return static_cast<std::uint32_t>(sum + data.size());
}

class ParserImpl {
public:
    ParserImpl(std::span<const std::uint8_t> data, PeInfo& output, PeParseOutcome& outcome)
        : reader_(data), data_(data), output_(output), outcome_(outcome) {}

    void run() {
        output_ = PeInfo{};
        if (!parseHeaders()) {
            return;
        }
        parseSections();
        parseOptionalDirectories();
        parseImportDirectory();
        parseDelayImportDirectory();
        parseExportDirectory();
        parseResourceDirectory();
        parseDebugDirectory();
        parseTlsDirectory();
        parseCertificateTable();
        detectOverlay();
        detectRichHeader();

        output_.partial = partial_;
        output_.parsed = true;
        outcome_.parsed = true;
    }

private:
    void diagnostic(std::string code, std::string message, bool fatal = false) {
        if (outcome_.diagnostics.size() < 256) {
            outcome_.diagnostics.push_back(
                Diagnostic{std::move(code), std::move(message), fatal});
        }
        if (!fatal) {
            partial_ = true;
        }
    }

    [[nodiscard]] bool mapRva(std::uint32_t rva, std::uint64_t length,
                              std::uint64_t& fileOffset) const {
        if (rva == 0) {
            return false;
        }
        const auto rva64 = static_cast<std::uint64_t>(rva);
        if (output_.sizeOfHeaders != 0 && rva64 < output_.sizeOfHeaders &&
            reader_.range(rva64, length)) {
            fileOffset = rva64;
            return true;
        }
        for (const auto& section : output_.sections) {
            if (!section.rawRangeValid) {
                continue;
            }
            const auto start = static_cast<std::uint64_t>(section.virtualAddress);
            const auto span = static_cast<std::uint64_t>(
                std::max(section.virtualSize, section.rawSize));
            if (rva64 < start || rva64 >= start + span) {
                continue;
            }
            const auto delta = rva64 - start;
            if (delta + length > section.rawSize) {
                continue;
            }
            const auto offset = static_cast<std::uint64_t>(section.rawOffset) + delta;
            if (reader_.range(offset, length)) {
                fileOffset = offset;
                return true;
            }
        }
        return false;
    }

    bool parseHeaders() {
        std::uint16_t dosMagic = 0;
        if (!reader_.u16(0, dosMagic) || dosMagic != pe::kDosMagic) {
            diagnostic("EB-PE-DOS", "The file does not begin with the DOS 'MZ' signature.", true);
            return false;
        }

        std::uint32_t peOffset = 0;
        if (!reader_.u32(0x3C, peOffset)) {
            diagnostic("EB-PE-TRUNCATED", "The DOS header is truncated.", true);
            return false;
        }
        if (peOffset < 0x40) {
            diagnostic("EB-PE-LFANEW", "e_lfanew does not point to a valid NT header.", true);
            return false;
        }
        if (!reader_.range(peOffset, 24)) {
            diagnostic("EB-PE-TRUNCATED", "The NT header is truncated.", true);
            return false;
        }

        std::uint32_t signature = 0;
        if (!reader_.u32(peOffset, signature) || signature != pe::kNtSignature) {
            diagnostic("EB-PE-SIGNATURE", "The PE signature is missing or invalid.", true);
            return false;
        }
        peOffset_ = peOffset;

        const auto fileHeaderOffset = static_cast<std::uint64_t>(peOffset) + 4;
        std::uint16_t sizeOfOptionalHeader = 0;
        if (!reader_.u16(fileHeaderOffset + 16, sizeOfOptionalHeader)) {
            diagnostic("EB-PE-TRUNCATED", "The COFF file header is truncated.", true);
            return false;
        }

        optionalOffset_ = fileHeaderOffset + 20;
        if (sizeOfOptionalHeader < 2 || !reader_.range(optionalOffset_, sizeOfOptionalHeader)) {
            diagnostic("EB-PE-OPTIONAL", "The optional header is truncated or missing.", true);
            return false;
        }

        std::uint16_t magic = 0;
        if (!reader_.u16(optionalOffset_, magic)) {
            diagnostic("EB-PE-OPTIONAL", "The optional header magic could not be read.", true);
            return false;
        }
        if (magic != pe::kOptionalHeader32 && magic != pe::kOptionalHeader64) {
            diagnostic("EB-PE-MAGIC", "The optional header magic is not PE32 or PE32+.", true);
            return false;
        }
        output_.is64Bit = magic == pe::kOptionalHeader64;
        const std::uint16_t minimumOptionalSize = output_.is64Bit ? 112 : 96;
        if (sizeOfOptionalHeader < minimumOptionalSize) {
            diagnostic("EB-PE-OPTIONAL", "The optional header is smaller than required.", true);
            return false;
        }

        reader_.u16(fileHeaderOffset, output_.machine);
        std::uint16_t sectionCount = 0;
        reader_.u16(fileHeaderOffset + 2, sectionCount);
        output_.numberOfSections = sectionCount;
        reader_.u32(fileHeaderOffset + 4, output_.timestamp);
        reader_.u16(fileHeaderOffset + 18, output_.characteristics);

        std::uint8_t linkerMajor = 0;
        std::uint8_t linkerMinor = 0;
        std::uint8_t osMajor = 0;
        std::uint8_t osMinor = 0;
        std::uint8_t subsystemMajor = 0;
        std::uint8_t subsystemMinor = 0;
        reader_.u8(optionalOffset_ + 2, linkerMajor);
        reader_.u8(optionalOffset_ + 3, linkerMinor);
        reader_.u8(optionalOffset_ + 40, osMajor);
        reader_.u8(optionalOffset_ + 41, osMinor);
        reader_.u8(optionalOffset_ + 48, subsystemMajor);
        reader_.u8(optionalOffset_ + 49, subsystemMinor);
        output_.linkerVersion = versionString(linkerMajor, linkerMinor);
        output_.osVersion = versionString(osMajor, osMinor);
        output_.subsystemVersion = versionString(subsystemMajor, subsystemMinor);

        reader_.u32(optionalOffset_ + 16, output_.entryPointRva);
        if (output_.is64Bit) {
            reader_.u64(optionalOffset_ + 24, output_.imageBase);
        } else {
            std::uint32_t imageBase32 = 0;
            reader_.u32(optionalOffset_ + 28, imageBase32);
            output_.imageBase = imageBase32;
        }
        reader_.u32(optionalOffset_ + 32, output_.sectionAlignment);
        reader_.u32(optionalOffset_ + 36, output_.fileAlignment);
        reader_.u32(optionalOffset_ + 56, output_.sizeOfImage);
        reader_.u32(optionalOffset_ + 60, output_.sizeOfHeaders);
        reader_.u32(optionalOffset_ + 64, output_.checksum);
        reader_.u16(optionalOffset_ + 68, output_.subsystem);
        reader_.u16(optionalOffset_ + 70, output_.dllCharacteristics);
        reader_.u32(optionalOffset_ + (output_.is64Bit ? 108 : 92),
                    output_.numberOfRvaAndSizes);

        output_.timestampUtc = util::formatUnixTimeUtc(output_.timestamp);
        output_.machineName = pe::machineName(output_.machine);
        output_.subsystemName = pe::subsystemName(output_.subsystem);
        output_.isDll = (output_.characteristics & 0x2000) != 0;
        output_.format = std::string(output_.is64Bit ? "PE32+" : "PE32") + " (" +
                         std::string(output_.machineName) + ")";

        output_.checksumPresent = output_.checksum != 0;
        output_.computedChecksum =
            computePeChecksum(data_, optionalOffset_ + 64);
        output_.checksumValid = output_.checksumPresent &&
                                output_.computedChecksum == output_.checksum;

        if (output_.numberOfSections == 0) {
            diagnostic("EB-PE-NO-SECTIONS", "The PE file declares zero sections.");
        }

        const auto directoriesOffset = optionalOffset_ + (output_.is64Bit ? 112 : 96);
        const auto availableDirectories =
            static_cast<std::uint32_t>((sizeOfOptionalHeader - (output_.is64Bit ? 112 : 96)) / 8);
        if (output_.numberOfRvaAndSizes > availableDirectories) {
            diagnostic("EB-PE-DIR-COUNT",
                        "The declared data directory count exceeds the optional header size.");
        }
        if (output_.numberOfRvaAndSizes > 16) {
            diagnostic("EB-PE-DIR-RESERVED",
                        "The data directory count exceeds the 16 defined entries.");
        }

        const std::uint32_t directoryCount =
            std::min<std::uint32_t>({output_.numberOfRvaAndSizes, availableDirectories, 16});
        for (std::uint32_t index = 0; index < directoryCount; ++index) {
            DataDirectoryInfo directory;
            directory.index = static_cast<int>(index);
            directory.name = std::string(pe::directoryName(directory.index));
            reader_.u32(directoriesOffset + index * 8ULL, directory.rva);
            reader_.u32(directoriesOffset + index * 8ULL + 4, directory.size);
            directory.present = directory.rva != 0 || directory.size != 0;
            output_.directories.push_back(directory);
        }

        output_.hasClrDirectory =
            directoryPresent(static_cast<int>(pe::DirectoryIndex::ClrRuntime));
        output_.hasRelocations =
            directoryPresent(static_cast<int>(pe::DirectoryIndex::BaseRelocation));
        return true;
    }

    void parseSections() {
        std::uint16_t sizeOfOptionalHeader = 0;
        reader_.u16(peOffset_ + 4 + 16, sizeOfOptionalHeader);
        const auto tableOffset = optionalOffset_ + sizeOfOptionalHeader;
        if (!reader_.range(tableOffset, 0)) {
            diagnostic("EB-PE-SECTION-TABLE", "The section table starts outside the file.");
            return;
        }

        const auto reported = output_.numberOfSections;
        const auto available = (reader_.size() - tableOffset) / 40;
        auto toRead = std::min<std::uint64_t>(reported, available);
        toRead = std::min<std::uint64_t>(toRead, pe::kMaxSections);
        if (toRead < reported) {
            diagnostic("EB-PE-SECTION-COUNT",
                        "The declared section count does not fit in the file or exceeds the "
                        "Windows loader limit of 96; only " + std::to_string(toRead) +
                            " sections were parsed.");
        }
        if (reported == 0) {
            return;
        }

        for (std::uint64_t index = 0; index < toRead; ++index) {
            const auto base = tableOffset + index * 40;
            SectionInfo section;
            std::array<char, 8> rawName{};
            for (std::size_t character = 0; character < rawName.size(); ++character) {
                std::uint8_t value = 0;
                reader_.u8(base + character, value);
                rawName[character] = static_cast<char>(value);
            }
            section.name = util::sanitizeAscii(
                std::string_view(rawName.data(), rawName.size()), 8);
            reader_.u32(base + 8, section.virtualSize);
            reader_.u32(base + 12, section.virtualAddress);
            reader_.u32(base + 16, section.rawSize);
            reader_.u32(base + 20, section.rawOffset);
            reader_.u32(base + 36, section.characteristics);

            constexpr std::uint32_t kRead = 0x40000000;
            constexpr std::uint32_t kWrite = 0x80000000;
            constexpr std::uint32_t kExecute = 0x20000000;
            constexpr std::uint32_t kCode = 0x00000020;
            constexpr std::uint32_t kInitialized = 0x00000040;
            constexpr std::uint32_t kUninitialized = 0x00000080;
            section.readable = (section.characteristics & kRead) != 0;
            section.writable = (section.characteristics & kWrite) != 0;
            section.executable = (section.characteristics & kExecute) != 0;
            section.code = (section.characteristics & kCode) != 0;
            section.initializedData = (section.characteristics & kInitialized) != 0;
            section.uninitializedData = (section.characteristics & kUninitialized) != 0;

            if (section.rawSize != 0) {
                const auto start = static_cast<std::uint64_t>(section.rawOffset);
                section.rawRangeValid = section.rawOffset != 0 && reader_.range(start, section.rawSize);
                if (!section.rawRangeValid) {
                    diagnostic("EB-PE-SECTION-RANGE",
                                "Section '" + section.name +
                                    "' points outside the file; its contents were not read.");
                }
            }
            section.entropy = -1.0;
            output_.sections.push_back(std::move(section));
        }
    }

    void parseOptionalDirectories() {
        for (auto& directory : output_.directories) {
            if (!directory.present) {
                directory.valid = true;
                continue;
            }
            if (directory.index == static_cast<int>(pe::DirectoryIndex::Certificate)) {
                const auto offset = static_cast<std::uint64_t>(directory.rva);
                if (directory.rva == 0 || directory.size == 0 ||
                    !reader_.range(offset, directory.size)) {
                    directory.valid = false;
                    directory.note = "Certificate table range is outside the file.";
                    diagnostic("EB-PE-CERT-RANGE",
                                "The certificate table lies outside the file or has an invalid size.");
                }
                continue;
            }
            if (directory.rva == 0) {
                directory.valid = false;
                directory.note = "The directory has a size but no RVA.";
                diagnostic("EB-PE-DIR-RVA",
                            "Data directory '" + directory.name + "' has no valid RVA.");
                continue;
            }
            std::uint64_t offset = 0;
            if (!mapRva(directory.rva, 1, offset)) {
                directory.valid = false;
                directory.note = "The directory RVA is not backed by any section.";
                diagnostic("EB-PE-DIR-MAP",
                            "Data directory '" + directory.name +
                                "' points to an unmapped RVA.");
            }
        }
    }

    [[nodiscard]] bool directoryPresent(int index) const {
        for (const auto& directory : output_.directories) {
            if (directory.index == index && directory.present) {
                return true;
            }
        }
        return false;
    }

    [[nodiscard]] const DataDirectoryInfo* directory(int index) const {
        for (const auto& entry : output_.directories) {
            if (entry.index == index) {
                return &entry;
            }
        }
        return nullptr;
    }

    void parseImportDirectory() {
        const auto* importDirectory = directory(static_cast<int>(pe::DirectoryIndex::Import));
        if (importDirectory == nullptr || !importDirectory->present || !importDirectory->valid) {
            return;
        }
        parseImportDescriptors(importDirectory->rva, false);
    }

    void parseDelayImportDirectory() {
        const auto* delayDirectory = directory(static_cast<int>(pe::DirectoryIndex::DelayImport));
        if (delayDirectory == nullptr || !delayDirectory->present || !delayDirectory->valid) {
            return;
        }
        bool emitted = false;
        for (std::uint32_t index = 0; index < 256; ++index) {
            std::uint64_t descriptorOffset = 0;
            if (!mapRva(delayDirectory->rva + index * 32U, 32, descriptorOffset)) {
                if (!emitted) {
                    diagnostic("EB-PE-DELAY-IMPORT",
                                "The delay-load import descriptor table could not be read.");
                    emitted = true;
                }
                break;
            }
            std::uint32_t attributes = 0;
            std::uint32_t nameValue = 0;
            std::uint32_t nameTable = 0;
            reader_.u32(descriptorOffset, attributes);
            reader_.u32(descriptorOffset + 4, nameValue);
            reader_.u32(descriptorOffset + 16, nameTable);
            if (attributes == 0 && nameValue == 0 && nameTable == 0) {
                break;
            }

            const auto toRva = [&](std::uint32_t value) -> std::optional<std::uint32_t> {
                if ((attributes & 1U) != 0) {
                    return value;
                }
                if (value >= output_.imageBase &&
                    static_cast<std::uint64_t>(value) - output_.imageBase <=
                        std::numeric_limits<std::uint32_t>::max()) {
                    return static_cast<std::uint32_t>(
                        static_cast<std::uint64_t>(value) - output_.imageBase);
                }
                return std::nullopt;
            };

            const auto nameRva = toRva(nameValue);
            const auto tableRva = toRva(nameTable);
            if (!nameRva || !tableRva) {
                if (!emitted) {
                    diagnostic("EB-PE-DELAY-IMPORT",
                                "A delay-load import descriptor contains invalid virtual addresses.");
                    emitted = true;
                }
                continue;
            }

            ImportLibrary library;
            library.delayLoad = true;
            std::string rawName;
            std::uint64_t nameOffset = 0;
            if (mapRva(*nameRva, 1, nameOffset) && reader_.cString(nameOffset, 260, rawName)) {
                library.name = util::sanitizeAscii(rawName, 260);
            }
            if (library.name.empty()) {
                library.name = "<unnamed delay-load library>";
            }
            readThunks(*tableRva, library);
            output_.imports.push_back(std::move(library));
        }
    }

    void parseImportDescriptors(std::uint32_t directoryRva, bool /*delay*/) {
        bool emitted = false;
        for (std::uint32_t index = 0; index < pe::kMaxImportDescriptors; ++index) {
            std::uint64_t descriptorOffset = 0;
            if (!mapRva(directoryRva + index * 20U, 20, descriptorOffset)) {
                if (!emitted) {
                    diagnostic("EB-PE-IMPORT-TABLE",
                                "The import descriptor table is truncated or unmapped.");
                    emitted = true;
                }
                break;
            }
            std::uint32_t originalFirstThunk = 0;
            std::uint32_t timestamp = 0;
            std::uint32_t forwarderChain = 0;
            std::uint32_t nameRva = 0;
            std::uint32_t firstThunk = 0;
            reader_.u32(descriptorOffset, originalFirstThunk);
            reader_.u32(descriptorOffset + 4, timestamp);
            reader_.u32(descriptorOffset + 8, forwarderChain);
            reader_.u32(descriptorOffset + 12, nameRva);
            reader_.u32(descriptorOffset + 16, firstThunk);
            (void)timestamp;
            (void)forwarderChain;

            if (originalFirstThunk == 0 && nameRva == 0 && firstThunk == 0) {
                break;
            }

            ImportLibrary library;
            library.delayLoad = false;
            std::string rawName;
            std::uint64_t nameOffset = 0;
            if (nameRva != 0 && mapRva(nameRva, 1, nameOffset) &&
                reader_.cString(nameOffset, 260, rawName)) {
                library.name = util::sanitizeAscii(rawName, 260);
            }
            if (library.name.empty()) {
                library.name = "<unnamed import library>";
                if (!emitted) {
                    diagnostic("EB-PE-IMPORT-NAME",
                                "An import descriptor has an unreadable library name.");
                    emitted = true;
                }
            }

            const auto thunkRva = originalFirstThunk != 0 ? originalFirstThunk : firstThunk;
            if (thunkRva != 0) {
                readThunks(thunkRva, library);
            } else if (!emitted) {
                diagnostic("EB-PE-IMPORT-THUNK",
                            "Import library '" + library.name + "' has no import name table.");
                emitted = true;
            }
            output_.imports.push_back(std::move(library));
        }
    }

    void readThunks(std::uint32_t thunkRva, ImportLibrary& library) {
        const std::uint32_t thunkSize = output_.is64Bit ? 8 : 4;
        bool emitted = false;
        for (std::uint32_t index = 0; index < pe::kMaxThunksPerLibrary; ++index) {
            std::uint64_t thunkOffset = 0;
            if (!mapRva(thunkRva + index * thunkSize, thunkSize, thunkOffset)) {
                if (!emitted && index == 0) {
                    diagnostic("EB-PE-IMPORT-THUNK",
                                "The import name table for '" + library.name +
                                    "' could not be read.");
                    emitted = true;
                }
                break;
            }

            std::uint64_t value = 0;
            if (output_.is64Bit) {
                reader_.u64(thunkOffset, value);
            } else {
                std::uint32_t value32 = 0;
                reader_.u32(thunkOffset, value32);
                value = value32;
            }
            if (value == 0) {
                break;
            }

            ImportFunction function;
            const std::uint64_t ordinalFlag =
                output_.is64Bit ? 0x8000000000000000ULL : 0x80000000ULL;
            if ((value & ordinalFlag) != 0) {
                function.byOrdinal = true;
                function.ordinal = static_cast<std::uint16_t>(value & 0xFFFFULL);
                function.name = "#" + std::to_string(function.ordinal);
            } else {
                if (value > std::numeric_limits<std::uint32_t>::max()) {
                    if (!emitted) {
                        diagnostic("EB-PE-IMPORT-THUNK",
                                    "An import thunk contains a truncated 64-bit RVA.");
                        emitted = true;
                    }
                    break;
                }
                const auto hintNameRva = static_cast<std::uint32_t>(value);
                std::uint64_t hintOffset = 0;
                if (!mapRva(hintNameRva, 2, hintOffset)) {
                    if (!emitted) {
                        diagnostic("EB-PE-IMPORT-NAME",
                                    "An import name RVA for '" + library.name +
                                        "' is not mapped; the file may use a bound import table.");
                        emitted = true;
                    }
                    break;
                }
                reader_.u16(hintOffset, function.hint);
                std::string functionName;
                if (reader_.cString(hintOffset + 2, 512, functionName)) {
                    function.name = util::sanitizeAscii(functionName, 512);
                }
                if (function.name.empty()) {
                    function.name = "<unreadable import name>";
                }
            }
            library.functions.push_back(std::move(function));
        }
        if (library.functions.size() == pe::kMaxThunksPerLibrary) {
            diagnostic("EB-PE-IMPORT-LIMIT",
                        "The import table for '" + library.name + "' exceeded the parser limit.");
        }
    }

    void parseExportDirectory() {
        const auto* exportDirectory = directory(static_cast<int>(pe::DirectoryIndex::Export));
        if (exportDirectory == nullptr || !exportDirectory->present || !exportDirectory->valid) {
            return;
        }
        std::uint64_t exportOffset = 0;
        if (!mapRva(exportDirectory->rva, 40, exportOffset)) {
            diagnostic("EB-PE-EXPORT", "The export directory could not be read.");
            return;
        }

        std::uint32_t nameRva = 0;
        std::uint32_t functionCount = 0;
        std::uint32_t nameCount = 0;
        std::uint32_t functionsRva = 0;
        std::uint32_t namesRva = 0;
        std::uint32_t ordinalsRva = 0;
        reader_.u32(exportOffset + 12, nameRva);
        reader_.u32(exportOffset + 16, output_.exportOrdinalBase);
        reader_.u32(exportOffset + 20, functionCount);
        reader_.u32(exportOffset + 24, nameCount);
        reader_.u32(exportOffset + 28, functionsRva);
        reader_.u32(exportOffset + 32, namesRva);
        reader_.u32(exportOffset + 36, ordinalsRva);

        std::uint64_t nameOffset = 0;
        std::string dllName;
        if (nameRva != 0 && mapRva(nameRva, 1, nameOffset) &&
            reader_.cString(nameOffset, 260, dllName)) {
            output_.exportDllName = util::sanitizeAscii(dllName, 260);
        }

        const auto count = std::min<std::uint32_t>(nameCount, pe::kMaxExports);
        if (nameCount > count) {
            diagnostic("EB-PE-EXPORT-LIMIT", "The export name table exceeded the parser limit.");
        }
        for (std::uint32_t index = 0; index < count; ++index) {
            std::uint64_t nameEntry = 0;
            std::uint64_t ordinalEntry = 0;
            if (!mapRva(namesRva + index * 4U, 4, nameEntry) ||
                !mapRva(ordinalsRva + index * 2U, 2, ordinalEntry)) {
                diagnostic("EB-PE-EXPORT", "The export name table is truncated.");
                break;
            }
            std::uint32_t functionNameRva = 0;
            std::uint16_t ordinalIndex = 0;
            reader_.u32(nameEntry, functionNameRva);
            reader_.u16(ordinalEntry, ordinalIndex);
            if (ordinalIndex >= functionCount) {
                diagnostic("EB-PE-EXPORT", "An export name references an invalid ordinal.");
                continue;
            }

            std::uint64_t functionEntry = 0;
            if (!mapRva(functionsRva + ordinalIndex * 4U, 4, functionEntry)) {
                diagnostic("EB-PE-EXPORT", "The export address table is truncated.");
                break;
            }
            std::uint32_t functionRva = 0;
            reader_.u32(functionEntry, functionRva);

            ExportInfo exportInfo;
            exportInfo.ordinal = output_.exportOrdinalBase +
                                 static_cast<std::uint32_t>(ordinalIndex);
            exportInfo.rva = functionRva;

            std::uint64_t functionNameOffset = 0;
            std::string functionName;
            if (mapRva(functionNameRva, 1, functionNameOffset) &&
                reader_.cString(functionNameOffset, 512, functionName)) {
                exportInfo.name = util::sanitizeAscii(functionName, 512);
            }

            const auto exportEnd = static_cast<std::uint64_t>(exportDirectory->rva) +
                                   exportDirectory->size;
            if (functionRva >= exportDirectory->rva && functionRva < exportEnd) {
                std::uint64_t forwarderOffset = 0;
                std::string forwarder;
                if (mapRva(functionRva, 1, forwarderOffset) &&
                    reader_.cString(forwarderOffset, 512, forwarder)) {
                    exportInfo.forwarder = true;
                    exportInfo.forwarderName = util::sanitizeAscii(forwarder, 512);
                }
            }
            output_.exports.push_back(std::move(exportInfo));
        }
    }

    [[nodiscard]] bool readResourceName(std::uint64_t base, std::uint32_t field,
                                        std::string& name) const {
        if ((field & 0x80000000U) == 0) {
            name = "#" + std::to_string(field);
            return true;
        }
        const auto stringOffset = base + static_cast<std::uint64_t>(field & 0x7FFFFFFFU);
        std::uint16_t length = 0;
        if (!reader_.u16(stringOffset, length) || length > 256) {
            return false;
        }
        std::span<const std::uint8_t> bytes;
        if (!reader_.bytes(stringOffset + 2, static_cast<std::size_t>(length) * 2, bytes)) {
            return false;
        }
        name = utf16ToUtf8(bytes);
        if (name.empty()) {
            name = "#0";
        }
        return true;
    }

    void parseResourceDirectory() {
        const auto* resourceDirectory = directory(static_cast<int>(pe::DirectoryIndex::Resource));
        if (resourceDirectory == nullptr || !resourceDirectory->present ||
            !resourceDirectory->valid) {
            return;
        }
        std::uint64_t base = 0;
        if (!mapRva(resourceDirectory->rva, 1, base)) {
            diagnostic("EB-PE-RESOURCE", "The resource directory could not be mapped.");
            return;
        }

        std::set<std::uint64_t> visited;
        std::size_t total = 0;
        bool limitReported = false;
        bool rangeReported = false;
        bool depthReported = false;

        std::function<void(std::uint64_t, int, const std::string&, const std::string&)> walk;
        walk = [&](std::uint64_t directoryOffset, int level, const std::string& typeName,
                   const std::string& name) {
            if (total >= pe::kMaxResources) {
                return;
            }
            if (!visited.insert(directoryOffset).second) {
                if (!rangeReported) {
                    diagnostic("EB-PE-RESOURCE", "The resource tree contains a cycle.");
                    rangeReported = true;
                }
                return;
            }
            std::uint16_t namedCount = 0;
            std::uint16_t idCount = 0;
            if (!reader_.u16(directoryOffset + 12, namedCount) ||
                !reader_.u16(directoryOffset + 14, idCount)) {
                if (!rangeReported) {
                    diagnostic("EB-PE-RESOURCE", "The resource directory header is truncated.");
                    rangeReported = true;
                }
                return;
            }
            const auto count = std::min<std::uint32_t>(
                static_cast<std::uint32_t>(namedCount) + idCount, 256);
            for (std::uint32_t index = 0; index < count && total < pe::kMaxResources; ++index) {
                std::uint64_t entryOffset = directoryOffset + 16 + index * 8;
                std::uint32_t nameField = 0;
                std::uint32_t dataField = 0;
                if (!reader_.u32(entryOffset, nameField) ||
                    !reader_.u32(entryOffset + 4, dataField)) {
                    if (!rangeReported) {
                        diagnostic("EB-PE-RESOURCE", "The resource directory entry table is truncated.");
                        rangeReported = true;
                    }
                    break;
                }

                std::string entryName;
                if (!readResourceName(base, nameField, entryName)) {
                    entryName = "#?";
                }

                if ((dataField & 0x80000000U) != 0) {
                    if (level >= 2) {
                        if (!depthReported) {
                            diagnostic("EB-PE-RESOURCE", "The resource tree exceeds the expected depth.");
                            depthReported = true;
                        }
                        continue;
                    }
                    const auto child = base + static_cast<std::uint64_t>(dataField & 0x7FFFFFFFU);
                    if (level == 0) {
                        walk(child, 1, resolveResourceType(entryName), {});
                    } else {
                        walk(child, 2, typeName, entryName);
                    }
                    continue;
                }

                const auto dataEntryOffset = base + static_cast<std::uint64_t>(dataField);
                std::uint32_t dataRva = 0;
                std::uint32_t dataSize = 0;
                if (!reader_.u32(dataEntryOffset, dataRva) ||
                    !reader_.u32(dataEntryOffset + 4, dataSize)) {
                    if (!rangeReported) {
                        diagnostic("EB-PE-RESOURCE", "A resource data entry is truncated.");
                        rangeReported = true;
                    }
                    continue;
                }

                ResourceEntry resource;
                resource.type = level == 0 ? resolveResourceType(entryName) : typeName;
                resource.name = level >= 1 ? (level == 1 ? entryName : name) : "<unnamed>";
                resource.language = level >= 2 ? entryName : "#0";
                resource.dataRva = dataRva;
                resource.size = dataSize;
                if (dataSize != 0) {
                    std::uint64_t dataOffset = 0;
                    if (mapRva(dataRva, dataSize, dataOffset)) {
                        resource.fileOffset = static_cast<std::uint32_t>(
                            std::min<std::uint64_t>(dataOffset, std::numeric_limits<std::uint32_t>::max()));
                    } else {
                        resource.dataValid = false;
                        if (!rangeReported) {
                            diagnostic("EB-PE-RESOURCE",
                                        "A resource payload points outside the file.");
                            rangeReported = true;
                        }
                    }
                }
                output_.resources.push_back(std::move(resource));
                ++total;
            }
        };

        walk(base, 0, {}, {});
        if (total >= pe::kMaxResources && !limitReported) {
            diagnostic("EB-PE-RESOURCE-LIMIT",
                        "The resource tree exceeded the parser limit; output was truncated.");
            limitReported = true;
        }
    }

    void parseDebugDirectory() {
        const auto* debugDirectory = directory(static_cast<int>(pe::DirectoryIndex::Debug));
        if (debugDirectory == nullptr || !debugDirectory->present || !debugDirectory->valid) {
            return;
        }
        std::uint64_t base = 0;
        if (!mapRva(debugDirectory->rva, 1, base)) {
            diagnostic("EB-PE-DEBUG", "The debug directory could not be mapped.");
            return;
        }
        if (debugDirectory->size % 28 != 0) {
            diagnostic("EB-PE-DEBUG", "The debug directory size is not a multiple of 28.");
        }
        const auto count = std::min<std::uint32_t>(debugDirectory->size / 28,
                                                   pe::kMaxDebugEntries);
        for (std::uint32_t index = 0; index < count; ++index) {
            std::uint64_t entryOffset = 0;
            if (!mapRva(debugDirectory->rva + index * 28U, 28, entryOffset)) {
                diagnostic("EB-PE-DEBUG", "The debug directory entry table is truncated.");
                break;
            }
            DebugEntry entry;
            std::uint32_t dataRva = 0;
            std::uint32_t pointerToRawData = 0;
            reader_.u32(entryOffset + 12, entry.type);
            reader_.u32(entryOffset + 16, entry.dataSize);
            reader_.u32(entryOffset + 20, dataRva);
            reader_.u32(entryOffset + 24, pointerToRawData);
            entry.typeName = std::string(pe::debugTypeName(entry.type));

            std::uint64_t dataOffset = 0;
            if (pointerToRawData != 0 &&
                reader_.range(pointerToRawData, std::min<std::uint32_t>(entry.dataSize, 4096))) {
                dataOffset = pointerToRawData;
                entry.rawOffsetValid = true;
            } else if (dataRva != 0 && mapRva(dataRva, std::min<std::uint32_t>(entry.dataSize, 1),
                                               dataOffset)) {
                entry.rawOffsetValid = true;
            }
            if (entry.rawOffsetValid) {
                entry.rawOffset = static_cast<std::uint32_t>(dataOffset);
                parseCodeView(entry);
            }
            output_.debugEntries.push_back(std::move(entry));
        }
    }

    void parseCodeView(DebugEntry& entry) {
        if (entry.type != 2 || entry.dataSize < 4 || !entry.rawOffsetValid) {
            return;
        }
        const auto available = static_cast<std::size_t>(
            std::min<std::uint32_t>(entry.dataSize, 1024));
        std::span<const std::uint8_t> bytes;
        if (!reader_.bytes(entry.rawOffset, available, bytes) || bytes.size() < 4) {
            return;
        }
        const bool rsds = bytes[0] == 'R' && bytes[1] == 'S' && bytes[2] == 'D' && bytes[3] == 'S';
        const bool nb10 = bytes[0] == 'N' && bytes[1] == 'B' && bytes[2] == '1' && bytes[3] == '0';
        if (rsds && bytes.size() >= 24) {
            std::array<std::uint8_t, 16> guid{};
            std::copy_n(bytes.begin() + 4, 16, guid.begin());
            entry.guid = pe::formatGuid(guid);
            std::uint32_t age = 0;
            for (int byte = 0; byte < 4; ++byte) {
                age |= static_cast<std::uint32_t>(bytes[20 + byte]) << (byte * 8);
            }
            entry.age = age;
            std::string path(reinterpret_cast<const char*>(bytes.data() + 24),
                             bytes.size() - 24);
            entry.pdbPath = util::sanitizeAscii(path, 512);
        } else if (nb10 && bytes.size() >= 16) {
            std::uint32_t age = 0;
            for (int byte = 0; byte < 4; ++byte) {
                age |= static_cast<std::uint32_t>(bytes[12 + byte]) << (byte * 8);
            }
            entry.age = age;
            std::string path(reinterpret_cast<const char*>(bytes.data() + 16),
                             bytes.size() - 16);
            entry.pdbPath = util::sanitizeAscii(path, 512);
        }
    }

    void parseTlsDirectory() {
        const auto* tlsDirectory = directory(static_cast<int>(pe::DirectoryIndex::Tls));
        if (tlsDirectory == nullptr || !tlsDirectory->present || !tlsDirectory->valid) {
            return;
        }
        const std::uint32_t structureSize = output_.is64Bit ? 40 : 24;
        std::uint64_t tlsOffset = 0;
        if (!mapRva(tlsDirectory->rva, structureSize, tlsOffset)) {
            diagnostic("EB-PE-TLS", "The TLS directory could not be read.");
            return;
        }

        output_.tls.present = true;
        output_.tls.imageBase = output_.imageBase;
        std::uint64_t callbacksVa = 0;
        if (output_.is64Bit) {
            reader_.u64(tlsOffset + 24, callbacksVa);
            reader_.u32(tlsOffset + 32, output_.tls.sizeOfZeroFill);
            reader_.u32(tlsOffset + 36, output_.tls.characteristics);
        } else {
            std::uint32_t callbacks32 = 0;
            reader_.u32(tlsOffset + 12, callbacks32);
            callbacksVa = callbacks32;
            reader_.u32(tlsOffset + 16, output_.tls.sizeOfZeroFill);
            reader_.u32(tlsOffset + 20, output_.tls.characteristics);
        }
        output_.tls.addressOfCallbacks = callbacksVa;
        output_.tls.callbacksPresent = callbacksVa != 0;
        if (callbacksVa == 0) {
            return;
        }
        if (callbacksVa < output_.imageBase) {
            diagnostic("EB-PE-TLS", "TLS callbacks use a virtual address below the image base.");
            return;
        }
        const auto callbacksRva = static_cast<std::uint32_t>(
            callbacksVa - output_.imageBase);
        const std::uint32_t pointerSize = output_.is64Bit ? 8 : 4;
        for (std::uint32_t index = 0; index < pe::kMaxTlsCallbacks; ++index) {
            std::uint64_t entryOffset = 0;
            if (!mapRva(callbacksRva + index * pointerSize, pointerSize, entryOffset)) {
                if (index == 0) {
                    diagnostic("EB-PE-TLS", "The TLS callback array could not be read.");
                }
                break;
            }
            std::uint64_t callback = 0;
            if (output_.is64Bit) {
                reader_.u64(entryOffset, callback);
            } else {
                std::uint32_t callback32 = 0;
                reader_.u32(entryOffset, callback32);
                callback = callback32;
            }
            if (callback == 0) {
                break;
            }
            output_.tls.callbacks.push_back(callback);
        }
        if (output_.tls.callbacks.size() == pe::kMaxTlsCallbacks) {
            diagnostic("EB-PE-TLS-LIMIT", "The TLS callback array exceeded the parser limit.");
        }
    }

    void parseCertificateTable() {
        const auto* certificateDirectory =
            directory(static_cast<int>(pe::DirectoryIndex::Certificate));
        if (certificateDirectory == nullptr || !certificateDirectory->present) {
            return;
        }
        output_.hasCertificateTable = true;
        output_.certificateTableOffset = certificateDirectory->rva;
        output_.certificateTableSize = certificateDirectory->size;
        if (!certificateDirectory->valid) {
            output_.certificateTableValid = false;
            return;
        }

        const auto start = static_cast<std::uint64_t>(certificateDirectory->rva);
        const auto end = start + certificateDirectory->size;
        std::uint64_t position = start;
        std::uint32_t count = 0;
        while (position + 8 <= end) {
            std::uint32_t length = 0;
            std::uint16_t revision = 0;
            std::uint16_t type = 0;
            if (!reader_.u32(position, length) || !reader_.u16(position + 4, revision) ||
                !reader_.u16(position + 6, type)) {
                output_.certificateTableValid = false;
                diagnostic("EB-PE-CERT", "A certificate table entry is truncated.");
                break;
            }
            (void)revision;
            (void)type;
            if (length < 8 || position + length > end) {
                output_.certificateTableValid = false;
                diagnostic("EB-PE-CERT", "A certificate table entry has an invalid length.");
                break;
            }
            ++count;
            position += (length + 7ULL) & ~7ULL;
        }
        output_.certificateEntryCount = count;
        if (count == 0 && certificateDirectory->size != 0) {
            output_.certificateTableValid = false;
            diagnostic("EB-PE-CERT", "The certificate table contains no valid entries.");
        }
    }

    void detectOverlay() {
        std::uint64_t extent = 0;
        if (output_.sizeOfHeaders != 0 && output_.sizeOfHeaders <= reader_.size()) {
            extent = std::max<std::uint64_t>(extent, output_.sizeOfHeaders);
        }
        for (const auto& section : output_.sections) {
            if (!section.rawRangeValid || section.rawSize == 0) {
                continue;
            }
            extent = std::max<std::uint64_t>(
                extent, static_cast<std::uint64_t>(section.rawOffset) + section.rawSize);
        }
        if (output_.certificateTableValid && output_.certificateTableSize != 0) {
            extent = std::max<std::uint64_t>(
                extent, output_.certificateTableOffset + output_.certificateTableSize);
        }
        if (extent > 0 && extent < reader_.size()) {
            output_.overlayOffset = extent;
            output_.overlaySize = reader_.size() - extent;
        }
    }

    void detectRichHeader() {
        const auto limit = std::min<std::uint64_t>(peOffset_, reader_.size());
        if (limit < 8) {
            return;
        }
        std::span<const std::uint8_t> bytes;
        if (!reader_.bytes(0, static_cast<std::size_t>(limit), bytes)) {
            return;
        }
        for (std::size_t index = 0; index + 4 <= bytes.size(); ++index) {
            if (bytes[index] == 'R' && bytes[index + 1] == 'i' &&
                bytes[index + 2] == 'c' && bytes[index + 3] == 'h') {
                output_.hasRichHeader = true;
                return;
            }
        }
    }

    Reader reader_;
    std::span<const std::uint8_t> data_;
    PeInfo& output_;
    PeParseOutcome& outcome_;
    bool partial_ = false;
    std::uint64_t peOffset_ = 0;
    std::uint64_t optionalOffset_ = 0;
};

} // namespace

PeParseOutcome PEParser::parse(std::span<const std::uint8_t> data, PeInfo& output) const {
    PeParseOutcome outcome;
    ParserImpl parser(data, output, outcome);
    parser.run();
    return outcome;
}

} // namespace explainbin
