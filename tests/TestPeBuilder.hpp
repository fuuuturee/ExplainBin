#pragma once

#include <algorithm>
#include <cstdint>
#include <map>
#include <string>
#include <utility>
#include <vector>

namespace testpe {

constexpr std::size_t kPeOffset = 0x80;
constexpr std::size_t kHeadersSize = 0x400;

struct SectionSpec {
    std::string name;
    std::vector<std::uint8_t> data;
    std::uint32_t virtualSize = 0;
    std::uint32_t virtualAddress = 0;
    std::uint32_t characteristics = 0x40000040; // initialized read data
};

struct Config {
    bool pe64 = false;
    bool dll = false;
    std::uint32_t timestamp = 0x60000000;
    std::uint16_t subsystem = 3;
    std::uint32_t dllCharacteristics = 0x8160;
    std::uint32_t entryPointRva = 0x1000;
    std::uint32_t sectionAlignment = 0x1000;
    std::uint32_t fileAlignment = 0x200;
    std::vector<SectionSpec> sections;
    std::map<int, std::pair<std::uint32_t, std::uint32_t>> directories;
};

inline std::uint32_t alignUp(std::uint32_t value, std::uint32_t alignment) {
    if (alignment == 0) {
        return value;
    }
    return (value + alignment - 1) & ~(alignment - 1);
}

inline void put16(std::vector<std::uint8_t>& data, std::size_t offset, std::uint16_t value) {
    if (offset + 2 > data.size()) {
        return;
    }
    data[offset] = static_cast<std::uint8_t>(value & 0xFF);
    data[offset + 1] = static_cast<std::uint8_t>((value >> 8) & 0xFF);
}

inline void put32(std::vector<std::uint8_t>& data, std::size_t offset, std::uint32_t value) {
    if (offset + 4 > data.size()) {
        return;
    }
    for (int index = 0; index < 4; ++index) {
        data[offset + static_cast<std::size_t>(index)] =
            static_cast<std::uint8_t>((value >> (index * 8)) & 0xFF);
    }
}

inline void put64(std::vector<std::uint8_t>& data, std::size_t offset, std::uint64_t value) {
    if (offset + 8 > data.size()) {
        return;
    }
    for (int index = 0; index < 8; ++index) {
        data[offset + static_cast<std::size_t>(index)] =
            static_cast<std::uint8_t>((value >> (index * 8)) & 0xFF);
    }
}

inline std::uint16_t get16(const std::vector<std::uint8_t>& data, std::size_t offset) {
    if (offset + 2 > data.size()) {
        return 0;
    }
    return static_cast<std::uint16_t>(data[offset] | (data[offset + 1] << 8));
}

inline std::uint32_t get32(const std::vector<std::uint8_t>& data, std::size_t offset) {
    if (offset + 4 > data.size()) {
        return 0;
    }
    std::uint32_t value = 0;
    for (int index = 0; index < 4; ++index) {
        value |= static_cast<std::uint32_t>(data[offset + static_cast<std::size_t>(index)])
                 << (index * 8);
    }
    return value;
}

inline std::size_t optionalHeaderOffset() {
    return kPeOffset + 4 + 20;
}

inline std::size_t optionalHeaderSize(bool pe64) {
    return pe64 ? 240 : 224;
}

inline std::size_t sectionTableOffset(bool pe64) {
    return optionalHeaderOffset() + optionalHeaderSize(pe64);
}

inline std::size_t directoryOffset(bool pe64, int index) {
    return optionalHeaderOffset() + (pe64 ? 112 : 96) + static_cast<std::size_t>(index) * 8;
}

inline SectionSpec textSection() {
    SectionSpec section;
    section.name = ".text";
    section.data.assign(0x200, 0x90);
    section.data[0] = 0xC3; // ret
    section.characteristics = 0x60000020; // code, execute, read
    return section;
}

inline SectionSpec rdataSection() {
    SectionSpec section;
    section.name = ".rdata";
    section.data = {'H', 'e', 'l', 'l', 'o', '\0'};
    section.characteristics = 0x40000040; // initialized data, read
    return section;
}

// Builds a minimal, structurally valid PE image with optional imported API.
inline std::vector<std::uint8_t> build(const Config& config) {
    const std::size_t optOffset = optionalHeaderOffset();
    const std::size_t optSize = optionalHeaderSize(config.pe64);
    const std::size_t sectionTable = sectionTableOffset(config.pe64);
    if (config.sections.size() > 16) {
        return {};
    }
    if (sectionTable + config.sections.size() * 40 > kHeadersSize) {
        return {};
    }

    struct Layout {
        SectionSpec spec;
        std::uint32_t virtualAddress = 0;
        std::uint32_t virtualSize = 0;
        std::uint32_t rawSize = 0;
        std::uint32_t rawOffset = 0;
    };
    std::vector<Layout> layouts;
    std::uint32_t nextVirtual = 0x1000;
    std::uint32_t nextRaw = static_cast<std::uint32_t>(kHeadersSize);
    for (const auto& section : config.sections) {
        Layout layout;
        layout.spec = section;
        layout.virtualSize = section.virtualSize != 0 ? section.virtualSize
                                                      : static_cast<std::uint32_t>(section.data.size());
        layout.virtualAddress = section.virtualAddress != 0
                                    ? section.virtualAddress
                                    : alignUp(nextVirtual, config.sectionAlignment);
        layout.rawSize = section.data.empty()
                             ? 0
                             : alignUp(static_cast<std::uint32_t>(section.data.size()),
                                       config.fileAlignment);
        layout.rawOffset = layout.rawSize == 0 ? 0 : nextRaw;
        if (layout.rawSize != 0) {
            nextRaw += layout.rawSize;
        }
        const auto span = std::max(layout.virtualSize, layout.rawSize);
        nextVirtual = std::max(nextVirtual, layout.virtualAddress + span);
        layouts.push_back(std::move(layout));
    }

    const std::uint32_t fileSize = nextRaw;
    std::vector<std::uint8_t> data(fileSize, 0);
    data[0] = 'M';
    data[1] = 'Z';
    put32(data, 0x3C, static_cast<std::uint32_t>(kPeOffset));
    const char* stub = "ExplainBin synthetic test image.";
    for (std::size_t index = 0; stub[index] != '\0' && 0x40 + index < kPeOffset; ++index) {
        data[0x40 + index] = static_cast<std::uint8_t>(stub[index]);
    }

    put32(data, kPeOffset, 0x00004550); // PE\0\0
    const std::size_t coff = kPeOffset + 4;
    put16(data, coff, config.pe64 ? 0x8664 : 0x014C);
    put16(data, coff + 2, static_cast<std::uint16_t>(layouts.size()));
    put32(data, coff + 4, config.timestamp);
    put16(data, coff + 16, static_cast<std::uint16_t>(optSize));
    std::uint16_t characteristics = 0x0002; // executable image
    characteristics |= config.pe64 ? 0x0020 : 0x0100;
    if (config.dll) {
        characteristics |= 0x2000;
    }
    put16(data, coff + 18, characteristics);

    const std::size_t opt = optOffset;
    put16(data, opt, config.pe64 ? 0x020B : 0x010B);
    data[opt + 2] = 14; // linker major
    data[opt + 3] = 0;
    std::uint32_t sizeOfCode = 0;
    std::uint32_t sizeOfData = 0;
    std::uint32_t baseOfCode = 0;
    std::uint32_t baseOfData = 0;
    std::uint32_t highestEnd = 0;
    for (const auto& layout : layouts) {
        if ((layout.spec.characteristics & 0x20) != 0) {
            sizeOfCode += layout.rawSize;
            if (baseOfCode == 0) {
                baseOfCode = layout.virtualAddress;
            }
        } else {
            sizeOfData += layout.rawSize;
            if (baseOfData == 0) {
                baseOfData = layout.virtualAddress;
            }
        }
        highestEnd = std::max(highestEnd, layout.virtualAddress + layout.virtualSize);
    }
    put32(data, opt + 4, sizeOfCode);
    put32(data, opt + 8, sizeOfData);
    put32(data, opt + 12, 0);
    put32(data, opt + 16, config.entryPointRva);
    put32(data, opt + 20, baseOfCode);
    if (config.pe64) {
        put64(data, opt + 24, 0x0000000140000000ULL);
    } else {
        put32(data, opt + 28, 0x00400000);
        put32(data, opt + 24, baseOfData);
    }
    put32(data, opt + 32, config.sectionAlignment);
    put32(data, opt + 36, config.fileAlignment);
    data[opt + 40] = 6;
    data[opt + 41] = 0;
    data[opt + 48] = 6;
    data[opt + 49] = 0;
    put32(data, opt + 56, alignUp(std::max<std::uint32_t>(highestEnd, 0x1000),
                                  config.sectionAlignment));
    put32(data, opt + 60, static_cast<std::uint32_t>(kHeadersSize));
    put32(data, opt + 64, 0);
    put16(data, opt + 68, config.subsystem);
    put16(data, opt + 70, static_cast<std::uint16_t>(config.dllCharacteristics));
    if (config.pe64) {
        put64(data, opt + 72, 0x100000);
        put64(data, opt + 80, 0x1000);
        put64(data, opt + 88, 0x100000);
        put64(data, opt + 96, 0x1000);
        put32(data, opt + 108, 16);
    } else {
        put32(data, opt + 72, 0x100000);
        put32(data, opt + 76, 0x1000);
        put32(data, opt + 80, 0x100000);
        put32(data, opt + 84, 0x1000);
        put32(data, opt + 92, 16);
    }

    const std::size_t dirOffset = opt + (config.pe64 ? 112 : 96);
    for (const auto& [index, entry] : config.directories) {
        if (index < 0 || index >= 16) {
            continue;
        }
        put32(data, dirOffset + static_cast<std::size_t>(index) * 8, entry.first);
        put32(data, dirOffset + static_cast<std::size_t>(index) * 8 + 4, entry.second);
    }

    for (std::size_t index = 0; index < layouts.size(); ++index) {
        const auto& layout = layouts[index];
        const auto entry = sectionTable + index * 40;
        for (std::size_t character = 0; character < layout.spec.name.size() && character < 8;
             ++character) {
            data[entry + character] = static_cast<std::uint8_t>(layout.spec.name[character]);
        }
        put32(data, entry + 8, layout.virtualSize);
        put32(data, entry + 12, layout.virtualAddress);
        put32(data, entry + 16, layout.rawSize);
        put32(data, entry + 20, layout.rawOffset);
        put32(data, entry + 36, layout.spec.characteristics);
        if (layout.rawSize != 0) {
            std::copy(layout.spec.data.begin(), layout.spec.data.end(),
                      data.begin() + layout.rawOffset);
        }
    }

    return data;
}

inline Config defaultConfig(bool pe64 = false) {
    Config config;
    config.pe64 = pe64;
    config.sections.push_back(textSection());
    config.sections.push_back(rdataSection());
    return config;
}

inline Config importConfig(bool pe64 = false) {
    Config config = defaultConfig(pe64);
    SectionSpec idata;
    idata.name = ".idata";
    idata.virtualAddress = 0x3000;
    idata.characteristics = 0x40000040;
    idata.data.assign(0x200, 0);
    const std::uint32_t base = 0x3000;
    const std::uint32_t thunkRva = base + 0x40;
    const std::uint32_t nameRva = base + 0x80;
    const std::uint32_t hintRva = base + 0xA0;
    const std::uint32_t pointerSize = pe64 ? 8 : 4;

    put32(idata.data, 0x00, thunkRva); // OriginalFirstThunk
    put32(idata.data, 0x0C, nameRva);  // Name
    put32(idata.data, 0x10, thunkRva); // FirstThunk

    if (pe64) {
        put64(idata.data, 0x40, hintRva);
        put64(idata.data, 0x48, 0);
    } else {
        put32(idata.data, 0x40, hintRva);
        put32(idata.data, 0x44, 0);
    }
    (void)pointerSize;

    const std::string dll = "KERNEL32.dll";
    for (std::size_t index = 0; index < dll.size(); ++index) {
        idata.data[0x80 + index] = static_cast<std::uint8_t>(dll[index]);
    }
    const std::string function = "CreateFileW";
    put16(idata.data, 0xA0, 0);
    for (std::size_t index = 0; index < function.size(); ++index) {
        idata.data[0xA2 + index] = static_cast<std::uint8_t>(function[index]);
    }

    config.sections.push_back(std::move(idata));
    config.directories[1] = {0x3000, 40};
    return config;
}

} // namespace testpe
