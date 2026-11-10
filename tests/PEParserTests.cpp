#include <gtest/gtest.h>

#include "TestPeBuilder.hpp"
#include "explainbin/core/PEFormat.hpp"
#include "explainbin/core/PEParser.hpp"

#include <cstdint>
#include <vector>

using explainbin::PeInfo;
using explainbin::PEParser;

namespace {

PeInfo parseOrFail(const std::vector<std::uint8_t>& data) {
    PeInfo info;
    PEParser parser;
    const auto outcome = parser.parse(data, info);
    EXPECT_TRUE(outcome.parsed);
    return info;
}

} // namespace

TEST(PEParser, ParsesMinimalPe32) {
    const auto data = testpe::build(testpe::defaultConfig(false));
    ASSERT_FALSE(data.empty());
    PeInfo info;
    PEParser parser;
    const auto outcome = parser.parse(data, info);
    EXPECT_TRUE(outcome.parsed);
    EXPECT_TRUE(info.parsed);
    EXPECT_FALSE(info.is64Bit);
    EXPECT_FALSE(info.isDll);
    EXPECT_EQ(info.format, "PE32 (x86)");
    EXPECT_EQ(info.machine, 0x014C);
    EXPECT_EQ(info.subsystemName, "Windows Console");
    EXPECT_EQ(info.entryPointRva, 0x1000U);
    EXPECT_EQ(info.imageBase, 0x00400000U);
    EXPECT_EQ(info.sections.size(), 2U);
    EXPECT_EQ(info.sections[0].name, ".text");
    EXPECT_TRUE(info.sections[0].executable);
    EXPECT_TRUE(info.sections[0].rawRangeValid);
    EXPECT_FALSE(info.checksumPresent);
    EXPECT_EQ(info.directories.size(), 16U);
}

TEST(PEParser, ParsesMinimalPe32Plus) {
    const auto data = testpe::build(testpe::defaultConfig(true));
    const auto info = parseOrFail(data);
    EXPECT_TRUE(info.is64Bit);
    EXPECT_EQ(info.format, "PE32+ (x64)");
    EXPECT_EQ(info.machine, 0x8664);
    EXPECT_EQ(info.imageBase, 0x0000000140000000ULL);
}

TEST(PEParser, RejectsNonPeFile) {
    std::vector<std::uint8_t> data(512, 'A');
    PeInfo info;
    PEParser parser;
    const auto outcome = parser.parse(data, info);
    EXPECT_FALSE(outcome.parsed);
    EXPECT_FALSE(info.parsed);
    ASSERT_FALSE(outcome.diagnostics.empty());
    EXPECT_TRUE(outcome.diagnostics.front().fatal);
}

TEST(PEParser, RejectsInvalidPeSignature) {
    auto data = testpe::build(testpe::defaultConfig(false));
    testpe::put32(data, testpe::kPeOffset, 0xDEADBEEF);
    PeInfo info;
    PEParser parser;
    const auto outcome = parser.parse(data, info);
    EXPECT_FALSE(outcome.parsed);
    EXPECT_FALSE(outcome.diagnostics.empty());
}

TEST(PEParser, HandlesTruncatedDosAndNtHeaders) {
    auto data = testpe::build(testpe::defaultConfig(false));
    data.resize(0x90);
    PeInfo info;
    PEParser parser;
    const auto outcome = parser.parse(data, info);
    EXPECT_FALSE(outcome.parsed);
    ASSERT_FALSE(outcome.diagnostics.empty());
    EXPECT_EQ(outcome.diagnostics.front().code, "EB-PE-TRUNCATED");
}

TEST(PEParser, RejectsOutOfRangeELfanew) {
    auto data = testpe::build(testpe::defaultConfig(false));
    testpe::put32(data, 0x3C, 0xFFFFFFFF);
    PeInfo info;
    PEParser parser;
    const auto outcome = parser.parse(data, info);
    EXPECT_FALSE(outcome.parsed);
    EXPECT_FALSE(outcome.diagnostics.empty());
}

TEST(PEParser, ClampsExcessiveSectionCount) {
    auto data = testpe::build(testpe::defaultConfig(false));
    testpe::put16(data, testpe::kPeOffset + 4 + 2, 0xFFFF);
    PeInfo info;
    PEParser parser;
    const auto outcome = parser.parse(data, info);
    EXPECT_TRUE(outcome.parsed);
    EXPECT_TRUE(info.partial);
    EXPECT_EQ(info.numberOfSections, 0xFFFFU);
    EXPECT_LE(info.sections.size(), static_cast<std::size_t>(explainbin::pe::kMaxSections));
    EXPECT_FALSE(outcome.diagnostics.empty());
}

TEST(PEParser, MarksSectionWithInvalidRawRange) {
    auto data = testpe::build(testpe::defaultConfig(false));
    testpe::put32(data, testpe::sectionTableOffset(false) + 20, 0xFFFF0000);
    const auto info = parseOrFail(data);
    ASSERT_FALSE(info.sections.empty());
    EXPECT_FALSE(info.sections[0].rawRangeValid);
    EXPECT_TRUE(info.partial);
}

TEST(PEParser, ParsesImportTable) {
    const auto data = testpe::build(testpe::importConfig(false));
    const auto info = parseOrFail(data);
    ASSERT_EQ(info.imports.size(), 1U);
    EXPECT_EQ(info.imports[0].name, "KERNEL32.dll");
    ASSERT_EQ(info.imports[0].functions.size(), 1U);
    EXPECT_EQ(info.imports[0].functions[0].name, "CreateFileW");
    EXPECT_FALSE(info.imports[0].delayLoad);
}

TEST(PEParser, Parses64BitImportTable) {
    const auto data = testpe::build(testpe::importConfig(true));
    const auto info = parseOrFail(data);
    ASSERT_EQ(info.imports.size(), 1U);
    ASSERT_EQ(info.imports[0].functions.size(), 1U);
    EXPECT_EQ(info.imports[0].functions[0].name, "CreateFileW");
}

TEST(PEParser, DetectsChecksumMismatch) {
    auto data = testpe::build(testpe::defaultConfig(false));
    testpe::put32(data, testpe::optionalHeaderOffset() + 64, 0x12345678);
    const auto info = parseOrFail(data);
    EXPECT_TRUE(info.checksumPresent);
    EXPECT_FALSE(info.checksumValid);
    EXPECT_NE(info.computedChecksum, info.checksum);
}

TEST(PEParser, MarksUnmappedDataDirectory) {
    auto data = testpe::build(testpe::defaultConfig(false));
    testpe::put32(data, testpe::directoryOffset(false, 3), 0xFFFFFF00);
    testpe::put32(data, testpe::directoryOffset(false, 3) + 4, 16);
    const auto info = parseOrFail(data);
    ASSERT_GE(info.directories.size(), 4U);
    EXPECT_FALSE(info.directories[3].valid);
    EXPECT_TRUE(info.partial);
}

TEST(PEParser, RejectsOptionalHeaderTooSmall) {
    auto data = testpe::build(testpe::defaultConfig(false));
    testpe::put16(data, testpe::kPeOffset + 4 + 16, 2);
    PeInfo info;
    PEParser parser;
    const auto outcome = parser.parse(data, info);
    EXPECT_FALSE(outcome.parsed);
    EXPECT_FALSE(outcome.diagnostics.empty());
}
