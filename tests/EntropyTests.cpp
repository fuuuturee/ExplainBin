#include <gtest/gtest.h>

#include "explainbin/core/EntropyAnalyzer.hpp"

#include <cmath>
#include <cstdint>
#include <vector>

TEST(EntropyAnalyzer, EmptyInputIsUnknown) {
    const std::span<const std::uint8_t> empty;
    EXPECT_DOUBLE_EQ(explainbin::EntropyAnalyzer::shannon(empty), -1.0);
}

TEST(EntropyAnalyzer, ConstantDataHasZeroEntropy) {
    const std::vector<std::uint8_t> input(4096, 0xAA);
    EXPECT_NEAR(explainbin::EntropyAnalyzer::shannon(input), 0.0, 1e-9);
}

TEST(EntropyAnalyzer, UniformByteDistributionIsEightBits) {
    std::vector<std::uint8_t> input;
    input.reserve(256 * 8);
    for (int repeat = 0; repeat < 8; ++repeat) {
        for (int byte = 0; byte < 256; ++byte) {
            input.push_back(static_cast<std::uint8_t>(byte));
        }
    }
    EXPECT_NEAR(explainbin::EntropyAnalyzer::shannon(input), 8.0, 1e-9);
}

TEST(EntropyAnalyzer, TwoEquallyLikelyValues) {
    std::vector<std::uint8_t> input(1000, 0x00);
    input.insert(input.end(), 1000, 0xFF);
    EXPECT_NEAR(explainbin::EntropyAnalyzer::shannon(input), 1.0, 1e-9);
}

TEST(EntropyAnalyzer, SectionRangesAreBounded) {
    std::vector<std::uint8_t> file(1024, 0x11);
    explainbin::PeInfo pe;
    explainbin::SectionInfo valid;
    valid.name = ".text";
    valid.rawOffset = 512;
    valid.rawSize = 512;
    explainbin::SectionInfo invalid;
    invalid.name = ".bad";
    invalid.rawOffset = 1000;
    invalid.rawSize = 100;
    invalid.rawRangeValid = true;
    pe.sections = {valid, invalid};

    const auto outcome = explainbin::EntropyAnalyzer::analyze(file, pe);
    EXPECT_TRUE(outcome.computed);
    EXPECT_NEAR(outcome.fileEntropy, 0.0, 1e-9);
    EXPECT_NEAR(pe.sections[0].entropy, 0.0, 1e-9);
    EXPECT_FALSE(pe.sections[1].rawRangeValid);
    EXPECT_DOUBLE_EQ(pe.sections[1].entropy, -1.0);
}
