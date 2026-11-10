#include <gtest/gtest.h>

#include "explainbin/core/HashCalculator.hpp"

#include <cstdint>
#include <span>
#include <vector>

using explainbin::HashCalculator;

TEST(HashCalculator, KnownVectorAbc) {
    const std::vector<std::uint8_t> input{'a', 'b', 'c'};
    const auto outcome = HashCalculator::calculate(input);
    ASSERT_TRUE(outcome.ok) << outcome.error;
    EXPECT_EQ(outcome.hashes.sha256,
              "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    EXPECT_EQ(outcome.hashes.sha1, "a9993e364706816aba3e25717850c26c9cd0d89d");
    EXPECT_EQ(outcome.hashes.md5, "900150983cd24fb0d6963f7d28e17f72");
}

TEST(HashCalculator, EmptyInput) {
    const std::span<const std::uint8_t> input;
    const auto outcome = HashCalculator::calculate(input);
    ASSERT_TRUE(outcome.ok) << outcome.error;
    EXPECT_EQ(outcome.hashes.sha256,
              "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    EXPECT_EQ(outcome.hashes.sha1, "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    EXPECT_EQ(outcome.hashes.md5, "d41d8cd98f00b204e9800998ecf8427e");
}

TEST(HashCalculator, Md5CanBeDisabled) {
    const std::vector<std::uint8_t> input{'a', 'b', 'c'};
    const auto outcome = HashCalculator::calculate(input, false);
    ASSERT_TRUE(outcome.ok) << outcome.error;
    EXPECT_TRUE(outcome.hashes.md5.empty());
    EXPECT_FALSE(outcome.hashes.sha256.empty());
    EXPECT_FALSE(outcome.hashes.sha1.empty());
}

TEST(HashCalculator, LargeInputUsesStreamingPath) {
    std::vector<std::uint8_t> input(1024 * 1024 + 137, 0);
    for (std::size_t index = 0; index < input.size(); ++index) {
        input[index] = static_cast<std::uint8_t>(index * 31 + 7);
    }
    const auto outcome = HashCalculator::calculate(input);
    ASSERT_TRUE(outcome.ok) << outcome.error;
    EXPECT_EQ(outcome.hashes.sha256.size(), 64U);
    EXPECT_EQ(outcome.hashes.sha1.size(), 40U);
    EXPECT_EQ(outcome.hashes.md5.size(), 32U);
}
