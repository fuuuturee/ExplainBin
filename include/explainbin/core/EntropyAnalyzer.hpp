#pragma once

#include "explainbin/core/Types.hpp"

#include <cstdint>
#include <span>

namespace explainbin {

struct EntropyOutcome {
    double fileEntropy = -1.0;
    bool computed = false;
};

class EntropyAnalyzer {
public:
    // Shannon entropy in bits per byte, range [0, 8]. Returns -1 for empty input.
    static double shannon(std::span<const std::uint8_t> data);

    // Computes whole-file entropy and per-section entropy for ranges that are
    // fully contained in the file. Invalid ranges keep the value -1.
    static EntropyOutcome analyze(std::span<const std::uint8_t> file, PeInfo& pe);
};

} // namespace explainbin
