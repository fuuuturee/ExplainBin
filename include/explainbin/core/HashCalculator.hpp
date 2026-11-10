#pragma once

#include "explainbin/core/Types.hpp"

#include <cstdint>
#include <span>
#include <string>

namespace explainbin {

struct HashOutcome {
    bool ok = false;
    HashSet hashes;
    std::string error;
};

// Computes hashes with Windows CNG (BCrypt). The input span is the exact byte
// sequence that was parsed, so hashes and structural analysis cannot diverge.
class HashCalculator {
public:
    static HashOutcome calculate(std::span<const std::uint8_t> data,
                                 bool includeMd5 = true);
};

} // namespace explainbin
