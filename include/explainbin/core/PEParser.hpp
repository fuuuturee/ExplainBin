#pragma once

#include "explainbin/core/Types.hpp"

#include <cstdint>
#include <span>
#include <vector>

namespace explainbin {

struct PeParseOutcome {
    bool parsed = false;
    std::vector<Diagnostic> diagnostics;
};

// Bounds-checked, non-loading Portable Executable parser. Every offset and
// size is validated against the actual file buffer before it is read.
class PEParser {
public:
    [[nodiscard]] PeParseOutcome parse(std::span<const std::uint8_t> data,
                                       PeInfo& output) const;
};

} // namespace explainbin
