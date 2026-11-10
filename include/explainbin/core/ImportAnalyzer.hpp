#pragma once

#include "explainbin/core/Types.hpp"

#include <vector>

namespace explainbin {

// Enriches imported APIs with category/context and evaluates capability
// combinations. It never labels an API itself as malicious.
class ImportAnalyzer {
public:
    void annotate(PeInfo& pe) const;
    [[nodiscard]] std::vector<Finding> analyze(const PeInfo& pe) const;
};

} // namespace explainbin
