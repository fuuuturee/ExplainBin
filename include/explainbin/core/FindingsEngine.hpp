#pragma once

#include "explainbin/core/Types.hpp"

#include <vector>

namespace explainbin {

// Applies the structural and signature rules. Import findings are produced by
// ImportAnalyzer and merged by Analyzer. The engine observes only data already
// parsed from the file; it never speculates about runtime behavior.
class FindingsEngine {
public:
    [[nodiscard]] std::vector<Finding> evaluate(const AnalysisResult& result) const;

    static void sortBySeverity(std::vector<Finding>& findings);
};

} // namespace explainbin
