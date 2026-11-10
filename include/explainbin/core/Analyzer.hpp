#pragma once

#include "explainbin/core/Types.hpp"

#include <filesystem>
#include <functional>
#include <string>

namespace explainbin {

class Analyzer {
public:
    using ProgressCallback = std::function<void(const std::string& stage, int percent)>;

    // Performs the complete local static-analysis pipeline. The analyzed file is
    // read, hashed and parsed; it is never executed or loaded as an image.
    [[nodiscard]] AnalysisResult analyze(const std::filesystem::path& path,
                                         const AnalysisOptions& options = {},
                                         const ProgressCallback& progress = {}) const;
};

} // namespace explainbin
