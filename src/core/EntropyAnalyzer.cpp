#include "explainbin/core/EntropyAnalyzer.hpp"

#include <array>
#include <cmath>

namespace explainbin {

double EntropyAnalyzer::shannon(std::span<const std::uint8_t> data) {
    if (data.empty()) {
        return -1.0;
    }

    std::array<std::uint64_t, 256> histogram{};
    for (const std::uint8_t byte : data) {
        ++histogram[byte];
    }

    const double total = static_cast<double>(data.size());
    double entropy = 0.0;
    for (const std::uint64_t count : histogram) {
        if (count == 0) {
            continue;
        }
        const double probability = static_cast<double>(count) / total;
        entropy -= probability * std::log2(probability);
    }
    return entropy;
}

EntropyOutcome EntropyAnalyzer::analyze(std::span<const std::uint8_t> file, PeInfo& pe) {
    EntropyOutcome outcome;
    outcome.fileEntropy = shannon(file);
    outcome.computed = outcome.fileEntropy >= 0.0;

    for (auto& section : pe.sections) {
        if (!section.rawRangeValid || section.rawSize == 0) {
            section.entropy = -1.0;
            continue;
        }
        const std::uint64_t end = static_cast<std::uint64_t>(section.rawOffset) + section.rawSize;
        if (end > file.size() || section.rawOffset > file.size()) {
            section.rawRangeValid = false;
            section.entropy = -1.0;
            continue;
        }
        section.entropy = shannon(file.subspan(section.rawOffset, section.rawSize));
    }

    return outcome;
}

} // namespace explainbin
