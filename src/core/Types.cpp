#include "explainbin/core/Types.hpp"

#include <array>
#include <cstdio>
#include <string>

namespace explainbin {

std::string_view toString(Severity severity) noexcept {
    switch (severity) {
    case Severity::Informational: return "Informational";
    case Severity::Low: return "Low";
    case Severity::Medium: return "Medium";
    case Severity::High: return "High";
    case Severity::Critical: return "Critical";
    }
    return "Unknown";
}

std::string_view toString(Confidence confidence) noexcept {
    switch (confidence) {
    case Confidence::Low: return "Low";
    case Confidence::Medium: return "Medium";
    case Confidence::High: return "High";
    }
    return "Unknown";
}

std::string_view toString(SignatureStatus status) noexcept {
    switch (status) {
    case SignatureStatus::NotChecked: return "Not checked";
    case SignatureStatus::Unsigned: return "Unsigned";
    case SignatureStatus::Valid: return "Valid";
    case SignatureStatus::Invalid: return "Invalid";
    case SignatureStatus::Unknown: return "Unknown";
    }
    return "Unknown";
}

int severityRank(Severity severity) noexcept {
    return static_cast<int>(severity);
}

SeverityCounts countSeverities(const std::vector<Finding>& findings) {
    SeverityCounts counts;
    for (const auto& finding : findings) {
        switch (finding.severity) {
        case Severity::Informational: ++counts.informational; break;
        case Severity::Low: ++counts.low; break;
        case Severity::Medium: ++counts.medium; break;
        case Severity::High: ++counts.high; break;
        case Severity::Critical: ++counts.critical; break;
        }
    }
    return counts;
}

std::string toUtf8(const std::filesystem::path& path) {
    const auto value = path.u8string();
    return {reinterpret_cast<const char*>(value.data()), value.size()};
}

std::filesystem::path fromUtf8(const std::string& utf8Path) {
    const auto* begin = reinterpret_cast<const char8_t*>(utf8Path.data());
    return std::filesystem::path(std::u8string(begin, begin + utf8Path.size()));
}

} // namespace explainbin
