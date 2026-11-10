#pragma once

#include <filesystem>
#include <string>
#include <string_view>

namespace explainbin {

// Writes a report as UTF-8. Overwrites the destination only after the caller
// has confirmed the path. Returns false and an error message on failure.
bool writeReportFile(const std::filesystem::path& path,
                     std::string_view content,
                     std::string& error);

} // namespace explainbin
