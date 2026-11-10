#include "explainbin/reports/ReportUtil.hpp"

#include "explainbin/core/Types.hpp"

#include <fstream>

namespace explainbin {

bool writeReportFile(const std::filesystem::path& path,
                     std::string_view content,
                     std::string& error) {
    try {
        std::ofstream stream(path, std::ios::binary | std::ios::trunc);
        if (!stream) {
            error = "Unable to open the report file for writing.";
            return false;
        }
        stream.write(content.data(), static_cast<std::streamsize>(content.size()));
        if (!stream) {
            error = "Unable to write the complete report file.";
            return false;
        }
        stream.flush();
        if (!stream) {
            error = "Unable to flush the report file.";
            return false;
        }
        return true;
    } catch (const std::exception& exception) {
        error = std::string("Report writing failed: ") + exception.what();
        return false;
    }
}

} // namespace explainbin
