#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace explainbin {

struct ReadFileResult {
    bool ok = false;
    std::string error;
    std::vector<std::uint8_t> data;
    std::uint64_t size = 0;
    std::string lastWriteTimeUtc;
    std::string creationTimeUtc;
};

// Reads an untrusted file into memory using a read-only handle. The file is
// never mapped as an image, executed, or loaded into the process.
class FileReader {
public:
    static ReadFileResult read(const std::filesystem::path& path,
                               std::uint64_t maxSizeBytes);
};

} // namespace explainbin
