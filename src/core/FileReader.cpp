#include "explainbin/core/FileReader.hpp"

#include "explainbin/core/Util.hpp"

#include <windows.h>

#include <algorithm>
#include <limits>
#include <memory>
#include <system_error>
#include <vector>

namespace explainbin {
namespace {

struct FileHandleCloser {
    void operator()(HANDLE handle) const noexcept {
        if (handle != INVALID_HANDLE_VALUE && handle != nullptr) {
            CloseHandle(handle);
        }
    }
};

using UniqueFileHandle = std::unique_ptr<void, FileHandleCloser>;

std::string win32Error(DWORD code) {
    return std::system_category().message(static_cast<int>(code));
}

} // namespace

ReadFileResult FileReader::read(const std::filesystem::path& path,
                                std::uint64_t maxSizeBytes) {
    ReadFileResult result;

    HANDLE rawHandle = CreateFileW(path.c_str(), GENERIC_READ,
                                   FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                   nullptr, OPEN_EXISTING,
                                   FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (rawHandle == INVALID_HANDLE_VALUE) {
        result.error = "Unable to open file: " + win32Error(GetLastError());
        return result;
    }
    UniqueFileHandle handle(rawHandle);

    LARGE_INTEGER size{};
    if (GetFileSizeEx(handle.get(), &size) == 0) {
        result.error = "Unable to determine file size: " + win32Error(GetLastError());
        return result;
    }
    if (size.QuadPart <= 0) {
        result.error = "The file is empty.";
        return result;
    }

    const auto fileSize = static_cast<std::uint64_t>(size.QuadPart);
    if (fileSize > maxSizeBytes) {
        result.error = "The file exceeds the configured analysis limit of " +
                       util::humanBytes(maxSizeBytes) + ".";
        return result;
    }
    if (fileSize > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max())) {
        result.error = "The file is too large for this build of ExplainBin.";
        return result;
    }

    FILETIME creation{};
    FILETIME access{};
    FILETIME write{};
    if (GetFileTime(handle.get(), &creation, &access, &write) != 0) {
        ULARGE_INTEGER creationValue{};
        creationValue.LowPart = creation.dwLowDateTime;
        creationValue.HighPart = creation.dwHighDateTime;
        ULARGE_INTEGER writeValue{};
        writeValue.LowPart = write.dwLowDateTime;
        writeValue.HighPart = write.dwHighDateTime;
        result.creationTimeUtc = util::formatFileTimeUtc(creationValue.QuadPart);
        result.lastWriteTimeUtc = util::formatFileTimeUtc(writeValue.QuadPart);
    }

    try {
        result.data.resize(static_cast<std::size_t>(fileSize));
    } catch (const std::bad_alloc&) {
        result.error = "Not enough memory to read the file.";
        return result;
    }

    constexpr DWORD kChunkSize = 16 * 1024 * 1024;
    DWORD totalRead = 0;
    while (totalRead < fileSize) {
        const auto remaining = fileSize - totalRead;
        const auto toRead = static_cast<DWORD>(std::min<std::uint64_t>(remaining, kChunkSize));
        DWORD bytesRead = 0;
        if (ReadFile(handle.get(), result.data.data() + totalRead, toRead, &bytesRead, nullptr) == 0) {
            result.error = "Unable to read file: " + win32Error(GetLastError());
            return result;
        }
        if (bytesRead == 0) {
            result.error = "The file ended unexpectedly while it was being read.";
            return result;
        }
        totalRead += bytesRead;
    }

    if (totalRead != fileSize) {
        result.error = "The file changed while it was being read.";
        return result;
    }

    result.ok = true;
    result.size = fileSize;
    return result;
}

} // namespace explainbin
