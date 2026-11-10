#include "explainbin/core/Util.hpp"

#include <array>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <ctime>
#include <iomanip>
#include <sstream>

namespace explainbin::util {
namespace {

// Howard Hinnant's civil-from-days algorithm. It avoids platform-specific
// gmtime functions and is safe for every int64 value we can encounter.
struct CivilDate {
    int year;
    unsigned month;
    unsigned day;
};

CivilDate civilFromDays(std::int64_t z) noexcept {
    z += 719468;
    const std::int64_t era = (z >= 0 ? z : z - 146096) / 146097;
    const unsigned doe = static_cast<unsigned>(z - era * 146097);
    const unsigned yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    const std::int64_t y = static_cast<std::int64_t>(yoe) + era * 400;
    const unsigned doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    const unsigned mp = (5 * doy + 2) / 153;
    const unsigned d = doy - (153 * mp + 2) / 5 + 1;
    const unsigned m = mp < 10 ? mp + 3 : mp - 9;
    return {static_cast<int>(y + (m <= 2)), m, d};
}

} // namespace

std::string formatUnixTimeUtc(std::int64_t seconds) {
    if (seconds <= 0) {
        return {};
    }
    std::int64_t days = seconds / 86400;
    std::int64_t remainder = seconds % 86400;
    if (remainder < 0) {
        remainder += 86400;
        --days;
    }
    const auto date = civilFromDays(days);
    const int hour = static_cast<int>(remainder / 3600);
    const int minute = static_cast<int>((remainder % 3600) / 60);
    const int second = static_cast<int>(remainder % 60);

    std::array<char, 32> buffer{};
    std::snprintf(buffer.data(), buffer.size(), "%04d-%02u-%02uT%02d:%02d:%02dZ",
                  date.year, date.month, date.day, hour, minute, second);
    return buffer.data();
}

std::string formatFileTimeUtc(std::uint64_t fileTime) {
    constexpr std::uint64_t kEpochDifference = 116444736000000000ULL;
    if (fileTime < kEpochDifference) {
        return {};
    }
    const auto unixSeconds = static_cast<std::int64_t>((fileTime - kEpochDifference) / 10000000ULL);
    return formatUnixTimeUtc(unixSeconds);
}

std::string currentUtcTimestamp() {
    const auto now = std::chrono::system_clock::now();
    const auto seconds = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();
    return formatUnixTimeUtc(seconds);
}

std::string toHex(std::span<const std::uint8_t> bytes) {
    static constexpr char kDigits[] = "0123456789abcdef";
    std::string result;
    result.resize(bytes.size() * 2);
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        result[i * 2] = kDigits[(bytes[i] >> 4) & 0x0F];
        result[i * 2 + 1] = kDigits[bytes[i] & 0x0F];
    }
    return result;
}

std::string toHex(std::uint64_t value) {
    std::array<char, 18> buffer{};
    std::snprintf(buffer.data(), buffer.size(), "0x%llx",
                  static_cast<unsigned long long>(value));
    return buffer.data();
}

std::string toLowerAscii(std::string value) {
    for (char& ch : value) {
        if (ch >= 'A' && ch <= 'Z') {
            ch = static_cast<char>(ch - 'A' + 'a');
        }
    }
    return value;
}

std::string humanBytes(std::uint64_t bytes) {
    static constexpr std::array<const char*, 5> kUnits{"B", "KiB", "MiB", "GiB", "TiB"};
    double value = static_cast<double>(bytes);
    std::size_t unit = 0;
    while (value >= 1024.0 && unit + 1 < kUnits.size()) {
        value /= 1024.0;
        ++unit;
    }
    std::ostringstream stream;
    stream << std::fixed << std::setprecision(value < 10.0 && unit > 0 ? 2 : (unit == 0 ? 0 : 1))
           << value << ' ' << kUnits[unit];
    return stream.str();
}

std::string sanitizeAscii(std::string_view value, std::size_t maxLength) {
    std::string result;
    result.reserve(std::min(maxLength, value.size()));
    for (const char ch : value) {
        if (result.size() >= maxLength) {
            break;
        }
        const auto byte = static_cast<unsigned char>(ch);
        if (byte == 0) {
            break;
        }
        result.push_back((byte >= 0x20 && byte <= 0x7E) ? ch : '?');
    }
    return result;
}

std::string trimTrailingZeros(std::string value) {
    const auto nul = value.find('\0');
    if (nul != std::string::npos) {
        value.resize(nul);
    }
    return value;
}

} // namespace explainbin::util
