#pragma once

#include <cstdint>
#include <span>
#include <string>
#include <string_view>

namespace explainbin::util {

// Formats seconds since the Unix epoch as an ISO-8601 UTC timestamp.
std::string formatUnixTimeUtc(std::int64_t seconds);

// Converts a Windows FILETIME (100 ns intervals since 1601-01-01 UTC).
std::string formatFileTimeUtc(std::uint64_t fileTime);

std::string currentUtcTimestamp();

std::string toHex(std::span<const std::uint8_t> bytes);
std::string toHex(std::uint64_t value);
std::string toLowerAscii(std::string value);
std::string humanBytes(std::uint64_t bytes);

// Copies at most maxLength characters, stopping at the first NUL, and replaces
// non-printable bytes so untrusted PE strings cannot corrupt reports or the UI.
std::string sanitizeAscii(std::string_view value, std::size_t maxLength);

std::string trimTrailingZeros(std::string value);

} // namespace explainbin::util
