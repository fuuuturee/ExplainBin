#pragma once

// The version is supplied by CMake from the project() version. The fallback
// keeps standalone editor/IDE parsing and non-CMake builds working.
#ifndef EXPLAINBIN_VERSION_STRING
#define EXPLAINBIN_VERSION_STRING "0.0.0-dev"
#endif

namespace explainbin {

inline constexpr const char* kToolName = "ExplainBin";
inline constexpr const char* kToolVersion = EXPLAINBIN_VERSION_STRING;
inline constexpr const char* kReportSchemaVersion = "1.0";

} // namespace explainbin
