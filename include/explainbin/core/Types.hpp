#pragma once

#include "explainbin/Version.h"

#include <cstdint>
#include <filesystem>
#include <map>
#include <string>
#include <string_view>
#include <vector>

namespace explainbin {

inline constexpr const char* kStaticAnalysisDisclaimer =
    "ExplainBin performs static analysis only. It never executes or loads the analyzed file. "
    "A low number of findings does not prove that a file is safe. Findings are heuristic "
    "observations, not a malware verdict.";

enum class Severity {
    Informational = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4
};

enum class Confidence {
    Low = 0,
    Medium = 1,
    High = 2
};

enum class SignatureStatus {
    NotChecked,
    Unsigned,
    Valid,
    Invalid,
    Unknown
};

std::string_view toString(Severity severity) noexcept;
std::string_view toString(Confidence confidence) noexcept;
std::string_view toString(SignatureStatus status) noexcept;
int severityRank(Severity severity) noexcept;

struct HashSet {
    std::string md5;
    std::string sha1;
    std::string sha256;
};

struct FileInfo {
    std::string path;
    std::string fileName;
    std::string extension;
    std::uint64_t size = 0;
    std::string lastWriteTimeUtc;
    std::string creationTimeUtc;
    HashSet hashes;
};

struct SectionInfo {
    std::string name;
    std::uint32_t virtualAddress = 0;
    std::uint32_t virtualSize = 0;
    std::uint32_t rawOffset = 0;
    std::uint32_t rawSize = 0;
    std::uint32_t characteristics = 0;
    double entropy = -1.0;
    bool readable = false;
    bool writable = false;
    bool executable = false;
    bool code = false;
    bool initializedData = false;
    bool uninitializedData = false;
    bool rawRangeValid = true;
};

struct DataDirectoryInfo {
    int index = 0;
    std::string name;
    std::uint32_t rva = 0;
    std::uint32_t size = 0;
    bool present = false;
    bool valid = true;
    std::string note;
};

struct ImportFunction {
    std::string name;
    std::uint16_t ordinal = 0;
    bool byOrdinal = false;
    std::uint16_t hint = 0;
    std::string category;
    std::string insight;
};

struct ImportLibrary {
    std::string name;
    std::vector<ImportFunction> functions;
    bool delayLoad = false;
};

struct ExportInfo {
    std::string name;
    std::uint32_t ordinal = 0;
    std::uint32_t rva = 0;
    bool forwarder = false;
    std::string forwarderName;
};

struct ResourceEntry {
    std::string type;
    std::string name;
    std::string language;
    std::uint32_t dataRva = 0;
    std::uint32_t size = 0;
    std::uint32_t fileOffset = 0;
    bool dataValid = true;
};

struct DebugEntry {
    std::uint32_t type = 0;
    std::string typeName;
    std::uint32_t dataSize = 0;
    std::uint32_t rawOffset = 0;
    bool rawOffsetValid = false;
    std::string pdbPath;
    std::string guid;
    std::uint32_t age = 0;
};

struct TlsInfo {
    bool present = false;
    bool callbacksPresent = false;
    std::uint64_t imageBase = 0;
    std::uint64_t addressOfCallbacks = 0;
    std::uint32_t sizeOfZeroFill = 0;
    std::uint32_t characteristics = 0;
    std::vector<std::uint64_t> callbacks;
};

struct PeInfo {
    bool parsed = false;
    bool partial = false;
    std::string format;
    bool is64Bit = false;
    bool isDll = false;
    std::uint16_t machine = 0;
    std::string machineName;
    std::uint16_t subsystem = 0;
    std::string subsystemName;
    std::uint32_t entryPointRva = 0;
    std::uint64_t imageBase = 0;
    std::uint32_t sectionAlignment = 0;
    std::uint32_t fileAlignment = 0;
    std::uint32_t sizeOfImage = 0;
    std::uint32_t sizeOfHeaders = 0;
    std::uint32_t checksum = 0;
    std::uint32_t computedChecksum = 0;
    bool checksumPresent = false;
    bool checksumValid = false;
    std::uint32_t timestamp = 0;
    std::string timestampUtc;
    std::uint16_t characteristics = 0;
    std::uint16_t dllCharacteristics = 0;
    std::string linkerVersion;
    std::string osVersion;
    std::string subsystemVersion;
    std::uint32_t numberOfSections = 0;
    std::uint32_t numberOfRvaAndSizes = 0;
    std::vector<SectionInfo> sections;
    std::vector<DataDirectoryInfo> directories;
    std::vector<ImportLibrary> imports;
    std::vector<ExportInfo> exports;
    std::string exportDllName;
    std::uint32_t exportOrdinalBase = 0;
    std::vector<ResourceEntry> resources;
    std::vector<DebugEntry> debugEntries;
    TlsInfo tls;
    bool hasCertificateTable = false;
    std::uint64_t certificateTableOffset = 0;
    std::uint64_t certificateTableSize = 0;
    std::uint32_t certificateEntryCount = 0;
    bool certificateTableValid = true;
    std::uint64_t overlayOffset = 0;
    std::uint64_t overlaySize = 0;
    bool hasClrDirectory = false;
    bool hasRelocations = false;
    bool hasRichHeader = false;
};

struct SignatureInfo {
    bool checked = false;
    bool present = false;
    // True when the signature was validated through a Windows catalog rather than an
    // embedded Authenticode certificate table.
    bool catalogSigned = false;
    SignatureStatus status = SignatureStatus::NotChecked;
    std::string statusText;
    std::string subject;
    std::string issuer;
    std::string serialNumber;
    std::string notBeforeUtc;
    std::string notAfterUtc;
    bool expired = false;
    bool notYetValid = false;
    std::string digestAlgorithm;
    std::string signatureAlgorithm;
    std::string trustMessage;
    long trustStatus = 0;
    bool revocationChecked = false;
    std::vector<std::string> chain;
};

struct Finding {
    std::string id;
    std::string category;
    std::string title;
    Severity severity = Severity::Informational;
    Confidence confidence = Confidence::Low;
    std::string description;
    std::string whyItMatters;
    std::vector<std::string> evidence;
    std::vector<std::string> legitimateExplanations;
    std::vector<std::string> nextSteps;
};

struct Diagnostic {
    std::string code;
    std::string message;
    bool fatal = false;
};

struct AnalysisOptions {
    std::uint64_t maxFileSizeBytes = 256ULL * 1024ULL * 1024ULL;
    bool verifySignature = true;
    bool computeMd5 = true;
};

struct AnalysisResult {
    bool success = false;
    bool parseSuccess = false;
    std::string errorMessage;
    FileInfo file;
    PeInfo pe;
    SignatureInfo signature;
    double fileEntropy = -1.0;
    bool fileEntropyComputed = false;
    std::vector<Finding> findings;
    std::vector<Diagnostic> diagnostics;
    std::string analyzedAtUtc;
    std::uint64_t durationMs = 0;
    std::string toolVersion = kToolVersion;
    bool signatureRequested = false;
};

struct SeverityCounts {
    int informational = 0;
    int low = 0;
    int medium = 0;
    int high = 0;
    int critical = 0;

    [[nodiscard]] int total() const noexcept {
        return informational + low + medium + high + critical;
    }
};

SeverityCounts countSeverities(const std::vector<Finding>& findings);

std::string toUtf8(const std::filesystem::path& path);
std::filesystem::path fromUtf8(const std::string& utf8Path);

} // namespace explainbin
