#include "explainbin/core/Analyzer.hpp"
#include "explainbin/reports/ReportExporter.hpp"
#include "explainbin/reports/ReportUtil.hpp"

#include <windows.h>

#include <filesystem>
#include <iostream>
#include <optional>
#include <string>
#include <vector>

namespace {

struct Arguments {
    std::filesystem::path input;
    std::optional<std::filesystem::path> json;
    std::optional<std::filesystem::path> html;
    std::optional<std::filesystem::path> text;
    bool noSignature = false;
    std::uint64_t maxSizeMb = 256;
    bool showHelp = false;
    bool showVersion = false;
};

void printUsage() {
    std::wcout
        << L"ExplainBin " << explainbin::kToolVersion << L" - local static PE analyzer\n\n"
        << L"Usage:\n"
        << L"  explainbin-cli <file.exe|file.dll> [options]\n\n"
        << L"Options:\n"
        << L"  --json <path>      Write a JSON report\n"
        << L"  --html <path>      Write a self-contained HTML report\n"
        << L"  --text <path>      Write a plain-text report\n"
        << L"  --no-signature     Skip Authenticode verification\n"
        << L"  --max-size <MB>    Maximum input size in MiB (default: 256)\n"
        << L"  --help             Show this help\n"
        << L"  --version          Show the version\n\n"
        << L"If no report path is supplied, the text report is printed to stdout.\n"
        << L"The analyzed file is never executed, loaded, or uploaded.\n";
}

void printUtf8(const std::string& text) {
    if (text.empty()) {
        return;
    }
    const int required = MultiByteToWideChar(CP_UTF8, 0, text.data(),
                                             static_cast<int>(text.size()), nullptr, 0);
    if (required <= 0) {
        std::cout << text;
        return;
    }
    std::wstring wide(static_cast<std::size_t>(required), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()),
                        wide.data(), required);
    std::wcout << wide;
}

bool parseArguments(int argc, wchar_t** argv, Arguments& arguments) {
    if (argc < 2) {
        return false;
    }
    for (int index = 1; index < argc; ++index) {
        const std::wstring value = argv[index];
        if (value == L"--help" || value == L"-h") {
            arguments.showHelp = true;
            continue;
        }
        if (value == L"--version") {
            arguments.showVersion = true;
            continue;
        }
        if (value == L"--no-signature") {
            arguments.noSignature = true;
            continue;
        }
        if (value == L"--json" || value == L"--html" || value == L"--text" ||
            value == L"--max-size") {
            if (index + 1 >= argc) {
                std::wcerr << L"Missing value for " << value << L"\n";
                return false;
            }
            const std::wstring next = argv[++index];
            if (value == L"--json") {
                arguments.json = std::filesystem::path(next);
            } else if (value == L"--html") {
                arguments.html = std::filesystem::path(next);
            } else if (value == L"--text") {
                arguments.text = std::filesystem::path(next);
            } else {
                std::size_t consumed = 0;
                try {
                    arguments.maxSizeMb = std::stoull(next, &consumed);
                } catch (const std::exception&) {
                    std::wcerr << L"Invalid value for --max-size.\n";
                    return false;
                }
                if (consumed != next.size()) {
                    std::wcerr << L"Invalid value for --max-size.\n";
                    return false;
                }
                if (arguments.maxSizeMb == 0 || arguments.maxSizeMb > 4096) {
                    std::wcerr << L"--max-size must be between 1 and 4096 MiB.\n";
                    return false;
                }
            }
            continue;
        }
        if (!value.empty() && value[0] == L'-') {
            std::wcerr << L"Unknown option: " << value << L"\n";
            return false;
        }
        if (!arguments.input.empty()) {
            std::wcerr << L"Only one input file can be analyzed per invocation.\n";
            return false;
        }
        arguments.input = std::filesystem::path(value);
    }
    return !arguments.input.empty() || arguments.showHelp || arguments.showVersion;
}

bool writeReport(const explainbin::IReportExporter& exporter,
                 const std::filesystem::path& path,
                 const explainbin::AnalysisResult& result) {
    std::string error;
    if (!explainbin::writeReportFile(path, exporter.render(result), error)) {
        std::wcerr << L"Failed to write " << path.wstring() << L": ";
        printUtf8(error);
        std::wcerr << L"\n";
        return false;
    }
    std::wcout << L"Report written: " << path.wstring() << L"\n";
    return true;
}

} // namespace

int wmain(int argc, wchar_t** argv) {
    Arguments arguments;
    if (!parseArguments(argc, argv, arguments)) {
        printUsage();
        return 2;
    }
    if (arguments.showVersion) {
        std::wcout << L"ExplainBin " << explainbin::kToolVersion << L"\n";
        return 0;
    }
    if (arguments.showHelp) {
        printUsage();
        return 0;
    }

    explainbin::AnalysisOptions options;
    options.maxFileSizeBytes = arguments.maxSizeMb * 1024ULL * 1024ULL;
    options.verifySignature = !arguments.noSignature;

    explainbin::Analyzer analyzer;
    const auto result = analyzer.analyze(arguments.input, options);

    if (!result.success) {
        std::wcerr << L"Analysis failed: ";
        printUtf8(result.errorMessage);
        std::wcerr << L"\n";
        return 3;
    }

    const auto counts = explainbin::countSeverities(result.findings);
    std::wcout << L"\nExplainBin analysis: " << arguments.input.wstring() << L"\n"
               << L"  SHA-256: " << result.file.hashes.sha256.c_str() << L"\n"
               << L"  Findings: " << counts.total() << L" ("
               << counts.critical << L" critical, " << counts.high << L" high, "
               << counts.medium << L" medium, " << counts.low << L" low, "
               << counts.informational << L" informational)\n"
               << L"  Signature: " << explainbin::toString(result.signature.status).data()
               << L"\n\n";

    bool wroteAny = false;
    if (arguments.json) {
        wroteAny = true;
        if (!writeReport(explainbin::JSONExporter{}, *arguments.json, result)) {
            return 4;
        }
    }
    if (arguments.html) {
        wroteAny = true;
        if (!writeReport(explainbin::HTMLExporter{}, *arguments.html, result)) {
            return 4;
        }
    }
    if (arguments.text) {
        wroteAny = true;
        if (!writeReport(explainbin::TextExporter{}, *arguments.text, result)) {
            return 4;
        }
    }
    if (!wroteAny) {
        printUtf8(explainbin::TextExporter{}.render(result));
    }

    std::wcout << L"\n" << explainbin::kStaticAnalysisDisclaimer << L"\n";
    return 0;
}
