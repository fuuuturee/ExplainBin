#include "explainbin/reports/ReportExporter.hpp"

#include "explainbin/core/Util.hpp"

#include <sstream>
#include <string>

namespace explainbin {
namespace {

void line(std::ostringstream& out, std::string_view label, std::string_view value) {
    out << "  " << label;
    const std::size_t width = label.size() < 22 ? 22 - label.size() : 0;
    out << std::string(width, ' ') << ": " << value << "\n";
}

} // namespace

std::string TextExporter::render(const AnalysisResult& result) const {
    std::ostringstream out;
    const auto counts = countSeverities(result.findings);

    out << "ExplainBin " << kToolVersion << " - static analysis report\n"
        << "Generated: " << util::currentUtcTimestamp() << " (UTC)\n"
        << "Analyzed:  " << result.analyzedAtUtc << " (UTC)\n\n";

    out << "FILE\n";
    line(out, "Path", result.file.path);
    line(out, "Name", result.file.fileName);
    line(out, "Size", util::humanBytes(result.file.size) + " (" +
                             std::to_string(result.file.size) + " bytes)");
    line(out, "Last write (UTC)", result.file.lastWriteTimeUtc);
    out << "\nHASHES\n";
    line(out, "SHA-256", result.file.hashes.sha256);
    line(out, "SHA-1", result.file.hashes.sha1);
    line(out, "MD5", result.file.hashes.md5.empty() ? "(not computed)" : result.file.hashes.md5);

    out << "\nANALYSIS\n";
    line(out, "Result", result.success ? "completed" : "failed");
    line(out, "PE parsed", result.parseSuccess ? "yes" : "no");
    if (!result.errorMessage.empty()) {
        line(out, "Error", result.errorMessage);
    }
    line(out, "Duration", std::to_string(result.durationMs) + " ms");
    if (result.pe.parsed) {
        line(out, "Format", result.pe.format);
        line(out, "Subsystem", result.pe.subsystemName);
        line(out, "Entry point RVA", util::toHex(result.pe.entryPointRva));
        line(out, "Image base", util::toHex(result.pe.imageBase));
        line(out, "Compile time", result.pe.timestampUtc.empty() ? "(zero or unavailable)"
                                                                 : result.pe.timestampUtc);
        line(out, "Sections", std::to_string(result.pe.sections.size()) + " parsed / " +
                                  std::to_string(result.pe.numberOfSections) + " declared");
        line(out, "Overlay", util::humanBytes(result.pe.overlaySize));
    }
    line(out, "Signature", toString(result.signature.status));
    if (result.signature.catalogSigned) {
        line(out, "Signature type", "Windows catalog (no embedded signature)");
    } else if (result.signature.present) {
        line(out, "Signature type", "Embedded Authenticode");
    }
    line(out, "Signature detail", result.signature.statusText);

    out << "\nSEVERITY COUNTS (observations, not a malware score)\n";
    line(out, "Informational", std::to_string(counts.informational));
    line(out, "Low", std::to_string(counts.low));
    line(out, "Medium", std::to_string(counts.medium));
    line(out, "High", std::to_string(counts.high));
    line(out, "Critical", std::to_string(counts.critical));
    line(out, "Total", std::to_string(counts.total()));

    out << "\nFINDINGS (" << result.findings.size() << ")\n";
    if (result.findings.empty()) {
        out << "  No findings matched the enabled rules. This does not prove the file is safe.\n";
    }
    for (const auto& finding : result.findings) {
        out << "\n[" << toString(finding.severity) << " | confidence "
            << toString(finding.confidence) << "] " << finding.id << " - " << finding.title
            << "\n  Category: " << finding.category << "\n"
            << "  What was observed: " << finding.description << "\n"
            << "  Why it matters: " << finding.whyItMatters << "\n";
        out << "  Technical evidence:\n";
        if (finding.evidence.empty()) {
            out << "    - (none recorded)\n";
        }
        for (const auto& evidence : finding.evidence) {
            out << "    - " << evidence << "\n";
        }
        out << "  Possible legitimate explanations:\n";
        if (finding.legitimateExplanations.empty()) {
            out << "    - (none recorded)\n";
        }
        for (const auto& explanation : finding.legitimateExplanations) {
            out << "    - " << explanation << "\n";
        }
        out << "  Recommended investigation:\n";
        if (finding.nextSteps.empty()) {
            out << "    - (none recorded)\n";
        }
        for (const auto& step : finding.nextSteps) {
            out << "    - " << step << "\n";
        }
    }

    if (result.pe.parsed) {
        out << "\nSECTIONS\n";
        out << "  Name        VirtualAddr  VirtualSize  RawSize  Entropy  Permissions\n";
        for (const auto& section : result.pe.sections) {
            std::string permissions;
            if (section.readable) permissions += "R";
            if (section.writable) permissions += "W";
            if (section.executable) permissions += "X";
            out << "  " << section.name;
            if (section.name.size() < 11) {
                out << std::string(11 - section.name.size(), ' ');
            }
            out << util::toHex(section.virtualAddress) << "  " << section.virtualSize << "  "
                << section.rawSize << "  ";
            if (section.entropy >= 0.0) {
                out << section.entropy;
            } else {
                out << "n/a";
            }
            out << "  " << (permissions.empty() ? "-" : permissions) << "\n";
        }

        std::size_t functionCount = 0;
        for (const auto& library : result.pe.imports) {
            functionCount += library.functions.size();
        }
        out << "\nIMPORTS\n";
        line(out, "Libraries", std::to_string(result.pe.imports.size()));
        line(out, "Functions", std::to_string(functionCount));
        for (const auto& library : result.pe.imports) {
            out << "  - " << library.name << " (" << library.functions.size()
                << (library.delayLoad ? ", delay-load" : "") << ")\n";
        }
        if (!result.pe.exports.empty()) {
            out << "\nEXPORTS (" << result.pe.exports.size() << " named)\n";
            std::size_t shown = 0;
            for (const auto& exportInfo : result.pe.exports) {
                if (shown++ >= 200) {
                    out << "  ... output truncated\n";
                    break;
                }
                out << "  " << exportInfo.name << " (ordinal " << exportInfo.ordinal << ")\n";
            }
        }
    }

    if (!result.diagnostics.empty()) {
        out << "\nPARSER DIAGNOSTICS\n";
        for (const auto& diagnostic : result.diagnostics) {
            out << "  " << diagnostic.code << (diagnostic.fatal ? " [fatal]" : "") << ": "
                << diagnostic.message << "\n";
        }
    }

    out << "\nDISCLAIMER\n  " << kStaticAnalysisDisclaimer << "\n"
        << "  A valid signature indicates provenance and integrity, not safety. "
           "No file was executed or uploaded.\n";
    return out.str();
}

} // namespace explainbin
