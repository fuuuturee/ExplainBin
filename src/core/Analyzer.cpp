#include "explainbin/core/Analyzer.hpp"

#include "explainbin/core/EntropyAnalyzer.hpp"
#include "explainbin/core/FileReader.hpp"
#include "explainbin/core/FindingsEngine.hpp"
#include "explainbin/core/HashCalculator.hpp"
#include "explainbin/core/ImportAnalyzer.hpp"
#include "explainbin/core/PEParser.hpp"
#include "explainbin/core/SignatureVerifier.hpp"
#include "explainbin/core/Util.hpp"

#include <algorithm>
#include <chrono>
#include <exception>
#include <map>
#include <set>
#include <string>
#include <vector>

namespace explainbin {
namespace {

void report(const Analyzer::ProgressCallback& progress, const std::string& stage, int percent) {
    if (progress) {
        progress(stage, percent);
    }
}

} // namespace

AnalysisResult Analyzer::analyze(const std::filesystem::path& path,
                                 const AnalysisOptions& options,
                                 const ProgressCallback& progress) const {
    const auto started = std::chrono::steady_clock::now();
    AnalysisResult result;
    result.analyzedAtUtc = util::currentUtcTimestamp();
    result.signatureRequested = options.verifySignature;
    result.file.path = toUtf8(path);
    result.file.fileName = toUtf8(path.filename());
    result.file.extension = toUtf8(path.extension());

    const auto finish = [&result, &started]() {
        const auto elapsed = std::chrono::steady_clock::now() - started;
        result.durationMs = static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count());
        result.analyzedAtUtc = util::currentUtcTimestamp();
    };

    report(progress, "Reading file", 5);
    auto file = FileReader::read(path, options.maxFileSizeBytes);
    if (!file.ok) {
        result.errorMessage = file.error;
        finish();
        report(progress, "Failed", 100);
        return result;
    }
    result.file.size = file.size;
    result.file.lastWriteTimeUtc = file.lastWriteTimeUtc;
    result.file.creationTimeUtc = file.creationTimeUtc;

    report(progress, "Computing cryptographic hashes", 15);
    auto hashes = HashCalculator::calculate(file.data, options.computeMd5);
    if (!hashes.ok) {
        result.errorMessage = "Hash calculation failed: " + hashes.error;
        finish();
        report(progress, "Failed", 100);
        return result;
    }
    result.file.hashes = hashes.hashes;

    report(progress, "Parsing PE headers and directories", 30);
    PeParseOutcome parseOutcome;
    try {
        PEParser parser;
        parseOutcome = parser.parse(file.data, result.pe);
    } catch (const std::exception& exception) {
        result.errorMessage = std::string("Unexpected parser error: ") + exception.what();
        result.diagnostics.push_back(
            Diagnostic{"EB-PE-EXCEPTION", result.errorMessage, true});
        result.parseSuccess = false;
        finish();
        report(progress, "Failed", 100);
        return result;
    }
    result.diagnostics = std::move(parseOutcome.diagnostics);
    result.parseSuccess = result.pe.parsed;

    if (result.pe.parsed) {
        report(progress, "Computing section entropy", 45);
        const auto entropy = EntropyAnalyzer::analyze(file.data, result.pe);
        result.fileEntropy = entropy.fileEntropy;
        result.fileEntropyComputed = entropy.computed;

        report(progress, "Annotating imported APIs", 55);
        ImportAnalyzer importAnalyzer;
        importAnalyzer.annotate(result.pe);

        report(progress, "Verifying digital signature", 65);
        if (options.verifySignature) {
            try {
                result.signature =
                    SignatureVerifier::verify(path, result.pe.hasCertificateTable);
            } catch (const std::exception& exception) {
                result.signature.checked = false;
                result.signature.status = SignatureStatus::Unknown;
                result.signature.statusText = "Signature verification raised an internal error.";
                result.signature.trustMessage = exception.what();
            } catch (...) {
                result.signature.checked = false;
                result.signature.status = SignatureStatus::Unknown;
                result.signature.statusText = "Signature verification raised an unknown error.";
            }
        } else {
            result.signature.checked = false;
            result.signature.status = SignatureStatus::NotChecked;
            result.signature.statusText = "Signature verification was disabled in settings.";
            result.signature.present = result.pe.hasCertificateTable;
        }

        report(progress, "Evaluating findings", 80);
        FindingsEngine engine;
        auto findings = engine.evaluate(result);
        auto importFindings = importAnalyzer.analyze(result.pe);
        findings.insert(findings.end(),
                        std::make_move_iterator(importFindings.begin()),
                        std::make_move_iterator(importFindings.end()));

        // Defensive deduplication: rules must have stable, unique IDs.
        std::set<std::string> seen;
        std::vector<Finding> uniqueFindings;
        uniqueFindings.reserve(findings.size());
        for (auto& finding : findings) {
            if (seen.insert(finding.id).second) {
                uniqueFindings.push_back(std::move(finding));
            }
        }
        FindingsEngine::sortBySeverity(uniqueFindings);
        result.findings = std::move(uniqueFindings);
    } else {
        result.signature.checked = false;
        result.signature.status = SignatureStatus::NotChecked;
        result.signature.statusText = "Not checked because the PE structure could not be parsed.";
        FindingsEngine engine;
        result.findings = engine.evaluate(result);
    }

    result.success = true;
    finish();
    report(progress, "Analysis complete", 100);
    return result;
}

} // namespace explainbin
