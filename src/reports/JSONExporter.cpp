#include "explainbin/reports/ReportExporter.hpp"

#include "explainbin/core/Util.hpp"

#include <nlohmann/json.hpp>

#include <string>

namespace explainbin {
namespace {

using json = nlohmann::ordered_json;

json sectionJson(const SectionInfo& section) {
    json value;
    value["name"] = section.name;
    value["virtualAddress"] = section.virtualAddress;
    value["virtualSize"] = section.virtualSize;
    value["rawOffset"] = section.rawOffset;
    value["rawSize"] = section.rawSize;
    value["characteristics"] = section.characteristics;
    value["entropy"] = section.entropy;
    value["readable"] = section.readable;
    value["writable"] = section.writable;
    value["executable"] = section.executable;
    value["code"] = section.code;
    value["rawRangeValid"] = section.rawRangeValid;
    return value;
}

json findingJson(const Finding& finding) {
    json value;
    value["id"] = finding.id;
    value["category"] = finding.category;
    value["title"] = finding.title;
    value["severity"] = std::string(toString(finding.severity));
    value["confidence"] = std::string(toString(finding.confidence));
    value["description"] = finding.description;
    value["whyItMatters"] = finding.whyItMatters;
    value["evidence"] = finding.evidence;
    value["possibleLegitimateExplanations"] = finding.legitimateExplanations;
    value["recommendedInvestigation"] = finding.nextSteps;
    return value;
}

json signatureJson(const SignatureInfo& signature) {
    json value;
    value["checked"] = signature.checked;
    value["present"] = signature.present;
    value["catalogSigned"] = signature.catalogSigned;
    value["status"] = std::string(toString(signature.status));
    value["statusText"] = signature.statusText;
    value["subject"] = signature.subject;
    value["issuer"] = signature.issuer;
    value["serialNumber"] = signature.serialNumber;
    value["notBeforeUtc"] = signature.notBeforeUtc;
    value["notAfterUtc"] = signature.notAfterUtc;
    value["expired"] = signature.expired;
    value["notYetValid"] = signature.notYetValid;
    value["digestAlgorithm"] = signature.digestAlgorithm;
    value["signatureAlgorithm"] = signature.signatureAlgorithm;
    value["trustMessage"] = signature.trustMessage;
    value["trustStatus"] = signature.trustStatus;
    value["revocationChecked"] = signature.revocationChecked;
    value["chain"] = signature.chain;
    return value;
}

} // namespace

std::string JSONExporter::render(const AnalysisResult& result) const {
    json report;
    report["schemaVersion"] = kReportSchemaVersion;
    report["tool"] = {
        {"name", kToolName},
        {"version", kToolVersion},
        {"analysisMode", "static-local"},
        {"disclaimer", kStaticAnalysisDisclaimer},
    };
    report["generatedAtUtc"] = util::currentUtcTimestamp();
    report["analysis"] = {
        {"success", result.success},
        {"parseSuccess", result.parseSuccess},
        {"error", result.errorMessage},
        {"durationMs", result.durationMs},
        {"signatureRequested", result.signatureRequested},
        {"fileEntropy", result.fileEntropy},
        {"fileEntropyComputed", result.fileEntropyComputed},
        {"analyzedAtUtc", result.analyzedAtUtc},
    };

    report["file"] = {
        {"path", result.file.path},
        {"fileName", result.file.fileName},
        {"extension", result.file.extension},
        {"sizeBytes", result.file.size},
        {"lastWriteTimeUtc", result.file.lastWriteTimeUtc},
        {"creationTimeUtc", result.file.creationTimeUtc},
        {"hashes", {
            {"md5", result.file.hashes.md5},
            {"sha1", result.file.hashes.sha1},
            {"sha256", result.file.hashes.sha256},
        }},
    };

    const auto counts = countSeverities(result.findings);
    report["severityCounts"] = {
        {"informational", counts.informational},
        {"low", counts.low},
        {"medium", counts.medium},
        {"high", counts.high},
        {"critical", counts.critical},
        {"total", counts.total()},
    };

    json pe;
    pe["parsed"] = result.pe.parsed;
    pe["partial"] = result.pe.partial;
    pe["format"] = result.pe.format;
    pe["is64Bit"] = result.pe.is64Bit;
    pe["isDll"] = result.pe.isDll;
    pe["machine"] = result.pe.machine;
    pe["machineName"] = result.pe.machineName;
    pe["subsystem"] = result.pe.subsystem;
    pe["subsystemName"] = result.pe.subsystemName;
    pe["entryPointRva"] = result.pe.entryPointRva;
    pe["imageBase"] = result.pe.imageBase;
    pe["sectionAlignment"] = result.pe.sectionAlignment;
    pe["fileAlignment"] = result.pe.fileAlignment;
    pe["sizeOfImage"] = result.pe.sizeOfImage;
    pe["sizeOfHeaders"] = result.pe.sizeOfHeaders;
    pe["checksum"] = result.pe.checksum;
    pe["computedChecksum"] = result.pe.computedChecksum;
    pe["checksumPresent"] = result.pe.checksumPresent;
    pe["checksumValid"] = result.pe.checksumValid;
    pe["timestamp"] = result.pe.timestamp;
    pe["timestampUtc"] = result.pe.timestampUtc;
    pe["characteristics"] = result.pe.characteristics;
    pe["dllCharacteristics"] = result.pe.dllCharacteristics;
    pe["linkerVersion"] = result.pe.linkerVersion;
    pe["osVersion"] = result.pe.osVersion;
    pe["subsystemVersion"] = result.pe.subsystemVersion;
    pe["numberOfSections"] = result.pe.numberOfSections;
    pe["numberOfRvaAndSizes"] = result.pe.numberOfRvaAndSizes;
    pe["hasClrDirectory"] = result.pe.hasClrDirectory;
    pe["hasRelocations"] = result.pe.hasRelocations;
    pe["hasRichHeader"] = result.pe.hasRichHeader;
    pe["overlay"] = {
        {"offset", result.pe.overlayOffset},
        {"size", result.pe.overlaySize},
    };
    pe["certificateTable"] = {
        {"present", result.pe.hasCertificateTable},
        {"offset", result.pe.certificateTableOffset},
        {"size", result.pe.certificateTableSize},
        {"entryCount", result.pe.certificateEntryCount},
        {"valid", result.pe.certificateTableValid},
    };

    json sections = json::array();
    for (const auto& section : result.pe.sections) {
        sections.push_back(sectionJson(section));
    }
    pe["sections"] = std::move(sections);

    json directories = json::array();
    for (const auto& directory : result.pe.directories) {
        directories.push_back({
            {"index", directory.index},
            {"name", directory.name},
            {"rva", directory.rva},
            {"size", directory.size},
            {"present", directory.present},
            {"valid", directory.valid},
            {"note", directory.note},
        });
    }
    pe["dataDirectories"] = std::move(directories);

    json imports = json::array();
    for (const auto& library : result.pe.imports) {
        json functions = json::array();
        for (const auto& function : library.functions) {
            functions.push_back({
                {"name", function.name},
                {"ordinal", function.ordinal},
                {"byOrdinal", function.byOrdinal},
                {"hint", function.hint},
                {"category", function.category},
                {"insight", function.insight},
            });
        }
        imports.push_back({
            {"name", library.name},
            {"delayLoad", library.delayLoad},
            {"functionCount", library.functions.size()},
            {"functions", std::move(functions)},
        });
    }
    pe["imports"] = std::move(imports);

    json exports = json::array();
    for (const auto& exportInfo : result.pe.exports) {
        exports.push_back({
            {"name", exportInfo.name},
            {"ordinal", exportInfo.ordinal},
            {"rva", exportInfo.rva},
            {"forwarder", exportInfo.forwarder},
            {"forwarderName", exportInfo.forwarderName},
        });
    }
    pe["exports"] = std::move(exports);
    pe["exportDllName"] = result.pe.exportDllName;
    pe["exportOrdinalBase"] = result.pe.exportOrdinalBase;

    json resources = json::array();
    for (const auto& resource : result.pe.resources) {
        resources.push_back({
            {"type", resource.type},
            {"name", resource.name},
            {"language", resource.language},
            {"dataRva", resource.dataRva},
            {"size", resource.size},
            {"fileOffset", resource.fileOffset},
            {"dataValid", resource.dataValid},
        });
    }
    pe["resources"] = std::move(resources);

    json debug = json::array();
    for (const auto& entry : result.pe.debugEntries) {
        debug.push_back({
            {"type", entry.type},
            {"typeName", entry.typeName},
            {"dataSize", entry.dataSize},
            {"rawOffset", entry.rawOffset},
            {"rawOffsetValid", entry.rawOffsetValid},
            {"pdbPath", entry.pdbPath},
            {"guid", entry.guid},
            {"age", entry.age},
        });
    }
    pe["debugEntries"] = std::move(debug);

    pe["tls"] = {
        {"present", result.pe.tls.present},
        {"callbacksPresent", result.pe.tls.callbacksPresent},
        {"imageBase", result.pe.tls.imageBase},
        {"addressOfCallbacks", result.pe.tls.addressOfCallbacks},
        {"sizeOfZeroFill", result.pe.tls.sizeOfZeroFill},
        {"characteristics", result.pe.tls.characteristics},
        {"callbacks", result.pe.tls.callbacks},
    };
    report["pe"] = std::move(pe);

    report["signature"] = signatureJson(result.signature);

    json findings = json::array();
    for (const auto& finding : result.findings) {
        findings.push_back(findingJson(finding));
    }
    report["findings"] = std::move(findings);

    json diagnostics = json::array();
    for (const auto& diagnostic : result.diagnostics) {
        diagnostics.push_back({
            {"code", diagnostic.code},
            {"message", diagnostic.message},
            {"fatal", diagnostic.fatal},
        });
    }
    report["diagnostics"] = std::move(diagnostics);

    return report.dump(2) + "\n";
}

} // namespace explainbin
