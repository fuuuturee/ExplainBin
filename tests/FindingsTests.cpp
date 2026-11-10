#include <gtest/gtest.h>

#include "TestPeBuilder.hpp"
#include "explainbin/core/FindingsEngine.hpp"
#include "explainbin/core/ImportAnalyzer.hpp"
#include "explainbin/core/PEFormat.hpp"
#include "explainbin/core/PEParser.hpp"

#include <algorithm>
#include <string>
#include <vector>

using namespace explainbin;

namespace {

PeInfo parseDefault() {
    const auto data = testpe::build(testpe::defaultConfig(false));
    PeInfo info;
    PEParser parser;
    (void)parser.parse(data, info);
    return info;
}

AnalysisResult baseResult(const PeInfo& pe, std::uint64_t fileSize = 8192) {
    AnalysisResult result;
    result.success = true;
    result.parseSuccess = pe.parsed;
    result.pe = pe;
    result.file.size = fileSize;
    result.file.fileName = "sample.exe";
    result.file.hashes.sha256 = "abc";
    return result;
}

bool hasFinding(const std::vector<Finding>& findings, const std::string& id) {
    return std::any_of(findings.begin(), findings.end(),
                       [&id](const Finding& finding) { return finding.id == id; });
}

const Finding* findFinding(const std::vector<Finding>& findings, const std::string& id) {
    for (const auto& finding : findings) {
        if (finding.id == id) {
            return &finding;
        }
    }
    return nullptr;
}

ImportLibrary libraryWith(std::string name, std::initializer_list<const char*> functions) {
    ImportLibrary library;
    library.name = std::move(name);
    for (const auto functionName : functions) {
        ImportFunction function;
        function.name = functionName;
        library.functions.push_back(std::move(function));
    }
    return library;
}

} // namespace

TEST(FindingsEngine, WritableExecutableSectionIsHighSeverity) {
    auto pe = parseDefault();
    ASSERT_FALSE(pe.sections.empty());
    pe.sections[0].writable = true;
    const auto result = baseResult(pe);
    FindingsEngine engine;
    const auto findings = engine.evaluate(result);
    const auto* finding = findFinding(findings, "EB-SEC-001");
    ASSERT_NE(finding, nullptr);
    EXPECT_EQ(finding->severity, Severity::High);
    EXPECT_EQ(finding->confidence, Confidence::High);
    EXPECT_FALSE(finding->evidence.empty());
    EXPECT_FALSE(finding->legitimateExplanations.empty());
    EXPECT_FALSE(finding->nextSteps.empty());
}

TEST(FindingsEngine, PackerSectionNameIsReported) {
    auto pe = parseDefault();
    ASSERT_FALSE(pe.sections.empty());
    pe.sections[0].name = "UPX0";
    const auto result = baseResult(pe);
    FindingsEngine engine;
    const auto findings = engine.evaluate(result);
    EXPECT_TRUE(hasFinding(findings, "EB-SEC-003"));
}

TEST(FindingsEngine, EntryPointOutsideExecutableSections) {
    auto pe = parseDefault();
    pe.entryPointRva = 0x9000;
    const auto result = baseResult(pe);
    FindingsEngine engine;
    const auto findings = engine.evaluate(result);
    ASSERT_TRUE(hasFinding(findings, "EB-SEC-005"));
    const auto* finding = findFinding(findings, "EB-SEC-005");
    EXPECT_EQ(finding->severity, Severity::High);
}

TEST(FindingsEngine, OverlayIsInformational) {
    auto pe = parseDefault();
    pe.overlaySize = 5000;
    pe.overlayOffset = 1000;
    const auto result = baseResult(pe, 6000);
    FindingsEngine engine;
    const auto findings = engine.evaluate(result);
    const auto* finding = findFinding(findings, "EB-PE-011");
    ASSERT_NE(finding, nullptr);
    EXPECT_EQ(finding->severity, Severity::Informational);
}

TEST(FindingsEngine, ChecksumMismatchAndTlsAndPdb) {
    auto pe = parseDefault();
    pe.checksumPresent = true;
    pe.checksumValid = false;
    pe.checksum = 0x11111111;
    pe.computedChecksum = 0x22222222;
    pe.tls.present = true;
    pe.tls.callbacks = {0x1000};
    DebugEntry debug;
    debug.type = 2;
    debug.typeName = "CodeView";
    debug.pdbPath = "C:\\build\\sample.pdb";
    pe.debugEntries.push_back(debug);
    const auto result = baseResult(pe);
    FindingsEngine engine;
    const auto findings = engine.evaluate(result);
    EXPECT_TRUE(hasFinding(findings, "EB-PE-012"));
    EXPECT_TRUE(hasFinding(findings, "EB-TLS-001"));
    EXPECT_TRUE(hasFinding(findings, "EB-DBG-001"));
}

TEST(FindingsEngine, UnsignedIsNotMalicious) {
    auto pe = parseDefault();
    auto result = baseResult(pe);
    result.signatureRequested = true;
    result.signature.checked = true;
    result.signature.status = SignatureStatus::Unsigned;
    result.signature.statusText = "No embedded signature";
    FindingsEngine engine;
    const auto findings = engine.evaluate(result);
    const auto* finding = findFinding(findings, "EB-SIG-001");
    ASSERT_NE(finding, nullptr);
    EXPECT_EQ(finding->severity, Severity::Informational);
    EXPECT_LE(severityRank(finding->severity), severityRank(Severity::Low));
}

TEST(FindingsEngine, InvalidSignatureIsHighSeverity) {
    auto pe = parseDefault();
    auto result = baseResult(pe);
    result.signatureRequested = true;
    result.signature.checked = true;
    result.signature.present = true;
    result.signature.status = SignatureStatus::Invalid;
    result.signature.trustMessage = "The digital signature did not verify.";
    FindingsEngine engine;
    const auto findings = engine.evaluate(result);
    const auto* finding = findFinding(findings, "EB-SIG-003");
    ASSERT_NE(finding, nullptr);
    EXPECT_EQ(finding->severity, Severity::High);
    EXPECT_EQ(finding->confidence, Confidence::High);
}

TEST(FindingsEngine, ValidSignatureIsInformational) {
    auto pe = parseDefault();
    auto result = baseResult(pe);
    result.signatureRequested = true;
    result.signature.checked = true;
    result.signature.present = true;
    result.signature.status = SignatureStatus::Valid;
    result.signature.subject = "CN=Example Publisher";
    result.signature.issuer = "CN=Example CA";
    FindingsEngine engine;
    const auto findings = engine.evaluate(result);
    const auto* finding = findFinding(findings, "EB-SIG-002");
    ASSERT_NE(finding, nullptr);
    EXPECT_EQ(finding->severity, Severity::Informational);
}

TEST(FindingsEngine, UnparseableFileProducesCriticalFinding) {
    AnalysisResult result;
    result.success = true;
    result.parseSuccess = false;
    result.pe.parsed = false;
    result.file.size = 100;
    result.diagnostics.push_back(Diagnostic{"EB-PE-DOS", "Not MZ", true});
    FindingsEngine engine;
    const auto findings = engine.evaluate(result);
    ASSERT_EQ(findings.size(), 1U);
    EXPECT_EQ(findings[0].id, "EB-PE-001");
    EXPECT_EQ(findings[0].severity, Severity::Critical);
}

TEST(ImportAnalyzer, InjectionCombinationIsDetected) {
    PeInfo pe;
    pe.parsed = true;
    pe.imports.push_back(libraryWith("KERNEL32.dll",
                                     {"VirtualAllocEx", "WriteProcessMemory",
                                      "CreateRemoteThread"}));
    ImportAnalyzer analyzer;
    const auto findings = analyzer.analyze(pe);
    const auto* finding = findFinding(findings, "EB-IMP-001");
    ASSERT_NE(finding, nullptr);
    EXPECT_EQ(finding->severity, Severity::Medium);
    EXPECT_EQ(finding->confidence, Confidence::Medium);
    EXPECT_EQ(finding->evidence.size(), 3U);
}

TEST(ImportAnalyzer, KeyloggingCombinationIsDetected) {
    PeInfo pe;
    pe.parsed = true;
    pe.imports.push_back(libraryWith("USER32.dll",
                                     {"SetWindowsHookExW", "GetAsyncKeyState"}));
    ImportAnalyzer analyzer;
    const auto findings = analyzer.analyze(pe);
    const auto* finding = findFinding(findings, "EB-IMP-002");
    ASSERT_NE(finding, nullptr);
    EXPECT_EQ(finding->severity, Severity::Low);
    EXPECT_EQ(finding->confidence, Confidence::Low);
}

TEST(ImportAnalyzer, NormalApisAreNotAutomaticallyMalicious) {
    PeInfo pe;
    pe.parsed = true;
    pe.imports.push_back(libraryWith("KERNEL32.dll", {"CreateFileW", "ReadFile"}));
    ImportAnalyzer analyzer;
    const auto findings = analyzer.analyze(pe);
    for (const auto& finding : findings) {
        EXPECT_LT(severityRank(finding.severity), severityRank(Severity::Medium))
            << finding.id << ": " << finding.title;
    }
}

TEST(ImportAnalyzer, AnnotatesKnownAndUnknownApis) {
    PeInfo pe;
    pe.parsed = true;
    pe.imports.push_back(libraryWith("KERNEL32.dll",
                                     {"VirtualAllocEx", "CreateFileW"}));
    ImportAnalyzer analyzer;
    analyzer.annotate(pe);
    ASSERT_EQ(pe.imports[0].functions.size(), 2U);
    EXPECT_EQ(pe.imports[0].functions[0].category, "Process memory access");
    EXPECT_FALSE(pe.imports[0].functions[0].insight.empty());
    EXPECT_EQ(pe.imports[0].functions[1].category, "Windows core");
}

TEST(ImportAnalyzer, NativeNtOnlyIsNotReportedAsInjection) {
    PeInfo pe;
    pe.parsed = true;
    pe.imports.push_back(libraryWith(
        "ntdll.dll",
        {"NtAllocateVirtualMemory", "NtWriteVirtualMemory", "NtCreateThreadEx"}));
    ImportAnalyzer analyzer;
    EXPECT_FALSE(hasFinding(analyzer.analyze(pe), "EB-IMP-001"));
}

TEST(ImportAnalyzer, InjectionApiProviderIsNotReportedAsInjection) {
    PeInfo pe;
    pe.parsed = true;
    pe.imports.push_back(libraryWith("KERNEL32.dll",
                                     {"VirtualAllocEx", "WriteProcessMemory",
                                      "CreateRemoteThread"}));
    // kernel32.dll and kernelbase.dll export and import these wrappers themselves.
    for (const char* name : {"VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"}) {
        ExportInfo exportInfo;
        exportInfo.name = name;
        pe.exports.push_back(exportInfo);
    }
    ImportAnalyzer analyzer;
    EXPECT_FALSE(hasFinding(analyzer.analyze(pe), "EB-IMP-001"));
}

TEST(ImportAnalyzer, EmptyImportsOnExportingDllIsInformational) {
    PeInfo pe;
    pe.parsed = true;
    ExportInfo exportInfo;
    exportInfo.name = "RtlAllocateHeap";
    pe.exports.push_back(exportInfo);
    ImportAnalyzer analyzer;
    const auto findings = analyzer.analyze(pe);
    const auto* finding = findFinding(findings, "EB-IMP-011");
    ASSERT_NE(finding, nullptr);
    EXPECT_EQ(finding->severity, Severity::Informational);
}

TEST(ImportAnalyzer, EmptyImportsWithoutExportsIsLow) {
    PeInfo pe;
    pe.parsed = true;
    ImportAnalyzer analyzer;
    const auto findings = analyzer.analyze(pe);
    const auto* finding = findFinding(findings, "EB-IMP-011");
    ASSERT_NE(finding, nullptr);
    EXPECT_EQ(finding->severity, Severity::Low);
}

TEST(ImportAnalyzer, EmptyImportsOnManagedAssemblyIsInformational) {
    PeInfo pe;
    pe.parsed = true;
    pe.hasClrDirectory = true;
    ImportAnalyzer analyzer;
    const auto findings = analyzer.analyze(pe);
    const auto* finding = findFinding(findings, "EB-IMP-011");
    ASSERT_NE(finding, nullptr);
    EXPECT_EQ(finding->severity, Severity::Informational);
}

TEST(ImportAnalyzer, GenericGdiImportsAreInformational) {
    PeInfo pe;
    pe.parsed = true;
    pe.imports.push_back(libraryWith("GDI32.dll", {"BitBlt", "CreateCompatibleBitmap"}));
    pe.imports.push_back(libraryWith("USER32.dll", {"GetDC"}));
    ImportAnalyzer analyzer;
    const auto findings = analyzer.analyze(pe);
    const auto* finding = findFinding(findings, "EB-IMP-012");
    ASSERT_NE(finding, nullptr);
    EXPECT_EQ(finding->severity, Severity::Informational);
    EXPECT_EQ(finding->confidence, Confidence::Low);
}

TEST(FindingsEngine, TlsDirectoryWithoutCallbacksIsNotReported) {
    auto pe = parseDefault();
    pe.tls.present = true;
    pe.tls.callbacks.clear();
    FindingsEngine engine;
    EXPECT_FALSE(hasFinding(engine.evaluate(baseResult(pe)), "EB-TLS-001"));
}

TEST(FindingsEngine, RawSizeLargerThanVirtualSizeDoesNotInventOverlap) {
    auto pe = parseDefault();
    pe.sections.clear();

    SectionInfo first;
    first.name = ".text";
    first.virtualAddress = 0x1000;
    first.virtualSize = 0x100;
    first.rawSize = 0x1000;
    first.executable = true;
    first.readable = true;

    SectionInfo second;
    second.name = ".data";
    second.virtualAddress = 0x1100;
    second.virtualSize = 0x100;
    second.rawSize = 0x100;
    second.readable = true;
    second.writable = true;

    pe.sections.push_back(first);
    pe.sections.push_back(second);

    FindingsEngine engine;
    EXPECT_FALSE(hasFinding(engine.evaluate(baseResult(pe)), "EB-SEC-006"));
}

TEST(FindingsEngine, ManagedAssemblyWithoutEntryPointIsNotReported) {
    auto pe = parseDefault();
    pe.entryPointRva = 0;
    pe.isDll = false;
    pe.hasClrDirectory = true;
    FindingsEngine engine;
    EXPECT_FALSE(hasFinding(engine.evaluate(baseResult(pe)), "EB-SEC-005"));
}

TEST(FindingsEngine, NativeExecutableWithoutEntryPointIsReported) {
    auto pe = parseDefault();
    pe.entryPointRva = 0;
    pe.isDll = false;
    pe.hasClrDirectory = false;
    FindingsEngine engine;
    EXPECT_TRUE(hasFinding(engine.evaluate(baseResult(pe)), "EB-SEC-005"));
}

TEST(FindingsEngine, ZeroRawExecutablePaddingSectionIsNotReported) {
    auto pe = parseDefault();
    ASSERT_FALSE(pe.sections.empty());
    pe.sections[0].name = "Pad2";
    pe.sections[0].executable = true;
    pe.sections[0].writable = false;
    pe.sections[0].rawSize = 0;
    pe.sections[0].virtualSize = 0x1000;

    FindingsEngine engine;
    EXPECT_FALSE(hasFinding(engine.evaluate(baseResult(pe)), "EB-SEC-007"));
}

TEST(FindingsEngine, ZeroRawExecutableNonPaddingSectionIsReported) {
    auto pe = parseDefault();
    ASSERT_FALSE(pe.sections.empty());
    pe.sections[0].name = "payload";
    pe.sections[0].executable = true;
    pe.sections[0].writable = false;
    pe.sections[0].rawSize = 0;
    pe.sections[0].virtualSize = 0x1000;

    FindingsEngine engine;
    EXPECT_TRUE(hasFinding(engine.evaluate(baseResult(pe)), "EB-SEC-007"));
}

TEST(PEFormat, CommonSectionNamesAreCaseInsensitiveAndAllowSuffixes) {
    EXPECT_TRUE(pe::isCommonSectionName(".text"));
    EXPECT_TRUE(pe::isCommonSectionName(".TEXT"));
    EXPECT_TRUE(pe::isCommonSectionName(".text$mn"));
    EXPECT_TRUE(pe::isCommonSectionName("fothk"));
    EXPECT_TRUE(pe::isCommonSectionName("PAGE"));
    EXPECT_TRUE(pe::isCommonSectionName("SCPCFGES"));
    EXPECT_TRUE(pe::isCommonSectionName("Pad2"));
    EXPECT_FALSE(pe::isCommonSectionName("encrypted"));

    EXPECT_TRUE(pe::isPaddingSectionName("Pad"));
    EXPECT_TRUE(pe::isPaddingSectionName("pad12"));
    EXPECT_FALSE(pe::isPaddingSectionName("padded"));
    EXPECT_FALSE(pe::isPaddingSectionName("payload"));
}

TEST(FindingsEngine, SortingPutsCriticalFirst) {
    std::vector<Finding> findings(4);
    findings[0].id = "A";
    findings[0].severity = Severity::Low;
    findings[1].id = "B";
    findings[1].severity = Severity::Critical;
    findings[2].id = "C";
    findings[2].severity = Severity::High;
    findings[3].id = "D";
    findings[3].severity = Severity::Informational;
    FindingsEngine::sortBySeverity(findings);
    EXPECT_EQ(findings[0].id, "B");
    EXPECT_EQ(findings[1].id, "C");
    EXPECT_EQ(findings[2].id, "A");
    EXPECT_EQ(findings[3].id, "D");
}
