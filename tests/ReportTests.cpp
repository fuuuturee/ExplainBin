#include <gtest/gtest.h>

#include "TestPeBuilder.hpp"
#include "explainbin/core/Analyzer.hpp"
#include "explainbin/reports/ReportExporter.hpp"

#include <nlohmann/json.hpp>

#include <windows.h>

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

using namespace explainbin;
using json = nlohmann::json;

namespace {

std::filesystem::path writeTemp(const std::vector<std::uint8_t>& bytes) {
    static std::atomic<unsigned> counter{0};
    const auto path = std::filesystem::temp_directory_path() /
                      ("explainbin_report_" + std::to_string(::GetCurrentProcessId()) + "_" +
                       std::to_string(counter.fetch_add(1)) + ".exe");
    std::ofstream stream(path, std::ios::binary | std::ios::trunc);
    stream.write(reinterpret_cast<const char*>(bytes.data()),
                 static_cast<std::streamsize>(bytes.size()));
    return path;
}

AnalysisResult analyzeSample() {
    const auto bytes = testpe::build(testpe::importConfig(false));
    const auto path = writeTemp(bytes);
    Analyzer analyzer;
    AnalysisOptions options;
    options.verifySignature = false;
    auto result = analyzer.analyze(path, options);
    std::error_code error;
    std::filesystem::remove(path, error);
    return result;
}

AnalysisResult syntheticResult() {
    AnalysisResult result;
    result.success = true;
    result.parseSuccess = true;
    result.pe.parsed = true;
    result.pe.format = "PE32 (x86)";
    result.pe.machineName = "x86";
    result.pe.subsystemName = "Windows Console";
    result.file.fileName = "<script>alert(\"x\")</script>.exe";
    result.file.path = "C:\\samples\\<b>weird</b>.exe";
    result.file.size = 4096;
    result.file.hashes.sha256 = "deadbeef";
    result.file.hashes.sha1 = "cafebabe";
    result.file.hashes.md5 = "feedface";
    result.durationMs = 12;
    result.analyzedAtUtc = "2026-01-01T00:00:00Z";

    Finding finding;
    finding.id = "EB-TEST-1";
    finding.category = "Test";
    finding.title = "Test finding <unsafe>";
    finding.severity = Severity::Medium;
    finding.confidence = Confidence::Medium;
    finding.description = "Observed <value> & more.";
    finding.whyItMatters = "Because <reasons>.";
    finding.evidence = {"evidence <one>"};
    finding.legitimateExplanations = {"maybe <fine>"};
    finding.nextSteps = {"check \"it\""};
    result.findings.push_back(std::move(finding));
    return result;
}

} // namespace

TEST(Reports, JsonContainsSchemaAndFindings) {
    const auto result = analyzeSample();
    ASSERT_TRUE(result.success) << result.errorMessage;

    const auto text = JSONExporter{}.render(result);
    const auto document = json::parse(text);

    EXPECT_EQ(document["schemaVersion"], kReportSchemaVersion);
    EXPECT_EQ(document["tool"]["name"], kToolName);
    EXPECT_EQ(document["tool"]["analysisMode"], "static-local");
    EXPECT_EQ(document["analysis"]["success"], true);
    EXPECT_EQ(document["analysis"]["parseSuccess"], true);
    EXPECT_EQ(document["file"]["sizeBytes"], result.file.size);
    EXPECT_EQ(document["file"]["hashes"]["sha256"], result.file.hashes.sha256);
    ASSERT_TRUE(document["pe"]["parsed"].get<bool>());
    EXPECT_EQ(document["pe"]["machineName"], "x86");
    ASSERT_TRUE(document["pe"]["imports"].is_array());
    ASSERT_FALSE(document["pe"]["imports"].empty());
    EXPECT_EQ(document["pe"]["imports"][0]["name"], "KERNEL32.dll");
    EXPECT_TRUE(document["findings"].is_array());
    EXPECT_TRUE(document["diagnostics"].is_array());
    EXPECT_EQ(document["severityCounts"]["total"].get<int>(),
              static_cast<int>(result.findings.size()));
}

TEST(Reports, JsonFindingHasExplainabilityFields) {
    const auto result = syntheticResult();
    const auto document = json::parse(JSONExporter{}.render(result));
    ASSERT_EQ(document["findings"].size(), 1U);
    const auto& finding = document["findings"][0];
    EXPECT_EQ(finding["id"], "EB-TEST-1");
    EXPECT_EQ(finding["severity"], "Medium");
    EXPECT_EQ(finding["confidence"], "Medium");
    EXPECT_TRUE(finding.contains("whyItMatters"));
    EXPECT_TRUE(finding.contains("evidence"));
    EXPECT_TRUE(finding.contains("possibleLegitimateExplanations"));
    EXPECT_TRUE(finding.contains("recommendedInvestigation"));
}

TEST(Reports, CatalogSignatureIsRepresentedInAllFormats) {
    auto result = syntheticResult();
    result.signatureRequested = true;
    result.signature.checked = true;
    result.signature.catalogSigned = true;
    result.signature.status = SignatureStatus::Valid;
    result.signature.statusText = "Valid catalog signature (the file has no embedded signature).";

    const auto document = json::parse(JSONExporter{}.render(result));
    EXPECT_TRUE(document["signature"]["catalogSigned"].get<bool>());
    EXPECT_EQ(document["signature"]["present"], false);
    EXPECT_EQ(document["signature"]["status"], "Valid");

    const auto text = TextExporter{}.render(result);
    EXPECT_NE(text.find("Windows catalog"), std::string::npos);

    const auto html = HTMLExporter{}.render(result);
    EXPECT_NE(html.find("Windows catalog"), std::string::npos);
}

TEST(Reports, JsonIsValidForUnparseableResult) {
    AnalysisResult result;
    result.success = true;
    result.parseSuccess = false;
    result.file.fileName = "broken.exe";
    result.file.size = 10;
    const auto document = json::parse(JSONExporter{}.render(result));
    EXPECT_EQ(document["pe"]["parsed"], false);
    EXPECT_EQ(document["findings"].size(), 0U);
}

TEST(Reports, HtmlEscapesUntrustedContent) {
    const auto result = syntheticResult();
    const auto html = HTMLExporter{}.render(result);

    EXPECT_EQ(html.find("<script>alert"), std::string::npos);
    EXPECT_EQ(html.find("<b>weird</b>"), std::string::npos);
    EXPECT_NE(html.find("&lt;script&gt;"), std::string::npos);
    EXPECT_NE(html.find("&quot;x&quot;"), std::string::npos);
    EXPECT_NE(html.find("<!doctype html>"), std::string::npos);
    EXPECT_NE(html.find("Static analysis is not a malware verdict"), std::string::npos);
    EXPECT_NE(html.find("no file was executed or uploaded"), std::string::npos);
}

TEST(Reports, HtmlContainsSectionsAndFindings) {
    const auto result = analyzeSample();
    ASSERT_TRUE(result.success);
    const auto html = HTMLExporter{}.render(result);
    EXPECT_NE(html.find("Findings"), std::string::npos);
    EXPECT_NE(html.find(".text"), std::string::npos);
    EXPECT_NE(html.find("Digital signature"), std::string::npos);
    EXPECT_NE(html.find("SHA-256"), std::string::npos);
    EXPECT_NE(html.find(result.file.hashes.sha256), std::string::npos);
}

TEST(Reports, TextContainsDisclaimerAndFindingDetails) {
    const auto result = syntheticResult();
    const auto text = TextExporter{}.render(result);
    EXPECT_NE(text.find("ExplainBin"), std::string::npos);
    EXPECT_NE(text.find("EB-TEST-1"), std::string::npos);
    EXPECT_NE(text.find("What was observed"), std::string::npos);
    EXPECT_NE(text.find("Why it matters"), std::string::npos);
    EXPECT_NE(text.find("Possible legitimate explanations"), std::string::npos);
    EXPECT_NE(text.find("Recommended investigation"), std::string::npos);
    EXPECT_NE(text.find(kStaticAnalysisDisclaimer), std::string::npos);
}
