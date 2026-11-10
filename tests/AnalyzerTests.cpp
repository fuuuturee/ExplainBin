#include <gtest/gtest.h>

#include "TestPeBuilder.hpp"
#include "explainbin/core/Analyzer.hpp"
#include "explainbin/core/HashCalculator.hpp"

#include <windows.h>

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

using namespace explainbin;

namespace {

class TempFile {
public:
    explicit TempFile(const std::vector<std::uint8_t>& bytes,
                      const std::wstring& extension = L".exe") {
        static std::atomic<unsigned> counter{0};
        const std::wstring name = L"explainbin_test_" +
                                  std::to_wstring(::GetCurrentProcessId()) + L"_" +
                                  std::to_wstring(counter.fetch_add(1)) + extension;
        path_ = std::filesystem::temp_directory_path() / name;
        std::ofstream stream(path_, std::ios::binary | std::ios::trunc);
        stream.write(reinterpret_cast<const char*>(bytes.data()),
                     static_cast<std::streamsize>(bytes.size()));
    }

    ~TempFile() {
        std::error_code error;
        std::filesystem::remove(path_, error);
    }

    TempFile(const TempFile&) = delete;
    TempFile& operator=(const TempFile&) = delete;

    [[nodiscard]] const std::filesystem::path& path() const { return path_; }

private:
    std::filesystem::path path_;
};

} // namespace

TEST(Analyzer, AnalyzesSyntheticPeEndToEnd) {
    const auto bytes = testpe::build(testpe::importConfig(false));
    ASSERT_FALSE(bytes.empty());
    const TempFile file(bytes);

    Analyzer analyzer;
    AnalysisOptions options;
    options.verifySignature = false;
    const auto result = analyzer.analyze(file.path(), options);

    ASSERT_TRUE(result.success) << result.errorMessage;
    EXPECT_TRUE(result.parseSuccess);
    EXPECT_EQ(result.file.size, bytes.size());
    EXPECT_EQ(result.file.fileName, toUtf8(file.path().filename()));
    EXPECT_TRUE(result.parseSuccess);
    EXPECT_TRUE(result.pe.parsed);
    EXPECT_EQ(result.file.hashes.sha256, HashCalculator::calculate(bytes).hashes.sha256);
    EXPECT_EQ(result.signature.status, SignatureStatus::NotChecked);
    EXPECT_FALSE(result.signatureRequested);
    // Signature verification was disabled, so neither a valid nor an unsigned
    // signature finding should be emitted (see Analyzer.DisabledSignatureIsNotReportedAsUnsigned).
    EXPECT_EQ(result.findings.end(),
              std::find_if(result.findings.begin(), result.findings.end(),
                           [](const Finding& finding) {
                               return finding.id.rfind("EB-SIG-", 0) == 0;
                           }));
    ASSERT_FALSE(result.pe.imports.empty());
    EXPECT_EQ(result.pe.imports.front().name, "KERNEL32.dll");
    EXPECT_FALSE(result.pe.imports.front().functions.empty());
    EXPECT_FALSE(result.pe.imports.front().functions.front().category.empty());
}

TEST(Analyzer, ReportsUnparseableFileAsFinding) {
    const std::vector<std::uint8_t> bytes(256, 'X');
    const TempFile file(bytes, L".bin");

    Analyzer analyzer;
    AnalysisOptions options;
    options.verifySignature = false;
    const auto result = analyzer.analyze(file.path(), options);

    EXPECT_TRUE(result.success);
    EXPECT_FALSE(result.parseSuccess);
    EXPECT_FALSE(result.pe.parsed);
    ASSERT_FALSE(result.findings.empty());
    EXPECT_EQ(result.findings.front().id, "EB-PE-001");
    EXPECT_EQ(result.findings.front().severity, Severity::Critical);
}

TEST(Analyzer, MissingFileFailsGracefully) {
    Analyzer analyzer;
    AnalysisOptions options;
    options.verifySignature = false;
    const auto result =
        analyzer.analyze(std::filesystem::temp_directory_path() / "explainbin_does_not_exist_12345.exe",
                         options);
    EXPECT_FALSE(result.success);
    EXPECT_FALSE(result.errorMessage.empty());
    EXPECT_FALSE(result.parseSuccess);
}

TEST(Analyzer, RespectsSizeLimit) {
    const std::vector<std::uint8_t> bytes(8192, 0);
    const TempFile file(bytes);

    Analyzer analyzer;
    AnalysisOptions options;
    options.verifySignature = false;
    options.maxFileSizeBytes = 1024;
    const auto result = analyzer.analyze(file.path(), options);

    EXPECT_FALSE(result.success);
    EXPECT_NE(result.errorMessage.find("limit"), std::string::npos) << result.errorMessage;
}

TEST(Analyzer, ReportsProgressMonotonically) {
    const auto bytes = testpe::build(testpe::defaultConfig(false));
    const TempFile file(bytes);

    Analyzer analyzer;
    AnalysisOptions options;
    options.verifySignature = false;
    std::vector<int> percents;
    std::vector<std::string> stages;
    const auto result = analyzer.analyze(file.path(), options,
        [&](const std::string& stage, int percent) {
            stages.push_back(stage);
            percents.push_back(percent);
        });

    ASSERT_TRUE(result.success);
    EXPECT_FALSE(stages.empty());
    ASSERT_FALSE(percents.empty());
    EXPECT_EQ(percents.front(), 5);
    EXPECT_EQ(percents.back(), 100);
    for (std::size_t index = 1; index < percents.size(); ++index) {
        EXPECT_GE(percents[index], percents[index - 1]);
    }
}

TEST(Analyzer, DisabledSignatureIsNotReportedAsUnsigned) {
    const auto bytes = testpe::build(testpe::defaultConfig(false));
    const TempFile file(bytes);

    Analyzer analyzer;
    AnalysisOptions options;
    options.verifySignature = false;
    const auto result = analyzer.analyze(file.path(), options);

    ASSERT_TRUE(result.success);
    EXPECT_TRUE(result.signature.statusText.find("disabled") != std::string::npos);
    EXPECT_TRUE(std::none_of(result.findings.begin(), result.findings.end(),
                             [](const Finding& finding) {
                                 return finding.id.rfind("EB-SIG-", 0) == 0;
                             }));
}
