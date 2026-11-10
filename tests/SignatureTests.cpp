#include <gtest/gtest.h>

#include "TestPeBuilder.hpp"
#include "explainbin/core/SignatureVerifier.hpp"

#include <windows.h>

#include <atomic>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

using namespace explainbin;

namespace {

std::filesystem::path writeTemp(const std::vector<std::uint8_t>& bytes,
                                const std::wstring& extension) {
    static std::atomic<unsigned> counter{0};
    const std::wstring name = L"explainbin_sig_" +
                              std::to_wstring(::GetCurrentProcessId()) + L"_" +
                              std::to_wstring(counter.fetch_add(1)) + extension;
    const auto path = std::filesystem::temp_directory_path() / name;
    std::ofstream stream(path, std::ios::binary | std::ios::trunc);
    stream.write(reinterpret_cast<const char*>(bytes.data()),
                 static_cast<std::streamsize>(bytes.size()));
    return path;
}

} // namespace

TEST(SignatureVerifier, UnsignedSyntheticPeIsNotValid) {
    const auto bytes = testpe::build(testpe::defaultConfig(false));
    ASSERT_FALSE(bytes.empty());
    const auto path = writeTemp(bytes, L".exe");

    const auto info = SignatureVerifier::verify(path, false);
    std::error_code error;
    std::filesystem::remove(path, error);

    EXPECT_TRUE(info.checked);
    EXPECT_FALSE(info.present);
    EXPECT_NE(info.status, SignatureStatus::Valid);
    EXPECT_FALSE(info.revocationChecked);
}

TEST(SignatureVerifier, NonExistentFileDoesNotCrash) {
    const auto info = SignatureVerifier::verify(
        std::filesystem::temp_directory_path() / "explainbin_missing_signature.exe", false);
    EXPECT_TRUE(info.checked);
    EXPECT_NE(info.status, SignatureStatus::Valid);
}

TEST(SignatureVerifier, ClaimsCertificateTableButFileIsNotSigned) {
    const auto bytes = testpe::build(testpe::defaultConfig(false));
    const auto path = writeTemp(bytes, L".exe");

    const auto info = SignatureVerifier::verify(path, true);
    std::error_code error;
    std::filesystem::remove(path, error);

    EXPECT_TRUE(info.checked);
    EXPECT_TRUE(info.present);
    // Windows rejects the certificate table, but ExplainBin must not claim a
    // valid signer for a file that has no usable Authenticode signature.
    EXPECT_NE(info.status, SignatureStatus::Valid);
    EXPECT_FALSE(info.trustMessage.empty());
}
