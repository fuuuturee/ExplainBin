#include "explainbin/core/HashCalculator.hpp"

#include "explainbin/core/Util.hpp"

#include <windows.h>
#include <bcrypt.h>

#include <algorithm>
#include <memory>
#include <system_error>
#include <vector>

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

namespace explainbin {
namespace {

struct AlgorithmCloser {
    void operator()(BCRYPT_ALG_HANDLE handle) const noexcept {
        if (handle != nullptr) {
            BCryptCloseAlgorithmProvider(handle, 0);
        }
    }
};

struct HashCloser {
    void operator()(BCRYPT_HASH_HANDLE handle) const noexcept {
        if (handle != nullptr) {
            BCryptDestroyHash(handle);
        }
    }
};

using UniqueAlgorithm = std::unique_ptr<void, AlgorithmCloser>;
using UniqueHash = std::unique_ptr<void, HashCloser>;

std::string ntStatusMessage(NTSTATUS status) {
    return "CNG error 0x" + util::toHex(static_cast<std::uint64_t>(static_cast<std::uint32_t>(status)));
}

bool hashWithAlgorithm(std::span<const std::uint8_t> data,
                       LPCWSTR algorithmName,
                       std::string& output,
                       std::string& error) {
    BCRYPT_ALG_HANDLE rawAlgorithm = nullptr;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&rawAlgorithm, algorithmName, nullptr, 0);
    if (!NT_SUCCESS(status)) {
        error = "Unable to open CNG algorithm provider: " + ntStatusMessage(status);
        return false;
    }
    UniqueAlgorithm algorithm(rawAlgorithm);

    DWORD objectLength = 0;
    DWORD bytesWritten = 0;
    status = BCryptGetProperty(algorithm.get(), BCRYPT_OBJECT_LENGTH,
                               reinterpret_cast<PUCHAR>(&objectLength),
                               sizeof(objectLength), &bytesWritten, 0);
    if (!NT_SUCCESS(status)) {
        error = "Unable to query CNG hash object size: " + ntStatusMessage(status);
        return false;
    }

    DWORD hashLength = 0;
    status = BCryptGetProperty(algorithm.get(), BCRYPT_HASH_LENGTH,
                               reinterpret_cast<PUCHAR>(&hashLength),
                               sizeof(hashLength), &bytesWritten, 0);
    if (!NT_SUCCESS(status) || hashLength == 0) {
        error = "Unable to query CNG hash length: " + ntStatusMessage(status);
        return false;
    }

    std::vector<UCHAR> objectBuffer(objectLength);
    std::vector<UCHAR> hashBuffer(hashLength);

    BCRYPT_HASH_HANDLE rawHash = nullptr;
    status = BCryptCreateHash(algorithm.get(), &rawHash,
                              objectBuffer.data(), static_cast<ULONG>(objectBuffer.size()),
                              nullptr, 0, 0);
    if (!NT_SUCCESS(status)) {
        error = "Unable to create CNG hash: " + ntStatusMessage(status);
        return false;
    }
    UniqueHash hash(rawHash);

    constexpr std::size_t kChunkSize = 1024 * 1024;
    std::size_t offset = 0;
    while (offset < data.size()) {
        const auto chunk = std::min(kChunkSize, data.size() - offset);
        status = BCryptHashData(hash.get(),
                                const_cast<PUCHAR>(reinterpret_cast<const UCHAR*>(data.data() + offset)),
                                static_cast<ULONG>(chunk), 0);
        if (!NT_SUCCESS(status)) {
            error = "CNG hashing failed: " + ntStatusMessage(status);
            return false;
        }
        offset += chunk;
    }

    status = BCryptFinishHash(hash.get(), hashBuffer.data(), static_cast<ULONG>(hashBuffer.size()), 0);
    if (!NT_SUCCESS(status)) {
        error = "Unable to finalize CNG hash: " + ntStatusMessage(status);
        return false;
    }

    output = util::toHex(std::span<const std::uint8_t>(
        reinterpret_cast<const std::uint8_t*>(hashBuffer.data()), hashBuffer.size()));
    return true;
}

} // namespace

HashOutcome HashCalculator::calculate(std::span<const std::uint8_t> data,
                                      bool includeMd5) {
    HashOutcome outcome;
    if (!hashWithAlgorithm(data, BCRYPT_SHA256_ALGORITHM, outcome.hashes.sha256, outcome.error)) {
        return outcome;
    }
    if (!hashWithAlgorithm(data, BCRYPT_SHA1_ALGORITHM, outcome.hashes.sha1, outcome.error)) {
        return outcome;
    }
    if (includeMd5 &&
        !hashWithAlgorithm(data, BCRYPT_MD5_ALGORITHM, outcome.hashes.md5, outcome.error)) {
        return outcome;
    }
    outcome.ok = true;
    return outcome;
}

} // namespace explainbin
