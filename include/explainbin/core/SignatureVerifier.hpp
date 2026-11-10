#pragma once

#include "explainbin/core/Types.hpp"

#include <filesystem>

namespace explainbin {

// Verifies embedded Authenticode signatures with WinVerifyTrust and extracts
// signer details with CryptQueryObject. Revocation checking is deliberately
// offline/cache-only, so analysis remains local.
class SignatureVerifier {
public:
    static SignatureInfo verify(const std::filesystem::path& path,
                                bool certificateTablePresent);
};

} // namespace explainbin
