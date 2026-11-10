#include "explainbin/core/SignatureVerifier.hpp"

#include "explainbin/core/Util.hpp"

#include <windows.h>
#include <wincrypt.h>
#include <mscat.h>
#include <softpub.h>
#include <wintrust.h>

#include <array>
#include <memory>
#include <string>
#include <vector>

namespace explainbin {
namespace {

struct StoreCloser {
    void operator()(HCERTSTORE store) const noexcept {
        if (store != nullptr) {
            CertCloseStore(store, 0);
        }
    }
};

struct MessageCloser {
    void operator()(HCRYPTMSG message) const noexcept {
        if (message != nullptr) {
            CryptMsgClose(message);
        }
    }
};

struct CertificateCloser {
    void operator()(const CERT_CONTEXT* certificate) const noexcept {
        if (certificate != nullptr) {
            CertFreeCertificateContext(certificate);
        }
    }
};

struct HandleCloser {
    void operator()(void* handle) const noexcept {
        if (handle != nullptr && handle != INVALID_HANDLE_VALUE) {
            CloseHandle(handle);
        }
    }
};

struct CatalogAdminCloser {
    void operator()(void* admin) const noexcept {
        if (admin != nullptr) {
            CryptCATAdminReleaseContext(static_cast<HCATADMIN>(admin), 0);
        }
    }
};

using UniqueStore = std::unique_ptr<void, StoreCloser>;
using UniqueMessage = std::unique_ptr<void, MessageCloser>;
using UniqueCertificate = std::unique_ptr<const CERT_CONTEXT, CertificateCloser>;
using UniqueFile = std::unique_ptr<void, HandleCloser>;
using UniqueCatalogAdmin = std::unique_ptr<void, CatalogAdminCloser>;

std::string wideToUtf8(const wchar_t* text) {
    if (text == nullptr) {
        return {};
    }
    const int required = WideCharToMultiByte(CP_UTF8, 0, text, -1, nullptr, 0, nullptr, nullptr);
    if (required <= 1) {
        return {};
    }
    std::string result(static_cast<std::size_t>(required - 1), '\0');
    WideCharToMultiByte(CP_UTF8, 0, text, -1, result.data(), required, nullptr, nullptr);
    return result;
}

std::string certificateName(const CERT_CONTEXT* certificate, DWORD type) {
    if (certificate == nullptr) {
        return {};
    }
    const DWORD size = CertGetNameStringW(certificate, type, 0, nullptr, nullptr, 0);
    if (size <= 1) {
        return {};
    }
    std::vector<wchar_t> buffer(size);
    if (CertGetNameStringW(certificate, type, 0, nullptr, buffer.data(), size) <= 1) {
        return {};
    }
    return wideToUtf8(buffer.data());
}

std::string oidName(const char* oid) {
    if (oid == nullptr) {
        return {};
    }
    static const std::array<std::pair<const char*, const char*>, 12> kNames{{
        {"1.2.840.113549.1.1.2", "MD2 with RSA"},
        {"1.2.840.113549.1.1.4", "MD5 with RSA"},
        {"1.2.840.113549.1.1.5", "SHA-1 with RSA"},
        {"1.2.840.113549.1.1.11", "SHA-256 with RSA"},
        {"1.2.840.113549.1.1.12", "SHA-384 with RSA"},
        {"1.2.840.113549.1.1.13", "SHA-512 with RSA"},
        {"1.2.840.10045.4.3.2", "ECDSA with SHA-256"},
        {"1.2.840.10045.4.3.3", "ECDSA with SHA-384"},
        {"1.3.14.3.2.29", "SHA-1 with RSA"},
        {"2.16.840.1.101.3.4.2.1", "SHA-256"},
        {"2.16.840.1.101.3.4.2.2", "SHA-384"},
        {"2.16.840.1.101.3.4.2.3", "SHA-512"},
    }};
    for (const auto& entry : kNames) {
        if (std::string(oid) == entry.first) {
            return entry.second;
        }
    }
    return oid;
}

std::string hresultText(LONG status) {
    switch (static_cast<unsigned long>(status)) {
    case 0x00000000UL:
        return "The signature and its certificate chain were trusted by Windows.";
    case 0x800B0100UL:
        return "No signature was present in the subject.";
    case 0x800B0101UL:
        return "A required certificate is not within its validity period.";
    case 0x800B0109UL:
        return "A certificate chain processed correctly but terminated in a root certificate "
               "that is not trusted by this system.";
    case 0x800B010AUL:
        return "A certificate chain could not be built to a trusted root authority.";
    case 0x800B010CUL:
        return "The revocation status of the certificate could not be determined.";
    case 0x800B010EUL:
        return "The certificate was revoked by its issuer.";
    case 0x800B0110UL:
        return "The certificate is not valid for the requested usage.";
    case 0x800B0111UL:
        return "The certificate is explicitly distrusted by the user or system policy.";
    case 0x800B0001UL:
        return "The specified trust provider is not known.";
    case 0x800B0003UL:
        return "The form specified for the subject is not one supported by the trust provider.";
    case 0x800B0004UL:
        return "The subject is not trusted for the specified action.";
    case 0x80096004UL:
        return "The signature of the certificate cannot be verified.";
    case 0x80096010UL:
        return "The digital signature of the object did not verify.";
    default:
        return "WinVerifyTrust returned status " +
               util::toHex(static_cast<std::uint64_t>(static_cast<std::uint32_t>(status))) + ".";
    }
}

std::string fileTimeText(const FILETIME& fileTime) {
    ULARGE_INTEGER value{};
    value.LowPart = fileTime.dwLowDateTime;
    value.HighPart = fileTime.dwHighDateTime;
    return util::formatFileTimeUtc(value.QuadPart);
}

void extractSignerDetails(const std::filesystem::path& path, SignatureInfo& info,
                          bool markPresent = true) {
    HCERTSTORE rawStore = nullptr;
    HCRYPTMSG rawMessage = nullptr;
    DWORD encoding = 0;
    DWORD contentType = 0;
    DWORD formatType = 0;
    // Embedded Authenticode signatures and detached .cat catalog files both carry a
    // PKCS#7 signed message, but they use different content-type flags.
    if (CryptQueryObject(CERT_QUERY_OBJECT_FILE, path.c_str(),
                         CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED |
                             CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
                         CERT_QUERY_FORMAT_FLAG_BINARY, 0, &encoding, &contentType,
                         &formatType, &rawStore, &rawMessage, nullptr) == FALSE) {
        return;
    }
    UniqueStore store(rawStore);
    UniqueMessage message(rawMessage);
    (void)encoding;
    (void)contentType;
    (void)formatType;

    DWORD signerSize = 0;
    if (CryptMsgGetParam(message.get(), CMSG_SIGNER_INFO_PARAM, 0, nullptr, &signerSize) == FALSE ||
        signerSize < sizeof(CMSG_SIGNER_INFO)) {
        return;
    }
    std::vector<BYTE> signerBuffer(signerSize);
    if (CryptMsgGetParam(message.get(), CMSG_SIGNER_INFO_PARAM, 0, signerBuffer.data(),
                         &signerSize) == FALSE) {
        return;
    }
    const auto* signerInfo = reinterpret_cast<const CMSG_SIGNER_INFO*>(signerBuffer.data());

    CERT_INFO certificateQuery{};
    certificateQuery.Issuer = signerInfo->Issuer;
    certificateQuery.SerialNumber = signerInfo->SerialNumber;
    UniqueCertificate certificate(
        CertFindCertificateInStore(store.get(), X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0,
                                   CERT_FIND_SUBJECT_CERT, &certificateQuery, nullptr));
    if (!certificate) {
        return;
    }

    if (markPresent) {
        info.present = true;
    }
    info.subject = certificateName(certificate.get(), CERT_NAME_SIMPLE_DISPLAY_TYPE);
    info.issuer = certificateName(certificate.get(), CERT_NAME_SIMPLE_DISPLAY_TYPE);
    // The issuer display name needs the issuer as the target; CertGetNameString
    // with SIMPLE_DISPLAY_TYPE returns the subject. Use the certificate's issuer
    // encoded name for the separate issuer value.
    const DWORD issuerSize = CertGetNameStringW(
        certificate.get(), CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_NAME_ISSUER_FLAG, nullptr,
        nullptr, 0);
    if (issuerSize > 1) {
        std::vector<wchar_t> issuerBuffer(issuerSize);
        if (CertGetNameStringW(certificate.get(), CERT_NAME_SIMPLE_DISPLAY_TYPE,
                               CERT_NAME_ISSUER_FLAG, nullptr, issuerBuffer.data(),
                               issuerSize) > 1) {
            info.issuer = wideToUtf8(issuerBuffer.data());
        }
    }

    if (certificate->pCertInfo != nullptr) {
        info.serialNumber = util::toHex(std::span<const std::uint8_t>(
            certificate->pCertInfo->SerialNumber.pbData,
            certificate->pCertInfo->SerialNumber.cbData));
        info.notBeforeUtc = fileTimeText(certificate->pCertInfo->NotBefore);
        info.notAfterUtc = fileTimeText(certificate->pCertInfo->NotAfter);
        info.signatureAlgorithm =
            oidName(certificate->pCertInfo->SignatureAlgorithm.pszObjId);

        const int validity = CertVerifyTimeValidity(nullptr, certificate->pCertInfo);
        info.expired = validity < 0;
        info.notYetValid = validity > 0;
    }
    info.digestAlgorithm = oidName(signerInfo->HashAlgorithm.pszObjId);

    if (!info.subject.empty()) {
        info.chain.push_back("Signer: " + info.subject);
    }
    if (!info.issuer.empty()) {
        info.chain.push_back("Issuer: " + info.issuer);
    }
}

// Finds a locally installed Windows catalog that contains this file's hash. Catalog
// membership is checked with the same hash algorithms Windows uses; no network access
// is needed. Returns the catalog path when a matching catalog exists.
bool findCatalogForFile(const std::filesystem::path& path,
                        std::filesystem::path& catalogPath) {
    HANDLE rawFile = CreateFileW(path.c_str(), GENERIC_READ,
                                 FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                 nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (rawFile == INVALID_HANDLE_VALUE) {
        return false;
    }
    UniqueFile file(rawFile);

    constexpr const wchar_t* kAlgorithms[] = {L"SHA256", L"SHA1"};
    for (const wchar_t* algorithm : kAlgorithms) {
        HCATADMIN rawAdmin = nullptr;
        if (CryptCATAdminAcquireContext2(&rawAdmin, nullptr, algorithm, nullptr, 0) == FALSE) {
            continue;
        }
        UniqueCatalogAdmin admin(rawAdmin);

        DWORD hashSize = 0;
        if (CryptCATAdminCalcHashFromFileHandle2(admin.get(), file.get(), &hashSize, nullptr,
                                                 0) == FALSE ||
            hashSize == 0) {
            continue;
        }
        std::vector<BYTE> hash(hashSize);
        if (CryptCATAdminCalcHashFromFileHandle2(admin.get(), file.get(), &hashSize, hash.data(),
                                                 0) == FALSE) {
            continue;
        }

        HCATINFO catalogHandle = CryptCATAdminEnumCatalogFromHash(
            static_cast<HCATADMIN>(admin.get()), hash.data(), hashSize, 0, nullptr);
        if (catalogHandle == nullptr) {
            continue;
        }

        CATALOG_INFO catalogInfo{};
        catalogInfo.cbStruct = sizeof(catalogInfo);
        const BOOL found =
            CryptCATCatalogInfoFromContext(catalogHandle, &catalogInfo, 0);
        if (found != FALSE && catalogInfo.wszCatalogFile[0] != L'\0') {
            catalogPath = catalogInfo.wszCatalogFile;
        }
        CryptCATAdminReleaseCatalogContext(static_cast<HCATADMIN>(admin.get()), catalogHandle,
                                           0);
        if (found != FALSE) {
            return true;
        }
    }
    return false;
}

bool verifyCatalogSignature(const std::filesystem::path& path, SignatureInfo& info) {
    std::filesystem::path catalogPath;
    if (!findCatalogForFile(path, catalogPath)) {
        return false;
    }

    WINTRUST_FILE_INFO fileInfo{};
    fileInfo.cbStruct = sizeof(fileInfo);
    fileInfo.pcwszFilePath = catalogPath.c_str();

    WINTRUST_DATA trustData{};
    trustData.cbStruct = sizeof(trustData);
    trustData.dwUIChoice = WTD_UI_NONE;
    trustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    trustData.dwUnionChoice = WTD_CHOICE_FILE;
    trustData.pFile = &fileInfo;
    trustData.dwStateAction = WTD_STATEACTION_VERIFY;
    trustData.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;
    trustData.dwUIContext = WTD_UICONTEXT_EXECUTE;

    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    const LONG status = WinVerifyTrust(nullptr, &action, &trustData);
    trustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(nullptr, &action, &trustData);
    if (status != ERROR_SUCCESS) {
        return false;
    }

    info.catalogSigned = true;
    info.present = false;
    info.status = SignatureStatus::Valid;
    info.statusText = "Valid catalog signature (the file has no embedded signature).";
    info.trustStatus = status;
    info.trustMessage =
        "The catalog containing this file's hash carries a trusted signature.";
    info.chain.clear();
    info.chain.push_back("Catalog: " + toUtf8(catalogPath));
    extractSignerDetails(catalogPath, info, false);
    return true;
}

} // namespace

SignatureInfo SignatureVerifier::verify(const std::filesystem::path& path,
                                        bool certificateTablePresent) {
    SignatureInfo info;
    info.checked = true;
    info.present = certificateTablePresent;
    info.revocationChecked = false;

    extractSignerDetails(path, info);

    WINTRUST_FILE_INFO fileInfo{};
    fileInfo.cbStruct = sizeof(fileInfo);
    fileInfo.pcwszFilePath = path.c_str();

    WINTRUST_DATA trustData{};
    trustData.cbStruct = sizeof(trustData);
    trustData.dwUIChoice = WTD_UI_NONE;
    trustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    trustData.dwUnionChoice = WTD_CHOICE_FILE;
    trustData.pFile = &fileInfo;
    trustData.dwStateAction = WTD_STATEACTION_VERIFY;
    trustData.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;
    trustData.dwUIContext = WTD_UICONTEXT_EXECUTE;

    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    const LONG status = WinVerifyTrust(nullptr, &action, &trustData);
    info.trustStatus = status;
    info.trustMessage = hresultText(status);

    trustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(nullptr, &action, &trustData);

    const bool noEmbeddedSignature =
        status == static_cast<LONG>(TRUST_E_NOSIGNATURE) ||
        status == static_cast<LONG>(TRUST_E_PROVIDER_UNKNOWN) ||
        status == static_cast<LONG>(TRUST_E_SUBJECT_FORM_UNKNOWN);

    if (status == ERROR_SUCCESS) {
        info.status = SignatureStatus::Valid;
        info.present = true;
        info.statusText = "Valid embedded Authenticode signature.";
    } else if (!info.present && noEmbeddedSignature &&
               verifyCatalogSignature(path, info)) {
        // The file is not embedded-signed, but a trusted local catalog contains its hash.
    } else if (status == static_cast<LONG>(TRUST_E_NOSIGNATURE)) {
        info.status = SignatureStatus::Unsigned;
        info.statusText = info.present
            ? "A certificate table is present, but Windows found no embedded signature to verify."
            : "No embedded or catalog Authenticode signature was found on this system.";
    } else if (status == static_cast<LONG>(TRUST_E_PROVIDER_UNKNOWN) ||
               status == static_cast<LONG>(TRUST_E_SUBJECT_FORM_UNKNOWN)) {
        info.status = info.present ? SignatureStatus::Unknown : SignatureStatus::Unsigned;
        info.statusText = info.present
            ? "The signature format is not supported or could not be interpreted."
            : "No embedded or catalog Authenticode signature was found on this system.";
    } else {
        info.status = SignatureStatus::Invalid;
        info.present = true;
        info.statusText = "The signature did not verify.";
    }

    if (info.revocationChecked == false && info.status == SignatureStatus::Valid) {
        info.chain.push_back("Revocation checking: offline/cache-only (not a full online check)");
    }
    return info;
}

} // namespace explainbin
