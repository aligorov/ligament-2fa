// WebAuthnClient.cpp — Win32 WebAuthn API client implementation
#include "WebAuthnClient.h"

namespace ligament {

WebAuthnClient::WebAuthnClient() {
    wchar_t sysDir[MAX_PATH] = { 0 };
    if (GetSystemDirectoryW(sysDir, MAX_PATH) > 0) {
        std::wstring dllPath = std::wstring(sysDir) + L"\\webauthn.dll";
        m_hWebAuthn = LoadLibraryW(dllPath.c_str());
    }
    if (!m_hWebAuthn) {
        m_hWebAuthn = LoadLibraryW(L"webauthn.dll");
    }

    if (m_hWebAuthn) {
        auto getProc = [](HMODULE h, const char* name1, const char* name2) -> FARPROC {
            FARPROC p = GetProcAddress(h, name1);
            if (!p && name2) p = GetProcAddress(h, name2);
            return p;
        };

        m_pfnGetAssertion = (FnWebAuthnAuthenticatorGetAssertion)getProc(
            m_hWebAuthn, "WebAuthNAuthenticatorGetAssertion", "WebAuthnAuthenticatorGetAssertion");
        m_pfnFreeAssertion = (FnWebAuthnFreeAssertion)getProc(
            m_hWebAuthn, "WebAuthNFreeAssertion", "WebAuthnFreeAssertion");
        m_pfnIsUVPAA = (FnWebAuthnIsUserVerifyingPlatformAuthenticatorAvailable)getProc(
            m_hWebAuthn, "WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable", "WebAuthnIsUserVerifyingPlatformAuthenticatorAvailable");
        m_pfnGetApiVersionNumber = (FnWebAuthnGetApiVersionNumber)getProc(
            m_hWebAuthn, "WebAuthNGetApiVersionNumber", "WebAuthnGetApiVersionNumber");
        m_pfnGetErrorName = (FnWebAuthnGetErrorName)getProc(
            m_hWebAuthn, "WebAuthNGetErrorName", "WebAuthnGetErrorName");

        DWORD apiVer = m_pfnGetApiVersionNumber ? m_pfnGetApiVersionNumber() : 0;
        LogDebug(L"webauthn: DLL загружена, apiVer=%lu GetAssertion=%p FreeAssertion=%p",
            apiVer, m_pfnGetAssertion, m_pfnFreeAssertion);
    } else {
        DWORD err = GetLastError();
        LogDebug(L"webauthn: не удалось загрузить webauthn.dll err=%lu (126 = файл не найден в System32)", err);
    }
}

WebAuthnClient::~WebAuthnClient() {
    if (m_hWebAuthn) {
        FreeLibrary(m_hWebAuthn);
        m_hWebAuthn = nullptr;
    }
}

bool WebAuthnClient::IsAvailable() const {
    return (m_pfnGetAssertion != nullptr && m_pfnFreeAssertion != nullptr);
}

bool WebAuthnClient::Authenticate(
    HWND hWnd,
    const std::wstring& rpId,
    const std::string& challengeBase64,
    const std::vector<std::string>& allowCredIdsBase64,
    const std::string& origin,
    std::string& outAssertionJson,
    std::string& outError)
{
    if (!IsAvailable()) {
        outError = "webauthn_dll_not_available";
        return false;
    }

    if (!hWnd || !IsWindow(hWnd)) {
        hWnd = GetForegroundWindow();
    }
    if (!hWnd || !IsWindow(hWnd)) {
        hWnd = GetActiveWindow();
    }
    if (!hWnd || !IsWindow(hWnd)) {
        hWnd = GetDesktopWindow();
    }

    std::string u8RpId = WideToUtf8(rpId);
    std::string effectiveOrigin = origin.empty() ? ("https://" + u8RpId) : origin;
    std::string clientDataStr = "{\"type\":\"webauthn.get\",\"challenge\":\"" + challengeBase64 + "\",\"origin\":\"" + effectiveOrigin + "\"}";

    WEBAUTHN_CLIENT_DATA clientData = {0};
    clientData.dwVersion = WEBAUTHN_CLIENT_DATA_CURRENT_VERSION;
    clientData.cbClientDataJSON = (DWORD)clientDataStr.length();
    clientData.pbClientDataJSON = (PBYTE)clientDataStr.data();
    clientData.pwszHashAlgId = WEBAUTHN_HASH_ALGORITHM_SHA_256;

    // Decode allowed credentials if present
    std::vector<std::vector<unsigned char>> rawIds;
    for (const auto& b64Id : allowCredIdsBase64) {
        std::vector<unsigned char> decoded = Base64UrlDecode(b64Id);
        if (!decoded.empty()) {
            rawIds.push_back(decoded);
        }
    }

    std::vector<WEBAUTHN_CREDENTIAL> creds(rawIds.size());
    for (size_t i = 0; i < rawIds.size(); ++i) {
        creds[i].dwVersion = 1; // WEBAUTHN_CREDENTIAL_VERSION_1
        creds[i].cbId = (DWORD)rawIds[i].size();
        creds[i].pbId = rawIds[i].data();
        creds[i].pwszCredentialType = WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY;
    }

    WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS options = {0};
    // CRITICAL for universal Windows compatibility (Win10 1903..22H2, Win11, Server 2022/2025):
    // dwVersion = 1 is the baseline supported by all Windows builds.
    options.dwVersion = 1;
    options.dwTimeoutMilliseconds = 60000;
    options.dwAuthenticatorAttachment = 0; // WEBAUTHN_AUTHENTICATOR_ATTACHMENT_ANY (All: Hello, YubiKey, Phone)
    options.dwUserVerificationRequirement = 2; // WEBAUTHN_USER_VERIFICATION_REQUIREMENT_PREFERRED

    if (!creds.empty()) {
        options.CredentialList.cCredentials = (DWORD)creds.size();
        options.CredentialList.pCredentials = creds.data();
    }

    PWEBAUTHN_ASSERTION pAssertion = nullptr;
    LogDebug(L"webauthn: AuthenticatorGetAssertion start rpId='%s' creds=%lu hWnd=%p origin='%hs'",
        rpId.c_str(), (unsigned long)creds.size(), hWnd, effectiveOrigin.c_str());

    HRESULT hr = m_pfnGetAssertion(
        hWnd,
        rpId.c_str(),
        &clientData,
        &options,
        &pAssertion
    );

    if (FAILED(hr) || !pAssertion) {
        std::wstring errName = L"";
        if (m_pfnGetErrorName) {
            PCWSTR pwszName = m_pfnGetErrorName(hr);
            if (pwszName) errName = pwszName;
        }
        LogDebug(L"webauthn: AuthenticatorGetAssertion failed: 0x%08X (%s)", hr, errName.c_str());

        if (hr == HRESULT_FROM_WIN32(ERROR_CANCELLED) || hr == 0x800704C7) {
            outError = "cancelled_by_user";
        } else if (hr == HRESULT_FROM_WIN32(ERROR_TIMEOUT) || hr == 0x800705B4) {
            outError = "timeout";
        } else if (hr == 0x80090036) { // NTE_NOT_FOUND
            outError = "key_not_found";
        } else if (hr == 0x80090016) { // NTE_BAD_KEYSET
            outError = "bad_keyset";
        } else if (!errName.empty()) {
            outError = WideToUtf8(errName);
        } else {
            outError = "assertion_failed_hr_" + std::to_string(hr);
        }
        return false;
    }

    // Build PublicKeyCredential JSON expected by Ligament /api/v1/auth/webauthn/finish
    std::string credId = (pAssertion->Credential.pbId && pAssertion->Credential.cbId > 0)
        ? Base64UrlEncode(pAssertion->Credential.pbId, pAssertion->Credential.cbId)
        : "";
    std::string authData = Base64UrlEncode(pAssertion->pbAuthenticatorData, pAssertion->cbAuthenticatorData);
    std::string clientDataB64 = Base64UrlEncode((const unsigned char*)clientDataStr.data(), clientDataStr.length());
    std::string signature = Base64UrlEncode(pAssertion->pbSignature, pAssertion->cbSignature);
    std::string userHandle = (pAssertion->pbUserId && pAssertion->cbUserId > 0)
        ? Base64UrlEncode(pAssertion->pbUserId, pAssertion->cbUserId)
        : "";

    std::stringstream ss;
    ss << "{"
       << "\"id\":\"" << credId << "\","
       << "\"rawId\":\"" << credId << "\","
       << "\"type\":\"public-key\","
       << "\"response\":{"
       << "\"authenticatorData\":\"" << authData << "\","
       << "\"clientDataJSON\":\"" << clientDataB64 << "\","
       << "\"signature\":\"" << signature << "\"";
    if (!userHandle.empty()) {
        ss << ",\"userHandle\":\"" << userHandle << "\"";
    }
    ss << "}}";

    outAssertionJson = ss.str();
    m_pfnFreeAssertion(pAssertion);

    LogDebug(L"WebAuthn assertion acquired successfully");
    return true;
}

} // namespace ligament
