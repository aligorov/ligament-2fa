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
        m_pfnGetAssertion = (FnWebAuthnAuthenticatorGetAssertion)GetProcAddress(m_hWebAuthn, "WebAuthnAuthenticatorGetAssertion");
        m_pfnFreeAssertion = (FnWebAuthnFreeAssertion)GetProcAddress(m_hWebAuthn, "WebAuthnFreeAssertion");
        m_pfnIsUVPAA = (FnWebAuthnIsUserVerifyingPlatformAuthenticatorAvailable)GetProcAddress(m_hWebAuthn, "WebAuthnIsUserVerifyingPlatformAuthenticatorAvailable");
        LogDebug(L"webauthn: DLL загружена, GetAssertion=%p FreeAssertion=%p UVPAA=%p",
            m_pfnGetAssertion, m_pfnFreeAssertion, m_pfnIsUVPAA);
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
    std::string& outAssertionJson,
    std::string& outError)
{
    if (!IsAvailable()) {
        outError = "webauthn_dll_not_available";
        return false;
    }

    std::string u8RpId = WideToUtf8(rpId);
    std::string clientDataStr = "{\"type\":\"webauthn.get\",\"challenge\":\"" + challengeBase64 + "\",\"origin\":\"https://" + u8RpId + "\"}";

    WEBAUTHN_CLIENT_DATA clientData = {0};
    clientData.dwVersion = WEBAUTHN_CLIENT_DATA_CURRENT_VERSION;
    clientData.cbClientDataJSON = (DWORD)clientDataStr.length();
    clientData.pbClientDataJSON = (PBYTE)clientDataStr.data();
    clientData.pwszHashAlgId = WEBAUTHN_HASH_ALGORITHM_SHA_256;

    WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS options = {0};
    options.dwVersion = WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_CURRENT_VERSION;
    options.dwTimeoutMilliseconds = 60000;
    options.dwUserVerificationRequirement = WEBAUTHN_USER_VERIFICATION_REQUIREMENT_PREFERRED;

    PWEBAUTHN_ASSERTION pAssertion = nullptr;
    LogDebug(L"Calling WebAuthnAuthenticatorGetAssertion for rpId: %s", rpId.c_str());

    HRESULT hr = m_pfnGetAssertion(
        hWnd,
        rpId.c_str(),
        &clientData,
        &options,
        &pAssertion
    );

    if (FAILED(hr) || !pAssertion) {
        LogDebug(L"WebAuthnAuthenticatorGetAssertion failed: 0x%08X", hr);
        if (hr == HRESULT_FROM_WIN32(ERROR_CANCELLED)) {
            outError = "cancelled_by_user";
        } else if (hr == HRESULT_FROM_WIN32(ERROR_TIMEOUT)) {
            outError = "timeout";
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
