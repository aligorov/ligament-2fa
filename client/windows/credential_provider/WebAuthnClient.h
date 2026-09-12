// WebAuthnClient.h — Win32 WebAuthn API client for FIDO2/YubiKey over RDP
#pragma once

#include "common.h"

namespace ligament {

class WebAuthnClient {
public:
    WebAuthnClient();
    ~WebAuthnClient();

    bool IsAvailable() const;

    // Performs physical key assertion (YubiKey / FIDO2 / Windows Hello / Passkey)
    // Supports all Windows 10 & Windows 11 versions and platforms.
    bool Authenticate(
        HWND hWnd,
        const std::wstring& rpId,
        const std::string& challengeBase64,
        const std::vector<std::string>& allowCredIdsBase64,
        const std::string& origin,
        std::string& outAssertionJson,
        std::string& outError
    );

private:
    HMODULE m_hWebAuthn = nullptr;

    typedef HRESULT (WINAPI *FnWebAuthnAuthenticatorGetAssertion)(
        HWND hWnd,
        PCWSTR pwszRpId,
        PCWEBAUTHN_CLIENT_DATA pWebAuthnClientData,
        PCWEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS pWebAuthnGetAssertionOptions,
        PWEBAUTHN_ASSERTION* ppWebAuthnAssertion
    );

    typedef VOID (WINAPI *FnWebAuthnFreeAssertion)(
        PWEBAUTHN_ASSERTION pWebAuthnAssertion
    );

    typedef BOOL (WINAPI *FnWebAuthnIsUserVerifyingPlatformAuthenticatorAvailable)();
    typedef DWORD (WINAPI *FnWebAuthnGetApiVersionNumber)();
    typedef PCWSTR (WINAPI *FnWebAuthnGetErrorName)(HRESULT hr);

    FnWebAuthnAuthenticatorGetAssertion m_pfnGetAssertion = nullptr;
    FnWebAuthnFreeAssertion m_pfnFreeAssertion = nullptr;
    FnWebAuthnIsUserVerifyingPlatformAuthenticatorAvailable m_pfnIsUVPAA = nullptr;
    FnWebAuthnGetApiVersionNumber m_pfnGetApiVersionNumber = nullptr;
    FnWebAuthnGetErrorName m_pfnGetErrorName = nullptr;
};

} // namespace ligament
