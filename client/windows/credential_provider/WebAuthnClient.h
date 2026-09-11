// WebAuthnClient.h — Win32 WebAuthn API client for FIDO2/YubiKey over RDP
#pragma once

#include "common.h"

namespace ligament {

class WebAuthnClient {
public:
    WebAuthnClient();
    ~WebAuthnClient();

    bool IsAvailable() const;

    // Performs physical key assertion (YubiKey / FIDO2 / Windows Hello)
    // When called over RDP, Windows redirects the prompt to the remote client machine.
    bool Authenticate(
        HWND hWnd,
        const std::wstring& rpId,
        const std::string& challengeBase64,
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

    FnWebAuthnAuthenticatorGetAssertion m_pfnGetAssertion = nullptr;
    FnWebAuthnFreeAssertion m_pfnFreeAssertion = nullptr;
    FnWebAuthnIsUserVerifyingPlatformAuthenticatorAvailable m_pfnIsUVPAA = nullptr;
};

} // namespace ligament
