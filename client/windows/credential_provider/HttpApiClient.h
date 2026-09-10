// HttpApiClient.h — WinHTTP REST client for Ligament 2FA backend
#pragma once

#include "common.h"

namespace ligament {

struct WebAuthnBeginResult {
    bool success = false;
    std::string handle;
    std::string challengeBase64;
    std::string rpId;
    std::vector<std::string> allowCredentialIds;
    std::string rawOptionsJson;
    std::string error;
};

class HttpApiClient {
public:
    HttpApiClient(const std::wstring& serverUrl, bool allowSelfSigned = false);
    ~HttpApiClient();

    // 1. Push authentication
    bool StartPush(const std::wstring& username, const std::wstring& channel, std::wstring& outChallengeId, std::string& outError);
    bool PollStatus(const std::wstring& challengeId, std::wstring& outStatus, std::string& outError);

    // 2. Combined password + OTP authentication
    bool VerifyCombined(const std::wstring& username, const std::wstring& password, const std::wstring& code, std::string& outError);

    // 3. WebAuthn / FIDO2 authentication
    WebAuthnBeginResult WebAuthnBegin(const std::wstring& username, const std::wstring& password);
    bool WebAuthnFinish(const std::string& handle, const std::string& assertionJson, std::string& outError);

private:
    std::wstring m_serverUrl;
    std::wstring m_host;
    INTERNET_PORT m_port = INTERNET_DEFAULT_HTTPS_PORT;
    bool m_isHttps = true;
    bool m_allowSelfSigned = false;
    HINTERNET m_hSession = nullptr;

    bool ParseUrl(const std::wstring& url);
    bool SendRequest(
        const std::wstring& verb,
        const std::wstring& path,
        const std::string& body,
        int& outStatusCode,
        std::string& outResponse
    );
};

} // namespace ligament
