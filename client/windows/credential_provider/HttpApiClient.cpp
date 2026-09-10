// HttpApiClient.cpp — WinHTTP REST client implementation
#include "HttpApiClient.h"

namespace ligament {

// Simple JSON extraction helper
static std::string ExtractJsonString(const std::string& json, const std::string& key) {
    std::string needle = "\"" + key + "\"";
    size_t pos = json.find(needle);
    if (pos == std::string::npos) return "";

    pos = json.find(':', pos + needle.length());
    if (pos == std::string::npos) return "";

    pos = json.find('\"', pos + 1);
    if (pos == std::string::npos) return "";

    size_t end = json.find('\"', pos + 1);
    if (end == std::string::npos) return "";

    return json.substr(pos + 1, end - pos - 1);
}

static bool ExtractJsonBool(const std::string& json, const std::string& key) {
    std::string needle = "\"" + key + "\"";
    size_t pos = json.find(needle);
    if (pos == std::string::npos) return false;

    pos = json.find(':', pos + needle.length());
    if (pos == std::string::npos) return false;

    size_t truePos = json.find("true", pos);
    size_t falsePos = json.find("false", pos);
    size_t commaPos = json.find_first_of(",}\n", pos);

    if (truePos != std::string::npos && (commaPos == std::string::npos || truePos < commaPos)) {
        return true;
    }
    return false;
}

HttpApiClient::HttpApiClient(const std::wstring& serverUrl)
    : m_serverUrl(serverUrl) {
    ParseUrl(serverUrl);
    m_hSession = WinHttpOpen(
        L"Ligament-2FA-CredentialProvider/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0
    );
    if (m_hSession) {
        // Set timeouts: resolve 5s, connect 10s, send 15s, receive 45s
        WinHttpSetTimeouts(m_hSession, 5000, 10000, 15000, 45000);
    }
}

HttpApiClient::~HttpApiClient() {
    if (m_hSession) {
        WinHttpCloseHandle(m_hSession);
        m_hSession = nullptr;
    }
}

bool HttpApiClient::ParseUrl(const std::wstring& url) {
    URL_COMPONENTS urlComp = {0};
    urlComp.dwStructSize = sizeof(urlComp);
    wchar_t hostName[512] = {0};
    wchar_t urlPath[1024] = {0};

    urlComp.lpszHostName = hostName;
    urlComp.dwHostNameLength = _countof(hostName);
    urlComp.lpszUrlPath = urlPath;
    urlComp.dwUrlPathLength = _countof(urlPath);

    if (WinHttpCrackUrl(url.c_str(), (DWORD)url.length(), 0, &urlComp)) {
        m_host = hostName;
        m_port = urlComp.nPort;
        m_isHttps = (urlComp.nScheme == INTERNET_SCHEME_HTTPS);
        return true;
    }
    return false;
}

bool HttpApiClient::SendRequest(
    const std::wstring& verb,
    const std::wstring& path,
    const std::string& body,
    int& outStatusCode,
    std::string& outResponse)
{
    outStatusCode = 0;
    outResponse.clear();

    if (!m_hSession || m_host.empty()) return false;

    HINTERNET hConnect = WinHttpConnect(m_hSession, m_host.c_str(), m_port, 0);
    if (!hConnect) {
        LogDebug(L"WinHttpConnect failed: %lu", GetLastError());
        return false;
    }

    DWORD dwFlags = m_isHttps ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET hRequest = WinHttpOpenRequest(
        hConnect,
        verb.c_str(),
        path.c_str(),
        nullptr,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        dwFlags
    );

    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        return false;
    }

    // Set Content-Type: application/json
    LPCWSTR headers = L"Content-Type: application/json\r\n";
    DWORD headersLen = (DWORD)wcslen(headers);

    LPVOID pBody = (body.empty()) ? nullptr : (LPVOID)body.c_str();
    DWORD bodyLen = (DWORD)body.length();

    BOOL bResult = WinHttpSendRequest(hRequest, headers, headersLen, pBody, bodyLen, bodyLen, 0);
    if (bResult) {
        bResult = WinHttpReceiveResponse(hRequest, nullptr);
    }

    if (bResult) {
        DWORD dwStatusCode = 0;
        DWORD dwSize = sizeof(dwStatusCode);
        WinHttpQueryHeaders(
            hRequest,
            WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            WINHTTP_HEADER_NAME_BY_INDEX,
            &dwStatusCode,
            &dwSize,
            WINHTTP_NO_HEADER_INDEX
        );
        outStatusCode = (int)dwStatusCode;

        // Read response body
        DWORD dwDownloaded = 0;
        do {
            dwSize = 0;
            if (!WinHttpQueryDataAvailable(hRequest, &dwSize)) break;
            if (dwSize == 0) break;

            std::vector<char> buffer(dwSize + 1, 0);
            if (WinHttpReadData(hRequest, buffer.data(), dwSize, &dwDownloaded)) {
                outResponse.append(buffer.data(), dwDownloaded);
            }
        } while (dwSize > 0);
    } else {
        LogDebug(L"WinHttpSendRequest/ReceiveResponse failed: %lu", GetLastError());
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    return bResult;
}

bool HttpApiClient::StartPush(
    const std::wstring& username,
    const std::wstring& channel,
    std::wstring& outChallengeId,
    std::string& outError)
{
    std::string u8User = WideToUtf8(username);
    std::string u8Chan = WideToUtf8(channel);

    std::string body = "{\"username\":\"" + u8User + "\",\"channel\":\"" + u8Chan + "\"}";

    int statusCode = 0;
    std::string response;
    if (!SendRequest(L"POST", L"/api/v1/auth/start", body, statusCode, response)) {
        outError = "network_error";
        return false;
    }

    if (statusCode == 200) {
        std::string cid = ExtractJsonString(response, "challenge_id");
        if (!cid.empty()) {
            outChallengeId = Utf8ToWide(cid);
            return true;
        }
    }

    outError = ExtractJsonString(response, "error");
    if (outError.empty()) outError = "status_" + std::to_string(statusCode);
    return false;
}

bool HttpApiClient::PollStatus(
    const std::wstring& challengeId,
    std::wstring& outStatus,
    std::string& outError)
{
    std::string u8Cid = WideToUtf8(challengeId);
    std::string body = "{\"challenge_id\":\"" + u8Cid + "\"}";

    int statusCode = 0;
    std::string response;
    if (!SendRequest(L"POST", L"/api/v1/auth/poll", body, statusCode, response)) {
        outError = "network_error";
        return false;
    }

    if (statusCode == 200) {
        std::string st = ExtractJsonString(response, "status");
        if (!st.empty()) {
            outStatus = Utf8ToWide(st);
            return true;
        }
    }

    outError = ExtractJsonString(response, "error");
    return false;
}

bool HttpApiClient::VerifyCombined(
    const std::wstring& username,
    const std::wstring& password,
    const std::wstring& code,
    std::string& outError)
{
    std::string u8User = WideToUtf8(username);
    std::string u8Pass = WideToUtf8(password);
    std::string u8Code = WideToUtf8(code);

    std::string body = "{\"username\":\"" + u8User + "\",\"password\":\"" + u8Pass + "\",\"code\":\"" + u8Code + "\"}";

    int statusCode = 0;
    std::string response;
    if (!SendRequest(L"POST", L"/api/v1/auth/combined", body, statusCode, response)) {
        outError = "network_error";
        return false;
    }

    if (statusCode == 200 && ExtractJsonBool(response, "ok")) {
        return true;
    }

    outError = ExtractJsonString(response, "error");
    if (outError.empty()) outError = "status_" + std::to_string(statusCode);
    return false;
}

WebAuthnBeginResult HttpApiClient::WebAuthnBegin(
    const std::wstring& username,
    const std::wstring& password)
{
    WebAuthnBeginResult res;
    std::string u8User = WideToUtf8(username);
    std::string u8Pass = WideToUtf8(password);

    std::string body = "{\"username\":\"" + u8User + "\",\"password\":\"" + u8Pass + "\"}";

    int statusCode = 0;
    std::string response;
    if (!SendRequest(L"POST", L"/api/v1/auth/webauthn/begin", body, statusCode, response)) {
        res.error = "network_error";
        return res;
    }

    if (statusCode == 200) {
        res.handle = ExtractJsonString(response, "handle");
        res.rawOptionsJson = response;
        res.success = !res.handle.empty();
        return res;
    }

    res.error = ExtractJsonString(response, "error");
    if (res.error.empty()) res.error = "status_" + std::to_string(statusCode);
    return res;
}

bool HttpApiClient::WebAuthnFinish(
    const std::string& handle,
    const std::string& assertionJson,
    std::string& outError)
{
    int statusCode = 0;
    std::string response;
    std::wstring path = L"/api/v1/auth/webauthn/finish?handle=" + Utf8ToWide(handle);

    if (!SendRequest(L"POST", path, assertionJson, statusCode, response)) {
        outError = "network_error";
        return false;
    }

    if (statusCode == 200) {
        return true;
    }

    outError = ExtractJsonString(response, "error");
    if (outError.empty()) outError = "status_" + std::to_string(statusCode);
    return false;
}

} // namespace ligament
