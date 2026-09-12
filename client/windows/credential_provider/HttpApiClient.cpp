// HttpApiClient.cpp — WinHTTP REST client implementation
#include "HttpApiClient.h"

namespace ligament {


HttpApiClient::HttpApiClient(const std::wstring& serverUrl, bool allowSelfSigned, int receiveTimeoutMs)
    : m_serverUrl(serverUrl), m_allowSelfSigned(allowSelfSigned) {
    ParseUrl(serverUrl);
    m_hSession = WinHttpOpen(
        L"Ligament-2FA-CredentialProvider/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0
    );
    if (m_hSession) {
        // Set timeouts: resolve 5s, connect 10s, send 15s, receive per ctor
        if (receiveTimeoutMs < 1000) receiveTimeoutMs = 1000;
        WinHttpSetTimeouts(m_hSession, 5000, 10000, 15000, receiveTimeoutMs);
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

    if (m_isHttps && m_allowSelfSigned) {
        DWORD dwSecFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
                           SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
                           SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
                           SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
        WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &dwSecFlags, sizeof(dwSecFlags));
    }

    // Set Content-Type: application/json
    LPCWSTR headers = L"Content-Type: application/json\r\n";
    DWORD headersLen = (DWORD)wcslen(headers);

    LPVOID pBody = (body.empty()) ? nullptr : (LPVOID)body.c_str();
    DWORD bodyLen = (DWORD)body.length();

    BOOL bResult = WinHttpSendRequest(hRequest, headers, headersLen, pBody, bodyLen, bodyLen, 0);
    if (!bResult && m_isHttps && m_allowSelfSigned && GetLastError() == ERROR_WINHTTP_SECURE_FAILURE) {
        DWORD dwSecFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
                           SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
                           SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
                           SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
        WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &dwSecFlags, sizeof(dwSecFlags));
        bResult = WinHttpSendRequest(hRequest, headers, headersLen, pBody, bodyLen, bodyLen, 0);
    }
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

struct SessionEndpointInfo {
    std::string clientIp;      // RDP client IPv4 (e.g. 192.168.1.55) or local console
    std::string clientName;    // RDP client computer name (e.g. LAPTOP-ALEX)
    std::string hostName;      // Local host computer name (e.g. WIN-SRV)
    std::string hostIp;        // Local host IPv4 (e.g. 192.168.1.100)
    std::string service;       // "Windows RDP (WIN-SRV)" or "Windows (WIN-SRV)"
    std::string clientDesc;    // "Windows RDP (LAPTOP-ALEX)" or "Локальная консоль"
    bool isRemote = false;
};

static SessionEndpointInfo GetSessionEndpointInfo() {
    SessionEndpointInfo info;

    // 1. Local computer name
    wchar_t compName[MAX_COMPUTERNAME_LENGTH + 1] = {0};
    DWORD compLen = _countof(compName);
    if (GetComputerNameW(compName, &compLen)) {
        info.hostName = WideToUtf8(compName);
    }

    // 2. Query WTS for RDP client IP
    PWTS_CLIENT_ADDRESS pAddr = nullptr;
    DWORD bytes = 0;
    if (WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, WTS_CURRENT_SESSION, WTSClientAddress, (LPWSTR*)&pAddr, &bytes) && pAddr) {
        if (pAddr->AddressFamily == AF_INET) {
            char ipBuf[64] = {0};
            snprintf(ipBuf, sizeof(ipBuf), "%u.%u.%u.%u",
                pAddr->Address[2], pAddr->Address[3], pAddr->Address[4], pAddr->Address[5]);
            if (strcmp(ipBuf, "0.0.0.0") != 0) {
                info.clientIp = ipBuf;
                info.isRemote = true;
            }
        }
        WTSFreeMemory(pAddr);
    }

    // Query WTS for RDP client computer name
    LPWSTR pClientName = nullptr;
    if (WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, WTS_CURRENT_SESSION, WTSClientName, &pClientName, &bytes) && pClientName) {
        if (wcslen(pClientName) > 0) {
            info.clientName = WideToUtf8(pClientName);
            info.isRemote = true;
        }
        WTSFreeMemory(pClientName);
    }

    // 3. Local machine IPv4 via GetAdaptersAddresses
    ULONG outBufLen = 15000;
    PIP_ADAPTER_ADDRESSES pAddresses = (IP_ADAPTER_ADDRESSES*)malloc(outBufLen);
    if (pAddresses) {
        DWORD dwRetVal = GetAdaptersAddresses(AF_INET, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER, NULL, pAddresses, &outBufLen);
        if (dwRetVal == ERROR_BUFFER_OVERFLOW) {
            free(pAddresses);
            pAddresses = (IP_ADAPTER_ADDRESSES*)malloc(outBufLen);
            if (pAddresses) {
                dwRetVal = GetAdaptersAddresses(AF_INET, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER, NULL, pAddresses, &outBufLen);
            }
        }
        if (dwRetVal == NO_ERROR && pAddresses) {
            for (PIP_ADAPTER_ADDRESSES pCurr = pAddresses; pCurr != nullptr; pCurr = pCurr->Next) {
                if (pCurr->OperStatus != IfOperStatusUp) continue;
                if (pCurr->IfType == IF_TYPE_SOFTWARE_LOOPBACK) continue;

                for (PIP_ADAPTER_UNICAST_ADDRESS pUnicast = pCurr->FirstUnicastAddress; pUnicast != nullptr; pUnicast = pUnicast->Next) {
                    if (pUnicast->Address.lpSockaddr && pUnicast->Address.lpSockaddr->sa_family == AF_INET) {
                        sockaddr_in* sa_in = (sockaddr_in*)pUnicast->Address.lpSockaddr;
                        char ipStr[INET_ADDRSTRLEN] = {0};
                        if (inet_ntop(AF_INET, &(sa_in->sin_addr), ipStr, sizeof(ipStr))) {
                            if (strncmp(ipStr, "127.", 4) != 0 && strcmp(ipStr, "0.0.0.0") != 0) {
                                info.hostIp = ipStr;
                                break;
                            }
                        }
                    }
                }
                if (!info.hostIp.empty()) break;
            }
        }
        if (pAddresses) free(pAddresses);
    }

    // Formulate descriptive strings
    if (info.isRemote) {
        info.service = "Windows RDP (" + (info.hostName.empty() ? "Сервер" : info.hostName) + ")";
        info.clientDesc = "Windows RDP (" + (info.clientName.empty() ? "Клиент" : info.clientName) + ")";
    } else {
        info.service = "Windows (" + (info.hostName.empty() ? "Консоль" : info.hostName) + ")";
        info.clientDesc = "Локальная консоль (" + (info.hostName.empty() ? "Консоль" : info.hostName) + ")";
        if (info.clientIp.empty()) {
            info.clientIp = info.hostIp.empty() ? "127.0.0.1" : info.hostIp;
        }
        if (info.clientName.empty()) {
            info.clientName = info.hostName;
        }
    }

    LogDebug(L"Endpoint info: remote=%d, host=%S, hostIp=%S, clientIp=%S, clientName=%S",
        info.isRemote ? 1 : 0,
        info.hostName.c_str(),
        info.hostIp.c_str(),
        info.clientIp.c_str(),
        info.clientName.c_str());

    return info;
}

bool HttpApiClient::StartPush(
    const std::wstring& username,
    const std::wstring& password,
    std::wstring& outChallengeId,
    std::wstring& outNumberMatch,
    std::string& outError)
{
    std::string u8User = EscapeJson(WideToUtf8(username));
    std::string u8Pass = EscapeJson(WideToUtf8(password));

    SessionEndpointInfo ep = GetSessionEndpointInfo();

    std::string body = "{\"username\":\"" + u8User +
                       "\",\"password\":\"" + u8Pass +
                       "\",\"service\":\"" + EscapeJson(ep.service) +
                       "\",\"client\":\"" + EscapeJson(ep.clientDesc) +
                       "\",\"host\":\"" + EscapeJson(ep.hostName) +
                       "\",\"client_ip\":\"" + EscapeJson(ep.clientIp) +
                       "\",\"host_ip\":\"" + EscapeJson(ep.hostIp) +
                       "\",\"client_name\":\"" + EscapeJson(ep.clientName) + "\"}";

    m_lastRetryAfterSec = 0;
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
            // number_match — контрольное число number-matching: приложение
            // требует его ввода, показываем на ЭКРАНЕ ВХОДА (тайл).
            outNumberMatch = Utf8ToWide(ExtractJsonString(response, "number_match"));
            return true;
        }
    }

    // Серверные коды (401 bad_credentials, 423 locked, 429 rate_limited/
    // cooldown, 409 no_channel, 500) остаются серверными строками —
    // "network_error" ставится только при транспортном отказе WinHTTP
    // выше, поэтому fail-open остаётся строго transport-only.
    m_lastRetryAfterSec = ExtractJsonInt(response, "retry_after");
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
    std::string u8User = EscapeJson(WideToUtf8(username));
    std::string u8Pass = EscapeJson(WideToUtf8(password));
    std::string u8Code = EscapeJson(WideToUtf8(code));

    SessionEndpointInfo ep = GetSessionEndpointInfo();

    std::string body = "{\"username\":\"" + u8User +
                       "\",\"password\":\"" + u8Pass +
                       "\",\"code\":\"" + u8Code +
                       "\",\"service\":\"" + EscapeJson(ep.service) +
                       "\",\"client\":\"" + EscapeJson(ep.clientDesc) +
                       "\",\"host\":\"" + EscapeJson(ep.hostName) +
                       "\",\"client_ip\":\"" + EscapeJson(ep.clientIp) +
                       "\",\"host_ip\":\"" + EscapeJson(ep.hostIp) +
                       "\",\"client_name\":\"" + EscapeJson(ep.clientName) + "\"}";

    m_lastRetryAfterSec = 0;
    int statusCode = 0;
    std::string response;
    if (!SendRequest(L"POST", L"/api/v1/auth/combined", body, statusCode, response)) {
        outError = "network_error";
        return false;
    }

    if (statusCode == 200 && ExtractJsonBool(response, "ok")) {
        return true;
    }

    // 401 приходит как {"ok":false} без поля error — fallback status_401;
    // 423 locked / 429 rate_limited несут код в "error".
    m_lastRetryAfterSec = ExtractJsonInt(response, "retry_after");
    outError = ExtractJsonString(response, "error");
    if (outError.empty()) outError = "status_" + std::to_string(statusCode);
    return false;
}

WebAuthnBeginResult HttpApiClient::WebAuthnBegin(
    const std::wstring& username,
    const std::wstring& password)
{
    WebAuthnBeginResult res;
    std::string u8User = EscapeJson(WideToUtf8(username));
    std::string u8Pass = EscapeJson(WideToUtf8(password));

    SessionEndpointInfo ep = GetSessionEndpointInfo();

    std::string body = "{\"username\":\"" + u8User +
                       "\",\"password\":\"" + u8Pass +
                       "\",\"service\":\"" + EscapeJson(ep.service) +
                       "\",\"client\":\"" + EscapeJson(ep.clientDesc) +
                       "\",\"host\":\"" + EscapeJson(ep.hostName) +
                       "\",\"client_ip\":\"" + EscapeJson(ep.clientIp) +
                       "\",\"host_ip\":\"" + EscapeJson(ep.hostIp) +
                       "\",\"client_name\":\"" + EscapeJson(ep.clientName) + "\"}";

    m_lastRetryAfterSec = 0;
    int statusCode = 0;
    std::string response;
    if (!SendRequest(L"POST", L"/api/v1/auth/webauthn/begin", body, statusCode, response)) {
        res.error = "network_error";
        return res;
    }

    if (statusCode == 200) {
        res.handle = ExtractJsonString(response, "handle");
        res.challengeId = ExtractJsonString(response, "challenge_id");
        res.rawOptionsJson = response;
        res.success = !res.handle.empty();
        return res;
    }

    m_lastRetryAfterSec = ExtractJsonInt(response, "retry_after");
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

    m_lastRetryAfterSec = 0;
    if (!SendRequest(L"POST", path, assertionJson, statusCode, response)) {
        outError = "network_error";
        return false;
    }

    if (statusCode == 200) {
        return true;
    }

    m_lastRetryAfterSec = ExtractJsonInt(response, "retry_after");
    outError = ExtractJsonString(response, "error");
    if (outError.empty()) outError = "status_" + std::to_string(statusCode);
    return false;
}

} // namespace ligament
