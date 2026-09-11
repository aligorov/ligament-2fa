// common.h — Common definitions, logging, and configuration for Ligament 2FA Credential Provider
#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <credentialprovider.h>
#include <ntsecapi.h>
#include <winhttp.h>
#include <webauthn.h>
#include <shlwapi.h>
#include <wtsapi32.h>

#include <string>
#include <vector>
#include <memory>
#include <sstream>

#include "guid.h"

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "secur32.lib")
#pragma comment(lib, "credui.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "wtsapi32.lib")

namespace ligament {

extern LONG g_cRefDll;

// Configuration loaded from registry (GPO: HKLM\SOFTWARE\Policies\Ligament\2FA)
struct Config {
    std::wstring serverUrl = L"https://twofa.corp.local";
    bool rdp2faEnabled = true;
    bool console2faEnabled = false;
    bool fido2Enabled = true;
    int pushTimeoutSec = 45;
    bool failClose = true;
    bool allowSelfSigned = false;
    std::vector<std::wstring> bypassAccounts;

    static Config LoadFromRegistry() {
        Config cfg;
        HKEY hKey = nullptr;
        // Priority 1: GPO policy
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Ligament\\2FA", 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
            // Priority 2: Local app settings
            RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Ligament\\2FA", 0, KEY_READ, &hKey);
        }

        if (hKey) {
            wchar_t buf[2048] = {0};
            DWORD dwType = 0, dwSize = sizeof(buf);
            if (RegQueryValueExW(hKey, L"ServerURL", nullptr, &dwType, (LPBYTE)buf, &dwSize) == ERROR_SUCCESS && dwType == REG_SZ) {
                if (wcslen(buf) > 0) cfg.serverUrl = buf;
            }

            DWORD dwVal = 0;
            dwSize = sizeof(dwVal);
            if (RegQueryValueExW(hKey, L"RDP2FAEnabled", nullptr, &dwType, (LPBYTE)&dwVal, &dwSize) == ERROR_SUCCESS) {
                cfg.rdp2faEnabled = (dwVal != 0);
            }
            if (RegQueryValueExW(hKey, L"Console2FAEnabled", nullptr, &dwType, (LPBYTE)&dwVal, &dwSize) == ERROR_SUCCESS) {
                cfg.console2faEnabled = (dwVal != 0);
            }
            if (RegQueryValueExW(hKey, L"FIDO2Enabled", nullptr, &dwType, (LPBYTE)&dwVal, &dwSize) == ERROR_SUCCESS) {
                cfg.fido2Enabled = (dwVal != 0);
            }
            if (RegQueryValueExW(hKey, L"PushTimeoutSeconds", nullptr, &dwType, (LPBYTE)&dwVal, &dwSize) == ERROR_SUCCESS && dwVal > 0) {
                cfg.pushTimeoutSec = (int)dwVal;
            }
            if (RegQueryValueExW(hKey, L"FailClose", nullptr, &dwType, (LPBYTE)&dwVal, &dwSize) == ERROR_SUCCESS) {
                cfg.failClose = (dwVal != 0);
            }
            if (RegQueryValueExW(hKey, L"AllowSelfSigned", nullptr, &dwType, (LPBYTE)&dwVal, &dwSize) == ERROR_SUCCESS) {
                cfg.allowSelfSigned = (dwVal != 0);
            }

            // Bypass accounts (comma separated)
            dwSize = sizeof(buf);
            if (RegQueryValueExW(hKey, L"BypassAccounts", nullptr, &dwType, (LPBYTE)buf, &dwSize) == ERROR_SUCCESS && dwType == REG_SZ) {
                std::wstringstream ss(buf);
                std::wstring item;
                while (std::getline(ss, item, L',')) {
                    // Trim spaces
                    size_t first = item.find_first_not_of(L" \t");
                    if (first != std::wstring::npos) {
                        size_t last = item.find_last_not_of(L" \t");
                        cfg.bypassAccounts.push_back(item.substr(first, (last - first + 1)));
                    }
                }
            }

            RegCloseKey(hKey);
        }
        return cfg;
    }

    bool IsBypassAccount(const std::wstring& username) const {
        // A UPN input (user@corp.local) is additionally matched by its
        // local part, so "administrator@corp.local" hits the SAM-name
        // whitelist entry "administrator".
        size_t at = username.find(L'@');
        for (const auto& acc : bypassAccounts) {
            if (_wcsicmp(acc.c_str(), username.c_str()) == 0) return true;
            if (at != std::wstring::npos &&
                _wcsicmp(acc.c_str(), username.substr(0, at).c_str()) == 0) return true;
        }
        return false;
    }
};

// Logging helper to DebugView / debugger
inline void LogDebug(const wchar_t* fmt, ...) {
    wchar_t buf[1024];
    va_list args;
    va_start(args, fmt);
    _vsnwprintf_s(buf, _countof(buf), _TRUNCATE, fmt, args);
    va_end(args);
    OutputDebugStringW(L"[Ligament2FA] ");
    OutputDebugStringW(buf);
    OutputDebugStringW(L"\n");
}

// UTF-8 <-> UTF-16 helpers
inline std::string WideToUtf8(const std::wstring& wstr) {
    if (wstr.empty()) return std::string();
    int sizeNeeded = WideCharToMultiByte(CP_UTF8, 0, wstr.data(), (int)wstr.size(), nullptr, 0, nullptr, nullptr);
    std::string result(sizeNeeded, 0);
    WideCharToMultiByte(CP_UTF8, 0, wstr.data(), (int)wstr.size(), &result[0], sizeNeeded, nullptr, nullptr);
    return result;
}

inline std::wstring Utf8ToWide(const std::string& str) {
    if (str.empty()) return std::wstring();
    int sizeNeeded = MultiByteToWideChar(CP_UTF8, 0, str.data(), (int)str.size(), nullptr, 0);
    std::wstring result(sizeNeeded, 0);
    MultiByteToWideChar(CP_UTF8, 0, str.data(), (int)str.size(), &result[0], sizeNeeded);
    return result;
}

// Escapes a UTF-8 string for embedding inside a JSON string literal:
// '"' and '\' are backslash-escaped, control characters < 0x20 become
// \u00XX. Prevents both malformed requests (passwords with quotes) and
// field injection via concatenated key duplication.
inline std::string EscapeJson(const std::string& str) {
    static const char hex[] = "0123456789abcdef";
    std::string out;
    out.reserve(str.size());
    for (char c : str) {
        switch (c) {
        case '"':  out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\b': out += "\\b"; break;
        case '\f': out += "\\f"; break;
        case '\n': out += "\\n"; break;
        case '\r': out += "\\r"; break;
        case '\t': out += "\\t"; break;
        default:
            if ((unsigned char)c < 0x20) {
                out += "\\u00";
                out += hex[(unsigned char)c >> 4];
                out += hex[(unsigned char)c & 0x0F];
            } else {
                out += c;
            }
            break;
        }
    }
    return out;
}

// Base64URL encoding/decoding for WebAuthn tokens
inline std::string Base64UrlEncode(const unsigned char* data, size_t len) {
    static const char lookup[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    std::string out;
    int val = 0, valb = -6;
    for (size_t i = 0; i < len; i++) {
        val = (val << 8) + data[i];
        valb += 8;
        while (valb >= 0) {
            out.push_back(lookup[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }
    if (valb > -6) out.push_back(lookup[((val << 8) >> (valb + 8)) & 0x3F]);
    return out;
}

inline std::string Base64UrlEncode(const std::string& str) {
    return Base64UrlEncode(reinterpret_cast<const unsigned char*>(str.data()), str.size());
}

inline std::string Base64UrlEncode(const std::vector<unsigned char>& vec) {
    return Base64UrlEncode(vec.data(), vec.size());
}

inline std::vector<unsigned char> Base64UrlDecode(const std::string& in) {
    std::vector<unsigned char> out;
    std::vector<int> T(256, -1);
    for (int i = 0; i < 64; i++) {
        T["ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"[i]] = i;
    }
    int val = 0, valb = -8;
    for (unsigned char c : in) {
        if (T[c] == -1) break;
        val = (val << 6) + T[c];
        valb += 6;
        if (valb >= 0) {
            out.push_back((val >> valb) & 0xFF);
            valb -= 8;
        }
    }
    return out;
}

inline std::string ExtractJsonString(const std::string& json, const std::string& key) {
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

inline bool ExtractJsonBool(const std::string& json, const std::string& key) {
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

// Числовой поле-экстрактор для ответов вида {"error":"rate_limited",
// "retry_after":30}: ExtractJsonString не видит значения без кавычек.
// Возвращает fallback, если ключа или числа нет.
inline int ExtractJsonInt(const std::string& json, const std::string& key, int fallback = 0) {
    std::string needle = "\"" + key + "\"";
    size_t pos = json.find(needle);
    if (pos == std::string::npos) return fallback;

    pos = json.find(':', pos + needle.length());
    if (pos == std::string::npos) return fallback;

    ++pos;
    while (pos < json.size() && (json[pos] == ' ' || json[pos] == '\t')) ++pos;
    size_t end = pos;
    while (end < json.size() && json[end] >= '0' && json[end] <= '9') ++end;
    if (end == pos) return fallback;
    return atoi(json.substr(pos, end - pos).c_str());
}

} // namespace ligament
