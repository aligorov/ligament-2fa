// dllmain.cpp — DLL exports and COM in-process registration
#include "common.h"
#include "ClassFactory.h"

HINSTANCE g_hinstDll = nullptr;
LONG g_cRefDll = 0;

static const wchar_t s_szCLSID[] = L"{7B896B21-8B35-4E7B-A350-9E17E5E3D10A}";
static const wchar_t s_szProviderName[] = L"Ligament 2FA Credential Provider";

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        g_hinstDll = hinstDLL;
        DisableThreadLibraryCalls(hinstDLL);
    }
    return TRUE;
}

STDAPI DllCanUnloadNow() {
    return (g_cRefDll == 0) ? S_OK : S_FALSE;
}

STDAPI DllGetClassObject(REFCLSID rclsid, REFIID riid, LPVOID* ppv) {
    if (!ppv) return E_POINTER;
    *ppv = nullptr;

    if (IsEqualCLSID(rclsid, CLSID_LigamentProvider)) {
        auto* pFactory = new ligament::ClassFactory();
        if (!pFactory) return E_OUTOFMEMORY;
        HRESULT hr = pFactory->QueryInterface(riid, ppv);
        pFactory->Release();
        return hr;
    }
    return CLASS_E_CLASSNOTAVAILABLE;
}

static HRESULT CreateRegKeyAndValue(HKEY hRoot, const std::wstring& subKey, const std::wstring& valueName, const std::wstring& data) {
    HKEY hKey = nullptr;
    LONG lRes = RegCreateKeyExW(hRoot, subKey.c_str(), 0, nullptr, REG_OPTION_NON_VOLATILE, KEY_WRITE, nullptr, &hKey, nullptr);
    if (lRes != ERROR_SUCCESS) return HRESULT_FROM_WIN32(lRes);

    lRes = RegSetValueExW(
        hKey,
        valueName.empty() ? nullptr : valueName.c_str(),
        0,
        REG_SZ,
        (const BYTE*)data.c_str(),
        (DWORD)((data.length() + 1) * sizeof(wchar_t))
    );
    RegCloseKey(hKey);
    return HRESULT_FROM_WIN32(lRes);
}

STDAPI DllRegisterServer() {
    wchar_t szDllPath[MAX_PATH] = {0};
    if (GetModuleFileNameW(g_hinstDll, szDllPath, _countof(szDllPath)) == 0) {
        return HRESULT_FROM_WIN32(GetLastError());
    }

    std::wstring clsidKey = std::wstring(L"CLSID\\") + s_szCLSID;
    std::wstring inprocKey = clsidKey + L"\\InprocServer32";

    // 1. Register COM InprocServer32 in HKCR
    CreateRegKeyAndValue(HKEY_CLASSES_ROOT, clsidKey, L"", s_szProviderName);
    CreateRegKeyAndValue(HKEY_CLASSES_ROOT, inprocKey, L"", szDllPath);
    CreateRegKeyAndValue(HKEY_CLASSES_ROOT, inprocKey, L"ThreadingModel", L"Apartment");

    // 2. Register Credential Provider in HKLM
    std::wstring cpKey = std::wstring(L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\Credential Providers\\") + s_szCLSID;
    CreateRegKeyAndValue(HKEY_LOCAL_MACHINE, cpKey, L"", s_szProviderName);

    // 3. Register Credential Provider Filter in HKLM
    std::wstring filterKey = std::wstring(L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\Credential Provider Filters\\") + s_szCLSID;
    CreateRegKeyAndValue(HKEY_LOCAL_MACHINE, filterKey, L"", s_szProviderName);

    ligament::LogDebug(L"Ligament 2FA Credential Provider registered successfully");
    return S_OK;
}

STDAPI DllUnregisterServer() {
    std::wstring clsidKey = std::wstring(L"CLSID\\") + s_szCLSID;
    std::wstring inprocKey = clsidKey + L"\\InprocServer32";
    std::wstring cpKey = std::wstring(L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\Credential Providers\\") + s_szCLSID;
    std::wstring filterKey = std::wstring(L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\Credential Provider Filters\\") + s_szCLSID;

    RegDeleteKeyW(HKEY_CLASSES_ROOT, inprocKey.c_str());
    RegDeleteKeyW(HKEY_CLASSES_ROOT, clsidKey.c_str());
    RegDeleteKeyW(HKEY_LOCAL_MACHINE, cpKey.c_str());
    RegDeleteKeyW(HKEY_LOCAL_MACHINE, filterKey.c_str());

    ligament::LogDebug(L"Ligament 2FA Credential Provider unregistered");
    return S_OK;
}
