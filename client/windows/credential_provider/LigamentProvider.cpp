// LigamentProvider.cpp — Implementation of ICredentialProvider and ICredentialProviderFilter
#include "LigamentProvider.h"

namespace ligament {

// Microsoft standard Password Credential Provider GUID: {60b78e88-ead8-445c-9cfd-0b87f74ea6cd}
static const GUID CLSID_PasswordProvider =
    { 0x60b78e88, 0xead8, 0x445c, { 0x9c, 0xfd, 0x0b, 0x87, 0xf7, 0x4e, 0xa6, 0xcd } };

extern const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR s_Fields[];

LigamentProvider::LigamentProvider() {
    m_config = Config::LoadFromRegistry();
}

LigamentProvider::~LigamentProvider() {
    if (m_pCredential) {
        m_pCredential->Release();
        m_pCredential = nullptr;
    }
    if (m_pEvents) {
        m_pEvents->Release();
        m_pEvents = nullptr;
    }
}

bool LigamentProvider::CheckIfRemoteSession() {
    if (GetSystemMetrics(SM_REMOTESESSION) != 0) {
        return true;
    }
    unsigned short* pProtocol = nullptr;
    DWORD bytes = 0;
    if (WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, WTS_CURRENT_SESSION, WTSClientProtocolType, (LPWSTR*)&pProtocol, &bytes)) {
        bool isRdp = (pProtocol && *pProtocol != 0);
        WTSFreeMemory(pProtocol);
        if (isRdp) return true;
    }
    return false;
}

// IUnknown
HRESULT LigamentProvider::QueryInterface(REFIID riid, void** ppv) {
    static const QITAB qit[] = {
        QITABENT(LigamentProvider, ICredentialProvider),
        QITABENT(LigamentProvider, ICredentialProviderFilter),
        { 0 },
    };
    return QISearch(this, qit, riid, ppv);
}

ULONG LigamentProvider::AddRef() {
    return InterlockedIncrement(&m_cRef);
}

ULONG LigamentProvider::Release() {
    LONG c = InterlockedDecrement(&m_cRef);
    if (c == 0) delete this;
    return c;
}

// ICredentialProvider
HRESULT LigamentProvider::SetUsageScenario(CPUS_USAGE_SCENARIO cpus, DWORD dwFlags) {
    m_scenario = cpus;
    m_flags = dwFlags;
    m_isRemoteSession = CheckIfRemoteSession();
    m_config = Config::LoadFromRegistry();

    // Check if 2FA applies to this scenario
    if (cpus == CPUS_LOGON || cpus == CPUS_UNLOCK_WORKSTATION) {
        if (m_isRemoteSession && m_config.rdp2faEnabled) {
            m_shouldEnforce2FA = true;
        } else if (!m_isRemoteSession && m_config.console2faEnabled) {
            m_shouldEnforce2FA = true;
        }
    }

    LogDebug(L"SetUsageScenario: cpus=%d, remote=%d, enforce2fa=%d, server=%s",
        cpus, m_isRemoteSession ? 1 : 0, m_shouldEnforce2FA ? 1 : 0, m_config.serverUrl.c_str());

    if (m_shouldEnforce2FA && !m_pCredential) {
        m_pCredential = new LigamentCredential();
        m_pCredential->Initialize(m_config, m_isRemoteSession);
    }
    return S_OK;
}

HRESULT LigamentProvider::SetSerialization(const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs) {
    // If NLA or CredSSP already provided credentials, unpack them if needed
    return S_OK;
}

HRESULT LigamentProvider::Advise(ICredentialProviderEvents* pcpe, UINT_PTR upAdviseContext) {
    if (m_pEvents) m_pEvents->Release();
    m_pEvents = pcpe;
    m_adviseContext = upAdviseContext;
    if (m_pEvents) m_pEvents->AddRef();
    return S_OK;
}

HRESULT LigamentProvider::Unadvise() {
    if (m_pEvents) {
        m_pEvents->Release();
        m_pEvents = nullptr;
    }
    m_adviseContext = 0;
    return S_OK;
}

HRESULT LigamentProvider::GetFieldDescriptorCount(DWORD* pdwCount) {
    if (!pdwCount) return E_POINTER;
    *pdwCount = FID_NUM_FIELDS;
    return S_OK;
}

HRESULT LigamentProvider::GetFieldDescriptorAt(DWORD dwIndex, CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** ppcpfd) {
    if (!ppcpfd) return E_POINTER;
    if (dwIndex >= FID_NUM_FIELDS) return E_INVALIDARG;

    CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR* pcpfd = (CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR*)CoTaskMemAlloc(sizeof(CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR));
    if (!pcpfd) return E_OUTOFMEMORY;

    pcpfd->dwFieldID = s_Fields[dwIndex].dwFieldID;
    pcpfd->cpft = s_Fields[dwIndex].cpft;
    pcpfd->guidFieldType = s_Fields[dwIndex].guidFieldType;

    if (s_Fields[dwIndex].pszLabel) {
        SHStrDupW(s_Fields[dwIndex].pszLabel, &pcpfd->pszLabel);
    } else {
        pcpfd->pszLabel = nullptr;
    }

    *ppcpfd = pcpfd;
    return S_OK;
}

HRESULT LigamentProvider::GetCredentialCount(DWORD* pdwCount, DWORD* pdwDefault, BOOL* pbAutoLogonWithDefault) {
    if (!pdwCount || !pdwDefault || !pbAutoLogonWithDefault) return E_POINTER;

    if (m_shouldEnforce2FA && m_pCredential) {
        *pdwCount = 1;
        *pdwDefault = 0;
        *pbAutoLogonWithDefault = FALSE;
    } else {
        *pdwCount = 0;
        *pdwDefault = CREDENTIAL_PROVIDER_NO_DEFAULT;
        *pbAutoLogonWithDefault = FALSE;
    }
    return S_OK;
}

HRESULT LigamentProvider::GetCredentialAt(DWORD dwIndex, ICredentialProviderCredential** ppcpc) {
    if (!ppcpc) return E_POINTER;
    if (dwIndex != 0 || !m_pCredential) return E_INVALIDARG;

    m_pCredential->AddRef();
    *ppcpc = m_pCredential;
    return S_OK;
}

// ICredentialProviderFilter: Filter out default password provider during remote RDP when 2FA is active
HRESULT LigamentProvider::Filter(
    CPUS_USAGE_SCENARIO cpus,
    DWORD dwFlags,
    GUID* rgclsidProviders,
    BOOL* rgbAllow,
    DWORD cProviders)
{
    bool isRemote = CheckIfRemoteSession();
    Config cfg = Config::LoadFromRegistry();

    bool enforce = (isRemote && cfg.rdp2faEnabled) || (!isRemote && cfg.console2faEnabled);

    if (enforce) {
        for (DWORD i = 0; i < cProviders; ++i) {
            if (IsEqualGUID(rgclsidProviders[i], CLSID_PasswordProvider)) {
                // Suppress standard password-only tile in favor of Ligament 2FA
                rgbAllow[i] = FALSE;
            }
        }
    }
    return S_OK;
}

} // namespace ligament
