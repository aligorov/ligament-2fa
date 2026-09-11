// LigamentProvider.h — ICredentialProvider & ICredentialProviderFilter implementation
#pragma once

#include "common.h"
#include "LigamentCredential.h"

namespace ligament {

class LigamentProvider : public ICredentialProvider, public ICredentialProviderFilter {
public:
    LigamentProvider();
    virtual ~LigamentProvider();

    // IUnknown
    IFACEMETHODIMP QueryInterface(REFIID riid, void** ppv);
    IFACEMETHODIMP_(ULONG) AddRef();
    IFACEMETHODIMP_(ULONG) Release();

    // ICredentialProvider
    IFACEMETHODIMP SetUsageScenario(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus, DWORD dwFlags);
    IFACEMETHODIMP SetSerialization(const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs);
    IFACEMETHODIMP Advise(ICredentialProviderEvents* pcpe, UINT_PTR upAdviseContext);
    IFACEMETHODIMP UnAdvise();
    IFACEMETHODIMP GetFieldDescriptorCount(DWORD* pdwCount);
    IFACEMETHODIMP GetFieldDescriptorAt(DWORD dwIndex, CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** ppcpfd);
    IFACEMETHODIMP GetCredentialCount(DWORD* pdwCount, DWORD* pdwDefault, BOOL* pbAutoLogonWithDefault);
    IFACEMETHODIMP GetCredentialAt(DWORD dwIndex, ICredentialProviderCredential** ppcpc);

    // ICredentialProviderFilter
    IFACEMETHODIMP Filter(
        CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
        DWORD dwFlags,
        GUID* rgclsidProviders,
        BOOL* rgbAllow,
        DWORD cProviders
    );
    IFACEMETHODIMP UpdateRemoteCredential(
        const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcsIn,
        CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcsOut
    );

private:
    LONG m_cRef = 1;
    ICredentialProviderEvents* m_pEvents = nullptr;
    UINT_PTR m_adviseContext = 0;
    CREDENTIAL_PROVIDER_USAGE_SCENARIO m_scenario = CPUS_INVALID;
    DWORD m_flags = 0;

    Config m_config;
    bool m_isRemoteSession = false;
    bool m_shouldEnforce2FA = false;

    LigamentCredential* m_pCredential = nullptr;

    bool CheckIfRemoteSession();
};

} // namespace ligament
