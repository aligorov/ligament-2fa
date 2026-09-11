// LigamentCredential.h — ICredentialProviderCredential implementation
#pragma once

#include "common.h"
#include "HttpApiClient.h"
#include "WebAuthnClient.h"

namespace ligament {

enum FIELD_ID {
    FID_LOGO = 0,
    FID_LARGE_TEXT,
    FID_USERNAME,
    FID_PASSWORD,
    FID_SUBMIT,
    FID_STATUS_TEXT,
    FID_FIDO2_BTN,
    FID_OTP_CODE,
    FID_SWITCH_FACTOR_BTN,
    FID_NUM_FIELDS
};

enum AUTH_FACTOR_MODE {
    MODE_FIDO2 = 0,
    MODE_PUSH,
    MODE_OTP
};

extern const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR s_Fields[];

class LigamentCredential : public ICredentialProviderCredential {
public:
    LigamentCredential();
    virtual ~LigamentCredential();

    // IUnknown
    IFACEMETHODIMP QueryInterface(REFIID riid, void** ppv);
    IFACEMETHODIMP_(ULONG) AddRef();
    IFACEMETHODIMP_(ULONG) Release();

    // ICredentialProviderCredential
    IFACEMETHODIMP Advise(ICredentialProviderCredentialEvents* pcpce);
    IFACEMETHODIMP UnAdvise();
    IFACEMETHODIMP SetSelected(BOOL* pbAutoLogon);
    IFACEMETHODIMP SetDeselected();
    IFACEMETHODIMP GetFieldState(DWORD dwFieldID, CREDENTIAL_PROVIDER_FIELD_STATE* pcpfs, CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE* pcpfis);
    IFACEMETHODIMP GetStringValue(DWORD dwFieldID, PWSTR* ppsz);
    IFACEMETHODIMP GetBitmapValue(DWORD dwFieldID, HBITMAP* phbmp);
    IFACEMETHODIMP GetCheckboxValue(DWORD dwFieldID, BOOL* pbChecked, PWSTR* ppszLabel);
    IFACEMETHODIMP GetSubmitButtonValue(DWORD dwFieldID, DWORD* pdwAdjacentTo);
    IFACEMETHODIMP GetComboBoxValueCount(DWORD dwFieldID, DWORD* pcItems, DWORD* pdwSelectedItem);
    IFACEMETHODIMP GetComboBoxValueAt(DWORD dwFieldID, DWORD dwItem, PWSTR* ppszItem);
    IFACEMETHODIMP SetStringValue(DWORD dwFieldID, PCWSTR psz);
    IFACEMETHODIMP SetCheckboxValue(DWORD dwFieldID, BOOL bChecked);
    IFACEMETHODIMP SetComboBoxSelectedValue(DWORD dwFieldID, DWORD dwSelectedItem);
    IFACEMETHODIMP CommandLinkClicked(DWORD dwFieldID);
    IFACEMETHODIMP GetSerialization(
        CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr,
        CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs,
        PWSTR* ppszOptionalStatusText,
        CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon
    );
    IFACEMETHODIMP ReportResult(
        NTSTATUS ntsStatus,
        NTSTATUS ntsSubstatus,
        PWSTR* ppszOptionalStatusText,
        CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon
    );

    void Initialize(const Config& cfg, bool isRemote);

private:
    LONG m_cRef = 1;
    ICredentialProviderCredentialEvents* m_pEvents = nullptr;
    Config m_config;
    bool m_isRemoteSession = false;

    AUTH_FACTOR_MODE m_currentMode = MODE_FIDO2;
    std::wstring m_username;
    std::wstring m_domain;
    std::wstring m_password;
    std::wstring m_otpCode;
    std::wstring m_statusText;

    bool m_authenticated = false;
    std::unique_ptr<HttpApiClient> m_apiClient;
    std::unique_ptr<WebAuthnClient> m_webAuthn;

    // Background push polling. GetSerialization starts the worker thread and
    // returns CPGSR_NO_CREDENTIAL_NOT_FINISHED; the worker never touches COM
    // interfaces (m_pEvents) or other LogonUI state — it only updates
    // m_pollState under m_csPoll through a thread-local HttpApiClient.
    HANDLE m_hPollThread = nullptr;
    CRITICAL_SECTION m_csPoll;
    struct PollState {
        std::wstring status;   // empty, "approved", "denied", "expired", "timeout"
        bool done = false;
        bool stop = false;
    } m_pollState;
    std::wstring m_pollChallengeId;

    static DWORD WINAPI PushPollThreadProc(LPVOID lpParam);
    void RunPushPolling();
    void StopPollThread();
    void JoinPollThread();
    void ResetAuthState();

    void TriggerFIDO2Auth();
    void SwitchToNextMode();
    void UpdateFieldStates();
    void NotifyFieldChanged(DWORD dwFieldID);
    HRESULT KerbInteractiveLogonPack(
        const std::wstring& domain,
        const std::wstring& user,
        const std::wstring& password,
        CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs
    );
};

} // namespace ligament
