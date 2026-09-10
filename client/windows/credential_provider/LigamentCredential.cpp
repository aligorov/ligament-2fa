// LigamentCredential.cpp — Implementation of Credential tile logic
#include "LigamentCredential.h"

namespace ligament {

// Field descriptors
static const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR s_Fields[] = {
    { FID_LOGO, CPFT_TILE_IMAGE, L"Логотип", CPFG_CREDENTIAL_PROVIDER_LOGO },
    { FID_LARGE_TEXT, CPFT_LARGE_TEXT, L"Ligament 2FA", CPFG_CREDENTIAL_PROVIDER_LABEL },
    { FID_USERNAME, CPFT_EDIT_TEXT, L"Имя пользователя", CPFG_LOGON_USERNAME },
    { FID_PASSWORD, CPFT_PASSWORD_TEXT, L"Пароль", CPFG_LOGON_PASSWORD },
    { FID_SUBMIT, CPFT_SUBMIT_BUTTON, L"Войти", CPFG_SUBMIT_BUTTON },
    { FID_STATUS_TEXT, CPFT_SMALL_TEXT, L"Статус", CPFG_SM_STATUS },
    { FID_FIDO2_BTN, CPFT_COMMAND_LINK, L"Войти с помощью ключа (FIDO2 / YubiKey)", CPFG_USER_FIDO2 },
    { FID_OTP_CODE, CPFT_EDIT_TEXT, L"Код подтверждения (TOTP / YubiKey OTP)", CPFG_USER_OTP },
    { FID_SWITCH_FACTOR_BTN, CPFT_COMMAND_LINK, L"Выбрать другой способ входа (Push / Код / Ключ)", CPFG_SWITCH_FACTOR },
};

LigamentCredential::LigamentCredential() {
    m_statusText = L"Подтвердите вход вторым фактором";
}

LigamentCredential::~LigamentCredential() {
    m_stopPolling = true;
    if (m_hPollThread) {
        WaitForSingleObject(m_hPollThread, 1000);
        CloseHandle(m_hPollThread);
        m_hPollThread = nullptr;
    }
}

void LigamentCredential::Initialize(const Config& cfg, bool isRemote) {
    m_config = cfg;
    m_isRemoteSession = isRemote;
    m_apiClient = std::make_unique<HttpApiClient>(cfg.serverUrl);
    m_webAuthn = std::make_unique<WebAuthnClient>();

    if (cfg.fido2Enabled && m_webAuthn->IsAvailable()) {
        m_currentMode = MODE_FIDO2;
        m_statusText = L"Вставьте YubiKey и нажмите кнопку ниже";
    } else {
        m_currentMode = MODE_PUSH;
        m_statusText = L"Вход через Telegram Push / приложение Ligament";
    }
}

// IUnknown
HRESULT LigamentCredential::QueryInterface(REFIID riid, void** ppv) {
    static const QITAB qit[] = {
        QITABENT(LigamentCredential, ICredentialProviderCredential),
        QITABENT(LigamentCredential, ICredentialProviderCredential2),
        { 0 },
    };
    return QISearch(this, qit, riid, ppv);
}

ULONG LigamentCredential::AddRef() {
    return InterlockedIncrement(&m_cRef);
}

ULONG LigamentCredential::Release() {
    LONG c = InterlockedDecrement(&m_cRef);
    if (c == 0) delete this;
    return c;
}

// ICredentialProviderCredential
HRESULT LigamentCredential::Advise(ICredentialProviderCredentialEvents* pcpce) {
    if (m_pEvents) m_pEvents->Release();
    m_pEvents = pcpce;
    if (m_pEvents) m_pEvents->AddRef();
    return S_OK;
}

HRESULT LigamentCredential::Unadvise() {
    if (m_pEvents) {
        m_pEvents->Release();
        m_pEvents = nullptr;
    }
    return S_OK;
}

HRESULT LigamentCredential::SetSelected(BOOL* pbAutoLogon) {
    *pbAutoLogon = FALSE;
    return S_OK;
}

HRESULT LigamentCredential::SetDeselected() {
    return S_OK;
}

HRESULT LigamentCredential::GetFieldState(
    DWORD dwFieldID,
    CREDENTIAL_PROVIDER_FIELD_STATE* pcpfs,
    CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE* pcpfis)
{
    *pcpfis = CPFIS_NONE;

    switch (dwFieldID) {
    case FID_LOGO:
    case FID_LARGE_TEXT:
    case FID_USERNAME:
    case FID_PASSWORD:
    case FID_SUBMIT:
    case FID_STATUS_TEXT:
    case FID_SWITCH_FACTOR_BTN:
        *pcpfs = CPFS_DISPLAYED;
        if (dwFieldID == FID_USERNAME || dwFieldID == FID_PASSWORD) {
            *pcpfis = CPFIS_FOCUSED;
        }
        break;

    case FID_FIDO2_BTN:
        *pcpfs = (m_currentMode == MODE_FIDO2) ? CPFS_DISPLAYED : CPFS_HIDDEN;
        break;

    case FID_OTP_CODE:
        *pcpfs = (m_currentMode == MODE_OTP) ? CPFS_DISPLAYED : CPFS_HIDDEN;
        break;

    default:
        *pcpfs = CPFS_HIDDEN;
        break;
    }
    return S_OK;
}

HRESULT LigamentCredential::GetStringValue(DWORD dwFieldID, PWSTR* ppsz) {
    std::wstring val;
    switch (dwFieldID) {
    case FID_LARGE_TEXT:
        val = L"Ligament Enterprise 2FA";
        break;
    case FID_USERNAME:
        val = m_username;
        break;
    case FID_PASSWORD:
        val = m_password;
        break;
    case FID_STATUS_TEXT:
        val = m_statusText;
        break;
    case FID_FIDO2_BTN:
        val = L"Войти с помощью YubiKey (FIDO2)";
        break;
    case FID_OTP_CODE:
        val = m_otpCode;
        break;
    case FID_SWITCH_FACTOR_BTN:
        if (m_currentMode == MODE_FIDO2) val = L"Переключить на Telegram Push / Код";
        else if (m_currentMode == MODE_PUSH) val = L"Переключить на ввод TOTP / YubiKey OTP";
        else val = L"Переключить на ключ YubiKey (FIDO2)";
        break;
    default:
        break;
    }
    return SHStrDupW(val.c_str(), ppsz);
}

HRESULT LigamentCredential::GetBitmapValue(DWORD dwFieldID, HBITMAP* phbmp) {
    *phbmp = nullptr;
    return E_NOTIMPL;
}

HRESULT LigamentCredential::GetCheckboxValue(DWORD dwFieldID, BOOL* pbChecked, PWSTR* ppszLabel) {
    return E_NOTIMPL;
}

HRESULT LigamentCredential::GetSubmitButtonValue(DWORD dwFieldID, DWORD* pdwAdjacentTo) {
    if (dwFieldID == FID_SUBMIT) {
        *pdwAdjacentTo = FID_PASSWORD;
        return S_OK;
    }
    return E_NOTIMPL;
}

HRESULT LigamentCredential::GetComboBoxValueCount(DWORD dwFieldID, DWORD* pcItems, DWORD* pdwSelectedItem) {
    return E_NOTIMPL;
}

HRESULT LigamentCredential::GetComboBoxValueAt(DWORD dwFieldID, DWORD dwItem, PWSTR* ppszItem) {
    return E_NOTIMPL;
}

HRESULT LigamentCredential::SetStringValue(DWORD dwFieldID, PCWSTR psz) {
    if (!psz) psz = L"";
    switch (dwFieldID) {
    case FID_USERNAME: {
        m_username = psz;
        // Split DOMAIN\user if present
        size_t slash = m_username.find(L'\\');
        if (slash != std::wstring::npos) {
            m_domain = m_username.substr(0, slash);
            m_username = m_username.substr(slash + 1);
        }
        break;
    }
    case FID_PASSWORD:
        m_password = psz;
        break;
    case FID_OTP_CODE:
        m_otpCode = psz;
        break;
    }
    return S_OK;
}

HRESULT LigamentCredential::SetCheckboxValue(DWORD dwFieldID, BOOL bChecked) {
    return E_NOTIMPL;
}

HRESULT LigamentCredential::SetComboBoxSelectedValue(DWORD dwFieldID, DWORD dwSelectedItem) {
    return E_NOTIMPL;
}

HRESULT LigamentCredential::CommandLinkClicked(DWORD dwFieldID) {
    if (dwFieldID == FID_FIDO2_BTN) {
        TriggerFIDO2Auth();
    } else if (dwFieldID == FID_SWITCH_FACTOR_BTN) {
        SwitchToNextMode();
    }
    return S_OK;
}

void LigamentCredential::SwitchToNextMode() {
    if (m_currentMode == MODE_FIDO2) m_currentMode = MODE_PUSH;
    else if (m_currentMode == MODE_PUSH) m_currentMode = MODE_OTP;
    else m_currentMode = (m_config.fido2Enabled && m_webAuthn->IsAvailable()) ? MODE_FIDO2 : MODE_PUSH;

    UpdateFieldStates();
}

void LigamentCredential::UpdateFieldStates() {
    if (m_currentMode == MODE_FIDO2) {
        m_statusText = L"Нажмите кнопку для запроса касания YubiKey";
    } else if (m_currentMode == MODE_PUSH) {
        m_statusText = L"Вход через Telegram / Ligament Authenticator";
    } else if (m_currentMode == MODE_OTP) {
        m_statusText = L"Введите 6 цифр TOTP или коснитесь YubiKey";
    }

    if (m_pEvents) {
        m_pEvents->OnFieldStateChanged(FID_FIDO2_BTN);
        m_pEvents->OnFieldStateChanged(FID_OTP_CODE);
        m_pEvents->OnFieldStateChanged(FID_STATUS_TEXT);
        m_pEvents->OnFieldStateChanged(FID_SWITCH_FACTOR_BTN);
    }
}

void LigamentCredential::TriggerFIDO2Auth() {
    if (m_username.empty()) {
        m_statusText = L"Сначала введите имя пользователя";
        if (m_pEvents) m_pEvents->OnFieldStateChanged(FID_STATUS_TEXT);
        return;
    }

    m_statusText = L"Запрос сессии WebAuthn...";
    if (m_pEvents) m_pEvents->OnFieldStateChanged(FID_STATUS_TEXT);

    WebAuthnBeginResult beginRes = m_apiClient->WebAuthnBegin(m_username, m_password);
    if (!beginRes.success) {
        m_statusText = L"Ошибка WebAuthn: " + Utf8ToWide(beginRes.error);
        if (m_pEvents) m_pEvents->OnFieldStateChanged(FID_STATUS_TEXT);
        return;
    }

    // Extract challenge & rpId from raw options JSON or use server host
    std::string challenge = ExtractJsonString(beginRes.rawOptionsJson, "challenge");
    std::wstring rpId = Utf8ToWide(ExtractJsonString(beginRes.rawOptionsJson, "rpId"));
    if (rpId.empty()) {
        // Fallback to server host from URL
        URL_COMPONENTS comp = { sizeof(comp) };
        wchar_t host[256] = {0};
        comp.lpszHostName = host;
        comp.dwHostNameLength = _countof(host);
        WinHttpCrackUrl(m_config.serverUrl.c_str(), 0, 0, &comp);
        rpId = host;
    }

    m_statusText = L"Коснитесь мигающего ключа YubiKey...";
    if (m_pEvents) m_pEvents->OnFieldStateChanged(FID_STATUS_TEXT);

    std::string assertionJson, authErr;
    HWND hWnd = GetForegroundWindow();
    bool asserted = m_webAuthn->Authenticate(hWnd, rpId, challenge, assertionJson, authErr);
    if (!asserted) {
        m_statusText = L"Ключ отклонен: " + Utf8ToWide(authErr);
        if (m_pEvents) m_pEvents->OnFieldStateChanged(FID_STATUS_TEXT);
        return;
    }

    m_statusText = L"Проверка криптографической подписи...";
    if (m_pEvents) m_pEvents->OnFieldStateChanged(FID_STATUS_TEXT);

    std::string finishErr;
    if (m_apiClient->WebAuthnFinish(beginRes.handle, assertionJson, finishErr)) {
        m_authenticated = true;
        m_statusText = L"Ключ успешно подтвержден!";
        if (m_pEvents) {
            m_pEvents->OnFieldStateChanged(FID_STATUS_TEXT);
            m_pEvents->OnCredentialsChanged();
        }
    } else {
        m_statusText = L"Ошибка валидации ключа: " + Utf8ToWide(finishErr);
        if (m_pEvents) m_pEvents->OnFieldStateChanged(FID_STATUS_TEXT);
    }
}

// Background thread for push polling
DWORD WINAPI LigamentCredential::PushPollThreadProc(LPVOID lpParam) {
    auto* self = reinterpret_cast<LigamentCredential*>(lpParam);
    // Background polling runs in RunPushPolling
    return 0;
}

void LigamentCredential::RunPushPolling(const std::wstring& challengeId) {
    int maxPolls = m_config.pushTimeoutSec;
    for (int i = 0; i < maxPolls && !m_stopPolling; ++i) {
        Sleep(1000);
        std::wstring status;
        std::string err;
        if (m_apiClient->PollStatus(challengeId, status, err)) {
            if (status == L"approved") {
                m_authenticated = true;
                m_statusText = L"Вход подтвержден в Telegram!";
                if (m_pEvents) {
                    m_pEvents->OnFieldStateChanged(FID_STATUS_TEXT);
                    m_pEvents->OnCredentialsChanged();
                }
                break;
            } else if (status == L"rejected") {
                m_statusText = L"Вход отклонен пользователем в Telegram";
                if (m_pEvents) m_pEvents->OnFieldStateChanged(FID_STATUS_TEXT);
                break;
            }
        }
    }
}

HRESULT LigamentCredential::GetSerialization(
    CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr,
    CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs,
    PWSTR* ppszOptionalStatusText,
    CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon)
{
    *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
    *pcpcs = {0};
    *ppszOptionalStatusText = nullptr;
    *pcpsiOptionalStatusIcon = CPSI_NONE;

    if (m_username.empty() || m_password.empty()) {
        SHStrDupW(L"Введите имя пользователя и пароль", ppszOptionalStatusText);
        return S_OK;
    }

    // 1. Check bypass accounts (Emergency / Break-Glass)
    if (m_config.IsBypassAccount(m_username)) {
        LogDebug(L"Account %s is in bypass whitelist, skipping 2FA", m_username.c_str());
        KerbInteractiveLogonPack(m_domain, m_username, m_password, pcpcs);
        *pcpgsr = CPGSR_RETURN_CREDENTIAL_FINISHED;
        return S_OK;
    }

    // 2. If already validated via FIDO2 / Push:
    if (m_authenticated) {
        KerbInteractiveLogonPack(m_domain, m_username, m_password, pcpcs);
        *pcpgsr = CPGSR_RETURN_CREDENTIAL_FINISHED;
        return S_OK;
    }

    // 3. Mode: OTP code (TOTP or YubiKey OTP)
    if (m_currentMode == MODE_OTP) {
        if (m_otpCode.empty()) {
            SHStrDupW(L"Введите 6 цифр TOTP или коснитесь YubiKey", ppszOptionalStatusText);
            return S_OK;
        }

        std::string err;
        if (m_apiClient->VerifyCombined(m_username, m_password, m_otpCode, err)) {
            m_authenticated = true;
            KerbInteractiveLogonPack(m_domain, m_username, m_password, pcpcs);
            *pcpgsr = CPGSR_RETURN_CREDENTIAL_FINISHED;
            return S_OK;
        } else {
            std::wstring msg = L"Неверный пароль или код 2FA (" + Utf8ToWide(err) + L")";
            SHStrDupW(msg.c_str(), ppszOptionalStatusText);
            *pcpsiOptionalStatusIcon = CPSI_ERROR;
            return S_OK;
        }
    }

    // 4. Mode: Push (Telegram / Ligament App)
    if (m_currentMode == MODE_PUSH) {
        std::wstring challengeId;
        std::string err;
        if (m_apiClient->StartPush(m_username, L"telegram", challengeId, err)) {
            m_statusText = L"Push отправлен! Подтвердите вход в Telegram...";
            if (m_pEvents) m_pEvents->OnFieldStateChanged(FID_STATUS_TEXT);

            // Poll synchronously or in thread
            for (int i = 0; i < m_config.pushTimeoutSec; ++i) {
                Sleep(1000);
                std::wstring status;
                if (m_apiClient->PollStatus(challengeId, status, err)) {
                    if (status == L"approved") {
                        m_authenticated = true;
                        KerbInteractiveLogonPack(m_domain, m_username, m_password, pcpcs);
                        *pcpgsr = CPGSR_RETURN_CREDENTIAL_FINISHED;
                        return S_OK;
                    } else if (status == L"rejected") {
                        SHStrDupW(L"Вход отклонен в Telegram", ppszOptionalStatusText);
                        *pcpsiOptionalStatusIcon = CPSI_ERROR;
                        return S_OK;
                    }
                }
            }
            SHStrDupW(L"Время ожидания подтверждения истекло", ppszOptionalStatusText);
            *pcpsiOptionalStatusIcon = CPSI_WARNING;
            return S_OK;
        } else {
            // Check fail-close policy
            if (!m_config.failClose && err == "network_error") {
                LogDebug(L"Fail-Open allowed due to network error and policy");
                KerbInteractiveLogonPack(m_domain, m_username, m_password, pcpcs);
                *pcpgsr = CPGSR_RETURN_CREDENTIAL_FINISHED;
                return S_OK;
            }
            std::wstring msg = L"Ошибка отправки Push (" + Utf8ToWide(err) + L")";
            SHStrDupW(msg.c_str(), ppszOptionalStatusText);
            *pcpsiOptionalStatusIcon = CPSI_ERROR;
            return S_OK;
        }
    }

    // 5. Mode: FIDO2 trigger on submit if button was not clicked
    if (m_currentMode == MODE_FIDO2) {
        TriggerFIDO2Auth();
        if (m_authenticated) {
            KerbInteractiveLogonPack(m_domain, m_username, m_password, pcpcs);
            *pcpgsr = CPGSR_RETURN_CREDENTIAL_FINISHED;
            return S_OK;
        }
    }

    return S_OK;
}

HRESULT LigamentCredential::ReportResult(
    NTSTATUS ntsStatus,
    NTSTATUS ntsSubstatus,
    PWSTR* ppszOptionalStatusText,
    CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon)
{
    return S_OK;
}

HRESULT LigamentCredential::GetUserSid(PWSTR* ppszSid) {
    *ppszSid = nullptr;
    return E_NOTIMPL;
}

HRESULT LigamentCredential::KerbInteractiveLogonPack(
    const std::wstring& domain,
    const std::wstring& user,
    const std::wstring& password,
    CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs)
{
    // Serialize into KERB_INTERACTIVE_LOGON
    DWORD domainBytes = (DWORD)(domain.length() * sizeof(wchar_t));
    DWORD userBytes = (DWORD)(user.length() * sizeof(wchar_t));
    DWORD passBytes = (DWORD)(password.length() * sizeof(wchar_t));

    DWORD totalSize = sizeof(KERB_INTERACTIVE_LOGON) + domainBytes + userBytes + passBytes;
    BYTE* buffer = (BYTE*)CoTaskMemAlloc(totalSize);
    if (!buffer) return E_OUTOFMEMORY;
    ZeroMemory(buffer, totalSize);

    KERB_INTERACTIVE_LOGON* pLogon = (KERB_INTERACTIVE_LOGON*)buffer;
    pLogon->MessageType = KerbInteractiveLogon;

    BYTE* ptr = buffer + sizeof(KERB_INTERACTIVE_LOGON);

    pLogon->LogonDomainName.Length = (USHORT)domainBytes;
    pLogon->LogonDomainName.MaximumLength = (USHORT)domainBytes;
    pLogon->LogonDomainName.Buffer = (PWSTR)ptr;
    CopyMemory(ptr, domain.data(), domainBytes);
    ptr += domainBytes;

    pLogon->UserName.Length = (USHORT)userBytes;
    pLogon->UserName.MaximumLength = (USHORT)userBytes;
    pLogon->UserName.Buffer = (PWSTR)ptr;
    CopyMemory(ptr, user.data(), userBytes);
    ptr += userBytes;

    pLogon->Password.Length = (USHORT)passBytes;
    pLogon->Password.MaximumLength = (USHORT)passBytes;
    pLogon->Password.Buffer = (PWSTR)ptr;
    CopyMemory(ptr, password.data(), passBytes);

    pcpcs->clsidCredentialProvider = CLSID_LigamentProvider;
    pcpcs->ulAuthenticationPackage = 0; // Negotiate
    pcpcs->cbSerialization = totalSize;
    pcpcs->rgbSerialization = buffer;

    return S_OK;
}

} // namespace ligament
