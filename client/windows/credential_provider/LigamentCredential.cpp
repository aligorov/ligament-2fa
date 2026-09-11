// LigamentCredential.cpp — Implementation of Credential tile logic
#include "LigamentCredential.h"

namespace ligament {

// Field descriptors
extern const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR s_Fields[] = {
    { FID_LOGO, CPFT_TILE_IMAGE, L"Логотип", GUID_NULL },
    { FID_LARGE_TEXT, CPFT_LARGE_TEXT, L"Ligament 2FA", GUID_NULL },
    { FID_USERNAME, CPFT_EDIT_TEXT, L"Имя пользователя", GUID_NULL },
    { FID_PASSWORD, CPFT_PASSWORD_TEXT, L"Пароль", GUID_NULL },
    { FID_SUBMIT, CPFT_SUBMIT_BUTTON, L"Войти", GUID_NULL },
    { FID_STATUS_TEXT, CPFT_SMALL_TEXT, L"Статус", GUID_NULL },
    { FID_FIDO2_BTN, CPFT_COMMAND_LINK, L"Войти с помощью ключа (FIDO2 / YubiKey)", GUID_NULL },
    { FID_OTP_CODE, CPFT_EDIT_TEXT, L"Код подтверждения (TOTP / YubiKey OTP)", GUID_NULL },
    { FID_SWITCH_FACTOR_BTN, CPFT_COMMAND_LINK, L"Выбрать другой способ входа (Push / Код / Ключ)", GUID_NULL },
};

LigamentCredential::LigamentCredential() {
    InterlockedIncrement(&g_cRefDll);
    InitializeCriticalSection(&m_csPoll);
    m_statusText = L"Подтвердите вход вторым фактором";
}

// Человеческие тексты для кодов ошибок сервера и транспорта. Сырые коды
// ("locked", "rate_limited", "status_423"...) пользователю не показываются;
// неизвестный код сервера конвертируется из UTF-8 и выводится как есть
// (сервер может прислать свой текст). retryAfterSec — поле retry_after из
// ответов 429 (см. HttpApiClient::LastRetryAfterSec).
static std::wstring DescribeServerError(const std::string& err, int retryAfterSec) {
    if (err == "network_error") {
        return L"сервер 2FA недоступен (проверьте сеть и настройку ServerURL)";
    }
    if (err == "bad_credentials" || err == "status_401") {
        return L"неверное имя пользователя или пароль";
    }
    if (err == "locked" || err == "status_423") {
        return L"вход временно заблокирован из-за неудачных попыток";
    }
    if (err == "rate_limited" || err == "status_429") {
        if (retryAfterSec > 0) {
            return L"слишком много попыток, повторите через " + std::to_wstring(retryAfterSec) + L" с";
        }
        return L"слишком много попыток, подождите немного";
    }
    if (err == "cooldown") {
        if (retryAfterSec > 0) {
            return L"повторная отправка возможна через " + std::to_wstring(retryAfterSec) + L" с";
        }
        return L"повторная отправка пока недоступна, подождите";
    }
    if (err == "no_channel") {
        return L"у пользователя не настроен канал доставки 2FA";
    }
    if (err == "no_credentials") {
        return L"нет зарегистрированных ключей FIDO2";
    }
    if (err == "webauthn_disabled" || err == "status_503") {
        return L"этот способ входа отключен на сервере";
    }
    if (err == "internal" || err == "status_500") {
        return L"внутренняя ошибка сервера 2FA";
    }
    if (err.rfind("status_", 0) == 0) {
        return L"сервер 2FA ответил ошибкой HTTP " + Utf8ToWide(err.substr(7));
    }
    if (err.empty()) {
        return L"сервер 2FA вернул пустой ответ";
    }
    return Utf8ToWide(err);
}

LigamentCredential::~LigamentCredential() {
    StopPollThread();
    DeleteCriticalSection(&m_csPoll);
    if (!m_password.empty()) {
        SecureZeroMemory(&m_password[0], m_password.size() * sizeof(wchar_t));
        m_password.clear();
    }
    if (!m_otpCode.empty()) {
        SecureZeroMemory(&m_otpCode[0], m_otpCode.size() * sizeof(wchar_t));
        m_otpCode.clear();
    }
    InterlockedDecrement(&g_cRefDll);
}

void LigamentCredential::Initialize(const Config& cfg, bool isRemote) {
    m_config = cfg;
    m_isRemoteSession = isRemote;
    // Этот клиент работает в потоке LogonUI (GetSerialization/
    // TriggerFIDO2Auth): receive-таймаут 15 c вместо дефолтных 45 c, чтобы
    // один медленный/умерший запрос не замораживал экран входа и RDP-сессию
    // на отведённый WinHTTP срок (connect 10 c + receive 45 c ~ минута).
    m_apiClient = std::make_unique<HttpApiClient>(cfg.serverUrl, cfg.allowSelfSigned, 15000);
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
    // Note: only ICredentialProviderCredential is implemented; the tile does
    // not implement ICredentialProviderCredential2 (GetUserSid), so it must
    // not be advertised in the QITAB.
    static const QITAB qit[] = {
        QITABENT(LigamentCredential, ICredentialProviderCredential),
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

HRESULT LigamentCredential::UnAdvise() {
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
    // Leaving the tile voids any 2FA result and pending push polling.
    ResetAuthState();
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
        *pcpfs = CPFS_DISPLAY_IN_SELECTED_TILE;
        if (dwFieldID == FID_USERNAME || dwFieldID == FID_PASSWORD) {
            *pcpfis = CPFIS_FOCUSED;
        }
        break;

    case FID_FIDO2_BTN:
        *pcpfs = (m_currentMode == MODE_FIDO2) ? CPFS_DISPLAY_IN_SELECTED_TILE : CPFS_HIDDEN;
        break;

    case FID_OTP_CODE:
        *pcpfs = (m_currentMode == MODE_OTP) ? CPFS_DISPLAY_IN_SELECTED_TILE : CPFS_HIDDEN;
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
        std::wstring raw = psz;
        // Reconstruct the previously stored name (DOMAIN\user or plain user)
        // to detect an actual change: switching users must void the previous
        // 2FA result, otherwise the next logon skips the second factor.
        std::wstring prevRaw = m_domain.empty()
            ? m_username
            : m_domain + L"\\" + m_username;
        if (_wcsicmp(raw.c_str(), prevRaw.c_str()) != 0) {
            ResetAuthState();
        }
        // Split DOMAIN\user if present; a plain name clears any stale domain
        size_t slash = raw.find(L'\\');
        if (slash != std::wstring::npos) {
            m_domain = raw.substr(0, slash);
            m_username = raw.substr(slash + 1);
        } else {
            m_domain.clear();
            m_username = raw;
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

void LigamentCredential::NotifyFieldChanged(DWORD dwFieldID) {
    if (!m_pEvents) return;
    CREDENTIAL_PROVIDER_FIELD_STATE cpfs = CPFS_HIDDEN;
    CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE cpfis = CPFIS_NONE;
    GetFieldState(dwFieldID, &cpfs, &cpfis);
    m_pEvents->SetFieldState(this, dwFieldID, cpfs);
    m_pEvents->SetFieldInteractiveState(this, dwFieldID, cpfis);
    if (dwFieldID == FID_STATUS_TEXT) {
        m_pEvents->SetFieldString(this, FID_STATUS_TEXT, m_statusText.c_str());
    } else if (dwFieldID == FID_SWITCH_FACTOR_BTN) {
        PWSTR psz = nullptr;
        if (SUCCEEDED(GetStringValue(FID_SWITCH_FACTOR_BTN, &psz)) && psz) {
            m_pEvents->SetFieldString(this, FID_SWITCH_FACTOR_BTN, psz);
            CoTaskMemFree(psz);
        }
    }
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
        NotifyFieldChanged(FID_FIDO2_BTN);
        NotifyFieldChanged(FID_OTP_CODE);
        NotifyFieldChanged(FID_STATUS_TEXT);
        NotifyFieldChanged(FID_SWITCH_FACTOR_BTN);
    }
}

void LigamentCredential::TriggerFIDO2Auth() {
    if (m_username.empty()) {
        m_statusText = L"Сначала введите имя пользователя";
        NotifyFieldChanged(FID_STATUS_TEXT);
        return;
    }

    m_statusText = L"Запрос сессии WebAuthn...";
    NotifyFieldChanged(FID_STATUS_TEXT);

    WebAuthnBeginResult beginRes = m_apiClient->WebAuthnBegin(m_username, m_password);
    if (!beginRes.success) {
        m_statusText = L"Ошибка WebAuthn: " + DescribeServerError(beginRes.error, m_apiClient->LastRetryAfterSec());
        NotifyFieldChanged(FID_STATUS_TEXT);
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
    NotifyFieldChanged(FID_STATUS_TEXT);

    std::string assertionJson, authErr;
    HWND hWnd = GetForegroundWindow();
    bool asserted = m_webAuthn->Authenticate(hWnd, rpId, challenge, assertionJson, authErr);
    if (!asserted) {
        m_statusText = L"Ключ отклонен: " + Utf8ToWide(authErr);
        NotifyFieldChanged(FID_STATUS_TEXT);
        return;
    }

    m_statusText = L"Проверка криптографической подписи...";
    NotifyFieldChanged(FID_STATUS_TEXT);

    std::string finishErr;
    if (m_apiClient->WebAuthnFinish(beginRes.handle, assertionJson, finishErr)) {
        m_authenticated = true;
        m_statusText = L"Ключ успешно подтвержден! Нажмите 'Войти'";
        NotifyFieldChanged(FID_STATUS_TEXT);
    } else {
        m_statusText = L"Ошибка валидации ключа: " + DescribeServerError(finishErr, m_apiClient->LastRetryAfterSec());
        NotifyFieldChanged(FID_STATUS_TEXT);
    }
}

// Background thread for push polling: thin wrapper over RunPushPolling.
DWORD WINAPI LigamentCredential::PushPollThreadProc(LPVOID lpParam) {
    auto* self = reinterpret_cast<LigamentCredential*>(lpParam);
    self->RunPushPolling();
    return 0;
}

void LigamentCredential::RunPushPolling() {
    // Copy everything the worker needs up front. The worker must never touch
    // COM interfaces (m_pEvents) or LogonUI state: it communicates only
    // through m_pollState under m_csPoll and uses its own HttpApiClient.
    std::wstring challengeId;
    {
        EnterCriticalSection(&m_csPoll);
        challengeId = m_pollChallengeId;
        LeaveCriticalSection(&m_csPoll);
    }
    Config cfg = m_config; // stable after Initialize; read-only here

    // Короткий receive-таймаут: один запрос блокирует поток не дольше ~8 c,
    // поэтому остановка (stop-флаг проверяется между запросами) и join в
    // LogonUI занимают секунды — это же ограничивает ожидание в деструкторе.
    HttpApiClient client(cfg.serverUrl, cfg.allowSelfSigned, 8000);

    int maxPolls = cfg.pushTimeoutSec;
    for (int i = 0; i < maxPolls; ++i) {
        // Wait one second between polls, in slices so that a stop request
        // is honored promptly.
        for (int slice = 0; slice < 4; ++slice) {
            EnterCriticalSection(&m_csPoll);
            bool stop = m_pollState.stop;
            LeaveCriticalSection(&m_csPoll);
            if (stop) return;
            Sleep(250);
        }

        std::wstring status;
        std::string err;
        // Server statuses: "approved" | "denied" | "pending" | "expired".
        // Network errors are tolerated until the overall timeout.
        if (client.PollStatus(challengeId, status, err)) {
            if (status == L"approved" || status == L"denied" || status == L"expired") {
                EnterCriticalSection(&m_csPoll);
                if (!m_pollState.stop) {
                    m_pollState.status = status;
                    m_pollState.done = true;
                }
                LeaveCriticalSection(&m_csPoll);
                return;
            }
            // "pending" and unknown statuses: keep polling
        }

        EnterCriticalSection(&m_csPoll);
        bool stop = m_pollState.stop;
        LeaveCriticalSection(&m_csPoll);
        if (stop) return;
    }

    EnterCriticalSection(&m_csPoll);
    if (!m_pollState.stop) {
        m_pollState.status = L"timeout";
        m_pollState.done = true;
    }
    LeaveCriticalSection(&m_csPoll);
}

void LigamentCredential::StopPollThread() {
    EnterCriticalSection(&m_csPoll);
    m_pollState.stop = true;
    LeaveCriticalSection(&m_csPoll);
    JoinPollThread();
}

void LigamentCredential::JoinPollThread() {
    if (m_hPollThread) {
        // Ждём ЗАВЕРШЕНИЯ потока без ограниченного таймаута: bounded-wait
        // против долгого WinHTTP-вызова приводил к освобождению объекта при
        // живом воркере (use-after-free в winlogon). Ожидание конечно по
        // построению: receive-таймаут poll-клиента 8 c, stop-флаг воркер
        // проверяет между запросами и в срезах ожидания.
        WaitForSingleObject(m_hPollThread, INFINITE);
        CloseHandle(m_hPollThread);
        m_hPollThread = nullptr;
    }
    // Старый воркер гарантированно завершён — состояние безопасно сбрасывать
    // и новый запуск не скрестится со старым результатом.
    EnterCriticalSection(&m_csPoll);
    m_pollState.status.clear();
    m_pollState.done = false;
    LeaveCriticalSection(&m_csPoll);
}

void LigamentCredential::ResetAuthState() {
    // A previously confirmed second factor must not survive a failed logon,
    // tile deselection or a switch to another user name.
    m_authenticated = false;
    if (!m_otpCode.empty()) {
        SecureZeroMemory(&m_otpCode[0], m_otpCode.size() * sizeof(wchar_t));
        m_otpCode.clear();
    }
    StopPollThread();
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
        // Do not log the user name: this DLL runs in winlogon/LogonUI context
        LogDebug(L"Account is in bypass whitelist, skipping 2FA");
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
            std::wstring msg = L"Вход отклонен: " + DescribeServerError(err, m_apiClient->LastRetryAfterSec());
            SHStrDupW(msg.c_str(), ppszOptionalStatusText);
            *pcpsiOptionalStatusIcon = CPSI_ERROR;
            return S_OK;
        }
    }

    // 4. Mode: Push (Telegram / Ligament App). Polling runs on a worker
    //    thread; GetSerialization never blocks the LogonUI thread — it starts
    //    the push once, then only checks the shared result and asks LogonUI
    //    to call again (CPGSR_NO_CREDENTIAL_NOT_FINISHED).
    if (m_currentMode == MODE_PUSH) {
        bool done = false;
        std::wstring status;
        if (!m_hPollThread) {
            // No worker running: send a fresh push challenge.
            std::wstring challengeId;
            std::wstring numberMatch;
            std::string err;
            if (m_apiClient->StartPush(m_username, m_password, challengeId, numberMatch, err)) {
                // number-matching: приложение требует ввести контрольное
                // число — показываем его ЗДЕСЬ, на экране входа (RDP).
                if (!numberMatch.empty()) {
                    m_statusText = L"Подтвердите вход в приложении Ligament. Введите в приложении цифры: " + numberMatch;
                } else {
                    m_statusText = L"Push отправлен! Подтвердите вход в приложении/Telegram...";
                }
                NotifyFieldChanged(FID_STATUS_TEXT);

                EnterCriticalSection(&m_csPoll);
                m_pollState = PollState();
                m_pollChallengeId = challengeId;
                LeaveCriticalSection(&m_csPoll);

                m_hPollThread = CreateThread(nullptr, 0, PushPollThreadProc, this, 0, nullptr);
                if (!m_hPollThread) {
                    // Cannot wait non-blockingly without the worker thread.
                    SHStrDupW(L"Не удалось запустить ожидание Push, попробуйте еще раз", ppszOptionalStatusText);
                    *pcpsiOptionalStatusIcon = CPSI_ERROR;
                }
                *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
                return S_OK;
            }

            // StartPush failed — check fail-close policy. Условие не менялось:
            // fail-open строго для транспортных отказов ("network_error"
            // ставится только когда WinHTTP не дошёл до HTTP-ответа).
            if (!m_config.failClose && err == "network_error") {
                LogDebug(L"Fail-Open allowed due to network error and policy");
                KerbInteractiveLogonPack(m_domain, m_username, m_password, pcpcs);
                *pcpgsr = CPGSR_RETURN_CREDENTIAL_FINISHED;
                return S_OK;
            }
            std::wstring msg = L"Не удалось отправить Push: " + DescribeServerError(err, m_apiClient->LastRetryAfterSec());
            SHStrDupW(msg.c_str(), ppszOptionalStatusText);
            *pcpsiOptionalStatusIcon = CPSI_ERROR;
            return S_OK;
        }

        // Worker is running (or has just finished): check the shared result.
        EnterCriticalSection(&m_csPoll);
        done = m_pollState.done;
        status = m_pollState.status;
        LeaveCriticalSection(&m_csPoll);

        if (!done) {
            *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
            return S_OK;
        }

        if (status == L"approved") {
            JoinPollThread();
            m_authenticated = true;
            KerbInteractiveLogonPack(m_domain, m_username, m_password, pcpcs);
            *pcpgsr = CPGSR_RETURN_CREDENTIAL_FINISHED;
            return S_OK;
        }

        // denied / expired / timeout — show the reason on the tile (legal
        // here: we are on the LogonUI thread) and let the user submit again,
        // which starts a fresh push challenge.
        std::wstring msg;
        if (status == L"denied") {
            msg = L"Вход отклонен пользователем";
            *pcpsiOptionalStatusIcon = CPSI_ERROR;
        } else if (status == L"expired") {
            msg = L"Срок действия подтверждения истек, попробуйте еще раз";
            *pcpsiOptionalStatusIcon = CPSI_WARNING;
        } else {
            msg = L"Время ожидания подтверждения истекло";
            *pcpsiOptionalStatusIcon = CPSI_WARNING;
        }
        JoinPollThread();
        m_statusText = msg;
        if (m_pEvents) {
            m_pEvents->SetFieldString(this, FID_STATUS_TEXT, msg.c_str());
        }
        SHStrDupW(msg.c_str(), ppszOptionalStatusText);
        *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
        return S_OK;
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
    UNREFERENCED_PARAMETER(ntsSubstatus);
    *ppszOptionalStatusText = nullptr;
    *pcpsiOptionalStatusIcon = CPSI_NONE;

    if (!m_password.empty()) {
        SecureZeroMemory(&m_password[0], m_password.size() * sizeof(wchar_t));
        m_password.clear();
    }
    if (!m_otpCode.empty()) {
        SecureZeroMemory(&m_otpCode[0], m_otpCode.size() * sizeof(wchar_t));
        m_otpCode.clear();
    }
    if (ntsStatus != 0) {
        // LSASS rejected the logon (expired password, domain issues, clock
        // skew, ...): the confirmed second factor is void and must not open
        // the door for the next attempt — possibly under another user name.
        m_authenticated = false;
        StopPollThread();
    }
    return S_OK;
}

#ifndef NEGOSSP_NAME_A
#define NEGOSSP_NAME_A "Negotiate"
#endif

#ifndef MICROSOFT_KERBEROS_NAME_A
#define MICROSOFT_KERBEROS_NAME_A "Kerberos"
#endif

static ULONG GetNegotiateAuthPackage() {
    HANDLE hLsa = nullptr;
    NTSTATUS status = LsaConnectUntrusted(&hLsa);
    if (status != 0) {
        return 0;
    }

    LSA_STRING pkgName;
    pkgName.Buffer = const_cast<PCHAR>(NEGOSSP_NAME_A);
    pkgName.Length = static_cast<USHORT>(strlen(NEGOSSP_NAME_A));
    pkgName.MaximumLength = pkgName.Length + 1;

    ULONG pkgId = 0;
    status = LsaLookupAuthenticationPackage(hLsa, &pkgName, &pkgId);
    if (status != 0) {
        // Fallback to Kerberos
        pkgName.Buffer = const_cast<PCHAR>(MICROSOFT_KERBEROS_NAME_A);
        pkgName.Length = static_cast<USHORT>(strlen(MICROSOFT_KERBEROS_NAME_A));
        pkgName.MaximumLength = pkgName.Length + 1;
        status = LsaLookupAuthenticationPackage(hLsa, &pkgName, &pkgId);
    }
    LsaDeregisterLogonProcess(hLsa);

    return (status == 0) ? pkgId : 0;
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
    pcpcs->ulAuthenticationPackage = GetNegotiateAuthPackage();
    pcpcs->cbSerialization = totalSize;
    pcpcs->rgbSerialization = buffer;

    return S_OK;
}

} // namespace ligament
