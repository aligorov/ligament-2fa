// LigamentCredential.cpp — Implementation of Credential tile logic
#include "LigamentCredential.h"

namespace ligament {

// Определение — ниже (перед GetNegotiateAuthPackage); вызовы в
// GetSerialization/ReportResult идут раньше, отсюда форвард-декларация.
static void CPLog(const wchar_t* fmt, ...);
static void GetMachineNames(std::wstring& netBios, std::wstring& dnsDomain);

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

void LigamentCredential::Initialize(const Config& cfg, bool isRemote, CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus) {
    m_config = cfg;
    m_isRemoteSession = isRemote;
    m_cpus = cpus;
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
            size_t at = raw.find(L'@');
            if (at != std::wstring::npos && at > 0 && at + 1 < raw.length()) {
                m_username = raw.substr(0, at);
                m_domain = raw.substr(at + 1);
            } else {
                m_domain.clear();
                m_username = raw;
            }
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
        return PackAndFinish(pcpgsr, pcpcs, ppszOptionalStatusText, pcpsiOptionalStatusIcon);
    }

    // 2. If already validated via FIDO2 / Push:
    if (m_authenticated) {
        CPLog(L"serialize: ветка already_authenticated");
        return PackAndFinish(pcpgsr, pcpcs, ppszOptionalStatusText, pcpsiOptionalStatusIcon);
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
            return PackAndFinish(pcpgsr, pcpcs, ppszOptionalStatusText, pcpsiOptionalStatusIcon);
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
                return PackAndFinish(pcpgsr, pcpcs, ppszOptionalStatusText, pcpsiOptionalStatusIcon);
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
            CPLog(L"push: approved — сериализация кредов тайла");
            JoinPollThread();
            m_authenticated = true;
            return PackAndFinish(pcpgsr, pcpcs, ppszOptionalStatusText, pcpsiOptionalStatusIcon);
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
            return PackAndFinish(pcpgsr, pcpcs, ppszOptionalStatusText, pcpsiOptionalStatusIcon);
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
    *ppszOptionalStatusText = nullptr;
    *pcpsiOptionalStatusIcon = CPSI_NONE;

    CPLog(L"ReportResult: ntsStatus=0x%08X ntsSubstatus=0x%08X",
        (unsigned)ntsStatus, (unsigned)ntsSubstatus);
    switch ((unsigned)ntsStatus) {
    case 0: break;
    case 0xC0000064: CPLog(L"ReportResult: STATUS_NO_SUCH_USER — учётки с таким именем нет"); break;
    case 0xC000006A: CPLog(L"ReportResult: STATUS_WRONG_PASSWORD — пароль не подошёл"); break;
    case 0xC000006D: CPLog(L"ReportResult: STATUS_LOGON_FAILURE — имя или пароль неверны"); break;
    case 0xC0000072: CPLog(L"ReportResult: STATUS_ACCOUNT_DISABLED — учётка отключена"); break;
    case 0xC0000234: CPLog(L"ReportResult: STATUS_ACCOUNT_LOCKED_OUT — учётка заблокирована"); break;
    case 0xC0000071: CPLog(L"ReportResult: STATUS_PASSWORD_EXPIRED — пароль истёк"); break;
    case 0xC0000193: CPLog(L"ReportResult: STATUS_ACCOUNT_EXPIRED — учётка истекла"); break;
    case 0xC0000022: CPLog(L"ReportResult: STATUS_ACCESS_DENIED — доступ запрещён (RDP-права/группы)"); break;
    case 0xC000006E: CPLog(L"ReportResult: STATUS_ACCOUNT_RESTRICTION — ограничение входа (часы/RDP-доступ)"); break;
    case 0xC00000E5: CPLog(L"ReportResult: STATUS_INTERNAL_ERROR — внутренняя ошибка обработки (обычно битая сериализация)"); break;
    default: CPLog(L"ReportResult: нераспознанный код — см. ntstatus.h"); break;
    }
    // дубль подстатуса десятичным числом: OCR скриншотов путает 0xC00000E5
    // и 0xC0000065, десятичная запись читается однозначно
    CPLog(L"ReportResult: sub_dec=%lu", (unsigned long)(unsigned)ntsSubstatus);
    switch ((unsigned)ntsSubstatus) {
    case 0: break;
    case 0xC000005E: CPLog(L"ReportResult: sub=STATUS_LOGON_TYPE_NOT_GRANTED — учётке ЗАПРЕЩЁН этот тип входа (для RDP: нет права \"Вход через удалённый рабочий стол\" / не в группе Remote Desktop Users)"); break;
    case 0xC0000064: CPLog(L"ReportResult: sub=STATUS_NO_SUCH_USER — нет такой учётки"); break;
    case 0xC000006A: CPLog(L"ReportResult: sub=STATUS_WRONG_PASSWORD — пароль неверен"); break;
    case 0xC0000071: CPLog(L"ReportResult: sub=STATUS_PASSWORD_EXPIRED — пароль истёк"); break;
    case 0xC0000072: CPLog(L"ReportResult: sub=STATUS_ACCOUNT_DISABLED — учётка отключена"); break;
    case 0xC0000234: CPLog(L"ReportResult: sub=STATUS_ACCOUNT_LOCKED_OUT — учётка заблокирована"); break;
    case 0xC000015B: CPLog(L"ReportResult: sub=STATUS_LOGON_TYPE_NOT_GRANTED(015B) — тип входа не предоставлен"); break;
    case 0xC000006E: CPLog(L"ReportResult: sub=STATUS_ACCOUNT_RESTRICTION — ограничение учётки"); break;
    case 0xC00000E5: CPLog(L"ReportResult: sub=STATUS_INTERNAL_ERROR — пакет не смог обработать блоб/запрос"); break;
    default: CPLog(L"ReportResult: sub=нераспознан"); break;
    }

    // САМОПРОВЕРКА кредов против локального SAM (LogonUser): разделяет
    // «Windows отверг ИМЕННО имя/пароль» и «проблема в пути провайдера».
    // Выполняется только при неудачном входе; неудачная проба увеличивает
    // счётчик плохих паролей ещё на 1 — не спамить попытками (лок-аут).
    if (ntsStatus != 0 && !m_password.empty() && !m_username.empty()) {
        std::wstring nb, dd;
        GetMachineNames(nb, dd);
        CPLog(L"env: computer=%s dnsDomain=%s", nb.c_str(), dd.c_str());
        // Пробуем резолв учётки по трём доменам; стоп на первом успехе.
        // Каждая НЕУДАЧНАЯ проба +1 к счётчику плохих паролей (лок-аут).
        const wchar_t* tries[3] = { L".", nb.c_str(), dd.c_str() };
        const wchar_t* names[3] = { L"local(.)", L"machine", L"domain" };
        bool anyOk = false;
        for (int i = 0; i < 3 && !anyOk; ++i) {
            if (!tries[i] || !tries[i][0]) continue;
            HANDLE hToken = nullptr;
            if (LogonUserW(m_username.c_str(), tries[i], m_password.c_str(),
                           LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, &hToken)) {
                CPLog(L"sam-probe[%s]: OK — креды ВАЛИДНЫ (домен резолва \"%s\")", names[i], tries[i]);
                CloseHandle(hToken);
                anyOk = true;
            } else {
                CPLog(L"sam-probe[%s]: FAIL err=%lu (1326=имя/пароль не подходят)", names[i], (unsigned long)GetLastError());
            }
        }
        if (!anyOk) CPLog(L"sam-probe: ИТОГ — креды не прошли ни одним способом; проверь имя учётки и пароль Windows");
    }

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

// CPLog — файловая диагностика провайдера (winlogon-контекст, прав на
// отладчик нет): %ProgramData%\Ligament\cp.log. Пишутся ТОЛЬКО несекретные
// детали (имя/домен/длины/пакет/коды NTSTATUS), никогда пароль.
static void CPLog(const wchar_t* fmt, ...) {
    static wchar_t path[MAX_PATH] = {0};
    if (path[0] == 0) {
        wchar_t progData[MAX_PATH] = {0};
        if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_COMMON_APPDATA, nullptr, 0, progData))) {
            wcscat_s(progData, L"\\Ligament");
            CreateDirectoryW(progData, nullptr);
            wcscat_s(progData, L"\\cp.log");
            wcscat_s(path, progData);
        } else {
            wcscpy_s(path, L"C:\\Windows\\Temp\\LigamentCP.log");
        }
    }
    HANDLE h = CreateFileW(path, FILE_APPEND_DATA, FILE_SHARE_READ, nullptr,
        OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return;
    SYSTEMTIME st; GetLocalTime(&st);
    wchar_t line[1024];
    int n = swprintf_s(line, L"[%02u.%02u %02u:%02u:%02u.%03u tid=%lu] ",
        st.wDay, st.wMonth, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
        GetCurrentThreadId());
    va_list args; va_start(args, fmt);
    int m = _vsnwprintf_s(line + n, (int)(wcslen(line) > 0 ? sizeof(line)/sizeof(wchar_t) - n : 0), _TRUNCATE, fmt, args);
    va_end(args);
    (void)m;
    wcscat_s(line, L"\r\n");
    DWORD written = 0;
    WriteFile(h, line, (DWORD)(wcslen(line) * sizeof(wchar_t)), &written, nullptr);
    CloseHandle(h);
}

// Имена машины: NetBIOS (домен для ЛОКАЛЬНЫХ учёток у MsV1_0) и DNS-домен
// (пустой = рабочая группа, не в домене).
static void GetMachineNames(std::wstring& netBios, std::wstring& dnsDomain) {
    wchar_t nb[MAX_COMPUTERNAME_LENGTH + 1] = {0};
    DWORD n = ARRAYSIZE(nb);
    if (GetComputerNameW(nb, &n)) netBios = nb;
    wchar_t dd[256] = {0};
    DWORD d = ARRAYSIZE(dd);
    if (GetComputerNameExW(ComputerNameDnsDomain, dd, &d)) dnsDomain = dd;
}

// id пакета 0 — ВАЛИДЕН (на части машин Negotiate зарегистрирован именно под 0,
// диагностика v0.4.63: lookup "Negotiate" status=0 id=0). Признак «нашлось» —
// только статус lookup, поэтому валидность держим отдельным флагом.
static ULONG g_authPkgId = 0;
static bool g_authPkgValid = false;

static ULONG GetNegotiateAuthPackage() {
    // Кэш на процесс: повторные коннекты к LSA на каждый pack — лишняя
    // точка отказа (диагностика v0.4.62: authPkg=0, вход валидными кредами
    // отвергался). Приоритет — Negotiate: это диспетчер, который сам выбирает
    // MsV1_0 для локальных учёток; прямой Kerberos локальные учётки без
    // домена не принимает (0xC000006D в v0.4.63). Фоллбэки — на случай,
    // если Negotiate в системе не зарегистрирован.
    static bool s_resolved = false;
    if (s_resolved) return g_authPkgId;
    // Отказ не кэшируем: следующий pack попробует LSA заново.

    HANDLE hLsa = nullptr;
    NTSTATUS status = LsaConnectUntrusted(&hLsa);
    if (status != 0) {
        CPLog(L"lsa: connect failed status=0x%08X", (unsigned)status);
        return g_authPkgId; // 0, невалиден
    }

    static const char* kNames[] = { NEGOSSP_NAME_A, MICROSOFT_KERBEROS_NAME_A, "MICROSOFT_V1_0" };
    ULONG pkgId = 0;
    for (int i = 0; i < 3; ++i) {
        LSA_STRING pkgName;
        pkgName.Buffer = const_cast<PCHAR>(kNames[i]);
        pkgName.Length = static_cast<USHORT>(strlen(kNames[i]));
        pkgName.MaximumLength = pkgName.Length + 1;
        NTSTATUS st = LsaLookupAuthenticationPackage(hLsa, &pkgName, &pkgId);
        CPLog(L"lsa: lookup \"%hs\" status=0x%08X id=%lu", kNames[i], (unsigned)st, pkgId);
        if (st == 0) { g_authPkgValid = true; break; }
        pkgId = 0;
    }
    LsaDeregisterLogonProcess(hLsa);

    g_authPkgId = pkgId;
    s_resolved = g_authPkgValid; // кэшируем только успешный lookup
    return g_authPkgId;
}

HRESULT LigamentCredential::KerbInteractiveLogonPack(
    const std::wstring& domain,
    const std::wstring& user,
    const std::wstring& password,
    CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs)
{
    // Канонический формат Winlogon/LSA (SDK-сэмпл, helpers.cpp,
    // KerbInteractiveUnlockLogonPack): обёртка KERB_INTERACTIVE_UNLOCK_LOGON
    // (KERB_INTERACTIVE_LOGON + LUID LogonSessionId, его заполняет Winlogon),
    // а Buffer-поля UNICODE_STRING — байтовые СМЕЩЕНИЯ от начала структуры,
    // НЕ указатели: блоб уходит в чужие процессы (Winlogon/LSASS), абсолютные
    // адреса там бессмысленны (v0.4.62–64: 0xC000006D/0xC00000E5 из-за
    // указателей и голой структуры). Строки без нуль-терминаторов,
    // MaximumLength = Length. Диагностика v0.4.64 подтвердила: пакет и креды
    // верны, формат был битый.
    // Голое имя пользователя на машине БЕЗ домена (рабочая группа): пустой
    // LogonDomainName — единственное значение, которым мы отличались от
    // рабочего штатного входа; штатный вход для локальных учёток резолвит
    // SAM по ИМЕНИ МАШИНЫ. Подставляем его принудительно.
    std::wstring effDomain = domain;
    bool forcedLocalDomain = false;
    if (effDomain.empty()) {
        std::wstring nb, dd;
        GetMachineNames(nb, dd);
        if (dd.empty() && !nb.empty()) {
            effDomain = nb;
            forcedLocalDomain = true;
        }
    }

    DWORD domainBytes = (DWORD)(effDomain.length() * sizeof(wchar_t));
    DWORD userBytes = (DWORD)(user.length() * sizeof(wchar_t));
    DWORD passBytes = (DWORD)(password.length() * sizeof(wchar_t));

    DWORD totalSize = sizeof(KERB_INTERACTIVE_UNLOCK_LOGON) + domainBytes + userBytes + passBytes;
    BYTE* buffer = (BYTE*)CoTaskMemAlloc(totalSize);
    if (!buffer) return E_OUTOFMEMORY;
    ZeroMemory(buffer, totalSize);

    KERB_INTERACTIVE_UNLOCK_LOGON* pKiul = (KERB_INTERACTIVE_UNLOCK_LOGON*)buffer;
    KERB_INTERACTIVE_LOGON* pLogon = &pKiul->Logon;
    pLogon->MessageType = (m_cpus == CPUS_UNLOCK_WORKSTATION)
        ? KerbWorkstationUnlockLogon
        : KerbInteractiveLogon;

    BYTE* ptr = buffer + sizeof(KERB_INTERACTIVE_UNLOCK_LOGON);

    pLogon->LogonDomainName.Length = (USHORT)domainBytes;
    pLogon->LogonDomainName.MaximumLength = (USHORT)domainBytes;
    pLogon->LogonDomainName.Buffer = (PWSTR)(ptr - buffer);
    CopyMemory(ptr, effDomain.data(), domainBytes);
    ptr += domainBytes;

    pLogon->UserName.Length = (USHORT)userBytes;
    pLogon->UserName.MaximumLength = (USHORT)userBytes;
    pLogon->UserName.Buffer = (PWSTR)(ptr - buffer);
    CopyMemory(ptr, user.data(), userBytes);
    ptr += userBytes;

    pLogon->Password.Length = (USHORT)passBytes;
    pLogon->Password.MaximumLength = (USHORT)passBytes;
    pLogon->Password.Buffer = (PWSTR)(ptr - buffer);
    CopyMemory(ptr, password.data(), passBytes);

    ULONG authPkg = GetNegotiateAuthPackage();
    if (!g_authPkgValid) {
        CPLog(L"pack: CRITICAL — LSA не отдал пакет, сериализация отменена");
        CoTaskMemFree(buffer);
        return E_FAIL;
    }

    pcpcs->clsidCredentialProvider = CLSID_LigamentProvider;
    pcpcs->ulAuthenticationPackage = authPkg;
    pcpcs->cbSerialization = totalSize;
    pcpcs->rgbSerialization = buffer;

    CPLog(L"pack(kiul): domain=\"%s\"(forced=%d) user=\"%s\" passLen=%u authPkg=%lu pkgResolved=%d msgType=%lu totalSize=%lu",
        effDomain.c_str(), forcedLocalDomain ? 1 : 0, user.c_str(), (unsigned)password.length(),
        authPkg, g_authPkgValid ? 1 : 0,
        (unsigned long)pLogon->MessageType, (unsigned long)totalSize);
    return S_OK;
}

HRESULT LigamentCredential::PackAndFinish(
    CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr,
    CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs,
    PWSTR* ppszOptionalStatusText,
    CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon)
{
    HRESULT hr = KerbInteractiveLogonPack(m_domain, m_username, m_password, pcpcs);
    if (SUCCEEDED(hr)) {
        *pcpgsr = CPGSR_RETURN_CREDENTIAL_FINISHED;
        return S_OK;
    }
    CPLog(L"pack: отказ сериализации hr=0x%08X", (unsigned)hr);
    SHStrDupW(L"Внутренняя ошибка провайдера, попробуйте еще раз", ppszOptionalStatusText);
    *pcpsiOptionalStatusIcon = CPSI_ERROR;
    *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
    return S_OK;
}

} // namespace ligament
