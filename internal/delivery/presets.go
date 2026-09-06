package delivery

import (
	"net/http"
	"slices"
	"strings"
)

// PresetInfo — метаданные пресета для UI (выбор пресета в настройках
// SMS-шлюза): имя, отображаемый заголовок и русское описание (креды,
// формат телефона, тест-режим, ориентир цены — из research-дока
// docs/research/2026-09-06-sms-gateways-ru.md). Config — конфиг с пустыми
// кредами-заглушками: JSON этой структуры подставляется в поле
// sms.gateway (форма настроек), администратор вписывает свои значения.
type PresetInfo struct {
	Name        string
	Title       string
	Description string
	Config      GatewayConfig
}

// Presets возвращает все пресеты шлюзов, отсортированные по имени.
func Presets() []PresetInfo {
	list := []PresetInfo{
		{
			Name:        "bytehand",
			Title:       "ByteHand",
			Description: "Креды: id, key и имя отправителя sender. Телефон +7… Тест-режима нет. ~7–9 ₽/SMS. Успех — числовой статус 0 (сравнивается как строка).",
			Config: GatewayConfig{
				Preset: "bytehand",
				Method: http.MethodGet,
				URL:    "https://api.bytehand.com/v1/send?id={id}&key={key}&from={sender}&to={phone}&text={text}",
				Headers: map[string]string{
					"id":     "",
					"key":    "",
					"sender": "",
				},
				Success: SuccessRule{JSONPath: "$.status", Equals: "0"},
			},
		},
		{
			Name:        "mainsms",
			Title:       "MainSMS",
			Description: "Креды: project и api_key. Телефон в формате E.164 (+7…). Тест-режим: параметр test=1. Цена от ~1.3 ₽/SMS.",
			Config: GatewayConfig{
				Preset: "mainsms",
				Method: http.MethodGet,
				URL:    "https://mainsms.ru/api/mainsms/message/send?project={project}&apikey={api_key}&recipients={phone}&message={text}",
				Headers: map[string]string{
					"project": "",
					"api_key": "",
				},
				Success: SuccessRule{JSONPath: "$.status", Equals: "success"},
			},
		},
		{
			Name:        "prostor",
			Title:       "Простор-СМС",
			Description: "Креды: login, password и sender. Телефон +7… Тест-режим: 50 дней / 10 SMS после регистрации. Цена от 1.49 ₽/SMS. Отправка JSON-телом POST.",
			Config: GatewayConfig{
				Preset:      "prostor",
				Method:      http.MethodPost,
				URL:         "https://api.prostor-sms.ru/messages/v2/send.json",
				ContentType: "application/json",
				Body:        `{"messages":[{"phone":"{phone}","sender":"{sender}","text":"{text}"}],"login":"{login}","password":"{password}"}`,
				Headers: map[string]string{
					"login":    "",
					"password": "",
					"sender":   "",
				},
				Success: SuccessRule{JSONPath: "$.status", Equals: "ok"},
			},
		},
		{
			Name:        "smsaero",
			Title:       "SMS Aero",
			Description: "Креды: auth_base64 = base64(email:api_key), вычислите один раз: echo -n 'email:KEY' | base64. Имя отправителя sender (по умолчанию «SMS Aero» — тестовый режим). Телефон 11 цифр без +. ~1.95–3.3 ₽/SMS. Ошибки — не-200, поэтому успех: HTTP 200.",
			Config: GatewayConfig{
				Preset: "smsaero",
				Method: http.MethodGet,
				URL:    "https://gate.smsaero.ru/v2/sms/send?number={phone}&text={text}&sign={sender}",
				Headers: map[string]string{
					"Authorization": "Basic {auth_base64}",
					"auth_base64":   "",
					"sender":        "SMS Aero",
				},
				// Ошибочные ответы smsaero приходят с не-200 — точного
				// статуса достаточно; bool-поле $.success оставлено
				// опцией, здесь json_path пуст.
				Success: SuccessRule{HTTPStatus: 200},
			},
		},
		{
			Name:        "smsc",
			Title:       "SMSC.ru",
			Description: "Креды: login и psw. Телефон любой (дефолт страны), fmt=3 (JSON-ответ). Тест-режим: cost=1 (прайс без отправки). ~3.8–11 ₽/SMS. Ошибки приходят с HTTP 200 — успех проверяется по полю $.cnt == 1.",
			Config: GatewayConfig{
				Preset: "smsc",
				Method: http.MethodGet,
				URL:    "https://smsc.ru/sys/send.php?login={login}&psw={psw}&phones={phone}&mes={text}&fmt=3&charset=utf-8",
				Headers: map[string]string{
					"login": "",
					"psw":   "",
				},
				Success: SuccessRule{HTTPStatus: 200, JSONPath: "$.cnt", Equals: "1"},
			},
		},
		{
			Name:        "smsgateway24",
			Title:       "SMSGateway24",
			Description: "Креды: token и device_id (Android-телефон с приложением SMSGateway24). Телефон +7… — с плюсом. Пробный период 5 дней, далее $38/мес независимо от числа SMS. Ошибки приходят с HTTP 200 — успех по $.error == 0.",
			Config: GatewayConfig{
				Preset: "smsgateway24",
				Method: http.MethodGet,
				URL:    "https://smsgateway24.com/getdata/addsms?token={token}&sendto={phone}&body={text}&device_id={device_id}&sim=0&urgent=1",
				Headers: map[string]string{
					"token":     "",
					"device_id": "",
				},
				Success: SuccessRule{JSONPath: "$.error", Equals: "0"},
			},
		},
		{
			Name:        "smsru",
			Title:       "SMS.ru",
			Description: "Кред: api_id. Телефон 11 цифр, начиная с 7. Тест-режим: параметр test=1. ~8.4 ₽/SMS. Успех: $.status == \"OK\".",
			Config: GatewayConfig{
				Preset: "smsru",
				Method: http.MethodGet,
				URL:    "https://sms.ru/sms/send?api_id={api_id}&to={phone}&msg={text}&json=1",
				Headers: map[string]string{
					"api_id": "",
				},
				Success: SuccessRule{JSONPath: "$.status", Equals: "OK"},
			},
		},
		{
			Name:        "twilio",
			Title:       "Twilio",
			Description: "Креды: sid, token и from (номер отправителя). Телефон E.164. Оплата по тарифу за SMS. Успех — любой 2xx (реальный Twilio отвечает 201 Created).",
			Config: GatewayConfig{
				Preset:      "twilio",
				Method:      http.MethodPost,
				URL:         "https://api.twilio.com/2010-04-01/Accounts/{sid}/Messages.json",
				ContentType: "application/x-www-form-urlencoded",
				Headers: map[string]string{
					"sid":   "",
					"token": "",
					"from":  "",
				},
				// Нулевое правило: реальный Twilio на успех отвечает
				// 201 Created (и другие 2xx), точный статус 200 его
				// отсекал бы; остаётся общий 2xx-гейт Send.
				Success: SuccessRule{},
			},
		},
		{
			Name:        "unisender",
			Title:       "Unisender",
			Description: "Креды: api_key и sender. Телефон 7… (плюс опционален). Тест-режима нет (для проверки есть checkSms). ~8–37 ₽/SMS. Ошибки — не-200; в теле нет константного поля успеха, поэтому правило: HTTP 200.",
			Config: GatewayConfig{
				Preset: "unisender",
				Method: http.MethodGet,
				URL:    "https://api.unisender.com/ru/api/sendSms?format=json&api_key={api_key}&phone={phone}&sender={sender}&text={text}",
				Headers: map[string]string{
					"api_key": "",
					"sender":  "",
				},
				Success: SuccessRule{HTTPStatus: 200},
			},
		},
	}
	slices.SortFunc(list, func(a, b PresetInfo) int {
		return strings.Compare(a.Name, b.Name)
	})
	return list
}

// Preset возвращает конфигурацию HTTP-шлюза SMS по имени. Учётные
// данные пресета задаются в Headers ПОСЛЕ получения конфига (в UI —
// вписываются в JSON шлюза):
//
//	smsc:          Headers["login"], Headers["psw"]
//	smsru:         Headers["api_id"]
//	smsaero:       Headers["auth_base64"], Headers["sender"]
//	mainsms:       Headers["project"], Headers["api_key"]
//	bytehand:      Headers["id"], Headers["key"], Headers["sender"]
//	prostor:       Headers["login"], Headers["password"], Headers["sender"]
//	unisender:     Headers["api_key"], Headers["sender"]
//	smsgateway24:  Headers["token"], Headers["device_id"]
//	twilio:        Headers["sid"], Headers["token"], Headers["from"]
//
// Значения подставляются в URL, тело и заголовки при отправке
// (плейсхолдеры {login}/{psw}/... по ключам Headers; {phone}/{text} —
// номер и текст). Пресет twilio использует basic-auth из sid/token и
// form-encoded тело To/From/Body; smsaero — заголовок
// Authorization: Basic {auth_base64}. Неизвестное имя — второй
// результат false.
//
// Правила успеха: smsc/smsgateway24 возвращают ошибки с HTTP 200 —
// у них обязательный json_path ($.cnt=="1" / $.error=="0"); bytehand
// $.status — число 0 (сравнение строкифицирует JSON-значения);
// smsaero/unisender ошибками отвечают не-200 — им достаточно статуса;
// twilio на создание сообщения возвращает 201 Created — нулевое правило
// (успех: любой 2xx).
func Preset(name string) (GatewayConfig, bool) {
	for _, p := range Presets() {
		if p.Name == name {
			return p.Config, true
		}
	}
	return GatewayConfig{}, false
}
