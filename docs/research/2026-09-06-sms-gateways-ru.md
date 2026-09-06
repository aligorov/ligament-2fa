# SMS-шлюзы РФ: проверенные пресеты (агентное исследование 2026-09-06)

Проверено живыми запросами (кредиты неверные — только структура ответов). 8 совместимых
шлюзов + причины отсева. Формат — под движок twofa (`GatewayConfig`: {phone}/{text}
в URL (QueryEscape) и теле (raw), значения Headers подставляются как {key},
Success-поля объединяются по AND, JSONPath одноуровневый `$.field`).

| Шлюз | Auth | Метод | Успех | Телефон | Цена ~ | Тест-режим |
|---|---|---|---|---|---|---|
| smsc.ru | login+psw (query) | GET /sys/send.php?fmt=3 | `$.cnt == "1"` (ошибки тоже HTTP 200!) | любые, дефолт страны | 3.8–11 ₽ | cost=1 (прайс без отправки) |
| sms.ru | api_id | GET /sms/send?json=1 | `$.status == "OK"` | 11 цифр 7… | ~8.4 ₽ | test=1 |
| smsaero.ru | **Basic auth** (email:api_key) | GET gate.smsaero.ru/v2/sms/send | HTTP 200 (+ `$.success=="true"`); ошибки — не-200 | 11 цифр без + | 1.95–3.3 ₽ | /v2/sms/testsend + имя «SMS Aero» |
| mainsms.ru | project+apikey | GET /api/mainsms/message/send | `$.status == "success"` | E.164 | от ~1.3 ₽ | test=1 |
| bytehand.com | id+key (v1) | GET api.bytehand.com/v1/send | `$.status == "0"` (число → stringify) | +7… | 7–9 ₽ | нет |
| prostor-sms.ru | login+password (JSON-тело) | POST api.prostor-sms.ru/messages/v2/send.json | `$.status == "ok"` | +7… | от 1.49 ₽ | 50 дней / 10 SMS |
| unisender | api_key | GET api.unisender.com/ru/api/sendSms | HTTP 200 (ошибки 4xx; в теле нет константного поля) | 7… (+ опц.) | 8–37 ₽ | нет (checkSms) |
| smsgateway24 | token + device_id | GET smsgateway24.com/getdata/addsms | `$.error == "0"` (число; ошибки — HTTP 200!) | **%2B+7…** (с плюсом!) | $38/мес без за SMS | trial 5 дней |

Ключевые нюансы движка, подтверждённые исследованием:
1. **Сравнение equals должно строкифицировать** JSON-значения: bytehand `$.status` — число `0`, smsaero `$.success` — bool `true`, smsgateway24 `$.error` — число `0`.
2. **JSON-тело (prostor)**: {text}/{phone} в теле JSON требуют JSON-экранирования (кавычки/переводы строк сломают тело).
3. **Basic auth (smsaero)**: единственный шлюз с заголовком — решено через `Authorization: Basic {auth_base64}` в Headers, где auth_base64 = base64(email:api_key) (вычисляет пользователь один раз).
4. smsc/smsgateway24 возвращают ошибки с HTTP 200 → json_path обязателен; smsaero/unisender — ошибки не-200 (достаточно http_status).

## Отсеяны (проверено)
- **ePochta (epochta.ru/atompark)**: API v3 требует MD5-подпись `sum` от отсортированных параметров (включая текст SMS) на каждый запрос — шаблонный движок не может.
- **SMS-Ассистент** (sms-assistent.ru): 301 → sms-telecom.by (ребрендинг в BY), сервис из РФ ушёл.
- **SMS-Lider.ru**: DNS не резолвится.
- **iTSMS.ru**: жив, но это рекламное агентство без публичного API.
- **SMSOnline.ru**: 301 на sms-online.com (международный сервис приёма SMS — другой продукт).

Полные отчёты агентов (эндпоинты, curl, коды ошибок, источники) — в истории сессии;
документация каждого шлюза указана в README (таблица пресетов).
