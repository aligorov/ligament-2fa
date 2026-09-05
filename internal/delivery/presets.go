package delivery

import "net/http"

// Preset возвращает конфигурацию HTTP-шлюза SMS по имени. Учётные
// данные пресета задаются в Headers ПОСЛЕ получения конфига:
//
//	smsc:   Headers["login"], Headers["psw"]
//	twilio: Headers["sid"], Headers["token"], Headers["from"]
//
// Значения подставляются в URL и тело при отправке (плейсхолдеры
// {login}/{psw}/{sid}/{token}/{from}). Пресет twilio использует
// basic-auth из sid/token и form-encoded тело To/From/Body.
// Неизвестное имя — второй результат false.
//
// Правила успеха: smsc отвечает 200 (точный статус); twilio на создание
// сообщения возвращает 201 Created, поэтому его Success — нулевое
// значение (HTTPStatus не задан): успехом считается любой 2xx.
func Preset(name string) (GatewayConfig, bool) {
	switch name {
	case "smsc":
		return GatewayConfig{
			Preset:  "smsc",
			Method:  http.MethodGet,
			URL:     "https://smsc.ru/sys/send.php?login={login}&psw={psw}&phones={phone}&mes={text}",
			Success: SuccessRule{HTTPStatus: 200},
		}, true
	case "twilio":
		return GatewayConfig{
			Preset:      "twilio",
			Method:      http.MethodPost,
			URL:         "https://api.twilio.com/2010-04-01/Accounts/{sid}/Messages.json",
			ContentType: "application/x-www-form-urlencoded",
			// Нулевое правило: реальный Twilio на успех отвечает
			// 201 Created (и другие 2xx), точный статус 200 его
			// отсекал бы; остаётся общий 2xx-гейт Send.
			Success: SuccessRule{},
		}, true
	}
	return GatewayConfig{}, false
}
