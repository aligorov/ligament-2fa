// Таблица reply-атрибутов Access-Accept: имена из radius.reply_attributes
// (глобальные) и users.radius_reply (per-user) → конкретные атрибуты пакета.
package radiusserver

import (
	"log/slog"
	"net"
	"strconv"
	"strings"

	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
	mt "layeh.com/radius/vendors/mikrotik"
)

// attrKind — способ кодирования значения стандартного атрибута на wire.
type attrKind int

const (
	kindString  attrKind = iota // строка (Filter-Id, ...)
	kindIP                      // 4-байтовый IPv4-адрес (Framed-IP-Address, ...)
	kindInteger                 // uint32 (Session-Timeout, ...)
)

// standardAttrs — известные стандартные (RFC 2865) атрибуты, разрешённые в
// reply-карте. layeh.com/radius не экспортирует словарь имя→тип
// (нет ни rfc2865.Attr, ни radius.AttributesType — проверено по исходникам
// замороженной библиотеки), поэтому v1 ограничен этой явной таблицей.
// Значения кодируются по типу атрибута: адрес — бинарный IPv4, таймауты —
// uint32, строки — строки. Прочие имена (кроме Mikrotik-*, см. ниже)
// пропускаются с записью в лог.
var standardAttrs = map[string]struct {
	typ  radius.Type
	kind attrKind
}{
	"Framed-IP-Address": {rfc2865.FramedIPAddress_Type, kindIP},
	"Framed-IP-Netmask": {rfc2865.FramedIPNetmask_Type, kindIP},
	"Session-Timeout":   {rfc2865.SessionTimeout_Type, kindInteger},
	"Idle-Timeout":      {rfc2865.IdleTimeout_Type, kindInteger},
	"Port-Limit":        {rfc2865.PortLimit_Type, kindInteger},
	"Framed-MTU":        {rfc2865.FramedMTU_Type, kindInteger},
	"Filter-Id":         {rfc2865.FilterID_Type, kindString},
}

// applyReplyAttrs добавляет reply-атрибуты в ответ Access-Accept. Поддержаны:
// четыре именованных MikroTik VSA (vendor 14988 из layeh-пакета mikrotik),
// Reply-Message и стандартные атрибуты из standardAttrs. Неизвестные
// «Mikrotik-*» и любые прочие имена пропускаются с предупреждением в лог —
// конфигурация не должна ронять аутентификацию.
func applyReplyAttrs(resp *radius.Packet, attrs map[string]string) {
	for name, value := range attrs {
		switch name {
		case "Reply-Message":
			setOrWarn("Reply-Message", func() error {
				return rfc2865.ReplyMessage_SetString(resp, value)
			})
		case "Mikrotik-Group":
			setOrWarn("Mikrotik-Group", func() error {
				return mt.MikrotikGroup_SetString(resp, value)
			})
		case "Mikrotik-Rate-Limit":
			setOrWarn("Mikrotik-Rate-Limit", func() error {
				return mt.MikrotikRateLimit_SetString(resp, value)
			})
		case "Mikrotik-Address-List":
			setOrWarn("Mikrotik-Address-List", func() error {
				return mt.MikrotikAddressList_SetString(resp, value)
			})
		default:
			if strings.HasPrefix(name, "Mikrotik-") {
				slog.Warn("radius: неизвестный Mikrotik-атрибут пропущен", "attr", name)
				continue
			}
			def, ok := standardAttrs[name]
			if !ok {
				slog.Warn("radius: неизвестный reply-атрибут пропущен", "attr", name)
				continue
			}
			addStandardAttr(resp, name, def.typ, def.kind, value)
		}
	}
}

// addStandardAttr кодирует значение стандартного атрибута по его типу.
func addStandardAttr(resp *radius.Packet, name string, typ radius.Type, kind attrKind, value string) {
	var (
		attr radius.Attribute
		err  error
	)
	switch kind {
	case kindString:
		attr, err = radius.NewString(value)
	case kindIP:
		ip := net.ParseIP(value)
		if ip == nil {
			slog.Warn("radius: некорректный IP в reply-атрибуте — пропущен", "attr", name, "value", value)
			return
		}
		attr, err = radius.NewIPAddr(ip)
	case kindInteger:
		n, perr := strconv.ParseUint(value, 10, 32)
		if perr != nil {
			slog.Warn("radius: некорректное число в reply-атрибуте — пропущен", "attr", name, "value", value)
			return
		}
		attr = radius.NewInteger(uint32(n))
	}
	if err != nil {
		slog.Warn("radius: кодирование reply-атрибута не удалось — пропущен", "attr", name, "error", err)
		return
	}
	resp.Add(typ, attr)
}

// setOrWarn выполняет установку атрибута; ошибка (например, строка длиннее
// 253 байт) логируется и проглатывается.
func setOrWarn(name string, set func() error) {
	if err := set(); err != nil {
		slog.Warn("radius: установка reply-атрибута не удалось — пропущен", "attr", name, "error", err)
	}
}
