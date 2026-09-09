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
	"layeh.com/radius/rfc2868"
	"layeh.com/radius/rfc2869"
	"layeh.com/radius/rfc3580"
	mt "layeh.com/radius/vendors/mikrotik"
)

// attrKind — способ кодирования значения стандартного атрибута на wire.
type attrKind int

const (
	kindString  attrKind = iota // строка (Filter-Id, ...)
	kindIP                      // 4-байтовый IPv4-адрес (Framed-IP-Address, ...)
	kindInteger                 // uint32 (Session-Timeout, ...)
)

// standardAttrs — известные стандартные (RFC 2865 / RFC 2869) атрибуты, разрешённые в
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
	"Framed-IP-Address":     {rfc2865.FramedIPAddress_Type, kindIP},
	"Framed-IP-Netmask":     {rfc2865.FramedIPNetmask_Type, kindIP},
	"Session-Timeout":       {rfc2865.SessionTimeout_Type, kindInteger},
	"Idle-Timeout":          {rfc2865.IdleTimeout_Type, kindInteger},
	"Port-Limit":            {rfc2865.PortLimit_Type, kindInteger},
	"Framed-MTU":            {rfc2865.FramedMTU_Type, kindInteger},
	"Filter-Id":             {rfc2865.FilterID_Type, kindString},
	"Framed-Route":          {rfc2865.FramedRoute_Type, kindString},
	"Framed-Pool":           {rfc2869.FramedPool_Type, kindString},
	"Acct-Interim-Interval": {rfc2869.AcctInterimInterval_Type, kindInteger},
}

// applyReplyAttrs добавляет reply-атрибуты в ответ Access-Accept. Поддержаны:
// три именованных MikroTik VSA (vendor 14988 из layeh-пакета mikrotik),
// Reply-Message, стандартные RFC 2865 атрибуты из standardAttrs, а также
// RFC 2868 / RFC 3580 атрибуты для динамического VLAN (UniFi, Cisco, Aruba, MikroTik).
func applyReplyAttrs(resp *radius.Packet, attrs map[string]string) {
	for name, value := range attrs {
		switch {
		case strings.EqualFold(name, "Reply-Message"):
			setOrWarn("Reply-Message", func() error {
				return rfc2865.ReplyMessage_SetString(resp, value)
			})
		case strings.EqualFold(name, "Mikrotik-Group"):
			setOrWarn("Mikrotik-Group", func() error {
				return mt.MikrotikGroup_SetString(resp, value)
			})
		case strings.EqualFold(name, "Mikrotik-Rate-Limit"):
			setOrWarn("Mikrotik-Rate-Limit", func() error {
				return mt.MikrotikRateLimit_SetString(resp, value)
			})
		case strings.EqualFold(name, "Mikrotik-Address-List"):
			setOrWarn("Mikrotik-Address-List", func() error {
				return mt.MikrotikAddressList_SetString(resp, value)
			})
		case strings.EqualFold(name, "Tunnel-Type"):
			setOrWarn("Tunnel-Type", func() error {
				var v uint64
				var err error
				if strings.EqualFold(value, "VLAN") {
					v = uint64(rfc3580.TunnelType_Value_VLAN)
				} else {
					v, err = strconv.ParseUint(value, 10, 32)
				}
				if err != nil {
					return err
				}
				return rfc2868.TunnelType_Add(resp, 1, rfc2868.TunnelType(v))
			})
		case strings.EqualFold(name, "Tunnel-Medium-Type"):
			setOrWarn("Tunnel-Medium-Type", func() error {
				var v uint64
				var err error
				if strings.EqualFold(value, "IEEE-802") || strings.EqualFold(value, "802") {
					v = uint64(rfc2868.TunnelMediumType_Value_IEEE802)
				} else {
					v, err = strconv.ParseUint(value, 10, 32)
				}
				if err != nil {
					return err
				}
				return rfc2868.TunnelMediumType_Add(resp, 1, rfc2868.TunnelMediumType(v))
			})
		case strings.EqualFold(name, "Tunnel-Private-Group-Id"):
			setOrWarn("Tunnel-Private-Group-Id", func() error {
				return rfc2868.TunnelPrivateGroupID_AddString(resp, 1, value)
			})
		default:
			if strings.HasPrefix(strings.ToLower(name), "mikrotik-") {
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

	// RFC 3580 §3.31, §3.32: если задан Tunnel-Private-Group-Id (номер или имя VLAN),
	// для динамического назначения VLAN на точках доступа (UniFi, Cisco, Aruba)
	// обязательно требуются Tunnel-Type=13 (VLAN) и Tunnel-Medium-Type=6 (IEEE-802).
	// Если администратор не указал их явно, добавляем их автоматически.
	hasAttr := func(k string) bool {
		for name := range attrs {
			if strings.EqualFold(name, k) {
				return true
			}
		}
		return false
	}
	if hasAttr("Tunnel-Private-Group-Id") {
		if !hasAttr("Tunnel-Type") {
			_ = rfc2868.TunnelType_Add(resp, 1, rfc2868.TunnelType(rfc3580.TunnelType_Value_VLAN))
		}
		if !hasAttr("Tunnel-Medium-Type") {
			_ = rfc2868.TunnelMediumType_Add(resp, 1, rfc2868.TunnelMediumType_Value_IEEE802)
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

// ExtractVLAN извлекает номер или имя VLAN из словаря reply-атрибутов (Tunnel-Private-Group-Id).
func ExtractVLAN(attrs map[string]string) string {
	for k, v := range attrs {
		if strings.EqualFold(k, "Tunnel-Private-Group-Id") {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

