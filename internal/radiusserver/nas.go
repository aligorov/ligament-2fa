// Package radiusserver — извлечение информации о точке доступа (NAS) и Wi-Fi сети (SSID).
package radiusserver

import (
	"fmt"
	"strings"
)

// ParseCalledStationID извлекает BSSID точки и SSID Wi-Fi сети из атрибута Called-Station-Id.
// По стандарту RFC 3580 §3.21 Wi-Fi точки (UniFi, Cisco, Aruba) передают: "BSSID:SSID"
// Например: "74-83-C2-4B-11-22:Corporate-WiFi" -> bssid="74:83:C2:4B:11:22", ssid="Corporate-WiFi".
// Или чистое имя SSID сети: "Corporate-WiFi" -> bssid="", ssid="Corporate-WiFi".
// Или чистый MAC-адрес: "74:83:C2:4B:11:22" -> bssid="74:83:C2:4B:11:22", ssid="".
func ParseCalledStationID(raw string) (bssid, ssid string) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", ""
	}

	// 1. Формат "BSSID:SSID", где BSSID с дефисами ("00-11-22-33-44-55:Corp-WiFi")
	if idx := strings.Index(raw, ":"); idx > 0 {
		prefix := raw[:idx]
		if strings.Count(prefix, "-") == 5 && len(cleanMAC(prefix)) == 12 {
			return formatMAC(cleanMAC(prefix)), raw[idx+1:]
		}
	}

	// 2. Формат "BSSID:SSID", где BSSID с двоеточиями ("00:11:22:33:44:55:Corp-WiFi")
	if strings.Count(raw, ":") >= 6 {
		if len(raw) > 17 && raw[17] == ':' {
			return formatMAC(cleanMAC(raw[:17])), raw[18:]
		}
	}

	// 3. Чистый MAC (с двоеточиями или дефисами)
	clean := cleanMAC(raw)
	if len(clean) == 12 && (strings.Count(raw, ":") == 5 || strings.Count(raw, "-") == 5) {
		return formatMAC(clean), ""
	}

	// 4. Если разделителей MAC нет — это чистое имя сети (SSID)
	return "", raw
}

// ResolveNASDescription формирует понятное описание точки доступа для логов и уведомлений.
// Приоритеты сопоставления:
// 1. Имя точки из справочника inventory по IP (напр. "192.168.1.50" -> "UniFi AP-Pro Офис 2 этаж")
// 2. Имя точки из справочника inventory по NAS-Identifier или BSSID
// 3. NAS-Identifier из пакета (если он текстовый и полезный)
// 4. SSID сети из Called-Station-Id (напр. "Wi-Fi (SSID: Corporate-WiFi)")
// 5. Исходный IP-адрес точки доступа.
func ResolveNASDescription(nasIP, nasID, calledStation string, inventory map[string]string) string {
	nasIP = strings.TrimSpace(nasIP)
	nasID = strings.TrimSpace(nasID)
	bssid, ssid := ParseCalledStationID(calledStation)

	var invName string
	if len(inventory) > 0 {
		if nasIP != "" && inventory[nasIP] != "" {
			invName = inventory[nasIP]
		} else if nasID != "" && inventory[nasID] != "" {
			invName = inventory[nasID]
		} else if bssid != "" && inventory[bssid] != "" {
			invName = inventory[bssid]
		}
	}

	if invName != "" {
		if nasIP != "" {
			if ssid != "" {
				return fmt.Sprintf("%s (%s, SSID: %s)", nasIP, invName, ssid)
			}
			return fmt.Sprintf("%s (%s)", nasIP, invName)
		}
		if ssid != "" {
			return fmt.Sprintf("%s (SSID: %s)", invName, ssid)
		}
		return invName
	}

	if nasIP != "" {
		if nasID != "" && !looksLikeMAC(nasID) && nasID != nasIP {
			if ssid != "" {
				return fmt.Sprintf("%s (%s, SSID: %s)", nasIP, nasID, ssid)
			}
			return fmt.Sprintf("%s (%s)", nasIP, nasID)
		}
		if ssid != "" {
			return fmt.Sprintf("%s (SSID: %s)", nasIP, ssid)
		}
		return nasIP
	}

	if nasID != "" && !looksLikeMAC(nasID) {
		if ssid != "" {
			return fmt.Sprintf("%s (SSID: %s)", nasID, ssid)
		}
		return nasID
	}

	if ssid != "" {
		return fmt.Sprintf("Wi-Fi (SSID: %s)", ssid)
	}

	return "Точка доступа (Wi-Fi)"
}

func looksLikeMAC(s string) bool {
	clean := cleanMAC(s)
	return len(clean) == 12 && (len(s) == 12 || len(s) == 17)
}
