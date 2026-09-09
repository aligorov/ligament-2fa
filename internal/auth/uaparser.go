// Package auth: разбор HTTP User-Agent и форматирование информации об устройствах и IP.
package auth

import (
	"net"
	"regexp"
	"strings"
)

// DeviceDetails содержит структурированную информацию об устройстве.
type DeviceDetails struct {
	Device   string // Apple Mac, Apple iPhone, Samsung (SM-S918B), ПК, etc.
	OS       string // macOS, iOS 17.5, Windows 10/11, Android 14, Linux
	Browser  string // Google Chrome 128, Safari 17.5, Microsoft Edge 128, etc.
	IsMobile bool
	Raw      string
}

var (
	reIOSVersion     = regexp.MustCompile(`(?:iPhone|CPU)\s+OS\s+(\d+[_\.\d]*)`)
	reIPadVersion    = regexp.MustCompile(`(?:iPad; CPU\s+OS)\s+(\d+[_\.\d]*)`)
	reAndroidVersion = regexp.MustCompile(`Android\s+(\d+[\.\d]*)`)
	reAndroidModel   = regexp.MustCompile(`;\s*([^;]+?)\s+Build/`)
	reChromeVer      = regexp.MustCompile(`(?:Chrome|CriOS)/(\d+)`)
	reSafariVer      = regexp.MustCompile(`Version/(\d+[\.\d]*).*Safari`)
	reFirefoxVer     = regexp.MustCompile(`Firefox/(\d+)`)
	reEdgeVer        = regexp.MustCompile(`(?:Edg|EdgA|Edge)/(\d+)`)
	reYaBrowserVer   = regexp.MustCompile(`YaBrowser/(\d+[\.\d]*)`)
	reOperaVer       = regexp.MustCompile(`(?:OPR|Opera)/(\d+)`)
)

// ParseUserAgent разбирает строку HTTP User-Agent на платформу, устройство и браузер.
func ParseUserAgent(ua string) DeviceDetails {
	ua = strings.TrimSpace(ua)
	if ua == "" {
		return DeviceDetails{}
	}

	details := DeviceDetails{Raw: ua}

	// 1. Определение ОС и устройства
	switch {
	case strings.Contains(ua, "iPhone"):
		details.IsMobile = true
		details.Device = "Apple iPhone"
		details.OS = "iOS"
		if m := reIOSVersion.FindStringSubmatch(ua); len(m) > 1 {
			details.OS = "iOS " + strings.ReplaceAll(m[1], "_", ".")
		}
	case strings.Contains(ua, "iPad"):
		details.IsMobile = true
		details.Device = "Apple iPad"
		details.OS = "iPadOS"
		if m := reIPadVersion.FindStringSubmatch(ua); len(m) > 1 {
			details.OS = "iPadOS " + strings.ReplaceAll(m[1], "_", ".")
		}
	case strings.Contains(ua, "Android"):
		details.IsMobile = true
		details.OS = "Android"
		if m := reAndroidVersion.FindStringSubmatch(ua); len(m) > 1 {
			details.OS = "Android " + m[1]
		}
		if m := reAndroidModel.FindStringSubmatch(ua); len(m) > 1 {
			model := strings.TrimSpace(m[1])
			if strings.HasPrefix(model, "SM-") {
				details.Device = "Samsung (" + model + ")"
			} else if strings.HasPrefix(model, "Pixel") {
				details.Device = "Google " + model
			} else if model != "" && len(model) < 30 {
				details.Device = model
			} else {
				details.Device = "Android-устройство"
			}
		} else {
			details.Device = "Android-устройство"
		}
	case strings.Contains(ua, "Macintosh") || strings.Contains(ua, "Mac OS X"):
		details.Device = "Apple Mac"
		details.OS = "macOS"
	case strings.Contains(ua, "Windows NT 10.0"):
		details.Device = "ПК"
		details.OS = "Windows 10/11"
	case strings.Contains(ua, "Windows NT 6.3"):
		details.Device = "ПК"
		details.OS = "Windows 8.1"
	case strings.Contains(ua, "Windows NT 6.1"):
		details.Device = "ПК"
		details.OS = "Windows 7"
	case strings.Contains(ua, "Windows"):
		details.Device = "ПК"
		details.OS = "Windows"
	case strings.Contains(ua, "Ubuntu"):
		details.Device = "ПК"
		details.OS = "Ubuntu Linux"
	case strings.Contains(ua, "Linux"):
		details.Device = "ПК"
		details.OS = "Linux"
	case strings.Contains(ua, "CrOS"):
		details.Device = "Chromebook"
		details.OS = "ChromeOS"
	default:
		details.Device = "Неизвестное устройство"
		details.OS = ""
	}

	// 2. Определение Браузера (важен порядок проверки)
	switch {
	case strings.Contains(ua, "YaBrowser"):
		if m := reYaBrowserVer.FindStringSubmatch(ua); len(m) > 1 {
			details.Browser = "Яндекс Браузер " + m[1]
		} else {
			details.Browser = "Яндекс Браузер"
		}
	case strings.Contains(ua, "Edg/") || strings.Contains(ua, "EdgA/") || strings.Contains(ua, "Edge/"):
		if m := reEdgeVer.FindStringSubmatch(ua); len(m) > 1 {
			details.Browser = "Microsoft Edge " + m[1]
		} else {
			details.Browser = "Microsoft Edge"
		}
	case strings.Contains(ua, "OPR/") || strings.Contains(ua, "Opera/"):
		if m := reOperaVer.FindStringSubmatch(ua); len(m) > 1 {
			details.Browser = "Opera " + m[1]
		} else {
			details.Browser = "Opera"
		}
	case strings.Contains(ua, "Firefox/"):
		if m := reFirefoxVer.FindStringSubmatch(ua); len(m) > 1 {
			details.Browser = "Firefox " + m[1]
		} else {
			details.Browser = "Firefox"
		}
	case strings.Contains(ua, "Chrome/") || strings.Contains(ua, "CriOS/"):
		if m := reChromeVer.FindStringSubmatch(ua); len(m) > 1 {
			details.Browser = "Google Chrome " + m[1]
		} else {
			details.Browser = "Google Chrome"
		}
	case strings.Contains(ua, "Safari/"):
		if m := reSafariVer.FindStringSubmatch(ua); len(m) > 1 {
			details.Browser = "Safari " + m[1]
		} else {
			details.Browser = "Safari"
		}
	case strings.Contains(ua, "Proxmox"):
		details.Browser = "Proxmox Client"
	case strings.Contains(ua, "curl/"):
		details.Browser = "curl"
	default:
		if len(ua) <= 30 && !strings.Contains(ua, "Mozilla") {
			details.Browser = ua
		}
	}

	return details
}

// FormatDeviceAndBrowser формирует читаемые строки устройства и браузера.
func FormatDeviceAndBrowser(ua string) (deviceStr, browserStr string) {
	ua = strings.TrimSpace(ua)
	if ua == "" {
		return "", ""
	}

	// Если это RADIUS MAC (например: "F4:E8:C7:4A:B9:82 (Apple, Inc.)")
	if strings.Contains(ua, "MAC:") || (len(ua) >= 17 && (strings.Contains(ua, ":") || strings.Contains(ua, "-")) && !strings.Contains(ua, "Mozilla")) {
		return ua, ""
	}

	d := ParseUserAgent(ua)
	if d.Device == "" && d.Browser == "" && d.OS == "" {
		if len(ua) > 60 {
			return ua[:57] + "...", ""
		}
		return ua, ""
	}

	var devParts []string
	if d.Device != "" && d.Device != "Неизвестное устройство" {
		devParts = append(devParts, d.Device)
	}
	if d.OS != "" {
		if len(devParts) > 0 {
			devParts = append(devParts, "("+d.OS+")")
		} else {
			devParts = append(devParts, d.OS)
		}
	}

	if len(devParts) > 0 {
		deviceStr = strings.Join(devParts, " ")
	} else if d.Device != "" {
		deviceStr = d.Device
	}

	browserStr = d.Browser
	return deviceStr, browserStr
}

// FormatIPDescription добавляет контекст к IP-адресу (локальная сеть / локально).
func FormatIPDescription(ipStr string) string {
	ipStr = strings.TrimSpace(ipStr)
	if ipStr == "" {
		return ""
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return ipStr
	}
	if ip.IsLoopback() {
		return ipStr + " (локально)"
	}
	if ip.IsPrivate() {
		return ipStr + " (локальная сеть)"
	}
	return ipStr
}
