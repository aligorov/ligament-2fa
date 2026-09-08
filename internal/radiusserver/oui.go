// Package radiusserver — распознавание производителя устройства по MAC-адресу (IEEE OUI).
package radiusserver

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// LookupDeviceVendor определяет производителя оборудования по MAC-адресу.
// Возвращает понятную строку (например: "Apple", "Samsung", "Случайный MAC (Private)")
// и флаг isRandom.
func LookupDeviceVendor(rawMAC string) (vendor string, isRandom bool) {
	clean := cleanMAC(rawMAC)
	if len(clean) < 6 {
		return "", false
	}

	// Проверка на Locally Administered Address (LAA / Private / Randomized MAC):
	// Второй младший бит первого байта (bit 1) равен 1:
	// x2:xx:xx, x6:xx:xx, xA:xx:xx, xE:xx:xx
	b0, err := hex.DecodeString(clean[:2])
	if err == nil && len(b0) > 0 && (b0[0]&0x02) != 0 {
		return "Частный/случайный MAC", true
	}

	oui := strings.ToUpper(clean[:6])
	if v, ok := ouiTable[oui]; ok {
		return v, false
	}

	return "Неизвестное устройство", false
}

// FormatDeviceDescription формирует сводное описание устройства для аудита и уведомлений:
// например "Apple (MAC: F0:18:98:3A:BC:12)".
func FormatDeviceDescription(rawMAC string) string {
	rawMAC = strings.TrimSpace(rawMAC)
	if rawMAC == "" {
		return ""
	}
	clean := cleanMAC(rawMAC)
	formattedMAC := formatMAC(clean)

	vendor, isRandom := LookupDeviceVendor(clean)
	if isRandom {
		return fmt.Sprintf("Частный адрес (%s)", formattedMAC)
	}
	if vendor != "" && vendor != "Неизвестное устройство" {
		return fmt.Sprintf("%s (%s)", vendor, formattedMAC)
	}
	return formattedMAC
}

func cleanMAC(s string) string {
	var sb strings.Builder
	for _, r := range s {
		if (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F') {
			sb.WriteRune(r)
		}
	}
	return sb.String()
}

func formatMAC(clean string) string {
	if len(clean) != 12 {
		return clean
	}
	return fmt.Sprintf("%s:%s:%s:%s:%s:%s",
		strings.ToUpper(clean[0:2]), strings.ToUpper(clean[2:4]),
		strings.ToUpper(clean[4:6]), strings.ToUpper(clean[6:8]),
		strings.ToUpper(clean[8:10]), strings.ToUpper(clean[10:12]))
}

// ouiTable — встроенная база топ-производителей (IEEE OUI).
var ouiTable = map[string]string{
	// Apple (MacBook, iPhone, iPad, Watch)
	"0017F2": "Apple", "001C42": "Apple", "001D4F": "Apple", "001E52": "Apple",
	"001F5B": "Apple", "0021E9": "Apple", "002312": "Apple", "0023DF": "Apple",
	"002436": "Apple", "002500": "Apple", "00254B": "Apple", "002608": "Apple",
	"00264A": "Apple", "0026B0": "Apple", "3C0630": "Apple", "3CD0F8": "Apple",
	"406C8F": "Apple", "442A60": "Apple", "444C0C": "Apple", "4860BC": "Apple",
	"4C57CA": "Apple", "5C969D": "Apple", "600308": "Apple", "6030D4": "Apple",
	"60F81D": "Apple", "680927": "Apple", "701124": "Apple", "703EAC": "Apple",
	"70DEE2": "Apple", "784F43": "Apple", "787B8A": "Apple", "7CD1C3": "Apple",
	"804971": "Apple", "80E650": "Apple", "843835": "Apple", "88665A": "Apple",
	"88C663": "Apple", "8C8590": "Apple", "9027E4": "Apple", "90B21F": "Apple",
	"94103E": "Apple", "9801A7": "Apple", "98D6BB": "Apple", "9C207B": "Apple",
	"A483E7": "Apple", "A85B78": "Apple", "AC87A3": "Apple", "ACCF85": "Apple",
	"B065BD": "Apple", "B418D1": "Apple", "B49CDF": "Apple", "B8782E": "Apple",
	"BC52B7": "Apple", "C0847A": "Apple", "C42C03": "Apple", "C83C85": "Apple",
	"CC29F4": "Apple", "D023DB": "Apple", "D4619D": "Apple", "D83062": "Apple",
	"DC2B61": "Apple", "E0B55F": "Apple", "E4CE8F": "Apple", "E8802E": "Apple",
	"EC3586": "Apple", "F01898": "Apple", "F4D488": "Apple", "F81EDF": "Apple",
	"FC253F": "Apple",

	// Samsung Electronics
	"0007AB": "Samsung", "001247": "Samsung", "00166C": "Samsung", "002119": "Samsung",
	"002454": "Samsung", "00265D": "Samsung", "08373D": "Samsung", "14F42A": "Samsung",
	"1C5A3E": "Samsung", "244B03": "Samsung", "2C0880": "Samsung", "3423BA": "Samsung",
	"3C8BFE": "Samsung", "4447CC": "Samsung", "488F5A": "Samsung", "4C3C16": "Samsung",
	"505527": "Samsung", "5492BE": "Samsung", "5C3C27": "Samsung", "606C66": "Samsung",
	"68D79A": "Samsung", "784B87": "Samsung", "805B65": "Samsung", "8425DB": "Samsung",
	"88329B": "Samsung", "8C7712": "Samsung", "9463D1": "Samsung", "983B16": "Samsung",
	"A0821F": "Samsung", "A470D6": "Samsung", "AC5F3E": "Samsung", "B0C554": "Samsung",
	"B407C6": "Samsung", "BC4486": "Samsung", "C4731E": "Samsung", "CCF957": "Samsung",
	"D022BE": "Samsung", "D487D8": "Samsung", "DC7144": "Samsung", "E4E0C5": "Samsung",
	"E8508B": "Samsung", "F409D8": "Samsung", "FCF136": "Samsung",

	// Intel (Ноутбуки, Wi-Fi модули AX200/AX210)
	"0002B3": "Intel", "000347": "Intel", "000423": "Intel", "0007E9": "Intel",
	"000E0C": "Intel", "001302": "Intel", "0013E8": "Intel", "001500": "Intel",
	"001B21": "Intel", "001E67": "Intel", "00216A": "Intel", "0024D7": "Intel",
	"081196": "Intel", "08D40C": "Intel", "244BFE": "Intel", "3413E8": "Intel",
	"3C5282": "Intel", "4851B7": "Intel", "4C796E": "Intel", "5C879C": "Intel",
	"680571": "Intel", "701CE7": "Intel", "7C5CF8": "Intel", "84A93E": "Intel",
	"887873": "Intel", "8C1645": "Intel", "94659C": "Intel", "984FEE": "Intel",
	"A434D9": "Intel", "AC74B1": "Intel", "B46921": "Intel", "B8AE6E": "Intel",
	"C85B76": "Intel", "D0AB46": "Intel", "DC5360": "Intel", "E4A471": "Intel",
	"F8633F": "Intel",

	// Xiaomi / Redmi / Poco
	"009EEA": "Xiaomi", "14F65A": "Xiaomi", "185936": "Xiaomi", "286C07": "Xiaomi",
	"3480B3": "Xiaomi", "38A4ED": "Xiaomi", "3C286D": "Xiaomi", "50642B": "Xiaomi",
	"584498": "Xiaomi", "64CC2E": "Xiaomi", "68DFDD": "Xiaomi", "742344": "Xiaomi",
	"7802F8": "Xiaomi", "7C1C4E": "Xiaomi", "842E27": "Xiaomi", "8CBEBE": "Xiaomi",
	"98FA9B": "Xiaomi", "9C99A0": "Xiaomi", "A475B9": "Xiaomi", "ACF7F3": "Xiaomi",
	"C40BC0": "Xiaomi", "D4970B": "Xiaomi", "DC5285": "Xiaomi", "F8A450": "Xiaomi",

	// Huawei / Honor
	"001882": "Huawei", "001E10": "Huawei", "00259E": "Huawei", "00464B": "Huawei",
	"0819A6": "Huawei", "104780": "Huawei", "14579F": "Huawei", "1C1D67": "Huawei",
	"200889": "Huawei", "2469A5": "Huawei", "2C97B1": "Huawei", "34CD6D": "Huawei",
	"3C4711": "Huawei", "4846FB": "Huawei", "4C5499": "Huawei", "548998": "Huawei",
	"5C0339": "Huawei", "60DE44": "Huawei", "68A03E": "Huawei", "7079B3": "Huawei",
	"786A89": "Huawei", "80B686": "Huawei", "885395": "Huawei", "8C0DF7": "Huawei",
	"94FE22": "Huawei", "9C28BF": "Huawei", "A4DCBE": "Huawei", "AC853D": "Huawei",
	"B41513": "Huawei", "C07009": "Huawei", "C8D15E": "Huawei", "D02D96": "Huawei",
	"DC094C": "Huawei", "E0247F": "Huawei", "E4A7C5": "Huawei", "EC233D": "Huawei",
	"F83DFF": "Huawei",

	// Google (Pixel, Chromebook)
	"001A11": "Google", "3C5AB4": "Google", "546009": "Google", "7032D5": "Google",
	"94EB2C": "Google", "A47733": "Google", "D4F547": "Google", "F40304": "Google",
	"F88FCA": "Google",

	// Microsoft (Surface, Windows)
	"0003FF": "Microsoft", "000D3A": "Microsoft", "00125A": "Microsoft",
	"00155D": "Microsoft", "0017FA": "Microsoft", "001D42": "Microsoft",
	"281878": "Microsoft", "485073": "Microsoft", "501AC5": "Microsoft",
	"6045BD": "Microsoft", "7085C2": "Microsoft", "7C1E52": "Microsoft",
	"985FD3": "Microsoft", "A43BF0": "Microsoft", "DCB54F": "Microsoft",
	"E45F01": "Microsoft",

	// Ubiquiti Networks (UniFi)
	"00156D": "Ubiquiti", "002722": "Ubiquiti", "0418D6": "Ubiquiti",
	"18E829": "Ubiquiti", "245A4C": "Ubiquiti", "44D9E7": "Ubiquiti",
	"7483C2": "Ubiquiti", "788A20": "Ubiquiti", "802AA8": "Ubiquiti",
	"B4FBE4": "Ubiquiti", "DC9FDB": "Ubiquiti", "E063DA": "Ubiquiti",
	"F09FC2": "Ubiquiti",

	// MikroTik
	"000C42": "MikroTik", "085531": "MikroTik", "18FD74": "MikroTik",
	"2C56DC": "MikroTik", "4C5E0C": "MikroTik", "64D154": "MikroTik",
	"6C3B6B": "MikroTik", "744D28": "MikroTik", "B869F4": "MikroTik",
	"C4AD34": "MikroTik", "CC2DE0": "MikroTik", "D401C3": "MikroTik",
	"DC2C6E": "MikroTik", "E48D8C": "MikroTik",

	// Cisco Systems
	"00000C": "Cisco", "000142": "Cisco", "000143": "Cisco", "000163": "Cisco",
	"000164": "Cisco", "000196": "Cisco", "000197": "Cisco", "000216": "Cisco",
	"000217": "Cisco", "00024A": "Cisco", "00024B": "Cisco", "00027D": "Cisco",
	"00027E": "Cisco", "0002B9": "Cisco", "0002BA": "Cisco", "000331": "Cisco",
	"000332": "Cisco", "00036B": "Cisco", "00036C": "Cisco", "00039F": "Cisco",

	// Raspberry Pi
	"B827EB": "Raspberry Pi", "D83ADD": "Raspberry Pi", "DC2632": "Raspberry Pi",
	"28CDC1": "Raspberry Pi",

	// Dell
	"00065B": "Dell", "000874": "Dell", "000BDB": "Dell", "000F1F": "Dell",
	"001143": "Dell", "00123F": "Dell", "001372": "Dell", "001422": "Dell",
	"180373": "Dell", "24B6FD": "Dell", "44A842": "Dell", "705A0F": "Dell",

	// HP / Hewlett-Packard
	"0001E6": "HP", "000802": "HP", "000F20": "HP", "00110A": "HP",
	"0014C2": "HP", "0018FE": "HP", "001E0B": "HP", "002481": "HP",

	// Lenovo
	"00061B": "Lenovo", "0012FE": "Lenovo", "001A6B": "Lenovo", "002186": "Lenovo",
	"083E8E": "Lenovo", "207693": "Lenovo", "4437E6": "Lenovo", "503EA1": "Lenovo",

	// Realtek
	"000732": "Realtek", "000EE8": "Realtek", "001020": "Realtek", "001A73": "Realtek",
	"00E04C": "Realtek", "08606E": "Realtek", "448500": "Realtek", "503EAA": "Realtek",

	// TP-Link
	"000A3A": "TP-Link", "000EC6": "TP-Link", "001478": "TP-Link", "0019E0": "TP-Link",
	"14CC20": "TP-Link", "282C02": "TP-Link", "50C7BF": "TP-Link", "704F57": "TP-Link",
	"8416F9": "TP-Link", "B04E26": "TP-Link", "C025E9": "TP-Link", "E848B8": "TP-Link",

	// Keenetic
	"28285D": "Keenetic", "50FF20": "Keenetic", "58D9D5": "Keenetic",
	"E4186B": "Keenetic", "EC43F6": "Keenetic", "EE43F6": "Keenetic",
}
