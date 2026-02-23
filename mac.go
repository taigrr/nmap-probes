package nmapprobes

import (
	"net"
	"strings"
)

func lookupMAC(mac string) string {
	mac = strings.ToUpper(mac)
	mac = strings.ReplaceAll(mac, ":", "")
	mac = strings.ReplaceAll(mac, "-", "")
	mac = strings.ReplaceAll(mac, ".", "")

	if len(mac) < 6 {
		return ""
	}

	prefix := mac[:6]
	if vendor, ok := macPrefixes[prefix]; ok {
		return vendor
	}
	return ""
}

func lookupMACHW(hw net.HardwareAddr) string {
	if len(hw) < 3 {
		return ""
	}
	const hexDigit = "0123456789ABCDEF"
	prefix := make([]byte, 6)
	for i := 0; i < 3; i++ {
		prefix[i*2] = hexDigit[hw[i]>>4]
		prefix[i*2+1] = hexDigit[hw[i]&0x0f]
	}
	if vendor, ok := macPrefixes[string(prefix)]; ok {
		return vendor
	}
	return ""
}
