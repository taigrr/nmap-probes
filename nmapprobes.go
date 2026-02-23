// Package nmapprobes provides pre-compiled nmap database files as Go byte slices.
//
// The data is derived from nmap's service probe, OS fingerprint, and MAC vendor
// databases. This package is licensed under the NPSL because it contains
// transformed nmap data.
//
// Consumers parse the returned bytes with their own parsers (e.g., gomap/probedb).
// This avoids circular dependencies and keeps the interface minimal.
package nmapprobes

import "net"

// ServiceProbes returns the embedded nmap-service-probes data.
// The returned bytes are in nmap-service-probes format and can be parsed
// by any compatible parser.
func ServiceProbes() []byte {
	return []byte(embeddedServiceProbes)
}

// MACPrefixes returns the full OUI-to-vendor map.
func MACPrefixes() map[string]string {
	return macPrefixes
}

// LookupMAC returns the vendor name for a MAC address.
// Accepts colon, dash, or no-separator formats.
func LookupMAC(mac string) string {
	return lookupMAC(mac)
}

// LookupMACHW returns the vendor name for a net.HardwareAddr.
func LookupMACHW(hw net.HardwareAddr) string {
	return lookupMACHW(hw)
}
