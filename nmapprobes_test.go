package nmapprobes

import (
	"strings"
	"testing"
)

func TestServiceProbes(t *testing.T) {
	data := ServiceProbes()
	if len(data) == 0 {
		t.Fatal("ServiceProbes returned empty data")
	}
	// Should contain nmap probe format markers
	s := string(data)
	if !strings.Contains(s, "Probe TCP NULL") {
		t.Error("expected 'Probe TCP NULL' in service probes data")
	}
	if !strings.Contains(s, "match ") {
		t.Error("expected 'match ' lines in service probes data")
	}
	t.Logf("ServiceProbes: %d bytes", len(data))
}

func TestMACPrefixes(t *testing.T) {
	m := MACPrefixes()
	if len(m) == 0 {
		t.Fatal("MACPrefixes returned empty map")
	}
	if len(m) < 30000 {
		t.Errorf("expected >30k MAC entries, got %d", len(m))
	}
	t.Logf("MACPrefixes: %d entries", len(m))
}

func TestLookupMAC(t *testing.T) {
	// Xerox is 000000
	v := LookupMAC("00:00:00:12:34:56")
	if v != "Xerox" {
		t.Errorf("LookupMAC(00:00:00:...) = %q, want Xerox", v)
	}

	v = LookupMAC("ff:ff:ff:ff:ff:ff")
	// Might or might not be in the DB
	_ = v

	v = LookupMAC("invalid")
	if v != "" {
		t.Errorf("LookupMAC(invalid) = %q, want empty", v)
	}
}

func TestOSFingerprints(t *testing.T) {
	data := OSFingerprints()
	if len(data) == 0 {
		t.Fatal("OSFingerprints returned empty data")
	}
	s := string(data)
	if !strings.Contains(s, "Fingerprint ") {
		t.Error("expected 'Fingerprint ' lines in OS DB data")
	}
	if !strings.Contains(s, "Class ") {
		t.Error("expected 'Class ' lines in OS DB data")
	}
	t.Logf("OSFingerprints: %d bytes", len(data))
}

func TestLookupMACHW(t *testing.T) {
	hw := []byte{0x00, 0x00, 0x00, 0x12, 0x34, 0x56}
	v := LookupMACHW(hw)
	if v != "Xerox" {
		t.Errorf("LookupMACHW = %q, want Xerox", v)
	}
}
