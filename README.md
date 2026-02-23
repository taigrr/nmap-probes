# nmap-probes

Pre-compiled Go databases derived from [nmap](https://nmap.org)'s data files:

- **Service probes** — 187 probes, 11,451 match patterns for service/version detection
- **OS fingerprints** — OS detection fingerprint database
- **MAC vendor prefixes** — 36,971 OUI-to-vendor mappings

## License

This package is licensed under the [Nmap Public Source License (NPSL)](https://nmap.org/npsl/) because
it contains data derived from nmap's databases. **Importing this package makes your binary subject to
the NPSL.** If that's not acceptable, use the parser from your main project and load the nmap data
files at runtime instead.

## Usage

```go
import "github.com/taigrr/nmap-probes"

// Service probes
db, err := nmapprobes.ServiceProbes()

// MAC vendor lookup
vendor := nmapprobes.LookupMAC("00:1A:2B:3C:4D:5E")

// OS fingerprints
osdb, err := nmapprobes.OSFingerprints()
```

## Regenerating

The `cmd/generate-*` tools parse nmap's raw data files into Go source.
You need a copy of the nmap source (or just the data files):

```bash
git clone --depth=1 https://github.com/nmap/nmap /tmp/nmap-ref

go run ./cmd/generate-probes/ -input /tmp/nmap-ref/nmap-service-probes -o probes_generated.go
go run ./cmd/generate-mac/ -input /tmp/nmap-ref/nmap-mac-prefixes -o mac_generated.go
```
