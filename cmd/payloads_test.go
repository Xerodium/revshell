package cmd

import (
	"encoding/base64"
	"encoding/binary"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf16"
)

func TestCatalogPayloads(t *testing.T) {
	catalog, err := loadPayloads("../payloadsList.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range targetShellTypeValues {
		if len(catalog[kind]) == 0 {
			t.Fatalf("no entries for %s", kind)
		}
		for _, entry := range catalog[kind] {
			t.Run(entry.Name, func(t *testing.T) {
				candidate := ShellCandidate{
					Name:       entry.Name,
					Type:       kind,
					Template:   entry.Template,
					Encoding:   EncodingNone,
					PowerShell: entry.PowerShell,
				}
				plain, err := renderPayload(candidate, "192.0.2.10", "9001")
				if err != nil {
					t.Fatal(err)
				}
				if strings.Contains(plain, "{{") {
					t.Fatal("unresolved placeholder")
				}
				if !strings.Contains(plain, "192.0.2.10") || !strings.Contains(plain, "9001") {
					t.Fatal("callback missing")
				}
				candidate.Encoding = EncodingBase64
				encoded, err := renderPayload(candidate, "192.0.2.10", "9001")
				if err != nil {
					t.Fatal(err)
				}
				decoded, err := base64.StdEncoding.DecodeString(encoded)
				if err != nil || string(decoded) != plain {
					t.Fatal("base64 round trip failed")
				}
				candidate.Encoding = EncodingUrl
				encoded, err = renderPayload(candidate, "192.0.2.10", "9001")
				if err != nil {
					t.Fatal(err)
				}
				unescaped, err := url.QueryUnescape(encoded)
				if err != nil || unescaped != plain {
					t.Fatal("URL round trip failed")
				}
			})
		}
	}
}

func decodePS(t *testing.T, encoded string) string {
	t.Helper()
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if len(data)%2 != 0 {
		t.Fatal("odd UTF-16 byte length")
	}
	units := make([]uint16, len(data)/2)
	for i := range units {
		units[i] = binary.LittleEndian.Uint16(data[i*2:])
	}
	return string(utf16.Decode(units))
}

func TestPowerShellEncoding(t *testing.T) {
	candidate := ShellCandidate{
		Name:       "PowerShell",
		Template:   "Write-Output 'héllo 🌍 {{IP}} {{PORT}}'",
		Encoding:   EncodingPowerShellBase64,
		PowerShell: true,
	}
	payload, err := renderPayload(candidate, "192.0.2.1", "9000")
	if err != nil {
		t.Fatal(err)
	}
	if got := decodePS(t, strings.TrimPrefix(payload, "powershell -EncodedCommand ")); got != "Write-Output 'héllo 🌍 192.0.2.1 9000'" {
		t.Fatalf("got %q", got)
	}
}

func TestCatalogMarksPowerShellPayload(t *testing.T) {
	catalog, err := loadPayloads("../payloadsList.json")
	if err != nil {
		t.Fatal(err)
	}

	marked := 0
	for _, entry := range catalog[TargetShellTypeWindows] {
		if !entry.PowerShell {
			continue
		}
		marked++
		candidate := ShellCandidate{
			Name:       entry.Name,
			Template:   entry.Template,
			Encoding:   EncodingPowerShellBase64,
			PowerShell: true,
		}
		payload, err := renderPayload(candidate, "192.0.2.1", "9000")
		if err != nil {
			t.Fatal(err)
		}
		script := decodePS(t, strings.TrimPrefix(payload, "powershell -EncodedCommand "))
		if !strings.Contains(script, "'192.0.2.1',9000") {
			t.Fatalf("callback missing from decoded %s payload", entry.Name)
		}
	}
	if marked != 1 {
		t.Fatalf("got %d PowerShell payloads, want 1", marked)
	}
}

func TestLoadPayloadsRejectsInvalidCatalogEntries(t *testing.T) {
	for _, test := range []struct {
		name string
		json string
	}{
		{"missing port", `{"reverse_shells":{"linux_unix":[{"language":"Bash","payload":"connect {{IP}}"}]}}`},
		{"missing IP", `{"reverse_shells":{"linux_unix":[{"language":"Bash","payload":"connect {{PORT}}"}]}}`},
		{"duplicate name", `{"reverse_shells":{"linux_unix":[{"language":"Bash","payload":"{{IP}} {{PORT}}"},{"language":"bash","payload":"{{IP}} {{PORT}}"}]}}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "payloads.json")
			if err := os.WriteFile(path, []byte(test.json), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := loadPayloads(path); err == nil {
				t.Fatal("invalid catalog was accepted")
			}
		})
	}
}

func TestInvalidPayload(t *testing.T) {
	for _, tc := range []struct {
		ip, port, template string
		encoding           Encoding
	}{
		{"invalid", "9000", "{{IP}}", EncodingNone},
		{"192.0.2.1", "0", "{{IP}}", EncodingNone},
		{"192.0.2.1", "65536", "{{IP}}", EncodingNone},
		{"192.0.2.1", "9000", "{{MISSING}}", EncodingBase64},
		{"192.0.2.1", "9000", "echo hello", EncodingPowerShellBase64},
		{"192.0.2.1", "9000", "echo hello", Encoding("invalid")},
	} {
		if _, err := renderPayload(ShellCandidate{Template: tc.template, Encoding: tc.encoding}, tc.ip, tc.port); err == nil {
			t.Fatalf("accepted %+v", tc)
		}
	}
}
