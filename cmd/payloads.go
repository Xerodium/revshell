package cmd

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf16"
)

var payloadPlaceholderPattern = regexp.MustCompile(`\{\{[A-Z][A-Z0-9_]*\}\}`)

type payloadEntry struct {
	Name        string `json:"language"`
	Description string `json:"description"`
	Template    string `json:"payload"`
	PowerShell  bool   `json:"powershell,omitempty"`
}

func loadPayloads(path string) (map[WebShellType][]payloadEntry, error) {
	data, err := readPayloadCatalog(path)
	if err != nil {
		return nil, err
	}
	var document struct {
		Shells struct {
			Linux   []payloadEntry `json:"linux_unix"`
			Windows []payloadEntry `json:"windows"`
			Web     []payloadEntry `json:"web_shells"`
		} `json:"reverse_shells"`
	}
	if err := json.Unmarshal(data, &document); err != nil {
		return nil, fmt.Errorf("parse payload catalog: %w", err)
	}
	catalog := map[WebShellType][]payloadEntry{
		TargetShellTypeLinux:    document.Shells.Linux,
		TargetShellTypeWindows:  document.Shells.Windows,
		TargetShellTypeWebShell: document.Shells.Web,
	}
	for kind, entries := range catalog {
		seenNames := make(map[string]struct{}, len(entries))
		for i, entry := range entries {
			if strings.TrimSpace(entry.Name) == "" || strings.TrimSpace(entry.Template) == "" {
				return nil, fmt.Errorf("empty language or payload in %s entry %d", kind, i+1)
			}
			nameKey := strings.ToLower(strings.TrimSpace(entry.Name))
			if _, exists := seenNames[nameKey]; exists {
				return nil, fmt.Errorf("duplicate payload %q in %s", entry.Name, kind)
			}
			seenNames[nameKey] = struct{}{}
			if !strings.Contains(entry.Template, "{{IP}}") || !strings.Contains(entry.Template, "{{PORT}}") {
				return nil, fmt.Errorf("payload %q in %s must contain {{IP}} and {{PORT}}", entry.Name, kind)
			}
		}
	}
	return catalog, nil
}

func readPayloadCatalog(path string) ([]byte, error) {
	paths := []string{path}
	if !filepath.IsAbs(path) {
		executable, err := os.Executable()
		if err == nil {
			besideExecutable := filepath.Join(filepath.Dir(executable), path)
			if besideExecutable != path {
				paths = append(paths, besideExecutable)
			}
		}
	}

	var readErrors []error
	for _, candidate := range paths {
		data, err := os.ReadFile(candidate)
		if err == nil {
			return data, nil
		}
		readErrors = append(readErrors, fmt.Errorf("%s: %w", candidate, err))
	}

	return nil, fmt.Errorf("read payload catalog: %w", errors.Join(readErrors...))
}

func powershellBase64(value string) string {
	units := utf16.Encode([]rune(value))
	data := make([]byte, 2*len(units))
	for i, unit := range units {
		binary.LittleEndian.PutUint16(data[i*2:], unit)
	}
	return base64.StdEncoding.EncodeToString(data)
}

func renderPayload(candidate ShellCandidate, ip, port string) (string, error) {
	if net.ParseIP(ip) == nil {
		return "", fmt.Errorf("invalid callback IP: %q", ip)
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return "", fmt.Errorf("invalid callback port: %q", port)
	}
	payload := strings.NewReplacer("{{IP}}", ip, "{{PORT}}", strconv.Itoa(n)).Replace(candidate.Template)
	if placeholder := payloadPlaceholderPattern.FindString(payload); placeholder != "" {
		return "", fmt.Errorf("unresolved placeholder %s in %s", placeholder, candidate.Name)
	}
	switch candidate.Encoding {
	case EncodingNone:
		return payload, nil
	case EncodingBase64:
		return base64.StdEncoding.EncodeToString([]byte(payload)), nil
	case EncodingUrl:
		return strings.ReplaceAll(url.QueryEscape(payload), "+", "%20"), nil
	case EncodingPowerShellBase64:
		if !candidate.PowerShell {
			return "", fmt.Errorf("PowerShell encoding requires a PowerShell script")
		}
		return "powershell -EncodedCommand " + powershellBase64(payload), nil
	default:
		return "", fmt.Errorf("unsupported encoding: %q", candidate.Encoding)
	}
}
