package discovery

import (
	_ "embed"
	"encoding/csv"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
)

//go:embed oui_starter.txt
var starterOUI string

var ouiTable = map[string]string{}

func init() { loadOUIText(starterOUI) }

func isHex6(s string) bool {
	if len(s) != 6 {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}

// loadOUIText reads "AABBCC Vendor name" lines, and also the official
// IEEE oui.txt format ("AA-BB-CC   (hex)   Vendor name").
func loadOUIText(text string) int {
	n := 0
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.Contains(line, "(base 16)") {
			continue
		}
		var key, name string
		if i := strings.Index(line, "(hex)"); i >= 0 {
			key = strings.ReplaceAll(strings.TrimSpace(line[:i]), "-", "")
			name = strings.TrimSpace(line[i+5:])
		} else if i := strings.IndexAny(line, " \t"); i > 0 {
			key = line[:i]
			name = strings.TrimSpace(line[i:])
		}
		key = strings.ToUpper(key)
		if !isHex6(key) || name == "" {
			continue
		}
		ouiTable[key] = name
		n++
	}
	return n
}

// LoadOUIFile loads a bigger vendor list. Accepts the IEEE oui.csv or
// oui.txt files, or a simple "AABBCC Vendor" text file.
func LoadOUIFile(path string) (int, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	if strings.EqualFold(filepath.Ext(path), ".csv") {
		r := csv.NewReader(strings.NewReader(string(b)))
		r.FieldsPerRecord = -1
		recs, err := r.ReadAll()
		if err != nil {
			return 0, err
		}
		n := 0
		for _, rec := range recs {
			if len(rec) < 3 {
				continue
			}
			key := strings.ToUpper(strings.TrimSpace(rec[1]))
			if isHex6(key) && strings.TrimSpace(rec[2]) != "" {
				ouiTable[key] = strings.TrimSpace(rec[2])
				n++
			}
		}
		return n, nil
	}
	return loadOUIText(string(b)), nil
}

// Vendor returns the manufacturer for a MAC address, "" if unknown.
func Vendor(mac string) string {
	hw, err := net.ParseMAC(mac)
	if err != nil || len(hw) < 3 {
		return ""
	}
	if hw[0]&0x02 != 0 {
		// Phones and laptops hide their real MAC on purpose (a privacy feature).
		return "Private (randomized) address"
	}
	return ouiTable[fmt.Sprintf("%02X%02X%02X", hw[0], hw[1], hw[2])]
}
