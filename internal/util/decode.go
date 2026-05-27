// Package decode provides a pre-scan decode pass to detect obfuscated secrets.
// Before running detectors on a line, this attempts to decode base64, hex,
// and URL-encoded content and returns additional decoded strings to scan.
package decode

import (
	"encoding/base64"
	"encoding/hex"
	"net/url"
	"regexp"
	"strings"
	"unicode/utf8"
)

var (
	base64Re = regexp.MustCompile(`[A-Za-z0-9+/=]{20,}`)
	hexRe    = regexp.MustCompile(`[0-9a-fA-F]{32,}`)
)

// Result holds a decoded string and how it was encoded.
type Result struct {
	Decoded      string
	EncodingType string // "base64", "hex", "url"
}

// DecodeLine attempts to decode the line through multiple encodings.
// Returns a slice of decoded strings (may be empty if nothing decoded).
func DecodeLine(line string) []Result {
	var results []Result

	// 1. Base64 decode.
	if matches := base64Re.FindAllString(line, 3); len(matches) > 0 {
		for _, m := range matches {
			decoded, err := base64.StdEncoding.DecodeString(m)
			if err != nil {
				// Try URL-safe base64.
				decoded, err = base64.URLEncoding.DecodeString(m)
			}
			if err == nil && utf8.Valid(decoded) && isPrintable(string(decoded)) {
				results = append(results, Result{
					Decoded:      string(decoded),
					EncodingType: "base64",
				})
			}
		}
	}

	// 2. Hex decode.
	if matches := hexRe.FindAllString(line, 3); len(matches) > 0 {
		for _, m := range matches {
			decoded, err := hex.DecodeString(m)
			if err == nil && utf8.Valid(decoded) && isPrintable(string(decoded)) {
				results = append(results, Result{
					Decoded:      string(decoded),
					EncodingType: "hex",
				})
			}
		}
	}

	// 3. URL decode.
	if strings.Contains(line, "%") {
		decoded, err := url.QueryUnescape(line)
		if err == nil && decoded != line {
			results = append(results, Result{
				Decoded:      decoded,
				EncodingType: "url",
			})
		}
	}

	return results
}

// isPrintable checks that a string contains mostly printable ASCII.
func isPrintable(s string) bool {
	if len(s) < 4 {
		return false
	}
	printable := 0
	for _, r := range s {
		if r >= 32 && r < 127 {
			printable++
		}
	}
	return float64(printable)/float64(len([]rune(s))) > 0.8
}
