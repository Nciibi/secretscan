// Package util provides shared utility functions for secretscan.
package util

import (
	"bufio"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

// MaxPreviewLength is the maximum length for a preview string.
const MaxPreviewLength = 120

// DefaultMaxFileSize is the default maximum file size to scan (10 MB).
const DefaultMaxFileSize = 10 * 1024 * 1024

// BinaryExtensions contains file extensions that are always treated as binary.
var BinaryExtensions = map[string]bool{
	".exe": true, ".dll": true, ".so": true, ".dylib": true, ".bin": true,
	".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".bmp": true,
	".ico": true, ".svg": true, ".webp": true, ".tiff": true,
	".mp3": true, ".mp4": true, ".avi": true, ".mov": true, ".wav": true,
	".zip": true, ".tar": true, ".gz": true, ".bz2": true, ".xz": true,
	".rar": true, ".7z": true,
	".pdf": true, ".doc": true, ".docx": true, ".xls": true, ".xlsx": true,
	".woff": true, ".woff2": true, ".ttf": true, ".eot": true, ".otf": true,
	".o": true, ".a": true, ".pyc": true, ".class": true,
	".jar": true, ".war": true, ".ear": true,
	".sqlite": true, ".db": true,
}

// IsBinaryExtension returns true if the file extension is known to be binary.
func IsBinaryExtension(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	return BinaryExtensions[ext]
}

// IsBinaryContent detects binary files by sampling the first 512 bytes.
func IsBinaryContent(path string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer f.Close()

	buf := make([]byte, 512)
	n, err := f.Read(buf)
	if err != nil && err != io.EOF {
		return false, err
	}
	buf = buf[:n]

	// Use net/http content type detection.
	contentType := http.DetectContentType(buf)
	if strings.HasPrefix(contentType, "text/") || strings.Contains(contentType, "json") || strings.Contains(contentType, "xml") {
		return false, nil
	}

	// Also check for valid UTF-8 with no null bytes.
	if utf8.Valid(buf) && !containsNull(buf) {
		return false, nil
	}

	return true, nil
}

func containsNull(b []byte) bool {
	for _, v := range b {
		if v == 0 {
			return true
		}
	}
	return false
}

// TruncatePreview truncates a string to MaxPreviewLength, replacing the secret portion with asterisks.
func TruncatePreview(s string, maxLen int) string {
	if maxLen <= 0 {
		maxLen = MaxPreviewLength
	}
	s = strings.TrimSpace(s)
	s = NormalizeLine(s)
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

// MaskSecret replaces the middle portion of a secret with asterisks, keeping the first and last few chars.
func MaskSecret(s string, revealChars int) string {
	if len(s) <= revealChars*2 {
		return strings.Repeat("*", len(s))
	}
	return s[:revealChars] + strings.Repeat("*", len(s)-revealChars*2) + s[len(s)-revealChars:]
}

// NormalizeLine normalizes line endings to LF and trims trailing whitespace.
func NormalizeLine(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	return strings.TrimRight(s, "\n")
}

// ReadLines reads a file line by line, applying a callback for each line.
// It respects the maxSize limit and stops reading if exceeded.
func ReadLines(path string, maxSize int64, fn func(lineNum int, line string) error) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if maxSize > 0 && info.Size() > maxSize {
		return nil // skip oversized files silently
	}

	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024) // 1MB buffer per line

	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		if err := fn(lineNum, line); err != nil {
			return err
		}
	}
	return scanner.Err()
}

// IsSymlink checks if a path is a symbolic link.
func IsSymlink(path string) (bool, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return false, err
	}
	return fi.Mode()&os.ModeSymlink != 0, nil
}

// FileExists checks whether a file exists and is not a directory.
func FileExists(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return !info.IsDir()
}
