package util

import (
	"os"
	"path/filepath"
	"testing"
)

func TestIsBinaryExtension(t *testing.T) {
	tests := []struct {
		path   string
		binary bool
	}{
		{"photo.png", true},
		{"app.exe", true},
		{"main.go", false},
		{"config.yaml", false},
		{"archive.tar.gz", true}, // only checks last ext, .gz is binary
		{"data.zip", true},
	}

	for _, tt := range tests {
		if got := IsBinaryExtension(tt.path); got != tt.binary {
			t.Errorf("IsBinaryExtension(%q) = %v, want %v", tt.path, got, tt.binary)
		}
	}
}

func TestTruncatePreview(t *testing.T) {
	short := "hello"
	if got := TruncatePreview(short, 120); got != short {
		t.Errorf("short string should not be truncated")
	}

	long := "a very long string that exceeds the maximum length limit that we have set for preview strings in our tool output display"
	got := TruncatePreview(long, 50)
	if len(got) > 50 {
		t.Errorf("truncated string too long: %d", len(got))
	}
}

func TestMaskSecret(t *testing.T) {
	tests := []struct {
		input  string
		reveal int
		want   string
	}{
		{"AKIAIOSFODNN7EXAMPLE", 4, "AKIA************MPLE"},
		{"short", 4, "*****"},
	}

	for _, tt := range tests {
		got := MaskSecret(tt.input, tt.reveal)
		if got != tt.want {
			t.Errorf("MaskSecret(%q, %d) = %q, want %q", tt.input, tt.reveal, got, tt.want)
		}
	}
}

func TestNormalizeLine(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"hello\r\n", "hello"},
		{"hello\r", "hello"},
		{"hello\n", "hello"},
		{"hello", "hello"},
	}

	for _, tt := range tests {
		if got := NormalizeLine(tt.input); got != tt.want {
			t.Errorf("NormalizeLine(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestReadLines(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.txt")
	os.WriteFile(path, []byte("line1\nline2\nline3\n"), 0644)

	var lines []string
	err := ReadLines(path, 0, func(num int, line string) error {
		lines = append(lines, line)
		return nil
	})

	if err != nil {
		t.Fatal(err)
	}
	if len(lines) != 3 {
		t.Errorf("expected 3 lines, got %d", len(lines))
	}
}

func TestFileExists(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "exists.txt")
	os.WriteFile(path, []byte("hi"), 0644)

	if !FileExists(path) {
		t.Error("file should exist")
	}
	if FileExists(filepath.Join(dir, "nope.txt")) {
		t.Error("file should not exist")
	}
}
