package ignore

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultIgnores(t *testing.T) {
	m := New()

	tests := []struct {
		path   string
		ignore bool
	}{
		{".git/config", true},
		{"node_modules/express/index.js", true},
		{"dist/bundle.js", true},
		{"vendor/github.com/pkg/errors", true},
		{"src/main.go", false},
		{"README.md", false},
	}

	for _, tt := range tests {
		got := m.ShouldIgnore(tt.path)
		if got != tt.ignore {
			t.Errorf("ShouldIgnore(%q) = %v, want %v", tt.path, got, tt.ignore)
		}
	}
}

func TestAddPattern(t *testing.T) {
	m := New()
	m.AddPattern("*.log")
	m.AddPattern("secret/")

	if !m.ShouldIgnore("app.log") {
		t.Error("expected *.log to match app.log")
	}
	if !m.ShouldIgnore("secret/data.txt") {
		t.Error("expected secret/ to match")
	}
	if m.ShouldIgnore("main.go") {
		t.Error("main.go should not be ignored")
	}
}

func TestNegation(t *testing.T) {
	m := New()
	m.AddPattern("*.log")
	m.AddPattern("!important.log")

	if m.ShouldIgnore("important.log") {
		t.Error("important.log should not be ignored due to negation")
	}
	if !m.ShouldIgnore("debug.log") {
		t.Error("debug.log should be ignored")
	}
}

func TestShouldIgnoreDir(t *testing.T) {
	m := New()

	if !m.ShouldIgnoreDir("node_modules") {
		t.Error("node_modules should be ignored")
	}
	if !m.ShouldIgnoreDir(".git") {
		t.Error(".git should be ignored")
	}
	if m.ShouldIgnoreDir("src") {
		t.Error("src should not be ignored")
	}
}

func TestLoadFile(t *testing.T) {
	dir := t.TempDir()
	ignoreFile := filepath.Join(dir, ".secretignore")

	content := `# comment
*.log
secret/
!keep.log
`
	if err := os.WriteFile(ignoreFile, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	m := New()
	if err := m.LoadFile(ignoreFile); err != nil {
		t.Fatal(err)
	}

	if !m.ShouldIgnore("app.log") {
		t.Error("app.log should be ignored")
	}
	if m.ShouldIgnore("keep.log") {
		t.Error("keep.log should not be ignored (negation)")
	}
}

func TestLoadFileMissing(t *testing.T) {
	m := New()
	// Should not error on missing file.
	if err := m.LoadFile("/nonexistent/.secretignore"); err != nil {
		t.Errorf("expected nil error for missing file, got %v", err)
	}
}

func TestGlobMatching(t *testing.T) {
	m := New()
	m.AddPattern("*.env")
	m.AddPattern("config/*.json")

	if !m.ShouldIgnore(".env") {
		t.Error(".env should match *.env")
	}
	if !m.ShouldIgnore("config/settings.json") {
		t.Error("config/settings.json should match config/*.json")
	}
	if m.ShouldIgnore("src/main.go") {
		t.Error("src/main.go should not be ignored")
	}
}
