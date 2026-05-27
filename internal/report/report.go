// Package report provides output formatting for scan results.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/fatih/color"
	"github.com/secretscan/secretscan/internal/models"
)

// Format represents an output format type.
type Format string

const (
	FormatText Format = "text"
	FormatJSON Format = "json"
	FormatSARIF Format = "sarif"
)

// Writer writes scan results in a specific format.
type Writer struct {
	format Format
	w      io.Writer
}

// NewWriter creates a new report writer.
func NewWriter(w io.Writer, format string) *Writer {
	f := FormatText
	switch strings.ToLower(format) {
	case "json":
		f = FormatJSON
	case "sarif":
		f = FormatSARIF
	}
	return &Writer{format: f, w: w}
}

// Write outputs the scan result in the configured format.
func (rw *Writer) Write(result models.ScanResult) error {
	// Sort by severity (critical first), then by file and line.
	sort.Slice(result.Findings, func(i, j int) bool {
		si := result.Findings[i].Severity.Weight()
		sj := result.Findings[j].Severity.Weight()
		if si != sj {
			return si > sj
		}
		if result.Findings[i].File != result.Findings[j].File {
			return result.Findings[i].File < result.Findings[j].File
		}
		return result.Findings[i].Line < result.Findings[j].Line
	})

	switch rw.format {
	case FormatJSON:
		return rw.writeJSON(result)
	case FormatSARIF:
		return rw.writeSARIF(result)
	default:
		return rw.writeText(result)
	}
}

func (rw *Writer) writeText(result models.ScanResult) error {
	bold := color.New(color.Bold)
	red := color.New(color.FgRed, color.Bold)
	yellow := color.New(color.FgYellow, color.Bold)
	cyan := color.New(color.FgCyan)
	green := color.New(color.FgGreen, color.Bold)
	dim := color.New(color.Faint)

	bold.Fprintf(rw.w, "\n🔍 secretscan results\n")
	dim.Fprintf(rw.w, "   Path: %s | Mode: %s | Duration: %s\n",
		result.ScanPath, result.ScanMode, result.Duration)
	dim.Fprintf(rw.w, "   Files scanned: %d", result.ScannedFiles)
	if result.ScannedCommits > 0 {
		dim.Fprintf(rw.w, " | Commits scanned: %d", result.ScannedCommits)
	}
	fmt.Fprintln(rw.w)
	fmt.Fprintln(rw.w, strings.Repeat("─", 70))

	if !result.HasFindings() {
		green.Fprintf(rw.w, "\n✅ No secrets found!\n\n")
		return nil
	}

	counts := result.CountBySeverity()
	fmt.Fprintf(rw.w, "\n")
	bold.Fprintf(rw.w, "📊 Summary: %d findings\n", len(result.Findings))
	if c := counts[models.SeverityCritical]; c > 0 {
		red.Fprintf(rw.w, "   🔴 Critical: %d\n", c)
	}
	if c := counts[models.SeverityHigh]; c > 0 {
		red.Fprintf(rw.w, "   🟠 High: %d\n", c)
	}
	if c := counts[models.SeverityMedium]; c > 0 {
		yellow.Fprintf(rw.w, "   🟡 Medium: %d\n", c)
	}
	if c := counts[models.SeverityLow]; c > 0 {
		dim.Fprintf(rw.w, "   ⚪ Low: %d\n", c)
	}
	fmt.Fprintln(rw.w, strings.Repeat("─", 70))

	for i, f := range result.Findings {
		fmt.Fprintln(rw.w)
		severityColor := dim
		icon := "⚪"
		switch f.Severity {
		case models.SeverityCritical:
			severityColor = red
			icon = "🔴"
		case models.SeverityHigh:
			severityColor = color.New(color.FgHiRed)
			icon = "🟠"
		case models.SeverityMedium:
			severityColor = yellow
			icon = "🟡"
		}

		bold.Fprintf(rw.w, "[%d] ", i+1)
		severityColor.Fprintf(rw.w, "%s %s ", icon, strings.ToUpper(string(f.Severity)))
		bold.Fprintf(rw.w, "| %s\n", f.Type)

		cyan.Fprintf(rw.w, "    📁 %s:%d:%d\n", f.File, f.Line, f.Column)
		fmt.Fprintf(rw.w, "    🔎 Detector: %s | Confidence: %d%% | Source: %s\n",
			f.Detector, f.Confidence, f.Source)
		dim.Fprintf(rw.w, "    📝 %s\n", f.Reason)
		fmt.Fprintf(rw.w, "    💬 %s\n", f.Preview)

		if f.CommitHash != "" {
			dim.Fprintf(rw.w, "    📌 Commit: %s — %s\n", f.CommitHash, f.CommitMessage)
		}
	}

	fmt.Fprintln(rw.w)
	fmt.Fprintln(rw.w, strings.Repeat("─", 70))
	red.Fprintf(rw.w, "⚠️  %d potential secret(s) found. Review and remediate.\n\n", len(result.Findings))
	return nil
}

func (rw *Writer) writeJSON(result models.ScanResult) error {
	enc := json.NewEncoder(rw.w)
	enc.SetIndent("", "  ")
	return enc.Encode(result)
}
