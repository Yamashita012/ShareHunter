package reporting

import (
	"encoding/json"
	"os"
	"time"
)

type Finding struct {
	Target     string `json:"target"`
	Share      string `json:"share"`
	Path       string `json:"path"`
	Category   string `json:"category"`
	Keyword    string `json:"keyword"`
	Confidence int    `json:"confidence"`
	Line       int    `json:"line"`
	Evidence   string `json:"evidence_redacted"`
	Size       int64  `json:"size_bytes"`
	Modified   int64  `json:"modified_unix"`
}
type Assessment struct {
	Tool           string         `json:"tool"`
	Version        string         `json:"version"`
	At             time.Time      `json:"started_at"`
	AuthMode       string         `json:"authentication_mode"`
	Targets        []string       `json:"targets"`
	FilesInspected int            `json:"files_inspected"`
	Directories    int            `json:"directories"`
	Duration       string         `json:"duration"`
	Findings       []Finding      `json:"findings"`
	Summary        map[string]int `json:"summary"`
	Errors         []string       `json:"errors,omitempty"`
}

func Summarize(f []Finding) map[string]int {
	m := map[string]int{}
	for _, x := range f {
		m[x.Category]++
	}
	return m
}
func WriteJSON(path string, a Assessment) error {
	b, e := json.MarshalIndent(a, "", "  ")
	if e != nil {
		return e
	}
	if err := os.WriteFile(path, b, 0600); err != nil {
		return err
	}
	return os.Chmod(path, 0600)
}
