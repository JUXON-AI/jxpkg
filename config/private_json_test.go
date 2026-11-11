package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadPrivateJSONRejectsAmbiguousAndUnboundedFiles(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "private.json")
	var out struct {
		Name   string `json:"name"`
		Nested *struct {
			ID string `json:"id"`
		} `json:"nested"`
	}
	for _, raw := range []string{`{"name":"a","name":"b"}`, `{"name":"a","NAME":"b"}`, `{"nested":{"id":"a","ID":"b"}}`, `{"nested":{"id":"a","id":"b"}}`, `{"unknown":true}`, `null`, `{} {}`, `{"name":"` + strings.Repeat("x", 32768) + `"}`} {
		if e := os.WriteFile(file, []byte(raw), 0600); e != nil {
			t.Fatal(e)
		}
		if e := LoadPrivateJSON(file, &out); !errors.Is(e, ErrPrivateConfiguration) {
			t.Fatal("invalid private file accepted")
		}
	}
	if e := os.WriteFile(file, []byte(`{"name":"valid","nested":null}`), 0600); e != nil {
		t.Fatal(e)
	}
	if e := LoadPrivateJSON(file, &out); e != nil || out.Name != "valid" {
		t.Fatal("valid private file rejected", e)
	}
	if e := os.Chmod(file, 0644); e != nil {
		t.Fatal(e)
	}
	if LoadPrivateJSON(file, &out) == nil {
		t.Fatal("public-readable secret accepted")
	}
	if LoadPrivateJSON(dir, &out) == nil {
		t.Fatal("directory accepted")
	}
}

func TestPrivateJSONChecksAliasesInsideArrays(t *testing.T) {
	file := filepath.Join(t.TempDir(), "config.json")
	var out struct {
		Rows []struct {
			ID string `json:"id"`
		} `json:"rows"`
	}
	if e := os.WriteFile(file, []byte(`{"rows":[{"id":"one","ID":"two"}]}`), 0600); e != nil {
		t.Fatal(e)
	}
	if LoadPrivateJSON(file, &out) == nil {
		t.Fatal("array nested aliases accepted")
	}
	if e := os.WriteFile(file, []byte(`{"rows":[{"id":"one"}]}`), 0600); e != nil {
		t.Fatal(e)
	}
	if e := LoadPrivateJSON(file, &out); e != nil || len(out.Rows) != 1 || out.Rows[0].ID != "one" {
		t.Fatal("valid array rejected", e)
	}
}
