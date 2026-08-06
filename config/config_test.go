package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const validConfigYAML = `
main:
  app: test-app
  env: test
  http_addr: 127.0.0.1:18080
  database_conns:
    core: "sqlite:///:memory:"
logger: {}
`

func TestLoadYamlReaderUsesStrictFields(t *testing.T) {
	t.Parallel()

	var cfg CoreConfig
	err := LoadYamlReader(strings.NewReader(strings.Replace(
		validConfigYAML,
		"  app: test-app",
		"  app: test-app\n  unexpected: value",
		1,
	)), &cfg)
	if err == nil {
		t.Fatal("expected unknown YAML field to be rejected")
	}
}

func TestLoadYamlReaderRejectsMultipleDocuments(t *testing.T) {
	t.Parallel()

	var cfg CoreConfig
	err := LoadYamlReader(strings.NewReader(validConfigYAML+"\n---\nmain: {}\n"), &cfg)
	if err == nil {
		t.Fatal("expected multiple YAML documents to be rejected")
	}
}

func TestLoadYamlReaderRejectsDatabaseBackedRuntimeSettings(t *testing.T) {
	t.Parallel()

	for _, field := range []string{"redis", "jwt"} {
		t.Run(field, func(t *testing.T) {
			configYAML := strings.Replace(
				validConfigYAML,
				"logger: {}",
				"  "+field+": {}\nlogger: {}",
				1,
			)
			var cfg CoreConfig
			if err := LoadYamlReader(strings.NewReader(configYAML), &cfg); err == nil {
				t.Fatalf("expected main.%s to be rejected; use core_settings", field)
			}
		})
	}
}

func TestCoreConfigValidate(t *testing.T) {
	t.Parallel()

	valid := CoreConfig{MainConf: MainConfig{
		App:           "test-app",
		Env:           "test",
		HttpAddr:      "127.0.0.1:18080",
		DatabaseConns: map[string]string{"core": "sqlite:///:memory:"},
	}}

	tests := []struct {
		name   string
		mutate func(*CoreConfig)
	}{
		{name: "missing app", mutate: func(cfg *CoreConfig) { cfg.MainConf.App = "" }},
		{name: "missing env", mutate: func(cfg *CoreConfig) { cfg.MainConf.Env = "" }},
		{name: "invalid http address", mutate: func(cfg *CoreConfig) { cfg.MainConf.HttpAddr = "18080" }},
		{name: "missing core database", mutate: func(cfg *CoreConfig) { cfg.MainConf.DatabaseConns = nil }},
		{name: "invalid core database", mutate: func(cfg *CoreConfig) { cfg.MainConf.DatabaseConns["core"] = "://" }},
	}

	if err := valid.Validate(); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := valid
			cfg.MainConf.DatabaseConns = map[string]string{"core": valid.MainConf.DatabaseConns["core"]}
			tt.mutate(&cfg)
			if err := cfg.Validate(); err == nil {
				t.Fatal("expected invalid config to be rejected")
			}
		})
	}
}

func TestLoadCoreConfigDoesNotReplaceValidConfigAfterFailure(t *testing.T) {
	dir := t.TempDir()
	validPath := filepath.Join(dir, "valid.yaml")
	invalidPath := filepath.Join(dir, "invalid.yaml")
	if err := os.WriteFile(validPath, []byte(validConfigYAML), 0o600); err != nil {
		t.Fatalf("write valid config: %v", err)
	}
	if err := os.WriteFile(invalidPath, []byte("main:\n  app: broken\n"), 0o600); err != nil {
		t.Fatalf("write invalid config: %v", err)
	}

	loaded, err := LoadCoreConfigFromFile(validPath)
	if err != nil {
		t.Fatalf("load valid config: %v", err)
	}
	if _, err := LoadCoreConfigFromFile(invalidPath); err == nil {
		t.Fatal("expected invalid config load to fail")
	}
	if Conf() != loaded {
		t.Fatal("failed load replaced the last valid configuration")
	}
}
