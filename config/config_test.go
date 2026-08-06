package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const validConfigYAML = `
main:
  app: test-app
  env: test
  http_addr: 127.0.0.1:18080
  database_conns:
    core: "sqlite:///:memory:"
  redis:
    addr: 127.0.0.1:6379
    password: ""
    db: 0
  jwt:
    secret: 0123456789abcdef0123456789abcdef
    expire: 24h
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

func TestCoreConfigValidate(t *testing.T) {
	t.Parallel()

	valid := CoreConfig{MainConf: MainConfig{
		App:           "test-app",
		Env:           "test",
		HttpAddr:      "127.0.0.1:18080",
		DatabaseConns: map[string]string{"core": "sqlite:///:memory:"},
		JWT: JwtConfig{
			Secret: strings.Repeat("a", 32),
			Expire: time.Hour,
		},
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
		{name: "short jwt secret", mutate: func(cfg *CoreConfig) { cfg.MainConf.JWT.Secret = "short" }},
		{name: "invalid jwt expiration", mutate: func(cfg *CoreConfig) { cfg.MainConf.JWT.Expire = 0 }},
		{name: "negative redis database", mutate: func(cfg *CoreConfig) { cfg.MainConf.Redis.DB = -1 }},
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
