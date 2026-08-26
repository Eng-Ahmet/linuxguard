package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestConfigDefaultAndLoad(t *testing.T) {
	// 1. Test DefaultConfig
	cfg := DefaultConfig()
	if cfg.Server.Host != "127.0.0.1" || cfg.Server.Port != 8080 {
		t.Errorf("Unexpected default server config: %+v", cfg.Server)
	}

	// 2. Test LoadConfig with non-existent path (falls back to default)
	loaded, err := LoadConfig("")
	if err != nil || loaded.Server.Port != 8080 {
		t.Errorf("Failed loading default config: %v", err)
	}

	// 3. Test LoadConfig with custom YAML file
	tempDir := t.TempDir()
	yamlFile := filepath.Join(tempDir, "custom.yaml")
	content := []byte(`
server:
  host: "0.0.0.0"
  port: 9090
database:
  path: "/tmp/custom.db"
`)
	if err := os.WriteFile(yamlFile, content, 0644); err != nil {
		t.Fatalf("Failed writing yaml file: %v", err)
	}

	customCfg, err := LoadConfig(yamlFile)
	if err != nil {
		t.Fatalf("Failed loading custom config: %v", err)
	}
	if customCfg.Server.Host != "0.0.0.0" || customCfg.Server.Port != 9090 || customCfg.Database.Path != "/tmp/custom.db" {
		t.Errorf("Custom config mismatch: %+v", customCfg)
	}
}
