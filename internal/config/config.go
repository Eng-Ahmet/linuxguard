package config

import (
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Server         ServerConfig         `yaml:"server"`
	Database       DatabaseConfig       `yaml:"database"`
	Monitoring     MonitoringConfig     `yaml:"monitoring"`
	ProcessMonitor ProcessMonitorConfig `yaml:"process_monitor"`
	Quarantine     QuarantineConfig     `yaml:"quarantine"`
	Detection      DetectionConfig      `yaml:"detection"`
}

type ServerConfig struct {
	Host string `yaml:"host"`
	Port int    `yaml:"port"`
}

type DatabaseConfig struct {
	Path string `yaml:"path"`
}

type MonitoringConfig struct {
	Paths         []string `yaml:"paths"`
	ExcludedPaths []string `yaml:"excluded_paths"`
}

type ProcessMonitorConfig struct {
	Enabled         bool `yaml:"enabled"`
	IntervalSeconds int  `yaml:"interval_seconds"`
}

type QuarantineConfig struct {
	Enabled bool   `yaml:"enabled"`
	Path    string `yaml:"path"`
}

type DetectionConfig struct {
	Enabled              bool     `yaml:"enabled"`
	SuspiciousExtensions []string `yaml:"suspicious_extensions"`
}

// DefaultConfig returns safe development defaults.
func DefaultConfig() *Config {
	return &Config{
		Server: ServerConfig{
			Host: "127.0.0.1",
			Port: 8080,
		},
		Database: DatabaseConfig{
			Path: "./linuxguard.db",
		},
		Monitoring: MonitoringConfig{
			Paths: []string{
				"./testdata",
			},
			ExcludedPaths: []string{
				"/proc",
				"/sys",
				"/dev",
				"/run",
			},
		},
		ProcessMonitor: ProcessMonitorConfig{
			Enabled:         true,
			IntervalSeconds: 3,
		},
		Quarantine: QuarantineConfig{
			Enabled: true,
			Path:    "./quarantine",
		},
		Detection: DetectionConfig{
			Enabled: true,
			SuspiciousExtensions: []string{
				".sh", ".bin", ".elf", ".py", ".pl", ".so",
			},
		},
	}
}

// LoadConfig loads configuration from a YAML file, overriding defaults if provided.
func LoadConfig(path string) (*Config, error) {
	cfg := DefaultConfig()
	if path == "" {
		return cfg, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return nil, err
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, err
	}

	return cfg, nil
}
