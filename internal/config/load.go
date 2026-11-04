package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Load reads and validates the Kayra YAML configuration file at path.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config %s: %w", path, err)
	}

	return &cfg, nil
}

// ActiveDatabase returns the single configured database entry's name and
// backend. The map is a "pick one, name it however you like" shape: Kayra
// requires exactly one entry.
func (c *Config) ActiveDatabase() (string, DatabaseBackend, error) {
	if len(c.Database) != 1 {
		return "", DatabaseBackend{}, fmt.Errorf("database: expected exactly one entry, found %d", len(c.Database))
	}
	for name, backend := range c.Database {
		return name, backend, nil
	}
	return "", DatabaseBackend{}, fmt.Errorf("database: no entry found")
}
