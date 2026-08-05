package config

import (
	"errors"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// LoadOptions carries the operator-side toggles that affect how a
// policy is validated. Currently this only exposes the explicit
// override needed to enable insecure_skip_verify.
type LoadOptions struct {
	// InsecureSkipVerifyOverride is the explicit operator assent to
	// disable TLS verification. Set from the --i-know-what-im-doing
	// CLI flag. Without it, Validate() refuses any policy that turns
	// the corresponding knob on.
	InsecureSkipVerifyOverride bool
}

// Load reads, parses and validates a YAML policy file at path. When
// path is empty, Load returns the built-in Default() policy instead,
// so the server is usable out of the box without a config file.
func Load(path string) (*Config, error) {
	return LoadWithOptions(path, LoadOptions{})
}

// LoadWithOptions is Load with operator-side toggles. The InsecureSkipVerify
// override is forwarded to Validate().
func LoadWithOptions(path string, opts LoadOptions) (*Config, error) {
	if path == "" {
		return Default(), nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var c Config
	if err := yaml.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if err := c.ValidateWithOptions(ValidateOptions{InsecureSkipVerifyOverride: opts.InsecureSkipVerifyOverride}); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}
	return &c, nil
}

var ErrConfigNotFound = errors.New("config not found")
