package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Config represents the application configuration
type Config struct {
	PostmanAPIKey   string           `yaml:"postman_api_key"`
	Email           EmailConfig      `yaml:"email"`
	Monitoring      MonitoringConfig `yaml:"monitoring"`
	MonitorKeywords []string         `yaml:"monitor_keywords"`
	IgnoreKeywords  []string         `yaml:"ignore_keywords"`
	DeepScan        DeepScanConfig   `yaml:"deep_scan"`
}

// DeepScanConfig holds deep scanning settings
type DeepScanConfig struct {
	Enabled       bool `yaml:"enabled"`
	VerifySecrets bool `yaml:"verify_secrets"`
}

// EmailConfig holds email notification settings
type EmailConfig struct {
	SMTPHost string   `yaml:"smtp_host"`
	SMTPPort int      `yaml:"smtp_port"`
	From     string   `yaml:"from"`
	Password string   `yaml:"password"`
	To       []string `yaml:"to"`
}

// MonitoringConfig holds monitoring settings
type MonitoringConfig struct {
	IntervalHours int `yaml:"interval_hours"`
}

// LoadConfig loads configuration from a YAML file
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return &cfg, nil
}

// Validate checks if the configuration is valid
func (c *Config) Validate() error {
	if c.PostmanAPIKey == "" || c.PostmanAPIKey == "YOUR_POSTMAN_API_KEY" {
		return fmt.Errorf("postman_api_key is required")
	}

	// Email is optional - only validate if SMTP host is provided
	if c.Email.SMTPHost != "" && c.Email.SMTPHost != "smtp.gmail.com" {
		if c.Email.From == "" {
			return fmt.Errorf("email.from is required when smtp_host is set")
		}
		if len(c.Email.To) == 0 {
			return fmt.Errorf("at least one email recipient is required when smtp_host is set")
		}
	}

	if len(c.MonitorKeywords) == 0 {
		return fmt.Errorf("at least one monitor keyword is required")
	}

	if c.Monitoring.IntervalHours <= 0 {
		c.Monitoring.IntervalHours = 24 // default to daily
	}

	// Deep scan is enabled by default if not specified
	// This is the desired behavior for security monitoring

	return nil
}

// HasEmailConfigured checks if email alerting is configured
func (c *Config) HasEmailConfigured() bool {
	return c.Email.SMTPHost != "" &&
		c.Email.From != "" &&
		len(c.Email.To) > 0 &&
		c.Email.SMTPHost != "smtp.gmail.com" ||
		(c.Email.SMTPHost == "smtp.gmail.com" && c.Email.From != "your-email@gmail.com")
}
