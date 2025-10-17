package config

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// LoadEnvFile loads environment variables from a .env file
func LoadEnvFile(path string) error {
	file, err := os.Open(path)
	if err != nil {
		// .env file is optional
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("failed to open .env file: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Parse KEY=VALUE
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue // Skip malformed lines
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		// Set environment variable
		if err := os.Setenv(key, value); err != nil {
			return fmt.Errorf("failed to set env var %s: %w", key, err)
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading .env file: %w", err)
	}

	return nil
}

// GetEnv gets an environment variable with a fallback default
func GetEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// GetEnvInt gets an integer environment variable with a fallback default
func GetEnvInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}
	return defaultValue
}

// GetEnvBool gets a boolean environment variable with a fallback default
func GetEnvBool(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if boolValue, err := strconv.ParseBool(value); err == nil {
			return boolValue
		}
	}
	return defaultValue
}

// GetEnvSlice gets a comma-separated environment variable as a slice
func GetEnvSlice(key string, defaultValue []string) []string {
	if value := os.Getenv(key); value != "" {
		parts := strings.Split(value, ",")
		result := make([]string, 0, len(parts))
		for _, part := range parts {
			if trimmed := strings.TrimSpace(part); trimmed != "" {
				result = append(result, trimmed)
			}
		}
		if len(result) > 0 {
			return result
		}
	}
	return defaultValue
}

// LoadConfigFromEnv loads configuration from environment variables
func LoadConfigFromEnv() (*Config, error) {
	cfg := &Config{
		PostmanAPIKey: GetEnv("POSTMAN_API_KEY", ""),
		Email: EmailConfig{
			SMTPHost: GetEnv("SMTP_HOST", ""),
			SMTPPort: GetEnvInt("SMTP_PORT", 587),
			From:     GetEnv("SMTP_FROM", ""),
			Password: GetEnv("SMTP_PASSWORD", ""),
			To:       GetEnvSlice("SMTP_TO", []string{}),
		},
		Monitoring: MonitoringConfig{
			IntervalHours: GetEnvInt("MONITOR_INTERVAL_HOURS", 24),
		},
		DeepScan: DeepScanConfig{
			Enabled:       GetEnvBool("DEEP_SCAN_ENABLED", true),
			VerifySecrets: GetEnvBool("VERIFY_SECRETS", true),
		},
		MonitorKeywords: GetEnvSlice("MONITOR_KEYWORDS", []string{}),
		IgnoreKeywords:  GetEnvSlice("IGNORE_KEYWORDS", []string{"example", "demo", "test", "sample", "tutorial"}),
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return cfg, nil
}
