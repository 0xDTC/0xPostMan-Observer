package scanner

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// SecretPattern represents a pattern to detect secrets
type SecretPattern struct {
	Name        string
	Pattern     *regexp.Regexp
	Description string
}

// SecretMatch represents a found secret
type SecretMatch struct {
	Type         string              // e.g., "AWS Access Key", "JWT Token"
	Value        string              // The matched value (partially redacted)
	RawValue     string              // The full unredacted value (for verification only)
	Location     string              // Where it was found (header, body, url, etc.)
	FullPath     string              // Full path in collection (folder/request/field)
	Description  string
	Verification *VerificationResult // Result of verification (if performed)
}

// SecretScanner scans for various types of secrets
type SecretScanner struct {
	patterns []SecretPattern
}

// NewSecretScanner creates a new secret scanner with predefined patterns
func NewSecretScanner() *SecretScanner {
	scanner := &SecretScanner{
		patterns: []SecretPattern{},
	}
	scanner.initializePatterns()
	return scanner
}

// initializePatterns sets up all secret detection patterns
func (s *SecretScanner) initializePatterns() {
	patterns := []struct {
		name        string
		regex       string
		description string
	}{
		// AWS Keys
		{
			"AWS Access Key",
			`(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}`,
			"AWS Access Key ID",
		},
		{
			"AWS Secret Key",
			`aws(.{0,20})?['\"][0-9a-zA-Z/+]{40}['\"]`,
			"AWS Secret Access Key",
		},

		// Generic API Keys
		{
			"Generic API Key",
			`(?i)(api[_-]?key|apikey|api[_-]?secret)[\s]*[:=][\s]*['\"]?([a-zA-Z0-9_\-]{20,})`,
			"Generic API Key",
		},

		// JWT Tokens
		{
			"JWT Token",
			`eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*`,
			"JSON Web Token",
		},

		// GitHub Tokens
		{
			"GitHub Token",
			`(?i)github[_-]?(?:token|pat|key)[\s]*[:=][\s]*['\"]?([a-zA-Z0-9_]{35,})`,
			"GitHub Personal Access Token",
		},
		{
			"GitHub OAuth",
			`ghp_[a-zA-Z0-9]{36}`,
			"GitHub OAuth Token",
		},

		// Generic Bearer Tokens
		{
			"Bearer Token",
			`(?i)bearer[\s]+([a-zA-Z0-9_\-\.=]+)`,
			"Bearer Authentication Token",
		},

		// Basic Auth
		{
			"Basic Auth",
			`(?i)basic[\s]+([a-zA-Z0-9+/=]{20,})`,
			"Basic Authentication Credentials",
		},

		// Passwords
		{
			"Password Field",
			`(?i)(password|passwd|pwd)[\s]*[:=][\s]*['\"]([^'\"]{8,})['\"]`,
			"Password in plain text",
		},

		// Private Keys
		{
			"Private Key",
			`-----BEGIN\s(?:RSA|DSA|EC|OPENSSH)?\s?PRIVATE KEY-----`,
			"Private Key",
		},

		// Slack Tokens
		{
			"Slack Token",
			`xox[baprs]-[0-9a-zA-Z]{10,48}`,
			"Slack Token",
		},

		// Google API Keys
		{
			"Google API Key",
			`AIza[0-9A-Za-z_-]{35}`,
			"Google API Key",
		},

		// Stripe Keys
		{
			"Stripe Secret Key",
			`sk_live_[0-9a-zA-Z]{24,}`,
			"Stripe Secret Key",
		},
		{
			"Stripe Restricted Key",
			`rk_live_[0-9a-zA-Z]{24,}`,
			"Stripe Restricted Key",
		},

		// SendGrid
		{
			"SendGrid API Key",
			`SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}`,
			"SendGrid API Key",
		},

		// Twilio
		{
			"Twilio API Key",
			`SK[a-z0-9]{32}`,
			"Twilio API Key",
		},

		// Heroku
		{
			"Heroku API Key",
			`[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`,
			"Heroku API Key (UUID format)",
		},

		// Generic Secrets
		{
			"Generic Secret",
			`(?i)(secret|token|credential)[\s]*[:=][\s]*['\"]([a-zA-Z0-9_\-\.=]{20,})['\"]`,
			"Generic Secret Value",
		},

		// Database Connection Strings
		{
			"Database Connection",
			`(?i)(mongodb|mysql|postgresql|postgres|mssql):\/\/[^\s]+`,
			"Database Connection String",
		},

		// OAuth Client Secrets
		{
			"OAuth Client Secret",
			`(?i)client[_-]?secret[\s]*[:=][\s]*['\"]?([a-zA-Z0-9_\-\.]{20,})`,
			"OAuth Client Secret",
		},
	}

	for _, p := range patterns {
		compiled, err := regexp.Compile(p.regex)
		if err != nil {
			continue // Skip invalid patterns
		}
		s.patterns = append(s.patterns, SecretPattern{
			Name:        p.name,
			Pattern:     compiled,
			Description: p.description,
		})
	}
}

// ScanCollection scans an entire Postman collection for secrets
func (s *SecretScanner) ScanCollection(collectionData map[string]interface{}) []SecretMatch {
	var matches []SecretMatch

	// Convert to JSON string for scanning
	jsonBytes, err := json.Marshal(collectionData)
	if err != nil {
		return matches
	}

	collectionJSON := string(jsonBytes)

	// Scan the entire collection
	matches = append(matches, s.scanData(collectionJSON, "Collection JSON")...)

	// Recursively scan items (requests/folders)
	if collection, ok := collectionData["collection"].(map[string]interface{}); ok {
		if items, ok := collection["item"].([]interface{}); ok {
			matches = append(matches, s.scanItems(items, "")...)
		}
	}

	return s.deduplicateMatches(matches)
}

// scanItems recursively scans collection items (folders and requests)
func (s *SecretScanner) scanItems(items []interface{}, path string) []SecretMatch {
	var matches []SecretMatch

	for i, item := range items {
		itemMap, ok := item.(map[string]interface{})
		if !ok {
			continue
		}

		// Get item name
		itemName := fmt.Sprintf("Item %d", i)
		if name, ok := itemMap["name"].(string); ok {
			itemName = name
		}

		currentPath := path
		if currentPath != "" {
			currentPath += " > " + itemName
		} else {
			currentPath = itemName
		}

		// Check if it's a folder with nested items
		if nestedItems, ok := itemMap["item"].([]interface{}); ok {
			matches = append(matches, s.scanItems(nestedItems, currentPath)...)
		}

		// Scan request details
		if request, ok := itemMap["request"].(map[string]interface{}); ok {
			matches = append(matches, s.scanRequest(request, currentPath)...)
		}
	}

	return matches
}

// scanRequest scans a single request for secrets
func (s *SecretScanner) scanRequest(request map[string]interface{}, path string) []SecretMatch {
	var matches []SecretMatch

	// Scan URL
	if url, ok := request["url"]; ok {
		urlStr := fmt.Sprintf("%v", url)
		for _, match := range s.scanData(urlStr, path+" > URL") {
			matches = append(matches, match)
		}
	}

	// Scan Headers
	if headers, ok := request["header"].([]interface{}); ok {
		for _, header := range headers {
			if headerMap, ok := header.(map[string]interface{}); ok {
				headerStr := fmt.Sprintf("%v: %v", headerMap["key"], headerMap["value"])
				for _, match := range s.scanData(headerStr, path+" > Header") {
					matches = append(matches, match)
				}
			}
		}
	}

	// Scan Body
	if body, ok := request["body"].(map[string]interface{}); ok {
		bodyStr := fmt.Sprintf("%v", body)
		for _, match := range s.scanData(bodyStr, path+" > Body") {
			matches = append(matches, match)
		}
	}

	// Scan Auth
	if auth, ok := request["auth"].(map[string]interface{}); ok {
		authStr := fmt.Sprintf("%v", auth)
		for _, match := range s.scanData(authStr, path+" > Auth") {
			matches = append(matches, match)
		}
	}

	return matches
}

// scanData scans a string for all secret patterns
func (s *SecretScanner) scanData(data string, location string) []SecretMatch {
	var matches []SecretMatch

	for _, pattern := range s.patterns {
		found := pattern.Pattern.FindAllString(data, -1)
		for _, match := range found {
			matches = append(matches, SecretMatch{
				Type:        pattern.Name,
				Value:       s.redactSecret(match),
				RawValue:    match, // Store for verification
				Location:    location,
				FullPath:    location,
				Description: pattern.Description,
			})
		}
	}

	return matches
}

// redactSecret partially redacts a secret value for safe display
func (s *SecretScanner) redactSecret(secret string) string {
	if len(secret) <= 8 {
		return "****"
	}

	// Show first 4 and last 4 characters
	visible := 4
	if len(secret) < 12 {
		visible = 2
	}

	start := secret[:visible]
	end := secret[len(secret)-visible:]
	middle := strings.Repeat("*", min(20, len(secret)-2*visible))

	return start + middle + end
}

// deduplicateMatches removes duplicate secret matches
func (s *SecretScanner) deduplicateMatches(matches []SecretMatch) []SecretMatch {
	seen := make(map[string]bool)
	var unique []SecretMatch

	for _, match := range matches {
		key := fmt.Sprintf("%s:%s:%s", match.Type, match.Value, match.Location)
		if !seen[key] {
			seen[key] = true
			unique = append(unique, match)
		}
	}

	return unique
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}