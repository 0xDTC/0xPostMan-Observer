package reporter

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/yourusername/postman-observer/notifier"
	"github.com/yourusername/postman-observer/scanner"
)

// Finding represents a complete finding report
type Finding struct {
	ObservedLink     string         `json:"observed_link"`
	CollectionURL    string         `json:"collection_url"`
	CollectionAPIURL string         `json:"collection_api_url"`
	CollectionID     string         `json:"collection_id"`
	Name             string         `json:"name"`
	Owner            string         `json:"owner"`
	Description      string         `json:"description"`
	IsPublic         bool           `json:"is_public"`
	Keyword          string         `json:"keyword"`
	SuggestedIgnore  string         `json:"suggested_ignore_keyword"`
	Secrets          []SecretDetail `json:"secrets"`
	SecretCount      int            `json:"secret_count"`
	Timestamp        string         `json:"timestamp"`
}

// SecretDetail represents detailed secret information
type SecretDetail struct {
	Type        string   `json:"type"`
	Value       string   `json:"value"`       // Full unmasked value
	Location    string   `json:"location"`    // Primary location (kept for backwards compatibility)
	Locations   []string `json:"locations"`   // All locations where this secret was found
	Occurrences int      `json:"occurrences"` // Number of times found
	FullPath    string   `json:"full_path"`
	Description string   `json:"description"`
	IsVerified  bool     `json:"is_verified"`
	IsValid     bool     `json:"is_valid"`
	RateLimited bool     `json:"rate_limited"`
	VerifyMsg   string   `json:"verify_message,omitempty"`
}

// Report represents the complete report structure
type Report struct {
	ReportTime    string    `json:"report_time"`
	TotalFindings int       `json:"total_findings"`
	CriticalCount int       `json:"critical_count"`
	WarningCount  int       `json:"warning_count"`
	TotalSecrets  int       `json:"total_secrets"`
	Findings      []Finding `json:"findings"`
}

// Reporter handles report generation
type Reporter struct {
	reportsDir string
}

// NewReporter creates a new reporter instance
func NewReporter(reportsDir string) *Reporter {
	return &Reporter{
		reportsDir: reportsDir,
	}
}

// DetectDuplicateSecrets finds secrets that appear in multiple collections
func DetectDuplicateSecrets(alerts []notifier.Alert) map[string][]string {
	secretToCollections := make(map[string][]string)

	for _, alert := range alerts {
		for _, secret := range alert.Secrets {
			if secret.RawValue != "" {
				secretToCollections[secret.RawValue] = append(secretToCollections[secret.RawValue], alert.Collection.Name)
			}
		}
	}

	// Filter to only keep duplicates
	duplicates := make(map[string][]string)
	for secret, collections := range secretToCollections {
		if len(collections) > 1 {
			duplicates[secret] = collections
		}
	}

	return duplicates
}

// GenerateReport creates a JSON report from alerts
func (r *Reporter) GenerateReport(alerts []notifier.Alert) (string, error) {
	if len(alerts) == 0 {
		return "", nil
	}

	// Create reports directory if it doesn't exist
	if err := os.MkdirAll(r.reportsDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create reports directory: %w", err)
	}

	// Detect duplicate secrets (not used in JSON report but kept for consistency)
	_ = DetectDuplicateSecrets(alerts)

	// Build report
	report := Report{
		ReportTime:    time.Now().Format("2006-01-02 03:04:05 PM"),
		TotalFindings: len(alerts),
		Findings:      make([]Finding, 0, len(alerts)),
	}

	totalSecrets := 0
	for _, alert := range alerts {
		finding := Finding{
			ObservedLink:     fmt.Sprintf("https://www.postman.com/collection/%s", alert.Collection.ID),
			CollectionURL:    fmt.Sprintf("https://www.postman.com/%s", alert.Collection.ID),
			CollectionAPIURL: fmt.Sprintf("https://api.getpostman.com/collections/%s", alert.Collection.ID),
			CollectionID:     alert.Collection.ID,
			Name:             alert.Collection.Name,
			Owner:            alert.Collection.Owner,
			Description:      alert.Collection.Description,
			IsPublic:         alert.IsPublic,
			Keyword:          alert.Keyword,
			SuggestedIgnore:  alert.Collection.Name, // Suggest collection name for ignore list
			SecretCount:      len(alert.Secrets),
			Timestamp:        alert.Timestamp.Format("2006-01-02 03:04:05 PM"),
			Secrets:          make([]SecretDetail, 0, len(alert.Secrets)),
		}

		// Count critical vs warning
		if len(alert.Secrets) > 0 {
			report.CriticalCount++
		} else {
			report.WarningCount++
		}

		// Add secret details
		for _, secret := range alert.Secrets {
			detail := SecretDetail{
				Type:        secret.Type,
				Value:       secret.RawValue, // Use full unmasked value
				Location:    secret.Location, // Primary location for backwards compatibility
				Locations:   secret.Locations,
				Occurrences: secret.Occurrences,
				FullPath:    secret.FullPath,
				Description: secret.Description,
			}

			// Add verification details if available
			if secret.Verification != nil {
				detail.IsVerified = true
				detail.IsValid = secret.Verification.IsValid
				detail.RateLimited = secret.Verification.RateLimited
				detail.VerifyMsg = secret.Verification.Message
			}

			finding.Secrets = append(finding.Secrets, detail)
			totalSecrets++
		}

		report.Findings = append(report.Findings, finding)
	}

	report.TotalSecrets = totalSecrets

	// Generate filename with timestamp
	timestamp := time.Now().Format("2006-01-02_03-04-05PM")
	filename := fmt.Sprintf("findings_%s.json", timestamp)
	filepath := filepath.Join(r.reportsDir, filename)

	// Write JSON report
	file, err := os.Create(filepath)
	if err != nil {
		return "", fmt.Errorf("failed to create report file: %w", err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(report); err != nil {
		return "", fmt.Errorf("failed to write report: %w", err)
	}

	return filepath, nil
}

// ConvertSecretsToDetails converts scanner secrets to report details
func ConvertSecretsToDetails(secrets []scanner.SecretMatch) []SecretDetail {
	details := make([]SecretDetail, 0, len(secrets))
	for _, secret := range secrets {
		detail := SecretDetail{
			Type:        secret.Type,
			Value:       secret.RawValue, // Use full unmasked value
			Location:    secret.Location, // Primary location for backwards compatibility
			Locations:   secret.Locations,
			Occurrences: secret.Occurrences,
			FullPath:    secret.FullPath,
			Description: secret.Description,
		}

		if secret.Verification != nil {
			detail.IsVerified = true
			detail.IsValid = secret.Verification.IsValid
			detail.RateLimited = secret.Verification.RateLimited
			detail.VerifyMsg = secret.Verification.Message
		}

		details = append(details, detail)
	}
	return details
}
