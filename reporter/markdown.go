package reporter

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/yourusername/postman-observer/notifier"
)

// GenerateMarkdownReport creates a Markdown table-formatted report
func (r *Reporter) GenerateMarkdownReport(alerts []notifier.Alert, duplicates map[string][]string) (string, error) {
	if len(alerts) == 0 {
		return "", nil
	}

	// Create reports directory
	if err := os.MkdirAll(r.reportsDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create reports directory: %w", err)
	}

	// Build report
	totalSecrets := 0
	criticalCount := 0
	warningCount := 0

	for _, alert := range alerts {
		if len(alert.Secrets) > 0 {
			criticalCount++
			totalSecrets += len(alert.Secrets)
		} else {
			warningCount++
		}
	}

	var md strings.Builder

	// Header
	md.WriteString(fmt.Sprintf("# 🔍 Postman Observer Security Report\n\n"))
	md.WriteString(fmt.Sprintf("**Generated:** %s\n\n", time.Now().Format("Monday, January 2, 2006 at 03:04:05 PM MST")))

	md.WriteString("---\n\n")

	// Summary
	md.WriteString("## 📊 Executive Summary\n\n")
	md.WriteString("| Metric | Count | Description |\n")
	md.WriteString("|--------|-------|-------------|\n")
	md.WriteString(fmt.Sprintf("| 🚨 **CRITICAL** | **%d** | Collections with exposed secrets |\n", criticalCount))
	md.WriteString(fmt.Sprintf("| ⚠️  **WARNING** | **%d** | Public collections (no secrets) |\n", warningCount))
	md.WriteString(fmt.Sprintf("| 🔑 **Total Secrets** | **%d** | Total credentials exposed |\n", totalSecrets))
	md.WriteString(fmt.Sprintf("| 📦 **Total Findings** | **%d** | Collections analyzed |\n\n", len(alerts)))

	md.WriteString("---\n\n")

	// Detailed Findings
	md.WriteString("## 🔍 Detailed Findings\n\n")

	for i, alert := range alerts {
		severity := "⚠️ WARNING"
		if len(alert.Secrets) > 0 {
			severity = "🚨 CRITICAL"
		}

		owner := "Unknown"
		if alert.Collection.Owner != "" {
			owner = alert.Collection.Owner
		}

		md.WriteString(fmt.Sprintf("### %d. %s\n\n", i+1, escapeMarkdown(alert.Collection.Name)))

		// Collection Info Table
		md.WriteString("| Property | Value |\n")
		md.WriteString("|----------|-------|\n")
		md.WriteString(fmt.Sprintf("| **Status** | %s |\n", severity))
		md.WriteString(fmt.Sprintf("| **Collection ID** | `%s` |\n", alert.Collection.ID))
		md.WriteString(fmt.Sprintf("| **Owner** | %s |\n", owner))
		md.WriteString(fmt.Sprintf("| **Keyword Matched** | `%s` |\n", escapeMarkdown(alert.Keyword)))
		md.WriteString(fmt.Sprintf("| **Secrets Found** | **%d** |\n", len(alert.Secrets)))
		md.WriteString(fmt.Sprintf("| **Suggested Ignore** | `%s` |\n", escapeMarkdown(alert.Collection.Name)))
		md.WriteString(fmt.Sprintf("| **Detected At** | %s |\n\n", alert.Timestamp.Format("2006-01-02 03:04:05 PM")))

		// Links
		md.WriteString("**🔗 Quick Links:**\n")
		md.WriteString(fmt.Sprintf("- [View Collection](https://www.postman.com/collection/%s)\n", alert.Collection.ID))
		md.WriteString(fmt.Sprintf("- [Web Interface](https://www.postman.com/%s)\n", alert.Collection.ID))
		md.WriteString(fmt.Sprintf("- [API Endpoint](https://api.getpostman.com/collections/%s)\n\n", alert.Collection.ID))

		// Secrets Details
		if len(alert.Secrets) > 0 {
			md.WriteString("#### 🔐 Exposed Secrets\n\n")
			md.WriteString("| # | Type | Value | Location | Status |\n")
			md.WriteString("|---|------|-------|----------|--------|\n")

			for j, secret := range alert.Secrets {
				verification := "-"
				if secret.Verification != nil {
					if secret.Verification.IsValid {
						verification = "✅ **ACTIVE**"
					} else {
						verification = "❌ Invalid"
					}
				}

				// Check for duplicates
				duplicateNote := ""
				if dups, exists := duplicates[secret.RawValue]; exists && len(dups) > 1 {
					duplicateNote = fmt.Sprintf(" ⚠️ **[Duplicate in %d collections]**", len(dups))
				}

				truncatedValue := secret.RawValue
				if len(truncatedValue) > 80 {
					truncatedValue = truncatedValue[:80] + "..."
				}

				md.WriteString(fmt.Sprintf("| %d | **%s** | `%s`%s | %s | %s |\n",
					j+1,
					escapeMarkdown(secret.Type),
					escapeMarkdown(truncatedValue),
					duplicateNote,
					escapeMarkdown(secret.Location),
					verification,
				))
			}
			md.WriteString("\n")

			// Full secret values (collapsed section)
			md.WriteString("<details>\n")
			md.WriteString("<summary>📋 Click to view full secret values (⚠️ Sensitive Data)</summary>\n\n")
			md.WriteString("```\n")
			for j, secret := range alert.Secrets {
				md.WriteString(fmt.Sprintf("%d. [%s]\n", j+1, secret.Type))
				md.WriteString(fmt.Sprintf("   Value: %s\n", secret.RawValue))
				md.WriteString(fmt.Sprintf("   Location: %s\n\n", secret.Location))
			}
			md.WriteString("```\n")
			md.WriteString("</details>\n\n")
		} else {
			md.WriteString("✅ **No secrets detected in this collection**\n\n")
		}

		md.WriteString("---\n\n")
	}

	// Duplicate Secrets Section
	if len(duplicates) > 0 {
		md.WriteString("## 🔄 Duplicate Secrets Report\n\n")
		md.WriteString("The following secrets appear in multiple collections:\n\n")
		md.WriteString("| Secret (truncated) | Type | Collections Count |\n")
		md.WriteString("|-------------------|------|-------------------|\n")

		for secretValue, collectionNames := range duplicates {
			if len(collectionNames) > 1 {
				truncated := secretValue
				if len(truncated) > 50 {
					truncated = truncated[:50] + "..."
				}

				// Determine type (simple heuristic)
				secretType := "Unknown"
				if strings.HasPrefix(secretValue, "ghp_") {
					secretType = "GitHub Token"
				} else if strings.HasPrefix(secretValue, "eyJ") {
					secretType = "JWT Token"
				} else if len(secretValue) == 36 && strings.Count(secretValue, "-") == 4 {
					secretType = "Heroku API Key"
				}

				md.WriteString(fmt.Sprintf("| `%s` | %s | **%d** collections |\n",
					escapeMarkdown(truncated),
					secretType,
					len(collectionNames),
				))
			}
		}
		md.WriteString("\n")
	}

	// Footer
	md.WriteString("---\n\n")
	md.WriteString("## ⚠️ Security Notice\n\n")
	md.WriteString("- **Store this report securely** - it contains sensitive credential information\n")
	md.WriteString("- **Limit access** to authorized security personnel only\n")
	md.WriteString("- **Revoke exposed secrets** immediately\n")
	md.WriteString("- **Add collections to ignore list** if they are intentional test/demo collections\n\n")
	md.WriteString("---\n\n")
	md.WriteString("*🤖 Generated by Postman Observer*\n")

	// Write to file
	timestamp := time.Now().Format("2006-01-02_03-04-05PM")
	filename := fmt.Sprintf("findings_%s.md", timestamp)
	filepath := filepath.Join(r.reportsDir, filename)

	if err := os.WriteFile(filepath, []byte(md.String()), 0644); err != nil {
		return "", fmt.Errorf("failed to write Markdown report: %w", err)
	}

	return filepath, nil
}

// escapeMarkdown escapes special markdown characters
func escapeMarkdown(s string) string {
	replacer := strings.NewReplacer(
		"|", "\\|",
		"[", "\\[",
		"]", "\\]",
		"*", "\\*",
		"_", "\\_",
		"`", "\\`",
	)
	return replacer.Replace(s)
}