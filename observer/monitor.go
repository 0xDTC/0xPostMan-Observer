package observer

import (
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/yourusername/postman-observer/config"
	"github.com/yourusername/postman-observer/notifier"
	"github.com/yourusername/postman-observer/postman"
	"github.com/yourusername/postman-observer/reporter"
	"github.com/yourusername/postman-observer/scanner"
)

// Monitor orchestrates the monitoring process
type Monitor struct {
	config          *config.Config
	client          *postman.Client
	notifier        *notifier.EmailNotifier
	reporter        *reporter.Reporter
	secretScanner   *scanner.SecretScanner
	secretVerifier  *scanner.SecretVerifier
	seenAlerts      map[string]time.Time // Track already alerted collections
	dryRun          bool                 // If true, don't send emails
	currentUserID   string               // Current user's ID to filter own collections
}

// NewMonitor creates a new monitor instance
func NewMonitor(cfg *config.Config) *Monitor {
	return &Monitor{
		config:          cfg,
		client:          postman.NewClient(cfg.PostmanAPIKey),
		notifier:        notifier.NewEmailNotifier(cfg.Email),
		reporter:        reporter.NewReporter("reports"),
		secretScanner:   scanner.NewSecretScanner(),
		secretVerifier:  scanner.NewSecretVerifier(),
		seenAlerts:      make(map[string]time.Time),
		dryRun:          false,
	}
}

// SetDryRun enables or disables dry-run mode
func (m *Monitor) SetDryRun(enabled bool) {
	m.dryRun = enabled
}

// Start begins the monitoring loop
func (m *Monitor) Start() {
	log.Println("🔍 Postman Observer started")

	// Get current user ID to filter own collections
	userID, err := m.client.GetCurrentUser()
	if err != nil {
		log.Printf("⚠️  Warning: Could not get current user info: %v", err)
		log.Println("   Continuing without user filtering (may include your own collections)")
	} else {
		m.currentUserID = userID
		log.Printf("✅ Authenticated as user ID: %s (filtering out your collections)", userID)
	}

	log.Printf("Monitoring %d keywords, ignoring %d patterns",
		len(m.config.MonitorKeywords), len(m.config.IgnoreKeywords))
	log.Printf("Checking every %d hours", m.config.Monitoring.IntervalHours)

	// Run immediately on start
	m.runCheck()

	// Schedule periodic checks
	ticker := time.NewTicker(time.Duration(m.config.Monitoring.IntervalHours) * time.Hour)
	defer ticker.Stop()

	for range ticker.C {
		m.runCheck()
	}
}

// RunOnce runs a single check and exits
func (m *Monitor) RunOnce() error {
	// Get current user ID to filter own collections
	userID, err := m.client.GetCurrentUser()
	if err != nil {
		log.Printf("⚠️  Warning: Could not get current user info: %v", err)
		log.Println("   Continuing without user filtering (may include your own collections)")
	} else {
		m.currentUserID = userID
		log.Printf("✅ Authenticated as user ID: %s (filtering out your collections)", userID)
	}

	return m.runCheck()
}

// runCheck performs a single monitoring check
func (m *Monitor) runCheck() error {
	log.Printf("⏰ Starting check at %s", time.Now().Format("2006-01-02 15:04:05"))

	var allAlerts []notifier.Alert

	// Search for each monitored keyword
	for _, keyword := range m.config.MonitorKeywords {
		log.Printf("🔎 Searching for keyword: %s", keyword)

		collections, err := m.client.SearchCollectionsByQuery(keyword)
		if err != nil {
			log.Printf("⚠️  Error searching for '%s': %v", keyword, err)
			continue
		}

		log.Printf("   Found %d collections", len(collections))

		// Filter and check each collection
		for _, col := range collections {
			// Skip user's own collections
			if m.currentUserID != "" && col.Owner == m.currentUserID {
				log.Printf("   ⏭️  Skipping your own collection: %s (Owner: %s)", col.Name, col.Owner)
				continue
			}

			if m.shouldIgnore(col) {
				log.Printf("   ⏭️  Skipping ignored collection: %s", col.Name)
				continue
			}

			// Check if we've already alerted about this collection recently (within 7 days)
			alertKey := fmt.Sprintf("%s:%s", keyword, col.ID)
			if lastAlert, exists := m.seenAlerts[alertKey]; exists {
				if time.Since(lastAlert) < 7*24*time.Hour {
					continue // Skip recently alerted collections
				}
			}

			// Fetch full collection details and scan for secrets if deep scan is enabled
			var secrets []scanner.SecretMatch
			if m.config.DeepScan.Enabled {
				log.Printf("   🔬 Deep scanning collection for secrets: %s", col.Name)

				collectionData, err := m.client.GetCollectionAsMap(col.ID)
				if err != nil {
					log.Printf("   ⚠️  Could not fetch collection details for scanning: %v", err)
					// Continue with basic alert even if deep scan fails
				} else {
					secrets = m.secretScanner.ScanCollection(collectionData)
					if len(secrets) > 0 {
						log.Printf("   ⚠️  Found %d secret(s) in collection!", len(secrets))

						// Verify secrets if enabled
						if m.config.DeepScan.VerifySecrets {
							log.Printf("   🔐 Verifying %d secret(s)...", len(secrets))
							verifiedCount := 0
							for i := range secrets {
								result := m.secretVerifier.VerifySecret(secrets[i])
								secrets[i].Verification = result
								if result.IsValid {
									verifiedCount++
									log.Printf("   ✅ Verified: %s - %s", secrets[i].Type, result.Message)
								} else if result.RateLimited {
									log.Printf("   ⏸️  Rate limited: %s", secrets[i].Type)
								} else {
									log.Printf("   ❌ Not active: %s - %s", secrets[i].Type, result.Message)
								}
							}
							if verifiedCount > 0 {
								log.Printf("   🚨 CRITICAL: %d ACTIVE secret(s) verified!", verifiedCount)
							}
						}
					}
				}
			}

			// New alert found - always alert about public collections
			alert := notifier.Alert{
				Keyword:    keyword,
				Collection: col,
				Secrets:    secrets,
				IsPublic:   true, // Collections found via API are accessible
				Timestamp:  time.Now(),
			}

			allAlerts = append(allAlerts, alert)
			m.seenAlerts[alertKey] = time.Now()

			// Log with explicit public exposure warning
			if len(secrets) > 0 {
				log.Printf("   🚨 CRITICAL: PUBLIC collection with %d EXPOSED SECRET(S) - %s (ID: %s)", len(secrets), col.Name, col.ID)
			} else {
				log.Printf("   ⚠️  WARNING: PUBLIC collection found (no secrets detected) - %s (ID: %s)", col.Name, col.ID)
			}
		}
	}

	// Send notifications if there are new alerts
	if len(allAlerts) > 0 {
		// Count critical vs warning alerts
		criticalCount := 0
		warningCount := 0
		for _, alert := range allAlerts {
			if len(alert.Secrets) > 0 {
				criticalCount++
			} else {
				warningCount++
			}
		}

		log.Printf("📊 Summary: %d CRITICAL (with secrets), %d WARNING (public only)", criticalCount, warningCount)

		if m.dryRun {
			log.Printf("🧪 DRY-RUN: Would send %d alert(s) via email (skipped)", len(allAlerts))
			for i, alert := range allAlerts {
				severity := "WARNING"
				if len(alert.Secrets) > 0 {
					severity = "CRITICAL"
				}
				log.Printf("   [%s] Alert %d: %s (Keyword: %s, Secrets: %d)",
					severity, i+1, alert.Collection.Name, alert.Keyword, len(alert.Secrets))
			}
		} else if !m.config.HasEmailConfigured() {
			log.Printf("⚠️  Email not configured - %d alert(s) detected but not sent", len(allAlerts))
			log.Println("📝 Alerts logged to file only. Configure email in config.yaml to receive alerts.")
			for i, alert := range allAlerts {
				severity := "WARNING"
				if len(alert.Secrets) > 0 {
					severity = "CRITICAL"
				}
				log.Printf("   [%s] Alert %d: %s (Keyword: %s, Secrets: %d)",
					severity, i+1, alert.Collection.Name, alert.Keyword, len(alert.Secrets))
			}
		} else {
			log.Printf("📧 Sending %d alert(s) via email (%d critical, %d warning)", len(allAlerts), criticalCount, warningCount)
			if err := m.notifier.SendAlert(allAlerts); err != nil {
				log.Printf("❌ Failed to send email notification: %v", err)
				return err
			}
			log.Println("✅ Alert email sent successfully")
		}

		// Detect duplicate secrets
		duplicates := reporter.DetectDuplicateSecrets(allAlerts)
		if len(duplicates) > 0 {
			log.Printf("⚠️  Found %d duplicate secret(s) across multiple collections!", len(duplicates))
		}

		// Generate reports in all formats
		log.Println("📄 Generating findings reports...")

		// JSON Report
		jsonPath, err := m.reporter.GenerateReport(allAlerts)
		if err != nil {
			log.Printf("⚠️  Failed to generate JSON report: %v", err)
		} else {
			log.Printf("✅ JSON report: %s", jsonPath)
		}

		// HTML Report
		htmlPath, err := m.reporter.GenerateHTMLReport(allAlerts, duplicates)
		if err != nil {
			log.Printf("⚠️  Failed to generate HTML report: %v", err)
		} else {
			log.Printf("✅ HTML report: %s", htmlPath)
		}

		// Markdown Report
		mdPath, err := m.reporter.GenerateMarkdownReport(allAlerts, duplicates)
		if err != nil {
			log.Printf("⚠️  Failed to generate Markdown report: %v", err)
		} else {
			log.Printf("✅ Markdown report: %s", mdPath)
		}
	} else {
		log.Println("✅ No new public collections found")
	}

	// Clean up old seen alerts (older than 30 days)
	m.cleanupSeenAlerts()

	log.Printf("✅ Check completed at %s\n", time.Now().Format("2006-01-02 03:04:05 PM"))
	return nil
}

// shouldIgnore checks if a collection should be ignored based on ignore keywords
func (m *Monitor) shouldIgnore(col postman.Collection) bool {
	name := strings.ToLower(col.Name)
	description := strings.ToLower(col.Description)

	for _, ignoreKeyword := range m.config.IgnoreKeywords {
		keyword := strings.ToLower(ignoreKeyword)
		if strings.Contains(name, keyword) || strings.Contains(description, keyword) {
			return true
		}
	}

	return false
}

// cleanupSeenAlerts removes old entries from the seen alerts map
func (m *Monitor) cleanupSeenAlerts() {
	cutoff := time.Now().Add(-30 * 24 * time.Hour)
	for key, timestamp := range m.seenAlerts {
		if timestamp.Before(cutoff) {
			delete(m.seenAlerts, key)
		}
	}
}