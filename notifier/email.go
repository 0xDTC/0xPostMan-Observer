package notifier

import (
	"bytes"
	"fmt"
	"net/smtp"
	"strings"
	"time"

	"github.com/yourusername/postman-observer/config"
	"github.com/yourusername/postman-observer/postman"
	"github.com/yourusername/postman-observer/scanner"
)

// EmailNotifier handles email notifications
type EmailNotifier struct {
	config config.EmailConfig
}

// Alert represents a security alert
type Alert struct {
	Keyword    string
	Collection postman.Collection
	Secrets    []scanner.SecretMatch
	IsPublic   bool // Explicitly marks if collection is publicly accessible
	Timestamp  time.Time
}

// NewEmailNotifier creates a new email notifier
func NewEmailNotifier(cfg config.EmailConfig) *EmailNotifier {
	return &EmailNotifier{
		config: cfg,
	}
}

// SendAlert sends an email alert for a discovered sensitive collection
func (n *EmailNotifier) SendAlert(alerts []Alert) error {
	if len(alerts) == 0 {
		return nil
	}

	// Count critical alerts (with secrets) vs warnings (public only)
	criticalCount := 0
	for _, alert := range alerts {
		if len(alert.Secrets) > 0 {
			criticalCount++
		}
	}

	var subject string
	if criticalCount > 0 {
		subject = fmt.Sprintf("🚨 CRITICAL: %d Public Collection(s) with Secrets Found", criticalCount)
	} else {
		subject = fmt.Sprintf("⚠️  WARNING: %d Public Collection(s) Found", len(alerts))
	}

	body := n.buildEmailBody(alerts)

	return n.sendEmail(subject, body)
}

// buildEmailBody creates the HTML email body
func (n *EmailNotifier) buildEmailBody(alerts []Alert) string {
	var buf bytes.Buffer

	buf.WriteString(`<!DOCTYPE html>
<html>
<head>
<style>
body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
.header { background-color: #e74c3c; color: white; padding: 20px; text-align: center; }
.alert { border-left: 4px solid #e74c3c; padding: 15px; margin: 20px 0; background-color: #f9f9f9; }
.collection-name { font-weight: bold; font-size: 1.2em; color: #2c3e50; }
.keyword { background-color: #fff3cd; padding: 2px 5px; border-radius: 3px; }
.timestamp { color: #7f8c8d; font-size: 0.9em; }
.footer { margin-top: 30px; padding-top: 20px; border-top: 1px solid #ddd; color: #7f8c8d; font-size: 0.9em; }
</style>
</head>
<body>
<div class="header">
<h1>🚨 Postman Observer Security Alert</h1>
<p>Sensitive collections detected on Postman Public Network</p>
</div>
<div style="padding: 20px;">
`)

	buf.WriteString(fmt.Sprintf("<p><strong>Alert Summary:</strong> %d sensitive collection(s) found at %s</p>",
		len(alerts), time.Now().Format("2006-01-02 15:04:05 MST")))

	for i, alert := range alerts {
		// Determine alert severity
		alertType := "⚠️  PUBLIC COLLECTION FOUND"
		alertColor := "#f39c12"
		if len(alert.Secrets) > 0 {
			alertType = "🚨 CRITICAL: PUBLIC COLLECTION WITH SECRETS"
			alertColor = "#e74c3c"
		}

		buf.WriteString(fmt.Sprintf(`<div class="alert" style="border-left-color: %s;">
<div style="background-color: %s; color: white; padding: 8px; margin-bottom: 10px; border-radius: 4px; font-weight: bold;">%s</div>
<div class="collection-name">%d. %s</div>
<p><strong>Matched Keyword:</strong> <span class="keyword">%s</span></p>
<p><strong>Collection ID:</strong> %s</p>
<p><strong>Description:</strong> %s</p>
<p><strong>Public Access:</strong> <span style="color: #e74c3c; font-weight: bold;">YES - Publicly Accessible</span></p>`,
			alertColor,
			alertColor,
			alertType,
			i+1,
			escapeHTML(alert.Collection.Name),
			escapeHTML(alert.Keyword),
			alert.Collection.ID,
			escapeHTML(alert.Collection.Description),
		))

		// Add secrets found section if any
		if len(alert.Secrets) > 0 {
			// Count verified secrets
			verifiedCount := 0
			for _, secret := range alert.Secrets {
				if secret.Verification != nil && secret.Verification.IsValid {
					verifiedCount++
				}
			}

			severity := "⚠️ SECRETS FOUND"
			bgColor := "#fff5f5"
			if verifiedCount > 0 {
				severity = fmt.Sprintf("🚨 CRITICAL - %d ACTIVE SECRET(S) VERIFIED", verifiedCount)
				bgColor = "#ffe0e0"
			}

			buf.WriteString(fmt.Sprintf(`
<p><strong style="color: #c0392b;">%s: %d</strong></p>
<div style="background-color: %s; border: 1px solid #e74c3c; padding: 10px; margin: 10px 0; border-radius: 5px;">
<ul style="margin: 5px 0; padding-left: 20px;">`, severity, len(alert.Secrets), bgColor))

			for _, secret := range alert.Secrets {
				verificationStatus := ""
				if secret.Verification != nil {
					statusColor := "#7f8c8d"
					if secret.Verification.IsValid {
						statusColor = "#c0392b"
					} else if secret.Verification.RateLimited {
						statusColor = "#f39c12"
					}
					verificationStatus = fmt.Sprintf(`<br/><small style="color: %s; font-weight: bold;">%s</small>`,
						statusColor, escapeHTML(secret.Verification.Message))
				}

				buf.WriteString(fmt.Sprintf(`
<li><strong>%s:</strong> <code style="background-color: #ffe6e6; padding: 2px 5px; border-radius: 3px;">%s</code><br/>
<small style="color: #7f8c8d;">Location: %s</small>%s</li>`,
					escapeHTML(secret.Type),
					escapeHTML(secret.Value),
					escapeHTML(secret.Location),
					verificationStatus,
				))
			}

			buf.WriteString(`
</ul>
</div>`)
		}

		buf.WriteString(fmt.Sprintf(`<p class="timestamp">Detected at: %s</p>
</div>`, alert.Timestamp.Format("2006-01-02 15:04:05 MST")))
	}

	buf.WriteString(`
<div class="footer">
<p>This is an automated alert from Postman Observer.</p>
<p>Please review these collections and take appropriate action if they contain sensitive information.</p>
</div>
</div>
</body>
</html>`)

	return buf.String()
}

// sendEmail sends an email using SMTP
func (n *EmailNotifier) sendEmail(subject, body string) error {
	auth := smtp.PlainAuth("", n.config.From, n.config.Password, n.config.SMTPHost)

	// Build email message
	msg := n.buildMessage(subject, body)

	addr := fmt.Sprintf("%s:%d", n.config.SMTPHost, n.config.SMTPPort)

	err := smtp.SendMail(
		addr,
		auth,
		n.config.From,
		n.config.To,
		[]byte(msg),
	)

	if err != nil {
		return fmt.Errorf("failed to send email: %w", err)
	}

	return nil
}

// buildMessage constructs the email message
func (n *EmailNotifier) buildMessage(subject, body string) string {
	var msg bytes.Buffer

	msg.WriteString(fmt.Sprintf("From: %s\r\n", n.config.From))
	msg.WriteString(fmt.Sprintf("To: %s\r\n", strings.Join(n.config.To, ",")))
	msg.WriteString(fmt.Sprintf("Subject: %s\r\n", subject))
	msg.WriteString("MIME-Version: 1.0\r\n")
	msg.WriteString("Content-Type: text/html; charset=UTF-8\r\n")
	msg.WriteString("\r\n")
	msg.WriteString(body)

	return msg.String()
}

// escapeHTML escapes HTML special characters
func escapeHTML(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, "\"", "&quot;")
	s = strings.ReplaceAll(s, "'", "&#39;")
	return s
}