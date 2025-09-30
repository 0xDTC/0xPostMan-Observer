package reporter

import (
	"fmt"
	gohtml "html"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/yourusername/postman-observer/notifier"
)

// GenerateHTMLReport creates an HTML table-formatted report
func (r *Reporter) GenerateHTMLReport(alerts []notifier.Alert, duplicates map[string][]string) (string, error) {
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

	// Generate HTML
	var html strings.Builder

	html.WriteString(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Postman Observer Report - ` + time.Now().Format("2006-01-02 03:04 PM") + `</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #0d1117;
            padding: 20px;
            line-height: 1.6;
            color: #c9d1d9;
        }
        .container {
            max-width: 1600px;
            margin: 0 auto;
            background: #161b22;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 8px 24px rgba(0,0,0,0.5);
            border: 1px solid #30363d;
        }
        h1 {
            color: #f0f6fc;
            border-bottom: 3px solid #e74c3c;
            padding-bottom: 15px;
            margin-bottom: 25px;
        }
        .summary {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-bottom: 30px;
        }
        .summary-card {
            padding: 20px;
            border-radius: 6px;
            color: white;
        }
        .summary-card h3 { font-size: 14px; opacity: 0.9; margin-bottom: 8px; }
        .summary-card .number { font-size: 32px; font-weight: bold; }
        .critical { background: linear-gradient(135deg, #e74c3c 0%, #c0392b 100%); }
        .warning { background: linear-gradient(135deg, #f39c12 0%, #e67e22 100%); }
        .info { background: linear-gradient(135deg, #3498db 0%, #2980b9 100%); }
        .total { background: linear-gradient(135deg, #9b59b6 0%, #8e44ad 100%); }

        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
            font-size: 14px;
            background: #0d1117;
            border: 1px solid #30363d;
        }
        th {
            background: #21262d;
            color: #f0f6fc;
            padding: 12px;
            text-align: left;
            font-weight: 600;
            position: sticky;
            top: 0;
            border-bottom: 2px solid #30363d;
        }
        td {
            padding: 10px 12px;
            border-bottom: 1px solid #30363d;
            vertical-align: top;
            color: #c9d1d9;
        }
        tr:hover { background: #1c2128; }

        .badge {
            display: inline-block;
            padding: 4px 10px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: 600;
            margin-right: 5px;
        }
        .badge-critical { background: #e74c3c; color: white; }
        .badge-warning { background: #f39c12; color: white; }
        .badge-success { background: #27ae60; color: white; }
        .badge-danger { background: #c0392b; color: white; }
        .badge-info { background: #3498db; color: white; }

        .collection-name {
            font-weight: 600;
            color: #58a6ff;
            font-size: 15px;
        }
        .secret-list {
            list-style: none;
            margin: 5px 0;
        }
        .secret-item {
            background: #1c1f26;
            border-left: 3px solid #e74c3c;
            padding: 8px 10px;
            margin: 5px 0;
            border-radius: 3px;
            font-size: 13px;
            border: 1px solid #30363d;
        }
        .secret-type {
            font-weight: 600;
            color: #ff7b72;
        }
        .secret-value {
            font-family: 'Courier New', monospace;
            background: #0d1117;
            padding: 4px 8px;
            border-radius: 3px;
            color: #79c0ff;
            word-break: break-all;
            border: 1px solid #30363d;
            display: block;
            margin: 4px 0;
        }
        .duplicate-warning {
            background: #332b00;
            border-left: 4px solid #f39c12;
            padding: 10px 15px;
            margin: 8px 0;
            border-radius: 4px;
            border: 1px solid #4b3900;
            color: #f2cc60;
        }
        .links a {
            color: #58a6ff;
            text-decoration: none;
            margin-right: 12px;
            font-size: 13px;
        }
        .links a:hover {
            text-decoration: underline;
            color: #79c0ff;
        }
        .owner-info {
            color: #8b949e;
            font-size: 13px;
            margin-top: 4px;
        }
        .no-secrets {
            color: #3fb950;
            font-style: italic;
        }
        footer {
            margin-top: 40px;
            padding-top: 20px;
            border-top: 2px solid #30363d;
            text-align: center;
            color: #8b949e;
            font-size: 13px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔍 Postman Observer Security Report</h1>
        <p style="color: #8b949e; margin-bottom: 25px;">Generated: ` + time.Now().Format("Monday, January 2, 2006 at 03:04:05 PM MST") + `</p>

        <div class="summary">
            <div class="summary-card critical">
                <h3>CRITICAL FINDINGS</h3>
                <div class="number">` + fmt.Sprintf("%d", criticalCount) + `</div>
                <p style="font-size: 13px;">Collections with secrets</p>
            </div>
            <div class="summary-card warning">
                <h3>WARNING</h3>
                <div class="number">` + fmt.Sprintf("%d", warningCount) + `</div>
                <p style="font-size: 13px;">Public collections</p>
            </div>
            <div class="summary-card total">
                <h3>TOTAL SECRETS</h3>
                <div class="number">` + fmt.Sprintf("%d", totalSecrets) + `</div>
                <p style="font-size: 13px;">Exposed credentials</p>
            </div>
            <div class="summary-card info">
                <h3>TOTAL FINDINGS</h3>
                <div class="number">` + fmt.Sprintf("%d", len(alerts)) + `</div>
                <p style="font-size: 13px;">Collections analyzed</p>
            </div>
        </div>

        <table>
            <thead>
                <tr>
                    <th style="width: 5%;">#</th>
                    <th style="width: 25%;">Collection</th>
                    <th style="width: 15%;">Owner</th>
                    <th style="width: 10%;">Status</th>
                    <th style="width: 10%;">Secrets</th>
                    <th style="width: 35%;">Details</th>
                </tr>
            </thead>
            <tbody>
`)

	// Add findings
	for i, alert := range alerts {
		severity := "WARNING"
		severityBadge := "badge-warning"
		if len(alert.Secrets) > 0 {
			severity = "CRITICAL"
			severityBadge = "badge-critical"
		}

		owner := "Unknown"
		if alert.Collection.Owner != "" {
			owner = gohtml.EscapeString(alert.Collection.Owner)
		}

		html.WriteString(fmt.Sprintf(`
                <tr>
                    <td><strong>%d</strong></td>
                    <td>
                        <div class="collection-name">%s</div>
                        <div class="owner-info">ID: %s</div>
                        <div class="owner-info">Keyword: <strong>%s</strong></div>
                        <div class="owner-info">Suggested Ignore: <code>%s</code></div>
                        <div class="links" style="margin-top: 8px;">
                            <a href="%s" target="_blank">🔗 View</a>
                            <a href="%s" target="_blank">📋 Web</a>
                            <a href="%s" target="_blank">🔌 API</a>
                        </div>
                    </td>
                    <td>%s</td>
                    <td><span class="badge %s">%s</span></td>
                    <td><span class="badge badge-danger">%d</span></td>
                    <td>`,
			i+1,
			gohtml.EscapeString(alert.Collection.Name),
			gohtml.EscapeString(alert.Collection.ID),
			gohtml.EscapeString(alert.Keyword),
			gohtml.EscapeString(alert.Collection.Name),
			fmt.Sprintf("https://www.postman.com/collection/%s", alert.Collection.ID),
			fmt.Sprintf("https://www.postman.com/%s", alert.Collection.ID),
			fmt.Sprintf("https://api.getpostman.com/collections/%s", alert.Collection.ID),
			owner,
			severityBadge,
			severity,
			len(alert.Secrets),
		))

		// Add secrets
		if len(alert.Secrets) > 0 {
			html.WriteString(`<ul class="secret-list">`)

			// Show ALL secrets (no limit)
			for j := 0; j < len(alert.Secrets); j++ {
				secret := alert.Secrets[j]
				verificationIcon := ""
				if secret.Verification != nil {
					if secret.Verification.IsValid {
						verificationIcon = " ✅ <strong>ACTIVE</strong>"
					} else {
						verificationIcon = " ❌ Invalid"
					}
				}

				// Check if duplicate
				duplicateMsg := ""
				if dups, exists := duplicates[secret.RawValue]; exists && len(dups) > 1 {
					duplicateMsg = fmt.Sprintf(`<div class="duplicate-warning">⚠️ <strong>Duplicate secret</strong> found in %d collections</div>`, len(dups))
				}

				html.WriteString(fmt.Sprintf(`
                            <li class="secret-item">
                                <span class="secret-type">%s</span>%s<br>
                                <span class="secret-value">%s</span><br>
                                <small style="color: #7f8c8d;">Location: %s</small>
                                %s
                            </li>`,
					gohtml.EscapeString(secret.Type),
					verificationIcon,
					gohtml.EscapeString(secret.RawValue),
					gohtml.EscapeString(secret.Location),
					duplicateMsg,
				))
			}

			html.WriteString(`</ul>`)
		} else {
			html.WriteString(`<p class="no-secrets">No secrets detected</p>`)
		}

		html.WriteString(`
                    </td>
                </tr>`)
	}

	html.WriteString(`
            </tbody>
        </table>

        <footer>
            <p><strong>🤖 Generated by Postman Observer</strong></p>
            <p style="margin-top: 8px;">For security purposes, store this report securely and limit access to authorized personnel only.</p>
        </footer>
    </div>
</body>
</html>`)

	// Write to file
	timestamp := time.Now().Format("2006-01-02_03-04-05PM")
	filename := fmt.Sprintf("findings_%s.html", timestamp)
	filepath := filepath.Join(r.reportsDir, filename)

	if err := os.WriteFile(filepath, []byte(html.String()), 0644); err != nil {
		return "", fmt.Errorf("failed to write HTML report: %w", err)
	}

	return filepath, nil
}