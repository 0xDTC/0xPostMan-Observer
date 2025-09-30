# 🔍 0xPostman-Observer

**Automated security monitoring tool for detecting exposed Postman collections with sensitive credentials**

Postman Observer is a Go-based security tool that continuously monitors Postman's public collections for your organization's keywords, detects exposed secrets (API keys, tokens, credentials), and generates comprehensive security reports with duplicate secret detection across multiple collections.

[![Go Version](https://img.shields.io/badge/Go-1.23+-00ADD8?style=flat&logo=go)](https://golang.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

---

## 📋 Table of Contents

- [Features](#-features)
- [Architecture](#-architecture)
  - [System Overview](#system-overview)
  - [Data Flow Diagram](#data-flow-diagram)
  - [Component Diagram](#component-diagram)
- [Installation](#-installation)
  - [Prerequisites](#prerequisites)
  - [Build from Source](#build-from-source)
- [Configuration](#-configuration)
  - [Environment Variables (.env)](#environment-variables-env)
  - [YAML Configuration](#yaml-configuration)
- [Usage](#-usage)
  - [Quick Start](#quick-start)
  - [Command Line Options](#command-line-options)
  - [Running as Cron Job](#running-as-cron-job)
- [Features in Detail](#-features-in-detail)
  - [Secret Detection](#secret-detection)
  - [Secret Verification](#secret-verification)
  - [Duplicate Detection](#duplicate-detection)
  - [Report Generation](#report-generation)
  - [User Filtering](#user-filtering)
  - [Rate Limiting](#rate-limiting)
- [Email Alerts](#-email-alerts)
  - [Supported Providers](#supported-providers)
  - [Email Configuration](#email-configuration)
- [Output & Reports](#-output--reports)
  - [Log Files](#log-files)
  - [JSON Reports](#json-reports)
  - [HTML Reports](#html-reports)
  - [Markdown Reports](#markdown-reports)
- [Troubleshooting](#-troubleshooting)
- [API Limitations](#-api-limitations)
- [Security Considerations](#-security-considerations)
- [Contributing](#-contributing)
- [License](#-license)

---

## ✨ Features

- 🔎 **Keyword-Based Monitoring** - Search for your organization's keywords in public Postman collections
- 🚨 **Secret Detection** - Identify 20+ types of exposed credentials (AWS keys, GitHub tokens, JWT, API keys, etc.)
- ✅ **Active Verification** - Test if detected secrets are still valid (GitHub, Slack, Stripe, etc.)
- 🔄 **Duplicate Detection** - Find identical secrets across multiple collections
- 👤 **User Filtering** - Automatically excludes your own collections from monitoring
- 📊 **Multiple Report Formats** - Generate JSON, HTML (dark theme), and Markdown reports
- 📧 **Email Alerts** - Optional email notifications (Gmail, AWS SES, SendGrid, etc.)
- ⏱️ **Rate Limiting** - Built-in API throttling to respect Postman's rate limits
- 🔗 **Clickable Links** - Direct links to collections in all reports
- 🌙 **Dark Theme Reports** - Professional GitHub-style dark theme for HTML reports
- 📝 **Detailed Logging** - Timestamped log files for every run
- ⚙️ **Flexible Configuration** - Support for .env, YAML, or environment variables

---

## 🏗 Architecture

### System Overview

```mermaid
graph TB
    A[Postman Observer CLI] --> B[Configuration Loader]
    B --> C[Monitor Orchestrator]
    C --> D[Postman API Client]
    C --> E[Secret Scanner]
    C --> F[Secret Verifier]
    C --> G[Report Generator]
    C --> H[Email Notifier]

    D --> I[Postman API]
    I --> D

    F --> J[External APIs]
    J --> F

    G --> K[JSON Reports]
    G --> L[HTML Reports]
    G --> M[Markdown Reports]

    H --> N[SMTP Server]

    style A fill:#e74c3c,color:#fff
    style C fill:#3498db,color:#fff
    style G fill:#f39c12,color:#fff
    style H fill:#27ae60,color:#fff
```

### Data Flow Diagram

```mermaid
flowchart LR
    Start([Start]) --> LoadConfig[Load Configuration]
    LoadConfig --> GetUser[Get Current User ID]
    GetUser --> SearchKeywords[Search for Keywords]

    SearchKeywords --> CheckOwner{Owner = Current User?}
    CheckOwner -->|Yes| Skip[Skip Collection]
    CheckOwner -->|No| CheckIgnore{Match Ignore Keywords?}

    CheckIgnore -->|Yes| Skip
    CheckIgnore -->|No| FetchDetails[Fetch Collection Details]

    FetchDetails --> ScanSecrets[Scan for Secrets]
    ScanSecrets --> FoundSecrets{Secrets Found?}

    FoundSecrets -->|Yes| VerifySecrets[Verify Secrets]
    FoundSecrets -->|No| CreateAlert[Create Alert]

    VerifySecrets --> CheckDuplicates[Check Duplicates]
    CheckDuplicates --> CreateAlert

    CreateAlert --> GenerateReports[Generate Reports]
    GenerateReports --> SendEmail{Email Configured?}

    SendEmail -->|Yes| SendNotification[Send Email Alert]
    SendEmail -->|No| LogOnly[Log Only Mode]

    SendNotification --> End([End])
    LogOnly --> End
    Skip --> SearchKeywords

    style Start fill:#27ae60,color:#fff
    style End fill:#e74c3c,color:#fff
    style GenerateReports fill:#f39c12,color:#fff
    style VerifySecrets fill:#9b59b6,color:#fff
```

### Component Diagram

```mermaid
classDiagram
    class Monitor {
        +config Config
        +client PostmanClient
        +reporter Reporter
        +scanner SecretScanner
        +verifier SecretVerifier
        +currentUserID string
        +Start()
        +RunOnce()
        -runCheck()
        -shouldIgnore()
    }

    class PostmanClient {
        +apiKey string
        +rateLimiter Ticker
        +GetCurrentUser() string
        +SearchCollectionsByQuery() []Collection
        +GetCollectionDetails() DetailedCollection
        -waitForRateLimit()
    }

    class SecretScanner {
        +patterns []SecretPattern
        +ScanCollection() []SecretMatch
        -scanValue()
    }

    class SecretVerifier {
        +httpClient Client
        +VerifySecret() VerificationResult
        -verifyGitHub()
        -verifySlack()
        -verifyJWT()
    }

    class Reporter {
        +reportsDir string
        +GenerateReport() string
        +GenerateHTMLReport() string
        +GenerateMarkdownReport() string
        +DetectDuplicateSecrets() map
    }

    class EmailNotifier {
        +config EmailConfig
        +SendAlert() error
        -buildEmailBody() string
        -sendEmail()
    }

    Monitor --> PostmanClient
    Monitor --> SecretScanner
    Monitor --> SecretVerifier
    Monitor --> Reporter
    Monitor --> EmailNotifier

    PostmanClient --> "Postman API"
    SecretVerifier --> "External APIs"
    Reporter --> "Files"
    EmailNotifier --> "SMTP Server"
```

---

## 🚀 Installation

### Prerequisites

- **Go 1.23+** - [Download Go](https://golang.org/dl/)
- **Postman API Key** - [Generate from Postman Settings](https://postman.com/settings/me/api-keys)
- **SMTP Server** (Optional) - For email alerts

### Build from Source

```bash
# Clone the repository
git clone https://github.com/yourusername/postman-observer.git
cd postman-observer

# Build the binary
go build -o postman-observer .

# Verify installation
./postman-observer --help
```

---

## ⚙️ Configuration

### Environment Variables (.env)

Create a `.env` file in the project root:

```bash
# Postman API Configuration
POSTMAN_API_KEY=PMAK-your-api-key-here

# Email Configuration (Optional - leave empty for logs-only mode)
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_FROM=your-email@gmail.com
SMTP_PASSWORD=your-app-password
SMTP_TO=security@example.com,admin@example.com

# Monitoring Configuration
MONITOR_INTERVAL_HOURS=24
DEEP_SCAN_ENABLED=true
VERIFY_SECRETS=true

# Keywords to Monitor (comma-separated)
MONITOR_KEYWORDS=mycompany,api-production,internal-api,confidential

# Keywords to Ignore (comma-separated)
IGNORE_KEYWORDS=example,demo,test,sample,tutorial
```

**Quick Setup:**

```bash
# Copy template
cp .env.example .env

# Edit with your credentials
nano .env
```

### YAML Configuration

Alternatively, create `config.yaml`:

```yaml
postman_api_key: "PMAK-your-api-key-here"

email:
  smtp_host: "smtp.gmail.com"
  smtp_port: 587
  from: "your-email@gmail.com"
  password: "your-app-password"
  to:
    - "security@example.com"
    - "admin@example.com"

monitoring:
  interval_hours: 24

monitor_keywords:
  - mycompany
  - api-production
  - internal-api
  - confidential

ignore_keywords:
  - example
  - demo
  - test
  - sample
  - tutorial

deep_scan:
  enabled: true
  verify_secrets: true
```

---

## 📖 Usage

### Quick Start

```bash
# Using .env file (recommended)
./postman-observer -use-env -once

# Using YAML config
./postman-observer -config config.yaml -once

# Continuous monitoring (runs every 24 hours)
./postman-observer -use-env
```

### Command Line Options

```
Usage of ./postman-observer:
  -config string
        Path to configuration file (default "config.yaml")
  -dry-run
        Search and scan only, don't send emails
  -env string
        Path to .env file (default ".env")
  -log-dir string
        Directory to store log files (default "logs")
  -once
        Run once and exit (for testing or cron jobs)
  -use-env
        Use environment variables instead of config file
```

### Running as Cron Job

Add to crontab for daily monitoring at 2 AM:

```bash
# Edit crontab
crontab -e

# Add this line
0 2 * * * cd /path/to/postman-observer && ./postman-observer -use-env -once >> cron.log 2>&1
```

---

## 🔍 Features in Detail

### Secret Detection

Detects **20+ types** of secrets using regex patterns:

| Secret Type | Example | Detection Method |
|-------------|---------|------------------|
| AWS Access Key | `AKIA...` | Pattern matching |
| AWS Secret Key | `wJalrXUtnFEMI/K7MDENG/...` | Pattern matching |
| GitHub Token | `ghp_...`, `gho_...`, `ghs_...` | Pattern + verification |
| JWT Token | `eyJhbGciOiJIUzI1NiIsInR5cCI6...` | Decode + validation |
| Bearer Token | `Bearer eyJhbGciOi...` | Pattern matching |
| API Keys | `api_key=...`, `apikey=...` | Pattern matching |
| Slack Token | `xoxb-...`, `xoxp-...` | Pattern + verification |
| Google API Key | `AIza...` | Pattern + verification |
| Stripe Key | `sk_live_...`, `pk_live_...` | Pattern + verification |
| SendGrid Key | `SG....` | Pattern + verification |
| Twilio Auth Token | `AC...` / `SK...` | Pattern matching |
| Heroku API Key | `UUID format` | Pattern matching |
| Private Keys | `-----BEGIN PRIVATE KEY-----` | Pattern matching |
| SSH Keys | `-----BEGIN OPENSSH PRIVATE KEY-----` | Pattern matching |
| Database URLs | `mongodb://`, `postgres://` | Pattern matching |
| OAuth Secrets | `client_secret=...` | Pattern matching |
| Basic Auth | `Authorization: Basic ...` | Pattern matching |

### Secret Verification

Actively tests if secrets are valid:

```mermaid
sequenceDiagram
    participant Scanner
    participant Verifier
    participant GitHub
    participant Slack
    participant Stripe

    Scanner->>Verifier: Found GitHub Token
    Verifier->>GitHub: GET /user
    GitHub-->>Verifier: 200 OK (Valid) / 401 (Invalid)

    Scanner->>Verifier: Found Slack Token
    Verifier->>Slack: POST /api/auth.test
    Slack-->>Verifier: Valid / Invalid

    Scanner->>Verifier: Found Stripe Key
    Verifier->>Stripe: GET /v1/charges
    Stripe-->>Verifier: Valid / Invalid

    Verifier-->>Scanner: Verification Results
```

**Supported Verification:**
- ✅ GitHub Personal Access Tokens
- ✅ Slack Bot/User Tokens
- ✅ Google API Keys
- ✅ Stripe API Keys
- ✅ SendGrid API Keys
- ✅ JWT Token Validation (decode + expiry check)

### Duplicate Detection

Finds identical secrets across multiple collections:

```bash
⚠️  Found 127 duplicate secret(s) across multiple collections!

Example:
Secret: eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtp...
Found in:
  - Test-Online
  - Testing Platform
  - API Testing Collection
```

### Report Generation

Generates **three report formats** simultaneously:

#### 1. **JSON Report** (`findings_YYYY-MM-DD_HH-MM-SSPM.json`)
- Machine-readable format
- Complete data structure
- Easy to parse with tools

#### 2. **HTML Report** (`findings_YYYY-MM-DD_HH-MM-SSPM.html`)
- Dark theme (GitHub-style)
- Interactive tables
- Clickable links
- Shows ALL secrets (no truncation)
- Responsive design

#### 3. **Markdown Report** (`findings_YYYY-MM-DD_HH-MM-SSPM.md`)
- Human-readable format
- Collapsible secret sections
- Duplicate detection table
- Easy to view in GitHub/GitLab

### User Filtering

**Automatically excludes your own collections:**

```mermaid
graph LR
    A[Search Collections] --> B{Check Owner}
    B -->|Owner = Your ID| C[Skip Collection]
    B -->|Owner ≠ Your ID| D[Process Collection]
    C --> A
    D --> E[Scan for Secrets]
    E --> F[Generate Report]
```

**How it works:**
1. Tool calls Postman API `/me` to get your user ID
2. Compares collection owner with your ID
3. Skips any collection you own
4. Only monitors **truly public** collections from **other users**

**Example Log:**
```
✅ Authenticated as user ID: 22339642 (filtering out your collections)
⏭️  Skipping your own collection: My Private API (Owner: 22339642)
```

### Rate Limiting

Built-in protection against API rate limits:

- **Default Rate**: 2 requests per second (500ms delay)
- **Applied to**: All Postman API calls
- **Prevents**: HTTP 429 (Too Many Requests) errors
- **Automatic**: No configuration needed

---

## 📧 Email Alerts

### Supported Providers

| Provider | SMTP Host | Port | Setup Guide |
|----------|-----------|------|-------------|
| Gmail | `smtp.gmail.com` | 587 | [Enable App Password](https://myaccount.google.com/apppasswords) |
| AWS SES | `email-smtp.us-east-1.amazonaws.com` | 587 | [AWS SES Setup](https://docs.aws.amazon.com/ses/latest/dg/smtp-credentials.html) |
| SendGrid | `smtp.sendgrid.net` | 587 | [SendGrid API Key](https://app.sendgrid.com/settings/api_keys) |
| Mailgun | `smtp.mailgun.org` | 587 | [Mailgun SMTP](https://documentation.mailgun.com/en/latest/user_manual.html#smtp) |
| Outlook | `smtp-mail.outlook.com` | 587 | Use Microsoft Account |

### Email Configuration

**Gmail Example:**

1. Go to [Google App Passwords](https://myaccount.google.com/apppasswords)
2. Generate an app password
3. Add to `.env`:

```bash
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_FROM=your-email@gmail.com
SMTP_PASSWORD=abcd efgh ijkl mnop  # App password (spaces allowed)
SMTP_TO=security@company.com,alerts@company.com
```

**Email is Optional:**
- Leave email fields empty to run in **logs-only mode**
- All findings still saved to reports
- No email notifications sent

---

## 📊 Output & Reports

### Log Files

**Format:** `observer_YYYY-MM-DD_HH-MM-SSPM.log`

**Location:** `logs/`

**Example:**
```
2025-09-30 07:20:07 ✅ Authenticated as user ID: 22339642
2025-09-30 07:20:07 🔎 Searching for keyword: mycompany
2025-09-30 07:20:08    Found 3 collections
2025-09-30 07:20:08    🔬 Deep scanning collection for secrets: API-Production
2025-09-30 07:20:09    ⚠️  Found 15 secret(s) in collection!
2025-09-30 07:20:09    🚨 CRITICAL: PUBLIC collection with 15 EXPOSED SECRET(S)
```

### JSON Reports

**Format:** Complete structured data

```json
{
  "report_time": "2025-09-30 07:20:07 PM",
  "total_findings": 4,
  "critical_count": 3,
  "warning_count": 1,
  "total_secrets": 127,
  "findings": [
    {
      "observed_link": "https://www.postman.com/collection/abc123",
      "collection_url": "https://www.postman.com/abc123",
      "collection_api_url": "https://api.getpostman.com/collections/abc123",
      "collection_id": "abc123",
      "name": "Production API",
      "owner": "12345678",
      "keyword": "mycompany",
      "suggested_ignore_keyword": "Production API",
      "secret_count": 15,
      "secrets": [
        {
          "type": "GitHub Token",
          "value": "ghp_abc123def456...",
          "location": "Request Headers",
          "is_verified": true,
          "is_valid": false,
          "verify_message": "❌ INVALID - Token revoked"
        }
      ]
    }
  ]
}
```

### HTML Reports

**Features:**
- ✅ Dark theme (GitHub-style)
- ✅ Responsive design
- ✅ All secrets visible (no truncation)
- ✅ Clickable links
- ✅ Duplicate warnings
- ✅ Verification status badges
- ✅ Executive summary cards

### Markdown Reports

**Features:**
- ✅ GitHub/GitLab compatible
- ✅ Collapsible secret sections
- ✅ Table of contents
- ✅ Duplicate detection table
- ✅ Quick links section

---

## 🔧 Troubleshooting

### Common Issues

**1. Authentication Failed**
```
Error: failed to get user info (status 401)
```
**Solution:** Verify your Postman API key is correct

---

**2. No Collections Found**
```
Found 0 collections
```
**Possible Reasons:**
- Keywords don't match any public collections
- All matching collections are your own (filtered out)
- Postman API rate limiting

**Solution:** Try broader keywords or check Postman API status

---

**3. Email Not Sending**
```
Failed to send email notification: dial tcp: i/o timeout
```
**Solution:**
- Verify SMTP credentials
- Check firewall/network settings
- Use app password for Gmail (not regular password)

---

**4. Rate Limiting**
```
API request failed with status 429: Too Many Requests
```
**Solution:** Tool has built-in rate limiting. If still occurring, reduce keyword count.

---

## ⚠️ API Limitations

**Postman API Restrictions:**

1. **Cannot Search ALL Public Collections**
   - API only returns collections you have access to
   - Includes: Your collections, team collections, and publicly shared collections you've viewed

2. **Workaround:**
   - Tool manually discovers collections by keywords
   - Filters out your own collections
   - Monitors truly public collections from other users

3. **Rate Limits:**
   - Postman enforces rate limits on API calls
   - Tool includes automatic throttling (500ms between calls)

---

## 🔐 Security Considerations

### Best Practices

1. **API Key Storage**
   - Never commit `.env` file to git
   - Use environment variables in CI/CD
   - Rotate API keys regularly

2. **Report Storage**
   - Reports contain **unmasked secrets**
   - Store securely with restricted access
   - Delete old reports regularly
   - Consider encrypting report directory

3. **Email Security**
   - Use app passwords (not regular passwords)
   - Encrypt email connections (TLS)
   - Limit email recipient list
   - Consider using company email servers

4. **Secret Handling**
   - Reports show full secret values for investigation
   - Revoke exposed secrets immediately
   - Notify affected teams
   - Update security policies

### Disclaimer

This tool is for **defensive security monitoring only**. Do not use it for:
- ❌ Credential harvesting
- ❌ Bulk secret collection
- ❌ Unauthorized access attempts
- ❌ Malicious purposes

**Use responsibly and ethically.**

---

## 🤝 Contributing

Contributions are welcome! Please follow these guidelines:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.