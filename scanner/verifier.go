package scanner

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// VerificationResult represents the result of verifying a secret
type VerificationResult struct {
	IsValid     bool
	Message     string
	StatusCode  int
	VerifiedAt  time.Time
	RateLimited bool
}

// SecretVerifier handles verification of discovered secrets
type SecretVerifier struct {
	httpClient *http.Client
}

// NewSecretVerifier creates a new secret verifier
func NewSecretVerifier() *SecretVerifier {
	return &SecretVerifier{
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
			// Don't follow redirects for verification
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

// VerifySecret attempts to verify if a secret is active
func (v *SecretVerifier) VerifySecret(secret SecretMatch) *VerificationResult {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	switch secret.Type {
	case "AWS Access Key":
		return v.verifyAWS(ctx, secret.Value)
	case "GitHub Token", "GitHub OAuth":
		return v.verifyGitHub(ctx, secret.Value)
	case "Slack Token":
		return v.verifySlack(ctx, secret.Value)
	case "Google API Key":
		return v.verifyGoogleAPI(ctx, secret.Value)
	case "Stripe Secret Key", "Stripe Restricted Key":
		return v.verifyStripe(ctx, secret.Value)
	case "SendGrid API Key":
		return v.verifySendGrid(ctx, secret.Value)
	case "JWT Token":
		return v.verifyJWT(ctx, secret.Value)
	default:
		return &VerificationResult{
			IsValid:    false,
			Message:    "Verification not supported for this secret type",
			VerifiedAt: time.Now(),
		}
	}
}

// verifyAWS checks if AWS credentials are valid
func (v *SecretVerifier) verifyAWS(ctx context.Context, _ string) *VerificationResult {
	// AWS STS GetCallerIdentity - most basic AWS API call
	// Note: This requires the secret key as well, which we might not have
	// So we do a simpler check - try to use it and see if we get authentication errors

	req, err := http.NewRequestWithContext(ctx, "POST", "https://sts.amazonaws.com/",
		strings.NewReader("Action=GetCallerIdentity&Version=2011-06-15"))
	if err != nil {
		return &VerificationResult{IsValid: false, Message: "Failed to create request"}
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := v.httpClient.Do(req)
	if err != nil {
		return &VerificationResult{IsValid: false, Message: "Request failed"}
	}
	defer resp.Body.Close()

	// Note: Without the secret key, we can't truly verify
	// But we can detect if the format is recognized
	return &VerificationResult{
		IsValid:    false,
		Message:    "AWS verification requires both access key and secret key",
		StatusCode: resp.StatusCode,
		VerifiedAt: time.Now(),
	}
}

// verifyGitHub checks if a GitHub token is valid
func (v *SecretVerifier) verifyGitHub(ctx context.Context, token string) *VerificationResult {
	// Extract actual token value (remove any prefix like "Bearer ")
	token = strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(token, "Bearer"), "bearer"))

	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.github.com/user", nil)
	if err != nil {
		return &VerificationResult{IsValid: false, Message: "Failed to create request", VerifiedAt: time.Now()}
	}

	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("User-Agent", "PostmanObserver-SecurityScanner")

	resp, err := v.httpClient.Do(req)
	if err != nil {
		return &VerificationResult{IsValid: false, Message: "Request failed: " + err.Error(), VerifiedAt: time.Now()}
	}
	defer resp.Body.Close()

	result := &VerificationResult{
		StatusCode: resp.StatusCode,
		VerifiedAt: time.Now(),
	}

	switch resp.StatusCode {
	case 200:
		result.IsValid = true
		result.Message = "✅ ACTIVE - Token is valid and working"
	case 401:
		result.IsValid = false
		result.Message = "❌ INVALID - Token is not valid or expired"
	case 403:
		// Check if it's rate limiting or insufficient permissions
		body, _ := io.ReadAll(resp.Body)
		if strings.Contains(string(body), "rate limit") {
			result.RateLimited = true
			result.Message = "⏸️  RATE LIMITED - Cannot verify at this time"
		} else {
			result.IsValid = true
			result.Message = "⚠️  VALID but insufficient permissions"
		}
	default:
		result.Message = fmt.Sprintf("⚠️  Unexpected status: %d", resp.StatusCode)
	}

	return result
}

// verifySlack checks if a Slack token is valid
func (v *SecretVerifier) verifySlack(ctx context.Context, token string) *VerificationResult {
	token = strings.TrimSpace(token)

	req, err := http.NewRequestWithContext(ctx, "POST", "https://slack.com/api/auth.test", nil)
	if err != nil {
		return &VerificationResult{IsValid: false, Message: "Failed to create request", VerifiedAt: time.Now()}
	}

	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := v.httpClient.Do(req)
	if err != nil {
		return &VerificationResult{IsValid: false, Message: "Request failed", VerifiedAt: time.Now()}
	}
	defer resp.Body.Close()

	var slackResp struct {
		Ok    bool   `json:"ok"`
		Error string `json:"error"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&slackResp); err != nil {
		return &VerificationResult{IsValid: false, Message: "Invalid response", VerifiedAt: time.Now()}
	}

	result := &VerificationResult{
		StatusCode: resp.StatusCode,
		VerifiedAt: time.Now(),
		IsValid:    slackResp.Ok,
	}

	if slackResp.Ok {
		result.Message = "✅ ACTIVE - Token is valid"
	} else {
		result.Message = fmt.Sprintf("❌ INVALID - %s", slackResp.Error)
	}

	return result
}

// verifyGoogleAPI checks if a Google API key is valid
func (v *SecretVerifier) verifyGoogleAPI(ctx context.Context, apiKey string) *VerificationResult {
	apiKey = strings.TrimSpace(apiKey)

	// Use the simplest Google API endpoint - just check if key is recognized
	url := fmt.Sprintf("https://www.googleapis.com/youtube/v3/search?part=snippet&q=test&key=%s", apiKey)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return &VerificationResult{IsValid: false, Message: "Failed to create request", VerifiedAt: time.Now()}
	}

	resp, err := v.httpClient.Do(req)
	if err != nil {
		return &VerificationResult{IsValid: false, Message: "Request failed", VerifiedAt: time.Now()}
	}
	defer resp.Body.Close()

	result := &VerificationResult{
		StatusCode: resp.StatusCode,
		VerifiedAt: time.Now(),
	}

	switch resp.StatusCode {
	case 200:
		result.IsValid = true
		result.Message = "✅ ACTIVE - API key is valid"
	case 400:
		body, _ := io.ReadAll(resp.Body)
		if strings.Contains(string(body), "API key not valid") {
			result.Message = "❌ INVALID - API key not recognized"
		} else if strings.Contains(string(body), "disabled") {
			result.IsValid = true
			result.Message = "⚠️  VALID but API disabled for this key"
		} else {
			result.Message = "⚠️  Cannot verify - ambiguous response"
		}
	case 403:
		result.IsValid = true
		result.Message = "⚠️  VALID but quota exceeded or API not enabled"
	default:
		result.Message = fmt.Sprintf("⚠️  Unexpected status: %d", resp.StatusCode)
	}

	return result
}

// verifyStripe checks if a Stripe key is valid
func (v *SecretVerifier) verifyStripe(ctx context.Context, key string) *VerificationResult {
	key = strings.TrimSpace(key)

	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.stripe.com/v1/customers?limit=1", nil)
	if err != nil {
		return &VerificationResult{IsValid: false, Message: "Failed to create request", VerifiedAt: time.Now()}
	}

	req.SetBasicAuth(key, "")

	resp, err := v.httpClient.Do(req)
	if err != nil {
		return &VerificationResult{IsValid: false, Message: "Request failed", VerifiedAt: time.Now()}
	}
	defer resp.Body.Close()

	result := &VerificationResult{
		StatusCode: resp.StatusCode,
		VerifiedAt: time.Now(),
	}

	switch resp.StatusCode {
	case 200:
		result.IsValid = true
		result.Message = "✅ ACTIVE - Stripe key is valid"
	case 401:
		result.IsValid = false
		result.Message = "❌ INVALID - Key is not valid"
	default:
		result.Message = fmt.Sprintf("⚠️  Unexpected status: %d", resp.StatusCode)
	}

	return result
}

// verifySendGrid checks if a SendGrid API key is valid
func (v *SecretVerifier) verifySendGrid(ctx context.Context, apiKey string) *VerificationResult {
	apiKey = strings.TrimSpace(apiKey)

	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.sendgrid.com/v3/scopes", nil)
	if err != nil {
		return &VerificationResult{IsValid: false, Message: "Failed to create request", VerifiedAt: time.Now()}
	}

	req.Header.Set("Authorization", "Bearer "+apiKey)

	resp, err := v.httpClient.Do(req)
	if err != nil {
		return &VerificationResult{IsValid: false, Message: "Request failed", VerifiedAt: time.Now()}
	}
	defer resp.Body.Close()

	result := &VerificationResult{
		StatusCode: resp.StatusCode,
		VerifiedAt: time.Now(),
	}

	switch resp.StatusCode {
	case 200:
		result.IsValid = true
		result.Message = "✅ ACTIVE - SendGrid API key is valid"
	case 401, 403:
		result.IsValid = false
		result.Message = "❌ INVALID - API key not valid"
	default:
		result.Message = fmt.Sprintf("⚠️  Unexpected status: %d", resp.StatusCode)
	}

	return result
}

// verifyJWT analyzes JWT structure (doesn't validate signature)
func (v *SecretVerifier) verifyJWT(_ context.Context, token string) *VerificationResult {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return &VerificationResult{
			IsValid:    false,
			Message:    "❌ INVALID - Malformed JWT",
			VerifiedAt: time.Now(),
		}
	}

	// Try to decode the payload (base64url)
	payload := parts[1]
	// Add padding if needed
	if m := len(payload) % 4; m != 0 {
		payload += strings.Repeat("=", 4-m)
	}

	decoded, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		// Try standard base64
		decoded, err = base64.StdEncoding.DecodeString(payload)
		if err != nil {
			return &VerificationResult{
				IsValid:    false,
				Message:    "❌ Cannot decode JWT payload",
				VerifiedAt: time.Now(),
			}
		}
	}

	// Parse JSON
	var claims map[string]interface{}
	if err := json.Unmarshal(decoded, &claims); err != nil {
		return &VerificationResult{
			IsValid:    false,
			Message:    "❌ Invalid JWT payload",
			VerifiedAt: time.Now(),
		}
	}

	// Check expiration
	if exp, ok := claims["exp"].(float64); ok {
		expTime := time.Unix(int64(exp), 0)
		if time.Now().After(expTime) {
			return &VerificationResult{
				IsValid:    false,
				Message:    fmt.Sprintf("⏰ EXPIRED - Token expired at %s", expTime.Format("2006-01-02 15:04")),
				VerifiedAt: time.Now(),
			}
		}
		return &VerificationResult{
			IsValid:    true,
			Message:    fmt.Sprintf("⚠️  VALID structure - Expires at %s (signature not verified)", expTime.Format("2006-01-02 15:04")),
			VerifiedAt: time.Now(),
		}
	}

	return &VerificationResult{
		IsValid:    true,
		Message:    "⚠️  VALID structure (no expiration, signature not verified)",
		VerifiedAt: time.Now(),
	}
}
