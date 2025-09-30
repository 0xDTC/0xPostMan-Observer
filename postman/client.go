package postman

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	baseURL = "https://api.getpostman.com"
)

// Client represents a Postman API client
type Client struct {
	apiKey     string
	httpClient *http.Client
	rateLimiter *time.Ticker
}

// Collection represents a Postman collection
type Collection struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	IsPublic    bool   `json:"isPublic"`
	Owner       string `json:"owner"`
	UID         string `json:"uid"`
	Fork        struct {
		Label string `json:"label"`
	} `json:"fork"`
}

// SearchResponse represents the response from search API
type SearchResponse struct {
	Data []struct {
		Score      float64 `json:"score"`
		Document   Collection `json:"document"`
		EntityType string `json:"entityType"`
	} `json:"data"`
	Meta struct {
		Total int `json:"total"`
	} `json:"meta"`
}

// DetailedCollection represents detailed collection info
type DetailedCollection struct {
	Collection struct {
		Info struct {
			Name        string `json:"name"`
			Description string `json:"description"`
			Schema      string `json:"schema"`
		} `json:"info"`
		Item []interface{} `json:"item"`
	} `json:"collection"`
}

// NewClient creates a new Postman API client
func NewClient(apiKey string) *Client {
	return &Client{
		apiKey: apiKey,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		rateLimiter: time.NewTicker(500 * time.Millisecond), // 2 requests per second max
	}
}

// GetCurrentUser retrieves the authenticated user's information
func (c *Client) GetCurrentUser() (string, error) {
	c.waitForRateLimit()

	endpoint := fmt.Sprintf("%s/me", baseURL)

	req, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("X-API-Key", c.apiKey)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("failed to get user info (status %d): %s", resp.StatusCode, string(body))
	}

	var result struct {
		User struct {
			ID       int    `json:"id"`
			Username string `json:"username"`
		} `json:"user"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("failed to decode response: %w", err)
	}

	return fmt.Sprintf("%d", result.User.ID), nil
}

// waitForRateLimit waits for rate limiter before making API call
func (c *Client) waitForRateLimit() {
	if c.rateLimiter != nil {
		<-c.rateLimiter.C
	}
}

// SearchPublicCollections searches for public collections by keyword
func (c *Client) SearchPublicCollections(keyword string) ([]Collection, error) {
	c.waitForRateLimit() // Rate limit API calls

	endpoint := fmt.Sprintf("%s/collections", baseURL)

	req, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("X-API-Key", c.apiKey)

	// Add query parameters for public collections
	q := req.URL.Query()
	q.Add("workspace", "public")
	req.URL.RawQuery = q.Encode()

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		Collections []Collection `json:"collections"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	// Filter collections by keyword
	var filtered []Collection
	keyword = strings.ToLower(keyword)

	for _, col := range result.Collections {
		if strings.Contains(strings.ToLower(col.Name), keyword) ||
		   strings.Contains(strings.ToLower(col.Description), keyword) {
			filtered = append(filtered, col)
		}
	}

	return filtered, nil
}

// SearchCollectionsByQuery searches collections accessible to the API key
// Note: Postman API limitation - cannot search ALL public collections
// This lists YOUR accessible collections and filters by keyword locally
func (c *Client) SearchCollectionsByQuery(query string) ([]Collection, error) {
	// Postman API does not provide a public search endpoint
	// We list all accessible collections and filter locally
	c.waitForRateLimit() // Rate limit API calls

	endpoint := fmt.Sprintf("%s/collections", baseURL)

	req, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("X-API-Key", c.apiKey)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		Collections []Collection `json:"collections"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	// Filter collections by keyword (case-insensitive)
	var filtered []Collection
	queryLower := strings.ToLower(query)

	for _, col := range result.Collections {
		nameLower := strings.ToLower(col.Name)
		descLower := strings.ToLower(col.Description)

		if strings.Contains(nameLower, queryLower) || strings.Contains(descLower, queryLower) {
			filtered = append(filtered, col)
		}
	}

	return filtered, nil
}

// GetCollectionDetails retrieves detailed information about a collection
func (c *Client) GetCollectionDetails(collectionID string) (*DetailedCollection, error) {
	c.waitForRateLimit() // Rate limit API calls

	endpoint := fmt.Sprintf("%s/collections/%s", baseURL, url.PathEscape(collectionID))

	req, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("X-API-Key", c.apiKey)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get collection details (status %d): %s", resp.StatusCode, string(body))
	}

	var details DetailedCollection
	if err := json.NewDecoder(resp.Body).Decode(&details); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &details, nil
}

// GetCollectionAsMap retrieves collection details as a raw map for scanning
func (c *Client) GetCollectionAsMap(collectionID string) (map[string]interface{}, error) {
	endpoint := fmt.Sprintf("%s/collections/%s", baseURL, url.PathEscape(collectionID))

	req, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("X-API-Key", c.apiKey)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get collection details (status %d): %s", resp.StatusCode, string(body))
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return result, nil
}