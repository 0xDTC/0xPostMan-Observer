package postman

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// WebScraper handles scraping Postman's public website for collections
type WebScraper struct {
	httpClient  *http.Client
	rateLimiter *time.Ticker
}

// ScrapedCollection represents a collection found via web scraping
type ScrapedCollection struct {
	Name        string
	Description string
	URL         string
	Username    string
	Workspace   string
}

// NewWebScraper creates a new Postman web scraper
func NewWebScraper() *WebScraper {
	return &WebScraper{
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		rateLimiter: time.NewTicker(2 * time.Second), // More conservative for web scraping
	}
}

// SearchPublicCollections searches for public Postman collections using Postman's native search API
// This uses the same endpoint that the Postman web UI uses: /_api/ws/proxy
func (ws *WebScraper) SearchPublicCollections(keyword string) ([]ScrapedCollection, error) {
	ws.waitForRateLimit()

	// Postman's internal search API endpoint
	searchURL := "https://www.postman.com/_api/ws/proxy"

	// Build the request body matching Postman's native search
	requestBody := map[string]interface{}{
		"service": "search",
		"method":  "POST",
		"path":    "/search-all",
		"body": map[string]interface{}{
			"from":              0,
			"mergeEntities":     true,
			"nested":            false,
			"requestOrigin":     "dropdown",
			"nonNestedRequests": true,
			"queryText":         keyword,
			"size":              25, // Maximum allowed by Postman API
			"domain":            "all",
			"filter":            map[string]interface{}{},
			"queryIndices": []string{
				"collaboration.workspace",
				"runtime.collection",
				"adp.api",
				"runtime.request",
				"flow.flow",
			},
		},
	}

	bodyJSON, err := json.Marshal(requestBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request body: %w", err)
	}

	req, err := http.NewRequest("POST", searchURL, strings.NewReader(string(bodyJSON)))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers to mimic the browser request
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	req.Header.Set("Origin", "https://www.postman.com")
	req.Header.Set("Referer", "https://www.postman.com/search")
	req.Header.Set("sec-fetch-dest", "empty")
	req.Header.Set("sec-fetch-mode", "cors")
	req.Header.Set("sec-fetch-site", "same-origin")

	resp, err := ws.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("search request returned status %d: %s", resp.StatusCode, string(body))
	}

	// Parse the JSON response
	var searchResponse struct {
		Data []struct {
			Score    float64                `json:"score"`
			Document map[string]interface{} `json:"document"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&searchResponse); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	var collections []ScrapedCollection
	seenURLs := make(map[string]bool)

	// Parse search results
	for _, result := range searchResponse.Data {
		doc := result.Document

		// Check the documentType field to filter for collections
		docType, _ := doc["documentType"].(string)
		entityType, _ := doc["entityType"].(string)

		// Only process collections (not workspaces, requests, etc)
		if docType != "collection" && entityType != "collection" {
			continue
		}

		// Extract collection details
		name, _ := doc["name"].(string)
		description, _ := doc["description"].(string)
		collectionID, _ := doc["id"].(string)

		// Try to extract owner/workspace info from various possible fields
		var username, workspaceSlug string

		// Get publisher handle (username)
		if publisherHandle, ok := doc["publisherHandle"].(string); ok {
			username = publisherHandle
		}

		// Try to get workspace from the workspaces array
		if workspaces, ok := doc["workspaces"].([]interface{}); ok && len(workspaces) > 0 {
			if ws, ok := workspaces[0].(map[string]interface{}); ok {
				if slug, ok := ws["slug"].(string); ok {
					workspaceSlug = slug
				}
			}
		}

		// Build collection URL
		// Note: Use the full collection ID for deep scanning via API
		var collectionURL string
		if username != "" && workspaceSlug != "" && collectionID != "" {
			collectionURL = fmt.Sprintf("https://www.postman.com/%s/%s/collection/%s", username, workspaceSlug, collectionID)
		} else if collectionID != "" {
			// Fallback to just collection ID
			collectionURL = fmt.Sprintf("https://www.postman.com/collection/%s", collectionID)
		}

		// Skip if no URL or already seen
		if collectionURL == "" || seenURLs[collectionURL] {
			continue
		}
		seenURLs[collectionURL] = true

		if name == "" {
			name = "Untitled Collection"
		}

		collections = append(collections, ScrapedCollection{
			Name:        name,
			Description: description,
			URL:         collectionURL,
			Username:    username,
			Workspace:   workspaceSlug, // Use slug, not name, for URL construction
		})
	}

	return collections, nil
}

// GetCollectionID extracts collection ID from URL
func (ws *WebScraper) GetCollectionID(collectionURL string) string {
	// URL format: https://www.postman.com/{username}/{workspace}/collection/{id}
	// or: https://www.postman.com/{username}/{workspace}/overview
	parts := strings.Split(strings.Trim(collectionURL, "/"), "/")
	for i, part := range parts {
		if part == "collection" && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	// If no explicit collection ID, try to use the last part of URL
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return ""
}

// waitForRateLimit waits for rate limiter before making request
func (ws *WebScraper) waitForRateLimit() {
	if ws.rateLimiter != nil {
		<-ws.rateLimiter.C
	}
}
