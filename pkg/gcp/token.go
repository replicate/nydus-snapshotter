package gcp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/containerd/containerd/log"
)

var (
	enabled    = false
	password   string
	passwordMu sync.Mutex
)

type token struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	TokenType   string `json:"token_type"`
}

func InitTokenRefresher(ctx context.Context) {
	enabled = true
	go runTokenRefreshLoop(ctx)
}

func IsEnabled() bool {
	return enabled
}

func HostIsGCP(host string) bool {
	switch {
	case host == "container.cloud.google.com":
		return true
	case host == "gcr.io":
		return true
	case strings.HasSuffix(host, ".gcr.io"):
		return true
	case strings.HasSuffix(host, ".pkg.dev"):
		return true
	default:
		return false
	}
}

func GetPassword() string {
	passwordMu.Lock()
	defer passwordMu.Unlock()
	return password
}

func runTokenRefreshLoop(ctx context.Context) {
	client := &http.Client{}
	for {
		intervalInt, err := refreshPassword(ctx, client)
		if err != nil {
			log.L.Errorf("Failed to refresh password from GCP token: %w", err)
		}
		refreshInterval := time.Duration(intervalInt) * time.Second
		select {
		case <-ctx.Done():
			return
		case <-time.After(refreshInterval):
		}
	}
}

func refreshPassword(ctx context.Context, client *http.Client) (int, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "http://metadata.google.internal./computeMetadata/v1/instance/service-accounts/default/token", nil)
	if err != nil {
		return 5, fmt.Errorf("Failed to create request: %v", err)
	}
	req.Header.Add("Metadata-Flavor", "Google")

	resp, err := client.Do(req)
	if err != nil {
		return 5, fmt.Errorf("Failed to send request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 5, fmt.Errorf("Request returned status code %d", resp.StatusCode)
	}

	var tok *token
	dec := json.NewDecoder(resp.Body)
	if err := dec.Decode(tok); err != nil {
		return 5, fmt.Errorf("Failed to decode response: %v", err)
	}

	passwordMu.Lock()
	defer passwordMu.Unlock()
	password = tok.AccessToken
	return tok.ExpiresIn, nil
}
