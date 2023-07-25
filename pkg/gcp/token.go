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

const (
	tokenURL                      = "http://metadata.google.internal./computeMetadata/v1/instance/service-accounts/default/token"
	metadataFlavor                = "Google"
	refreshInterval time.Duration = 5 * time.Second
)

var (
	enabled    = false
	password   string
	passwordMu sync.Mutex
	client     = &http.Client{}
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
	case host == "container.cloud.google.com", host == "gcr.io", strings.HasSuffix(host, ".gcr.io"), strings.HasSuffix(host, ".pkg.dev"):
		return true
	default:
		return false
	}
}

func GetPassword() string {
	passwordMu.Lock()
	defer passwordMu.Unlock()
	return password // return a copy of password
}

func runTokenRefreshLoop(ctx context.Context) {
	ticker := time.NewTicker(refreshInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := refreshPassword(ctx); err != nil {
				log.L.Errorf("Failed to refresh password from GCP token: %v", err)
			}
		case <-ctx.Done():
			return
		}
	}
}

func refreshPassword(ctx context.Context) error {
	req, err := http.NewRequest("GET", tokenURL, nil)
	if err != nil {
		return fmt.Errorf("Failed to create request: %v\n", err)
	}
	req.Header.Add("Metadata-Flavor", metadataFlavor)
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("Failed to send request: %v\n", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Request returned status code %d", resp.StatusCode)
	}

	var tok token
	dec := json.NewDecoder(resp.Body)
	if err := dec.Decode(&tok); err != nil {
		return fmt.Errorf("Failed to decode response: %v\n", err)
	}

	passwordMu.Lock()
	password = tok.AccessToken
	passwordMu.Unlock()

	return nil
}
