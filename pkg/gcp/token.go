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

func handleErrorAndSleep(err error) {
	log.L.Errorf("%v", err)
	time.Sleep(5 * time.Second)
}

func runTokenRefreshLoop(ctx context.Context) {
	client := &http.Client{}

	for {
		req, err := http.NewRequest("GET", "http://metadata.google.internal./computeMetadata/v1/instance/service-accounts/default/token", nil)
		if err != nil {
			handleErrorAndSleep(fmt.Errorf("Failed to create request: %v", err))
			continue
		}
		req.Header.Add("Metadata-Flavor", "Google")

		resp, err := client.Do(req)
		if err != nil {
			handleErrorAndSleep(fmt.Errorf("Failed to send request: %v", err))
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			handleErrorAndSleep(fmt.Errorf("Request returned status code %d", resp.StatusCode))
			continue
		}

		var tok token
		dec := json.NewDecoder(resp.Body)
		if err := dec.Decode(&tok); err != nil {
			handleErrorAndSleep(fmt.Errorf("Failed to decode response: %v", err))
			continue
		}

		passwordMu.Lock()
		password = tok.AccessToken
		passwordMu.Unlock()

		sleepDuration := time.Duration(tok.ExpiresIn) * time.Second
		time.Sleep(sleepDuration)
	}
}
