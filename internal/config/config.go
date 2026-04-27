package config

import (
	"fmt"
	"os"

	"github.com/joho/godotenv"
)

type Config struct {
	PAT        string
	APIBaseURL string
}

func Load() (*Config, error) {
	_ = godotenv.Load()

	pat := os.Getenv("DEVGUARD_PAT")
	if pat == "" {
		return nil, fmt.Errorf("DEVGUARD_PAT environment variable is required")
	}

	baseURL := os.Getenv("DEVGUARD_API_URL")
	if baseURL == "" {
		baseURL = "https://api.devguard.org/api/v1"
	}

	return &Config{
		PAT:        pat,
		APIBaseURL: baseURL,
	}, nil
}

func MustLoad() *Config {
	cfg, err := Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "config error: %v\n", err)
		os.Exit(1)
	}
	return cfg
}
