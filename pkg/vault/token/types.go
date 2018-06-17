package token

import (
	"time"

	"github.com/hashicorp/vault/api"
)

type tokenStatus struct {
	HasToken  bool
	TTL       time.Duration
	ExpiresIn time.Duration
	Expired   bool
}

type Renewer struct {
	client *api.Client
	authFn func(*api.Client) error
}