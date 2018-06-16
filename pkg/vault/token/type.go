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
	err    chan error
	client *api.Client
	authFn func(*api.Client) error
}