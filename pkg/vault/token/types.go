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

// Renewer manages vault token, it starts a control loop that checks the
// status of a token every second and performs the following actions:
//
// - If no token exists then auth is attempted (requires auth method)
// - If the token is half way through its lifespan a token renew is attempted
// - If the token is expired auth is attempted (requires auth method)
//
// If any of these actions fail the renewer exits with an error, allowing the
// application to handle to handle this failure. Its worth noting that the
// vault client has built in support for retrying failed requests, so a single
// failure should not cause an error.
type Renewer struct {
	client       *api.Client
	authProvider AuthProvider
}

// AuthMethod the method used to authenticate against vault and update the
// client token.
type AuthProvider interface {
	Auth(*api.Client) error
	String() string
}
