package token

import (
	"encoding/json"
	"time"

	"github.com/golang/glog"
	"github.com/hashicorp/vault/api"
	"github.com/pkg/errors"
)

// ErrNoAuthProvider is the error returned when a Renewer is created without
// an auth method provided
var ErrNoAuthProvider = errors.New("no vault authentication method provided")

// NewRenewer creates a Vault token renewer that will renew tokens halfway
// through their lifespan. If an auth method is provided then the controller
// can also authenticate against Vault if a authentication method is provided
func NewRenewer(client *api.Client, authProvider AuthProvider) *Renewer {
	return &Renewer{
		client:       client,
		authProvider: authProvider,
	}
}

func (r *Renewer) currentTokenStatus() (*tokenStatus, error) {
	if r.client.Token() == "" {
		return &tokenStatus{
			HasToken: false,
		}, nil
	}

	secret, err := r.client.Auth().Token().LookupSelf()
	if err != nil {
		return nil, errors.Wrap(err, "looking up own token")
	}

	expires, err := time.Parse(time.RFC3339, secret.Data["expire_time"].(string))
	if err != nil {
		return nil, errors.Wrap(err, "parsing token expire time")
	}

	ttl, err := secret.Data["ttl"].(json.Number).Int64()
	if err != nil {
		return nil, errors.Wrap(err, "parsing token ttl")
	}

	if time.Now().UTC().After(expires) {
		return &tokenStatus{
			HasToken: true,
			Expired:  true,
		}, nil
	}

	return &tokenStatus{
		HasToken:  true,
		ExpiresIn: time.Now().UTC().Sub(expires),
		TTL:       time.Duration(ttl) * time.Second,
	}, nil
}

func (r *Renewer) auth() error {
	if r.authProvider != nil {
		err := r.authProvider.Auth(r.client)
		return errors.Wrap(err, "authenticating with vault")
	}

	return ErrNoAuthProvider
}

func (r *Renewer) renew() error {
	_, err := r.client.Auth().Token().RenewSelf(0)
	return errors.Wrap(err, "renewing token")
}

func (r *Renewer) tick() error {
	status, err := r.currentTokenStatus()

	if err != nil {
		return err
	}

	if !status.HasToken {
		glog.Info("no token - attempting auth")
		return r.auth()
	}

	if status.Expired {
		glog.Info("token expired - attempting auth")
		return r.auth()
	}

	if status.ExpiresIn <= status.TTL/2 {
		glog.Info("token halfway through ttl - attempting refresh")
		return r.renew()
	}

	return nil
}

// RunOnce runs the renew/auth action once
func (r *Renewer) RunOnce() error {
	return r.tick()
}

// Run starts the renewer loop until stopped or an error occurs
func (r *Renewer) Run(done <-chan struct{}) error {
	ticker := time.NewTicker(time.Second)
	for {
		select {
		case <-ticker.C:
			if err := r.tick(); err != nil {
				ticker.Stop()
				return err
			}
		case <-done:
			ticker.Stop()
			return nil
		}
	}
}
