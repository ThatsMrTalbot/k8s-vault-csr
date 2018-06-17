package token

import (
	"time"
	"encoding/json"
	"github.com/golang/glog"
	"github.com/pkg/errors"
	"github.com/hashicorp/vault/api"
	
)

var ErrNoAuthProvider = errors.New("no vault authentication method provided")

var infinity = time.Duration(^uint64(0) >> 1)

func NewRenewer(client *api.Client, authFn func(*api.Client) error) *Renewer {
	if authFn == nil {
		authFn = func(*api.Client) error {
			return ErrNoAuthProvider
		}
	}

	return &Renewer{
		client: client,
		authFn: authFn,
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
		return nil, err
	}

	expires, err := time.Parse(time.RFC3339, secret.Data["expire_time"].(string))
	if err != nil {
		return nil, err
	}

	ttl, err := secret.Data["ttl"].(json.Number).Int64()
	if err != nil {
		return nil, err
	}

	if time.Now().UTC().After(expires) {
		return &tokenStatus{
			HasToken: true,
			Expired: true,
		}, nil
	}

	return &tokenStatus{
		HasToken: true,
		ExpiresIn: time.Now().UTC().Sub(expires),
		TTL: time.Duration(ttl) * time.Second,
	}, nil
}

func (r *Renewer) auth() error {
	return r.authFn(r.client)
}

func (r *Renewer) renew() error {
	_, err := r.client.Auth().Token().RenewSelf(0)
	return err
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

func (r *Renewer) Run(done <-chan struct{}) error  {
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