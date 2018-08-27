package token

import (
	"fmt"
	"io/ioutil"

	"github.com/golang/glog"
	"github.com/hashicorp/vault/api"
	"github.com/pkg/errors"
)

// ErrNoAuthInfo is returned when an auth provider returns no authentication
// info when requested from the vault server.
var ErrNoAuthInfo = errors.New("no auth info returned")

type AuthProviderKubernetes struct {
	Mount     string
	Role      string
	TokenFile string
}

func (p AuthProviderKubernetes) String() string {
	return "kubernetes"
}

// Auth implements AuthProvider
func (p AuthProviderKubernetes) Auth(client *api.Client) error {
	glog.V(2).Info("authenticating using kubernetes service account")

	glog.V(3).Infof("reading service token file %s", p.TokenFile)
	token, err := ioutil.ReadFile(p.TokenFile)
	if err != nil {
		return errors.Wrap(err, "reading service token file")
	}

	glog.V(3).Infof("attempting kubernetes authentication mount=%s role=%s", p.Mount, p.Role)
	secret, err := client.Logical().Write(
		fmt.Sprintf("auth/%s/login", p.Mount),
		map[string]interface{}{
			"role": p.Role,
			"jwt":  string(token),
		},
	)

	if err != nil {
		return errors.Wrap(err, "authenticating with service token")
	}

	if secret.Auth == nil {
		return ErrNoAuthInfo
	}

	client.SetToken(secret.Auth.ClientToken)

	return nil
}

type AuthProviderAppRole struct {
	Mount    string
	RoleID   string
	SecretID string
}

func (p AuthProviderAppRole) String() string {
	return "approle"
}

// AppRoleAuth authenticates against Vault using an approle and secret.
func (p AuthProviderAppRole) Auth(client *api.Client) error {
	glog.V(2).Info("authenticating using approle")

	glog.V(3).Infof("attempting approle authentication roleid=%s", p.RoleID)
	secret, err := client.Logical().Write(
		fmt.Sprintf("auth/%s/login", p.Mount),
		map[string]interface{}{
			"role_id":   p.RoleID,
			"secret_id": p.SecretID,
		},
	)

	if err != nil {
		return errors.Wrap(err, "authenticating with approle")
	}

	if secret.Auth == nil {
		return ErrNoAuthInfo
	}

	client.SetToken(secret.Auth.ClientToken)

	return nil
}
