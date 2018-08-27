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

// KubernetesAuth authenticates against Vault using a Kubernetes service token.
func KubernetesAuth(mount, role, tokenfile string) AuthProvider {
	return func(client *api.Client) error {
		glog.V(2).Info("authenticating using kubernetes service account")

		glog.V(3).Infof("reading service token file %s", tokenfile)
		token, err := ioutil.ReadFile(tokenfile)
		if err != nil {
			return errors.Wrap(err, "reading service token file")
		}

		glog.V(3).Infof("attempting kubernetes authentication mount=%s role=%s", mount, role)
		secret, err := client.Logical().Write(
			fmt.Sprintf("auth/%s/login", mount),
			map[string]interface{}{
				"role": role,
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
}

// AppRoleAuth authenticates against Vault using an approle and secret.
func AppRoleAuth(mount, roleID, secretID string) AuthProvider {
	return func(client *api.Client) error {
		glog.V(2).Info("authenticating using approle")

		glog.V(3).Infof("attempting approle authentication roleid=%s", roleID)
		secret, err := client.Logical().Write(
			fmt.Sprintf("auth/%s/login", mount),
			map[string]interface{}{
				"role_id":   roleID,
				"secret_id": secretID,
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
}
