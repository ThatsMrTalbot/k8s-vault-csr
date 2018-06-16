package token

import (
	"io/ioutil"
	"fmt"

	"github.com/hashicorp/vault/api"
)

func KubernetesAuth(mount, role, tokenfile string) func(*api.Client) error {
	return func(client *api.Client) error {
		token, err := ioutil.ReadFile(tokenfile)
		if err != nil {
			return err			
		}

		secret, err := client.Logical().Write(
			fmt.Sprintf("auth/%s/login", mount),
			map[string]interface{}{
				"role": role,
				"jwt": string(token),
			},
		)

		if err != nil {
			return err
		}

		client.SetToken(secret.Auth.ClientToken)

		return nil
	}
}

