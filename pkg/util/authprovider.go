package util

import (
	"github.com/pkg/errors"
	"github.com/spf13/pflag"
	"github.com/thatsmrtalbot/k8s-vault-csr/pkg/vault/token"
)

// FlagAuthProvider creates flags for vault auth providers
func FlagAuthProvider(ptr *token.AuthProvider, fs *pflag.FlagSet) {
	provider := authProvider{
		ptr: ptr,
	}

	fs.Var(provider, "vault-auth", "method to use for vault auth (kubernetes|approle)")

	// Vault Kubernetes auth flags
	fs.StringVar(&provider.kubernetes.Mount, "kubernetes-auth-mount", "kubernetes", "name of the kubernetes auth mount in vault")
	fs.StringVar(&provider.kubernetes.Role, "kubernetes-auth-role", "", "role to use when authenticating with vault using the service token")
	fs.StringVar(&provider.kubernetes.TokenFile, "kubernetes-auth-token-file", "/var/run/secrets/kubernetes.io/serviceaccount", "file to load service token from")

	// Vault AppRole auth flags
	fs.StringVar(&provider.appRole.Mount, "approle-auth-mount", "", "name of the approle auth mount in vault")
	fs.StringVar(&provider.appRole.RoleID, "approle-auth-roleid", "", "vault role id to use when authenticating with an approle")
	fs.StringVar(&provider.appRole.SecretID, "approle-auth-secretid", "", "vault secret id to use when authenticating with an approle")
}

type authProvider struct {
	ptr *token.AuthProvider

	kubernetes token.AuthProviderKubernetes
	appRole    token.AuthProviderAppRole
}

func (a authProvider) String() string {
	if *a.ptr != nil {
		return (*a.ptr).String()
	}

	return ""
}

func (a authProvider) Set(provider string) error {
	switch provider {
	case "kubernetes":
		*a.ptr = a.kubernetes
	case "approle":
		*a.ptr = a.appRole
	case "":
		*a.ptr = nil
	default:
		return errors.Errorf("unknown auth provider: %s", provider)
	}

	return nil
}

func (a authProvider) Type() string {
	return "string"
}
