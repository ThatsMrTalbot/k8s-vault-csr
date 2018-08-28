package bootstrap

import (
	"github.com/golang/glog"
	"github.com/hashicorp/vault/api"
	"github.com/spf13/cobra"
	"github.com/thatsmrtalbot/k8s-vault-csr/pkg/controller/certificate/bootstrap"
	"github.com/thatsmrtalbot/k8s-vault-csr/pkg/util"
	"github.com/thatsmrtalbot/k8s-vault-csr/pkg/vault/token"
	"k8s.io/client-go/tools/clientcmd"

	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

var (
	// Bootstrap flags
	nodeName  string
	groupName string

	// Vault generic flags
	vaultAddr string
	vaultAuth token.AuthProvider

	// Vault PKI flags
	signVerbatim bool
	pkiMount     string
	pkiRole      string
	pkiTTL       string

	// Kubeconfig flags
	masterAddr string
	insecure   bool
	kubeconfig string
)

var Cmd = &cobra.Command{
	Use:   "bootstrap",
	Short: "create bootstrap certificate using vault",
	Args:  cobra.NoArgs,
	Long: `Create certificates with the "system:bootstrappers" group.

  By default the role should be pre-configured in vault in such a way that it has 
  "O=system:bootstrappers" and can be used as a client cert. This tool then needs 
  permissions in vault to issue a cert with that role.

  Alternatively this tool can use the sign-verbatim endpoint, but it is 
  discoraged as it requires giving access to the sign-verbatim endpoint to this 
  tool, which is a lot of power.

  Complete documentation of the RBAC required to have the generated certs work 
  can be found here:
  https://kubernetes.io/docs/reference/command-line-tools-reference/kubelet-tls-bootstrapping/`,
	Run: func(cmd *cobra.Command, args []string) {
		client, err := api.NewClient(&api.Config{
			Address:    vaultAddr,
			MaxRetries: 10,
		})

		if err != nil {
			glog.Exitf("create vault client: %s", err)
		}

		err = token.NewRenewer(client, vaultAuth).RunOnce()

		if err != nil {
			glog.Exitf("renew vault token: %s", err)
		}

		var key, cert, ca []byte

		if signVerbatim {
			key, cert, ca, err = bootstrap.CreateBootstrapCertWithSignVerbatim(client, pkiMount, pkiRole, pkiTTL, nodeName, groupName)
		} else {
			key, cert, ca, err = bootstrap.CreateBootstrapCertWithIssue(client, pkiMount, pkiRole, pkiTTL, nodeName)
		}

		if err != nil {
			glog.Exitf("generate bootstrap certificate: %s", err)
		}

		kubeconfigData := clientcmdapi.Config{
			// Define a cluster stanza based on the bootstrap kubeconfig.
			Clusters: map[string]*clientcmdapi.Cluster{"default-cluster": {
				Server:                   masterAddr,
				InsecureSkipTLSVerify:    insecure,
				CertificateAuthorityData: ca,
			}},
			// Define auth based on the obtained client cert.
			AuthInfos: map[string]*clientcmdapi.AuthInfo{"default-auth": {
				ClientCertificateData: cert,
				ClientKeyData:         key,
			}},
			// Define a context that connects the auth info and cluster, and set it as the default
			Contexts: map[string]*clientcmdapi.Context{"default-context": {
				Cluster:   "default-cluster",
				AuthInfo:  "default-auth",
				Namespace: "default",
			}},
			CurrentContext: "default-context",
		}

		// Marshal to disk
		err = clientcmd.WriteToFile(kubeconfigData, kubeconfig)
		if err != nil {
			glog.Exitf("write kubeconfig to disk: %s", err)
		}
	},
}

func init() {
	Cmd.Flags().StringVar(&nodeName, "node-name", "", "node name to use in the bootstrap certificate")
	Cmd.Flags().StringVar(&groupName, "group-name", "system:bootstrappers", "group name to use in the bootstrap certificate")
	Cmd.Flags().StringVar(&vaultAddr, "vault-address", "", "vault server address")
	Cmd.Flags().StringVar(&pkiMount, "vault-pki-mount", "pki", "specify the pki mount to use to generate certificates")
	Cmd.Flags().StringVar(&pkiRole, "vault-pki-role", "", "specify role to use, only ttl is used from the role")
	Cmd.Flags().StringVar(&pkiRole, "vault-pki-sign-verbatim", "", "use sign-verbatim to create the bootstrap certificate")
	Cmd.Flags().StringVar(&pkiTTL, "vault-pki-ttl", "1h", "ttl of the bootstrap certificate")
	Cmd.Flags().StringVar(&masterAddr, "output-kubeconfig-master-url", "", "url of the apiserver")
	Cmd.Flags().BoolVar(&insecure, "output-kubeconfig-insecure", false, "allow insecure certificates for the apiserver")
	Cmd.Flags().StringVar(&kubeconfig, "output-kubeconfig-path", "", "path to write kubeconfig to")

	util.FlagAuthProvider(&vaultAuth, Cmd.Flags())
}
