package controller

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/golang/glog"
	"github.com/hashicorp/vault/api"
	"github.com/spf13/cobra"
	"github.com/thatsmrtalbot/k8s-vault-csr/pkg/controller/certificate/signer"
	"github.com/thatsmrtalbot/k8s-vault-csr/pkg/util"
	"github.com/thatsmrtalbot/k8s-vault-csr/pkg/vault/token"
	"golang.org/x/sync/errgroup"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

var (
	// Kubernetes flags
	masterAddr string
	kubeconfig string

	// Vault generic flags
	vaultAddr string
	vaultAuth token.AuthProvider

	// Controller flags
	workers int

	// Vault PKI flags
	pkiMount string
	pkiRole  string
)

var Cmd = &cobra.Command{
	Use:   "controller",
	Short: "run certificate signing controller",
	Args:  cobra.NoArgs,
	Long: `Signs CSR requests using Vaults 'sign-verbatim' endpoint.

  This controller must be given the RBAC ClusterRole
  "system:controller:certificate-controller" in order 
  to function.
  
  It also requires sufficient permissions in vault to call the 
  'sign-verbatim' endpoint on the pki mount`,
	Run: func(cmd *cobra.Command, args []string) {
		// create vault client
		client, err := api.NewClient(&api.Config{
			Address:    vaultAddr,
			MaxRetries: 10,
		})

		if err != nil {
			glog.Exitf("create vault client: %s", err)
		}

		// create token renewer
		renewer := token.NewRenewer(client, vaultAuth)

		// ensure we have a token
		err = renewer.RunOnce()
		if err != nil {
			glog.Exitf("renewing vault token: %s", err)
		}

		// creates the in-cluster config
		config, err := clientcmd.BuildConfigFromFlags(masterAddr, kubeconfig)
		if err != nil {
			glog.Exitf("building kubernetes config from flags: %s", err)
		}

		// creates the clientset
		clientset, err := kubernetes.NewForConfig(config)
		if err != nil {
			glog.Fatalf("create kubernetes config: %s", err)
		}

		// create informer factory
		factory := informers.NewSharedInformerFactory(clientset, time.Minute*5)

		// create signing controller
		signing, err := signer.NewVaultSigningController(
			clientset,
			factory.Certificates().V1beta1().CertificateSigningRequests(),
			client,
			pkiMount,
			pkiRole,
		)

		if err != nil {
			glog.Fatalf("create vault signing controller: %s", err)
		}

		// start workers
		ctx, cancel := context.WithCancel(context.Background())
		wg, ctx := errgroup.WithContext(ctx)

		wg.Go(func() error {
			signing.Run(workers, ctx.Done())
			return nil
		})

		wg.Go(func() error {
			return renewer.Run(ctx.Done())
		})

		term := make(chan os.Signal)
		signal.Notify(term, os.Interrupt, syscall.SIGTERM)

		select {
		case <-term:
			glog.Info("received SIGTERM, exiting gracefully...")
		case <-ctx.Done():
		}

		cancel()
		if err := wg.Wait(); err != nil {
			glog.Fatalf("unhandled error received: %s", err)
		}
	},
}

func init() {
	// Kubernetes flags
	Cmd.Flags().StringVar(&masterAddr, "master", "", "kubernetes master url")
	Cmd.Flags().StringVar(&kubeconfig, "kubeconfig", "", "kubeconfig file to use")
	Cmd.Flags().StringVar(&vaultAddr, "vault-address", "", "vault server address")
	Cmd.Flags().IntVar(&workers, "signer-workers", 4, "number of signing workers to run")
	Cmd.Flags().StringVar(&pkiMount, "vault-pki-mount", "pki", "specify the pki mount to use to generate certificates")
	Cmd.Flags().StringVar(&pkiRole, "vault-pki-role", "", "specify role to use, only ttl is used from the role")
	util.FlagAuthProvider(&vaultAuth, Cmd.Flags())
}
