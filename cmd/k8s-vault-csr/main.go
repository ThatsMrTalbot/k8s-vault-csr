package main

import (
	"context"
	"flag"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/golang/glog"
	"github.com/hashicorp/vault/api"
	"github.com/thatsmrtalbot/k8s-vault-csr/pkg/controller/certificate/signer"
	"github.com/thatsmrtalbot/k8s-vault-csr/pkg/vault/token"
	"golang.org/x/sync/errgroup"
	"k8s.io/apiserver/pkg/util/logs"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

// EnvPrefix is the prefix used when setting flags via environment vars
const EnvPrefix = "VAULT_CSR_SIGNER"

var (
	// Kubernetes flags
	masterAddr = flag.String("master", "", "kubernetes master url")
	kubeconfig = flag.String("kubeconfig", "", "kubeconfig file to use")

	// Vault generic flags
	vaultAddr = flag.String("vault-address", "", "vault server address")
	vaultAuth = flag.String("vault-auth", "", "method to use for vault auth (kubernetes | approle)")

	// Vault Kubernetes auth flags
	serviceTokenMount = flag.String("kubernetes-auth-mount", "kubernetes", "name of the kubernetes auth mount in vault")
	serviceTokenRole  = flag.String("kubernetes-auth-role", "", "role to use when authenticating with vault using the service token")
	serviceTokenFile  = flag.String("kubernetes-auth-token-file", "/var/run/secrets/kubernetes.io/serviceaccount", "file to load service token from")

	// Vault AppRole auth flags
	appRoleRoleMount = flag.String("approle-auth-mount", "", "name of the approle auth mount in vault")
	appRoleRoleID    = flag.String("approle-auth-roleid", "", "vault role id to use when authenticating with an approle")
	appRoleSecretID  = flag.String("approle-auth-secretid", "", "vault secret id to use when authenticating with an approle")

	// Controller flags
	workers = flag.Int("signer-workers", 4, "number of signing workers to run")

	// Vault PKI flags
	pkiMount = flag.String("vault-pki-mount", "pki", "specify the pki mount to use to generate certificates")
	pkiRole  = flag.String("vault-pki-role", "", "specify role to use, only ttl is used from the role")
)

// init sets up logs and parses flags
func init() {
	logs.InitLogs()
	flagsFromEnv()
	flag.Parse()
}

// authProvider gets the token auth provider from the flags provided
func authProvider() token.AuthProvider {
	switch *vaultAuth {
	case "kubernetes":
		return token.KubernetesAuth(*serviceTokenMount, *serviceTokenRole, *serviceTokenFile)
	case "approle":
		return token.AppRoleAuth(*appRoleRoleMount, *appRoleRoleID, *appRoleSecretID)
	case "":
		return nil
	}

	glog.Fatalf("unknown auth method: %s", vaultAuth)

	return nil
}

// flagsFromEnv visits all the flags and checks to see if a corresponding environment variable
// is set, if it is then the flag value is changed to environment variables value
func flagsFromEnv() {
	flag.VisitAll(func(f *flag.Flag) {
		env := EnvPrefix + "_" + strings.ToUpper(strings.Replace(f.Name, "-", "_", -1))
		val := os.Getenv(env)

		if val != "" {
			flag.Set(f.Name, val)
		}
	})
}

// main is the application entrypoint
func main() {
	// create vault client and renewer
	client, err := api.NewClient(&api.Config{
		Address:    *vaultAddr,
		MaxRetries: 10,
	})

	if err != nil {
		glog.Fatal(err.Error())
	}

	renewer := token.NewRenewer(client, authProvider())

	// creates the in-cluster config
	config, err := clientcmd.BuildConfigFromFlags(*masterAddr, *kubeconfig)
	if err != nil {
		glog.Fatal(err.Error())
	}

	// creates the clientset
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		glog.Fatal(err.Error())
	}

	// create informer factory
	factory := informers.NewSharedInformerFactory(clientset, time.Minute*5)

	// create signing controller
	signing, err := signer.NewVaultSigningController(
		clientset,
		factory.Certificates().V1beta1().CertificateSigningRequests(),
		client,
		*pkiMount,
		*pkiRole,
	)

	if err != nil {
		glog.Fatal(err.Error())
	}

	// start workers
	ctx, cancel := context.WithCancel(context.Background())
	wg, ctx := errgroup.WithContext(ctx)

	wg.Go(func() error {
		signing.Run(*workers, ctx.Done())
		return nil
	})

	wg.Go(func() error {
		return renewer.Run(ctx.Done())
	})

	term := make(chan os.Signal)
	signal.Notify(term, os.Interrupt, syscall.SIGTERM)

	select {
	case <-term:
		glog.Error("received SIGTERM, exiting gracefully...")
	case <-ctx.Done():
	}

	cancel()
	if err := wg.Wait(); err != nil {
		glog.Exitf("unhandled error received: %s", err)
	}
}
