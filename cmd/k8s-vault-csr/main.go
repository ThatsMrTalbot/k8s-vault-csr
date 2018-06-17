package main

import (
	"time"
	"os"
	"os/signal"
	"syscall"
	"context"
	"flag"

	"golang.org/x/sync/errgroup"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/apiserver/pkg/util/logs"
	"github.com/hashicorp/vault/api"
	"k8s.io/client-go/informers"
	"github.com/golang/glog"
	"k8s.io/client-go/kubernetes"
	"github.com/thatsmrtalbot/k8s-vault-csr/pkg/controller/certificate/signer"
	"github.com/thatsmrtalbot/k8s-vault-csr/pkg/vault/token"
)

var (
	masterAddr         = flag.String("master", "", "kubernetes mastere url")
	kubeconfig         = flag.String("kubeconfig", "", "kubeconfig file to use")
	vaultAddr          = flag.String("vault-address", "", "vault server address")
	useServiceToken    = flag.Bool("use-kubernetes-auth", false, "use service token vault authentication")
	serviceTokenMount  = flag.String("kubernetes-auth-mount", "kubernetes", "name of the kubernetes auth mount in vault")
	serviceTokenRole   = flag.String("kubernetes-auth-role", "", "role to use when authenticating with vault using the service token")
	serviceTokenFile   = flag.String("service-token-file", "/var/run/secrets/kubernetes.io/serviceaccount", "file to load service token from")
	workers            = flag.Int("signer-workers", 4, "number of workers to run")
	pkiMount           = flag.String("vault-pki-mount", "pki", "specify the pki mount to use to generate certificates")
	pkiRole            = flag.String("vault-pki-role", "", "specify role to use, only ttl is used from the role")
)

func init() {
	logs.InitLogs()
	flag.Parse() 
}

func main() {
	// create vault client and renewer
	client, err := api.NewClient(&api.Config{
		Address: *vaultAddr,
		MaxRetries: 10,
	})

	if err != nil {
		glog.Fatal(err.Error())
	}

	var authFn func(*api.Client) error

	if *useServiceToken {
		authFn = token.KubernetesAuth(*serviceTokenMount, *serviceTokenRole, *serviceTokenFile)
	}

	renewer := token.NewRenewer(client, authFn)

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
	factory := informers.NewSharedInformerFactory(clientset, time.Minute * 5)
	
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