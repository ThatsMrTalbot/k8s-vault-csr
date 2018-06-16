package main

import (
	"time"
	"os"
	"os/signal"
	"syscall"
	"context"
	"flag"
	"sync"

	"k8s.io/client-go/rest"
	"github.com/hashicorp/vault/api"
	"k8s.io/client-go/informers"
	"github.com/golang/glog"
	"k8s.io/client-go/kubernetes"
	"github.com/thatsmrtalbot/k8s-vault-csr/pkg/controller/certificate/signer"
	"github.com/thatsmrtalbot/k8s-vault-csr/pkg/vault/token"
)

var (
	vaultAddr          = flag.String("vault-address", "", "the vault server address")
	useServiceToken    = flag.Bool("use-service-token", false, "use service token vault authentication")
	serviceTokenMount  = flag.String("service-token-mount", "kubernetes", "name of the kubernetes auth mount in vault")
	serviceTokenRole   = flag.String("service-token-role", "", "role to use when authenticating with vault using the service token")
	serviceTokenFile   = flag.String("service-token-file", "/var/run/secrets/kubernetes.io/serviceaccount", "file to load service token from")
	workers            = flag.Int("workers", 4, "number of workers to run")
	pkiMount           = flag.String("mount", "pki", "specify the pki mount to use to generate certificates")
	pkiRole            = flag.String("role", "", "specify role to use, only ttl is used from the role")
)

func init() {
	flag.Lookup("logtostderr").DefValue = "true"
	flag.Lookup("logtostderr").Value.Set("true")
	flag.Parse() 
}

func main() {
	ctx, cancel := context.WithCancel(context.Background())

	// handle interupt
	term := make(chan os.Signal)
	signal.Notify(term, os.Interrupt, syscall.SIGTERM)

	go func() {
		select {
		case <-term:
			glog.Info("received SIGTERM, exiting gracefully...")
		case <-ctx.Done():
		}
	
		cancel()
	}()

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

	go func() {
		select {
		case err := <-renewer.Error():
			glog.Error("error renewing token: %s", err)
			cancel()
		}
	}()

	// creates the in-cluster config
	config, err := rest.InClusterConfig()
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
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		signing.Run(*workers, ctx.Done())
		wg.Done()
	}()

	go func() {
		renewer.Run(ctx.Done())
		wg.Done()
	}()

	wg.Wait()
}