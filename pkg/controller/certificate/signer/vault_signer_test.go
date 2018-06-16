package signer

import (
	"context"
	"testing"
	"reflect"
	"crypto/x509"

	log "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/helper/logging"
	"github.com/hashicorp/vault/http"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/physical/inmem"
	"github.com/hashicorp/vault/vault"
	"github.com/hashicorp/vault/builtin/logical/pki"
	"k8s.io/client-go/util/cert"
	capi "k8s.io/api/certificates/v1beta1"	
)

const kubeletCSR = `
-----BEGIN CERTIFICATE REQUEST-----
MIH1MIGdAgEAMDsxFTATBgNVBAoTDHN5c3RlbTpub2RlczEiMCAGA1UEAxMZc3lz
dGVtOm5vZGU6ay1hLW5vZGUtczM2YjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IA
BJbxa5Y8SrUJVHpOoWD5ceqH+5R9mjIhwVP2sqfTcLkjvbitzOiLlxSq/LwJ+qq7
kVpf9f3GopZVhRWbYSCg0YGgADAKBggqhkjOPQQDAgNHADBEAiAabb6XFtPOJUCQ
+84NhxLEvPANhrtwFq3Q0qFZ9TzH5QIgc/697RTTcbri2lVj+10dLFIC3VYJ7br4
QjA7haCYXrA=
-----END CERTIFICATE REQUEST-----
`

func TestSigner(t *testing.T) {
	// Set up vault

	logger := logging.NewVaultLogger(log.Trace)

	phys, err := inmem.NewInmem(nil, logger)
	if err != nil {
		t.Fatal(err)
		return
	}

	core, err := vault.NewCore(&vault.CoreConfig{
		Physical: phys,
		LogicalBackends: map[string]logical.Factory{
			"pki": func(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
				return pki.Factory(ctx, conf)
			},
		},
		DisableMlock: true,
	})

	if err != nil {
		t.Fatal("error initializing core: ", err)
		return
	}

	init, err := core.Initialize(context.Background(), &vault.InitParams{
		BarrierConfig: &vault.SealConfig{
			SecretShares:    1,
			SecretThreshold: 1,
		},
		RecoveryConfig: nil,
	})

	if err != nil {
		t.Fatal("error initializing core: ", err)
		return
	}

	if unsealed, err := core.Unseal(init.SecretShares[0]); err != nil {
		t.Fatal("error unsealing core: ", err)
		return
	} else if !unsealed {
		t.Fatal("vault shouldn't be sealed")
		return
	}

	ln, addr := http.TestServer(nil, core)
	defer ln.Close()

	clientConfig := api.DefaultConfig()
	clientConfig.Address = addr
	client, err := api.NewClient(clientConfig)

	if err != nil {
		t.Fatal("error initializing HTTP client: ", err)
		return
	}

	client.SetToken(init.RootToken)

	// Setup vault mounts

	err = client.Sys().Mount("pki", &api.MountInput{
		Type: "pki",
		Config: api.MountConfigInput{
			MaxLeaseTTL: "87600h",
		},
	})

	if err != nil {
		t.Fatal("error mounting pki: ", err)
		return
	}

	_, err = client.Logical().Write("pki/root/generate/internal", map[string]interface{}{
		"common_name": "Test Vault CA",
		"ttl": "87600h",
	})

	if err != nil {
		t.Fatal("error generating root ca: ", err)
		return
	}

	// Test case

	csr := &capi.CertificateSigningRequest{
		Spec: capi.CertificateSigningRequestSpec{
			Request: []byte(kubeletCSR),
			Usages: []capi.KeyUsage{
				capi.UsageSigning,
				capi.UsageKeyEncipherment,
				capi.UsageServerAuth,
				capi.UsageClientAuth,
			},
		},
	}

	signer := newVaultSigner(nil, client, "pki", "")

	csr, err = signer.sign(csr)
	if err != nil {
		t.Fatalf("failed to sign CSR: %v", err)
	}
	certData := csr.Status.Certificate
	if len(certData) == 0 {
		t.Fatalf("expected a certificate after signing")
	}

	certs, err := cert.ParseCertsPEM(certData)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}
	if len(certs) != 1 {
		t.Fatalf("expected one certificate")
	}

	crt := certs[0]

	if crt.Subject.CommonName != "system:node:k-a-node-s36b" {
		t.Errorf("expected common name of 'system:node:k-a-node-s36b', but got: %v", certs[0].Subject.CommonName)
	}
	if !reflect.DeepEqual(crt.Subject.Organization, []string{"system:nodes"}) {
		t.Errorf("expected organization to be [system:nodes] but got: %v", crt.Subject.Organization)
	}
	if crt.KeyUsage != x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment {
		t.Errorf("bad key usage")
	}
	if !reflect.DeepEqual(crt.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}) {
		t.Errorf("bad extended key usage")
	}
}
