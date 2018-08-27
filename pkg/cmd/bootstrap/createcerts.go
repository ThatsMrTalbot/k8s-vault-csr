package bootstrap

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"

	"github.com/hashicorp/vault/api"
	"github.com/pkg/errors"
	certutil "k8s.io/client-go/util/cert"
)

func createBootstrapCertWithSignVerbatim(client *api.Client) (key, cert, ca []byte, err error) {
	key, err = generateECKey()
	if err != nil {
		return nil, nil, nil, errors.Wrap(err, "generate key")
	}

	csr, err := createBootstrapCSR(key, nodeName)
	if err != nil {
		return nil, nil, nil, errors.Wrap(err, "generate csr")
	}

	secret, err := client.Logical().Write(
		fmt.Sprintf("%s/sign-verbatim/%s", pkiMount, pkiRole),
		map[string]interface{}{
			"csr":           string(csr),
			"key_usage":     []string{"DigitalSignature", "KeyEncipherment"},
			"ext_key_usage": []string{"ClientAuth"},
			"ttl":           pkiTTL,
		},
	)

	if err != nil {
		return nil, nil, nil, err
	}

	cert = []byte(secret.Data["certificate"].(string) + "\n")
	ca = []byte(secret.Data["ca_chain"].(string) + "\n")

	if len(ca) == 1 {
		ca = []byte(secret.Data["issuing_ca"].(string) + "\n")
	}

	return
}

func createBootstrapCertWithIssue(client *api.Client) (key, cert, ca []byte, err error) {
	secret, err := client.Logical().Write(
		fmt.Sprintf("%s/issue/%s", pkiMount, pkiRole),
		map[string]interface{}{
			"common_name":          fmt.Sprintf("system:node:%s", nodeName),
			"exclude_cn_from_sans": true,
			"ttl": pkiTTL,
		},
	)

	if err != nil {
		return nil, nil, nil, err
	}

	cert = []byte(secret.Data["certificate"].(string) + "\n")
	ca = []byte(secret.Data["ca_chain"].(string) + "\n")

	if len(ca) == 1 {
		ca = []byte(secret.Data["issuing_ca"].(string) + "\n")
	}

	return
}

func createBootstrapCSR(privateKeyData []byte, nodeName string) (csrData []byte, err error) {
	subject := &pkix.Name{
		Organization: []string{"system:bootstrappers"},
		CommonName:   "system:node:" + nodeName,
	}

	privateKey, err := certutil.ParsePrivateKeyPEM(privateKeyData)
	if err != nil {
		return nil, errors.Wrap(err, "invalid private key for certificate request")
	}

	csrData, err = certutil.MakeCSR(privateKey, subject, nil, nil)
	if err != nil {
		return nil, errors.Wrap(err, "unable to generate certificate request")
	}

	return csrData, nil
}

func generateECKey() ([]byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, errors.Wrap(err, "generate ECDSA key")
	}

	keyDer, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, errors.Wrap(err, "serialize ECDSA key")
	}

	keyBlock := pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyDer,
	}

	return pem.EncodeToMemory(&keyBlock), nil
}
