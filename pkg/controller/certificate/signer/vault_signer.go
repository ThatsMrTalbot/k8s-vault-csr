package signer

import (
	"fmt"

	"github.com/golang/glog"
	vaultAPI "github.com/hashicorp/vault/api"
	"github.com/pkg/errors"
	capi "k8s.io/api/certificates/v1beta1"
	certificatesinformers "k8s.io/client-go/informers/certificates/v1beta1"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/kubernetes/pkg/controller/certificates"
)

// KeyUsage contains a mapping of string names to key usages.
var keyUsageLookup = map[capi.KeyUsage]string{
	"signing":            "DigitalSignature",
	"digital signature":  "DigitalSignature",
	"content commitment": "ContentCommitment",
	"key encipherment":   "KeyEncipherment",
	"key agreement":      "KeyAgreement",
	"data encipherment":  "DataEncipherment",
	"cert sign":          "CertSign",
	"crl sign":           "CRLSign",
	"encipher only":      "EncipherOnly",
	"decipher only":      "DecipherOnly",
}

// ExtKeyUsage contains a mapping of string names to extended key
// usages.
var extKeyUsageLookup = map[capi.KeyUsage]string{
	"any":              "Any",
	"server auth":      "ServerAuth",
	"client auth":      "ClientAuth",
	"code signing":     "CodeSigning",
	"email protection": "EmailProtection",
	"s/mime":           "EmailProtection",
	"ipsec end system": "IPSECEndSystem",
	"ipsec tunnel":     "IPSECTunnel",
	"ipsec user":       "IPSECUser",
	"timestamping":     "TimeStamping",
	"ocsp signing":     "OCSPSigning",
	"microsoft sgc":    "MicrosoftServerGatedCrypto",
	"netscape sgc":     "NetscapeServerGatedCrypto",
}

// NewVaultSigningController creates a certificate signing controller that
// uses vault to sign certificates. It uses the `sign verbatim` functionality
// of vault to achieve this.
func NewVaultSigningController(
	kclient clientset.Interface,
	csrInformer certificatesinformers.CertificateSigningRequestInformer,
	vclient *vaultAPI.Client,
	mount string,
	role string,
) (*certificates.CertificateController, error) {
	return certificates.NewCertificateController(
		kclient,
		csrInformer,
		newVaultSigner(kclient, vclient, mount, role).handle,
	), nil
}

type vaultSigner struct {
	kclient clientset.Interface
	vclient *vaultAPI.Client

	mount string
	role  string
}

func newVaultSigner(
	kclient clientset.Interface,
	vclient *vaultAPI.Client,
	mount string,
	role string,
) *vaultSigner {
	return &vaultSigner{
		kclient: kclient,
		vclient: vclient,
		mount:   mount,
		role:    role,
	}
}

func (s *vaultSigner) handle(csr *capi.CertificateSigningRequest) error {
	if !certificates.IsCertificateRequestApproved(csr) {
		return nil
	}

	glog.V(1).Infof("signing csr using vault namespace=%s name=%s", csr.ObjectMeta.Namespace, csr.ObjectMeta.Name)

	csr, err := s.sign(csr)
	if err != nil {
		return errors.Wrap(err, "handling signing request")
	}

	_, err = s.kclient.CertificatesV1beta1().CertificateSigningRequests().UpdateStatus(csr)
	return errors.Wrap(err, "handling signing request: updating signature for csr")
}

func (s *vaultSigner) sign(csr *capi.CertificateSigningRequest) (*capi.CertificateSigningRequest, error) {
	secret, err := s.vclient.Logical().Write(
		fmt.Sprintf("%s/sign-verbatim/%s", s.mount, s.role),
		map[string]interface{}{
			"csr":           string(csr.Spec.Request),
			"key_usage":     s.parseKeyUsages(csr.Spec.Usages),
			"ext_key_usage": s.parseExtKeyUsages(csr.Spec.Usages),
		},
	)

	if err != nil {
		return nil, errors.Wrap(err, "signing with vault api")
	}

	csr.Status.Certificate = []byte(secret.Data["certificate"].(string))

	return csr, nil
}

func (s *vaultSigner) parseKeyUsages(usages []capi.KeyUsage) []string {
	var keyUsages []string

	for _, u := range usages {
		if s, ok := keyUsageLookup[u]; ok {
			keyUsages = append(keyUsages, s)
		}
	}

	return keyUsages
}

func (s *vaultSigner) parseExtKeyUsages(usages []capi.KeyUsage) []string {
	var keyUsages []string

	for _, u := range usages {
		if s, ok := extKeyUsageLookup[u]; ok {
			keyUsages = append(keyUsages, s)
		}
	}

	return keyUsages
}
