# Kubernetes CSR Vault Controller

Kubernetes supports the approval and signing of x509 Certificate Signing Requests. This can be used internally by Kubernetes for things such as kubelet client certificate rotation. Typically CSRs are signed by the controller-manager with a provided CA and key.

This project replaces that controller with a signer that uses Vault to sign the approved CSR objects. This allows kubelet certificate rotation, and indeed all in cluster certificate signing to be delegated to Hashicorp Vault.

## How it works

This controller uses much of the same code as the default Kubernetes CSR signer, the only difference is the function that performs the signing. For this is uses the `sign-verbatim` endpoint provided by the Vault PKI mount to sign the CSR. 

## Known issues 

The latest release of Vault (0.10.2) does not allow a client to specify "key usage" or "extended key usage" when using the `sign-verbatim` endpoint. This has been solved in master (https://github.com/hashicorp/vault/pull/4777) and should be in Vault 0.10.3

