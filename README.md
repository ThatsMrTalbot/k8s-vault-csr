[![Build Status](https://travis-ci.org/ThatsMrTalbot/k8s-vault-csr.svg?branch=master)](https://travis-ci.org/ThatsMrTalbot/k8s-vault-csr)

# Kubernetes CSR Vault Controller

Kubernetes supports the approval and signing of x509 Certificate Signing Requests. This can be used internally by Kubernetes for things such as kubelet client certificate rotation. Typically CSRs are signed by the controller-manager with a provided CA and key.

This project replaces that controller with a signer that uses Vault to sign the approved CSR objects. This allows kubelet certificate rotation, and indeed all in cluster certificate signing to be delegated to Hashicorp Vault.

## How it works

This controller uses much of the same code as the default Kubernetes CSR signer, the only difference is the function that performs the signing. For this is uses the `sign-verbatim` endpoint provided by the Vault PKI mount to sign the CSR. 

## Known issues 

The latest release of Vault (0.10.2) does not allow a client to specify "key usage" or "extended key usage" when using the `sign-verbatim` endpoint. This has been solved in master (https://github.com/hashicorp/vault/pull/4777) and should be in Vault 0.10.3

## Installing

`k8s-vault-csr` can run in cluster or standalone. The fastest path is to run in cluster:

- The default `csrsigning` controller first need disabling in the controller manager. This can be done through the command line flag `--controllers`, for example `--controllers=-csrsigning`
- If you want to use kubernetes auth in vault then this needs setting up, the signer needs permission to call `/pki/sign-verbatim/role` where   `pki` and `role` are the pki mount and role respectively.
- Deploy `kube-vault-signer` and RBAC. See `deploy.yaml` for an example. 

## Flags

```
Usage of k8s-vault-csr:
  -alsologtostderr
    	log to standard error as well as files
  -kubeconfig string
    	kubeconfig file to use
  -log_backtrace_at value
    	when logging hits line file:N, emit a stack trace
  -log_dir string
    	If non-empty, write log files in this directory
  -logtostderr
    	log to standard error instead of files
  -master string
    	kubernetes mastere url
  -mount string
    	specify the pki mount to use to generate certificates (default "pki")
  -role string
    	specify role to use, only ttl is used from the role
  -service-token-file string
    	file to load service token from (default "/var/run/secrets/kubernetes.io/serviceaccount")
  -service-token-mount string
    	name of the kubernetes auth mount in vault (default "kubernetes")
  -service-token-role string
    	role to use when authenticating with vault using the service token
  -stderrthreshold value
    	logs at or above this threshold go to stderr
  -use-service-token
    	use service token vault authentication
  -v value
    	log level for V logs
  -vault-address string
    	vault server address
  -vmodule value
    	comma-separated list of pattern=N settings for file-filtered logging
  -workers int
    	number of workers to run (default 4)
```