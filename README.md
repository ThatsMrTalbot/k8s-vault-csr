[![Build Status](https://travis-ci.org/ThatsMrTalbot/k8s-vault-csr.svg?branch=master)](https://travis-ci.org/ThatsMrTalbot/k8s-vault-csr)

# Kubernetes CSR Vault Controller

Kubernetes supports the approval and signing of x509 Certificate Signing Requests. This can be used internally by Kubernetes for things such as kubelet client certificate rotation. Typically CSRs are signed by the controller-manager with a provided CA and key.

This project replaces that controller with a signer that uses Vault to sign the approved CSR objects. This allows kubelet certificate rotation, and indeed all in cluster certificate signing to be delegated to Hashicorp Vault.

## How it works

This controller uses much of the same code as the default Kubernetes CSR signer, the only difference is the function that performs the signing. For this is uses the `sign-verbatim` endpoint provided by the Vault PKI mount to sign the CSR. 

## Requirements

This controller requires Vault 0.10.3 or greater to function. This is because it relies on the ability to specify "key usage" or "extended key usage" when using the `sign-verbatim` endpoint (https://github.com/hashicorp/vault/pull/4777).  

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
  -approle-auth-mount string
    	name of the approle auth mount in vault
  -approle-auth-roleid string
    	vault role id to use when authenticating with an approle
  -approle-auth-secretid string
    	vault secret id to use when authenticating with an approle
  -kubeconfig string
    	kubeconfig file to use
  -kubernetes-auth-mount string
    	name of the kubernetes auth mount in vault (default "kubernetes")
  -kubernetes-auth-role string
    	role to use when authenticating with vault using the service token
  -kubernetes-auth-token-file string
    	file to load service token from (default "/var/run/secrets/kubernetes.io/serviceaccount")
  -log_backtrace_at value
    	when logging hits line file:N, emit a stack trace
  -log_dir string
    	If non-empty, write log files in this directory
  -logtostderr
    	log to standard error instead of files
  -master string
    	kubernetes master url
  -signer-workers int
    	number of signing workers to run (default 4)
  -stderrthreshold value
    	logs at or above this threshold go to stderr
  -v value
    	log level for V logs
  -vault-address string
    	vault server address
  -vault-auth string
    	method to use for vault auth (kubernetes | approle)
  -vault-pki-mount string
    	specify the pki mount to use to generate certificates (default "pki")
  -vault-pki-role string
    	specify role to use, only ttl is used from the role
  -vmodule value
    	comma-separated list of pattern=N settings for file-filtered logging
```