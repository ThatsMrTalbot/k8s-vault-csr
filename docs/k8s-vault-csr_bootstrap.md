## k8s-vault-csr bootstrap

create bootstrap certificate using vault

### Synopsis

Create certificates with the "system:bootstrappers" group.

  By default the role should be pre-configured in vault in such a way that it has 
  "O=system:bootstrappers" and can be used as a client cert. This tool then needs 
  permissions in vault to issue a cert with that role.

  Alternatively this tool can use the sign-verbatim endpoint, but it is 
  discoraged as it requires giving access to the sign-verbatim endpoint to this 
  tool, which is a lot of power.

  Complete documentation of the RBAC required to have the generated certs work 
  can be found here:
  https://kubernetes.io/docs/reference/command-line-tools-reference/kubelet-tls-bootstrapping/

```
k8s-vault-csr bootstrap [flags]
```

### Options

```
      --approle-auth-mount string             name of the approle auth mount in vault
      --approle-auth-roleid string            vault role id to use when authenticating with an approle
      --approle-auth-secretid string          vault secret id to use when authenticating with an approle
  -h, --help                                  help for bootstrap
      --kubernetes-auth-mount string          name of the kubernetes auth mount in vault (default "kubernetes")
      --kubernetes-auth-role string           role to use when authenticating with vault using the service token
      --kubernetes-auth-token-file string     file to load service token from (default "/var/run/secrets/kubernetes.io/serviceaccount")
      --node-name string                      node name to use in the bootstrap certificate
      --output-kubeconfig-insecure            allow insecure certificates for the apiserver
      --output-kubeconfig-master-url string   url of the apiserver
      --output-kubeconfig-path string         path to write kubeconfig to
      --vault-address string                  vault server address
      --vault-auth string                     method to use for vault auth (kubernetes|approle)
      --vault-pki-mount string                specify the pki mount to use to generate certificates (default "pki")
      --vault-pki-role string                 specify role to use, only ttl is used from the role
      --vault-pki-sign-verbatim string        use sign-verbatim to create the bootstrap certificate
      --vault-pki-ttl string                  ttl of the bootstrap certificate (default "1h")
```

### Options inherited from parent commands

```
      --alsologtostderr                  log to standard error as well as files
      --log-flush-frequency duration     Maximum number of seconds between log flushes (default 5s)
      --log_backtrace_at traceLocation   when logging hits line file:N, emit a stack trace (default :0)
      --log_dir string                   If non-empty, write log files in this directory
      --logtostderr                      log to standard error instead of files (default true)
      --stderrthreshold severity         logs at or above this threshold go to stderr (default 2)
  -v, --v Level                          log level for V logs
      --vmodule moduleSpec               comma-separated list of pattern=N settings for file-filtered logging
```

### SEE ALSO

* [k8s-vault-csr](k8s-vault-csr.md)	 - tools for managing kubernetes certs with vault

###### Auto generated by spf13/cobra on 27-Aug-2018