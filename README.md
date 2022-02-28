# k8s-client-certs
Python CLI for creating automatically signed kubernetes client certificates

```bash
usage: clientcerts [-h] [-u USER] [-g [GROUPS]] [-e EXPIRY] [--ca-certificate CA_CERTIFICATE] [-f FILE] apiserver

Create a kubeconfig using automatically approved client certificates. Your currently active KUBECONFIG needs to be
able to approve CertificateSigningRequests

positional arguments:
  apiserver             The kube-apiserver URL to use with the client certificate e.g. https://cluster.domain.tld

optional arguments:
  -h, --help            show this help message and exit
  -u USER, --user USER  Mapped kubernetes username, can be used for rbac
  -g [GROUPS], --groups [GROUPS]
                        1..n groups for rbac mappings
  -e EXPIRY, --expiry EXPIRY
                        Validity of the client certificate in seconds. Requires k8s >= 1.22
  --ca-certificate CA_CERTIFICATE
                        CA to load for connecting to the kubernetes Cluster
  -f FILE, --file FILE  Output path for the client certificate based kubeconfig. Existing files will be overwritten
```
