import base64
import os
import sys
from inspect import cleandoc
import socket
import argparse
import json

from OpenSSL import crypto, SSL
from pykube import HTTPClient, KubeConfig
from pykube.objects import APIObject
from pykube.exceptions import KubernetesError, ObjectDoesNotExist

class CertificateSigningRequest(APIObject):
    version = "certificates.k8s.io/v1"
    endpoint = "certificatesigningrequests"
    kind = "CertificateSigningRequest"

    @property
    def certificate(self):
        self.reload()
        return self.obj["status"]["certificate"]

    def approve(self):
        """
        Automatically approve the CSR using the API.
        A certificate is approved by adding a status condition of type Approval

        The patch can only be applied to the approval operation endpoint
        """
        patch_status = {
            "status": {
                "conditions": [
                    {
                        "message": "Approved by automatic kubenav script",
                        "status": "True",
                        "type": "Approved",
                        "reason": "KubenavApprove"
                    }
                ]
            }
        }
        r = self.api.patch(**self.api_kwargs(
            operation="approval",
            headers={"Content-Type": "application/merge-patch+json"},
            data=json.dumps(patch_status),
        ))
        self.api.raise_for_status(r)
        self.set_obj(r.json()) 

    @staticmethod
    def new(api: HTTPClient, user, group: str, csr: crypto.X509Req):
        """
        Create a kubernetes CertificateSigningRequest using the standard client handler on the apiserver
        The CSR has to be a valid X509 CSR with CN being the username and O being the group in kubernetes
        """
        csr_b64 = base64.b64encode(crypto.dump_certificate_request(crypto.FILETYPE_PEM, csr)).decode('utf-8')
        obj = {
            "apiVersion": "certificates.k8s.io/v1",
            "kind": "CertificateSigningRequest",
            "metadata": {
                "name": user
            },
            "spec": {
                "username": user,
                "groups": [group],
                "request": csr_b64,
                "signerName": "kubernetes.io/kube-apiserver-client",
                "usages": ["client auth"]
            }
        }
        return CertificateSigningRequest(api, obj)


def generate_key(bits: int = 2048) -> crypto.PKey:
    """
    Create a simple RSA private key
    """
    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, bits)

    return key

def generate_csr(key: crypto.PKey, user: str, group: str) -> crypto.X509Req:
    """
    Generate a Kubernetes CertificateSigningRequest-specific request using the provided key
    """
    req = crypto.X509Req()
    req.get_subject().commonName = user
    req.get_subject().organizationName = group
    req.get_subject().organizationalUnitName = group
    req.set_pubkey(key)
    req.sign(key, "sha256")

    return req

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Create a kubeconfig using automatically approved client certificates")
    parser.add_argument("-u", "--user", help="Mapped kubernetes username, can be used for rbac")
    parser.add_argument("-g", "--group", nargs="?", help="1..n groups for rbac mappings") #  action="append",
    parser.add_argument("apiserver", help="The kube-apiserver URL e.g. https://cluster.domain.tld")

    args = parser.parse_args()
    print(args)

    # Workaround for missing Hanse CA certificates in certifi trustchain
    os.environ["REQUESTS_CA_BUNDLE"] = "/etc/ssl/certs/ca-certificates.crt"

    # Workaround for concatenated KUBECONFIG files. pykube is missing the support
    if ":" in os.environ["KUBECONFIG"]:
        os.environ["KUBECONFIG"] = os.environ["KUBECONFIG"].split(":")[0]
    api = HTTPClient(KubeConfig.from_file())

    key = generate_key(2048)
    csr = generate_csr(key, args.user, args.group)

    try:
        try:
            # Delete if a certificate exists. Can't use it without the private key
            k8s_csr = CertificateSigningRequest.objects(api).get_by_name(args.user)
            k8s_csr.delete()
        except ObjectDoesNotExist:
            pass
        finally:
            k8s_csr = CertificateSigningRequest.new(api, args.user, args.group, csr)
        k8s_csr.create()
        k8s_csr.approve()
    except KubernetesError as e:
        print(e.with_traceback())
        sys.exit(1)

    with open("kubeconfig", "w+") as f:
        f.write(cleandoc(
            f"""
            apiVersion: v1
            kind: Config
            clusters:
            - cluster:
                insecure-skip-tls-verify: true
                server: {args.apiserver}
              name: default
            contexts:
            - context:
                cluster: default
                namespace: default
                user: default
              name: default
            current-context: default
            users:
            - name: default
              user:
                client-certificate-data: {k8s_csr.certificate}
                client-key-data: {base64.b64encode(crypto.dump_privatekey(crypto.FILETYPE_PEM, key)).decode('utf-8')}
            """
            )
        )
