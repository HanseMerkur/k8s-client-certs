import base64
import json

from pykube.objects import APIObject
from pykube import HTTPClient

from cryptography import x509
from cryptography.hazmat.primitives import serialization



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
                        "reason": "KubenavApprove",
                    }
                ]
            }
        }
        r = self.api.patch(
            **self.api_kwargs(
                operation="approval",
                headers={"Content-Type": "application/merge-patch+json"},
                data=json.dumps(patch_status),
            )
        )
        self.api.raise_for_status(r)
        self.set_obj(r.json())

    @staticmethod
    def new(
        api: HTTPClient,
        user: str,
        csr: x509.CertificateSigningRequest,
        expiry: str = "86400",
    ):
        """
        Create a kubernetes CertificateSigningRequest using the standard client handler on the apiserver
        The CSR has to be a valid X509 CSR with CN being the username and O being the group in kubernetes

        :param expiry will only be used by kubelet > v1.22
        """
        csr_b64 = base64.b64encode(csr.public_bytes(serialization.Encoding.PEM)).decode(
            "utf-8"
        )
        obj = {
            "apiVersion": "certificates.k8s.io/v1",
            "kind": "CertificateSigningRequest",
            "metadata": {"name": user},
            "spec": {
                "request": csr_b64,
                "expirationSeconds": int(expiry or "86400"),
                "signerName": "kubernetes.io/kube-apiserver-client",
                "usages": ["client auth"],
            },
        }
        return CertificateSigningRequest(api, obj)

