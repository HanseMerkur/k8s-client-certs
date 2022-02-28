import sys
from typing import List
import base64

from yaml import dump, Dumper
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID
from pykube import HTTPClient, KubeConfig
from pykube.exceptions import KubernetesError, ObjectDoesNotExist

from clientcerts.kubernetes import CertificateSigningRequest


class ClientCertificate:
    def _generate_key(self, bits: int = 2048) -> RSAPrivateKey:
        """
        Create a simple RSA private key
        """
        return rsa.generate_private_key(public_exponent=65537, key_size=bits)

    def generate_csr(
        self, user: str, groups: List[str]
    ) -> x509.CertificateSigningRequest:
        """
        Generate a Kubernetes CertificateSigningRequest-specific request using the provided key
        """

        builder = x509.CertificateSigningRequestBuilder()
        subject = [x509.NameAttribute(NameOID.COMMON_NAME, user)]
        for group in groups:
            subject.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, group))
        builder = builder.subject_name(x509.Name(subject))
        request = builder.sign(self.key, hashes.SHA256())
        return request

    def __init__(self, args):
        self.apiserver = args.apiserver
        self.user = args.user
        self.groups = args.groups
        self.expiry = args.expiry
        self.path = args.file

        self.api = HTTPClient(KubeConfig.from_file())
        self.key = self._generate_key(2048)

    def create_csr(self) -> CertificateSigningRequest:
        """
        Create and Approve the CertificateSigningRequest on the kubernetes cluster

        If one exist with the same name delete it first as we cannot ensure that we have the private key the CSR was signed with.
        """

        csr = self.generate_csr(self.user, self.groups)
        try:
            try:
                # Delete if a certificate exists. Can't use it without the private key
                k8s_csr = CertificateSigningRequest.objects(self.api).get_by_name(
                    self.user
                )
                k8s_csr.delete()
            except ObjectDoesNotExist:
                pass
            finally:
                k8s_csr = CertificateSigningRequest.new(
                    self.api, self.user, csr, expiry=self.expiry
                )
            k8s_csr.create()
            k8s_csr.approve()
        except KubernetesError as e:
            print(e.with_traceback())
            sys.exit(1)
        return k8s_csr

    def write_kubeconfig(self, k8s_csr):
        """
        Write out the kubeconfig file
        """

        key_pem = self.key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
        kubeconfig = {
            "apiVersion": "v1",
            "kind": "Config",
            "clusters": [
                {
                    "name": "default",
                    "cluster": {
                        "insecure-skip-tls-verify": "true",
                        "server": self.apiserver,
                    },
                }
            ],
            "contexts": [
                {
                    "name": "default",
                    "context": {
                        "cluster": "default",
                        "namespace": "default",
                        "user": "default",
                    },
                }
            ],
            "current-context": "default",
            "users": [
                {
                    "name": "default",
                    "user": {
                        "client-certificate-data": k8s_csr.certificate,
                        "client-key-data": base64.b64encode(key_pem).decode(
                            "utf-8"
                        ),
                    },
                }
            ],
        }
        with open(self.path, "w+") as f:
            f.write(dump(kubeconfig, Dumper=Dumper))
