import base64
import json
from inspect import cleandoc
import socket
import argparse
import sys
from typing import List

from OpenSSL import crypto, SSL
from kubernetes import client, config
from kubernetes.client import configuration
from kubernetes.client.exceptions import ApiException

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
    req.get_subject().organizationalUnitName = group
    req.set_pubkey(key)
    req.sign(key, "sha256")

    return req

def download_ca(url: str) -> str:
    """
    Download the Certificate Authority Chain from the provided URL.
    The chain can be used to enrich the kubeconfig
    """

    server = url.lstrip("https://").split(":")
    hostname = server[0]
    port = int(server[1]) if len(server) == 2 else 443

    context = SSL.Context(method=SSL.TLS_METHOD)

    conn = SSL.Connection(context, socket=socket.socket(socket.AF_INET, socket.SOCK_STREAM))
    conn.settimeout(5)
    conn.connect((hostname, port))
    conn.setblocking(1)
    conn.do_handshake()
    conn.set_tlsext_host_name(hostname.encode())

    if len(conn.get_peer_cert_chain()) < 1:
        raise Exception("No CA certificate available")

    ca_chain = ""
    for cert in conn.get_peer_cert_chain():
        ca_chain += crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode("utf-8").rstrip()

    return ca_chain

def create_signing_request(csr: crypto.X509Req, user: str, group: str) -> client.V1CertificateSigningRequest:
    """
    Create a kubernetes CertificateSigningRequest using the standard client handler on the apiserver
    The CSR has to be a valid X509 CSR with CN being the username and O being the group in kubernetes
    """

    csr_b64 = base64.b64encode(crypto.dump_certificate_request(crypto.FILETYPE_PEM, csr)).decode('utf-8')

    csr_spec = client.V1CertificateSigningRequestSpec(
        username=user,
        groups=[group],
        request=csr_b64,
        signer_name="kubernetes.io/kube-apiserver-client",
        usages=["client auth"]
    )

    csr_req = client.V1CertificateSigningRequest(
        api_version="certificates.k8s.io/v1",
        kind="CertificateSigningRequest",
        metadata = {"name": user},
        spec = csr_spec
    )
    
    csr_api = client.CertificatesV1Api()
    try:
        resp = csr_api.create_certificate_signing_request(csr_req)
    except ApiException as e:
        print(json.loads(e.body)["message"])
    return resp

def approve_signing_request(k8s_csr: client.V1CertificateSigningRequest):
    """
    Automatically approve the CSR using the API.
    A certificate is approved by adding a status condition of type Approval
    """

    condition = client.V1CertificateSigningRequestCondition(
        message="Approved by automatic kubenav script",
        status='True',
        type="Approved",
        reason="KubenavApprove",
        last_transition_time=None,
        last_update_time=None,
    )
    status = client.V1CertificateSigningRequestStatus(conditions=[condition])
    k8s_csr.status = status
    csr_api = client.CertificatesV1Api()
    try:
        csr_api.patch_certificate_signing_request_approval(k8s_csr.metadata.name, body=k8s_csr)
    except ApiException as e:
        print(json.loads(e.body["message"]))

def receive_certificate(k8s_csr: client.V1CertificateSigningRequest) -> bytes:
    """
    Download the approved certificate which is saved in the CertificateSigningRequest status field
    """

    csr_api = client.CertificatesV1Api()
    try:
        resp = csr_api.read_certificate_signing_request(k8s_csr.metadata.name)
    except ApiException as e:
        print(json.loads(e.body)["message"])

    return resp.status.certificate


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Create a kubeconfig using automatically approved client certificates")
    parser.add_argument("-u", "--user", help="Mapped kubernetes username, can be used for rbac")
    parser.add_argument("-g", "--group", nargs="?", help="1..n groups for rbac mappings") #  action="append",
    parser.add_argument("apiserver", help="The kube-apiserver URL e.g. https://cluster.domain.tld")

    args = parser.parse_args()
    print(args)

    config.load_kube_config()
    configuration.Configuration().verify_ssl = False

    key = generate_key(2048)
    csr = generate_csr(key, args.user, args.group)

    k8s_csr = create_signing_request(csr, args.user, args.group)
    approve_signing_request(k8s_csr)
    k8s_cert = receive_certificate(k8s_csr)

    #ca = download_ca(server)
    # -> certificate-authority-data: {base64.b64encode(ca.encode('utf-8')).decode('utf-8')}

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
                client-certificate-data: {k8s_cert}
                client-key-data: {base64.b64encode(crypto.dump_privatekey(crypto.FILETYPE_PEM, key)).decode('utf-8')}
            """
            )
        )
