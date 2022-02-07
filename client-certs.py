import base64
import json
from inspect import cleandoc

from OpenSSL import crypto
import requests
from kubernetes import client, config
from kubernetes.client import configuration
from kubernetes.client.exceptions import ApiException

def generate_key(bits: int = 2048) -> crypto.PKey:
    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, bits)

    return key

def generate_csr(key: crypto.PKey, cn, o: str) -> crypto.X509Req:
    req = crypto.X509Req()
    req.get_subject().commonName = cn
    req.get_subject().organizationName = o
    req.set_pubkey(key)
    req.sign(key, "sha256")

    return req

def download_ca():
    # Replace with: https://stackoverflow.com/a/58246407/294643
    ca = requests.get("https://s3.hanse-merkur.de/wellerl/ca/Hansemerkur-CA.crt")
    sub_ca = requests.get("https://s3.hanse-merkur.de/wellerl/ca/Hansemerkur-SubCA.crt")

    return ca.content + sub_ca.content

def create_signing_request(csr: crypto.X509Req, user, group: str) -> client.V1CertificateSigningRequest:
    """
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
    """

    csr_api = client.CertificatesV1Api()
    try:
        resp = csr_api.read_certificate_signing_request(k8s_csr.metadata.name)
    except ApiException as e:
        print(json.loads(e.body)["message"])

    return resp.status.certificate


if __name__ == "__main__":
    user = "wellerl"
    group = "cluster-admin"
    server = "https://api.int.hcp.hanse-merkur.de:6443"

    config.load_kube_config()
    configuration.Configuration().verify_ssl = False

    key = generate_key(2048)
    csr = generate_csr(key, user, group)

    k8s_csr = create_signing_request(csr, user, group)
    approve_signing_request(k8s_csr)
    k8s_cert = receive_certificate(k8s_csr)

    ca = download_ca()

    with open("kubeconfig", "w+") as f:
        f.write(cleandoc(
            f"""
            apiVersion: v1
            kind: Config
            clusters:
            - cluster:
                #certificate-authority-data: {base64.b64encode(ca).decode('utf-8')}
                insecure-skip-tls-verify: true
                server: {server}
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
