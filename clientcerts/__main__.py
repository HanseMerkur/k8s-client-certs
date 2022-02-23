#!/usr/bin/env python3
import os
import argparse
from inspect import cleandoc

from clientcerts.app import ClientCertificate

DESCRIPTION ="""
Create a kubeconfig using automatically approved client certificates.

Your currently active KUBECONFIG needs to be able to approve CertificateSigningRequests
"""

def main():
    """
    Wrapper for console_scripts
    """

    # Workaround for missing Hanse CA certificates in certifi trustchain
    os.environ["REQUESTS_CA_BUNDLE"] = "/etc/ssl/certs/ca-certificates.crt"

    # Workaround for concatenated KUBECONFIG files. pykube is missing the support
    if ":" in os.environ["KUBECONFIG"]:
        os.environ["KUBECONFIG"] = os.environ["KUBECONFIG"].split(":")[0]

    parser = argparse.ArgumentParser(
        description=cleandoc(DESCRIPTION)
    )
    parser.add_argument(
        "-u", "--user", help="Mapped kubernetes username, can be used for rbac"
    )
    parser.add_argument(
        "-g",
        "--groups",
        nargs="?",
        action="append",
        help="1..n groups for rbac mappings",
    )
    parser.add_argument(
        "-e",
        "--expiry",
        help="Validity of the client certificate in seconds. Requires k8s >= 1.22",
    )
    parser.add_argument(
        "--ca-certificate",
        default="/etc/ssl/certs/ca-certificates.crt",
        help="CA to load for connecting to the kubernetes Cluster"
    )
    parser.add_argument(
        "-f",
        "--file",
        default="kubeconfig",
        help="Output path for the client certificate based kubeconfig. Existing files will be overwritten"
    )
    parser.add_argument(
        "apiserver", help="The kube-apiserver URL to use with the client certificate e.g. https://cluster.domain.tld"
    )

    args = parser.parse_args()

    # Let requests load your custom vendor ca-certificates
    os.environ["REQUESTS_CA_BUNDLE"] = args.ca_certificate

    # Workaround for concatenated KUBECONFIG files. pykube is missing the support
    if ":" in os.environ["KUBECONFIG"]:
        os.environ["KUBECONFIG"] = os.environ["KUBECONFIG"].split(":")[0]

    client_certificate = ClientCertificate(args)
    csr = client_certificate.create_csr()
    client_certificate.write_kubeconfig(csr)

if __name__ == '__main__':
    main()