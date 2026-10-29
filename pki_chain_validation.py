#!/usr/bin/env python3
"""
PKI Trust Chain Validation Simulator
Root CA -> Intermediate CA -> End-user certificate

Generates a real three-level X.509 chain and validates the end-user
certificate by checking, at every link:
  1. Issuer name of child == Subject name of parent
  2. Child's signature verifies under parent's public key
  3. Validity period (not before / not after)
  4. Parent is a CA (BasicConstraints CA=TRUE, KeyUsage keyCertSign)
  5. Path-length constraint is respected
  6. The chain terminates in a self-signed root present in the trust store
"""

import datetime as dt
from dataclasses import dataclass, field

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID


# --------------------------------------------------------------------------
# Certificate issuance (the "simulation" side)
# --------------------------------------------------------------------------
def make_name(common_name: str, org: str = "PKI Demo") -> x509.Name:
    return x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])


def issue_cert(subject_name, subject_key, issuer_name, issuer_key, *,
               is_ca, path_length=None, days=365,
               not_before=None, san_dns=None):
    """Issue a certificate signed with issuer_key."""
    now = not_before or dt.datetime.now(dt.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject_name)
        .issuer_name(issuer_name)
        .public_key(subject_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + dt.timedelta(days=days))
        .add_extension(
            x509.BasicConstraints(ca=is_ca, path_length=path_length),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=is_ca,
                crl_sign=is_ca,
                content_commitment=False, key_encipherment=not is_ca,
                data_encipherment=False, key_agreement=False,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
    )
    if san_dns:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(d) for d in san_dns]),
            critical=False,
        )
    return builder.sign(issuer_key, hashes.SHA256())


@dataclass
class PKI:
    root_key: rsa.RSAPrivateKey
    root_cert: x509.Certificate
    inter_key: rsa.RSAPrivateKey
    inter_cert: x509.Certificate
    leaf_key: rsa.RSAPrivateKey
    leaf_cert: x509.Certificate


def build_pki() -> PKI:
    new_key = lambda: rsa.generate_private_key(public_exponent=65537, key_size=2048)

    # Root CA: self-signed, may sign one level of intermediates (pathlen=1)
    root_key = new_key()
    root_name = make_name("Demo Root CA")
    root_cert = issue_cert(root_name, root_key, root_name, root_key,
                           is_ca=True, path_length=1, days=3650)

    # Intermediate CA: signed by Root, can only sign end-entities (pathlen=0)
    inter_key = new_key()
    inter_name = make_name("Demo Intermediate CA")
    inter_cert = issue_cert(inter_name, inter_key, root_name, root_key,
                            is_ca=True, path_length=0, days=1825)

    # End-user: signed by Intermediate
    leaf_key = new_key()
    leaf_name = make_name("alice@example.com")
    leaf_cert = issue_cert(leaf_name, leaf_key, inter_name, inter_key,
                           is_ca=False, days=365, san_dns=["alice.example.com"])

    return PKI(root_key, root_cert, inter_key, inter_cert, leaf_key, leaf_cert)


# --------------------------------------------------------------------------
# Chain validation (the core of the exercise)
# --------------------------------------------------------------------------
class ChainValidationError(Exception):
    pass


@dataclass
class ValidationResult:
    valid: bool
    log: list = field(default_factory=list)


def verify_signature(child: x509.Certificate, parent: x509.Certificate) -> None:
    """Verify that `child` was signed by the private key matching `parent`."""
    pub = parent.public_key()
    try:
        if isinstance(pub, rsa.RSAPublicKey):
            pub.verify(child.signature, child.tbs_certificate_bytes,
                       padding.PKCS1v15(), child.signature_hash_algorithm)
        elif isinstance(pub, ec.EllipticCurvePublicKey):
            pub.verify(child.signature, child.tbs_certificate_bytes,
                       ec.ECDSA(child.signature_hash_algorithm))
        else:
            raise ChainValidationError(f"Unsupported key type: {type(pub).__name__}")
    except InvalidSignature:
        raise ChainValidationError("signature does not verify against issuer's public key")


def check_validity(cert: x509.Certificate, at: dt.datetime) -> None:
    if at < cert.not_valid_before_utc:
        raise ChainValidationError(f"not yet valid (starts {cert.not_valid_before_utc:%Y-%m-%d})")
    if at > cert.not_valid_after_utc:
        raise ChainValidationError(f"expired (ended {cert.not_valid_after_utc:%Y-%m-%d})")


def check_is_ca(cert: x509.Certificate) -> x509.BasicConstraints:
    try:
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
        ku = cert.extensions.get_extension_for_class(x509.KeyUsage).value
    except x509.ExtensionNotFound:
        raise ChainValidationError("missing BasicConstraints/KeyUsage; cannot act as CA")
    if not bc.ca:
        raise ChainValidationError("BasicConstraints CA=FALSE; not allowed to issue certificates")
    if not ku.key_cert_sign:
        raise ChainValidationError("KeyUsage lacks keyCertSign")
    return bc


def validate_chain(leaf: x509.Certificate,
                   intermediates: list,
                   trust_store: list,
                   at: dt.datetime = None) -> ValidationResult:
    """
    Build a path leaf -> intermediate(s) -> trusted root, then validate each link.
    Returns a ValidationResult with a step-by-step log.
    """
    at = at or dt.datetime.now(dt.timezone.utc)
    res = ValidationResult(valid=False)
    log = res.log.append
    cn = lambda c: c.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value

    try:
        # ---- 1. Path building: walk issuer names until we hit a trust anchor
        pool = list(intermediates)
        path = [leaf]
        current = leaf
        while True:
            anchor = next((r for r in trust_store if r.subject == current.issuer), None)
            if anchor is not None:
                path.append(anchor)
                break
            nxt = next((c for c in pool if c.subject == current.issuer
                        and c is not current), None)
            if nxt is None:
                # Distinguish: is the issuer a self-signed root (untrusted) or truly missing?
                self_signed = (current.issuer == current.subject)
                if self_signed:
                    raise ChainValidationError(
                        f"root CA '{cn(current)}' is self-signed but NOT present "
                        f"in the trust store — chain is untrusted")
                else:
                    raise ChainValidationError(
                        f"cannot find issuer '{current.issuer.rfc4514_string()}' "
                        f"for '{cn(current)}' — chain is incomplete")
            pool.remove(nxt)
            path.append(nxt)
            current = nxt
            if len(path) > 10:
                raise ChainValidationError("path too long / loop detected")

        log("Path built: " + "  ->  ".join(cn(c) for c in path))

        # ---- 2. Validate each (child, parent) link
        for i in range(len(path) - 1):
            child, parent = path[i], path[i + 1]
            tag = f"[{cn(child)} <- {cn(parent)}]"

            if child.issuer != parent.subject:
                raise ChainValidationError(f"{tag} issuer/subject name mismatch")
            log(f"{tag} issuer name matches parent subject")

            verify_signature(child, parent)
            log(f"{tag} signature VERIFIED with parent's public key")

            check_validity(child, at)
            log(f"{tag} child within validity period")

            bc = check_is_ca(parent)
            log(f"{tag} parent is a CA (CA=TRUE, keyCertSign)")

            # pathlen = max number of CA certs allowed *below* this parent
            # (excluding the leaf). CAs between parent and leaf = i.
            if bc.path_length is not None and i > bc.path_length:
                raise ChainValidationError(
                    f"{tag} path length constraint ({bc.path_length}) exceeded")
            log(f"{tag} path-length constraint OK "
                f"(pathlen={bc.path_length}, CAs below={i})")

        # ---- 3. Validate the trust anchor itself
        root = path[-1]
        verify_signature(root, root)
        log(f"[{cn(root)}] self-signature VERIFIED")
        check_validity(root, at)
        log(f"[{cn(root)}] within validity period")
        if root not in trust_store:
            raise ChainValidationError("root not in trust store")
        log(f"[{cn(root)}] present in trust store -> TRUSTED")

        res.valid = True
        log("RESULT: chain is VALID")
    except ChainValidationError as e:
        log(f"FAILURE: {e}")
        log("RESULT: chain is INVALID")
    return res


# --------------------------------------------------------------------------
# Demo
# --------------------------------------------------------------------------
def show(title, result):
    print(f"\n=== {title} ===")
    for line in result.log:
        print("  " + line)


def tamper(cert: x509.Certificate) -> x509.Certificate:
    """Flip one byte inside the signature to simulate a forged/modified cert."""
    der = bytearray(cert.public_bytes(Encoding.DER))
    der[-5] ^= 0xFF  # signature is the last element of the DER structure
    return x509.load_der_x509_certificate(bytes(der))


def main():
    pki = build_pki()
    trust = [pki.root_cert]
    print("Generated chain: Demo Root CA -> Demo Intermediate CA -> alice@example.com")

    # 1. Happy path
    show("Test 1: valid chain",
         validate_chain(pki.leaf_cert, [pki.inter_cert], trust))

    # 2. Tampered end-user certificate
    show("Test 2: tampered end-user certificate",
         validate_chain(tamper(pki.leaf_cert), [pki.inter_cert], trust))

    # 3. Rogue intermediate (signed by an attacker's key, same name)
    evil_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    evil_name = make_name("Evil Root CA")
    evil_root = issue_cert(evil_name, evil_key, evil_name, evil_key,
                           is_ca=True, path_length=1)
    fake_inter = issue_cert(pki.inter_cert.subject, pki.inter_key,
                            pki.root_cert.subject, evil_key,  # wrong signer
                            is_ca=True, path_length=0)
    show("Test 3: intermediate signed by an impostor (claims to be from real Root)",
         validate_chain(pki.leaf_cert, [fake_inter], trust))

    # 4. Root not in trust store
    show("Test 4: root CA not trusted",
         validate_chain(pki.leaf_cert, [pki.inter_cert], []))

    # 5. Expired validation time
    future = dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=400)
    show("Test 5: end-user certificate expired (checked 400 days from now)",
         validate_chain(pki.leaf_cert, [pki.inter_cert], trust, at=future))

    # 6. Missing intermediate
    show("Test 6: missing intermediate certificate",
         validate_chain(pki.leaf_cert, [], trust))

    # 7. End-user cert abused as a CA
    sub_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    sub_cert = issue_cert(make_name("sub.example.com"), sub_key,
                          pki.leaf_cert.subject, pki.leaf_key, is_ca=False)
    show("Test 7: end-user certificate used to issue another certificate",
         validate_chain(sub_cert, [pki.leaf_cert, pki.inter_cert], trust))


if __name__ == "__main__":
    main()