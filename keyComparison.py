#!/usr/bin/env python3
"""
compare_keys.py

Generate RSA and ECC keys and print their bit sizes and encoded lengths
so students can observe differences in key length and on-disk/transit size.

Requires: cryptography (pip install cryptography)
"""

from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import serialization
import sys

def rsa_info(bits: int):
    # Generate RSA private key
    key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    priv_der = key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_der = key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    # RSA "size" is modulus size in bits
    modulus_size = key.key_size
    return {
        "type": "RSA",
        "param": bits,
        "modulus_bits": modulus_size,
        "private_der_len": len(priv_der),
        "public_der_len": len(pub_der),
    }

def ecc_info(curve):
    # Generate ECC private key on given curve
    key = ec.generate_private_key(curve())
    priv_der = key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_der = key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    # ECC "size" can be reported by curve key size in bits (field size)
    curve_name = key.curve.name
    curve_size = key.curve.key_size
    return {
        "type": "ECC",
        "param": curve_name,
        "curve_bits": curve_size,
        "private_der_len": len(priv_der),
        "public_der_len": len(pub_der),
    }


def print_row(info):
    if info["type"] == "RSA":
        print(f"RSA {info['param']:>4} bits -- modulus_bits={info['modulus_bits']:>4} "
              f"| private DER={info['private_der_len']:>5} bytes | public DER={info['public_der_len']:>5} bytes")
    else:
        print(f"ECC {info['param']:>9} -- curve_bits={info['curve_bits']:>4} "
              f"| private DER={info['private_der_len']:>5} bytes | public DER={info['public_der_len']:>5} bytes")


def main():
    print("Generating keys (may take a few seconds)...\n")
    results = []
    # Common RSA sizes to compare
    for bits in (1024, 2048, 3072, 4096):
        try:
            results.append(rsa_info(bits))
        except ValueError:
            # some environments may refuse too-small keys
            pass

    # Common NIST curves
    curves = [ec.SECP256R1, ec.SECP384R1, ec.SECP521R1]
    for c in curves:
        results.append(ecc_info(c))

    print("Key type and parameters -- encoded DER sizes")
    print("-" * 72)
    for r in results:
        print_row(r)

    # Simple observation printed for students to notice
    print("\nObservation hints:")
    print(" - ECC curve_bits are much smaller than RSA modulus bits for comparable security.")
    print(" - DER-encoded key sizes (bytes) reflect smaller ECC keys in storage/transit.")
    print(" - Smaller key material can mean faster operations and less bandwidth, but")
    print("   algorithm and implementation details (sign/verify/encrypt) also affect performance.")


if __name__ == "__main__":
    main()