"""
Educational script for testing AES and RSA encryption/decryption.
This demonstrates symmetric (AES) and asymmetric (RSA) encryption concepts.
"""

from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64


def aes_encrypt(plaintext, key):
    """Encrypt plaintext using AES in CBC mode."""
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
    return base64.b64encode(cipher.iv + ciphertext).decode()


def aes_decrypt(encrypted_data, key):
    """Decrypt AES encrypted data."""
    encrypted_data = base64.b64decode(encrypted_data)
    iv = encrypted_data[:AES.block_size]
    ciphertext = encrypted_data[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return plaintext.decode()


def rsa_encrypt(plaintext, public_key):
    """Encrypt plaintext using RSA public key."""
    cipher = PKCS1_OAEP.new(public_key)
    ciphertext = cipher.encrypt(plaintext.encode())
    return base64.b64encode(ciphertext).decode()


def rsa_decrypt(encrypted_data, private_key):
    """Decrypt RSA encrypted data using private key."""
    encrypted_data = base64.b64decode(encrypted_data)
    cipher = PKCS1_OAEP.new(private_key)
    plaintext = cipher.decrypt(encrypted_data)
    return plaintext.decode()


def main():
    print("=== Encryption/Decryption Educational Tool ===\n")
    
    # AES Demonstration
    print("--- AES (Symmetric Encryption) ---")
    aes_key = get_random_bytes(16)  # 128-bit key
    message = "Hello, this is a secret message!"
    
    print(f"Original message: {message}")
    encrypted_aes = aes_encrypt(message, aes_key)
    print(f"AES Encrypted: {encrypted_aes}")
    decrypted_aes = aes_decrypt(encrypted_aes, aes_key)
    print(f"AES Decrypted: {decrypted_aes}")
    print(f"Match: {message == decrypted_aes}\n")
    
    # RSA Demonstration
    print("--- RSA (Asymmetric Encryption) ---")
    rsa_key = RSA.generate(2048)
    public_key = rsa_key.publickey()
    
    short_message = "Secret data"  # RSA can only encrypt small messages
    print(f"Original message: {short_message}")
    encrypted_rsa = rsa_encrypt(short_message, public_key)
    print(f"RSA Encrypted: {encrypted_rsa}")
    decrypted_rsa = rsa_decrypt(encrypted_rsa, rsa_key)
    print(f"RSA Decrypted: {decrypted_rsa}")
    print(f"Match: {short_message == decrypted_rsa}\n")
    
    # Interactive mode
    print("--- Try it yourself! ---")
    user_input = input("Enter a message to encrypt (or press Enter to skip): ")
    
    if user_input:
        print("\n1. AES Encryption:")
        aes_result = aes_encrypt(user_input, aes_key)
        print(f"Encrypted: {aes_result}")
        print(f"Decrypted: {aes_decrypt(aes_result, aes_key)}")
        
        if len(user_input) < 200:  # RSA has size limitations
            print("\n2. RSA Encryption:")
            rsa_result = rsa_encrypt(user_input, public_key)
            print(f"Encrypted: {rsa_result}")
            print(f"Decrypted: {rsa_decrypt(rsa_result, rsa_key)}")
        else:
            print("\n2. RSA: Message too long for RSA encryption")


if __name__ == "__main__":
    # Note: Install required library with: pip install pycryptodome
    main()
