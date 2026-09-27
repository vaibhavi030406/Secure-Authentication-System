from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

BASE_DIR = Path(__file__).resolve().parent
PRIVATE_KEY_FILE = BASE_DIR / "private_key.pem"
PUBLIC_KEY_FILE = BASE_DIR / "public_key.pem"


def generate_keys():
    """Generate an RSA-2048 key pair if the key files do not exist."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()

    PRIVATE_KEY_FILE.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )

    PUBLIC_KEY_FILE.write_bytes(
        public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )

    print("RSA-2048 key pair generated successfully!")


def load_keys():
    """Load the RSA key pair, generating it when necessary."""
    if not PRIVATE_KEY_FILE.exists() or not PUBLIC_KEY_FILE.exists():
        generate_keys()

    private_key = serialization.load_pem_private_key(
        PRIVATE_KEY_FILE.read_bytes(),
        password=None,
    )

    public_key = serialization.load_pem_public_key(
        PUBLIC_KEY_FILE.read_bytes()
    )

    return private_key, public_key


def encrypt_data(data, public_key):
    """Encrypt text using RSA-OAEP with SHA-256."""
    return public_key.encrypt(
        data.encode("utf-8"),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def decrypt_data(encrypted_data, private_key):
    """Decrypt RSA-OAEP ciphertext using the private key."""
    decrypted = private_key.decrypt(
        encrypted_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return decrypted.decode("utf-8")


if __name__ == "__main__":
    private_key, public_key = load_keys()

    message = "Secure Authentication System"
    encrypted = encrypt_data(message, public_key)
    decrypted = decrypt_data(encrypted, private_key)

    print("\nOriginal Message:")
    print(message)
    print("\nRSA-2048 Encrypted Message (hex):")
    print(encrypted.hex())
    print("\nDecrypted Message:")
    print(decrypted)
