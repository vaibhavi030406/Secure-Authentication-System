import bcrypt

from crypto_utils import create_auth_token, generate_auth_nonce
from rsa_utils import decrypt_data, encrypt_data, load_keys


def test_bcrypt():
    password = "MyPassword123!"
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    assert bcrypt.checkpw(password.encode(), hashed)
    assert not bcrypt.checkpw(b"WrongPassword123!", hashed)
    print("[PASS] bcrypt password hashing and verification")


def test_sha256_token():
    username = "student"
    nonce = generate_auth_nonce()
    token = create_auth_token(username, nonce)
    assert len(token) == 64
    assert token == create_auth_token(username, nonce)
    print("[PASS] SHA-256 authentication token generation")


def test_rsa_round_trip():
    private_key, public_key = load_keys()
    message = "Secure Authentication System"
    encrypted = encrypt_data(message, public_key)
    decrypted = decrypt_data(encrypted, private_key)
    assert decrypted == message
    assert encrypted != message.encode()
    print("[PASS] RSA-2048 encryption and decryption")


def test_integrated_flow():
    username = "student"
    nonce = generate_auth_nonce()
    token = create_auth_token(username, nonce)
    private_key, public_key = load_keys()
    encrypted = encrypt_data(token, public_key)
    decrypted = decrypt_data(encrypted, private_key)
    assert decrypted == create_auth_token(username, nonce)
    print("[PASS] Integrated bcrypt + SHA-256 + RSA authentication flow")


if __name__ == "__main__":
    test_bcrypt()
    test_sha256_token()
    test_rsa_round_trip()
    test_integrated_flow()
    print("\nAll cryptography tests passed.")
