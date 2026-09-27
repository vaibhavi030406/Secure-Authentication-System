import hashlib
import secrets


def sha256_hash(data):
    """Return the SHA-256 hexadecimal digest of a string."""
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def generate_auth_nonce():
    """Generate a fresh random value for every successful login."""
    return secrets.token_hex(16)


def create_auth_token(username, nonce):
    """Create a SHA-256 authentication token from username + fresh nonce."""
    data = f"{username}|{nonce}"
    return sha256_hash(data)


if __name__ == "__main__":
    username = "student"
    nonce = generate_auth_nonce()
    token = create_auth_token(username, nonce)

    print("Username:", username)
    print("Random Nonce:", nonce)
    print("SHA-256 Authentication Token:", token)
    print("Token Length:", len(token))
