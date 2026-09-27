# Secure Authentication System

A Flask-based academic Cryptography and Network Security project demonstrating three cryptographic applications in one authentication workflow:

1. **bcrypt** – secure password hashing and password verification.
2. **SHA-256** – generation of a 256-bit authentication token.
3. **RSA-2048** – public-key encryption and private-key decryption of the authentication token.

## Authentication workflow

```text
Registration
    |
    v
Password -> bcrypt + salt -> password hash -> SQLite

Login
    |
    v
Entered Password
    |
    +---- bcrypt verification ----> Valid password
                                      |
                                      v
                               Fresh random nonce
                                      |
                                      v
                           Username + nonce
                                      |
                                      v
                                  SHA-256
                                      |
                                      v
                           Authentication token
                                      |
                                      v
                         RSA-2048 public-key encryption
                                      |
                                      v
                           Encrypted authentication token
                                      |
                                      v
                         RSA-2048 private-key decryption
                                      |
                                      v
                        Regenerate SHA-256 token
                                      |
                                      v
                              Compare tokens
                                      |
                              VERIFIED / FAILED
```

## Project structure

```text
Secure-Authentication-System/
├── app.py
├── crypto_utils.py
├── rsa_utils.py
├── database.py
├── test_crypto.py
├── requirements.txt
├── .env
├── .gitignore
├── templates/
│   ├── login.html
│   ├── register.html
│   └── dashboard.html
└── static/
    └── style.css
```

## Requirements

- Python 3.10+
- Flask
- bcrypt
- cryptography
- python-dotenv

## Installation

Open a terminal in the project folder:

```bash
python -m venv venv
```

Windows PowerShell:

```powershell
.\venv\Scripts\Activate.ps1
```

Install dependencies:

```bash
python -m pip install -r requirements.txt
```

## Run the cryptography tests

```bash
python test_crypto.py
```

Expected result:

```text
[PASS] bcrypt password hashing and verification
[PASS] SHA-256 authentication token generation
[PASS] RSA-2048 encryption and decryption
[PASS] Integrated bcrypt + SHA-256 + RSA authentication flow

All cryptography tests passed.
```

## Run the application

```bash
python app.py
```

Open the Flask address shown in the terminal, normally:

```text
http://127.0.0.1:5000
```

The application automatically creates an RSA-2048 key pair if the PEM files do not already exist.

## Demonstration for the CNS assignment

### 1. Registration
- Enter a username and a strong password.
- The password is never stored as plaintext.
- bcrypt creates a salted password hash.

### 2. Login
- Enter the registered credentials.
- bcrypt verifies the password.
- A fresh random nonce is generated.
- SHA-256 generates the authentication token.
- RSA-2048 encrypts the token using the public key.

### 3. Dashboard verification
- The RSA private key decrypts the token.
- The SHA-256 token is regenerated from the username and nonce.
- Both token values are compared.
- The dashboard is displayed only when the values match.

### 4. Logout
The Flask session is cleared and the user is returned to the login page.

## Security notes

- Do not commit real production secrets or private RSA keys to a public repository.
- The included `.env` value is for local academic demonstration only.
- The SQLite database stores password hashes, not plaintext passwords.
