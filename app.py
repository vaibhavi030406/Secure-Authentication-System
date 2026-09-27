from hmac import compare_digest
import os
import re

import bcrypt
from dotenv import load_dotenv
from flask import Flask, redirect, render_template, request, session, url_for

from crypto_utils import create_auth_token, generate_auth_nonce
from database import add_user, create_database, get_user
from rsa_utils import decrypt_data, encrypt_data, load_keys

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY") or os.urandom(32)

# Database
create_database()

# RSA-2048 key pair
private_key, public_key = load_keys()


def validate_registration(username, password):
    """Return an error message or None when registration input is valid."""
    if len(username) < 3:
        return "Username must contain at least 3 characters."
    if len(password) < 8:
        return "Password must contain at least 8 characters."
    if not re.search(r"[A-Z]", password):
        return "Password must contain at least one uppercase letter."
    if not re.search(r"[a-z]", password):
        return "Password must contain at least one lowercase letter."
    if not re.search(r"[0-9]", password):
        return "Password must contain at least one number."
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return "Password must contain at least one special character."
    return None


@app.route("/", methods=["GET", "POST"])
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = get_user(username)

        if user:
            stored_hash = user[2]

            # 1. bcrypt verifies the stored password hash.
            if bcrypt.checkpw(password.encode("utf-8"), stored_hash.encode("utf-8")):
                # 2. SHA-256 creates a fresh authentication token using a random nonce.
                nonce = generate_auth_nonce()
                auth_token = create_auth_token(username, nonce)

                # 3. RSA-2048 encrypts the SHA-256 token with the public key.
                encrypted_token = encrypt_data(auth_token, public_key)

                session.clear()
                session["username"] = username
                session["auth_nonce"] = nonce
                session["encrypted_token"] = encrypted_token.hex()

                return redirect(url_for("dashboard"))

        return render_template("login.html", error="Invalid username or password!")

    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        error = validate_registration(username, password)
        if error:
            return render_template("register.html", error=error)

        # bcrypt adds a salt automatically and stores only the password hash.
        password_hash = bcrypt.hashpw(
            password.encode("utf-8"), bcrypt.gensalt()
        ).decode("utf-8")

        if add_user(username, password_hash):
            return redirect(url_for("login"))

        return render_template("register.html", error="Username already exists!")

    return render_template("register.html")


@app.route("/dashboard")
def dashboard():
    if "username" not in session:
        return redirect(url_for("login"))

    username = session["username"]
    nonce = session.get("auth_nonce")
    encrypted_hex = session.get("encrypted_token", "")

    verification_status = "FAILED"
    decrypted_token = ""
    expected_token = ""

    try:
        encrypted_token = bytes.fromhex(encrypted_hex)
        decrypted_token = decrypt_data(encrypted_token, private_key)
        expected_token = create_auth_token(username, nonce)

        # Complete RSA verification: decrypt, regenerate SHA-256 token, compare.
        if compare_digest(decrypted_token, expected_token):
            verification_status = "VERIFIED"
        else:
            session.clear()
            return redirect(url_for("login"))
    except (ValueError, TypeError, UnicodeDecodeError):
        session.clear()
        return redirect(url_for("login"))
    except Exception:
        session.clear()
        return redirect(url_for("login"))

    return render_template(
        "dashboard.html",
        username=username,
        auth_token=decrypted_token,
        encrypted_token=encrypted_hex,
        verification_status=verification_status,
    )


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


if __name__ == "__main__":
    app.run(debug=True)
