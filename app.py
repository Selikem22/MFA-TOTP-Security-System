import sqlite3
import hashlib
import pyotp
import requests

from flask import Flask, render_template, request, redirect, url_for, session, jsonify

# ========= CONFIG =========
DB_NAME = "Security.db"
DEMO_EMAIL = "test@example.com"
DEMO_PASSWORD = "Vicky65"   # plaintext for demo
APP_SECRET = "CHANGE_THIS_SECRET_KEY"

# ESP32 settings – change IP to your ESP32 IP from Serial Monitor
ESP32_IP = "172.20.10.10"   # <<< PUT YOUR ESP32 IP HERE
ESP32_PORT = 8080           # must match ESP32 server port

app = Flask(__name__)
app.secret_key = APP_SECRET


# ========= DATABASE HELPERS =========
def init_db():
    """Create database and demo user if they don't exist."""
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()

    # Users table
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            secret_key TEXT NOT NULL
        )
        """
    )

    # Check if demo user exists
    c.execute("SELECT id FROM users WHERE email = ?", (DEMO_EMAIL,))
    row = c.fetchone()

    if not row:
        # Create a new TOTP secret for demo user
        secret_key = pyotp.random_base32()

        # Simple password hash (SHA256) – just for demo
        password_hash = hashlib.sha256(DEMO_PASSWORD.encode()).hexdigest()

        c.execute(
            "INSERT INTO users (email, password_hash, secret_key) VALUES (?, ?, ?)",
            (DEMO_EMAIL, password_hash, secret_key),
        )
        conn.commit()

        print("=== Created DEMO USER ===")
        print(f"EMAIL: {DEMO_EMAIL}")
        print(f"PASSWORD: {DEMO_PASSWORD}")
        print(f"SECRET KEY: {secret_key}")
        print("Use this SAME secret in your ESP32 TOTP code if you ever do TOTP on ESP.")
    else:
        # Just print existing secret
        c.execute("SELECT secret_key FROM users WHERE email = ?", (DEMO_EMAIL,))
        row2 = c.fetchone()
        if row2:
            print("SECRET KEY FOR DEMO USER (", DEMO_EMAIL, "):", row2[0])

    conn.close()


def get_user_by_email(email):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("SELECT id, email, password_hash, secret_key FROM users WHERE email = ?", (email,))
    row = c.fetchone()
    conn.close()
    return row  # (id, email, password_hash, secret_key) or None


def trigger_esp32_send_otp(otp_value: str):
    """
    Call ESP32 /sendotp endpoint with ?value=<otp>.
    ESP32 will send that OTP to Telegram.
    """
    try:
        url = f"http://{ESP32_IP}:{ESP32_PORT}/sendotp?value={otp_value}"
        print("Triggering ESP32 with URL:", url)
        r = requests.get(url, timeout=5)
        print("ESP32 response status:", r.status_code)
        print("ESP32 response body:", r.text)
    except Exception as e:
        print("Error contacting ESP32:", e)


# ========= ROUTES =========

@app.route("/")
def home():
    return redirect(url_for("login_page"))


@app.route("/login", methods=["GET", "POST"])
def login_page():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        user = get_user_by_email(email)
        if not user:
            return render_template("invalid.html")

        user_id, user_email, stored_hash, secret_key = user

        entered_hash = hashlib.sha256(password.encode()).hexdigest()
        if entered_hash != stored_hash:
            return render_template("invalid.html")

        # Password correct -> create session
        session["user_id"] = user_id
        session["user_email"] = user_email

        # Generate OTP using user's secret key
        totp = pyotp.TOTP(secret_key)
        current_otp = totp.now()
        print("Generated OTP:", current_otp)

        # Ask ESP32 to send this OTP to Telegram
        trigger_esp32_send_otp(current_otp)

        # Store OTP just for debug
        session["last_otp"] = current_otp

        return redirect(url_for("otp_page"))
    
    return render_template("login.html")

@app.route("/otp", methods=["GET"])
def otp_page():
    # Require login
    if "user_id" not in session:
        return redirect(url_for("login_page"))
    return render_template("otp.html", email=session.get("user_email"))

@app.route("/verify_otp", methods=["POST"])
def verify_otp():
    if "user_id" not in session:
        return redirect(url_for("login_page"))

    entered_otp = request.form.get("otp", "").strip()
    saved_otp = session.get("last_otp")
    user_email = session.get("user_email")

    print("Entered OTP:", entered_otp)
    print("Saved OTP in session:", saved_otp)

    if not user_email:
        return render_template("fail.html")

    user = get_user_by_email(user_email)
    if not user:
        return render_template("fail.html")

    _, _, _, secret_key = user
    valid_otp = pyotp.TOTP(secret_key)

    # Validate the entered code against the real TOTP secret, allowing the
    # usual 30-second drift window used by authenticator apps.
    if valid_otp.verify(entered_otp, valid_window=1):
        session["otp_passed"] = True
        return redirect(url_for("timetable"))

    return render_template("fail.html")

@app.route("/timetable")
def timetable():
    if "user_id" not in session or not session.get("otp_passed"):
        return redirect(url_for("login_page"))

    email = session.get("user_email")
    return render_template("timetable.html", email=email)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login_page"))


# Optional debug API
@app.route("/api/otp")
def api_otp():
    email = session.get("user_email", DEMO_EMAIL)
    user = get_user_by_email(email)
    if not user:
        return jsonify({"error": "user not found"}), 404

    _, _, _, secret_key = user
    totp = pyotp.TOTP(secret_key)
    return jsonify({"otp": totp.now()})

if __name__ == "__main__":
    init_db()
    app.run(debug=True, host="0.0.0.0", port=5515)