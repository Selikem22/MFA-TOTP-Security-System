import pyotp

from app import app, get_user_by_email


def test_login_page_renders():
    client = app.test_client()
    response = client.get("/login")
    assert response.status_code == 200
    assert b"Login" in response.data


def test_verify_otp_uses_secret_key_instead_of_debug_value():
    client = app.test_client()
    user = get_user_by_email("test@example.com")
    assert user is not None

    with client.session_transaction() as session:
        session["user_id"] = user[0]
        session["user_email"] = user[1]
        session.pop("last_otp", None)

    valid_otp = pyotp.TOTP(user[3]).now()
    response = client.post("/verify_otp", data={"otp": valid_otp}, follow_redirects=False)

    assert response.status_code == 302
    assert response.headers["Location"] == "/timetable"
