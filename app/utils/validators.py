import re


def validate_username(username):
    if not isinstance(username, str):
        return False

    if not 3 <= len(username) <= 30:
        return False

    if not re.fullmatch(r"[a-z0-9_.]+", username):
        return False

    return True


def validate_email(email):
    if not isinstance(email, str):
        return False

    email = email.strip().lower()

    if not email or len(email) > 255:
        return False

    pattern = r"^[^@\s]+@[^@\s]+\.[^@\s]+$"

    return bool(re.fullmatch(pattern, email))


def validate_password(password):
    if not isinstance(password, str):
        return False

    if len(password) < 8:
        return False

    if not re.search(r"[A-Z]", password):
        return False

    if not re.search(r"[a-z]", password):
        return False

    if not re.search(r"[0-9]", password):
        return False

    return True