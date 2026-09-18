import bcrypt
import jwt

from datetime import datetime, timedelta, timezone

from app.config import Config
from app.models.database import get_db_connection
from app.utils.validators import (
    validate_username,
    validate_email,
    validate_password
)


def register_user(username, email, password):
    username = username.strip().lower()
    email = email.strip().lower()

    if not validate_username(username):
        return {
            "success": False,
            "status": 400,
            "message": "Invalid username"
        }

    if not validate_email(email):
        return {
            "success": False,
            "status": 400,
            "message": "Invalid email"
        }

    if not validate_password(password):
        return {
            "success": False,
            "status": 400,
            "message": "Invalid password"
        }

    connection = None
    cursor = None

    try:
        connection = get_db_connection()
        cursor = connection.cursor()

        cursor.execute(
            "SELECT id FROM users WHERE username = %s",
            (username,)
        )

        if cursor.fetchone():
            return {
                "success": False,
                "status": 409,
                "message": "Username already exists"
            }

        cursor.execute(
            "SELECT COUNT(*) FROM users WHERE email = %s",
            (email,)
        )

        profile_count = cursor.fetchone()[0]

        if profile_count >= 4:
            return {
                "success": False,
                "status": 409,
                "message": "This email already has 4 profiles"
            }

        password_hash = bcrypt.hashpw(
            password.encode("utf-8"),
            bcrypt.gensalt()
        ).decode("utf-8")

        cursor.execute(
            """
            INSERT INTO users (username, email, password_hash)
            VALUES (%s, %s, %s)
            """,
            (username, email, password_hash)
        )

        connection.commit()

        return {
            "success": True,
            "status": 201,
            "message": "User registered successfully"
        }

    except Exception:
        if connection:
            connection.rollback()

        return {
            "success": False,
            "status": 500,
            "message": "Registration failed"
        }

    finally:
        if cursor:
            cursor.close()

        if connection:
            connection.close()


def login_user(username, password):
    username = username.strip().lower()

    if not username or not password:
        return {
            "success": False,
            "status": 400,
            "message": "Username and password are required"
        }

    connection = None
    cursor = None

    try:
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        cursor.execute(
            """
            SELECT id, username, password_hash, status
            FROM users
            WHERE username = %s
            """,
            (username,)
        )

        user = cursor.fetchone()

        if not user:
            return {
                "success": False,
                "status": 401,
                "message": "Invalid username or password"
            }

        password_matches = bcrypt.checkpw(
            password.encode("utf-8"),
            user["password_hash"].encode("utf-8")
        )

        if not password_matches:
            return {
                "success": False,
                "status": 401,
                "message": "Invalid username or password"
            }

        payload = {
            "user_id": user["id"],
            "username": user["username"],
            "exp": datetime.now(timezone.utc) + timedelta(hours=24)
        }

        token = jwt.encode(
            payload,
            Config.JWT_SECRET,
            algorithm="HS256"
        )

        return {
            "success": True,
            "status": 200,
            "message": "Login successful",
            "token": token
        }

    except Exception:
        return {
            "success": False,
            "status": 500,
            "message": "Login failed"
        }

    finally:
        if cursor:
            cursor.close()

        if connection:
            connection.close()