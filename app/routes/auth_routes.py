from flask import Blueprint, request, jsonify
from app.services.auth_services import register_user, login_user
from app.utils.security import token_required
from app.models.database import get_db_connection
import bcrypt
import jwt

from datetime import datetime, timedelta

from app.config import Config
from app.models.database import get_db_connection

auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/auth/register", methods=["POST"])
def register():
    data = request.get_json()

    if not data:
        return jsonify({
            "error": "Request body must be JSON"
        }), 400

    allowed_fields = {"username", "email", "password"}

    if set(data.keys()) != allowed_fields:
        return jsonify({
            "error": "Request must contain username, email and password only"
        }), 400

    result = register_user(
        data["username"],
        data["email"],
        data["password"]
    )

    if not result["success"]:
        return jsonify({
            "error": result["message"]
        }), result["status"]

    return jsonify({
        "message": result["message"]
    }), result["status"]

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
            SELECT id, username, password_hash
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
            "exp": datetime.utcnow() + timedelta(hours=24)
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


@auth_bp.route("/auth/login", methods=["POST"])
def login():
    data = request.get_json()

    if not data:
        return jsonify({
            "error": "Request body must be JSON"
        }), 400

    allowed_fields = {"username", "password"}

    if set(data.keys()) != allowed_fields:
        return jsonify({
            "error": "Request must contain username and password only"
        }), 400

    result = login_user(
        data["username"],
        data["password"]
    )

    if not result["success"]:
        return jsonify({
            "error": result["message"]
        }), result["status"]

    return jsonify({
        "message": result["message"],
        "token": result["token"]
    }), result["status"]

@auth_bp.route("/auth/me", methods=["GET"])
@token_required
def get_current_user(payload):
    user_id = payload["user_id"]

    connection = None
    cursor = None

    try:
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        cursor.execute(
            """
            SELECT id, username, email, created_at, is_online, status
            FROM users
            WHERE id = %s
            """,
            (user_id,)
        )

        user = cursor.fetchone()

        if not user:
            return jsonify({
                "error": "User not found"
            }), 404

        return jsonify({
            "user_id": user["id"],
            "username": user["username"],
            "email": user["email"],
            "created_at": user["created_at"],
            "is_online": bool(user["is_online"]),
            "status": user["status"]
        }), 200

    except Exception:
        return jsonify({
            "error": "Failed to retrieve user"
        }), 500

    finally:
        if cursor:
            cursor.close()

        if connection:
            connection.close()