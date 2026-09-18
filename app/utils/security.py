import jwt

from functools import wraps
from flask import request, jsonify

from app.config import Config
from app.models.database import get_db_connection


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):

        auth_header = request.headers.get("Authorization")

        if not auth_header:
            return jsonify({
                "error": "Authorization token is required"
            }), 401

        parts = auth_header.split()

        if len(parts) != 2 or parts[0].lower() != "bearer":
            return jsonify({
                "error": "Invalid authorization format"
            }), 401

        token = parts[1]

        try:
            payload = jwt.decode(
                token,
                Config.JWT_SECRET,
                algorithms=["HS256"]
            )

        except jwt.ExpiredSignatureError:
            return jsonify({
                "error": "Token has expired"
            }), 401

        except jwt.InvalidTokenError:
            return jsonify({
                "error": "Invalid token"
            }), 401

        connection = None
        cursor = None

        try:
            connection = get_db_connection()
            cursor = connection.cursor(dictionary=True)

            cursor.execute(
                """
                SELECT id, status
                FROM users
                WHERE id = %s
                """,
                (payload["user_id"],)
            )

            user = cursor.fetchone()

            if not user:
                return jsonify({
                    "error": "User not found"
                }), 401

            if user["status"] == "blocked":
                return jsonify({
                    "error": "Account is blocked"
                }), 403

            return f(payload, *args, **kwargs)

        except Exception:
            return jsonify({
                "error": "Authentication failed"
            }), 500

        finally:
            if cursor:
                cursor.close()

            if connection:
                connection.close()

    return decorated