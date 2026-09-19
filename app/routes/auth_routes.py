from flask import Blueprint, request, jsonify

from app.services.auth_services import (
    register_user,
    login_user
)


auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/register", methods=["POST"])
def register():
    data = request.get_json()

    if not data:
        return jsonify({
            "success": False,
            "message": "Request body is required"
        }), 400

    username = data.get("username")
    email = data.get("email")
    password = data.get("password")

    if username is None or email is None or password is None:
        return jsonify({
            "success": False,
            "message": "Username, email and password are required"
        }), 400

    result = register_user(
        username,
        email,
        password
    )

    return jsonify({
        "success": result["success"],
        "message": result["message"]
    }), result["status"]


@auth_bp.route("/login", methods=["POST"])
def login():
    data = request.get_json()

    if not data:
        return jsonify({
            "success": False,
            "message": "Request body is required"
        }), 400

    username = data.get("username")
    password = data.get("password")

    if username is None or password is None:
        return jsonify({
            "success": False,
            "message": "Username and password are required"
        }), 400

    result = login_user(
        username,
        password
    )

    response = {
        "success": result["success"],
        "message": result["message"]
    }

    if result["success"]:
        response["token"] = result["token"]

    return jsonify(response), result["status"]